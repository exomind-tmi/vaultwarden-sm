//! Secrets Manager service-account routes: CRUD plus access-token management.
//!
//! "Service account" is Bitwarden's name for what we store as a machine account. People manage
//! them; machine accounts do not (see [`crate::access::Principal::machine_account_access`]). Access
//! is resolved per request and denials return 404, so a caller cannot probe what exists.
//!
//! Access tokens are created server-side only insofar as the client secret is: the browser holds
//! the organization key and ships the already-encrypted payload and wrapped key. The plaintext
//! client secret is returned exactly once, at creation.

use std::collections::HashSet;

use diesel::prelude::*;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{get, post, put, routes, Route, State};

use crate::access::{rights_all, rights_in_org, Principal};
use crate::api::dto::{
    AccessTokenCreateRequest, AccessTokenCreationResponse, AccessTokenItemResponse,
    BulkDeleteResponse, ListResponse, RevokeAccessTokensRequest, ServiceAccountCreateRequest,
    ServiceAccountDetailsResponse, ServiceAccountResponse, ServiceAccountUpdateRequest,
};
use crate::db::DbPool;
use crate::models::{AccessToken, MachineAccount};

pub fn routes() -> Vec<Route> {
    routes![
        list_service_accounts,
        get_service_account,
        create_service_account,
        update_service_account,
        delete_service_accounts,
        list_access_tokens,
        create_access_token,
        revoke_access_tokens,
    ]
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

/// Count the non-deleted secrets a machine account can read through its project grants.
fn access_to_secrets(conn: &mut SqliteConnection, machine_account_id: &str) -> anyhow::Result<i64> {
    use crate::schema::{machine_account_project_access as mapa, project_secret as ps, secrets};

    let project_ids: Vec<String> = mapa::table
        .filter(
            mapa::machine_account_id
                .eq(machine_account_id)
                .and(mapa::can_read.ne(0)),
        )
        .select(mapa::project_id)
        .load(conn)?;
    if project_ids.is_empty() {
        return Ok(0);
    }

    let secret_ids: Vec<String> = ps::table
        .inner_join(secrets::table.on(secrets::id.eq(ps::secret_id)))
        .filter(
            ps::project_id
                .eq_any(&project_ids)
                .and(secrets::deleted_date.is_null()),
        )
        .select(ps::secret_id)
        .distinct()
        .load(conn)?;
    Ok(secret_ids.len() as i64)
}

#[get("/organizations/<org_id>/service-accounts?<includeAccessToSecrets>")]
#[allow(non_snake_case)]
pub async fn list_service_accounts(
    org_id: String,
    includeAccessToSecrets: Option<bool>,
    principal: Principal,
    pool: &State<DbPool>,
) -> Result<Json<ListResponse<ServiceAccountDetailsResponse>>, Status> {
    if principal.org_access(&org_id).is_none() {
        return Err(Status::NotFound);
    }
    let pool = pool.inner().clone();
    let include_counts = includeAccessToSecrets.unwrap_or(false);

    let rows = rocket::tokio::task::spawn_blocking(
        move || -> anyhow::Result<Vec<ServiceAccountDetailsResponse>> {
            use crate::schema::machine_accounts;
            let mut conn = pool.get()?;

            let access = principal.machine_account_access(&mut conn)?;
            let rights = rights_in_org(&access, &org_id);
            let ids: Vec<String> = rights.keys().cloned().collect();

            let mas: Vec<MachineAccount> = machine_accounts::table
                .filter(machine_accounts::id.eq_any(&ids))
                .load(&mut conn)?;

            let mut out = Vec::new();
            for ma in mas {
                let Some(r) = rights.get(&ma.id) else {
                    continue;
                };
                if !r.read {
                    continue;
                }
                let count = if include_counts {
                    access_to_secrets(&mut conn, &ma.id)?
                } else {
                    0
                };
                out.push(ServiceAccountDetailsResponse {
                    service_account: ma.into(),
                    access_to_secrets: count,
                });
            }
            Ok(out)
        },
    )
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::InternalServerError)?;

    Ok(Json(ListResponse::new(rows)))
}

#[get("/service-accounts/<id>")]
pub async fn get_service_account(
    id: String,
    principal: Principal,
    pool: &State<DbPool>,
) -> Result<Json<ServiceAccountResponse>, Status> {
    let pool = pool.inner().clone();

    let found = rocket::tokio::task::spawn_blocking(
        move || -> anyhow::Result<Option<MachineAccount>> {
            use crate::schema::machine_accounts;
            let mut conn = pool.get()?;

            let access = principal.machine_account_access(&mut conn)?;
            let rights = rights_all(&access);
            match rights.get(&id) {
                Some(r) if r.read => {}
                _ => return Ok(None),
            }
            Ok(machine_accounts::table.find(&id).first(&mut conn).optional()?)
        },
    )
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::InternalServerError)?;

    match found {
        Some(ma) => Ok(Json(ma.into())),
        None => Err(Status::NotFound),
    }
}

#[post("/organizations/<org_id>/service-accounts", data = "<req>")]
pub async fn create_service_account(
    org_id: String,
    principal: Principal,
    req: Json<ServiceAccountCreateRequest>,
    pool: &State<DbPool>,
) -> Result<Json<ServiceAccountResponse>, Status> {
    let Some(org) = principal.org_access(&org_id) else {
        return Err(Status::NotFound);
    };
    // Only organization Owners/Admins create service accounts. Members and machine accounts cannot.
    match &principal {
        Principal::User { .. } if org.is_admin => {}
        _ => return Err(Status::Forbidden),
    }

    let pool = pool.inner().clone();
    let name = req.name.clone();

    let ma = rocket::tokio::task::spawn_blocking(move || -> anyhow::Result<MachineAccount> {
        use crate::schema::machine_accounts;
        let mut conn = pool.get()?;

        let now = now_iso();
        let ma = MachineAccount {
            id: uuid::Uuid::new_v4().to_string(),
            organization_id: org_id,
            name_enc: name,
            creation_date: now.clone(),
            revision_date: now,
        };
        diesel::insert_into(machine_accounts::table)
            .values(&ma)
            .execute(&mut conn)?;
        Ok(ma)
    })
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::InternalServerError)?;

    Ok(Json(ma.into()))
}

#[put("/service-accounts/<id>", data = "<req>")]
pub async fn update_service_account(
    id: String,
    principal: Principal,
    req: Json<ServiceAccountUpdateRequest>,
    pool: &State<DbPool>,
) -> Result<Json<ServiceAccountResponse>, Status> {
    let pool = pool.inner().clone();
    let name = req.name.clone();

    let ma = rocket::tokio::task::spawn_blocking(move || -> anyhow::Result<MachineAccount> {
        use crate::schema::machine_accounts;
        let mut conn = pool.get()?;

        let access = principal.machine_account_access(&mut conn)?;
        match rights_all(&access).get(&id) {
            Some(r) if r.write => {}
            _ => anyhow::bail!("not found or no write access"),
        }

        let now = now_iso();
        diesel::update(machine_accounts::table.find(&id))
            .set((
                machine_accounts::name_enc.eq(&name),
                machine_accounts::revision_date.eq(&now),
            ))
            .execute(&mut conn)?;
        Ok(machine_accounts::table.find(&id).first(&mut conn)?)
    })
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::NotFound)?;

    Ok(Json(ma.into()))
}

#[post("/service-accounts/delete", data = "<ids>")]
pub async fn delete_service_accounts(
    principal: Principal,
    ids: Json<Vec<String>>,
    pool: &State<DbPool>,
) -> Result<Json<ListResponse<BulkDeleteResponse>>, Status> {
    let pool = pool.inner().clone();
    let ids = ids.into_inner();

    let out = rocket::tokio::task::spawn_blocking(
        move || -> anyhow::Result<Vec<BulkDeleteResponse>> {
            use crate::schema::{
                access_tokens, machine_account_project_access as mapa, machine_accounts,
                user_machine_account_access as umaa,
            };
            let mut conn = pool.get()?;

            let access = principal.machine_account_access(&mut conn)?;
            let rights = rights_all(&access);
            let writable: HashSet<String> = rights
                .iter()
                .filter(|(_, r)| r.write)
                .map(|(id, _)| id.clone())
                .collect();

            let mut out = Vec::new();
            for id in ids {
                if writable.contains(&id) {
                    // Remove dependents first (no cascading FK on these tables).
                    diesel::delete(
                        access_tokens::table.filter(access_tokens::machine_account_id.eq(&id)),
                    )
                    .execute(&mut conn)?;
                    diesel::delete(mapa::table.filter(mapa::machine_account_id.eq(&id)))
                        .execute(&mut conn)?;
                    diesel::delete(umaa::table.filter(umaa::machine_account_id.eq(&id)))
                        .execute(&mut conn)?;
                    diesel::delete(machine_accounts::table.find(&id)).execute(&mut conn)?;
                    out.push(BulkDeleteResponse {
                        id,
                        error: None,
                        object: "bulkDeleteResponse",
                    });
                } else {
                    out.push(BulkDeleteResponse {
                        id,
                        error: Some("access denied".into()),
                        object: "bulkDeleteResponse",
                    });
                }
            }
            Ok(out)
        },
    )
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::InternalServerError)?;

    Ok(Json(ListResponse::new(out)))
}

#[get("/service-accounts/<id>/access-tokens")]
pub async fn list_access_tokens(
    id: String,
    principal: Principal,
    pool: &State<DbPool>,
) -> Result<Json<ListResponse<AccessTokenItemResponse>>, Status> {
    let pool = pool.inner().clone();

    let rows = rocket::tokio::task::spawn_blocking(
        move || -> anyhow::Result<Option<Vec<AccessToken>>> {
            use crate::schema::access_tokens;
            let mut conn = pool.get()?;

            let access = principal.machine_account_access(&mut conn)?;
            match rights_all(&access).get(&id) {
                Some(r) if r.read => {}
                _ => return Ok(None),
            }
            let tokens: Vec<AccessToken> = access_tokens::table
                .filter(access_tokens::machine_account_id.eq(&id))
                .load(&mut conn)?;
            Ok(Some(tokens))
        },
    )
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::InternalServerError)?;

    match rows {
        Some(tokens) => Ok(Json(ListResponse::new(
            tokens.into_iter().map(Into::into).collect(),
        ))),
        None => Err(Status::NotFound),
    }
}

#[post("/service-accounts/<id>/access-tokens", data = "<req>")]
pub async fn create_access_token(
    id: String,
    principal: Principal,
    req: Json<AccessTokenCreateRequest>,
    pool: &State<DbPool>,
) -> Result<Json<AccessTokenCreationResponse>, Status> {
    let req = req.into_inner();

    // An expiry, if given, must be in the future.
    if let Some(expire_at) = &req.expire_at {
        match chrono::DateTime::parse_from_rfc3339(expire_at) {
            Ok(exp) if exp > chrono::Utc::now() => {}
            _ => return Err(Status::BadRequest),
        }
    }

    let pool = pool.inner().clone();

    let created = rocket::tokio::task::spawn_blocking(
        move || -> anyhow::Result<Option<(AccessToken, String)>> {
            use crate::schema::access_tokens;
            let mut conn = pool.get()?;

            let access = principal.machine_account_access(&mut conn)?;
            match rights_all(&access).get(&id) {
                Some(r) if r.write => {}
                _ => return Ok(None),
            }

            // The server contributes only the client secret; the payload and wrapped key arrive
            // already encrypted under keys the browser holds.
            let client_secret = sm_core::crypto::random_client_secret();
            let now = now_iso();
            let token = AccessToken {
                id: uuid::Uuid::new_v4().to_string(),
                machine_account_id: id,
                name_enc: req.name,
                client_secret_hash: sm_core::crypto::hash_client_secret(&client_secret),
                scope: serde_json::to_string(&["api.secrets"])?,
                encrypted_payload: req.encrypted_payload,
                key_enc: req.key,
                expire_at: req.expire_at,
                creation_date: now.clone(),
                revision_date: now,
            };
            diesel::insert_into(access_tokens::table)
                .values(&token)
                .execute(&mut conn)?;
            Ok(Some((token, client_secret)))
        },
    )
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::InternalServerError)?;

    match created {
        Some((token, client_secret)) => Ok(Json(AccessTokenCreationResponse {
            id: token.id,
            name: token.name_enc,
            client_secret,
            expire_at: token.expire_at,
            creation_date: token.creation_date,
            revision_date: token.revision_date,
            object: "accessTokenCreation",
        })),
        None => Err(Status::NotFound),
    }
}

#[post("/service-accounts/<id>/access-tokens/revoke", data = "<req>")]
pub async fn revoke_access_tokens(
    id: String,
    principal: Principal,
    req: Json<RevokeAccessTokensRequest>,
    pool: &State<DbPool>,
) -> Result<Status, Status> {
    let pool = pool.inner().clone();
    let token_ids = req.into_inner().ids;

    let ok = rocket::tokio::task::spawn_blocking(move || -> anyhow::Result<bool> {
        use crate::schema::access_tokens;
        let mut conn = pool.get()?;

        let access = principal.machine_account_access(&mut conn)?;
        match rights_all(&access).get(&id) {
            Some(r) if r.write => {}
            _ => return Ok(false),
        }
        // Only revoke tokens that belong to this service account.
        diesel::delete(
            access_tokens::table.filter(
                access_tokens::id
                    .eq_any(&token_ids)
                    .and(access_tokens::machine_account_id.eq(&id)),
            ),
        )
        .execute(&mut conn)?;
        Ok(true)
    })
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::InternalServerError)?;

    if ok {
        Ok(Status::NoContent)
    } else {
        Err(Status::NotFound)
    }
}
