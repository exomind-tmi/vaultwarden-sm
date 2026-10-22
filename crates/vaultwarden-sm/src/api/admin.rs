//! Admin API: the control plane `vws` drives to provision organizations, machine accounts,
//! access tokens, and project access — the pieces `bws` cannot create itself.
//!
//! Mounted under `/admin` and guarded by a shared admin token (`ADMIN_TOKEN`), mirroring
//! Vaultwarden's admin page. The server is a zero-knowledge store here: every payload arrives
//! already encrypted or hashed by `vws` (which holds the org key), so this layer only persists
//! and relates rows. It never sees a plaintext organization key.

use diesel::prelude::*;
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use rocket::serde::json::Json;
use rocket::{delete, get, post, routes, Route, State};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::api::dto::{ListResponse, ServiceAccountResponse};
use crate::db::DbPool;
use crate::models::{
    AccessToken, MachineAccount, MachineAccountProjectAccess, Organization, Project,
};

/// Shared-secret configuration for the admin API. When the token is `None`, the admin API is
/// disabled and every route answers `503`.
pub struct AdminConfig {
    pub token: Option<String>,
}

/// Request guard: authenticates an admin caller by the `ADMIN_TOKEN` bearer.
pub struct AdminAuth;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AdminAuth {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let Some(config) = req.rocket().state::<AdminConfig>() else {
            return Outcome::Error((Status::InternalServerError, ()));
        };
        // Admin API disabled unless an admin token is configured.
        let Some(expected) = config.token.as_deref() else {
            return Outcome::Error((Status::ServiceUnavailable, ()));
        };

        let provided = req
            .headers()
            .get_one("Authorization")
            .and_then(|h| h.strip_prefix("Bearer "));
        let Some(provided) = provided else {
            return Outcome::Error((Status::Unauthorized, ()));
        };

        if provided
            .as_bytes()
            .ct_eq(expected.as_bytes())
            .unwrap_u8()
            == 1
        {
            Outcome::Success(AdminAuth)
        } else {
            Outcome::Error((Status::Unauthorized, ()))
        }
    }
}

pub fn routes() -> Vec<Route> {
    routes![
        create_organization,
        list_organizations,
        create_machine_account,
        list_machine_accounts,
        delete_machine_account,
        create_access_token,
        list_access_tokens,
        delete_access_token,
        grant_project_access,
        list_projects,
    ]
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

// --- request / response DTOs (admin control plane) ---

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateOrgRequest {
    pub id: String,
    pub name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgResponse {
    pub id: String,
    pub name: String,
    pub creation_date: String,
    pub revision_date: String,
    pub object: &'static str,
}

impl From<Organization> for OrgResponse {
    fn from(o: Organization) -> Self {
        OrgResponse {
            id: o.id,
            name: o.name,
            creation_date: o.creation_date,
            revision_date: o.revision_date,
            object: "organization",
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateMachineAccountRequest {
    pub id: String,
    pub name_enc: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccessTokenRequest {
    pub id: String,
    pub name_enc: String,
    pub client_secret_hash: String,
    pub encrypted_payload: String,
    pub key_enc: String,
    #[serde(default)]
    pub scope: Option<Vec<String>>,
    #[serde(default)]
    pub expire_at: Option<String>,
}

/// An access token as the admin sees it — never includes the secret (that is shown once, by `vws`,
/// at creation time and never recoverable from the server).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessTokenResponse {
    pub id: String,
    pub machine_account_id: String,
    pub name: String,
    pub scope: Vec<String>,
    pub expire_at: Option<String>,
    pub creation_date: String,
    pub revision_date: String,
    pub object: &'static str,
}

impl From<AccessToken> for AccessTokenResponse {
    fn from(t: AccessToken) -> Self {
        let scope = serde_json::from_str(&t.scope).unwrap_or_default();
        AccessTokenResponse {
            id: t.id,
            machine_account_id: t.machine_account_id,
            name: t.name_enc,
            scope,
            expire_at: t.expire_at,
            creation_date: t.creation_date,
            revision_date: t.revision_date,
            object: "accessToken",
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantProjectAccessRequest {
    pub project_id: String,
    #[serde(default = "default_true")]
    pub read: bool,
    #[serde(default = "default_true")]
    pub write: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectRow {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub object: &'static str,
}

// --- organizations ---

#[post("/organizations", data = "<req>")]
pub async fn create_organization(
    _admin: AdminAuth,
    req: Json<CreateOrgRequest>,
    pool: &State<DbPool>,
) -> Result<Json<OrgResponse>, Status> {
    let pool = pool.inner().clone();
    let req = req.into_inner();

    let org = rocket::tokio::task::spawn_blocking(move || -> anyhow::Result<Organization> {
        use crate::schema::organizations;
        let mut conn = pool.get()?;
        let now = now_iso();
        let org = Organization {
            id: req.id,
            name: req.name,
            creation_date: now.clone(),
            revision_date: now,
        };
        diesel::insert_into(organizations::table)
            .values(&org)
            .execute(&mut conn)?;
        Ok(org)
    })
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::Conflict)?;

    Ok(Json(org.into()))
}

#[get("/organizations")]
pub async fn list_organizations(
    _admin: AdminAuth,
    pool: &State<DbPool>,
) -> Result<Json<ListResponse<OrgResponse>>, Status> {
    let pool = pool.inner().clone();
    let orgs = rocket::tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<Organization>> {
        use crate::schema::organizations;
        let mut conn = pool.get()?;
        Ok(organizations::table.load(&mut conn)?)
    })
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::InternalServerError)?;

    Ok(Json(ListResponse::new(
        orgs.into_iter().map(Into::into).collect(),
    )))
}

// --- machine accounts ---

#[post("/organizations/<org_id>/machine-accounts", data = "<req>")]
pub async fn create_machine_account(
    _admin: AdminAuth,
    org_id: String,
    req: Json<CreateMachineAccountRequest>,
    pool: &State<DbPool>,
) -> Result<Json<ServiceAccountResponse>, Status> {
    let pool = pool.inner().clone();
    let req = req.into_inner();

    let ma = rocket::tokio::task::spawn_blocking(move || -> anyhow::Result<MachineAccount> {
        use crate::schema::{machine_accounts, organizations};
        let mut conn = pool.get()?;

        // Parent org must exist.
        organizations::table
            .find(&org_id)
            .first::<Organization>(&mut conn)
            .optional()?
            .ok_or_else(|| anyhow::anyhow!("org not found"))?;

        let now = now_iso();
        let ma = MachineAccount {
            id: req.id,
            organization_id: org_id,
            name_enc: req.name_enc,
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
    .map_err(|_| Status::NotFound)?;

    Ok(Json(ma.into()))
}

#[get("/organizations/<org_id>/machine-accounts")]
pub async fn list_machine_accounts(
    _admin: AdminAuth,
    org_id: String,
    pool: &State<DbPool>,
) -> Result<Json<ListResponse<ServiceAccountResponse>>, Status> {
    let pool = pool.inner().clone();
    let rows = rocket::tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<MachineAccount>> {
        use crate::schema::machine_accounts;
        let mut conn = pool.get()?;
        Ok(machine_accounts::table
            .filter(machine_accounts::organization_id.eq(&org_id))
            .load(&mut conn)?)
    })
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::InternalServerError)?;

    Ok(Json(ListResponse::new(
        rows.into_iter().map(Into::into).collect(),
    )))
}

#[delete("/machine-accounts/<id>")]
pub async fn delete_machine_account(
    _admin: AdminAuth,
    id: String,
    pool: &State<DbPool>,
) -> Result<Status, Status> {
    let pool = pool.inner().clone();
    rocket::tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        use crate::schema::{access_tokens, machine_account_project_access as mapa, machine_accounts};
        let mut conn = pool.get()?;
        diesel::delete(access_tokens::table.filter(access_tokens::machine_account_id.eq(&id)))
            .execute(&mut conn)?;
        diesel::delete(mapa::table.filter(mapa::machine_account_id.eq(&id))).execute(&mut conn)?;
        diesel::delete(machine_accounts::table.find(&id)).execute(&mut conn)?;
        Ok(())
    })
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::InternalServerError)?;

    Ok(Status::NoContent)
}

// --- access tokens ---

#[post("/machine-accounts/<ma_id>/access-tokens", data = "<req>")]
pub async fn create_access_token(
    _admin: AdminAuth,
    ma_id: String,
    req: Json<CreateAccessTokenRequest>,
    pool: &State<DbPool>,
) -> Result<Json<AccessTokenResponse>, Status> {
    let pool = pool.inner().clone();
    let req = req.into_inner();

    let token = rocket::tokio::task::spawn_blocking(move || -> anyhow::Result<AccessToken> {
        use crate::schema::{access_tokens, machine_accounts};
        let mut conn = pool.get()?;

        // Parent machine account must exist.
        machine_accounts::table
            .find(&ma_id)
            .first::<MachineAccount>(&mut conn)
            .optional()?
            .ok_or_else(|| anyhow::anyhow!("machine account not found"))?;

        let scope = req
            .scope
            .unwrap_or_else(|| vec!["api.secrets".to_string()]);
        let now = now_iso();
        let token = AccessToken {
            id: req.id,
            machine_account_id: ma_id,
            name_enc: req.name_enc,
            client_secret_hash: req.client_secret_hash,
            scope: serde_json::to_string(&scope)?,
            encrypted_payload: req.encrypted_payload,
            key_enc: req.key_enc,
            expire_at: req.expire_at,
            creation_date: now.clone(),
            revision_date: now,
        };
        diesel::insert_into(access_tokens::table)
            .values(&token)
            .execute(&mut conn)?;
        Ok(token)
    })
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::NotFound)?;

    Ok(Json(token.into()))
}

#[get("/machine-accounts/<ma_id>/access-tokens")]
pub async fn list_access_tokens(
    _admin: AdminAuth,
    ma_id: String,
    pool: &State<DbPool>,
) -> Result<Json<ListResponse<AccessTokenResponse>>, Status> {
    let pool = pool.inner().clone();
    let rows = rocket::tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<AccessToken>> {
        use crate::schema::access_tokens;
        let mut conn = pool.get()?;
        Ok(access_tokens::table
            .filter(access_tokens::machine_account_id.eq(&ma_id))
            .load(&mut conn)?)
    })
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::InternalServerError)?;

    Ok(Json(ListResponse::new(
        rows.into_iter().map(Into::into).collect(),
    )))
}

#[delete("/access-tokens/<id>")]
pub async fn delete_access_token(
    _admin: AdminAuth,
    id: String,
    pool: &State<DbPool>,
) -> Result<Status, Status> {
    let pool = pool.inner().clone();
    rocket::tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        use crate::schema::access_tokens;
        let mut conn = pool.get()?;
        diesel::delete(access_tokens::table.find(&id)).execute(&mut conn)?;
        Ok(())
    })
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::InternalServerError)?;

    Ok(Status::NoContent)
}

// --- project access ---

#[post("/machine-accounts/<ma_id>/project-access", data = "<req>")]
pub async fn grant_project_access(
    _admin: AdminAuth,
    ma_id: String,
    req: Json<GrantProjectAccessRequest>,
    pool: &State<DbPool>,
) -> Result<Status, Status> {
    let pool = pool.inner().clone();
    let req = req.into_inner();

    rocket::tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        use crate::schema::{machine_account_project_access as mapa, machine_accounts, projects};
        let mut conn = pool.get()?;

        // The machine account and the project must exist in the same organization.
        let ma: MachineAccount = machine_accounts::table
            .find(&ma_id)
            .first(&mut conn)
            .optional()?
            .ok_or_else(|| anyhow::anyhow!("machine account not found"))?;
        let project: Project = projects::table
            .find(&req.project_id)
            .first(&mut conn)
            .optional()?
            .ok_or_else(|| anyhow::anyhow!("project not found"))?;
        if project.organization_id != ma.organization_id {
            anyhow::bail!("cross-organization access denied");
        }

        let row = MachineAccountProjectAccess {
            machine_account_id: ma_id,
            project_id: req.project_id,
            can_read: req.read as i32,
            can_write: req.write as i32,
        };
        diesel::insert_into(mapa::table)
            .values(&row)
            .on_conflict((mapa::machine_account_id, mapa::project_id))
            .do_update()
            .set((
                mapa::can_read.eq(row.can_read),
                mapa::can_write.eq(row.can_write),
            ))
            .execute(&mut conn)?;
        Ok(())
    })
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::NotFound)?;

    Ok(Status::NoContent)
}

// --- projects (read-only helper so `vws` can resolve ids) ---

#[get("/organizations/<org_id>/projects")]
pub async fn list_projects(
    _admin: AdminAuth,
    org_id: String,
    pool: &State<DbPool>,
) -> Result<Json<ListResponse<ProjectRow>>, Status> {
    let pool = pool.inner().clone();
    let rows = rocket::tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<Project>> {
        use crate::schema::projects;
        let mut conn = pool.get()?;
        Ok(projects::table
            .filter(
                projects::organization_id
                    .eq(&org_id)
                    .and(projects::deleted_date.is_null()),
            )
            .load(&mut conn)?)
    })
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::InternalServerError)?;

    let data = rows
        .into_iter()
        .map(|p| ProjectRow {
            id: p.id,
            organization_id: p.organization_id,
            name: p.name_enc,
            object: "project",
        })
        .collect();
    Ok(Json(ListResponse::new(data)))
}
