//! Secrets Manager secret routes: list, get, sync, and CRUD.
//!
//! A principal reaches secrets through the projects it can read; writing needs a project it can
//! write. Access is resolved once per request via [`crate::access`]. Denials return 404, not 403,
//! so a token cannot even learn that a secret it may not see exists.

use std::collections::{HashMap, HashSet};

use diesel::prelude::*;
use diesel::SqliteConnection;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{get, post, put, routes, Route, State};

use crate::access::{rights_all, rights_in_org, Principal, Rights};
use crate::api::dto::{
    BaseSecret, BulkDeleteResponse, GetByIdsRequest, ListResponse, ProjectRef, SecretCreateRequest,
    SecretListItem, SecretResponse, SecretUpdateRequest, SecretsListResponse, SyncResponse,
};
use crate::db::DbPool;
use crate::models::{Project, ProjectSecret, Secret};

pub fn routes() -> Vec<Route> {
    routes![
        list_secrets,
        get_secret,
        sync,
        create_secret,
        update_secret,
        delete_secrets,
        get_secrets_by_ids,
    ]
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

/// Everything a principal can reach, resolved once per request from a project-rights map.
struct Accessible {
    secrets: Vec<Secret>,
    secret_projects: HashMap<String, Vec<ProjectRef>>,
    secret_write: HashMap<String, bool>,
    projects: Vec<ProjectRef>,
}

fn load_accessible(
    conn: &mut SqliteConnection,
    rights: &HashMap<String, Rights>,
) -> anyhow::Result<Accessible> {
    use crate::schema::{project_secret, projects, secrets};

    let readable: Vec<String> = rights
        .iter()
        .filter(|(_, r)| r.read)
        .map(|(id, _)| id.clone())
        .collect();
    let can_write: HashMap<String, bool> = rights
        .iter()
        .map(|(id, r)| (id.clone(), r.write))
        .collect();

    let projs: Vec<Project> = projects::table
        .filter(
            projects::id
                .eq_any(&readable)
                .and(projects::deleted_date.is_null()),
        )
        .load(conn)?;
    let proj_name: HashMap<String, String> = projs
        .iter()
        .map(|p| (p.id.clone(), p.name_enc.clone()))
        .collect();
    let project_refs: Vec<ProjectRef> = projs
        .iter()
        .map(|p| ProjectRef {
            id: p.id.clone(),
            name: p.name_enc.clone(),
        })
        .collect();

    let links: Vec<ProjectSecret> = project_secret::table
        .filter(project_secret::project_id.eq_any(&readable))
        .load(conn)?;

    let mut secret_projects: HashMap<String, Vec<ProjectRef>> = HashMap::new();
    let mut secret_write: HashMap<String, bool> = HashMap::new();
    let mut secret_ids: Vec<String> = Vec::new();
    for l in &links {
        let Some(name) = proj_name.get(&l.project_id) else {
            continue;
        };
        secret_projects
            .entry(l.secret_id.clone())
            .or_default()
            .push(ProjectRef {
                id: l.project_id.clone(),
                name: name.clone(),
            });
        let w = *can_write.get(&l.project_id).unwrap_or(&false);
        let entry = secret_write.entry(l.secret_id.clone()).or_insert(false);
        *entry = *entry || w;
        if !secret_ids.contains(&l.secret_id) {
            secret_ids.push(l.secret_id.clone());
        }
    }

    let secrets_rows: Vec<Secret> = secrets::table
        .filter(
            secrets::id
                .eq_any(&secret_ids)
                .and(secrets::deleted_date.is_null()),
        )
        .load(conn)?;

    Ok(Accessible {
        secrets: secrets_rows,
        secret_projects,
        secret_write,
        projects: project_refs,
    })
}

/// Resolve the principal's accessible set, optionally restricted to one organization.
async fn load(
    pool: &State<DbPool>,
    principal: Principal,
    org_filter: Option<String>,
) -> Result<Accessible, Status> {
    let pool = pool.inner().clone();
    rocket::tokio::task::spawn_blocking(move || {
        let mut conn = pool.get()?;
        let access = principal.project_access(&mut conn)?;
        let rights = match &org_filter {
            Some(org) => rights_in_org(&access, org),
            None => rights_all(&access),
        };
        load_accessible(&mut conn, &rights)
    })
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::InternalServerError)
}

fn base_secret(s: &Secret, projects: Vec<ProjectRef>) -> BaseSecret {
    BaseSecret {
        id: s.id.clone(),
        organization_id: s.organization_id.clone(),
        key: s.key_enc.clone(),
        value: s.value_enc.clone(),
        note: s.note_enc.clone(),
        creation_date: s.creation_date.clone(),
        revision_date: s.revision_date.clone(),
        projects,
        object: "baseSecret",
    }
}

fn secret_response(s: &Secret, projects: Vec<ProjectRef>, write: bool) -> SecretResponse {
    SecretResponse {
        read: true,
        write,
        id: s.id.clone(),
        organization_id: s.organization_id.clone(),
        key: s.key_enc.clone(),
        value: s.value_enc.clone(),
        note: s.note_enc.clone(),
        creation_date: s.creation_date.clone(),
        revision_date: s.revision_date.clone(),
        projects,
        object: "secret",
    }
}

// --- read ---

#[get("/organizations/<org_id>/secrets")]
pub async fn list_secrets(
    org_id: String,
    principal: Principal,
    pool: &State<DbPool>,
) -> Result<Json<SecretsListResponse>, Status> {
    if principal.org_access(&org_id).is_none() {
        return Err(Status::NotFound);
    }
    let acc = load(pool, principal, Some(org_id)).await?;

    let secrets = acc
        .secrets
        .iter()
        .map(|s| SecretListItem {
            id: s.id.clone(),
            organization_id: s.organization_id.clone(),
            key: s.key_enc.clone(),
            creation_date: s.creation_date.clone(),
            revision_date: s.revision_date.clone(),
            projects: acc.secret_projects.get(&s.id).cloned().unwrap_or_default(),
            read: true,
            write: *acc.secret_write.get(&s.id).unwrap_or(&false),
        })
        .collect();

    Ok(Json(SecretsListResponse {
        secrets,
        projects: acc.projects,
    }))
}

#[get("/secrets/<id>")]
pub async fn get_secret(
    id: String,
    principal: Principal,
    pool: &State<DbPool>,
) -> Result<Json<SecretResponse>, Status> {
    let acc = load(pool, principal, None).await?;
    let Some(s) = acc.secrets.iter().find(|s| s.id == id) else {
        return Err(Status::NotFound);
    };
    let projects = acc.secret_projects.get(&s.id).cloned().unwrap_or_default();
    let write = *acc.secret_write.get(&s.id).unwrap_or(&false);
    Ok(Json(secret_response(s, projects, write)))
}

#[get("/organizations/<org_id>/secrets/sync")]
pub async fn sync(
    org_id: String,
    principal: Principal,
    pool: &State<DbPool>,
) -> Result<Json<SyncResponse>, Status> {
    if principal.org_access(&org_id).is_none() {
        return Err(Status::NotFound);
    }
    let acc = load(pool, principal, Some(org_id)).await?;

    let data: Vec<BaseSecret> = acc
        .secrets
        .iter()
        .map(|s| base_secret(s, acc.secret_projects.get(&s.id).cloned().unwrap_or_default()))
        .collect();

    Ok(Json(SyncResponse {
        has_changes: true,
        secrets: ListResponse::new(data),
        object: "secretsSync",
    }))
}

// --- write ---

#[post("/organizations/<org_id>/secrets", data = "<req>")]
pub async fn create_secret(
    org_id: String,
    principal: Principal,
    req: Json<SecretCreateRequest>,
    pool: &State<DbPool>,
) -> Result<Json<SecretResponse>, Status> {
    let Some(org) = principal.org_access(&org_id) else {
        return Err(Status::NotFound);
    };
    // A secret with no project can only be created by a machine account or an Owner/Admin; a
    // regular member must place secrets in a project they can write.
    let privileged = matches!(principal, Principal::Machine { .. }) || org.is_admin;

    let project_id = req
        .project_ids
        .clone()
        .unwrap_or_default()
        .into_iter()
        .next();

    let pool = pool.inner().clone();
    let key = req.key.clone();
    let value = req.value.clone();
    let note = req.note.clone();

    let (secret, project_ref) = rocket::tokio::task::spawn_blocking(
        move || -> anyhow::Result<(Secret, Option<ProjectRef>)> {
            use crate::schema::{project_secret, projects, secrets};
            let mut conn = pool.get()?;

            // The federated user's org may have no row here yet; create it so the FK holds.
            crate::db::ensure_org(&mut conn, &org_id)?;

            let access = principal.project_access(&mut conn)?;
            let writable: HashSet<String> = rights_in_org(&access, &org_id)
                .into_iter()
                .filter(|(_, r)| r.write)
                .map(|(id, _)| id)
                .collect();

            let mut project_ref = None;
            if let Some(pid) = &project_id {
                if !writable.contains(pid) {
                    anyhow::bail!("no write access to project");
                }
                let name: Option<String> = projects::table
                    .find(pid)
                    .select(projects::name_enc)
                    .first(&mut conn)
                    .optional()?;
                if let Some(name) = name {
                    project_ref = Some(ProjectRef {
                        id: pid.clone(),
                        name,
                    });
                }
            } else if !privileged {
                anyhow::bail!("members cannot create unassigned secrets");
            }

            let id = uuid::Uuid::new_v4().to_string();
            let now = now_iso();
            let secret = Secret {
                id: id.clone(),
                organization_id: org_id.clone(),
                key_enc: key,
                value_enc: value,
                note_enc: note,
                creation_date: now.clone(),
                revision_date: now,
                deleted_date: None,
            };
            diesel::insert_into(secrets::table)
                .values(&secret)
                .execute(&mut conn)?;
            if let Some(pid) = &project_id {
                diesel::insert_into(project_secret::table)
                    .values(&ProjectSecret {
                        project_id: pid.clone(),
                        secret_id: id,
                    })
                    .execute(&mut conn)?;
            }
            Ok((secret, project_ref))
        },
    )
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::NotFound)?;

    Ok(Json(secret_response(
        &secret,
        project_ref.into_iter().collect(),
        true,
    )))
}

#[put("/secrets/<id>", data = "<req>")]
pub async fn update_secret(
    id: String,
    principal: Principal,
    req: Json<SecretUpdateRequest>,
    pool: &State<DbPool>,
) -> Result<Json<SecretResponse>, Status> {
    let pool = pool.inner().clone();
    let key = req.key.clone();
    let value = req.value.clone();
    let note = req.note.clone();
    let project_ids = req.project_ids.clone();

    let (secret, projects) = rocket::tokio::task::spawn_blocking(
        move || -> anyhow::Result<(Secret, Vec<ProjectRef>)> {
            use crate::schema::{project_secret, secrets};
            let mut conn = pool.get()?;

            let access = principal.project_access(&mut conn)?;
            let rights = rights_all(&access);
            let acc = load_accessible(&mut conn, &rights)?;
            if !acc.secrets.iter().any(|s| s.id == id) {
                anyhow::bail!("not found");
            }
            if !*acc.secret_write.get(&id).unwrap_or(&false) {
                anyhow::bail!("no write access");
            }

            let now = now_iso();
            diesel::update(secrets::table.find(&id))
                .set((
                    secrets::key_enc.eq(&key),
                    secrets::value_enc.eq(&value),
                    secrets::note_enc.eq(&note),
                    secrets::revision_date.eq(&now),
                ))
                .execute(&mut conn)?;

            // Project reassignment (at most one, matching the reference's single-project rule).
            if let Some(pids) = &project_ids {
                let target = pids.first().cloned();
                if let Some(ref pid) = target {
                    if !rights.get(pid).map(|r| r.write).unwrap_or(false) {
                        anyhow::bail!("no write access to target project");
                    }
                }
                diesel::delete(project_secret::table.filter(project_secret::secret_id.eq(&id)))
                    .execute(&mut conn)?;
                if let Some(pid) = target {
                    diesel::insert_into(project_secret::table)
                        .values(&ProjectSecret {
                            project_id: pid,
                            secret_id: id.clone(),
                        })
                        .execute(&mut conn)?;
                }
            }

            let updated: Secret = secrets::table.find(&id).first(&mut conn)?;
            let after = load_accessible(&mut conn, &rights)?;
            let projects = after.secret_projects.get(&id).cloned().unwrap_or_default();
            Ok((updated, projects))
        },
    )
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::NotFound)?;

    Ok(Json(secret_response(&secret, projects, true)))
}

#[post("/secrets/delete", data = "<ids>")]
pub async fn delete_secrets(
    principal: Principal,
    ids: Json<Vec<String>>,
    pool: &State<DbPool>,
) -> Result<Json<ListResponse<BulkDeleteResponse>>, Status> {
    let pool = pool.inner().clone();
    let ids = ids.into_inner();

    let responses = rocket::tokio::task::spawn_blocking(
        move || -> anyhow::Result<Vec<BulkDeleteResponse>> {
            use crate::schema::secrets;
            let mut conn = pool.get()?;

            let access = principal.project_access(&mut conn)?;
            let acc = load_accessible(&mut conn, &rights_all(&access))?;
            let writable: HashSet<String> = acc
                .secrets
                .iter()
                .filter(|s| *acc.secret_write.get(&s.id).unwrap_or(&false))
                .map(|s| s.id.clone())
                .collect();

            let now = now_iso();
            let mut out = Vec::new();
            for id in ids {
                if writable.contains(&id) {
                    diesel::update(secrets::table.find(&id))
                        .set(secrets::deleted_date.eq(Some(now.clone())))
                        .execute(&mut conn)?;
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

    Ok(Json(ListResponse::new(responses)))
}

#[post("/secrets/get-by-ids", data = "<req>")]
pub async fn get_secrets_by_ids(
    principal: Principal,
    req: Json<GetByIdsRequest>,
    pool: &State<DbPool>,
) -> Result<Json<ListResponse<BaseSecret>>, Status> {
    let wanted: HashSet<String> = req.into_inner().ids.into_iter().collect();
    let acc = load(pool, principal, None).await?;

    let data: Vec<BaseSecret> = acc
        .secrets
        .iter()
        .filter(|s| wanted.contains(&s.id))
        .map(|s| base_secret(s, acc.secret_projects.get(&s.id).cloned().unwrap_or_default()))
        .collect();

    Ok(Json(ListResponse::new(data)))
}
