//! Secrets Manager secret routes: list, get, and sync.
//!
//! A machine account reaches secrets through the projects it can read. Denials return 404,
//! not 403, so a token cannot even learn that a secret it may not see exists.

use std::collections::HashMap;

use diesel::prelude::*;
use diesel::SqliteConnection;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{get, routes, Route, State};

use crate::api::auth::SmAuth;
use crate::api::dto::{
    BaseSecret, ListResponse, ProjectRef, SecretListItem, SecretResponse, SecretsListResponse,
    SyncResponse,
};
use crate::db::DbPool;
use crate::models::{MachineAccountProjectAccess, Project, ProjectSecret, Secret};

pub fn routes() -> Vec<Route> {
    routes![list_secrets, get_secret, sync]
}

/// Everything a machine account can reach, resolved once per request.
struct Accessible {
    secrets: Vec<Secret>,
    secret_projects: HashMap<String, Vec<ProjectRef>>,
    secret_write: HashMap<String, bool>,
    projects: Vec<ProjectRef>,
}

fn load_accessible(conn: &mut SqliteConnection, ma_id: &str) -> anyhow::Result<Accessible> {
    use crate::schema::{machine_account_project_access as mapa, project_secret, projects, secrets};

    let access: Vec<MachineAccountProjectAccess> = mapa::table
        .filter(mapa::machine_account_id.eq(ma_id))
        .load(conn)?;
    let can_write: HashMap<String, bool> = access
        .iter()
        .map(|a| (a.project_id.clone(), a.can_write != 0))
        .collect();
    let readable: Vec<String> = access
        .iter()
        .filter(|a| a.can_read != 0)
        .map(|a| a.project_id.clone())
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

async fn load(pool: &State<DbPool>, ma_id: String) -> Result<Accessible, Status> {
    let pool = pool.inner().clone();
    rocket::tokio::task::spawn_blocking(move || {
        let mut conn = pool.get()?;
        load_accessible(&mut conn, &ma_id)
    })
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::InternalServerError)
}

#[get("/organizations/<org_id>/secrets")]
pub async fn list_secrets(
    org_id: String,
    auth: SmAuth,
    pool: &State<DbPool>,
) -> Result<Json<SecretsListResponse>, Status> {
    if auth.organization_id != org_id {
        return Err(Status::NotFound);
    }
    let acc = load(pool, auth.machine_account_id.clone()).await?;

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
    auth: SmAuth,
    pool: &State<DbPool>,
) -> Result<Json<SecretResponse>, Status> {
    let acc = load(pool, auth.machine_account_id.clone()).await?;
    let Some(s) = acc.secrets.iter().find(|s| s.id == id) else {
        return Err(Status::NotFound);
    };

    Ok(Json(SecretResponse {
        read: true,
        write: *acc.secret_write.get(&s.id).unwrap_or(&false),
        id: s.id.clone(),
        organization_id: s.organization_id.clone(),
        key: s.key_enc.clone(),
        value: s.value_enc.clone(),
        note: s.note_enc.clone(),
        creation_date: s.creation_date.clone(),
        revision_date: s.revision_date.clone(),
        projects: acc.secret_projects.get(&s.id).cloned().unwrap_or_default(),
        object: "secret",
    }))
}

#[get("/organizations/<org_id>/secrets/sync")]
pub async fn sync(
    org_id: String,
    auth: SmAuth,
    pool: &State<DbPool>,
) -> Result<Json<SyncResponse>, Status> {
    if auth.organization_id != org_id {
        return Err(Status::NotFound);
    }
    let acc = load(pool, auth.machine_account_id.clone()).await?;

    let data: Vec<BaseSecret> = acc
        .secrets
        .iter()
        .map(|s| BaseSecret {
            id: s.id.clone(),
            organization_id: s.organization_id.clone(),
            key: s.key_enc.clone(),
            value: s.value_enc.clone(),
            note: s.note_enc.clone(),
            creation_date: s.creation_date.clone(),
            revision_date: s.revision_date.clone(),
            projects: acc.secret_projects.get(&s.id).cloned().unwrap_or_default(),
            object: "baseSecret",
        })
        .collect();

    Ok(Json(SyncResponse {
        has_changes: true,
        secrets: ListResponse::new(data),
        object: "secretsSync",
    }))
}
