//! Secrets Manager project routes: list, get, and CRUD.
//!
//! Access is resolved through [`crate::access`]: a machine account sees its explicitly granted
//! projects; an organization Owner/Admin sees every project in the org; a regular member sees only
//! projects granted by access policy. Denials return 404 so a caller cannot probe what exists.

use std::collections::HashSet;

use diesel::prelude::*;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{get, post, put, routes, Route, State};

use crate::access::{rights_all, rights_in_org, Principal};
use crate::api::dto::{
    BulkDeleteResponse, ListResponse, ProjectCreateRequest, ProjectResponse, ProjectUpdateRequest,
};
use crate::db::DbPool;
use crate::models::{MachineAccountProjectAccess, Project};

pub fn routes() -> Vec<Route> {
    routes![
        list_projects,
        get_project,
        create_project,
        update_project,
        delete_projects,
    ]
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

fn project_response(p: Project, read: bool, write: bool) -> ProjectResponse {
    ProjectResponse {
        id: p.id,
        organization_id: p.organization_id,
        name: p.name_enc,
        creation_date: p.creation_date,
        revision_date: p.revision_date,
        read,
        write,
        object: "project",
    }
}

#[get("/organizations/<org_id>/projects")]
pub async fn list_projects(
    org_id: String,
    principal: Principal,
    pool: &State<DbPool>,
) -> Result<Json<ListResponse<ProjectResponse>>, Status> {
    if principal.org_access(&org_id).is_none() {
        return Err(Status::NotFound);
    }
    let pool = pool.inner().clone();

    let rows = rocket::tokio::task::spawn_blocking(
        move || -> anyhow::Result<Vec<(Project, bool, bool)>> {
            use crate::schema::projects;
            let mut conn = pool.get()?;

            let access = principal.project_access(&mut conn)?;
            let rights = rights_in_org(&access, &org_id);
            let ids: Vec<String> = rights.keys().cloned().collect();

            let projects: Vec<Project> = projects::table
                .filter(
                    projects::id
                        .eq_any(&ids)
                        .and(projects::deleted_date.is_null()),
                )
                .load(&mut conn)?;

            let mut out = Vec::new();
            for p in projects {
                if let Some(r) = rights.get(&p.id) {
                    out.push((p, r.read, r.write));
                }
            }
            Ok(out)
        },
    )
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::InternalServerError)?;

    let data = rows
        .into_iter()
        .map(|(p, r, w)| project_response(p, r, w))
        .collect();

    Ok(Json(ListResponse::new(data)))
}

#[get("/projects/<id>")]
pub async fn get_project(
    id: String,
    principal: Principal,
    pool: &State<DbPool>,
) -> Result<Json<ProjectResponse>, Status> {
    let pool = pool.inner().clone();

    let found = rocket::tokio::task::spawn_blocking(
        move || -> anyhow::Result<Option<(Project, bool, bool)>> {
            use crate::schema::projects;
            let mut conn = pool.get()?;

            let access = principal.project_access(&mut conn)?;
            let rights = rights_all(&access);
            let Some(r) = rights.get(&id) else {
                return Ok(None);
            };
            if !r.read {
                return Ok(None);
            }
            let p: Option<Project> = projects::table
                .find(&id)
                .filter(projects::deleted_date.is_null())
                .first(&mut conn)
                .optional()?;
            Ok(p.map(|p| (p, r.read, r.write)))
        },
    )
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::InternalServerError)?;

    match found {
        Some((p, r, w)) => Ok(Json(project_response(p, r, w))),
        None => Err(Status::NotFound),
    }
}

#[post("/organizations/<org_id>/projects", data = "<req>")]
pub async fn create_project(
    org_id: String,
    principal: Principal,
    req: Json<ProjectCreateRequest>,
    pool: &State<DbPool>,
) -> Result<Json<ProjectResponse>, Status> {
    let Some(org) = principal.org_access(&org_id) else {
        return Err(Status::NotFound);
    };
    // A machine account creating a project grants itself access to it (as `bws` expects). An
    // Owner/Admin needs no grant — they see everything. A regular member cannot create projects.
    let self_grant_ma = match &principal {
        Principal::Machine {
            machine_account_id, ..
        } => Some(machine_account_id.clone()),
        Principal::User { .. } if org.is_admin => None,
        Principal::User { .. } => return Err(Status::Forbidden),
    };

    let pool = pool.inner().clone();
    let name = req.name.clone();

    let project = rocket::tokio::task::spawn_blocking(move || -> anyhow::Result<Project> {
        use crate::schema::{machine_account_project_access as mapa, projects};
        let mut conn = pool.get()?;

        let id = uuid::Uuid::new_v4().to_string();
        let now = now_iso();
        let project = Project {
            id: id.clone(),
            organization_id: org_id,
            name_enc: name,
            creation_date: now.clone(),
            revision_date: now,
            deleted_date: None,
        };
        diesel::insert_into(projects::table)
            .values(&project)
            .execute(&mut conn)?;
        if let Some(ma) = self_grant_ma {
            diesel::insert_into(mapa::table)
                .values(&MachineAccountProjectAccess {
                    machine_account_id: ma,
                    project_id: id,
                    can_read: 1,
                    can_write: 1,
                })
                .execute(&mut conn)?;
        }
        Ok(project)
    })
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::InternalServerError)?;

    Ok(Json(project_response(project, true, true)))
}

#[put("/projects/<id>", data = "<req>")]
pub async fn update_project(
    id: String,
    principal: Principal,
    req: Json<ProjectUpdateRequest>,
    pool: &State<DbPool>,
) -> Result<Json<ProjectResponse>, Status> {
    let pool = pool.inner().clone();
    let name = req.name.clone();

    let project = rocket::tokio::task::spawn_blocking(move || -> anyhow::Result<Project> {
        use crate::schema::projects;
        let mut conn = pool.get()?;

        let access = principal.project_access(&mut conn)?;
        let rights = rights_all(&access);
        match rights.get(&id) {
            Some(r) if r.write => {}
            _ => anyhow::bail!("not found or no write access"),
        }

        let now = now_iso();
        diesel::update(
            projects::table
                .find(&id)
                .filter(projects::deleted_date.is_null()),
        )
        .set((projects::name_enc.eq(&name), projects::revision_date.eq(&now)))
        .execute(&mut conn)?;

        let project: Project = projects::table.find(&id).first(&mut conn)?;
        Ok(project)
    })
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::NotFound)?;

    Ok(Json(project_response(project, true, true)))
}

#[post("/projects/delete", data = "<ids>")]
pub async fn delete_projects(
    principal: Principal,
    ids: Json<Vec<String>>,
    pool: &State<DbPool>,
) -> Result<Json<ListResponse<BulkDeleteResponse>>, Status> {
    let pool = pool.inner().clone();
    let ids = ids.into_inner();

    let out = rocket::tokio::task::spawn_blocking(
        move || -> anyhow::Result<Vec<BulkDeleteResponse>> {
            use crate::schema::projects;
            let mut conn = pool.get()?;

            let access = principal.project_access(&mut conn)?;
            let rights = rights_all(&access);
            let writable: HashSet<String> = rights
                .iter()
                .filter(|(_, r)| r.write)
                .map(|(id, _)| id.clone())
                .collect();

            let now = now_iso();
            let mut out = Vec::new();
            for id in ids {
                if writable.contains(&id) {
                    diesel::update(projects::table.find(&id))
                        .set(projects::deleted_date.eq(Some(now.clone())))
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

    Ok(Json(ListResponse::new(out)))
}
