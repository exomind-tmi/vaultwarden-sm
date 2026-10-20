//! Secrets Manager project routes: list, get, and CRUD.

use std::collections::HashSet;

use diesel::prelude::*;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{get, post, put, routes, Route, State};

use crate::api::auth::SmAuth;
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
    auth: SmAuth,
    pool: &State<DbPool>,
) -> Result<Json<ListResponse<ProjectResponse>>, Status> {
    if auth.organization_id != org_id {
        return Err(Status::NotFound);
    }

    let pool = pool.inner().clone();
    let ma = auth.machine_account_id.clone();

    let rows = rocket::tokio::task::spawn_blocking(
        move || -> anyhow::Result<Vec<(Project, i32, i32)>> {
            use crate::schema::{machine_account_project_access as mapa, projects};
            let mut conn = pool.get()?;

            let access: Vec<MachineAccountProjectAccess> = mapa::table
                .filter(mapa::machine_account_id.eq(&ma))
                .load(&mut conn)?;
            let ids: Vec<String> = access.iter().map(|a| a.project_id.clone()).collect();

            let projects: Vec<Project> = projects::table
                .filter(
                    projects::id
                        .eq_any(&ids)
                        .and(projects::deleted_date.is_null()),
                )
                .load(&mut conn)?;

            let mut out = Vec::new();
            for p in projects {
                if let Some(a) = access.iter().find(|a| a.project_id == p.id) {
                    out.push((p, a.can_read, a.can_write));
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
        .map(|(p, r, w)| project_response(p, r != 0, w != 0))
        .collect();

    Ok(Json(ListResponse::new(data)))
}

#[get("/projects/<id>")]
pub async fn get_project(
    id: String,
    auth: SmAuth,
    pool: &State<DbPool>,
) -> Result<Json<ProjectResponse>, Status> {
    let pool = pool.inner().clone();
    let ma = auth.machine_account_id.clone();

    let found = rocket::tokio::task::spawn_blocking(
        move || -> anyhow::Result<Option<(Project, i32, i32)>> {
            use crate::schema::{machine_account_project_access as mapa, projects};
            let mut conn = pool.get()?;

            let access: Option<MachineAccountProjectAccess> = mapa::table
                .filter(
                    mapa::machine_account_id
                        .eq(&ma)
                        .and(mapa::project_id.eq(&id)),
                )
                .first(&mut conn)
                .optional()?;
            let Some(a) = access else {
                return Ok(None);
            };
            if a.can_read == 0 {
                return Ok(None);
            }
            let p: Option<Project> = projects::table
                .find(&id)
                .filter(projects::deleted_date.is_null())
                .first(&mut conn)
                .optional()?;
            Ok(p.map(|p| (p, a.can_read, a.can_write)))
        },
    )
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::InternalServerError)?;

    match found {
        Some((p, r, w)) => Ok(Json(project_response(p, r != 0, w != 0))),
        None => Err(Status::NotFound),
    }
}

#[post("/organizations/<org_id>/projects", data = "<req>")]
pub async fn create_project(
    org_id: String,
    auth: SmAuth,
    req: Json<ProjectCreateRequest>,
    pool: &State<DbPool>,
) -> Result<Json<ProjectResponse>, Status> {
    if auth.organization_id != org_id {
        return Err(Status::NotFound);
    }
    let pool = pool.inner().clone();
    let ma = auth.machine_account_id.clone();
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
        // The creating machine account gets read/write on the new project.
        diesel::insert_into(mapa::table)
            .values(&MachineAccountProjectAccess {
                machine_account_id: ma,
                project_id: id,
                can_read: 1,
                can_write: 1,
            })
            .execute(&mut conn)?;
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
    auth: SmAuth,
    req: Json<ProjectUpdateRequest>,
    pool: &State<DbPool>,
) -> Result<Json<ProjectResponse>, Status> {
    let pool = pool.inner().clone();
    let ma = auth.machine_account_id.clone();
    let name = req.name.clone();

    let project = rocket::tokio::task::spawn_blocking(move || -> anyhow::Result<Project> {
        use crate::schema::{machine_account_project_access as mapa, projects};
        let mut conn = pool.get()?;

        let access: Option<MachineAccountProjectAccess> = mapa::table
            .filter(
                mapa::machine_account_id
                    .eq(&ma)
                    .and(mapa::project_id.eq(&id)),
            )
            .first(&mut conn)
            .optional()?;
        let Some(a) = access else {
            anyhow::bail!("not found");
        };
        if a.can_write == 0 {
            anyhow::bail!("no write access");
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
    auth: SmAuth,
    ids: Json<Vec<String>>,
    pool: &State<DbPool>,
) -> Result<Json<ListResponse<BulkDeleteResponse>>, Status> {
    let pool = pool.inner().clone();
    let ma = auth.machine_account_id.clone();
    let ids = ids.into_inner();

    let out = rocket::tokio::task::spawn_blocking(
        move || -> anyhow::Result<Vec<BulkDeleteResponse>> {
            use crate::schema::{machine_account_project_access as mapa, projects};
            let mut conn = pool.get()?;

            let writable: HashSet<String> = mapa::table
                .filter(mapa::machine_account_id.eq(&ma).and(mapa::can_write.eq(1)))
                .select(mapa::project_id)
                .load::<String>(&mut conn)?
                .into_iter()
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
