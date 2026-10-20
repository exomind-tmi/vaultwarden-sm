//! Secrets Manager project routes.

use diesel::prelude::*;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{get, routes, Route, State};

use crate::api::auth::SmAuth;
use crate::api::dto::{ListResponse, ProjectResponse};
use crate::db::DbPool;
use crate::models::{MachineAccountProjectAccess, Project};

pub fn routes() -> Vec<Route> {
    routes![list_projects]
}

#[get("/organizations/<org_id>/projects")]
pub async fn list_projects(
    org_id: String,
    auth: SmAuth,
    pool: &State<DbPool>,
) -> Result<Json<ListResponse<ProjectResponse>>, Status> {
    // Isolation: a token scoped to another org must not learn this one exists.
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
        .map(|(p, r, w)| ProjectResponse {
            id: p.id,
            organization_id: p.organization_id,
            name: p.name_enc,
            creation_date: p.creation_date,
            revision_date: p.revision_date,
            read: r != 0,
            write: w != 0,
            object: "project",
        })
        .collect();

    Ok(Json(ListResponse::new(data)))
}
