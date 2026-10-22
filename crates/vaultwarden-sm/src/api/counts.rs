//! Secrets Manager count routes: the small tallies the web vault shows in its navigation.
//!
//! Every count is scoped to what the caller may actually see, so an admin and a member looking at
//! the same organization can get different numbers — exactly what each is allowed to reach.

use diesel::prelude::*;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{get, routes, Route, State};

use crate::access::{rights_in_org, Principal};
use crate::api::dto::OrganizationCountsResponse;
use crate::db::DbPool;

pub fn routes() -> Vec<Route> {
    routes![organization_counts]
}

#[get("/organizations/<org_id>/sm-counts")]
pub async fn organization_counts(
    org_id: String,
    principal: Principal,
    pool: &State<DbPool>,
) -> Result<Json<OrganizationCountsResponse>, Status> {
    if principal.org_access(&org_id).is_none() {
        return Err(Status::NotFound);
    }
    let pool = pool.inner().clone();

    let counts = rocket::tokio::task::spawn_blocking(
        move || -> anyhow::Result<(i64, i64, i64)> {
            use crate::schema::{project_secret as ps, secrets};
            let mut conn = pool.get()?;

            // Projects and service accounts: the readable ones in this organization.
            let project_rights = rights_in_org(&principal.project_access(&mut conn)?, &org_id);
            let readable_projects: Vec<String> = project_rights
                .iter()
                .filter(|(_, r)| r.read)
                .map(|(id, _)| id.clone())
                .collect();

            let service_accounts = rights_in_org(&principal.machine_account_access(&mut conn)?, &org_id)
                .values()
                .filter(|r| r.read)
                .count() as i64;

            // Secrets: distinct non-deleted secrets reachable through those readable projects.
            let secrets = if readable_projects.is_empty() {
                0
            } else {
                let ids: Vec<String> = ps::table
                    .inner_join(secrets::table.on(secrets::id.eq(ps::secret_id)))
                    .filter(
                        ps::project_id
                            .eq_any(&readable_projects)
                            .and(secrets::deleted_date.is_null()),
                    )
                    .select(ps::secret_id)
                    .distinct()
                    .load::<String>(&mut conn)?;
                ids.len() as i64
            };

            Ok((readable_projects.len() as i64, secrets, service_accounts))
        },
    )
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::InternalServerError)?;

    let (projects, secrets, service_accounts) = counts;
    Ok(Json(OrganizationCountsResponse {
        projects,
        secrets,
        service_accounts,
        object: "organizationCounts",
    }))
}
