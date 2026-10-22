//! Secrets Manager access-policy routes: the granular grants the web vault manages.
//!
//! Four relationships are editable, each a `GET` to read and a `PUT` to replace:
//!  - people on a project        → `user_project_access`
//!  - people on a service account → `user_machine_account_access`
//!  - service accounts on a project (and its inverse, the projects granted to a service account)
//!                                → `machine_account_project_access`
//!
//! Only people manage policies, and only with write access to the anchor resource (a machine
//! account never manages policies); denials return 404. Groups are not modelled in v1 — group
//! request arrays are ignored and group response arrays are always empty. People potential-grantees
//! are intentionally absent: the web vault already has the organization's member list from
//! vaultwarden and resolves names and ids there.

use diesel::prelude::*;
use diesel::SqliteConnection;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{get, put, routes, Route, State};

use crate::access::{Principal, Rights};
use crate::api::dto::{
    AccessPolicyRequest, GrantedAccessPolicyRequest, GrantedProjectAccessPolicyPermissionDetailsResponse,
    GrantedProjectAccessPolicyResponse, ListResponse, PeopleAccessPoliciesRequest,
    PotentialGranteeResponse, ProjectPeopleAccessPoliciesResponse,
    ProjectServiceAccountsAccessPoliciesRequest, ProjectServiceAccountsAccessPoliciesResponse,
    ServiceAccountAccessPolicyResponse, ServiceAccountGrantedPoliciesPermissionDetailsResponse,
    ServiceAccountGrantedPoliciesRequest, ServiceAccountPeopleAccessPoliciesResponse,
    UserAccessPolicyResponse,
};
use crate::db::DbPool;
use crate::models::{MachineAccountProjectAccess, UserMachineAccountAccess, UserProjectAccess};

pub fn routes() -> Vec<Route> {
    routes![
        get_project_people,
        put_project_people,
        get_service_account_people,
        put_service_account_people,
        get_project_service_accounts,
        put_project_service_accounts,
        get_service_account_granted_policies,
        put_service_account_granted_policies,
        service_account_potential_grantees,
        project_potential_grantees,
    ]
}

/// A single grant: the grantee (or granted) id with its rights.
#[derive(Debug, Clone)]
pub struct Grant {
    pub id: String,
    pub rights: Rights,
}

// --- data operations (pure over a connection, so they can be tested without the HTTP layer) ---

fn read_project_people(conn: &mut SqliteConnection, project_id: &str) -> anyhow::Result<Vec<Grant>> {
    use crate::schema::user_project_access as upa;
    let rows: Vec<UserProjectAccess> = upa::table
        .filter(upa::project_id.eq(project_id))
        .load(conn)?;
    Ok(rows.into_iter().map(grant_from_user_project).collect())
}

fn replace_project_people(
    conn: &mut SqliteConnection,
    project_id: &str,
    grants: &[Grant],
) -> anyhow::Result<()> {
    use crate::schema::user_project_access as upa;
    conn.transaction(|conn| {
        diesel::delete(upa::table.filter(upa::project_id.eq(project_id))).execute(conn)?;
        for g in grants {
            diesel::insert_into(upa::table)
                .values(&UserProjectAccess {
                    user_id: g.id.clone(),
                    project_id: project_id.to_string(),
                    can_read: g.rights.read as i32,
                    can_write: g.rights.write as i32,
                })
                .execute(conn)?;
        }
        diesel::result::QueryResult::Ok(())
    })?;
    Ok(())
}

fn read_sa_people(conn: &mut SqliteConnection, ma_id: &str) -> anyhow::Result<Vec<Grant>> {
    use crate::schema::user_machine_account_access as umaa;
    let rows: Vec<UserMachineAccountAccess> = umaa::table
        .filter(umaa::machine_account_id.eq(ma_id))
        .load(conn)?;
    Ok(rows.into_iter().map(grant_from_user_ma).collect())
}

fn replace_sa_people(conn: &mut SqliteConnection, ma_id: &str, grants: &[Grant]) -> anyhow::Result<()> {
    use crate::schema::user_machine_account_access as umaa;
    conn.transaction(|conn| {
        diesel::delete(umaa::table.filter(umaa::machine_account_id.eq(ma_id))).execute(conn)?;
        for g in grants {
            diesel::insert_into(umaa::table)
                .values(&UserMachineAccountAccess {
                    user_id: g.id.clone(),
                    machine_account_id: ma_id.to_string(),
                    can_read: g.rights.read as i32,
                    can_write: g.rights.write as i32,
                })
                .execute(conn)?;
        }
        diesel::result::QueryResult::Ok(())
    })?;
    Ok(())
}

fn read_project_service_accounts(
    conn: &mut SqliteConnection,
    project_id: &str,
) -> anyhow::Result<Vec<Grant>> {
    use crate::schema::machine_account_project_access as mapa;
    let rows: Vec<MachineAccountProjectAccess> = mapa::table
        .filter(mapa::project_id.eq(project_id))
        .load(conn)?;
    Ok(rows
        .into_iter()
        .map(|r| Grant {
            id: r.machine_account_id,
            rights: Rights {
                read: r.can_read != 0,
                write: r.can_write != 0,
            },
        })
        .collect())
}

/// Replace the set of machine accounts granted to a project. The counterpart grants (a machine
/// account's projects) share the same table, so each row is keyed by (machine_account_id, project_id).
fn replace_project_service_accounts(
    conn: &mut SqliteConnection,
    project_id: &str,
    grants: &[Grant],
) -> anyhow::Result<()> {
    use crate::schema::machine_account_project_access as mapa;
    conn.transaction(|conn| {
        diesel::delete(mapa::table.filter(mapa::project_id.eq(project_id))).execute(conn)?;
        for g in grants {
            diesel::insert_into(mapa::table)
                .values(&MachineAccountProjectAccess {
                    machine_account_id: g.id.clone(),
                    project_id: project_id.to_string(),
                    can_read: g.rights.read as i32,
                    can_write: g.rights.write as i32,
                })
                .execute(conn)?;
        }
        diesel::result::QueryResult::Ok(())
    })?;
    Ok(())
}

fn read_sa_granted_projects(conn: &mut SqliteConnection, ma_id: &str) -> anyhow::Result<Vec<Grant>> {
    use crate::schema::machine_account_project_access as mapa;
    let rows: Vec<MachineAccountProjectAccess> = mapa::table
        .filter(mapa::machine_account_id.eq(ma_id))
        .load(conn)?;
    Ok(rows
        .into_iter()
        .map(|r| Grant {
            id: r.project_id,
            rights: Rights {
                read: r.can_read != 0,
                write: r.can_write != 0,
            },
        })
        .collect())
}

fn replace_sa_granted_projects(
    conn: &mut SqliteConnection,
    ma_id: &str,
    grants: &[Grant],
) -> anyhow::Result<()> {
    use crate::schema::machine_account_project_access as mapa;
    conn.transaction(|conn| {
        diesel::delete(mapa::table.filter(mapa::machine_account_id.eq(ma_id))).execute(conn)?;
        for g in grants {
            diesel::insert_into(mapa::table)
                .values(&MachineAccountProjectAccess {
                    machine_account_id: ma_id.to_string(),
                    project_id: g.id.clone(),
                    can_read: g.rights.read as i32,
                    can_write: g.rights.write as i32,
                })
                .execute(conn)?;
        }
        diesel::result::QueryResult::Ok(())
    })?;
    Ok(())
}

fn grant_from_user_project(r: UserProjectAccess) -> Grant {
    Grant {
        id: r.user_id,
        rights: Rights {
            read: r.can_read != 0,
            write: r.can_write != 0,
        },
    }
}

fn grant_from_user_ma(r: UserMachineAccountAccess) -> Grant {
    Grant {
        id: r.user_id,
        rights: Rights {
            read: r.can_read != 0,
            write: r.can_write != 0,
        },
    }
}

/// Ids of the organization's non-deleted projects (for validating grants stay in-org).
fn project_ids_in_org(conn: &mut SqliteConnection, org_id: &str) -> anyhow::Result<Vec<String>> {
    use crate::schema::projects;
    Ok(projects::table
        .filter(
            projects::organization_id
                .eq(org_id)
                .and(projects::deleted_date.is_null()),
        )
        .select(projects::id)
        .load(conn)?)
}

/// Ids of the organization's machine accounts.
fn machine_account_ids_in_org(conn: &mut SqliteConnection, org_id: &str) -> anyhow::Result<Vec<String>> {
    use crate::schema::machine_accounts;
    Ok(machine_accounts::table
        .filter(machine_accounts::organization_id.eq(org_id))
        .select(machine_accounts::id)
        .load(conn)?)
}

// --- authorization: only a user with write access to the anchor resource manages its policies ---

/// The organization a user may manage this project's policies in, or `None` (→ 404). Machines never
/// manage policies.
fn authorize_project(
    principal: &Principal,
    conn: &mut SqliteConnection,
    project_id: &str,
) -> anyhow::Result<Option<String>> {
    if matches!(principal, Principal::Machine { .. }) {
        return Ok(None);
    }
    let access = principal.project_access(conn)?;
    Ok(access
        .get(project_id)
        .filter(|a| a.rights.write)
        .map(|a| a.organization_id.clone()))
}

fn authorize_service_account(
    principal: &Principal,
    conn: &mut SqliteConnection,
    ma_id: &str,
) -> anyhow::Result<Option<String>> {
    if matches!(principal, Principal::Machine { .. }) {
        return Ok(None);
    }
    let access = principal.machine_account_access(conn)?;
    Ok(access
        .get(ma_id)
        .filter(|a| a.rights.write)
        .map(|a| a.organization_id.clone()))
}

fn current_user_id(principal: &Principal) -> Option<&str> {
    match principal {
        Principal::User { user_id, .. } => Some(user_id),
        Principal::Machine { .. } => None,
    }
}

fn user_policy(g: &Grant, current_user: Option<&str>) -> UserAccessPolicyResponse {
    UserAccessPolicyResponse {
        organization_user_id: g.id.clone(),
        organization_user_name: None,
        current_user: current_user == Some(g.id.as_str()),
        read: g.rights.read,
        write: g.rights.write,
        object: "userAccessPolicy",
    }
}

// --- people on a project ---

#[get("/projects/<id>/access-policies/people")]
pub async fn get_project_people(
    id: String,
    principal: Principal,
    pool: &State<DbPool>,
) -> Result<Json<ProjectPeopleAccessPoliciesResponse>, Status> {
    let pool = pool.inner().clone();
    let me = current_user_id(&principal).map(str::to_string);

    let result = rocket::tokio::task::spawn_blocking(move || -> anyhow::Result<Option<Vec<Grant>>> {
        let mut conn = pool.get()?;
        if authorize_project(&principal, &mut conn, &id)?.is_none() {
            return Ok(None);
        }
        Ok(Some(read_project_people(&mut conn, &id)?))
    })
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::InternalServerError)?;

    match result {
        Some(grants) => Ok(Json(ProjectPeopleAccessPoliciesResponse {
            user_access_policies: grants.iter().map(|g| user_policy(g, me.as_deref())).collect(),
            group_access_policies: Vec::new(),
            object: "projectPeopleAccessPolicies",
        })),
        None => Err(Status::NotFound),
    }
}

#[put("/projects/<id>/access-policies/people", data = "<req>")]
pub async fn put_project_people(
    id: String,
    principal: Principal,
    req: Json<PeopleAccessPoliciesRequest>,
    pool: &State<DbPool>,
) -> Result<Json<ProjectPeopleAccessPoliciesResponse>, Status> {
    // Project people policies must each grant read (write is optional).
    let grants = to_grants(&req.user_access_policy_requests);
    if grants.iter().any(|g| !g.rights.read) {
        return Err(Status::BadRequest);
    }
    let pool = pool.inner().clone();
    let me = current_user_id(&principal).map(str::to_string);

    let saved = rocket::tokio::task::spawn_blocking(move || -> anyhow::Result<Option<Vec<Grant>>> {
        let mut conn = pool.get()?;
        if authorize_project(&principal, &mut conn, &id)?.is_none() {
            return Ok(None);
        }
        replace_project_people(&mut conn, &id, &grants)?;
        Ok(Some(read_project_people(&mut conn, &id)?))
    })
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::InternalServerError)?;

    match saved {
        Some(grants) => Ok(Json(ProjectPeopleAccessPoliciesResponse {
            user_access_policies: grants.iter().map(|g| user_policy(g, me.as_deref())).collect(),
            group_access_policies: Vec::new(),
            object: "projectPeopleAccessPolicies",
        })),
        None => Err(Status::NotFound),
    }
}

// --- people on a service account ---

#[get("/service-accounts/<id>/access-policies/people")]
pub async fn get_service_account_people(
    id: String,
    principal: Principal,
    pool: &State<DbPool>,
) -> Result<Json<ServiceAccountPeopleAccessPoliciesResponse>, Status> {
    let pool = pool.inner().clone();
    let me = current_user_id(&principal).map(str::to_string);

    let result = rocket::tokio::task::spawn_blocking(move || -> anyhow::Result<Option<Vec<Grant>>> {
        let mut conn = pool.get()?;
        if authorize_service_account(&principal, &mut conn, &id)?.is_none() {
            return Ok(None);
        }
        Ok(Some(read_sa_people(&mut conn, &id)?))
    })
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::InternalServerError)?;

    match result {
        Some(grants) => Ok(Json(ServiceAccountPeopleAccessPoliciesResponse {
            user_access_policies: grants.iter().map(|g| user_policy(g, me.as_deref())).collect(),
            group_access_policies: Vec::new(),
            object: "serviceAccountAccessPolicies",
        })),
        None => Err(Status::NotFound),
    }
}

#[put("/service-accounts/<id>/access-policies/people", data = "<req>")]
pub async fn put_service_account_people(
    id: String,
    principal: Principal,
    req: Json<PeopleAccessPoliciesRequest>,
    pool: &State<DbPool>,
) -> Result<Json<ServiceAccountPeopleAccessPoliciesResponse>, Status> {
    // Machine-account access must be read and write.
    let grants = to_grants(&req.user_access_policy_requests);
    if grants.iter().any(|g| !(g.rights.read && g.rights.write)) {
        return Err(Status::BadRequest);
    }
    let pool = pool.inner().clone();
    let me = current_user_id(&principal).map(str::to_string);

    let saved = rocket::tokio::task::spawn_blocking(move || -> anyhow::Result<Option<Vec<Grant>>> {
        let mut conn = pool.get()?;
        if authorize_service_account(&principal, &mut conn, &id)?.is_none() {
            return Ok(None);
        }
        replace_sa_people(&mut conn, &id, &grants)?;
        Ok(Some(read_sa_people(&mut conn, &id)?))
    })
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::InternalServerError)?;

    match saved {
        Some(grants) => Ok(Json(ServiceAccountPeopleAccessPoliciesResponse {
            user_access_policies: grants.iter().map(|g| user_policy(g, me.as_deref())).collect(),
            group_access_policies: Vec::new(),
            object: "serviceAccountAccessPolicies",
        })),
        None => Err(Status::NotFound),
    }
}

// --- service accounts on a project ---

#[get("/projects/<id>/access-policies/service-accounts")]
pub async fn get_project_service_accounts(
    id: String,
    principal: Principal,
    pool: &State<DbPool>,
) -> Result<Json<ProjectServiceAccountsAccessPoliciesResponse>, Status> {
    let pool = pool.inner().clone();

    let result = rocket::tokio::task::spawn_blocking(move || -> anyhow::Result<Option<Vec<Grant>>> {
        let mut conn = pool.get()?;
        if authorize_project(&principal, &mut conn, &id)?.is_none() {
            return Ok(None);
        }
        Ok(Some(read_project_service_accounts(&mut conn, &id)?))
    })
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::InternalServerError)?;

    match result {
        Some(grants) => Ok(Json(ProjectServiceAccountsAccessPoliciesResponse {
            service_account_access_policies: grants.iter().map(service_account_policy).collect(),
            object: "ProjectServiceAccountsAccessPolicies",
        })),
        None => Err(Status::NotFound),
    }
}

#[put("/projects/<id>/access-policies/service-accounts", data = "<req>")]
pub async fn put_project_service_accounts(
    id: String,
    principal: Principal,
    req: Json<ProjectServiceAccountsAccessPoliciesRequest>,
    pool: &State<DbPool>,
) -> Result<Json<ProjectServiceAccountsAccessPoliciesResponse>, Status> {
    let grants = to_grants(&req.service_account_access_policy_requests);
    if grants.iter().any(|g| !g.rights.read) {
        return Err(Status::BadRequest);
    }
    let pool = pool.inner().clone();

    let saved = rocket::tokio::task::spawn_blocking(move || -> anyhow::Result<Option<Result<Vec<Grant>, Status>>> {
        let mut conn = pool.get()?;
        let Some(org_id) = authorize_project(&principal, &mut conn, &id)? else {
            return Ok(None);
        };
        // Every granted machine account must belong to the project's organization.
        let valid = machine_account_ids_in_org(&mut conn, &org_id)?;
        if grants.iter().any(|g| !valid.contains(&g.id)) {
            return Ok(Some(Err(Status::BadRequest)));
        }
        replace_project_service_accounts(&mut conn, &id, &grants)?;
        Ok(Some(Ok(read_project_service_accounts(&mut conn, &id)?)))
    })
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::InternalServerError)?;

    match saved {
        Some(Ok(grants)) => Ok(Json(ProjectServiceAccountsAccessPoliciesResponse {
            service_account_access_policies: grants.iter().map(service_account_policy).collect(),
            object: "ProjectServiceAccountsAccessPolicies",
        })),
        Some(Err(status)) => Err(status),
        None => Err(Status::NotFound),
    }
}

// --- projects granted to a service account ---

#[get("/service-accounts/<id>/granted-policies")]
pub async fn get_service_account_granted_policies(
    id: String,
    principal: Principal,
    pool: &State<DbPool>,
) -> Result<Json<ServiceAccountGrantedPoliciesPermissionDetailsResponse>, Status> {
    let pool = pool.inner().clone();

    let result = rocket::tokio::task::spawn_blocking(move || -> anyhow::Result<Option<Vec<Grant>>> {
        let mut conn = pool.get()?;
        if authorize_service_account(&principal, &mut conn, &id)?.is_none() {
            return Ok(None);
        }
        Ok(Some(read_sa_granted_projects(&mut conn, &id)?))
    })
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::InternalServerError)?;

    match result {
        Some(grants) => Ok(Json(ServiceAccountGrantedPoliciesPermissionDetailsResponse {
            granted_project_policies: grants.iter().map(granted_project_policy).collect(),
            object: "ServiceAccountGrantedPoliciesPermissionDetails",
        })),
        None => Err(Status::NotFound),
    }
}

#[put("/service-accounts/<id>/granted-policies", data = "<req>")]
pub async fn put_service_account_granted_policies(
    id: String,
    principal: Principal,
    req: Json<ServiceAccountGrantedPoliciesRequest>,
    pool: &State<DbPool>,
) -> Result<Json<ServiceAccountGrantedPoliciesPermissionDetailsResponse>, Status> {
    let grants = to_granted_grants(&req.project_granted_policy_requests);
    if grants.iter().any(|g| !g.rights.read) {
        return Err(Status::BadRequest);
    }
    let pool = pool.inner().clone();

    let saved = rocket::tokio::task::spawn_blocking(move || -> anyhow::Result<Option<Result<Vec<Grant>, Status>>> {
        let mut conn = pool.get()?;
        let Some(org_id) = authorize_service_account(&principal, &mut conn, &id)? else {
            return Ok(None);
        };
        // Every granted project must belong to the service account's organization.
        let valid = project_ids_in_org(&mut conn, &org_id)?;
        if grants.iter().any(|g| !valid.contains(&g.id)) {
            return Ok(Some(Err(Status::BadRequest)));
        }
        replace_sa_granted_projects(&mut conn, &id, &grants)?;
        Ok(Some(Ok(read_sa_granted_projects(&mut conn, &id)?)))
    })
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::InternalServerError)?;

    match saved {
        Some(Ok(grants)) => Ok(Json(ServiceAccountGrantedPoliciesPermissionDetailsResponse {
            granted_project_policies: grants.iter().map(granted_project_policy).collect(),
            object: "ServiceAccountGrantedPoliciesPermissionDetails",
        })),
        Some(Err(status)) => Err(status),
        None => Err(Status::NotFound),
    }
}

// --- potential grantees (dropdown sources for the web vault) ---

#[get("/organizations/<org_id>/access-policies/service-accounts/potential-grantees")]
pub async fn service_account_potential_grantees(
    org_id: String,
    principal: Principal,
    pool: &State<DbPool>,
) -> Result<Json<ListResponse<PotentialGranteeResponse>>, Status> {
    if principal.org_access(&org_id).is_none() {
        return Err(Status::NotFound);
    }
    let pool = pool.inner().clone();

    let rows = rocket::tokio::task::spawn_blocking(
        move || -> anyhow::Result<Vec<(String, String)>> {
            use crate::schema::machine_accounts;
            let mut conn = pool.get()?;
            Ok(machine_accounts::table
                .filter(machine_accounts::organization_id.eq(&org_id))
                .select((machine_accounts::id, machine_accounts::name_enc))
                .load(&mut conn)?)
        },
    )
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::InternalServerError)?;

    let data = rows
        .into_iter()
        .map(|(id, name)| potential_grantee(id, name, "serviceAccount"))
        .collect();
    Ok(Json(ListResponse::new(data)))
}

#[get("/organizations/<org_id>/access-policies/projects/potential-grantees")]
pub async fn project_potential_grantees(
    org_id: String,
    principal: Principal,
    pool: &State<DbPool>,
) -> Result<Json<ListResponse<PotentialGranteeResponse>>, Status> {
    if principal.org_access(&org_id).is_none() {
        return Err(Status::NotFound);
    }
    let pool = pool.inner().clone();

    let rows = rocket::tokio::task::spawn_blocking(
        move || -> anyhow::Result<Vec<(String, String)>> {
            use crate::schema::projects;
            let mut conn = pool.get()?;
            Ok(projects::table
                .filter(
                    projects::organization_id
                        .eq(&org_id)
                        .and(projects::deleted_date.is_null()),
                )
                .select((projects::id, projects::name_enc))
                .load(&mut conn)?)
        },
    )
    .await
    .map_err(|_| Status::InternalServerError)?
    .map_err(|_| Status::InternalServerError)?;

    let data = rows
        .into_iter()
        .map(|(id, name)| potential_grantee(id, name, "project"))
        .collect();
    Ok(Json(ListResponse::new(data)))
}

// --- response builders ---

fn service_account_policy(g: &Grant) -> ServiceAccountAccessPolicyResponse {
    ServiceAccountAccessPolicyResponse {
        service_account_id: g.id.clone(),
        service_account_name: None,
        read: g.rights.read,
        write: g.rights.write,
        object: "serviceAccountProjectAccessPolicy",
    }
}

fn granted_project_policy(g: &Grant) -> GrantedProjectAccessPolicyPermissionDetailsResponse {
    GrantedProjectAccessPolicyPermissionDetailsResponse {
        access_policy: GrantedProjectAccessPolicyResponse {
            granted_project_id: g.id.clone(),
            granted_project_name: None,
            read: g.rights.read,
            write: g.rights.write,
            object: "grantedProjectAccessPolicy",
        },
        // The caller is a writer on the service account; the web vault refines visibility itself.
        has_permission: true,
        object: "grantedProjectAccessPolicyPermissionDetails",
    }
}

fn potential_grantee(id: String, name: String, kind: &'static str) -> PotentialGranteeResponse {
    PotentialGranteeResponse {
        id,
        name,
        kind,
        email: None,
        current_user_in_group: false,
        current_user: false,
        object: "potentialGrantee",
    }
}

fn to_grants(reqs: &[AccessPolicyRequest]) -> Vec<Grant> {
    reqs.iter()
        .map(|r| Grant {
            id: r.grantee_id.clone(),
            rights: Rights {
                read: r.read,
                write: r.write,
            },
        })
        .collect()
}

fn to_granted_grants(reqs: &[GrantedAccessPolicyRequest]) -> Vec<Grant> {
    reqs.iter()
        .map(|r| Grant {
            id: r.granted_id.clone(),
            rights: Rights {
                read: r.read,
                write: r.write,
            },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::models::{MachineAccount, Organization, Project};

    const ORG: &str = "aaaaaaaa-0000-0000-0000-000000000000";
    const PROJECT: &str = "pppppppp-0000-0000-0000-000000000000";
    const MA: &str = "mmmmmmmm-0000-0000-0000-000000000000";
    const USER1: &str = "11111111-0000-0000-0000-000000000000";
    const USER2: &str = "22222222-0000-0000-0000-000000000000";

    fn conn() -> diesel::r2d2::PooledConnection<diesel::r2d2::ConnectionManager<SqliteConnection>> {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("vwsm-ap-{}.db", uuid::Uuid::new_v4()));
        let pool = db::init_pool(path.to_str().unwrap()).unwrap();
        db::run_migrations(&pool).unwrap();
        let mut c = pool.get().unwrap();
        let now = "2026-10-22T00:00:00Z".to_string();
        diesel::insert_into(crate::schema::organizations::table)
            .values(&Organization {
                id: ORG.into(),
                name: "org".into(),
                creation_date: now.clone(),
                revision_date: now.clone(),
            })
            .execute(&mut c)
            .unwrap();
        diesel::insert_into(crate::schema::projects::table)
            .values(&Project {
                id: PROJECT.into(),
                organization_id: ORG.into(),
                name_enc: "2.p|p|p".into(),
                creation_date: now.clone(),
                revision_date: now.clone(),
                deleted_date: None,
            })
            .execute(&mut c)
            .unwrap();
        diesel::insert_into(crate::schema::machine_accounts::table)
            .values(&MachineAccount {
                id: MA.into(),
                organization_id: ORG.into(),
                name_enc: "2.m|m|m".into(),
                creation_date: now.clone(),
                revision_date: now,
            })
            .execute(&mut c)
            .unwrap();
        c
    }

    fn grant(id: &str, read: bool, write: bool) -> Grant {
        Grant {
            id: id.into(),
            rights: Rights { read, write },
        }
    }

    #[test]
    fn project_people_replace_is_idempotent_and_overwrites() {
        let mut c = conn();
        replace_project_people(&mut c, PROJECT, &[grant(USER1, true, false), grant(USER2, true, true)])
            .unwrap();
        let mut got = read_project_people(&mut c, PROJECT).unwrap();
        got.sort_by(|a, b| a.id.cmp(&b.id));
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].id, USER1);
        assert_eq!(got[0].rights, Rights { read: true, write: false });

        // Replacing wipes the previous set — USER1 is dropped, USER2 upgraded stays.
        replace_project_people(&mut c, PROJECT, &[grant(USER2, true, true)]).unwrap();
        let got = read_project_people(&mut c, PROJECT).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, USER2);
    }

    #[test]
    fn sa_people_round_trips() {
        let mut c = conn();
        replace_sa_people(&mut c, MA, &[grant(USER1, true, true)]).unwrap();
        let got = read_sa_people(&mut c, MA).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, USER1);
        assert!(got[0].rights.read && got[0].rights.write);
    }

    #[test]
    fn project_service_accounts_and_sa_granted_projects_are_two_views_of_one_table() {
        let mut c = conn();
        // Grant the project to the machine account from the project side.
        replace_project_service_accounts(&mut c, PROJECT, &[grant(MA, true, true)]).unwrap();

        // The same row reads back from the service-account side as a granted project.
        let granted = read_sa_granted_projects(&mut c, MA).unwrap();
        assert_eq!(granted.len(), 1);
        assert_eq!(granted[0].id, PROJECT);
        assert!(granted[0].rights.write);

        // Replacing from the service-account side clears it.
        replace_sa_granted_projects(&mut c, MA, &[]).unwrap();
        assert!(read_project_service_accounts(&mut c, PROJECT).unwrap().is_empty());
    }
}
