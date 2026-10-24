//! Authorization: turning an authenticated principal into the Secrets Manager resources it may
//! read or write.
//!
//! Two kinds of principal reach the SM API over the same URLs:
//!  - a **machine account** (one of our own access tokens), scoped to its single organization via
//!    explicit project grants (`machine_account_project_access`);
//!  - an **organization member** (a vaultwarden user), where Owners/Admins get implicit full
//!    access to their org's Secrets Manager and everyone else gets only what access policies grant
//!    (`user_project_access`).
//!
//! Both collapse to the one question the handlers ask — "which projects can this principal read or
//! write?" — answered by [`Principal::project_access`]. Secrets are reached through their projects,
//! except for an Owner/Admin, who sees every secret of the organization
//! ([`Principal::admin_org_ids`]) — including one with no project, or whose project was deleted.
//! The same machinery answers the parallel question for
//! machine accounts ([`Principal::machine_account_access`]) so the service-account endpoints share
//! one authorization model.

use std::collections::{HashMap, HashSet};

use diesel::prelude::*;
use diesel::SqliteConnection;

use crate::membership::{Membership, OrgRole};
use crate::models::{MachineAccountProjectAccess, UserMachineAccountAccess, UserProjectAccess};

/// Read/write rights on a single resource.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Rights {
    pub read: bool,
    pub write: bool,
}

/// Rights on a resource plus the organization it belongs to (so organization-scoped endpoints can
/// filter a cross-org map without re-querying). Used for both projects and machine accounts.
#[derive(Debug, Clone)]
pub struct ResourceAccess {
    pub rights: Rights,
    pub organization_id: String,
}

/// An authenticated caller of the Secrets Manager API.
pub enum Principal {
    Machine {
        machine_account_id: String,
        organization_id: String,
    },
    User {
        user_id: String,
        memberships: Vec<Membership>,
    },
}

/// The principal's standing in a given organization.
pub struct OrgAccess {
    /// Owner/Admin (full access), as opposed to a regular member (access policies only). A machine
    /// account is never an admin — it only ever has its explicit grants.
    pub is_admin: bool,
}

impl Principal {
    /// Gate an organization-scoped request. `None` means "no access" — handlers translate that to
    /// 404, so a caller cannot even probe which organizations exist.
    pub fn org_access(&self, org_id: &str) -> Option<OrgAccess> {
        match self {
            Principal::Machine { organization_id, .. } => {
                (organization_id == org_id).then_some(OrgAccess { is_admin: false })
            }
            Principal::User { memberships, .. } => memberships
                .iter()
                .find(|m| m.organization_id == org_id)
                .map(|m| OrgAccess {
                    is_admin: m.role == OrgRole::Admin,
                }),
        }
    }

    /// The organizations where this principal is an Owner/Admin and so sees every secret, not just
    /// those reachable through its projects. A machine account has none.
    pub fn admin_org_ids(&self) -> Vec<String> {
        match self {
            Principal::Machine { .. } => Vec::new(),
            Principal::User { memberships, .. } => admin_orgs(memberships),
        }
    }

    /// Every project this principal can reach, keyed by project id, across all organizations it
    /// belongs to. The source differs by principal kind; the shape does not.
    pub fn project_access(
        &self,
        conn: &mut SqliteConnection,
    ) -> anyhow::Result<HashMap<String, ResourceAccess>> {
        match self {
            Principal::Machine {
                machine_account_id,
                organization_id,
            } => machine_project_access(conn, machine_account_id, organization_id),
            Principal::User {
                user_id,
                memberships,
            } => user_project_access_map(conn, user_id, memberships),
        }
    }

    /// Every machine account this principal may manage, keyed by machine-account id. Machine
    /// accounts are managed by people only: an Owner/Admin manages every machine account in their
    /// organizations, a member manages only those granted by `user_machine_account_access`, and a
    /// machine account manages none (it cannot administer itself or its peers).
    pub fn machine_account_access(
        &self,
        conn: &mut SqliteConnection,
    ) -> anyhow::Result<HashMap<String, ResourceAccess>> {
        match self {
            Principal::Machine { .. } => Ok(HashMap::new()),
            Principal::User {
                user_id,
                memberships,
            } => user_machine_account_access_map(conn, user_id, memberships),
        }
    }
}

fn machine_project_access(
    conn: &mut SqliteConnection,
    machine_account_id: &str,
    organization_id: &str,
) -> anyhow::Result<HashMap<String, ResourceAccess>> {
    use crate::schema::machine_account_project_access as mapa;

    // A machine account's grants only ever reference projects of its own organization (enforced
    // when the grant is created), so the org is the account's org.
    let rows: Vec<MachineAccountProjectAccess> = mapa::table
        .filter(mapa::machine_account_id.eq(machine_account_id))
        .load(conn)?;
    Ok(rows
        .into_iter()
        .map(|r| {
            (
                r.project_id,
                ResourceAccess {
                    rights: Rights {
                        read: r.can_read != 0,
                        write: r.can_write != 0,
                    },
                    organization_id: organization_id.to_string(),
                },
            )
        })
        .collect())
}

fn user_project_access_map(
    conn: &mut SqliteConnection,
    user_id: &str,
    memberships: &[Membership],
) -> anyhow::Result<HashMap<String, ResourceAccess>> {
    use crate::schema::{projects, user_project_access as upa};

    let admin_orgs: Vec<String> = admin_orgs(memberships);
    let member_orgs: HashSet<&str> = member_orgs(memberships);

    let mut out: HashMap<String, ResourceAccess> = HashMap::new();

    // Admins see every non-deleted project in their organizations, read and write.
    if !admin_orgs.is_empty() {
        let admin_projects: Vec<(String, String)> = projects::table
            .filter(
                projects::organization_id
                    .eq_any(&admin_orgs)
                    .and(projects::deleted_date.is_null()),
            )
            .select((projects::id, projects::organization_id))
            .load(conn)?;
        for (id, org) in admin_projects {
            out.insert(
                id,
                ResourceAccess {
                    rights: Rights {
                        read: true,
                        write: true,
                    },
                    organization_id: org,
                },
            );
        }
    }

    // Explicit grants, but only for projects that still exist and live in an organization the user
    // currently belongs to. A grant left over from a membership that has since been revoked must
    // not keep granting access. Admin orgs are already fully covered above, so `or_insert` keeps
    // the broader admin rights on any overlap.
    let grants: Vec<UserProjectAccess> = upa::table
        .filter(upa::user_id.eq(user_id))
        .load(conn)?;
    if !grants.is_empty() {
        let granted_ids: Vec<String> = grants.iter().map(|g| g.project_id.clone()).collect();
        let proj_orgs: HashMap<String, String> = projects::table
            .filter(
                projects::id
                    .eq_any(&granted_ids)
                    .and(projects::deleted_date.is_null()),
            )
            .select((projects::id, projects::organization_id))
            .load::<(String, String)>(conn)?
            .into_iter()
            .collect();

        for g in grants {
            let Some(org) = proj_orgs.get(&g.project_id) else {
                continue; // project deleted or gone
            };
            if !member_orgs.contains(org.as_str()) {
                continue; // no longer a member of that org
            }
            out.entry(g.project_id).or_insert(ResourceAccess {
                rights: Rights {
                    read: g.can_read != 0,
                    write: g.can_write != 0,
                },
                organization_id: org.clone(),
            });
        }
    }

    Ok(out)
}

fn user_machine_account_access_map(
    conn: &mut SqliteConnection,
    user_id: &str,
    memberships: &[Membership],
) -> anyhow::Result<HashMap<String, ResourceAccess>> {
    use crate::schema::{machine_accounts, user_machine_account_access as umaa};

    let admin_orgs: Vec<String> = admin_orgs(memberships);
    let member_orgs: HashSet<&str> = member_orgs(memberships);

    let mut out: HashMap<String, ResourceAccess> = HashMap::new();

    // Admins manage every machine account in their organizations, read and write.
    if !admin_orgs.is_empty() {
        let admin_mas: Vec<(String, String)> = machine_accounts::table
            .filter(machine_accounts::organization_id.eq_any(&admin_orgs))
            .select((machine_accounts::id, machine_accounts::organization_id))
            .load(conn)?;
        for (id, org) in admin_mas {
            out.insert(
                id,
                ResourceAccess {
                    rights: Rights {
                        read: true,
                        write: true,
                    },
                    organization_id: org,
                },
            );
        }
    }

    // Explicit grants, valid only for machine accounts that still exist in an organization the user
    // currently belongs to. Admin orgs are already covered above, so `or_insert` preserves the
    // broader admin rights on overlap. (Machine accounts have no soft-delete, so existence is enough.)
    let grants: Vec<UserMachineAccountAccess> = umaa::table
        .filter(umaa::user_id.eq(user_id))
        .load(conn)?;
    if !grants.is_empty() {
        let granted_ids: Vec<String> = grants.iter().map(|g| g.machine_account_id.clone()).collect();
        let ma_orgs: HashMap<String, String> = machine_accounts::table
            .filter(machine_accounts::id.eq_any(&granted_ids))
            .select((machine_accounts::id, machine_accounts::organization_id))
            .load::<(String, String)>(conn)?
            .into_iter()
            .collect();

        for g in grants {
            let Some(org) = ma_orgs.get(&g.machine_account_id) else {
                continue; // machine account gone
            };
            if !member_orgs.contains(org.as_str()) {
                continue; // no longer a member of that org
            }
            out.entry(g.machine_account_id).or_insert(ResourceAccess {
                rights: Rights {
                    read: g.can_read != 0,
                    write: g.can_write != 0,
                },
                organization_id: org.clone(),
            });
        }
    }

    Ok(out)
}

fn admin_orgs(memberships: &[Membership]) -> Vec<String> {
    memberships
        .iter()
        .filter(|m| m.role == OrgRole::Admin)
        .map(|m| m.organization_id.clone())
        .collect()
}

fn member_orgs(memberships: &[Membership]) -> HashSet<&str> {
    memberships
        .iter()
        .map(|m| m.organization_id.as_str())
        .collect()
}

/// Resource rights restricted to one organization — for organization-scoped endpoints.
pub fn rights_in_org(
    access: &HashMap<String, ResourceAccess>,
    org_id: &str,
) -> HashMap<String, Rights> {
    access
        .iter()
        .filter(|(_, a)| a.organization_id == org_id)
        .map(|(id, a)| (id.clone(), a.rights))
        .collect()
}

/// Resource rights across every organization — for endpoints that address a resource by id without
/// an organization in the path.
pub fn rights_all(access: &HashMap<String, ResourceAccess>) -> HashMap<String, Rights> {
    access
        .iter()
        .map(|(id, a)| (id.clone(), a.rights))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::models::{MachineAccount, Organization, Project};

    const ORG_A: &str = "aaaaaaaa-0000-0000-0000-000000000000";
    const ORG_B: &str = "bbbbbbbb-0000-0000-0000-000000000000";
    const USER: &str = "11111111-0000-0000-0000-000000000000";
    const MA: &str = "22222222-0000-0000-0000-000000000000";

    fn conn() -> diesel::r2d2::PooledConnection<diesel::r2d2::ConnectionManager<SqliteConnection>> {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("vwsm-access-{}.db", uuid::Uuid::new_v4()));
        let pool = db::init_pool(path.to_str().unwrap()).unwrap();
        db::run_migrations(&pool).unwrap();
        pool.get().unwrap()
    }

    fn now() -> String {
        "2026-10-22T00:00:00Z".to_string()
    }

    fn seed_org(conn: &mut SqliteConnection, id: &str) {
        use crate::schema::organizations;
        diesel::insert_into(organizations::table)
            .values(&Organization {
                id: id.into(),
                name: "org".into(),
                creation_date: now(),
                revision_date: now(),
            })
            .execute(conn)
            .unwrap();
    }

    fn seed_project(conn: &mut SqliteConnection, id: &str, org: &str, deleted: bool) {
        use crate::schema::projects;
        diesel::insert_into(projects::table)
            .values(&Project {
                id: id.into(),
                organization_id: org.into(),
                name_enc: "2.p|p|p".into(),
                creation_date: now(),
                revision_date: now(),
                deleted_date: deleted.then(now),
            })
            .execute(conn)
            .unwrap();
    }

    fn grant_user(conn: &mut SqliteConnection, project: &str, read: i32, write: i32) {
        use crate::schema::user_project_access as upa;
        diesel::insert_into(upa::table)
            .values(&UserProjectAccess {
                user_id: USER.into(),
                project_id: project.into(),
                can_read: read,
                can_write: write,
            })
            .execute(conn)
            .unwrap();
    }

    fn member(org: &str, role: OrgRole) -> Membership {
        Membership {
            organization_id: org.into(),
            role,
        }
    }

    #[test]
    fn org_access_gate() {
        let machine = Principal::Machine {
            machine_account_id: MA.into(),
            organization_id: ORG_A.into(),
        };
        assert!(machine.org_access(ORG_A).is_some());
        assert!(!machine.org_access(ORG_A).unwrap().is_admin);
        assert!(machine.org_access(ORG_B).is_none());

        let user = Principal::User {
            user_id: USER.into(),
            memberships: vec![member(ORG_A, OrgRole::Admin), member(ORG_B, OrgRole::Member)],
        };
        assert!(user.org_access(ORG_A).unwrap().is_admin);
        assert!(!user.org_access(ORG_B).unwrap().is_admin);
        assert!(user.org_access("cccccccc-0000-0000-0000-000000000000").is_none());
    }

    #[test]
    fn admin_sees_all_non_deleted_projects_of_their_org() {
        let mut c = conn();
        seed_org(&mut c, ORG_A);
        seed_org(&mut c, ORG_B);
        seed_project(&mut c, "p-a1", ORG_A, false);
        seed_project(&mut c, "p-a2", ORG_A, false);
        seed_project(&mut c, "p-a-del", ORG_A, true);
        seed_project(&mut c, "p-b1", ORG_B, false); // different org, user not a member

        let user = Principal::User {
            user_id: USER.into(),
            memberships: vec![member(ORG_A, OrgRole::Admin)],
        };
        let access = user.project_access(&mut c).unwrap();
        let mut ids: Vec<&String> = access.keys().collect();
        ids.sort();
        assert_eq!(ids, ["p-a1", "p-a2"]);
        assert!(access["p-a1"].rights.read && access["p-a1"].rights.write);
    }

    #[test]
    fn member_sees_only_valid_grants() {
        let mut c = conn();
        seed_org(&mut c, ORG_A);
        seed_org(&mut c, ORG_B);
        seed_project(&mut c, "p-a1", ORG_A, false); // granted, member -> visible
        seed_project(&mut c, "p-a-del", ORG_A, true); // granted but deleted -> hidden
        seed_project(&mut c, "p-b1", ORG_B, false); // granted but not a member of B -> hidden

        grant_user(&mut c, "p-a1", 1, 0);
        grant_user(&mut c, "p-a-del", 1, 1);
        grant_user(&mut c, "p-b1", 1, 1);

        let user = Principal::User {
            user_id: USER.into(),
            memberships: vec![member(ORG_A, OrgRole::Member)],
        };
        let access = user.project_access(&mut c).unwrap();
        let ids: Vec<&String> = access.keys().collect();
        assert_eq!(ids, ["p-a1"]);
        assert_eq!(
            access["p-a1"].rights,
            Rights {
                read: true,
                write: false
            }
        );
    }

    #[test]
    fn machine_sees_its_grants() {
        use crate::schema::machine_account_project_access as mapa;
        let mut c = conn();
        seed_org(&mut c, ORG_A);
        seed_project(&mut c, "p-a1", ORG_A, false);
        diesel::insert_into(crate::schema::machine_accounts::table)
            .values(&MachineAccount {
                id: MA.into(),
                organization_id: ORG_A.into(),
                name_enc: "2.x|y|z".into(),
                creation_date: now(),
                revision_date: now(),
            })
            .execute(&mut c)
            .unwrap();
        diesel::insert_into(mapa::table)
            .values(&MachineAccountProjectAccess {
                machine_account_id: MA.into(),
                project_id: "p-a1".into(),
                can_read: 1,
                can_write: 1,
            })
            .execute(&mut c)
            .unwrap();

        let machine = Principal::Machine {
            machine_account_id: MA.into(),
            organization_id: ORG_A.into(),
        };
        let access = machine.project_access(&mut c).unwrap();
        assert_eq!(access.len(), 1);
        assert_eq!(access["p-a1"].organization_id, ORG_A);
        assert!(access["p-a1"].rights.write);
    }

    fn seed_ma(conn: &mut SqliteConnection, id: &str, org: &str) {
        use crate::schema::machine_accounts;
        diesel::insert_into(machine_accounts::table)
            .values(&MachineAccount {
                id: id.into(),
                organization_id: org.into(),
                name_enc: "2.x|y|z".into(),
                creation_date: now(),
                revision_date: now(),
            })
            .execute(conn)
            .unwrap();
    }

    fn grant_user_ma(conn: &mut SqliteConnection, ma: &str, read: i32, write: i32) {
        use crate::schema::user_machine_account_access as umaa;
        diesel::insert_into(umaa::table)
            .values(&UserMachineAccountAccess {
                user_id: USER.into(),
                machine_account_id: ma.into(),
                can_read: read,
                can_write: write,
            })
            .execute(conn)
            .unwrap();
    }

    #[test]
    fn admin_manages_all_machine_accounts_of_their_org() {
        let mut c = conn();
        seed_org(&mut c, ORG_A);
        seed_org(&mut c, ORG_B);
        seed_ma(&mut c, "ma-a1", ORG_A);
        seed_ma(&mut c, "ma-a2", ORG_A);
        seed_ma(&mut c, "ma-b1", ORG_B); // different org, user not a member

        let user = Principal::User {
            user_id: USER.into(),
            memberships: vec![member(ORG_A, OrgRole::Admin)],
        };
        let access = user.machine_account_access(&mut c).unwrap();
        let mut ids: Vec<&String> = access.keys().collect();
        ids.sort();
        assert_eq!(ids, ["ma-a1", "ma-a2"]);
        assert!(access["ma-a1"].rights.read && access["ma-a1"].rights.write);
    }

    #[test]
    fn member_manages_only_valid_machine_account_grants() {
        let mut c = conn();
        seed_org(&mut c, ORG_A);
        seed_org(&mut c, ORG_B);
        seed_ma(&mut c, "ma-a1", ORG_A); // granted, member -> visible
        seed_ma(&mut c, "ma-b1", ORG_B); // granted but not a member of B -> hidden

        grant_user_ma(&mut c, "ma-a1", 1, 1);
        grant_user_ma(&mut c, "ma-b1", 1, 1);
        // A grant to a machine account that no longer exists cannot occur: the FK cascades, deleting
        // the grant with the account. The "account gone" branch stays as defence in depth.

        let user = Principal::User {
            user_id: USER.into(),
            memberships: vec![member(ORG_A, OrgRole::Member)],
        };
        let access = user.machine_account_access(&mut c).unwrap();
        let ids: Vec<&String> = access.keys().collect();
        assert_eq!(ids, ["ma-a1"]);
        assert!(access["ma-a1"].rights.write);
    }

    #[test]
    fn machine_manages_no_machine_accounts() {
        let mut c = conn();
        seed_org(&mut c, ORG_A);
        seed_ma(&mut c, MA, ORG_A);

        let machine = Principal::Machine {
            machine_account_id: MA.into(),
            organization_id: ORG_A.into(),
        };
        assert!(machine.machine_account_access(&mut c).unwrap().is_empty());
    }
}
