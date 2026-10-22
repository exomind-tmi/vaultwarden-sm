//! Organization membership resolution against the companion vaultwarden instance.
//!
//! vaultwarden carries no organization membership or role in its session tokens, so we ask
//! vaultwarden itself: `GET /api/accounts/profile` with the user's own bearer token returns the
//! organizations they belong to, each with a role (`type`) and a `status`. We cache the result
//! briefly, so a burst of Secrets Manager requests costs one upstream call — accepting that a
//! membership change takes up to the TTL to be reflected.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Deserialize;

/// How a member's organization role maps onto Secrets Manager authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrgRole {
    /// Owner/Admin: implicit full access to the organization's Secrets Manager.
    Admin,
    /// Everyone else: access only through explicit access policies.
    Member,
}

#[derive(Debug, Clone)]
pub struct Membership {
    pub organization_id: String,
    pub role: OrgRole,
}

// vaultwarden's MembershipStatus::Confirmed (see db/models/organization.rs).
const STATUS_CONFIRMED: i32 = 2;
// vaultwarden's MembershipType: Owner = 0, Admin = 1.
const TYPE_OWNER: i32 = 0;
const TYPE_ADMIN: i32 = 1;

#[derive(Deserialize)]
struct ProfileResponse {
    organizations: Vec<ProfileOrganization>,
}

#[derive(Deserialize)]
struct ProfileOrganization {
    id: String,
    #[serde(rename = "type")]
    role: i32,
    status: i32,
    #[serde(default)]
    enabled: bool,
}

/// Parse a vaultwarden `/api/accounts/profile` body into the caller's confirmed memberships.
/// Pure, so it is unit-tested without a live vaultwarden.
fn parse_memberships(body: &str) -> anyhow::Result<Vec<Membership>> {
    let profile: ProfileResponse = serde_json::from_str(body)?;
    Ok(profile
        .organizations
        .into_iter()
        .filter(|o| o.status == STATUS_CONFIRMED && o.enabled)
        .map(|o| Membership {
            organization_id: o.id,
            role: if o.role == TYPE_OWNER || o.role == TYPE_ADMIN {
                OrgRole::Admin
            } else {
                OrgRole::Member
            },
        })
        .collect())
}

struct CacheEntry {
    fetched_at: Instant,
    memberships: Vec<Membership>,
}

pub struct MembershipResolver {
    http: reqwest::Client,
    profile_url: String,
    ttl: Duration,
    cache: Mutex<HashMap<String, CacheEntry>>,
}

impl MembershipResolver {
    /// `vaultwarden_base` is the internal base URL of vaultwarden (e.g. `http://vaultwarden`),
    /// reachable on the shared docker network — never the public domain, to avoid looping back
    /// out through the edge.
    pub fn new(vaultwarden_base: &str, ttl: Duration) -> anyhow::Result<Self> {
        let base = vaultwarden_base.trim_end_matches('/');
        Ok(Self {
            http: reqwest::Client::builder().build()?,
            profile_url: format!("{base}/api/accounts/profile"),
            ttl,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// Confirmed memberships for `user_id`, using `bearer` (the user's own vaultwarden token) to
    /// authenticate the upstream call. Cached per user for the configured TTL.
    pub async fn resolve(&self, user_id: &str, bearer: &str) -> anyhow::Result<Vec<Membership>> {
        if let Some(hit) = self.cached(user_id) {
            return Ok(hit);
        }
        let body = self
            .http
            .get(&self.profile_url)
            .bearer_auth(bearer)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        let memberships = parse_memberships(&body)?;
        self.store(user_id, &memberships);
        Ok(memberships)
    }

    fn cached(&self, user_id: &str) -> Option<Vec<Membership>> {
        let cache = self.cache.lock().ok()?;
        let entry = cache.get(user_id)?;
        (entry.fetched_at.elapsed() < self.ttl).then(|| entry.memberships.clone())
    }

    fn store(&self, user_id: &str, memberships: &[Membership]) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(
                user_id.to_string(),
                CacheEntry {
                    fetched_at: Instant::now(),
                    memberships: memberships.to_vec(),
                },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // One of each: confirmed owner, confirmed admin, confirmed plain user, confirmed manager,
    // an invited (status 0) and a revoked (status -1) org, plus a disabled one.
    const PROFILE: &str = r#"{
        "object": "profile",
        "id": "user-uuid",
        "organizations": [
            {"id": "org-owner",   "type": 0, "status": 2, "enabled": true},
            {"id": "org-admin",   "type": 1, "status": 2, "enabled": true},
            {"id": "org-user",    "type": 2, "status": 2, "enabled": true},
            {"id": "org-manager", "type": 3, "status": 2, "enabled": true},
            {"id": "org-invited", "type": 2, "status": 0, "enabled": true},
            {"id": "org-revoked", "type": 1, "status": -1, "enabled": true},
            {"id": "org-disabled","type": 1, "status": 2, "enabled": false}
        ]
    }"#;

    fn role_of<'a>(ms: &'a [Membership], org: &str) -> Option<&'a OrgRole> {
        ms.iter().find(|m| m.organization_id == org).map(|m| &m.role)
    }

    #[test]
    fn keeps_only_confirmed_enabled_memberships() {
        let ms = parse_memberships(PROFILE).unwrap();
        let ids: Vec<&str> = ms.iter().map(|m| m.organization_id.as_str()).collect();
        assert_eq!(ids, ["org-owner", "org-admin", "org-user", "org-manager"]);
    }

    #[test]
    fn maps_owner_and_admin_to_admin_role() {
        let ms = parse_memberships(PROFILE).unwrap();
        assert_eq!(role_of(&ms, "org-owner"), Some(&OrgRole::Admin));
        assert_eq!(role_of(&ms, "org-admin"), Some(&OrgRole::Admin));
    }

    #[test]
    fn maps_user_and_manager_to_member_role() {
        let ms = parse_memberships(PROFILE).unwrap();
        assert_eq!(role_of(&ms, "org-user"), Some(&OrgRole::Member));
        assert_eq!(role_of(&ms, "org-manager"), Some(&OrgRole::Member));
    }

    #[test]
    fn empty_organizations_is_no_memberships() {
        let ms = parse_memberships(r#"{"organizations": []}"#).unwrap();
        assert!(ms.is_empty());
    }
}
