//! Response DTOs matching the Secrets Manager API wire format.

use serde::Serialize;

/// Generic `{ "data": [...], "continuationToken": null, "object": "list" }` envelope.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListResponse<T> {
    pub data: Vec<T>,
    pub continuation_token: Option<String>,
    pub object: &'static str,
}

impl<T> ListResponse<T> {
    pub fn new(data: Vec<T>) -> Self {
        Self {
            data,
            continuation_token: None,
            object: "list",
        }
    }
}

#[derive(Serialize, Clone)]
pub struct ProjectRef {
    pub id: String,
    /// Encrypted (EncString).
    pub name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectResponse {
    pub id: String,
    pub organization_id: String,
    /// Encrypted (EncString).
    pub name: String,
    pub creation_date: String,
    pub revision_date: String,
    pub read: bool,
    pub write: bool,
    pub object: &'static str,
}

/// Secret in a list: metadata only, no value/note.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretListItem {
    pub id: String,
    pub organization_id: String,
    pub key: String,
    pub creation_date: String,
    pub revision_date: String,
    pub projects: Vec<ProjectRef>,
    pub read: bool,
    pub write: bool,
}

#[derive(Serialize)]
pub struct SecretsListResponse {
    pub secrets: Vec<SecretListItem>,
    pub projects: Vec<ProjectRef>,
}

/// Single secret with the decrypted-by-client value and note.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretResponse {
    pub read: bool,
    pub write: bool,
    pub id: String,
    pub organization_id: String,
    pub key: String,
    pub value: String,
    pub note: Option<String>,
    pub creation_date: String,
    pub revision_date: String,
    pub projects: Vec<ProjectRef>,
    pub object: &'static str,
}

/// Secret as it appears in a sync payload (with value/note), `object: "baseSecret"`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BaseSecret {
    pub id: String,
    pub organization_id: String,
    pub key: String,
    pub value: String,
    pub note: Option<String>,
    pub creation_date: String,
    pub revision_date: String,
    pub projects: Vec<ProjectRef>,
    pub object: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    pub has_changes: bool,
    pub secrets: ListResponse<BaseSecret>,
    pub object: &'static str,
}

// --- request bodies ---

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretCreateRequest {
    pub key: String,
    pub value: String,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub project_ids: Option<Vec<String>>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretUpdateRequest {
    pub key: String,
    pub value: String,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub project_ids: Option<Vec<String>>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetByIdsRequest {
    pub ids: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkDeleteResponse {
    pub id: String,
    pub error: Option<String>,
    pub object: &'static str,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectCreateRequest {
    pub name: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectUpdateRequest {
    pub name: String,
}

// --- service accounts ---

/// A machine account as the Secrets Manager API exposes it (Bitwarden calls these "service
/// accounts"). The canonical shape, shared by the admin control plane and the user-facing API.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccountResponse {
    pub id: String,
    pub organization_id: String,
    /// Encrypted (EncString).
    pub name: String,
    pub creation_date: String,
    pub revision_date: String,
    pub object: &'static str,
}

impl From<crate::models::MachineAccount> for ServiceAccountResponse {
    fn from(m: crate::models::MachineAccount) -> Self {
        ServiceAccountResponse {
            id: m.id,
            organization_id: m.organization_id,
            name: m.name_enc,
            creation_date: m.creation_date,
            revision_date: m.revision_date,
            object: "serviceAccount",
        }
    }
}

/// A service account plus the number of secrets it can reach — the web vault's list view.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccountDetailsResponse {
    #[serde(flatten)]
    pub service_account: ServiceAccountResponse,
    pub access_to_secrets: i64,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccountCreateRequest {
    pub name: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccountUpdateRequest {
    pub name: String,
}

// --- access tokens (user-facing) ---

/// Creation request: the browser holds the organization key, so it ships the already-encrypted
/// payload (org key wrapped under the token key) and `key` (token key wrapped under the org key).
/// The server contributes only the client secret.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessTokenCreateRequest {
    pub name: String,
    pub encrypted_payload: String,
    pub key: String,
    #[serde(default)]
    pub expire_at: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeAccessTokensRequest {
    pub ids: Vec<String>,
}

/// An access token in a list: metadata only, never the secret (shown once, at creation).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessTokenItemResponse {
    pub id: String,
    /// Encrypted (EncString).
    pub name: String,
    pub scopes: Vec<String>,
    pub expire_at: Option<String>,
    pub creation_date: String,
    pub revision_date: String,
    pub object: &'static str,
}

impl From<crate::models::AccessToken> for AccessTokenItemResponse {
    fn from(t: crate::models::AccessToken) -> Self {
        let scopes = serde_json::from_str(&t.scope).unwrap_or_default();
        AccessTokenItemResponse {
            id: t.id,
            name: t.name_enc,
            scopes,
            expire_at: t.expire_at,
            creation_date: t.creation_date,
            revision_date: t.revision_date,
            object: "accessToken",
        }
    }
}

/// The one-time creation response: carries the plaintext client secret, which the browser splices
/// into the full access-token string. The server never stores or returns it again.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessTokenCreationResponse {
    pub id: String,
    /// Encrypted (EncString).
    pub name: String,
    pub client_secret: String,
    pub expire_at: Option<String>,
    pub creation_date: String,
    pub revision_date: String,
    pub object: &'static str,
}

// --- counts ---

/// Organization-level Secrets Manager tallies, each scoped to what the caller may see.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationCountsResponse {
    pub projects: i64,
    pub secrets: i64,
    pub service_accounts: i64,
    pub object: &'static str,
}

// --- access policies ---
//
// Grantee ids are vaultwarden user UUIDs (people), machine-account ids, or project ids, matching
// what the SM API stores. Groups are not modelled in v1: the request arrays are accepted and the
// response arrays are always empty, so the wire shape stays Bitwarden-compatible.

/// A grant by grantee id with read/write — the unit of a people or service-account policy.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessPolicyRequest {
    pub grantee_id: String,
    pub read: bool,
    pub write: bool,
}

/// A grant addressed by the granted resource's id (used when a service account is granted projects).
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantedAccessPolicyRequest {
    pub granted_id: String,
    pub read: bool,
    pub write: bool,
}

/// PUT body for people policies on a project or a service account. A `groupAccessPolicyRequests`
/// array, if sent, is ignored (serde drops the unknown field): groups are not modelled in v1.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeopleAccessPoliciesRequest {
    #[serde(default)]
    pub user_access_policy_requests: Vec<AccessPolicyRequest>,
}

/// PUT body for the service accounts granted access to a project.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectServiceAccountsAccessPoliciesRequest {
    #[serde(default)]
    pub service_account_access_policy_requests: Vec<AccessPolicyRequest>,
}

/// PUT body for the projects a service account is granted.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccountGrantedPoliciesRequest {
    #[serde(default)]
    pub project_granted_policy_requests: Vec<GrantedAccessPolicyRequest>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserAccessPolicyResponse {
    /// The granted user's vaultwarden UUID (the SM API calls this the organization-user id).
    pub organization_user_id: String,
    /// The display name is resolved by the web vault from vaultwarden; the SM store does not keep it.
    pub organization_user_name: Option<String>,
    pub current_user: bool,
    pub read: bool,
    pub write: bool,
    pub object: &'static str,
}

/// Groups are not modelled in v1; this exists only so the response arrays keep their Bitwarden shape.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupAccessPolicyResponse {
    pub group_id: String,
    pub group_name: Option<String>,
    pub current_user_in_group: bool,
    pub read: bool,
    pub write: bool,
    pub object: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccountAccessPolicyResponse {
    pub service_account_id: String,
    pub service_account_name: Option<String>,
    pub read: bool,
    pub write: bool,
    pub object: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantedProjectAccessPolicyResponse {
    pub granted_project_id: String,
    pub granted_project_name: Option<String>,
    pub read: bool,
    pub write: bool,
    pub object: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantedProjectAccessPolicyPermissionDetailsResponse {
    pub access_policy: GrantedProjectAccessPolicyResponse,
    pub has_permission: bool,
    pub object: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectPeopleAccessPoliciesResponse {
    pub user_access_policies: Vec<UserAccessPolicyResponse>,
    pub group_access_policies: Vec<GroupAccessPolicyResponse>,
    pub object: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccountPeopleAccessPoliciesResponse {
    pub user_access_policies: Vec<UserAccessPolicyResponse>,
    pub group_access_policies: Vec<GroupAccessPolicyResponse>,
    pub object: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectServiceAccountsAccessPoliciesResponse {
    pub service_account_access_policies: Vec<ServiceAccountAccessPolicyResponse>,
    pub object: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccountGrantedPoliciesPermissionDetailsResponse {
    pub granted_project_policies: Vec<GrantedProjectAccessPolicyPermissionDetailsResponse>,
    pub object: &'static str,
}

/// An entry in a potential-grantees dropdown (a machine account or a project).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PotentialGranteeResponse {
    pub id: String,
    /// Encrypted (EncString) for machine accounts and projects.
    pub name: String,
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub email: Option<String>,
    pub current_user_in_group: bool,
    pub current_user: bool,
    pub object: &'static str,
}
