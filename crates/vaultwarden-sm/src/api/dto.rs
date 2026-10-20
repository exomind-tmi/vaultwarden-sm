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
