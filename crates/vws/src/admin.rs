//! Thin HTTP client for the server's `/admin` control plane.

use anyhow::{bail, Context, Result};
use reqwest::blocking::{Client, RequestBuilder};
use reqwest::StatusCode;
use serde_json::Value;

pub struct AdminClient {
    base: String,
    token: String,
    http: Client,
}

impl AdminClient {
    pub fn new(server_url: &str, admin_token: &str, insecure: bool) -> Result<Self> {
        let http = Client::builder()
            .danger_accept_invalid_certs(insecure)
            .build()
            .context("failed to build HTTP client")?;
        Ok(Self {
            base: server_url.trim_end_matches('/').to_string(),
            token: admin_token.to_string(),
            http,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}/admin{}", self.base, path)
    }

    fn auth(&self, rb: RequestBuilder) -> RequestBuilder {
        rb.bearer_auth(&self.token)
    }

    /// Send a request, mapping transport and HTTP-status errors to friendly messages.
    fn send(&self, rb: RequestBuilder, what: &str) -> Result<Option<Value>> {
        let resp = self.auth(rb).send().context("request to server failed")?;
        let status = resp.status();
        if status.is_success() {
            if status == StatusCode::NO_CONTENT {
                return Ok(None);
            }
            let body = resp.text().unwrap_or_default();
            if body.is_empty() {
                return Ok(None);
            }
            let value: Value = serde_json::from_str(&body)
                .with_context(|| format!("could not parse server response to {what}"))?;
            return Ok(Some(value));
        }
        match status {
            StatusCode::UNAUTHORIZED => bail!("admin token rejected (check `vws login`)"),
            StatusCode::SERVICE_UNAVAILABLE => {
                bail!("admin API is disabled on the server (set ADMIN_TOKEN there)")
            }
            StatusCode::NOT_FOUND => bail!("{what}: not found"),
            StatusCode::CONFLICT => bail!("{what}: already exists"),
            other => {
                let body = resp.text().unwrap_or_default();
                bail!("{what} failed: HTTP {} {}", other.as_u16(), body)
            }
        }
    }

    pub fn create_organization(&self, id: &str, name: &str) -> Result<Value> {
        let rb = self
            .http
            .post(self.url("/organizations"))
            .json(&serde_json::json!({ "id": id, "name": name }));
        self.send(rb, "create organization")?
            .context("empty response creating organization")
    }

    pub fn list_organizations(&self) -> Result<Value> {
        let rb = self.http.get(self.url("/organizations"));
        self.send(rb, "list organizations")?
            .context("empty response listing organizations")
    }

    pub fn create_machine_account(&self, org_id: &str, id: &str, name_enc: &str) -> Result<Value> {
        let rb = self
            .http
            .post(self.url(&format!("/organizations/{org_id}/machine-accounts")))
            .json(&serde_json::json!({ "id": id, "nameEnc": name_enc }));
        self.send(rb, "create machine account")?
            .context("empty response creating machine account")
    }

    pub fn list_machine_accounts(&self, org_id: &str) -> Result<Value> {
        let rb = self
            .http
            .get(self.url(&format!("/organizations/{org_id}/machine-accounts")));
        self.send(rb, "list machine accounts")?
            .context("empty response listing machine accounts")
    }

    pub fn delete_machine_account(&self, id: &str) -> Result<()> {
        let rb = self.http.delete(self.url(&format!("/machine-accounts/{id}")));
        self.send(rb, "delete machine account")?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_access_token(
        &self,
        ma_id: &str,
        id: &str,
        name_enc: &str,
        client_secret_hash: &str,
        encrypted_payload: &str,
        key_enc: &str,
    ) -> Result<Value> {
        let rb = self
            .http
            .post(self.url(&format!("/machine-accounts/{ma_id}/access-tokens")))
            .json(&serde_json::json!({
                "id": id,
                "nameEnc": name_enc,
                "clientSecretHash": client_secret_hash,
                "encryptedPayload": encrypted_payload,
                "keyEnc": key_enc,
            }));
        self.send(rb, "create access token")?
            .context("empty response creating access token")
    }

    pub fn list_access_tokens(&self, ma_id: &str) -> Result<Value> {
        let rb = self
            .http
            .get(self.url(&format!("/machine-accounts/{ma_id}/access-tokens")));
        self.send(rb, "list access tokens")?
            .context("empty response listing access tokens")
    }

    pub fn delete_access_token(&self, id: &str) -> Result<()> {
        let rb = self.http.delete(self.url(&format!("/access-tokens/{id}")));
        self.send(rb, "delete access token")?;
        Ok(())
    }

    pub fn grant_project_access(
        &self,
        ma_id: &str,
        project_id: &str,
        read: bool,
        write: bool,
    ) -> Result<()> {
        let rb = self
            .http
            .post(self.url(&format!("/machine-accounts/{ma_id}/project-access")))
            .json(&serde_json::json!({
                "projectId": project_id,
                "read": read,
                "write": write,
            }));
        self.send(rb, "grant project access")?;
        Ok(())
    }
}
