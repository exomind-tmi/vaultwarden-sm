//! The local `vws` profile: the admin's half of the zero-knowledge split.
//!
//! The server never holds a plaintext organization key — `vws` does, here on disk. The profile
//! keeps the server URL, the admin token, and, per organization, its name and base64 org key.
//! It also remembers the active access token so `bws` passthrough works without re-exporting env.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Profile {
    /// Base URL of the vaultwarden-sm server (no trailing slash), e.g. `https://vault-sm.example.com`.
    pub server_url: Option<String>,
    /// Shared admin token (matches the server's `ADMIN_TOKEN`).
    pub admin_token: Option<String>,
    /// The organization subsequent commands act on unless overridden.
    pub current_org: Option<String>,
    /// The access token injected into `bws` passthrough as `BWS_ACCESS_TOKEN`.
    pub active_access_token: Option<String>,
    /// Known organizations keyed by id. Holds the plaintext org key (base64) the server never sees.
    pub orgs: std::collections::BTreeMap<String, OrgEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgEntry {
    pub name: String,
    /// Base64 of the AES-256-CBC-HMAC organization key.
    pub key_b64: String,
}

impl Profile {
    /// Resolve the profile path: the `--profile`/`VWS_PROFILE` value, else `~/.vws/profile.json`.
    pub fn resolve_path(explicit: Option<PathBuf>) -> Result<PathBuf> {
        if let Some(p) = explicit {
            return Ok(p);
        }
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .context("cannot locate home directory; set VWS_PROFILE or pass --profile")?;
        Ok(PathBuf::from(home).join(".vws").join("profile.json"))
    }

    pub fn load(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(s) => serde_json::from_str(&s).context("profile is not valid JSON"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Profile::default()),
            Err(e) => Err(e).context("failed to read profile"),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).context("failed to create profile directory")?;
        }
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json).context("failed to write profile")?;
        Ok(())
    }

    /// The organization id the command targets: `--org`/argument if given, else `current_org`.
    pub fn require_org<'a>(&'a self, override_id: Option<&'a str>) -> Result<&'a str> {
        override_id
            .or(self.current_org.as_deref())
            .context("no current organization; run `vws org init` or `vws org use <id>` first")
    }

    pub fn org_entry(&self, org_id: &str) -> Result<&OrgEntry> {
        self.orgs
            .get(org_id)
            .with_context(|| format!("organization {org_id} is not in this profile (its org key is unknown here)"))
    }
}
