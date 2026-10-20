//! JWT signing for Secrets Manager access tokens (RS256), plus RSA key bootstrap.
//!
//! Mirrors vaultwarden's approach: load the RSA private key from disk, generating and
//! persisting a fresh 2048-bit key on first run. The signing key is internal — `bws` never
//! verifies the signature, our API does — so the key library choice is ours.

use std::path::Path;

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;

const JWT_ALGORITHM: Algorithm = Algorithm::RS256;

/// Claims for a Secrets Manager machine-account access token.
/// Field set and names match what Bitwarden's identity server emits.
#[derive(Serialize)]
pub struct SmAccessClaims {
    pub iss: String,
    pub nbf: i64,
    pub iat: i64,
    pub exp: i64,
    pub scope: Vec<String>,
    pub client_id: String,
    pub sub: String,
    #[serde(rename = "type")]
    pub token_type: String,
    pub organization: String,
    pub jti: String,
}

pub struct JwtSigner {
    encoding_key: EncodingKey,
    header: Header,
    issuer: String,
}

impl JwtSigner {
    /// Load the RSA private key from `pem_path`, generating and persisting a new 2048-bit key
    /// if the file does not exist.
    pub fn load_or_create(pem_path: &Path, issuer: String) -> anyhow::Result<Self> {
        let pem = if pem_path.exists() {
            std::fs::read(pem_path)?
        } else {
            use rsa::pkcs1::EncodeRsaPrivateKey;
            let mut rng = rand::thread_rng();
            let key = rsa::RsaPrivateKey::new(&mut rng, 2048)?;
            let pem = key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)?;
            let bytes = pem.as_bytes().to_vec();
            if let Some(parent) = pem_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(pem_path, &bytes)?;
            bytes
        };

        let encoding_key = EncodingKey::from_rsa_pem(&pem)?;
        let mut header = Header::new(JWT_ALGORITHM);
        header.typ = Some("at+jwt".to_string());

        Ok(Self {
            encoding_key,
            header,
            issuer,
        })
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn sign<C: Serialize>(&self, claims: &C) -> anyhow::Result<String> {
        Ok(jsonwebtoken::encode(&self.header, claims, &self.encoding_key)?)
    }
}
