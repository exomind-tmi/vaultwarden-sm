//! JWT signing and validation for Secrets Manager access tokens (RS256), plus RSA key
//! bootstrap.
//!
//! Mirrors vaultwarden's approach: load the RSA private key from disk, generating and
//! persisting a fresh 2048-bit key on first run. The signing key is internal — our API
//! verifies the tokens it issued — so the key library choice is ours.

use std::path::Path;

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, LineEnding};
use rsa::pkcs8::EncodePublicKey;
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};

const JWT_ALGORITHM: Algorithm = Algorithm::RS256;

/// Claims for a Secrets Manager machine-account access token.
/// Field set and names match what Bitwarden's identity server emits.
#[derive(Serialize, Deserialize)]
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
    decoding_key: DecodingKey,
    header: Header,
    issuer: String,
}

impl JwtSigner {
    /// Load the RSA private key from `pem_path`, generating and persisting a new 2048-bit key
    /// if the file does not exist. Derives the public key for in-process verification.
    pub fn load_or_create(pem_path: &Path, issuer: String) -> anyhow::Result<Self> {
        let key: RsaPrivateKey = if pem_path.exists() {
            let pem = std::fs::read_to_string(pem_path)?;
            RsaPrivateKey::from_pkcs1_pem(&pem)?
        } else {
            let mut rng = rand::thread_rng();
            let key = RsaPrivateKey::new(&mut rng, 2048)?;
            let pem = key.to_pkcs1_pem(LineEnding::LF)?;
            if let Some(parent) = pem_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(pem_path, pem.as_bytes())?;
            key
        };

        let priv_pem = key.to_pkcs1_pem(LineEnding::LF)?;
        let pub_pem = key.to_public_key().to_public_key_pem(LineEnding::LF)?;

        let encoding_key = EncodingKey::from_rsa_pem(priv_pem.as_bytes())?;
        let decoding_key = DecodingKey::from_rsa_pem(pub_pem.as_bytes())?;

        let mut header = Header::new(JWT_ALGORITHM);
        header.typ = Some("at+jwt".to_string());

        Ok(Self {
            encoding_key,
            decoding_key,
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

    /// Verify a token's signature, issuer and expiry, returning its claims.
    pub fn validate(&self, token: &str) -> anyhow::Result<SmAccessClaims> {
        let mut validation = Validation::new(JWT_ALGORITHM);
        validation.set_issuer(&[self.issuer.clone()]);
        validation.validate_exp = true;
        let data = jsonwebtoken::decode::<SmAccessClaims>(token, &self.decoding_key, &validation)?;
        Ok(data.claims)
    }
}
