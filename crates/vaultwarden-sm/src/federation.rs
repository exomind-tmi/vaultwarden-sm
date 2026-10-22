//! Federated authentication against the companion vaultwarden instance.
//!
//! vaultwarden signs user session tokens (RS256) with the RSA private key it persists at
//! `${DATA_FOLDER}/rsa_key.pem`. We mount that same key file read-only, derive the public key
//! from it, and verify vaultwarden-issued user JWTs here. That means no shared secret beyond the
//! key file, no network round-trip to check a signature, and no dependency on a JWKS endpoint
//! (vaultwarden exposes none).
//!
//! This verifier only authenticates: it proves "a valid, unexpired vaultwarden session for user
//! X". Authorization — organization membership, role and Secrets Manager access policies — is a
//! separate layer, because vaultwarden does not carry any of that in the token.

use std::path::Path;
use std::time::Duration;

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use rsa::pkcs1::{DecodeRsaPrivateKey, LineEnding};
use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
use rsa::RsaPrivateKey;
use serde::Deserialize;

use crate::membership::MembershipResolver;

const JWT_ALGORITHM: Algorithm = Algorithm::RS256;

/// Everything needed to accept vaultwarden end users: verify their session tokens and resolve
/// their organization memberships. Present in Rocket state only when federation is configured; its
/// absence simply means the user flow is off and the machine-account flow still works.
pub struct Federation {
    pub verifier: VaultwardenVerifier,
    pub resolver: MembershipResolver,
}

impl Federation {
    /// `vw_key_path` is the shared (read-only) vaultwarden RSA key file; `domain_origin` is the
    /// origin both services share; `vw_base` is vaultwarden's internal base URL; `membership_ttl`
    /// bounds how stale a cached membership may be.
    pub fn load(
        vw_key_path: &Path,
        domain_origin: &str,
        vw_base: &str,
        membership_ttl: Duration,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            verifier: VaultwardenVerifier::load(vw_key_path, domain_origin)?,
            resolver: MembershipResolver::new(vw_base, membership_ttl)?,
        })
    }
}

/// The subset of vaultwarden's `LoginJwtClaims` we rely on. Unknown claims (premium, device,
/// scope, sstamp, …) are ignored by serde.
#[derive(Debug, Deserialize)]
struct VaultwardenLoginClaims {
    sub: String,
    email: String,
    #[serde(default)]
    name: String,
}

/// An authenticated vaultwarden end user, as asserted by a verified session token.
#[derive(Debug, Clone)]
pub struct VaultwardenUser {
    pub user_id: String,
    pub email: String,
    pub name: String,
}

pub struct VaultwardenVerifier {
    decoding_key: DecodingKey,
    login_issuer: String,
}

impl VaultwardenVerifier {
    /// Load vaultwarden's RSA private key from `pem_path` and derive the public key used to verify
    /// its signatures. `domain_origin` is vaultwarden's configured origin (scheme + host [+ port],
    /// no trailing slash); the login issuer is `"{domain_origin}|login"`, matching vaultwarden's
    /// `JWT_LOGIN_ISSUER`.
    pub fn load(pem_path: &Path, domain_origin: &str) -> anyhow::Result<Self> {
        let pem = std::fs::read_to_string(pem_path)?;
        Self::from_private_pem(&pem, domain_origin)
    }

    fn from_private_pem(pem: &str, domain_origin: &str) -> anyhow::Result<Self> {
        // vaultwarden writes a PKCS#1 ("RSA PRIVATE KEY") PEM via OpenSSL; accept PKCS#8 too so a
        // key produced by either toolchain works.
        let key = RsaPrivateKey::from_pkcs1_pem(pem)
            .or_else(|_| RsaPrivateKey::from_pkcs8_pem(pem))?;
        let pub_pem = key.to_public_key().to_public_key_pem(LineEnding::LF)?;
        let decoding_key = DecodingKey::from_rsa_pem(pub_pem.as_bytes())?;
        Ok(Self {
            decoding_key,
            login_issuer: format!("{domain_origin}|login"),
        })
    }

    /// Verify a vaultwarden user session token: RS256 signature, issuer, `nbf` and `exp`. Mirrors
    /// vaultwarden's own `decode_jwt` validation (30s leeway).
    pub fn validate(&self, token: &str) -> anyhow::Result<VaultwardenUser> {
        let mut validation = Validation::new(JWT_ALGORITHM);
        validation.leeway = 30;
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.set_issuer(&[self.login_issuer.clone()]);

        let data = jsonwebtoken::decode::<VaultwardenLoginClaims>(
            token.trim(),
            &self.decoding_key,
            &validation,
        )?;
        let c = data.claims;
        Ok(VaultwardenUser {
            user_id: c.sub,
            email: c.email,
            name: c.name,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header};
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use serde::Serialize;

    const ORIGIN: &str = "https://vault.exomind-tmi.com";

    #[derive(Serialize)]
    struct TestClaims {
        iss: String,
        sub: String,
        email: String,
        name: String,
        nbf: i64,
        exp: i64,
        // A claim we do not model, to prove unknown fields are ignored.
        scope: Vec<String>,
    }

    /// A fresh 2048-bit key, returned as its PKCS#1 PEM — exactly what vaultwarden persists.
    fn gen_key_pem() -> String {
        let mut rng = rand::thread_rng();
        let key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        key.to_pkcs1_pem(LineEnding::LF).unwrap().to_string()
    }

    fn sign(pem: &str, claims: &TestClaims) -> String {
        let enc = EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
        jsonwebtoken::encode(&Header::new(Algorithm::RS256), claims, &enc).unwrap()
    }

    fn login_claims() -> TestClaims {
        let now = chrono::Utc::now().timestamp();
        TestClaims {
            iss: format!("{ORIGIN}|login"),
            sub: "11111111-1111-1111-1111-111111111111".into(),
            email: "anton@example.com".into(),
            name: "Anton".into(),
            nbf: now - 10,
            exp: now + 3600,
            scope: vec!["api".into(), "offline_access".into()],
        }
    }

    #[test]
    fn accepts_a_valid_vaultwarden_login_token() {
        let pem = gen_key_pem();
        let verifier = VaultwardenVerifier::from_private_pem(&pem, ORIGIN).unwrap();
        let token = sign(&pem, &login_claims());

        let user = verifier.validate(&token).unwrap();
        assert_eq!(user.user_id, "11111111-1111-1111-1111-111111111111");
        assert_eq!(user.email, "anton@example.com");
        assert_eq!(user.name, "Anton");
    }

    #[test]
    fn rejects_a_token_signed_by_a_different_key() {
        let real_pem = gen_key_pem();
        let attacker_pem = gen_key_pem();
        let verifier = VaultwardenVerifier::from_private_pem(&real_pem, ORIGIN).unwrap();
        let token = sign(&attacker_pem, &login_claims());

        assert!(verifier.validate(&token).is_err());
    }

    #[test]
    fn rejects_a_wrong_issuer() {
        let pem = gen_key_pem();
        let verifier = VaultwardenVerifier::from_private_pem(&pem, ORIGIN).unwrap();
        let mut claims = login_claims();
        // Right key, wrong issuer: another vaultwarden token kind (invite, admin, …) must not pass
        // as a user session.
        claims.iss = format!("{ORIGIN}|invite");
        let token = sign(&pem, &claims);

        assert!(verifier.validate(&token).is_err());
    }

    #[test]
    fn rejects_an_expired_token() {
        let pem = gen_key_pem();
        let verifier = VaultwardenVerifier::from_private_pem(&pem, ORIGIN).unwrap();
        let now = chrono::Utc::now().timestamp();
        let mut claims = login_claims();
        claims.nbf = now - 7200;
        claims.exp = now - 3600; // well beyond the 30s leeway
        let token = sign(&pem, &claims);

        assert!(verifier.validate(&token).is_err());
    }
}
