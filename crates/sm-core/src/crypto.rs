//! Crypto core: access-token parsing, key derivation, wrapping/unwrapping of symmetric keys,
//! and token issuance — all wire-compatible with `bws` by construction, since it builds on the
//! same `bitwarden-crypto` crate the official Bitwarden clients use.
//!
//! The algorithm mirrors the reference in Bitwarden's `util/RustSdk/rust/src/`
//! (`sm_access_token.rs` and `crypto_util.rs`).

use base64::{engine::general_purpose::STANDARD, Engine};
use bitwarden_crypto::{
    derive_shareable_key, BitwardenLegacyKeyBytes, EncString, KeyDecryptable, KeyEncryptable,
    SymmetricCryptoKey,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("malformed access token")]
    MalformedToken,
    #[error("invalid base64 in access-token key")]
    InvalidKeyB64,
    #[error("access-token encryption key must be 16 bytes")]
    BadKeyLength,
    #[error("crypto operation failed")]
    Crypto,
}

/// A parsed access token of the form `0.<id>.<client_secret>:<base64(encryption_key[16])>`.
///
/// `client_secret` authenticates the token (the server stores its hash); `encryption_key`
/// derives the key that decrypts `encrypted_payload`.
pub struct AccessToken {
    pub id: String,
    pub client_secret: String,
    pub encryption_key: Zeroizing<[u8; 16]>,
}

impl AccessToken {
    pub fn parse(s: &str) -> Result<Self, CryptoError> {
        // "0" "." <id> "." <client_secret ":" base64-key>
        let mut parts = s.splitn(3, '.');
        let version = parts.next().ok_or(CryptoError::MalformedToken)?;
        let id = parts.next().ok_or(CryptoError::MalformedToken)?;
        let secret_and_key = parts.next().ok_or(CryptoError::MalformedToken)?;
        if version != "0" {
            return Err(CryptoError::MalformedToken);
        }

        let (client_secret, key_b64) = secret_and_key
            .split_once(':')
            .ok_or(CryptoError::MalformedToken)?;

        let key_bytes = STANDARD
            .decode(key_b64)
            .map_err(|_| CryptoError::InvalidKeyB64)?;
        let key: [u8; 16] = key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::BadKeyLength)?;

        Ok(Self {
            id: id.to_string(),
            client_secret: client_secret.to_string(),
            encryption_key: Zeroizing::new(key),
        })
    }

    /// The AES-256-CBC-HMAC key derived from the 16-byte encryption key, exactly as the
    /// SDK/`bws` does: `derive_shareable_key(key16, "accesstoken", Some("sm-access-token"))`.
    pub fn derive_key(&self) -> SymmetricCryptoKey {
        derive_token_key(&self.encryption_key)
    }
}

fn derive_token_key(encryption_key: &[u8; 16]) -> SymmetricCryptoKey {
    SymmetricCryptoKey::Aes256CbcHmacKey(derive_shareable_key(
        Zeroizing::new(*encryption_key),
        "accesstoken",
        Some("sm-access-token"),
    ))
}

/// Wrap a symmetric key (e.g. the org key) under `wrapping_key`, returning an `EncString`.
/// Used to build `encrypted_payload` when issuing an access token.
pub fn wrap_key(
    key_to_wrap: &SymmetricCryptoKey,
    wrapping_key: &SymmetricCryptoKey,
) -> Result<String, CryptoError> {
    let wrapped = key_to_wrap
        .to_encoded()
        .encrypt_with_key(wrapping_key)
        .map_err(|_| CryptoError::Crypto)?;
    Ok(wrapped.to_string())
}

/// Unwrap an `EncString` back into a symmetric key.
pub fn unwrap_key(
    wrapped: &str,
    wrapping_key: &SymmetricCryptoKey,
) -> Result<SymmetricCryptoKey, CryptoError> {
    let parsed: EncString = wrapped.parse().map_err(|_| CryptoError::Crypto)?;
    let bytes: Vec<u8> = parsed
        .decrypt_with_key(wrapping_key)
        .map_err(|_| CryptoError::Crypto)?;
    SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(bytes.as_slice()))
        .map_err(|_| CryptoError::Crypto)
}

/// Generate a fresh AES-256-CBC-HMAC organization key (32-byte enc + 32-byte MAC).
pub fn generate_org_key() -> SymmetricCryptoKey {
    let mut bytes = Zeroizing::new([0u8; 64]);
    rand::thread_rng().fill_bytes(bytes.as_mut_slice());
    SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(bytes.as_slice()))
        .expect("64 random bytes form a valid AES-256-CBC-HMAC key")
}

/// The parts of a freshly issued access token.
pub struct IssuedAccessToken {
    /// `0.<id>.<client_secret>:<base64(encryption_key)>` — handed to the client, shown once.
    pub token_string: String,
    /// Base64(SHA256(client_secret)) — stored for authentication.
    pub client_secret_hash: String,
    /// Org key wrapped under the token key — stored and served back at token time.
    pub encrypted_payload: String,
    /// Token key wrapped under the org key — stored so an admin can recover it without the seed.
    pub key_enc: String,
}

/// Issue a new access token for a machine account, given the organization key and a pre-chosen
/// token id. Generates the encryption seed and client secret, and returns the token string plus
/// the fields to persist.
pub fn issue_access_token(
    access_token_id: &str,
    org_key: &SymmetricCryptoKey,
) -> Result<IssuedAccessToken, CryptoError> {
    let mut seed = Zeroizing::new([0u8; 16]);
    rand::thread_rng().fill_bytes(seed.as_mut_slice());

    let client_secret = random_secret(30);
    let token_key = derive_token_key(&seed);

    let encrypted_payload = wrap_key(org_key, &token_key)?;
    let key_enc = wrap_key(&token_key, org_key)?;
    let client_secret_hash = STANDARD.encode(Sha256::digest(client_secret.as_bytes()));
    let token_string = format!(
        "0.{}.{}:{}",
        access_token_id,
        client_secret,
        STANDARD.encode(seed.as_slice())
    );

    Ok(IssuedAccessToken {
        token_string,
        client_secret_hash,
        encrypted_payload,
        key_enc,
    })
}

fn random_secret(len: usize) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| CHARS[(rng.next_u32() as usize) % CHARS.len()] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_well_formed_access_token() {
        let key16 = [7u8; 16];
        let key_b64 = STANDARD.encode(key16);
        let s = format!("0.aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.supersecret:{key_b64}");

        let t = AccessToken::parse(&s).expect("should parse");
        assert_eq!(t.id, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        assert_eq!(t.client_secret, "supersecret");
        assert_eq!(*t.encryption_key, key16);
    }

    #[test]
    fn rejects_bad_version_and_shape() {
        assert!(AccessToken::parse("1.id.secret:AAAA").is_err());
        assert!(AccessToken::parse("0.id.no-colon").is_err());
        assert!(AccessToken::parse("garbage").is_err());
    }

    #[test]
    fn issued_token_round_trips_org_key() {
        let org_key = generate_org_key();
        let issued = issue_access_token("test-id-1234", &org_key).expect("issue");

        // A client parsing the token string derives the same key that unwraps the payload.
        let parsed = AccessToken::parse(&issued.token_string).expect("parse issued");
        assert_eq!(parsed.id, "test-id-1234");

        let token_key = parsed.derive_key();
        let recovered = unwrap_key(&issued.encrypted_payload, &token_key).expect("unwrap payload");
        assert_eq!(recovered.to_base64(), org_key.to_base64());

        // The stored hash matches the secret embedded in the token string.
        let expected_hash = STANDARD.encode(Sha256::digest(parsed.client_secret.as_bytes()));
        assert_eq!(expected_hash, issued.client_secret_hash);

        // key_enc recovers the token key via the org key (admin-recovery path).
        let via_org = unwrap_key(&issued.key_enc, &org_key).expect("unwrap key_enc");
        assert_eq!(via_org.to_base64(), token_key.to_base64());
    }
}
