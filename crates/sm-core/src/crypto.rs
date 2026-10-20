//! Crypto core: access-token parsing, key derivation, and wrapping/unwrapping of symmetric
//! keys — wire-compatible with `bws` by construction, since it builds on the same
//! `bitwarden-crypto` crate the official Bitwarden clients use.
//!
//! The algorithm mirrors the reference in Bitwarden's `util/RustSdk/rust/src/`
//! (`sm_access_token.rs` and `crypto_util.rs`).

use base64::{engine::general_purpose::STANDARD, Engine};
use bitwarden_crypto::{
    derive_shareable_key, BitwardenLegacyKeyBytes, EncString, KeyDecryptable, KeyEncryptable,
    SymmetricCryptoKey,
};
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
        SymmetricCryptoKey::Aes256CbcHmacKey(derive_shareable_key(
            Zeroizing::new(*self.encryption_key),
            "accesstoken",
            Some("sm-access-token"),
        ))
    }
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
}
