//! `sm-core` — shared core for vaultwarden-sm.
//!
//! - [`crypto`] — wrappers over `bitwarden-crypto`: access-token parsing, key derivation,
//!   and wrapping/unwrapping of symmetric keys (wire-compatible with `bws`).
//! - API DTOs will land in the `dto` step.

pub mod crypto;

// TODO(step-dto): pub mod dto;
