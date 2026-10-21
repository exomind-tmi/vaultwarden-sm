//! `sm-core` — shared core for vaultwarden-sm.
//!
//! - [`crypto`] — wrappers over `bitwarden-crypto`: access-token parsing, key derivation,
//!   and wrapping/unwrapping of symmetric keys (wire-compatible with `bws`).
//! - API DTOs will land in the `dto` step.

pub mod crypto;

// Re-exported so dependents (e.g. `vws`) can name key types without a direct dependency on the
// pinned `bitwarden-crypto` git revision.
pub use bitwarden_crypto;

// TODO(step-dto): pub mod dto;
