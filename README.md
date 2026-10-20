# vaultwarden-sm

A standalone **Bitwarden Secrets Manager** backend that makes the official `bws` CLI work
against a self-hosted setup — designed to live next to
[vaultwarden](https://github.com/dani-garcia/vaultwarden) on the same host.

Named in tribute to vaultwarden: same spirit (lightweight, Rust, self-hostable), same stack
(Rocket + Diesel + bundled SQLite), different bounded context. Secrets Manager shares almost
nothing with the password manager — only **User** and **Organization** — so it ships as its own
service rather than a vaultwarden fork.

## Components

- **`vaultwarden-sm`** — the server: identity (`client_credentials`) + the Secrets Manager API
  slice that `bws` actually calls.
- **`vws`** — companion CLI: wraps `bws` entirely and adds the admin commands `bws` lacks
  (machine accounts, access tokens, projects, org init), standing in for the (proprietary) web UI.
- **`sm-core`** — shared DTOs and crypto wrappers over `bitwarden-crypto`.

## Status

Early scaffolding. **MVP scope:** identity + secrets/projects CRUD + sync.
**Out of scope:** access policies, versions, trash, events, porting, counts, web UI.

## Crypto

Reuses Bitwarden's own `bitwarden-crypto` crate, so access tokens and encrypted payloads are
byte-compatible with `bws` by construction. Access-token format:
`0.<id>.<clientSecret>:<base64(encryptionKey)>`.

## Deployment

Runs as an extra service in the same `docker-compose` as vaultwarden, on the same Docker
network, with its own isolated SQLite database.
