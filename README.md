# vaultwarden-sm

A standalone **Bitwarden Secrets Manager** backend that makes the official `bws` CLI work
against a self-hosted setup — designed to live next to
[vaultwarden](https://github.com/dani-garcia/vaultwarden) on the same host.

> Unofficial. Not affiliated with, authorized, or endorsed by Bitwarden or vaultwarden.

Named in tribute to vaultwarden: same spirit (lightweight, Rust, self-hostable), same stack
(Rocket + Diesel + bundled SQLite), different bounded context. Secrets Manager shares almost
nothing with the password manager — only **User** and **Organization** — so it ships as its own
service rather than a vaultwarden fork.

## Components

- **`vaultwarden-sm`** — the server: identity (`client_credentials`) + the Secrets Manager API
  that `bws` and the web vault call.
- **`vws`** — companion CLI: wraps `bws` entirely and adds the admin commands `bws` lacks
  (machine accounts, access tokens, projects, org init).
- **`sm-core`** — shared DTOs and crypto wrappers over `bitwarden-crypto`.

## Status

Working end to end — the real `bws` CLI drives this backend over the wire (proven live). Beyond the
machine-account flow (identity + secrets/projects CRUD + sync), it federates with vaultwarden to
accept user sessions and serves the granular Secrets Manager surface the web vault uses: service
accounts, access tokens, access policies, and counts. Out of scope for now: secret versions, trash,
events, porting.

## Crypto

Reuses Bitwarden's own `bitwarden-crypto` crate, so access tokens and encrypted payloads are
byte-compatible with `bws` by construction. Access-token format:
`0.<id>.<clientSecret>:<base64(encryptionKey)>`.

## Deployment

Runs as an extra service in the same `docker-compose` as vaultwarden, on the same Docker network,
with its own isolated SQLite database. CI publishes the image to `ghcr.io/exomind-tmi/vaultwarden-sm`.

## License

GPL-3.0-only. See [LICENSE](LICENSE).
