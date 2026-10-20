//! Identity: the `client_credentials` token endpoint `bws` calls.
//!
//! Mounted under `/identity`, so the route is `POST /identity/connect/token`.

use base64::{engine::general_purpose::STANDARD, Engine};
use diesel::prelude::*;
use rocket::form::Form;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{post, routes, FromForm, Route, State};
use serde::Serialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::db::DbPool;
use crate::jwt::{JwtSigner, SmAccessClaims};
use crate::models::{AccessToken, MachineAccount};
use crate::schema::{access_tokens, machine_accounts};

const ACCESS_TOKEN_LIFETIME_SECS: i64 = 3600;

#[derive(FromForm)]
pub struct TokenRequest {
    pub grant_type: String,
    pub client_id: String,
    pub client_secret: String,
    // `scope` is sent by bws but ignored: the granted scope is defined by the token itself.
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: i64,
    pub token_type: String,
    pub scope: String,
    pub encrypted_payload: String,
}

pub fn routes() -> Vec<Route> {
    routes![connect_token]
}

#[post("/connect/token", data = "<req>")]
pub async fn connect_token(
    req: Form<TokenRequest>,
    pool: &State<DbPool>,
    signer: &State<JwtSigner>,
) -> Result<Json<TokenResponse>, Status> {
    if req.grant_type != "client_credentials" {
        return Err(Status::BadRequest);
    }

    let pool = pool.inner().clone();
    let client_id = req.client_id.clone();

    // Diesel is synchronous — run the lookup on a blocking thread.
    let looked_up = rocket::tokio::task::spawn_blocking(move || -> anyhow::Result<(AccessToken, MachineAccount)> {
        let mut conn = pool.get()?;
        let token: AccessToken = access_tokens::table
            .find(&client_id)
            .first(&mut conn)
            .optional()?
            .ok_or_else(|| anyhow::anyhow!("access token not found"))?;
        let ma: MachineAccount = machine_accounts::table
            .find(&token.machine_account_id)
            .first(&mut conn)?;
        Ok((token, ma))
    })
    .await
    .map_err(|_| Status::InternalServerError)?;

    // Unknown client or missing machine account -> unauthorized (no distinction leaked).
    let (token, ma) = looked_up.map_err(|_| Status::Unauthorized)?;

    // Verify the client secret: Base64(SHA256(secret)) == stored hash, constant-time.
    let computed = STANDARD.encode(Sha256::digest(req.client_secret.as_bytes()));
    if computed
        .as_bytes()
        .ct_eq(token.client_secret_hash.as_bytes())
        .unwrap_u8()
        != 1
    {
        return Err(Status::Unauthorized);
    }

    // Expiry check (expire_at is stored as RFC3339, nullable = never expires).
    if let Some(expire_at) = &token.expire_at {
        match chrono::DateTime::parse_from_rfc3339(expire_at) {
            Ok(exp) if exp > chrono::Utc::now() => {}
            Ok(_) => return Err(Status::Unauthorized),
            Err(_) => return Err(Status::InternalServerError),
        }
    }

    let now = chrono::Utc::now().timestamp();
    let jti = uuid::Uuid::new_v4().simple().to_string().to_uppercase();
    let scopes: Vec<String> =
        serde_json::from_str(&token.scope).unwrap_or_else(|_| vec!["api.secrets".to_string()]);

    let claims = SmAccessClaims {
        iss: signer.issuer().to_string(),
        nbf: now,
        iat: now,
        exp: now + ACCESS_TOKEN_LIFETIME_SECS,
        scope: scopes.clone(),
        client_id: token.id.clone(),
        sub: ma.id.clone(),
        token_type: "ServiceAccount".to_string(),
        organization: ma.organization_id.clone(),
        jti,
    };

    let access_token = signer
        .sign(&claims)
        .map_err(|_| Status::InternalServerError)?;

    Ok(Json(TokenResponse {
        access_token,
        expires_in: ACCESS_TOKEN_LIFETIME_SECS,
        token_type: "Bearer".to_string(),
        scope: scopes.join(" "),
        encrypted_payload: token.encrypted_payload,
    }))
}
