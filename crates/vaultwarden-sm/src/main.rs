mod api;
mod db;
mod jwt;
mod models;
mod schema;

use std::path::PathBuf;

use rocket::{Build, Rocket};

/// Build the Rocket instance. Shared by `main` and the integration tests.
pub fn build_rocket(pool: db::DbPool, signer: jwt::JwtSigner) -> Rocket<Build> {
    rocket::build()
        .manage(pool)
        .manage(signer)
        .mount("/identity", api::identity::routes())
}

#[rocket::main]
async fn main() -> anyhow::Result<()> {
    let data_dir = std::env::var("DATA_DIR").unwrap_or_else(|_| "data".to_string());
    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| format!("{data_dir}/vaultwarden-sm.db"));
    let domain = std::env::var("DOMAIN").unwrap_or_else(|_| "http://localhost".to_string());
    let rsa_key_path = PathBuf::from(&data_dir).join("rsa_key.pem");

    std::fs::create_dir_all(&data_dir).ok();

    let pool = db::init_pool(&database_url)?;
    db::run_migrations(&pool)?;

    let signer = jwt::JwtSigner::load_or_create(&rsa_key_path, domain)?;

    build_rocket(pool, signer).launch().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::{engine::general_purpose::STANDARD, Engine};
    use diesel::prelude::*;
    use rocket::http::{ContentType, Status};
    use rocket::local::blocking::Client;
    use sha2::{Digest, Sha256};

    use crate::models::{AccessToken, MachineAccount, Organization};

    fn seed(pool: &db::DbPool, token_id: &str, ma_id: &str, org_id: &str, secret: &str) {
        use crate::schema::{access_tokens, machine_accounts, organizations};
        let mut conn = pool.get().unwrap();
        let now = "2026-10-20T00:00:00Z".to_string();

        diesel::insert_into(organizations::table)
            .values(&Organization {
                id: org_id.into(),
                name: "Test Org".into(),
                creation_date: now.clone(),
                revision_date: now.clone(),
            })
            .execute(&mut conn)
            .unwrap();

        diesel::insert_into(machine_accounts::table)
            .values(&MachineAccount {
                id: ma_id.into(),
                organization_id: org_id.into(),
                name_enc: "2.x|y|z".into(),
                creation_date: now.clone(),
                revision_date: now.clone(),
            })
            .execute(&mut conn)
            .unwrap();

        let hash = STANDARD.encode(Sha256::digest(secret.as_bytes()));
        diesel::insert_into(access_tokens::table)
            .values(&AccessToken {
                id: token_id.into(),
                machine_account_id: ma_id.into(),
                name_enc: "2.x|y|z".into(),
                client_secret_hash: hash,
                scope: "[\"api.secrets\"]".into(),
                encrypted_payload: "2.aaa|bbb|ccc".into(),
                key_enc: "2.x|y|z".into(),
                expire_at: None,
                creation_date: now.clone(),
                revision_date: now,
            })
            .execute(&mut conn)
            .unwrap();
    }

    fn test_client(uniq: &str) -> Client {
        let dir = std::env::temp_dir();
        let db_path = dir.join(format!("vwsm-test-{uniq}.db"));
        let pem_path = dir.join(format!("vwsm-test-{uniq}.pem"));
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(&pem_path);

        let pool = db::init_pool(db_path.to_str().unwrap()).unwrap();
        db::run_migrations(&pool).unwrap();
        seed(
            &pool,
            "513ade31-e3b6-4f17-9fb2-b4e901215c4f",
            "07b4020e-3068-4fd3-80c0-b4e9012066d2",
            "55fa6ee9-886d-4127-9fb2-b4e9011f5de6",
            "testsecret",
        );
        let signer = jwt::JwtSigner::load_or_create(&pem_path, "http://localhost".into()).unwrap();
        Client::tracked(build_rocket(pool, signer)).unwrap()
    }

    fn jwt_claims(token: &str) -> serde_json::Value {
        let payload_b64 = token.split('.').nth(1).unwrap();
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .unwrap();
        serde_json::from_slice(&payload).unwrap()
    }

    #[test]
    fn connect_token_issues_jwt_with_expected_claims() {
        let client = test_client("ok");
        let resp = client
            .post("/identity/connect/token")
            .header(ContentType::Form)
            .body("grant_type=client_credentials&client_id=513ade31-e3b6-4f17-9fb2-b4e901215c4f&client_secret=testsecret&scope=api.secrets")
            .dispatch();

        assert_eq!(resp.status(), Status::Ok);
        let body: serde_json::Value = resp.into_json().unwrap();
        assert_eq!(body["token_type"], "Bearer");
        assert_eq!(body["expires_in"], 3600);
        assert_eq!(body["scope"], "api.secrets");
        assert_eq!(body["encrypted_payload"], "2.aaa|bbb|ccc");

        let claims = jwt_claims(body["access_token"].as_str().unwrap());
        assert_eq!(claims["type"], "ServiceAccount");
        assert_eq!(claims["client_id"], "513ade31-e3b6-4f17-9fb2-b4e901215c4f");
        assert_eq!(claims["sub"], "07b4020e-3068-4fd3-80c0-b4e9012066d2");
        assert_eq!(claims["organization"], "55fa6ee9-886d-4127-9fb2-b4e9011f5de6");
        assert_eq!(claims["scope"][0], "api.secrets");
    }

    #[test]
    fn connect_token_rejects_wrong_secret() {
        let client = test_client("badsecret");
        let resp = client
            .post("/identity/connect/token")
            .header(ContentType::Form)
            .body("grant_type=client_credentials&client_id=513ade31-e3b6-4f17-9fb2-b4e901215c4f&client_secret=wrong")
            .dispatch();
        assert_eq!(resp.status(), Status::Unauthorized);
    }

    #[test]
    fn connect_token_rejects_unknown_client() {
        let client = test_client("unknown");
        let resp = client
            .post("/identity/connect/token")
            .header(ContentType::Form)
            .body("grant_type=client_credentials&client_id=00000000-0000-0000-0000-000000000000&client_secret=testsecret")
            .dispatch();
        assert_eq!(resp.status(), Status::Unauthorized);
    }
}
