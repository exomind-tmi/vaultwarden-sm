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
        .mount("/api", api::api_routes())
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
    use rocket::http::{ContentType, Header, Status};
    use rocket::local::blocking::Client;
    use sha2::{Digest, Sha256};

    use crate::models::{
        AccessToken, MachineAccount, MachineAccountProjectAccess, Organization, Project,
        ProjectSecret, Secret,
    };

    const ORG_ID: &str = "55fa6ee9-886d-4127-9fb2-b4e9011f5de6";
    const MA_ID: &str = "07b4020e-3068-4fd3-80c0-b4e9012066d2";
    const TOKEN_ID: &str = "513ade31-e3b6-4f17-9fb2-b4e901215c4f";
    const PROJECT_ID: &str = "369d1153-fb53-42fc-9743-b4e901201deb";
    const SECRET_ID: &str = "e94e691a-a37c-4a48-8506-b4e901222e26";

    fn seed(pool: &db::DbPool, secret: &str) {
        use crate::schema::{access_tokens, machine_accounts, organizations};
        let mut conn = pool.get().unwrap();
        let now = "2026-10-20T00:00:00Z".to_string();

        diesel::insert_into(organizations::table)
            .values(&Organization {
                id: ORG_ID.into(),
                name: "Test Org".into(),
                creation_date: now.clone(),
                revision_date: now.clone(),
            })
            .execute(&mut conn)
            .unwrap();

        diesel::insert_into(machine_accounts::table)
            .values(&MachineAccount {
                id: MA_ID.into(),
                organization_id: ORG_ID.into(),
                name_enc: "2.x|y|z".into(),
                creation_date: now.clone(),
                revision_date: now.clone(),
            })
            .execute(&mut conn)
            .unwrap();

        let hash = STANDARD.encode(Sha256::digest(secret.as_bytes()));
        diesel::insert_into(access_tokens::table)
            .values(&AccessToken {
                id: TOKEN_ID.into(),
                machine_account_id: MA_ID.into(),
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

    fn seed_project(pool: &db::DbPool) {
        use crate::schema::{machine_account_project_access as mapa, projects};
        let mut conn = pool.get().unwrap();
        let now = "2026-10-20T00:00:00Z".to_string();

        diesel::insert_into(projects::table)
            .values(&Project {
                id: PROJECT_ID.into(),
                organization_id: ORG_ID.into(),
                name_enc: "2.p|p|p".into(),
                creation_date: now.clone(),
                revision_date: now,
                deleted_date: None,
            })
            .execute(&mut conn)
            .unwrap();

        diesel::insert_into(mapa::table)
            .values(&MachineAccountProjectAccess {
                machine_account_id: MA_ID.into(),
                project_id: PROJECT_ID.into(),
                can_read: 1,
                can_write: 1,
            })
            .execute(&mut conn)
            .unwrap();
    }

    fn seed_secret(pool: &db::DbPool) {
        use crate::schema::{project_secret, secrets};
        let mut conn = pool.get().unwrap();
        let now = "2026-10-20T00:00:00Z".to_string();

        diesel::insert_into(secrets::table)
            .values(&Secret {
                id: SECRET_ID.into(),
                organization_id: ORG_ID.into(),
                key_enc: "2.k|k|k".into(),
                value_enc: "2.v|v|v".into(),
                note_enc: Some("2.n|n|n".into()),
                creation_date: now.clone(),
                revision_date: now,
                deleted_date: None,
            })
            .execute(&mut conn)
            .unwrap();

        diesel::insert_into(project_secret::table)
            .values(&ProjectSecret {
                project_id: PROJECT_ID.into(),
                secret_id: SECRET_ID.into(),
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
        seed(&pool, "testsecret");
        let signer = jwt::JwtSigner::load_or_create(&pem_path, "http://localhost".into()).unwrap();
        Client::tracked(build_rocket(pool, signer)).unwrap()
    }

    fn obtain_token(client: &Client) -> String {
        let resp = client
            .post("/identity/connect/token")
            .header(ContentType::Form)
            .body(format!(
                "grant_type=client_credentials&client_id={TOKEN_ID}&client_secret=testsecret"
            ))
            .dispatch();
        let body: serde_json::Value = resp.into_json().unwrap();
        body["access_token"].as_str().unwrap().to_string()
    }

    fn jwt_claims(token: &str) -> serde_json::Value {
        let payload_b64 = token.split('.').nth(1).unwrap();
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .unwrap();
        serde_json::from_slice(&payload).unwrap()
    }

    // --- identity ---

    #[test]
    fn connect_token_issues_jwt_with_expected_claims() {
        let client = test_client("ok");
        let resp = client
            .post("/identity/connect/token")
            .header(ContentType::Form)
            .body(format!(
                "grant_type=client_credentials&client_id={TOKEN_ID}&client_secret=testsecret&scope=api.secrets"
            ))
            .dispatch();

        assert_eq!(resp.status(), Status::Ok);
        let body: serde_json::Value = resp.into_json().unwrap();
        assert_eq!(body["token_type"], "Bearer");
        assert_eq!(body["expires_in"], 3600);
        assert_eq!(body["scope"], "api.secrets");
        assert_eq!(body["encrypted_payload"], "2.aaa|bbb|ccc");

        let claims = jwt_claims(body["access_token"].as_str().unwrap());
        assert_eq!(claims["type"], "ServiceAccount");
        assert_eq!(claims["client_id"], TOKEN_ID);
        assert_eq!(claims["sub"], MA_ID);
        assert_eq!(claims["organization"], ORG_ID);
        assert_eq!(claims["scope"][0], "api.secrets");
    }

    #[test]
    fn connect_token_rejects_wrong_secret() {
        let client = test_client("badsecret");
        let resp = client
            .post("/identity/connect/token")
            .header(ContentType::Form)
            .body(format!(
                "grant_type=client_credentials&client_id={TOKEN_ID}&client_secret=wrong"
            ))
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

    // --- projects ---

    #[test]
    fn list_projects_returns_accessible() {
        let client = test_client("projects");
        seed_project(client.rocket().state::<db::DbPool>().unwrap());
        let token = obtain_token(&client);

        let resp = client
            .get(format!("/api/organizations/{ORG_ID}/projects"))
            .header(Header::new("Authorization", format!("Bearer {token}")))
            .dispatch();

        assert_eq!(resp.status(), Status::Ok);
        let body: serde_json::Value = resp.into_json().unwrap();
        assert_eq!(body["object"], "list");
        assert_eq!(body["data"][0]["object"], "project");
        assert_eq!(body["data"][0]["id"], PROJECT_ID);
        assert_eq!(body["data"][0]["read"], true);
    }

    #[test]
    fn list_projects_other_org_is_404() {
        let client = test_client("projotherorg");
        let token = obtain_token(&client);

        let resp = client
            .get("/api/organizations/00000000-0000-0000-0000-000000000000/projects")
            .header(Header::new("Authorization", format!("Bearer {token}")))
            .dispatch();

        assert_eq!(resp.status(), Status::NotFound);
    }

    #[test]
    fn api_requires_bearer_token() {
        let client = test_client("noauth");
        let resp = client
            .get(format!("/api/organizations/{ORG_ID}/projects"))
            .dispatch();
        assert_eq!(resp.status(), Status::Unauthorized);
    }

    // --- secrets ---

    #[test]
    fn list_secrets_excludes_values() {
        let client = test_client("seclist");
        let pool = client.rocket().state::<db::DbPool>().unwrap();
        seed_project(pool);
        seed_secret(pool);
        let token = obtain_token(&client);

        let resp = client
            .get(format!("/api/organizations/{ORG_ID}/secrets"))
            .header(Header::new("Authorization", format!("Bearer {token}")))
            .dispatch();

        assert_eq!(resp.status(), Status::Ok);
        let body: serde_json::Value = resp.into_json().unwrap();
        assert_eq!(body["secrets"][0]["id"], SECRET_ID);
        assert!(body["secrets"][0]["value"].is_null());
        assert_eq!(body["secrets"][0]["projects"][0]["id"], PROJECT_ID);
    }

    #[test]
    fn get_secret_includes_value() {
        let client = test_client("secget");
        let pool = client.rocket().state::<db::DbPool>().unwrap();
        seed_project(pool);
        seed_secret(pool);
        let token = obtain_token(&client);

        let resp = client
            .get(format!("/api/secrets/{SECRET_ID}"))
            .header(Header::new("Authorization", format!("Bearer {token}")))
            .dispatch();

        assert_eq!(resp.status(), Status::Ok);
        let body: serde_json::Value = resp.into_json().unwrap();
        assert_eq!(body["object"], "secret");
        assert_eq!(body["id"], SECRET_ID);
        assert_eq!(body["value"], "2.v|v|v");
        assert_eq!(body["note"], "2.n|n|n");
    }

    #[test]
    fn sync_includes_values() {
        let client = test_client("secsync");
        let pool = client.rocket().state::<db::DbPool>().unwrap();
        seed_project(pool);
        seed_secret(pool);
        let token = obtain_token(&client);

        let resp = client
            .get(format!("/api/organizations/{ORG_ID}/secrets/sync"))
            .header(Header::new("Authorization", format!("Bearer {token}")))
            .dispatch();

        assert_eq!(resp.status(), Status::Ok);
        let body: serde_json::Value = resp.into_json().unwrap();
        assert_eq!(body["object"], "secretsSync");
        assert_eq!(body["hasChanges"], true);
        assert_eq!(body["secrets"]["object"], "list");
        assert_eq!(body["secrets"]["data"][0]["object"], "baseSecret");
        assert_eq!(body["secrets"]["data"][0]["value"], "2.v|v|v");
    }

    #[test]
    fn get_secret_unknown_is_404() {
        let client = test_client("secget404");
        let token = obtain_token(&client);

        let resp = client
            .get("/api/secrets/00000000-0000-0000-0000-000000000000")
            .header(Header::new("Authorization", format!("Bearer {token}")))
            .dispatch();

        assert_eq!(resp.status(), Status::NotFound);
    }

    #[test]
    fn create_secret_then_visible_in_sync() {
        let client = test_client("seccreate");
        seed_project(client.rocket().state::<db::DbPool>().unwrap());
        let token = obtain_token(&client);

        let resp = client
            .post(format!("/api/organizations/{ORG_ID}/secrets"))
            .header(Header::new("Authorization", format!("Bearer {token}")))
            .header(ContentType::JSON)
            .body(format!(
                r#"{{"key":"2.k|k|k","value":"2.v|v|v","note":"2.n|n|n","projectIds":["{PROJECT_ID}"]}}"#
            ))
            .dispatch();

        assert_eq!(resp.status(), Status::Ok);
        let body: serde_json::Value = resp.into_json().unwrap();
        assert_eq!(body["object"], "secret");
        assert_eq!(body["value"], "2.v|v|v");
        let new_id = body["id"].as_str().unwrap().to_string();

        let sync = client
            .get(format!("/api/organizations/{ORG_ID}/secrets/sync"))
            .header(Header::new("Authorization", format!("Bearer {token}")))
            .dispatch();
        let sbody: serde_json::Value = sync.into_json().unwrap();
        let found = sbody["secrets"]["data"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["id"] == new_id);
        assert!(found, "created secret should appear in sync");
    }

    #[test]
    fn delete_secret_removes_from_sync() {
        let client = test_client("secdelete");
        let pool = client.rocket().state::<db::DbPool>().unwrap();
        seed_project(pool);
        seed_secret(pool);
        let token = obtain_token(&client);

        let resp = client
            .post("/api/secrets/delete")
            .header(Header::new("Authorization", format!("Bearer {token}")))
            .header(ContentType::JSON)
            .body(format!(r#"["{SECRET_ID}"]"#))
            .dispatch();

        assert_eq!(resp.status(), Status::Ok);
        let body: serde_json::Value = resp.into_json().unwrap();
        assert_eq!(body["data"][0]["id"], SECRET_ID);
        assert!(body["data"][0]["error"].is_null());

        let sync = client
            .get(format!("/api/organizations/{ORG_ID}/secrets/sync"))
            .header(Header::new("Authorization", format!("Bearer {token}")))
            .dispatch();
        let sbody: serde_json::Value = sync.into_json().unwrap();
        assert_eq!(sbody["secrets"]["data"].as_array().unwrap().len(), 0);
    }

    // --- project CRUD ---

    #[test]
    fn create_project_then_listed_and_gettable() {
        let client = test_client("projcreate");
        let token = obtain_token(&client);

        let resp = client
            .post(format!("/api/organizations/{ORG_ID}/projects"))
            .header(Header::new("Authorization", format!("Bearer {token}")))
            .header(ContentType::JSON)
            .body(r#"{"name":"2.p|p|p"}"#)
            .dispatch();

        assert_eq!(resp.status(), Status::Ok);
        let body: serde_json::Value = resp.into_json().unwrap();
        assert_eq!(body["object"], "project");
        assert_eq!(body["write"], true);
        let pid = body["id"].as_str().unwrap().to_string();

        let got = client
            .get(format!("/api/projects/{pid}"))
            .header(Header::new("Authorization", format!("Bearer {token}")))
            .dispatch();
        assert_eq!(got.status(), Status::Ok);
        let gbody: serde_json::Value = got.into_json().unwrap();
        assert_eq!(gbody["id"], pid);
    }

    #[test]
    fn delete_project_removes_from_list() {
        let client = test_client("projdelete");
        seed_project(client.rocket().state::<db::DbPool>().unwrap());
        let token = obtain_token(&client);

        let resp = client
            .post("/api/projects/delete")
            .header(Header::new("Authorization", format!("Bearer {token}")))
            .header(ContentType::JSON)
            .body(format!(r#"["{PROJECT_ID}"]"#))
            .dispatch();

        assert_eq!(resp.status(), Status::Ok);
        let body: serde_json::Value = resp.into_json().unwrap();
        assert_eq!(body["data"][0]["id"], PROJECT_ID);
        assert!(body["data"][0]["error"].is_null());

        let list = client
            .get(format!("/api/organizations/{ORG_ID}/projects"))
            .header(Header::new("Authorization", format!("Bearer {token}")))
            .dispatch();
        let lbody: serde_json::Value = list.into_json().unwrap();
        assert_eq!(lbody["data"].as_array().unwrap().len(), 0);
    }
}
