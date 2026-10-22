mod access;
mod api;
mod db;
mod federation;
mod jwt;
mod membership;
mod models;
mod schema;

use std::path::PathBuf;
use std::time::Duration;

use rocket::{Build, Rocket};

/// How long a resolved membership may be cached before vaultwarden is asked again.
const MEMBERSHIP_TTL: Duration = Duration::from_secs(60);

/// Build the Rocket instance. Shared by `main` and the integration tests. `federation` is `Some`
/// when the user flow is enabled (vaultwarden key mounted); `None` leaves only the machine flow.
pub fn build_rocket(
    pool: db::DbPool,
    signer: jwt::JwtSigner,
    admin_token: Option<String>,
    federation: Option<federation::Federation>,
) -> Rocket<Build> {
    let mut rocket = rocket::build()
        .manage(pool)
        .manage(signer)
        .manage(api::admin::AdminConfig {
            token: admin_token,
        })
        .mount("/identity", api::identity::routes())
        .mount("/api", api::api_routes())
        .mount("/admin", api::admin::routes());

    if let Some(federation) = federation {
        rocket = rocket.manage(federation);
    }
    rocket
}

#[rocket::main]
async fn main() -> anyhow::Result<()> {
    let data_dir = std::env::var("DATA_DIR").unwrap_or_else(|_| "data".to_string());
    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| format!("{data_dir}/vaultwarden-sm.db"));
    let domain = std::env::var("DOMAIN").unwrap_or_else(|_| "http://localhost".to_string());
    let rsa_key_path = PathBuf::from(&data_dir).join("rsa_key.pem");

    // The admin token guards the `/admin` control plane `vws` uses. Unset => admin API disabled.
    let admin_token = std::env::var("ADMIN_TOKEN").ok().filter(|t| !t.is_empty());

    std::fs::create_dir_all(&data_dir).ok();

    let pool = db::init_pool(&database_url)?;
    db::run_migrations(&pool)?;

    let signer = jwt::JwtSigner::load_or_create(&rsa_key_path, domain.clone())?;

    let federation = load_federation(&domain);

    build_rocket(pool, signer, admin_token, federation)
        .launch()
        .await?;

    Ok(())
}

/// Build the federation layer from the environment, or `None` (user flow disabled) when the
/// vaultwarden RSA key is not configured or not readable. `domain` is the origin both services
/// share (vaultwarden's login issuer is `"{domain}|login"`).
///
/// - `VAULTWARDEN_RSA_KEY_PATH`: path to vaultwarden's `rsa_key.pem`, mounted read-only.
/// - `VAULTWARDEN_URL`: vaultwarden's internal base URL on the shared network (default
///   `http://vaultwarden`), never the public domain.
fn load_federation(domain: &str) -> Option<federation::Federation> {
    let key_path = std::env::var("VAULTWARDEN_RSA_KEY_PATH").ok()?;
    let vw_base =
        std::env::var("VAULTWARDEN_URL").unwrap_or_else(|_| "http://vaultwarden".to_string());

    match federation::Federation::load(
        std::path::Path::new(&key_path),
        domain,
        &vw_base,
        MEMBERSHIP_TTL,
    ) {
        Ok(fed) => {
            eprintln!("federation enabled: verifying vaultwarden users via {key_path}");
            Some(fed)
        }
        Err(e) => {
            eprintln!("federation disabled: could not load vaultwarden key {key_path}: {e}");
            None
        }
    }
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
        Client::tracked(build_rocket(pool, signer, None, None)).unwrap()
    }

    const ADMIN_TOKEN: &str = "test-admin-token";

    /// A client with a fresh (empty) database and the admin API enabled. Used by admin tests,
    /// which provision everything through `/admin` rather than seeding rows directly.
    fn admin_client(uniq: &str) -> Client {
        let dir = std::env::temp_dir();
        let db_path = dir.join(format!("vwsm-admin-{uniq}.db"));
        let pem_path = dir.join(format!("vwsm-admin-{uniq}.pem"));
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(&pem_path);

        let pool = db::init_pool(db_path.to_str().unwrap()).unwrap();
        db::run_migrations(&pool).unwrap();
        let signer = jwt::JwtSigner::load_or_create(&pem_path, "http://localhost".into()).unwrap();
        Client::tracked(build_rocket(pool, signer, Some(ADMIN_TOKEN.into()), None)).unwrap()
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

    // --- end to end ---

    #[test]
    fn end_to_end_issue_authenticate_recover_and_sync() {
        let dir = std::env::temp_dir();
        let db_path = dir.join("vwsm-test-e2e.db");
        let pem_path = dir.join("vwsm-test-e2e.pem");
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(&pem_path);

        let pool = db::init_pool(db_path.to_str().unwrap()).unwrap();
        db::run_migrations(&pool).unwrap();

        // Issue a real access token against a fresh org key.
        let org_key = sm_core::crypto::generate_org_key();
        let issued = sm_core::crypto::issue_access_token(TOKEN_ID, &org_key).unwrap();

        {
            use crate::schema::{
                access_tokens, machine_account_project_access as mapa, machine_accounts,
                organizations, project_secret, projects, secrets,
            };
            let mut conn = pool.get().unwrap();
            let now = "2026-10-20T00:00:00Z".to_string();
            diesel::insert_into(organizations::table)
                .values(&Organization {
                    id: ORG_ID.into(),
                    name: "Org".into(),
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
            diesel::insert_into(access_tokens::table)
                .values(&AccessToken {
                    id: TOKEN_ID.into(),
                    machine_account_id: MA_ID.into(),
                    name_enc: "2.x|y|z".into(),
                    client_secret_hash: issued.client_secret_hash.clone(),
                    scope: "[\"api.secrets\"]".into(),
                    encrypted_payload: issued.encrypted_payload.clone(),
                    key_enc: issued.key_enc.clone(),
                    expire_at: None,
                    creation_date: now.clone(),
                    revision_date: now.clone(),
                })
                .execute(&mut conn)
                .unwrap();
            diesel::insert_into(projects::table)
                .values(&Project {
                    id: PROJECT_ID.into(),
                    organization_id: ORG_ID.into(),
                    name_enc: "2.p|p|p".into(),
                    creation_date: now.clone(),
                    revision_date: now.clone(),
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
            diesel::insert_into(secrets::table)
                .values(&Secret {
                    id: SECRET_ID.into(),
                    organization_id: ORG_ID.into(),
                    key_enc: "2.k|k|k".into(),
                    value_enc: "2.v|v|v".into(),
                    note_enc: None,
                    creation_date: now.clone(),
                    revision_date: now.clone(),
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

        let signer = jwt::JwtSigner::load_or_create(&pem_path, "http://localhost".into()).unwrap();
        let client = Client::tracked(build_rocket(pool, signer, None, None)).unwrap();

        // The client parses its own token string to get the secret and derive the token key.
        let at = sm_core::crypto::AccessToken::parse(&issued.token_string).unwrap();

        // 1) Authenticate.
        let resp = client
            .post("/identity/connect/token")
            .header(ContentType::Form)
            .body(format!(
                "grant_type=client_credentials&client_id={TOKEN_ID}&client_secret={}",
                at.client_secret
            ))
            .dispatch();
        assert_eq!(resp.status(), Status::Ok);
        let body: serde_json::Value = resp.into_json().unwrap();
        let bearer = body["access_token"].as_str().unwrap().to_string();
        let payload = body["encrypted_payload"].as_str().unwrap();

        // 2) Recover the org key from the payload via the token key (as bws would).
        let token_key = at.derive_key();
        let recovered = sm_core::crypto::recover_org_key(payload, &token_key).unwrap();
        assert_eq!(
            recovered.to_base64().to_string(),
            org_key.to_base64().to_string()
        );

        // 3) Use the bearer JWT to sync secrets.
        let sync = client
            .get(format!("/api/organizations/{ORG_ID}/secrets/sync"))
            .header(Header::new("Authorization", format!("Bearer {bearer}")))
            .dispatch();
        assert_eq!(sync.status(), Status::Ok);
        let sbody: serde_json::Value = sync.into_json().unwrap();
        assert_eq!(sbody["secrets"]["data"][0]["id"], SECRET_ID);
    }

    // --- admin API ---

    fn admin_header() -> Header<'static> {
        Header::new("Authorization", format!("Bearer {ADMIN_TOKEN}"))
    }

    #[test]
    fn admin_requires_token() {
        let client = admin_client("noauth");
        // Missing bearer.
        let resp = client.get("/admin/organizations").dispatch();
        assert_eq!(resp.status(), Status::Unauthorized);
        // Wrong bearer.
        let resp = client
            .get("/admin/organizations")
            .header(Header::new("Authorization", "Bearer wrong"))
            .dispatch();
        assert_eq!(resp.status(), Status::Unauthorized);
    }

    #[test]
    fn admin_disabled_without_configured_token() {
        // test_client builds the rocket with admin_token = None.
        let client = test_client("admindisabled");
        let resp = client
            .get("/admin/organizations")
            .header(Header::new("Authorization", "Bearer anything"))
            .dispatch();
        assert_eq!(resp.status(), Status::ServiceUnavailable);
    }

    /// The full control-plane flow exactly as `vws` drives it: the admin (holding the org key
    /// locally) provisions an org, a machine account, and an access token through `/admin`, then
    /// a `bws`-style client authenticates, recovers the org key, and uses the SM API.
    #[test]
    fn admin_bootstrap_then_authenticate_and_use_sm_api() {
        let client = admin_client("bootstrap");

        // The admin generates the org key locally; the server never receives it in plaintext.
        let org_key = sm_core::crypto::generate_org_key();
        let org_id = uuid::Uuid::new_v4().to_string();
        let ma_id = uuid::Uuid::new_v4().to_string();
        let token_id = uuid::Uuid::new_v4().to_string();

        // 1) Create organization.
        let resp = client
            .post("/admin/organizations")
            .header(admin_header())
            .header(ContentType::JSON)
            .body(serde_json::json!({ "id": org_id, "name": "Acme" }).to_string())
            .dispatch();
        assert_eq!(resp.status(), Status::Ok);

        // 2) Create machine account (name encrypted locally under the org key).
        let ma_name_enc = sm_core::crypto::encrypt_str("ci-runner", &org_key).unwrap();
        let resp = client
            .post(format!("/admin/organizations/{org_id}/machine-accounts"))
            .header(admin_header())
            .header(ContentType::JSON)
            .body(serde_json::json!({ "id": ma_id, "nameEnc": ma_name_enc }).to_string())
            .dispatch();
        assert_eq!(resp.status(), Status::Ok);

        // 3) Issue an access token locally, then register its public parts with the server.
        let issued = sm_core::crypto::issue_access_token(&token_id, &org_key).unwrap();
        let token_name_enc = sm_core::crypto::encrypt_str("default", &org_key).unwrap();
        let resp = client
            .post(format!("/admin/machine-accounts/{ma_id}/access-tokens"))
            .header(admin_header())
            .header(ContentType::JSON)
            .body(
                serde_json::json!({
                    "id": token_id,
                    "nameEnc": token_name_enc,
                    "clientSecretHash": issued.client_secret_hash,
                    "encryptedPayload": issued.encrypted_payload,
                    "keyEnc": issued.key_enc,
                })
                .to_string(),
            )
            .dispatch();
        assert_eq!(resp.status(), Status::Ok);

        // 4) The client authenticates with the token string (as bws does).
        let at = sm_core::crypto::AccessToken::parse(&issued.token_string).unwrap();
        let resp = client
            .post("/identity/connect/token")
            .header(ContentType::Form)
            .body(format!(
                "grant_type=client_credentials&client_id={token_id}&client_secret={}",
                at.client_secret
            ))
            .dispatch();
        assert_eq!(resp.status(), Status::Ok);
        let body: serde_json::Value = resp.into_json().unwrap();
        let bearer = body["access_token"].as_str().unwrap().to_string();
        let payload = body["encrypted_payload"].as_str().unwrap();

        // 5) Recover the org key from the payload — proves the round trip over the real wire.
        let token_key = at.derive_key();
        let recovered = sm_core::crypto::recover_org_key(payload, &token_key).unwrap();
        assert_eq!(recovered.to_base64(), org_key.to_base64());

        // 6) Create a project and a secret through the SM API, encrypting under the org key.
        let proj_name_enc = sm_core::crypto::encrypt_str("prod", &org_key).unwrap();
        let resp = client
            .post(format!("/api/organizations/{org_id}/projects"))
            .header(Header::new("Authorization", format!("Bearer {bearer}")))
            .header(ContentType::JSON)
            .body(serde_json::json!({ "name": proj_name_enc }).to_string())
            .dispatch();
        assert_eq!(resp.status(), Status::Ok);
        let pbody: serde_json::Value = resp.into_json().unwrap();
        let project_id = pbody["id"].as_str().unwrap().to_string();

        let key_enc = sm_core::crypto::encrypt_str("DB_PASSWORD", &org_key).unwrap();
        let value_enc = sm_core::crypto::encrypt_str("s3cr3t", &org_key).unwrap();
        let resp = client
            .post(format!("/api/organizations/{org_id}/secrets"))
            .header(Header::new("Authorization", format!("Bearer {bearer}")))
            .header(ContentType::JSON)
            .body(
                serde_json::json!({
                    "key": key_enc,
                    "value": value_enc,
                    "note": "",
                    "projectIds": [project_id],
                })
                .to_string(),
            )
            .dispatch();
        assert_eq!(resp.status(), Status::Ok);

        // 7) Sync and decrypt the secret value with the recovered org key.
        let sync = client
            .get(format!("/api/organizations/{org_id}/secrets/sync"))
            .header(Header::new("Authorization", format!("Bearer {bearer}")))
            .dispatch();
        assert_eq!(sync.status(), Status::Ok);
        let sbody: serde_json::Value = sync.into_json().unwrap();
        let enc_value = sbody["secrets"]["data"][0]["value"].as_str().unwrap();
        let decrypted = sm_core::crypto::decrypt_str(enc_value, &recovered).unwrap();
        assert_eq!(decrypted, "s3cr3t");
    }

    #[test]
    fn admin_grant_project_access_rejects_cross_org() {
        let client = admin_client("crossorg");
        let org_key = sm_core::crypto::generate_org_key();
        let org_id = uuid::Uuid::new_v4().to_string();
        let ma_id = uuid::Uuid::new_v4().to_string();

        client
            .post("/admin/organizations")
            .header(admin_header())
            .header(ContentType::JSON)
            .body(serde_json::json!({ "id": org_id, "name": "Acme" }).to_string())
            .dispatch();
        let ma_name_enc = sm_core::crypto::encrypt_str("runner", &org_key).unwrap();
        client
            .post(format!("/admin/organizations/{org_id}/machine-accounts"))
            .header(admin_header())
            .header(ContentType::JSON)
            .body(serde_json::json!({ "id": ma_id, "nameEnc": ma_name_enc }).to_string())
            .dispatch();

        // Granting access to a project that does not exist is a 404.
        let resp = client
            .post(format!("/admin/machine-accounts/{ma_id}/project-access"))
            .header(admin_header())
            .header(ContentType::JSON)
            .body(
                serde_json::json!({
                    "projectId": uuid::Uuid::new_v4().to_string(),
                    "read": true,
                    "write": true,
                })
                .to_string(),
            )
            .dispatch();
        assert_eq!(resp.status(), Status::NotFound);
    }

    // --- federation (vaultwarden user) flow over HTTP ---

    use jsonwebtoken::{Algorithm as JwtAlg, EncodingKey, Header as JwtHeader};
    use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding as RsaLineEnding};
    use rsa::RsaPrivateKey;

    const FED_ORIGIN: &str = "https://vault.exomind-tmi.com";

    #[derive(serde::Serialize)]
    struct UserClaims {
        iss: String,
        sub: String,
        email: String,
        name: String,
        nbf: i64,
        exp: i64,
    }

    /// A fresh RSA key as PKCS#1 PEM — the shape vaultwarden persists in `rsa_key.pem`.
    fn fed_key_pem() -> String {
        let mut rng = rand::thread_rng();
        let key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        key.to_pkcs1_pem(RsaLineEnding::LF).unwrap().to_string()
    }

    /// Sign a vaultwarden-style user session token (RS256, login issuer) with the given key.
    fn sign_user_token(pem: &str, sub: &str) -> String {
        let now = chrono::Utc::now().timestamp();
        let claims = UserClaims {
            iss: format!("{FED_ORIGIN}|login"),
            sub: sub.into(),
            email: "u@example.com".into(),
            name: "User".into(),
            nbf: now - 10,
            exp: now + 3600,
        };
        let enc = EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
        jsonwebtoken::encode(&JwtHeader::new(JwtAlg::RS256), &claims, &enc).unwrap()
    }

    /// Stand in for vaultwarden's `/api/accounts/profile`: answer every connection with the same
    /// profile JSON (all the membership resolver reads) and close. The listener binds before the
    /// port is returned, so the socket is accepting by the time the resolver calls it.
    fn start_profile_stub(profile: String) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    profile.len(),
                    profile
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        });
        format!("http://127.0.0.1:{port}")
    }

    fn profile_json(sub: &str, org_type: i32) -> String {
        format!(
            r#"{{"object":"profile","id":"{sub}","organizations":[{{"id":"{ORG_ID}","type":{org_type},"status":2,"enabled":true}}]}}"#
        )
    }

    /// A federation-enabled server with one org, one project and one machine account seeded, wired
    /// to the given vaultwarden profile stub and verifying tokens with `pem`.
    fn fed_client(uniq: &str, pem: &str, vw_base: &str) -> Client {
        let dir = std::env::temp_dir();
        let db_path = dir.join(format!("vwsm-fed-{uniq}.db"));
        let signer_pem = dir.join(format!("vwsm-fed-signer-{uniq}.pem"));
        let vw_pem = dir.join(format!("vwsm-fed-vwkey-{uniq}.pem"));
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(&signer_pem);
        std::fs::write(&vw_pem, pem).unwrap();

        let pool = db::init_pool(db_path.to_str().unwrap()).unwrap();
        db::run_migrations(&pool).unwrap();

        {
            use crate::schema::{machine_accounts, organizations, projects};
            let mut conn = pool.get().unwrap();
            let now = "2026-10-22T00:00:00Z".to_string();
            diesel::insert_into(organizations::table)
                .values(&Organization {
                    id: ORG_ID.into(),
                    name: "Org".into(),
                    creation_date: now.clone(),
                    revision_date: now.clone(),
                })
                .execute(&mut conn)
                .unwrap();
            diesel::insert_into(projects::table)
                .values(&Project {
                    id: PROJECT_ID.into(),
                    organization_id: ORG_ID.into(),
                    name_enc: "2.p|p|p".into(),
                    creation_date: now.clone(),
                    revision_date: now.clone(),
                    deleted_date: None,
                })
                .execute(&mut conn)
                .unwrap();
            diesel::insert_into(machine_accounts::table)
                .values(&MachineAccount {
                    id: MA_ID.into(),
                    organization_id: ORG_ID.into(),
                    name_enc: "2.m|m|m".into(),
                    creation_date: now.clone(),
                    revision_date: now,
                })
                .execute(&mut conn)
                .unwrap();
        }

        let signer = jwt::JwtSigner::load_or_create(&signer_pem, "http://localhost".into()).unwrap();
        let fed = federation::Federation::load(&vw_pem, FED_ORIGIN, vw_base, MEMBERSHIP_TTL).unwrap();
        Client::tracked(build_rocket(pool, signer, None, Some(fed))).unwrap()
    }

    #[test]
    fn federation_admin_user_flow_over_http() {
        let pem = fed_key_pem();
        let sub = "aaaaaaaa-1111-2222-3333-444444444444";
        let vw = start_profile_stub(profile_json(sub, 1)); // type 1 = Admin
        let client = fed_client("admin", &pem, &vw);
        let token = sign_user_token(&pem, sub);
        let bearer = Header::new("Authorization", format!("Bearer {token}"));

        // Admin sees the seeded machine account.
        let resp = client
            .get(format!("/api/organizations/{ORG_ID}/service-accounts"))
            .header(bearer.clone())
            .dispatch();
        assert_eq!(resp.status(), Status::Ok);
        let body: serde_json::Value = resp.into_json().unwrap();
        assert_eq!(body["data"][0]["id"], MA_ID);
        assert_eq!(body["data"][0]["object"], "serviceAccount");

        // Counts reflect the seed: one project, no secrets, one service account.
        let resp = client
            .get(format!("/api/organizations/{ORG_ID}/sm-counts"))
            .header(bearer.clone())
            .dispatch();
        assert_eq!(resp.status(), Status::Ok);
        let counts: serde_json::Value = resp.into_json().unwrap();
        assert_eq!(counts["object"], "organizationCounts");
        assert_eq!(counts["projects"], 1);
        assert_eq!(counts["secrets"], 0);
        assert_eq!(counts["serviceAccounts"], 1);

        // Admin creates a service account.
        let resp = client
            .post(format!("/api/organizations/{ORG_ID}/service-accounts"))
            .header(bearer.clone())
            .header(ContentType::JSON)
            .body(r#"{"name":"2.n|n|n"}"#)
            .dispatch();
        assert_eq!(resp.status(), Status::Ok);

        // Grant a person read on the project, then read the policy back.
        let grantee = "bbbbbbbb-5555-6666-7777-888888888888";
        let resp = client
            .put(format!("/api/projects/{PROJECT_ID}/access-policies/people"))
            .header(bearer.clone())
            .header(ContentType::JSON)
            .body(format!(
                r#"{{"userAccessPolicyRequests":[{{"granteeId":"{grantee}","read":true,"write":false}}]}}"#
            ))
            .dispatch();
        assert_eq!(resp.status(), Status::Ok);

        let resp = client
            .get(format!("/api/projects/{PROJECT_ID}/access-policies/people"))
            .header(bearer)
            .dispatch();
        assert_eq!(resp.status(), Status::Ok);
        let pol: serde_json::Value = resp.into_json().unwrap();
        assert_eq!(pol["object"], "projectPeopleAccessPolicies");
        assert_eq!(pol["userAccessPolicies"][0]["organizationUserId"], grantee);
        assert_eq!(pol["userAccessPolicies"][0]["read"], true);
    }

    #[test]
    fn federation_member_user_flow_is_granular() {
        let pem = fed_key_pem();
        let sub = "cccccccc-1111-2222-3333-444444444444";
        let vw = start_profile_stub(profile_json(sub, 2)); // type 2 = regular User (member)
        let client = fed_client("member", &pem, &vw);

        // Grant this member read+write on the seeded project (as an admin would via the policy API).
        {
            use crate::schema::user_project_access as upa;
            let mut conn = client.rocket().state::<db::DbPool>().unwrap().get().unwrap();
            diesel::insert_into(upa::table)
                .values(&crate::models::UserProjectAccess {
                    user_id: sub.into(),
                    project_id: PROJECT_ID.into(),
                    can_read: 1,
                    can_write: 1,
                })
                .execute(&mut conn)
                .unwrap();
        }

        let token = sign_user_token(&pem, sub);
        let bearer = Header::new("Authorization", format!("Bearer {token}"));

        // The member sees exactly the one granted project.
        let resp = client
            .get(format!("/api/organizations/{ORG_ID}/projects"))
            .header(bearer.clone())
            .dispatch();
        assert_eq!(resp.status(), Status::Ok);
        let body: serde_json::Value = resp.into_json().unwrap();
        let ids: Vec<&str> = body["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, [PROJECT_ID]);

        // No machine accounts are granted to this member, so the list is empty.
        let resp = client
            .get(format!("/api/organizations/{ORG_ID}/service-accounts"))
            .header(bearer.clone())
            .dispatch();
        assert_eq!(resp.status(), Status::Ok);
        let body: serde_json::Value = resp.into_json().unwrap();
        assert_eq!(body["data"].as_array().unwrap().len(), 0);

        // A member may create neither projects nor service accounts.
        let resp = client
            .post(format!("/api/organizations/{ORG_ID}/projects"))
            .header(bearer.clone())
            .header(ContentType::JSON)
            .body(r#"{"name":"2.x|x|x"}"#)
            .dispatch();
        assert_eq!(resp.status(), Status::Forbidden);

        let resp = client
            .post(format!("/api/organizations/{ORG_ID}/service-accounts"))
            .header(bearer)
            .header(ContentType::JSON)
            .body(r#"{"name":"2.x|x|x"}"#)
            .dispatch();
        assert_eq!(resp.status(), Status::Forbidden);
    }
}
