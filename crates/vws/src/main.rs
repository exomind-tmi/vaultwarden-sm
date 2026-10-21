//! `vws` — the admin companion for vaultwarden-sm.
//!
//! It owns the two things `bws` cannot do against a bare server:
//!   * the admin control plane (organizations, machine accounts, access tokens, project access);
//!   * holding the organization key locally, so the server stays a zero-knowledge store.
//!
//! Every other subcommand is forwarded verbatim to `bws`, with the active access token and server
//! URL injected — so `vws secret list`, `vws project create`, `vws run …` all work as `bws` does.

mod admin;
mod profile;

use std::path::PathBuf;
use std::process::Command as ProcessCommand;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use admin::AdminClient;
use profile::{OrgEntry, Profile};
use sm_core::crypto;

#[derive(Parser)]
#[command(name = "vws", version, about = "vaultwarden-sm admin CLI and bws wrapper")]
struct Cli {
    /// Profile file to use.
    #[arg(long, global = true, env = "VWS_PROFILE")]
    profile: Option<PathBuf>,

    /// Override the server base URL (e.g. https://vault-sm.example.com).
    #[arg(long, global = true, env = "VWS_SERVER_URL")]
    server: Option<String>,

    /// Override the admin token.
    #[arg(long, global = true, env = "VWS_ADMIN_TOKEN")]
    admin_token: Option<String>,

    /// Accept invalid/self-signed TLS certificates (self-hosted convenience).
    #[arg(long, global = true)]
    insecure: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Save the server URL and admin token to the profile.
    Login {
        #[arg(long)]
        server: String,
        #[arg(long)]
        admin_token: String,
    },

    /// Organization administration.
    #[command(subcommand)]
    Org(OrgCmd),

    /// Machine account administration.
    #[command(subcommand, alias = "ma")]
    MachineAccount(MaCmd),

    /// Access token administration.
    #[command(subcommand, alias = "at")]
    AccessToken(AtCmd),

    /// Grant a machine account access to a project.
    Grant {
        #[arg(long = "machine-account", short = 'm')]
        machine_account: String,
        #[arg(long)]
        project: String,
        /// Withhold read access (read is granted by default).
        #[arg(long)]
        no_read: bool,
        /// Withhold write access (write is granted by default).
        #[arg(long)]
        no_write: bool,
    },

    /// Anything else is forwarded to `bws`.
    #[command(external_subcommand)]
    Bws(Vec<String>),
}

#[derive(Subcommand)]
enum OrgCmd {
    /// Create an organization, generate its org key locally, and make it current.
    Init {
        #[arg(long)]
        name: String,
        /// Use a specific id instead of a generated one.
        #[arg(long)]
        id: Option<String>,
    },
    /// List organizations known to the server.
    List,
    /// Switch the current organization.
    Use { org_id: String },
}

#[derive(Subcommand)]
enum MaCmd {
    /// Create a machine account in the current organization.
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        id: Option<String>,
    },
    /// List machine accounts in the current organization.
    List,
    /// Delete a machine account (and its tokens and project access).
    Delete { id: String },
}

#[derive(Subcommand)]
enum AtCmd {
    /// Issue an access token for a machine account. The token string is shown once.
    Create {
        #[arg(long = "machine-account", short = 'm')]
        machine_account: String,
        #[arg(long, default_value = "default")]
        name: String,
        /// Store the new token in the profile for `bws` passthrough.
        #[arg(long)]
        set_active: bool,
    },
    /// List a machine account's access tokens (metadata only; secrets are never recoverable).
    List {
        #[arg(long = "machine-account", short = 'm')]
        machine_account: String,
    },
    /// Revoke an access token.
    Delete { id: String },
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

/// Connection settings pulled from the CLI, so the command match can take `cli.command` by value
/// without leaving the rest of `cli` partially moved.
struct Ctx {
    server: Option<String>,
    admin_token: Option<String>,
    insecure: bool,
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let profile_path = Profile::resolve_path(cli.profile.clone())?;
    let mut profile = Profile::load(&profile_path)?;
    let ctx = Ctx {
        server: cli.server.clone(),
        admin_token: cli.admin_token.clone(),
        insecure: cli.insecure,
    };

    match cli.command {
        Command::Login {
            server,
            admin_token,
        } => {
            profile.server_url = Some(server.trim_end_matches('/').to_string());
            profile.admin_token = Some(admin_token);
            profile.save(&profile_path)?;
            println!("Saved server URL and admin token to {}", profile_path.display());
            Ok(())
        }

        Command::Org(cmd) => run_org(cmd, &ctx, &mut profile, &profile_path),
        Command::MachineAccount(cmd) => run_ma(cmd, &ctx, &profile),
        Command::AccessToken(cmd) => run_at(cmd, &ctx, &mut profile, &profile_path),

        Command::Grant {
            machine_account,
            project,
            no_read,
            no_write,
        } => {
            let client = admin_client(&ctx, &profile)?;
            client.grant_project_access(&machine_account, &project, !no_read, !no_write)?;
            println!(
                "Granted machine account {machine_account} access to project {project} (read={}, write={})",
                !no_read, !no_write
            );
            Ok(())
        }

        Command::Bws(args) => run_bws(&ctx, &profile, &args),
    }
}

/// Build an admin client from CLI overrides falling back to the profile.
fn admin_client(ctx: &Ctx, profile: &Profile) -> Result<AdminClient> {
    let server = ctx
        .server
        .clone()
        .or_else(|| profile.server_url.clone())
        .context("no server URL; run `vws login` or pass --server")?;
    let token = ctx
        .admin_token
        .clone()
        .or_else(|| profile.admin_token.clone())
        .context("no admin token; run `vws login` or pass --admin-token")?;
    AdminClient::new(&server, &token, ctx.insecure)
}

fn run_org(cmd: OrgCmd, ctx: &Ctx, profile: &mut Profile, path: &std::path::Path) -> Result<()> {
    let client = admin_client(ctx, profile)?;
    match cmd {
        OrgCmd::Init { name, id } => {
            let org_id = id.unwrap_or_else(new_id);
            // Generate the org key locally and keep it — the server only gets the id and label.
            let org_key = crypto::generate_org_key();
            let key_b64 = crypto::key_to_base64(&org_key);

            client.create_organization(&org_id, &name)?;

            profile.orgs.insert(
                org_id.clone(),
                OrgEntry {
                    name: name.clone(),
                    key_b64,
                },
            );
            profile.current_org = Some(org_id.clone());
            profile.save(path)?;

            println!("Created organization \"{name}\"");
            println!("  id:      {org_id}");
            println!("  org key: stored in {} (keep it safe — the server cannot recover it)", path.display());
            Ok(())
        }
        OrgCmd::List => {
            let resp = client.list_organizations()?;
            print_org_list(&resp);
            Ok(())
        }
        OrgCmd::Use { org_id } => {
            profile.current_org = Some(org_id.clone());
            profile.save(path)?;
            println!("Current organization is now {org_id}");
            Ok(())
        }
    }
}

fn run_ma(cmd: MaCmd, ctx: &Ctx, profile: &Profile) -> Result<()> {
    let client = admin_client(ctx, profile)?;
    match cmd {
        MaCmd::Create { name, id } => {
            let org_id = profile.require_org(None)?.to_string();
            let org_key = org_key(profile, &org_id)?;
            let ma_id = id.unwrap_or_else(new_id);
            let name_enc = crypto::encrypt_str(&name, &org_key)?;

            client.create_machine_account(&org_id, &ma_id, &name_enc)?;
            println!("Created machine account \"{name}\"");
            println!("  id: {ma_id}");
            Ok(())
        }
        MaCmd::List => {
            let org_id = profile.require_org(None)?.to_string();
            let org_key = org_key(profile, &org_id)?;
            let resp = client.list_machine_accounts(&org_id)?;
            print_named_list(&resp, "data", &org_key, "machine accounts");
            Ok(())
        }
        MaCmd::Delete { id } => {
            client.delete_machine_account(&id)?;
            println!("Deleted machine account {id}");
            Ok(())
        }
    }
}

fn run_at(cmd: AtCmd, ctx: &Ctx, profile: &mut Profile, path: &std::path::Path) -> Result<()> {
    let client = admin_client(ctx, profile)?;
    match cmd {
        AtCmd::Create {
            machine_account,
            name,
            set_active,
        } => {
            let org_id = profile.require_org(None)?.to_string();
            let org_key = org_key(profile, &org_id)?;

            // All token crypto happens here, locally, against the org key we hold.
            let token_id = new_id();
            let issued = crypto::issue_access_token(&token_id, &org_key)?;
            let name_enc = crypto::encrypt_str(&name, &org_key)?;

            client.create_access_token(
                &machine_account,
                &token_id,
                &name_enc,
                &issued.client_secret_hash,
                &issued.encrypted_payload,
                &issued.key_enc,
            )?;

            if set_active {
                profile.active_access_token = Some(issued.token_string.clone());
                profile.save(path)?;
            }

            println!("Access token \"{name}\" created for machine account {machine_account}.");
            println!("Save it now — it is shown only once:\n");
            println!("    {}", issued.token_string);
            if set_active {
                println!("\n(stored as the active token for `vws` → `bws` passthrough)");
            }
            Ok(())
        }
        AtCmd::List { machine_account } => {
            let org_id = profile.require_org(None)?.to_string();
            let org_key = org_key(profile, &org_id)?;
            let resp = client.list_access_tokens(&machine_account)?;
            print_named_list(&resp, "data", &org_key, "access tokens");
            Ok(())
        }
        AtCmd::Delete { id } => {
            client.delete_access_token(&id)?;
            println!("Revoked access token {id}");
            Ok(())
        }
    }
}

/// Forward a command to `bws`, injecting the active token and server URL from the profile.
fn run_bws(ctx: &Ctx, profile: &Profile, args: &[String]) -> Result<()> {
    let server = ctx.server.clone().or_else(|| profile.server_url.clone());

    let mut cmd = ProcessCommand::new("bws");
    cmd.args(args);
    if let Some(server) = server {
        cmd.env("BWS_SERVER_URL", server);
    }
    // Only inject the token if the caller has not already set one in the environment.
    if std::env::var_os("BWS_ACCESS_TOKEN").is_none() {
        if let Some(token) = &profile.active_access_token {
            cmd.env("BWS_ACCESS_TOKEN", token);
        }
    }

    let status = cmd
        .status()
        .context("failed to run `bws` — is it installed and on PATH?")?;
    std::process::exit(status.code().unwrap_or(1));
}

fn org_key(profile: &Profile, org_id: &str) -> Result<sm_core::bitwarden_crypto::SymmetricCryptoKey> {
    let entry = profile.org_entry(org_id)?;
    crypto::key_from_base64(&entry.key_b64).context("stored org key is corrupt")
}

fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn print_org_list(resp: &serde_json::Value) {
    let empty = vec![];
    let items = resp["data"].as_array().unwrap_or(&empty);
    if items.is_empty() {
        println!("(no organizations)");
        return;
    }
    for it in items {
        println!(
            "{}  {}",
            it["id"].as_str().unwrap_or("?"),
            it["name"].as_str().unwrap_or("")
        );
    }
}

/// Print a `{ data: [ { id, name } ] }` list, decrypting the `name` field with the org key.
fn print_named_list(
    resp: &serde_json::Value,
    field: &str,
    org_key: &sm_core::bitwarden_crypto::SymmetricCryptoKey,
    what: &str,
) {
    let empty = vec![];
    let items = resp[field].as_array().unwrap_or(&empty);
    if items.is_empty() {
        println!("(no {what})");
        return;
    }
    for it in items {
        let id = it["id"].as_str().unwrap_or("?");
        let name = it["name"]
            .as_str()
            .map(|enc| crypto::decrypt_str(enc, org_key).unwrap_or_else(|_| "<undecryptable>".into()))
            .unwrap_or_default();
        println!("{id}  {name}");
    }
}
