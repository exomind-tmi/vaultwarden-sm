mod db;
mod models;
mod schema;

fn main() -> anyhow::Result<()> {
    // TODO(step-server): replace with a Rocket launch (identity + Secrets Manager routes).
    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "vaultwarden-sm.db".to_string());

    let pool = db::init_pool(&database_url)?;
    db::run_migrations(&pool)?;

    println!("vaultwarden-sm: database ready ({database_url}), migrations applied.");
    Ok(())
}
