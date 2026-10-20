//! Database connection (r2d2 pool) and embedded migration runner.

use diesel::r2d2::{ConnectionManager, Pool};
use diesel::sqlite::SqliteConnection;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};

/// Migrations are embedded in the binary and applied on startup.
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

pub type DbPool = Pool<ConnectionManager<SqliteConnection>>;

/// Build a connection pool to the SQLite file.
pub fn init_pool(database_url: &str) -> anyhow::Result<DbPool> {
    let manager = ConnectionManager::<SqliteConnection>::new(database_url);
    let pool = Pool::builder().build(manager)?;
    Ok(pool)
}

/// Apply all pending migrations.
pub fn run_migrations(pool: &DbPool) -> anyhow::Result<()> {
    let mut conn = pool.get()?;
    conn.run_pending_migrations(MIGRATIONS)
        .map_err(|e| anyhow::anyhow!("failed to apply migrations: {e}"))?;
    Ok(())
}
