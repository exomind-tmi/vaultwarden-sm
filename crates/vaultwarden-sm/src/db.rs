//! Database connection (r2d2 pool) and embedded migration runner.

use diesel::prelude::*;
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

/// Lazily register an organization row so that projects/secrets/machine accounts — which reference
/// `organizations(id)` — can be written for it.
///
/// The federated web flow never provisions organizations explicitly: membership is resolved from
/// vaultwarden, and the first write into an org (a project, a secret, a service account) is what
/// creates its row here. The organization's name is unknown to this zero-knowledge backend, so it is
/// left blank. Idempotent — an existing row (e.g. one the `vws`/admin flow created) is left intact.
pub fn ensure_org(conn: &mut SqliteConnection, org_id: &str) -> QueryResult<()> {
    use crate::schema::organizations;
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    diesel::insert_into(organizations::table)
        .values((
            organizations::id.eq(org_id),
            organizations::name.eq(""),
            organizations::creation_date.eq(&now),
            organizations::revision_date.eq(&now),
        ))
        .on_conflict_do_nothing()
        .execute(conn)?;
    Ok(())
}
