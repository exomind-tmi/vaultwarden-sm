-- Secrets Manager — initial schema (MVP).
-- Zero-knowledge: *_enc columns hold EncString blobs the server never decrypts.
-- Dates are ISO-8601 TEXT (how SQLite stores chrono values).

-- Organization: lite container. Name stored in clear (like Organization.Name in Bitwarden).
CREATE TABLE organizations (
    id             TEXT NOT NULL PRIMARY KEY,
    name           TEXT NOT NULL,
    creation_date  TEXT NOT NULL,
    revision_date  TEXT NOT NULL
);

-- Machine account (service account).
CREATE TABLE machine_accounts (
    id               TEXT NOT NULL PRIMARY KEY,
    organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name_enc         TEXT NOT NULL,
    creation_date    TEXT NOT NULL,
    revision_date    TEXT NOT NULL
);
CREATE INDEX ix_machine_accounts_org ON machine_accounts(organization_id);

-- Access token (api key) of a machine account. Fields mirror Bitwarden's ApiKey.
CREATE TABLE access_tokens (
    id                  TEXT NOT NULL PRIMARY KEY,
    machine_account_id  TEXT NOT NULL REFERENCES machine_accounts(id) ON DELETE CASCADE,
    name_enc            TEXT NOT NULL,
    client_secret_hash  TEXT NOT NULL,          -- hash of client_secret (authentication)
    scope               TEXT NOT NULL,          -- JSON, e.g. ["api.secrets"]
    encrypted_payload   TEXT NOT NULL,          -- org key wrapped under the token key (served to bws)
    key_enc             TEXT NOT NULL,          -- token key wrapped under the org key (for admin recovery)
    expire_at           TEXT,
    creation_date       TEXT NOT NULL,
    revision_date       TEXT NOT NULL
);
CREATE INDEX ix_access_tokens_ma ON access_tokens(machine_account_id);

-- Project.
CREATE TABLE projects (
    id               TEXT NOT NULL PRIMARY KEY,
    organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name_enc         TEXT NOT NULL,
    creation_date    TEXT NOT NULL,
    revision_date    TEXT NOT NULL,
    deleted_date     TEXT
);
CREATE INDEX ix_projects_org ON projects(organization_id);

-- Secret.
CREATE TABLE secrets (
    id               TEXT NOT NULL PRIMARY KEY,
    organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    key_enc          TEXT NOT NULL,
    value_enc        TEXT NOT NULL,
    note_enc         TEXT,
    creation_date    TEXT NOT NULL,
    revision_date    TEXT NOT NULL,
    deleted_date     TEXT
);
CREATE INDEX ix_secrets_org ON secrets(organization_id);

-- Secret<->project link (M:N, like Bitwarden's ProjectSecret; in practice a secret is in <= 1 project).
CREATE TABLE project_secret (
    project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    secret_id   TEXT NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    PRIMARY KEY (project_id, secret_id)
);
CREATE INDEX ix_project_secret_secret ON project_secret(secret_id);

-- Machine-account access to a project (simplified access policy for the MVP).
CREATE TABLE machine_account_project_access (
    machine_account_id  TEXT NOT NULL REFERENCES machine_accounts(id) ON DELETE CASCADE,
    project_id          TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    can_read            INTEGER NOT NULL DEFAULT 1,
    can_write           INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (machine_account_id, project_id)
);
CREATE INDEX ix_ma_project_access_project ON machine_account_project_access(project_id);
