-- User access policies (people -> Secrets Manager resources).
-- Mirrors Bitwarden's UserProjectAccessPolicy / UserServiceAccountAccessPolicy, scoped to the
-- granular model: an org member who is not Owner/Admin sees only what is granted here.
-- user_id is a vaultwarden user UUID; users live in vaultwarden, so there is no local FK for it.

-- A person's access to a project's secrets.
CREATE TABLE user_project_access (
    user_id     TEXT NOT NULL,
    project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    can_read    INTEGER NOT NULL DEFAULT 1,
    can_write   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, project_id)
);
CREATE INDEX ix_user_project_access_project ON user_project_access(project_id);

-- A person's access to manage a machine account (view/rotate its tokens, change its project grants).
CREATE TABLE user_machine_account_access (
    user_id             TEXT NOT NULL,
    machine_account_id  TEXT NOT NULL REFERENCES machine_accounts(id) ON DELETE CASCADE,
    can_read            INTEGER NOT NULL DEFAULT 1,
    can_write           INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, machine_account_id)
);
CREATE INDEX ix_user_ma_access_ma ON user_machine_account_access(machine_account_id);
