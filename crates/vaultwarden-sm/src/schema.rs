// Diesel schema. Matches migrations/2026-10-20-000001_init/up.sql.
// (Regenerate with: `diesel print-schema > src/schema.rs`.)

diesel::table! {
    organizations (id) {
        id -> Text,
        name -> Text,
        creation_date -> Text,
        revision_date -> Text,
    }
}

diesel::table! {
    machine_accounts (id) {
        id -> Text,
        organization_id -> Text,
        name_enc -> Text,
        creation_date -> Text,
        revision_date -> Text,
    }
}

diesel::table! {
    access_tokens (id) {
        id -> Text,
        machine_account_id -> Text,
        name_enc -> Text,
        client_secret_hash -> Text,
        scope -> Text,
        encrypted_payload -> Text,
        key_enc -> Text,
        expire_at -> Nullable<Text>,
        creation_date -> Text,
        revision_date -> Text,
    }
}

diesel::table! {
    projects (id) {
        id -> Text,
        organization_id -> Text,
        name_enc -> Text,
        creation_date -> Text,
        revision_date -> Text,
        deleted_date -> Nullable<Text>,
    }
}

diesel::table! {
    secrets (id) {
        id -> Text,
        organization_id -> Text,
        key_enc -> Text,
        value_enc -> Text,
        note_enc -> Nullable<Text>,
        creation_date -> Text,
        revision_date -> Text,
        deleted_date -> Nullable<Text>,
    }
}

diesel::table! {
    project_secret (project_id, secret_id) {
        project_id -> Text,
        secret_id -> Text,
    }
}

diesel::table! {
    machine_account_project_access (machine_account_id, project_id) {
        machine_account_id -> Text,
        project_id -> Text,
        can_read -> Integer,
        can_write -> Integer,
    }
}

diesel::joinable!(machine_accounts -> organizations (organization_id));
diesel::joinable!(access_tokens -> machine_accounts (machine_account_id));
diesel::joinable!(projects -> organizations (organization_id));
diesel::joinable!(secrets -> organizations (organization_id));

diesel::allow_tables_to_appear_in_same_query!(
    organizations,
    machine_accounts,
    access_tokens,
    projects,
    secrets,
    project_secret,
    machine_account_project_access,
);
