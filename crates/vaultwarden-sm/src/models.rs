//! Diesel models. For the MVP a single struct per table serves both reads and inserts.
//! Dates are stored as ISO-8601 TEXT; conversion to/from chrono lives in the logic layer.

use diesel::prelude::*;

use crate::schema::*;

#[derive(Queryable, Insertable, Debug, Clone)]
#[diesel(table_name = organizations)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub creation_date: String,
    pub revision_date: String,
}

#[derive(Queryable, Insertable, Debug, Clone)]
#[diesel(table_name = machine_accounts)]
pub struct MachineAccount {
    pub id: String,
    pub organization_id: String,
    pub name_enc: String,
    pub creation_date: String,
    pub revision_date: String,
}

#[derive(Queryable, Insertable, Debug, Clone)]
#[diesel(table_name = access_tokens)]
pub struct AccessToken {
    pub id: String,
    pub machine_account_id: String,
    pub name_enc: String,
    pub client_secret_hash: String,
    pub scope: String,
    pub encrypted_payload: String,
    pub key_enc: String,
    pub expire_at: Option<String>,
    pub creation_date: String,
    pub revision_date: String,
}

#[derive(Queryable, Insertable, Debug, Clone)]
#[diesel(table_name = projects)]
pub struct Project {
    pub id: String,
    pub organization_id: String,
    pub name_enc: String,
    pub creation_date: String,
    pub revision_date: String,
    pub deleted_date: Option<String>,
}

#[derive(Queryable, Insertable, Debug, Clone)]
#[diesel(table_name = secrets)]
pub struct Secret {
    pub id: String,
    pub organization_id: String,
    pub key_enc: String,
    pub value_enc: String,
    pub note_enc: Option<String>,
    pub creation_date: String,
    pub revision_date: String,
    pub deleted_date: Option<String>,
}

#[derive(Queryable, Insertable, Debug, Clone)]
#[diesel(table_name = project_secret)]
pub struct ProjectSecret {
    pub project_id: String,
    pub secret_id: String,
}

#[derive(Queryable, Insertable, Debug, Clone)]
#[diesel(table_name = machine_account_project_access)]
pub struct MachineAccountProjectAccess {
    pub machine_account_id: String,
    pub project_id: String,
    pub can_read: i32,
    pub can_write: i32,
}
