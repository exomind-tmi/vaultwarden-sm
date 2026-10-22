//! HTTP API: identity (token issuance) and the Secrets Manager routes.

pub mod access_policies;
pub mod admin;
pub mod auth;
pub mod counts;
pub mod dto;
pub mod identity;
pub mod projects;
pub mod secrets;
pub mod service_accounts;

use rocket::Route;

/// Routes mounted under `/api`.
pub fn api_routes() -> Vec<Route> {
    let mut routes = projects::routes();
    routes.extend(secrets::routes());
    routes.extend(service_accounts::routes());
    routes.extend(counts::routes());
    routes.extend(access_policies::routes());
    routes
}
