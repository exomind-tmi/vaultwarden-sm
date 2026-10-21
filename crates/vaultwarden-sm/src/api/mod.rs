//! HTTP API: identity (token issuance) and the Secrets Manager routes.

pub mod admin;
pub mod auth;
pub mod dto;
pub mod identity;
pub mod projects;
pub mod secrets;

use rocket::Route;

/// Routes mounted under `/api`.
pub fn api_routes() -> Vec<Route> {
    let mut routes = projects::routes();
    routes.extend(secrets::routes());
    routes
}
