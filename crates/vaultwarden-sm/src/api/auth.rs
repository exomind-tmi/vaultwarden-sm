//! Request guard that authenticates a Secrets Manager machine-account access token
//! (Bearer JWT issued by our identity endpoint).

use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};

use crate::jwt::JwtSigner;

pub struct SmAuth {
    pub machine_account_id: String,
    pub organization_id: String,
    /// Reserved for future scope enforcement (all SM tokens carry "api.secrets").
    #[allow(dead_code)]
    pub scopes: Vec<String>,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for SmAuth {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let Some(signer) = req.rocket().state::<JwtSigner>() else {
            return Outcome::Error((Status::InternalServerError, ()));
        };

        let token = req
            .headers()
            .get_one("Authorization")
            .and_then(|h| h.strip_prefix("Bearer "));
        let Some(token) = token else {
            return Outcome::Error((Status::Unauthorized, ()));
        };

        match signer.validate(token) {
            Ok(claims) if claims.token_type == "ServiceAccount" => Outcome::Success(SmAuth {
                machine_account_id: claims.sub,
                organization_id: claims.organization,
                scopes: claims.scope,
            }),
            _ => Outcome::Error((Status::Unauthorized, ())),
        }
    }
}
