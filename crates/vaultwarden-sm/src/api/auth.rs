//! Request guard that authenticates a caller of the Secrets Manager API into a [`Principal`].
//!
//! Two token kinds are accepted on the same routes:
//!  - a machine-account access token (a Bearer JWT our identity endpoint issued), verified with
//!    our own signing key;
//!  - a vaultwarden user session token (RS256, signed by vaultwarden), verified with vaultwarden's
//!    public key and resolved to the user's organization memberships.
//!
//! The user kind is only available when federation is configured (the [`Federation`] state is
//! present); otherwise only machine tokens authenticate.

use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};

use crate::access::Principal;
use crate::federation::Federation;
use crate::jwt::JwtSigner;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Principal {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let token = req
            .headers()
            .get_one("Authorization")
            .and_then(|h| h.strip_prefix("Bearer "));
        let Some(token) = token else {
            return Outcome::Error((Status::Unauthorized, ()));
        };

        // 1) Our own machine-account token.
        if let Some(signer) = req.rocket().state::<JwtSigner>() {
            if let Ok(claims) = signer.validate(token) {
                if claims.token_type == "ServiceAccount" {
                    return Outcome::Success(Principal::Machine {
                        machine_account_id: claims.sub,
                        organization_id: claims.organization,
                    });
                }
            }
        }

        // 2) A vaultwarden user session token, if federation is configured.
        if let Some(fed) = req.rocket().state::<Federation>() {
            if let Ok(user) = fed.verifier.validate(token) {
                return match fed.resolver.resolve(&user.user_id, token).await {
                    Ok(memberships) => Outcome::Success(Principal::User {
                        user_id: user.user_id,
                        memberships,
                    }),
                    // Token is valid but vaultwarden could not be reached to resolve membership —
                    // that is an upstream failure, not bad credentials.
                    Err(_) => Outcome::Error((Status::BadGateway, ())),
                };
            }
        }

        Outcome::Error((Status::Unauthorized, ()))
    }
}
