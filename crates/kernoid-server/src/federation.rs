// SPDX-License-Identifier: AGPL-3.0-or-later
//! Logging in with an external identity provider over HTTP (RFC 0001, 7.7): where an address logs in, starting the
//! login, the provider's callback, and exchanging the result for a session.

use std::time::Duration;

use axum::{
    Json,
    extract::{Extension, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    AppState, Client, CurrentInstance, Problem, oidc,
    sessions::{SessionCreated, client_meta},
};

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub(crate) struct AddressQuery {
    /// The address someone types in to log in.
    address: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct ProviderSummary {
    id: String,
    name: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct LoginOptions {
    /// If set, this address logs in at that identity provider instead of with a password.
    identity_provider: Option<ProviderSummary>,
}

/// Where an address logs in: at an identity provider its domain is routed to, or with kernoid's own login. Says
/// nothing about whether the account exists.
#[utoipa::path(get, path = "/v1/login-options", tag = "login", params(AddressQuery),
    responses((status = 200, body = LoginOptions)))]
pub(crate) async fn login_options(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    Query(query): Query<AddressQuery>,
) -> Response {
    match state.oidc.login_options(instance.id, &query.address).await {
        Ok(found) => Json(LoginOptions {
            identity_provider: found.map(|idp| ProviderSummary { id: idp.id.to_string(), name: idp.name }),
        })
        .into_response(),
        Err(error) => oidc::problem(error),
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct StartLogin {
    identity_provider: String,
    /// The OpenID Connect auth request to finish afterwards, if any.
    auth_request: Option<String>,
    /// The address typed in, passed on as `login_hint`.
    login_hint: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct StartedLogin {
    /// Send the browser here.
    url: String,
}

/// Starts a login at an identity provider; answers with where to send the browser.
#[utoipa::path(post, path = "/v1/idp-logins", tag = "login", request_body = StartLogin, responses(
    (status = 200, body = StartedLogin),
    (status = 400, description = "the provider cannot be reached", body = Problem),
    (status = 404, description = "no such identity provider", body = Problem),
))]
pub(crate) async fn start(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    Json(body): Json<StartLogin>,
) -> Response {
    let Ok(idp) = Uuid::parse_str(&body.identity_provider) else {
        return Problem::new(StatusCode::NOT_FOUND).detail("the identity provider does not exist").into_response();
    };
    match state.oidc.start_idp_login(&instance, idp, body.auth_request.as_deref(), body.login_hint.as_deref()).await {
        Ok(url) => Json(StartedLogin { url }).into_response(),
        Err(error) => oidc::problem(error),
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct Callback {
    state: Option<String>,
    code: Option<String>,
    error: Option<String>,
}

/// Where the identity provider sends the browser back to; kernoid answers with a redirect to the login UI.
pub(crate) async fn callback(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    Query(query): Query<Callback>,
) -> Response {
    let target =
        state.oidc.idp_callback(&instance, query.state.as_deref(), query.code.as_deref(), query.error.as_deref()).await;
    Redirect::to(&target).into_response()
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct ExchangeLogin {
    /// What the login UI got after the callback: `<login id>.<code>`, usable once.
    login: String,
    /// How long the session lasts; 8 hours if left out.
    lifetime_seconds: Option<u64>,
    /// For browsers: keep the session in an HttpOnly cookie instead of answering with the token.
    #[serde(default)]
    cookie: bool,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct ExchangedLogin {
    session: SessionCreated,
    /// The auth request the login was for – finish it next.
    auth_request: Option<String>,
}

/// Exchanges the result of a login at an identity provider for a session – once.
#[utoipa::path(post, path = "/v1/idp-logins/session", tag = "login", request_body = ExchangeLogin, responses(
    (status = 201, body = ExchangedLogin),
    (status = 401, description = "unknown, expired or used already", body = Problem),
))]
pub(crate) async fn exchange(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    client: Option<Extension<Client>>,
    headers: HeaderMap,
    Json(body): Json<ExchangeLogin>,
) -> Response {
    let meta = client_meta(client.as_ref().map(|c| &c.0), &headers);
    let lifetime = body.lifetime_seconds.map(Duration::from_secs);
    match state.oidc.exchange_idp_login(instance.id, &body.login, lifetime, &meta).await {
        Ok(result) => {
            let set = body.cookie.then(|| crate::cookie::set(&state, &result.session.token, result.session.expires_at));
            let mut session = SessionCreated::from(result.session);
            if set.is_some() {
                session = session.without_token();
            }
            let mut response =
                (StatusCode::CREATED, Json(ExchangedLogin { session, auth_request: result.auth_request }))
                    .into_response();
            if let Some(set) = set {
                response.headers_mut().insert(axum::http::header::SET_COOKIE, set);
            }
            response
        }
        Err(error) => oidc::problem(error),
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct AcsForm {
    #[serde(rename = "SAMLResponse")]
    saml_response: Option<String>,
    #[serde(rename = "RelayState")]
    relay_state: Option<String>,
}

/// Where a SAML provider posts its Response (HTTP-POST binding); kernoid answers with a redirect to the login UI.
pub(crate) async fn saml_acs(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    axum::Form(form): axum::Form<AcsForm>,
) -> Response {
    let target = state.oidc.saml_acs(&instance, form.relay_state.as_deref(), form.saml_response.as_deref()).await;
    Redirect::to(&target).into_response()
}

/// kernoid's SAML service provider metadata for this instance – to give a SAML provider's administrator.
pub(crate) async fn saml_metadata(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
) -> Response {
    let metadata = match state.oidc.saml_metadata(&instance).await {
        Ok(metadata) => metadata,
        Err(error) => return oidc::problem(error),
    };
    let mut response = metadata.into_response();
    response
        .headers_mut()
        .insert(axum::http::header::CONTENT_TYPE, axum::http::HeaderValue::from_static("application/samlmetadata+xml"));
    response
}

/// kernoid's SAML single logout service (HTTP-Redirect binding; `saml_slo_post` for HTTP-POST): a provider's
/// LogoutRequest – kernoid ends the sessions and answers – or its LogoutResponse to kernoid's request.
pub(crate) async fn saml_slo(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Response {
    match state.oidc.saml_slo(&instance, query.as_deref().unwrap_or("")).await {
        Ok(Some(target)) => Redirect::to(&target).into_response(),
        Ok(None) => (StatusCode::OK, "Logged out.").into_response(),
        Err(error) => oidc::problem(error),
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct SloForm {
    #[serde(rename = "SAMLRequest")]
    saml_request: Option<String>,
    #[serde(rename = "SAMLResponse")]
    saml_response: Option<String>,
    #[serde(rename = "RelayState")]
    relay_state: Option<String>,
}

/// kernoid's SAML single logout service in the HTTP-POST binding: the same as `saml_slo`, the message signed in
/// its XML.
pub(crate) async fn saml_slo_post(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    axum::Form(form): axum::Form<SloForm>,
) -> Response {
    let message = match kernoid_oidc::saml::read_post(
        form.saml_request.as_deref(),
        form.saml_response.as_deref(),
        form.relay_state.as_deref(),
    ) {
        Ok(message) => message,
        Err(error) => {
            return Problem::new(StatusCode::BAD_REQUEST).detail(error.to_string()).into_response();
        }
    };
    match state.oidc.saml_slo_message(&instance, message).await {
        Ok(Some(target)) => Redirect::to(&target).into_response(),
        Ok(None) => (StatusCode::OK, "Logged out.").into_response(),
        Err(error) => oidc::problem(error),
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct LoggedOut {
    /// Where to send the browser next: the SAML provider the session came from, to log out there too – or nothing.
    redirect: Option<String>,
}

/// Logs out: ends the session of the bearer token. If it came from a SAML provider with single logout, the answer
/// says where to send the browser next.
#[utoipa::path(post, path = "/v1/sessions/current/logout", tag = "sessions", responses(
    (status = 200, body = LoggedOut),
    (status = 401, description = "no valid session", body = Problem),
))]
pub(crate) async fn logout(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    crate::sessions::SessionToken(token): crate::sessions::SessionToken,
) -> Response {
    match state.oidc.logout(&instance, &token).await {
        Ok(redirect) => {
            ([(axum::http::header::SET_COOKIE, crate::cookie::clear(&state))], Json(LoggedOut { redirect }))
                .into_response()
        }
        Err(error) => oidc::problem(error),
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct Handoff {
    /// The one-time code from `/idp#link=…`.
    login: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct LinkProposalView {
    /// The provider's verified address, which an account of the instance has.
    email: String,
    provider: String,
    /// A separate account may be created instead (`POST /v1/idp-logins/register`).
    may_register: bool,
}

/// What a provider login that found an account with its verified address proposes (RFC 0003, 3): log in to that
/// account to link it – or, where registration is open, create a separate one. Does not use the code up.
#[utoipa::path(post, path = "/v1/idp-logins/proposal", tag = "login", request_body = Handoff, responses(
    (status = 200, body = LinkProposalView),
    (status = 401, description = "unknown, expired or used already", body = Problem),
))]
pub(crate) async fn proposal(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    Json(body): Json<Handoff>,
) -> Response {
    match state.oidc.link_proposal(instance.id, &body.login).await {
        Ok(proposal) => Json(LinkProposalView {
            email: proposal.email,
            provider: proposal.provider,
            may_register: proposal.may_register,
        })
        .into_response(),
        Err(error) => oidc::problem(error),
    }
}

/// Links the provider login of a proposal to the account of the session – the person logged in to it to prove it is
/// theirs; from then on the provider logs in as that account.
#[utoipa::path(post, path = "/v1/idp-logins/link", tag = "login", request_body = Handoff, responses(
    (status = 204),
    (status = 400, description = "the session is not the proposed account's", body = Problem),
    (status = 401, description = "no valid session, or the code is unknown, expired or used", body = Problem),
))]
pub(crate) async fn confirm_link(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    crate::sessions::SessionToken(token): crate::sessions::SessionToken,
    Json(body): Json<Handoff>,
) -> Response {
    match state.oidc.confirm_link(instance.id, &body.login, &token).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => oidc::problem(error),
    }
}

/// Creates a separate account for the provider login of a proposal instead of linking it, where registration is
/// open, and logs it in.
#[utoipa::path(post, path = "/v1/idp-logins/register", tag = "login", request_body = ExchangeLogin, responses(
    (status = 201, body = ExchangedLogin),
    (status = 400, description = "registering is not possible here", body = Problem),
    (status = 401, description = "unknown, expired or used already", body = Problem),
))]
pub(crate) async fn register_instead(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    client: Option<Extension<Client>>,
    headers: HeaderMap,
    Json(body): Json<ExchangeLogin>,
) -> Response {
    let meta = client_meta(client.as_ref().map(|c| &c.0), &headers);
    let lifetime = body.lifetime_seconds.map(Duration::from_secs);
    match state.oidc.register_instead(instance.id, &body.login, lifetime, &meta).await {
        Ok(result) => {
            let set = body.cookie.then(|| crate::cookie::set(&state, &result.session.token, result.session.expires_at));
            let mut session = SessionCreated::from(result.session);
            if set.is_some() {
                session = session.without_token();
            }
            let mut response =
                (StatusCode::CREATED, Json(ExchangedLogin { session, auth_request: result.auth_request }))
                    .into_response();
            if let Some(set) = set {
                response.headers_mut().insert(axum::http::header::SET_COOKIE, set);
            }
            response
        }
        Err(error) => oidc::problem(error),
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct StartLink {
    identity_provider: String,
}

/// Starts linking another provider to one's own account (RFC 0003, 3); answers with where to send the browser.
#[utoipa::path(post, path = "/v1/account/idp-links", tag = "account", request_body = StartLink, responses(
    (status = 200, body = StartedLogin),
    (status = 401, description = "no valid session", body = Problem),
    (status = 404, description = "no such identity provider", body = Problem),
))]
pub(crate) async fn start_link(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    crate::sessions::SessionToken(token): crate::sessions::SessionToken,
    Json(body): Json<StartLink>,
) -> Response {
    let Ok(idp) = Uuid::parse_str(&body.identity_provider) else {
        return Problem::new(StatusCode::NOT_FOUND).detail("the identity provider does not exist").into_response();
    };
    match state.oidc.start_idp_link(&instance, &token, idp).await {
        Ok(url) => Json(StartedLogin { url }).into_response(),
        Err(error) => oidc::problem(error),
    }
}

/// The providers offered to everyone on the login page ("Sign in with …").
#[utoipa::path(get, path = "/v1/login-providers", tag = "login", responses((status = 200, body = [ProviderSummary])))]
pub(crate) async fn open_providers(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
) -> Response {
    match state.oidc.open_providers(instance.id).await {
        Ok(list) => Json(
            list.into_iter()
                .map(|provider| ProviderSummary { id: provider.id.to_string(), name: provider.name })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(error) => oidc::problem(error),
    }
}
