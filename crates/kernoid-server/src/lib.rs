// SPDX-License-Identifier: AGPL-3.0-or-later
//! The HTTP server of the `api` role: health checks, the REST API (described by `/openapi.json`) and the GraphQL
//! API (`/graphql`), and the routes of the modules that are on. Every response carries an `x-request-id`; errors are
//! problem details. kernoid serves HTTPS itself (`[http.tls]`) or plain HTTP behind a reverse proxy that it trusts
//! for `Forwarded` headers only if configured (`trusted_proxies`).

pub mod acme;
pub mod admin;
mod app_passwords;
mod autoconfig;
pub mod certificate_files;
mod consents;
mod cookie;
mod cors;
mod dav;
mod federation;
mod files_admin;
mod forwarded;
mod graphql;
mod groupware_admin;
mod instance;
mod jmap;
mod jmap_ws;
mod login_ui;
mod mail_admin;
pub mod metrics;
mod mfa;
mod oidc;
mod problem;
mod registration;
mod scim;
mod sessions;
mod webdav;

pub use forwarded::Client;
pub use instance::CurrentInstance;
pub use problem::Problem;

use std::{future::Future, net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::State,
    http::{Method, StatusCode, header},
    routing::{get, post},
};
use kernoid_config::Http;
use kernoid_identity::{DnsResolver, Identity};
use kernoid_store::{BlobStore, PgPool};
use serde::Serialize;
use tower_http::{
    catch_panic::CatchPanicLayer,
    cors::{Any, CorsLayer},
    limit::RequestBodyLimitLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use utoipa::OpenApi;
use utoipa_axum::{router::OpenApiRouter, routes};

/// Largest request body; uploads of files will get their own, streaming routes.
const BODY_LIMIT: usize = 2 * 1024 * 1024;
/// Largest JMAP request or upload: a message of the default `mail.max_message_size` and its encoding – or more, where
/// files (`files.max_file_size`) or messages may be larger.
const MAIL_BODY_LIMIT: usize = 72 * 1024 * 1024;
/// Longest time for one request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Longest time for an upload or a write of a file – until the server answers; downloads stream after it.
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(6 * 60 * 60);
/// How long running requests may take to finish after shutdown began.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(30);

/// What request handlers share.
#[derive(Debug, Clone)]
pub struct AppState {
    pub db: PgPool,
    pub blobs: BlobStore,
    pub identity: Identity,
    pub oidc: kernoid_oidc::Oidc,
    /// The modules compiled in, which tenants may switch on.
    pub modules: Arc<[&'static str]>,
    /// For verifying tenants' domains; without it, only instance administrators can mark domains verified.
    pub dns: Option<DnsResolver>,
    /// The DNS check of mail domains; without `[smtp]`, there is none.
    pub mail_dns: Option<Arc<kernoid_smtp::dns_check::Checker>>,
    /// JMAP, and the changes it pushes; without them, no mail over HTTP.
    pub jmap: Option<kernoid_jmap::Jmap>,
    /// CalDAV and CardDAV; absent where kernoid handles no mail.
    pub dav: Option<kernoid_dav::Dav>,
    pub mail_events: Option<kernoid_mail::MailEvents>,
    /// The sender of kernoid's own messages (`mail.notification_from`).
    pub notification_from: Option<String>,
    /// Where mail programs connect (`smtp.hostname`), for their autoconfiguration; None without `[smtp]`.
    pub mail_host: Option<String>,
    /// Whether kernoid serves IMAP too.
    pub imap: bool,
}

impl AppState {
    pub fn new(db: PgPool, blobs: BlobStore, identity: Identity, oidc: kernoid_oidc::Oidc) -> Self {
        Self {
            db,
            blobs,
            identity,
            oidc,
            modules: Arc::from([]),
            dns: None,
            mail_dns: None,
            jmap: None,
            dav: None,
            mail_events: None,
            notification_from: None,
            mail_host: None,
            imap: false,
        }
    }

    pub fn with_modules(mut self, modules: &[&'static str]) -> Self {
        self.modules = Arc::from(modules);
        self
    }

    pub fn with_dns(mut self, dns: DnsResolver) -> Self {
        self.dns = Some(dns);
        self
    }

    pub fn with_dav(mut self, dav: kernoid_dav::Dav) -> Self {
        self.dav = Some(dav);
        self
    }

    pub fn with_jmap(mut self, jmap: kernoid_jmap::Jmap, events: kernoid_mail::MailEvents) -> Self {
        self.jmap = Some(jmap);
        self.mail_events = Some(events);
        self
    }

    /// Sends kernoid's own messages (registration codes) from `from`, through the queue of the mail store.
    pub fn with_notifications(mut self, from: String) -> Self {
        self.notification_from = Some(from);
        self
    }

    /// Tells mail programs to connect to `host` (autoconfiguration), for IMAP too if `imap`.
    pub fn with_mail_host(mut self, host: String, imap: bool) -> Self {
        self.mail_host = Some(host);
        self.imap = imap;
        self
    }

    pub fn with_mail_dns(mut self, checker: kernoid_smtp::dns_check::Checker) -> Self {
        self.mail_dns = Some(Arc::new(checker));
        self
    }
}

#[derive(OpenApi)]
#[openapi(info(title = "kernoid", description = "Administration API of kernoid."))]
struct ApiDoc;

/// kernoid's own routes, together with `modules` (the routes of the modules that are on), with the layers every
/// request passes: request id, tracing, metrics, limits, the client as seen through trusted proxies.
/// Every REST route with its OpenAPI description.
fn rest() -> OpenApiRouter<AppState> {
    OpenApiRouter::with_openapi(ApiDoc::openapi())
        .routes(routes!(live))
        .routes(routes!(ready))
        .routes(routes!(version))
        .routes(routes!(instance::current, admin::instance::rename))
        .routes(routes!(sessions::create, sessions::list))
        .routes(routes!(sessions::current, sessions::terminate))
        .routes(routes!(federation::logout))
        .routes(routes!(oidc::auth_request, oidc::finish))
        .routes(routes!(oidc::decline))
        .routes(routes!(mfa::start_login))
        .routes(routes!(mfa::finish_login))
        .routes(routes!(mfa::check_totp))
        .routes(routes!(mfa::start_check))
        .routes(routes!(mfa::finish_check))
        .routes(routes!(mfa::start_totp, mfa::remove_totp))
        .routes(routes!(mfa::confirm_totp))
        .routes(routes!(mfa::passkeys))
        .routes(routes!(mfa::start_registration))
        .routes(routes!(mfa::finish_registration))
        .routes(routes!(mfa::remove_passkey))
        .routes(routes!(mfa::factors))
        .routes(routes!(app_passwords::list, app_passwords::add))
        .routes(routes!(app_passwords::remove))
        .routes(routes!(mfa::generate_recovery_codes))
        .routes(routes!(mfa::check_recovery_code))
        .routes(routes!(sessions::terminate_other))
        .routes(routes!(sessions::change_password))
        .routes(routes!(sessions::change_profile))
        .routes(routes!(consents::own))
        .routes(routes!(consents::revoke_own))
        .routes(routes!(admin::tenant::get, admin::tenant::rename))
        .routes(routes!(admin::tenant::set_policy))
        .routes(routes!(admin::tenant::set_module))
        .routes(routes!(admin::tenant::permissions))
        .routes(routes!(admin::tenant::add_domain))
        .routes(routes!(admin::tenant::verify_domain))
        .routes(routes!(admin::tenant::remove_domain))
        .routes(routes!(admin::accounts::list, admin::accounts::add))
        .routes(routes!(admin::accounts::get, admin::accounts::change))
        .routes(routes!(admin::accounts::addresses))
        .routes(routes!(admin::accounts::add_alias, admin::accounts::remove_alias))
        .routes(routes!(admin::accounts::set_password))
        .routes(routes!(admin::accounts::reset_second_factors))
        .routes(routes!(admin::accounts::sessions))
        .routes(routes!(admin::accounts::terminate_session))
        .routes(routes!(admin::logins::add_external))
        .routes(routes!(admin::logins::list_services))
        .routes(routes!(admin::logins::grant_service, admin::logins::revoke_service))
        .routes(routes!(admin::logins::set_username))
        .routes(routes!(admin::logins::set_contact))
        .routes(routes!(admin::logins::login_policy, admin::logins::set_login_policy))
        .routes(routes!(admin::logins::registration, admin::logins::set_registration))
        .routes(routes!(admin::logins::service_policies))
        .routes(routes!(admin::logins::set_service_policy))
        .routes(routes!(admin::logins::set_registration_tenant))
        .routes(routes!(consents::list))
        .routes(routes!(consents::revoke))
        .routes(routes!(admin::directory::groups, admin::directory::add_group))
        .routes(routes!(admin::directory::rename_group, admin::directory::remove_group))
        .routes(routes!(admin::directory::set_send_as))
        .routes(routes!(admin::directory::add_member, admin::directory::remove_member))
        .routes(routes!(admin::directory::add_address, admin::directory::remove_address))
        .routes(routes!(admin::tenant::mail_dns))
        .routes(routes!(admin::tenant::rotate_dkim))
        .routes(routes!(admin::mail::add_shared_mailbox))
        .routes(routes!(admin::mail::overview))
        .routes(routes!(admin::mail::set_quota))
        .routes(routes!(admin::mail::default_quota, admin::mail::set_default_quota))
        .routes(routes!(admin::mail::access, admin::mail::set_access, admin::mail::remove_access))
        .routes(routes!(admin::mail::sieve_scripts))
        .routes(routes!(admin::mail::put_sieve_script, admin::mail::remove_sieve_script))
        .routes(routes!(admin::mail::activate_sieve_script))
        .routes(routes!(admin::mail::import))
        .routes(routes!(admin::mail::retention, admin::mail::set_retention))
        .routes(routes!(admin::files::overview))
        .routes(routes!(admin::files::set_quota))
        .routes(routes!(admin::files::default_quota, admin::files::set_default_quota))
        .routes(routes!(admin::files::drives, admin::files::add_drive))
        .routes(routes!(admin::files::access, admin::files::set_access, admin::files::remove_access))
        .routes(routes!(admin::mail::export, admin::mail::import_mbox))
        .routes(routes!(admin::mail::queue))
        .routes(routes!(admin::audit::log))
        .routes(routes!(admin::mail::own_shared))
        .routes(routes!(admin::mail::own_access, admin::mail::share_own, admin::mail::unshare_own))
        .routes(routes!(admin::collections::list))
        .routes(routes!(admin::collections::access))
        .routes(routes!(admin::collections::set_access, admin::collections::remove_access))
        .routes(routes!(admin::collections::export))
        .routes(routes!(admin::collections::import))
        .routes(routes!(admin::collections::own_list))
        .routes(routes!(admin::collections::own_access, admin::collections::share, admin::collections::unshare))
        .routes(routes!(admin::directory::roles))
        .routes(routes!(admin::directory::define_role, admin::directory::delete_role))
        .routes(routes!(admin::directory::grant_role, admin::directory::revoke_role))
        .routes(routes!(admin::projects::list, admin::projects::add))
        .routes(routes!(admin::projects::get, admin::projects::change, admin::projects::remove))
        .routes(routes!(admin::projects::set_role, admin::projects::remove_role))
        .routes(routes!(admin::projects::authorizations))
        .routes(routes!(admin::projects::grant, admin::projects::revoke))
        .routes(routes!(admin::projects::grants))
        .routes(routes!(admin::projects::grant_project, admin::projects::revoke_project_grant))
        .routes(routes!(admin::projects::granted))
        .routes(routes!(admin::identity_providers::list, admin::identity_providers::add))
        .routes(routes!(
            admin::identity_providers::get,
            admin::identity_providers::change,
            admin::identity_providers::remove
        ))
        .routes(routes!(admin::identity_providers::set_secret, admin::identity_providers::remove_secret))
        .routes(routes!(admin::identity_providers::check))
        .routes(routes!(admin::identity_providers::links))
        .routes(routes!(admin::identity_providers::unlink))
        .routes(routes!(admin::provisioning::list, admin::provisioning::add))
        .routes(routes!(admin::provisioning::remove))
        .routes(routes!(federation::login_options))
        .routes(routes!(federation::open_providers))
        .routes(routes!(federation::proposal))
        .routes(routes!(federation::confirm_link))
        .routes(routes!(federation::register_instead))
        .routes(routes!(federation::start_link))
        .routes(routes!(registration::options))
        .routes(routes!(registration::start))
        .routes(routes!(registration::confirm))
        .routes(routes!(federation::start))
        .routes(routes!(federation::exchange))
        .routes(routes!(admin::applications::list, admin::applications::add))
        .routes(routes!(admin::applications::get, admin::applications::change))
        .routes(routes!(admin::applications::set_policy))
        .routes(routes!(admin::applications::set_options))
        .routes(routes!(admin::applications::new_secret))
        .routes(routes!(admin::instance::details))
        .routes(routes!(admin::instance::add_domain, admin::instance::remove_domain))
        .routes(routes!(admin::instance::set_primary_domain))
        .routes(routes!(admin::instance::set_login_ui))
        .routes(routes!(admin::instance::set_passkey_rp_id))
        .routes(routes!(admin::instance::define_role, admin::instance::delete_role))
        .routes(routes!(admin::instance::tenants, admin::instance::add_tenant))
        .routes(routes!(admin::instance::change_tenant))
        .routes(routes!(admin::instance::roles))
        .routes(routes!(admin::instance::grant_role, admin::instance::revoke_role))
        .routes(routes!(admin::instance::signing_keys, admin::instance::add_signing_key))
        .routes(routes!(admin::instance::activate_signing_key))
        .routes(routes!(admin::instance::remove_signing_key))
}

/// The OpenAPI description of the REST API, as `/openapi.json` serves it.
pub fn openapi() -> utoipa::openapi::OpenApi {
    rest().split_for_parts().1
}

/// The GraphQL schema in SDL.
pub fn graphql_schema() -> String {
    graphql::schema().sdl()
}

pub fn router(state: AppState, modules: Router, http: &Http) -> Router {
    let (rest, openapi) = rest().with_state(state.clone()).split_for_parts();
    // A login UI of the instance's own, on another origin, calls the API from the browser (cors.rs).
    let rest = rest.layer(axum::middleware::from_fn_with_state(state.clone(), cors::login_ui));
    let openapi = Arc::new(openapi);
    let listener = forwarded::Listener { trusted_proxies: http.trusted_proxies.clone(), tls: http.tls.is_some() };
    // What a web app calls from the browser – discovery, keys, tokens, userinfo – may be called from any origin: no
    // cookies are involved, the requests carry their own credentials. Authorize and end_session are navigations.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);
    let browser_called = Router::new()
        .route("/.well-known/openid-configuration", get(oidc::configuration))
        .route("/.well-known/webauthn", get(mfa::related_origins))
        .route("/oauth/v2/keys", get(oidc::keys))
        .route("/oauth/v2/token", post(oidc::token))
        .route("/oauth/v2/revoke", post(oidc::revoke))
        .route("/oidc/v1/userinfo", get(oidc::userinfo).post(oidc::userinfo))
        .layer(cors);
    // SCIM 2.0 for the tenants' directories (scim.rs): its own standard, outside the OpenAPI description.
    let provisioning = Router::new()
        .route("/scim/v2/ServiceProviderConfig", get(scim::service_provider_config))
        .route("/scim/v2/ResourceTypes", get(scim::resource_types))
        .route("/scim/v2/Schemas", get(scim::schemas))
        .route("/scim/v2/Users", get(scim::list_users).post(scim::create_user))
        .route(
            "/scim/v2/Users/{id}",
            get(scim::get_user).put(scim::replace_user).patch(scim::patch_user).delete(scim::delete_user),
        )
        .route("/scim/v2/Groups", get(scim::list_groups).post(scim::create_group))
        .route("/scim/v2/Bulk", post(scim::bulk))
        .route(
            "/scim/v2/Groups/{id}",
            get(scim::get_group).put(scim::replace_group).patch(scim::patch_group).delete(scim::delete_group),
        );
    let protocol = Router::new()
        .route("/oauth/v2/authorize", get(oidc::authorize))
        .route("/idp/callback", get(federation::callback))
        .route("/idp/saml/acs", post(federation::saml_acs))
        .route("/idp/saml/metadata", get(federation::saml_metadata))
        .route("/idp/saml/slo", get(federation::saml_slo))
        .route("/oidc/v1/end_session", get(oidc::end_session_get).post(oidc::end_session_post))
        .route("/oauth/v2/introspect", post(oidc::introspect))
        .merge(browser_called)
        .merge(provisioning)
        .with_state(state.clone());
    // JMAP (jmap.rs): mail programs in the browser call it from any origin with their own credentials; requests are
    // larger than the rest of the API takes.
    let mail_cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::PUT])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE, header::ACCEPT, header::RANGE])
        .expose_headers([header::CONTENT_RANGE, header::CONTENT_LENGTH]);
    let mail = Router::new()
        .route("/.well-known/jmap", get(jmap::well_known))
        .route("/.well-known/autoconfig/mail/config-v1.1.xml", get(autoconfig::config))
        .route("/mail/config-v1.1.xml", get(autoconfig::config))
        .route("/jmap/session", get(jmap::session))
        .route("/jmap/api", post(jmap::api))
        .route("/jmap/download/{account}/{blob}/{name}", get(jmap::download))
        .route("/jmap/eventsource", get(jmap::event_source))
        .route("/jmap/ws", get(jmap_ws::upgrade))
        .layer(axum::extract::DefaultBodyLimit::max(MAIL_BODY_LIMIT))
        .layer(RequestBodyLimitLayer::new(MAIL_BODY_LIMIT))
        .layer(mail_cors.clone())
        .with_state(state.clone());
    // Transfers: uploads and direct writes stream files of up to `files.max_file_size` and may take long – they have
    // their own limits, not the 30 seconds of everything else (RFC 0005, 5).
    let transfer_limit = state.jmap.as_ref().map_or(MAIL_BODY_LIMIT, |jmap| {
        MAIL_BODY_LIMIT.max(usize::try_from(jmap.max_size()).unwrap_or(usize::MAX).saturating_add(64 * 1024))
    });
    let transfers = Router::new()
        .route("/jmap/upload/{account}/", post(jmap::upload))
        .route("/jmap/files/{account}/{node}", axum::routing::put(jmap::write_file))
        .layer(mail_cors)
        .merge(webdav::routes())
        .layer(axum::extract::DefaultBodyLimit::max(transfer_limit))
        .layer(RequestBodyLimitLayer::new(transfer_limit))
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, TRANSFER_TIMEOUT))
        .with_state(state.clone());
    // CalDAV and CardDAV (dav.rs): WebDAV's own methods, any of them; not called from browsers.
    let dav = Router::new()
        .route("/.well-known/caldav", axum::routing::any(dav::well_known))
        .route("/.well-known/carddav", axum::routing::any(dav::well_known))
        .route("/dav", axum::routing::any(dav::handle))
        .route("/dav/", axum::routing::any(dav::handle))
        .route("/dav/{*path}", axum::routing::any(dav::handle))
        .layer(axum::extract::DefaultBodyLimit::max(dav::DAV_BODY_LIMIT))
        .layer(RequestBodyLimitLayer::new(dav::DAV_BODY_LIMIT))
        .with_state(state.clone());
    rest.merge(protocol)
        .route("/openapi.json", axum::routing::get(move || std::future::ready(Json(openapi.as_ref().clone()))))
        .route("/graphql", post(graphql::handler).with_state((state, graphql::schema())))
        .nest_service("/login", login_ui::routes(&http.login_ui))
        .nest_service("/app", login_ui::app_routes(&http.web_app))
        .route("/", axum::routing::get(|| async { axum::response::Redirect::to("/app/") }))
        .merge(modules)
        .layer(RequestBodyLimitLayer::new(BODY_LIMIT))
        .merge(mail)
        .merge(dav)
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, REQUEST_TIMEOUT))
        .merge(transfers)
        .fallback(problem::not_found)
        .layer(axum::middleware::from_fn(metrics::layer))
        .layer(axum::middleware::from_fn_with_state(listener, forwarded::layer))
        .layer(CatchPanicLayer::custom(problem::panicked))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(TraceLayer::new_for_http().make_span_with(|request: &axum::http::Request<_>| {
            let id = request.headers().get("x-request-id").and_then(|v| v.to_str().ok()).unwrap_or("");
            tracing::info_span!("request", method = %request.method(), path = %request.uri().path(), request_id = id)
        }))
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
}

#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error("cannot read the TLS certificate or key: {0}")]
    Tls(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Serves `router` on `http.listen` – over TLS if `http.tls` is set – until `shutdown` completes, then lets running
/// requests finish.
pub async fn serve(
    http: &Http,
    router: Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), ServeError> {
    serve_with(http, router, shutdown, None).await
}

/// Like [`serve`]; with `certificates` (ACME), HTTPS with the certificate of each instance domain, by SNI.
pub async fn serve_with(
    http: &Http,
    router: Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
    certificates: Option<Arc<acme::Certificates>>,
) -> Result<(), ServeError> {
    let handle = axum_server::Handle::new();
    tokio::spawn({
        let handle = handle.clone();
        async move {
            shutdown.await;
            handle.graceful_shutdown(Some(SHUTDOWN_GRACE));
        }
    });
    let service = router.into_make_service_with_connect_info::<SocketAddr>();
    if let Some(certificates) = certificates {
        let mut config =
            rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|e| ServeError::Tls(e.to_string()))?
                .with_no_client_auth()
                .with_cert_resolver(certificates);
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(config));
        tracing::info!(address = %http.listen, "https listening (ACME certificates)");
        axum_server::bind_rustls(http.listen, config).handle(handle).serve(service).await?;
        return Ok(());
    }
    match &http.tls {
        Some(tls) => {
            let config = tls_config(&tls.certificate, &tls.key)?;
            tracing::info!(address = %http.listen, "https listening");
            axum_server::bind_rustls(http.listen, config).handle(handle).serve(service).await?;
        }
        None => {
            tracing::info!(address = %http.listen, "http listening");
            axum_server::bind(http.listen).handle(handle).serve(service).await?;
        }
    }
    Ok(())
}

/// The TLS configuration for mail protocols (`STARTTLS`, implicit TLS): the files of `mail.tls` if set (read again
/// when they change); otherwise the same certificates as HTTPS – from ACME, or the files of `http.tls`. Without
/// HTTP's ALPN. `None` if kernoid has no certificates.
pub fn mail_tls(
    http: &Http,
    certificates: Option<Arc<acme::Certificates>>,
    files: Option<Arc<certificate_files::FileCertificates>>,
) -> Result<Option<Arc<rustls::ServerConfig>>, ServeError> {
    let tls_error = |error: &dyn std::fmt::Display| ServeError::Tls(error.to_string());
    let builder = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| tls_error(&e))?
        .with_no_client_auth();
    if let Some(files) = files {
        return Ok(Some(Arc::new(builder.with_cert_resolver(files))));
    }
    if let Some(certificates) = certificates {
        return Ok(Some(Arc::new(builder.with_cert_resolver(certificates))));
    }
    let Some(tls) = &http.tls else { return Ok(None) };
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    let chain = CertificateDer::pem_file_iter(&tls.certificate)
        .map_err(|e| tls_error(&e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| tls_error(&e))?;
    let key = PrivateKeyDer::from_pem_file(&tls.key).map_err(|e| tls_error(&e))?;
    Ok(Some(Arc::new(builder.with_single_cert(chain, key).map_err(|e| tls_error(&e))?)))
}

/// TLS 1.2 and 1.3 with rustls' defaults; the crypto provider is chosen here, not process-wide.
fn tls_config(
    certificate: &std::path::Path,
    key: &std::path::Path,
) -> Result<axum_server::tls_rustls::RustlsConfig, ServeError> {
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    let tls_error = |error: &dyn std::fmt::Display| ServeError::Tls(error.to_string());
    let chain = CertificateDer::pem_file_iter(certificate)
        .map_err(|e| tls_error(&e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| tls_error(&e))?;
    let key = PrivateKeyDer::from_pem_file(key).map_err(|e| tls_error(&e))?;
    let mut config =
        rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| tls_error(&e))?
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .map_err(|e| tls_error(&e))?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(config)))
}

/// Liveness: the process runs. Says nothing about its dependencies, so an orchestrator does not restart every
/// process when the database is away.
#[utoipa::path(get, path = "/healthz", tag = "health", responses((status = 200, description = "the process runs", body = String)))]
async fn live() -> &'static str {
    "ok"
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct Readiness {
    database: Check,
    blob: Check,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
enum Check {
    Ok,
    Failed,
}

/// Readiness: PostgreSQL and object storage answer. Details of failures go to the log, not to the caller.
#[utoipa::path(get, path = "/readyz", tag = "health", responses(
    (status = 200, description = "ready", body = Readiness),
    (status = 503, description = "a dependency does not answer", body = Readiness),
))]
async fn ready(State(state): State<AppState>) -> (StatusCode, Json<Readiness>) {
    let (database, blob) = tokio::join!(kernoid_store::ping(&state.db), state.blobs.ping());
    let readiness = Readiness { database: check("database", database), blob: check("blob", blob) };
    let status = match readiness {
        Readiness { database: Check::Ok, blob: Check::Ok } => StatusCode::OK,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    };
    (status, Json(readiness))
}

fn check<E: std::fmt::Display>(name: &str, result: Result<(), E>) -> Check {
    match result {
        Ok(()) => Check::Ok,
        Err(error) => {
            tracing::warn!(check = name, %error, "not ready");
            Check::Failed
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct Version {
    name: &'static str,
    version: &'static str,
}

/// The name and version of this kernoid.
#[utoipa::path(get, path = "/version", tag = "meta", responses((status = 200, body = Version)))]
async fn version() -> Json<Version> {
    Json(Version { name: "kernoid", version: env!("CARGO_PKG_VERSION") })
}

#[cfg(test)]
mod tests;
