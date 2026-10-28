// SPDX-License-Identifier: AGPL-3.0-or-later
//! Applications: the OpenID Connect clients of a tenant. A confidential application (a server) has a secret, shown
//! once and stored as SHA-256; a public one (in the browser, on a phone) has none and relies on PKCE alone. Redirect
//! URIs are matched exactly – no patterns, no prefixes.

use kernoid_events::{
    Error, Event, InlineFuture,
    aggregate::{Aggregate, CommandError, DomainEvent},
    inline,
};
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{Oidc, OidcError, Result, internal, random_secret, sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Confidential,
    Public,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Confidential => "confidential",
            Kind::Public => "public",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ApplicationEvent {
    #[serde(rename = "application.added")]
    Added {
        name: String,
        kind: Kind,
        redirect_uris: Vec<String>,
        /// Where a logout may send the browser back to; added later, hence the default for older events.
        #[serde(default)]
        post_logout_redirect_uris: Vec<String>,
        /// The project it belongs to; applications from before projects have none.
        #[serde(default)]
        project: Option<Uuid>,
    },
    #[serde(rename = "application.renamed")]
    Renamed { name: String },
    /// Moved to another project of the tenant.
    #[serde(rename = "application.project_set")]
    ProjectSet { project: Uuid },
    #[serde(rename = "application.redirect_uris_set")]
    RedirectUrisSet { redirect_uris: Vec<String> },
    #[serde(rename = "application.post_logout_redirect_uris_set")]
    PostLogoutRedirectUrisSet { post_logout_redirect_uris: Vec<String> },
    /// The secret itself is kept in `application_secrets`, as a hash.
    #[serde(rename = "application.secret_changed")]
    SecretChanged,
    /// Whether logins to the application need a second factor.
    #[serde(rename = "application.mfa_requirement_set")]
    MfaRequirementSet { required: bool },
    #[serde(rename = "application.deactivated")]
    Deactivated,
    #[serde(rename = "application.reactivated")]
    Reactivated,
    #[serde(rename = "application.options_set")]
    OptionsSet { options: AppOptions },
}

/// How access tokens look to the application.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenFormat {
    /// `kat1.…`, checked at userinfo and introspection.
    #[default]
    Opaque,
    /// A JWT (RFC 9068) that resource servers verify themselves.
    Jwt,
}

impl TokenFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Opaque => "opaque",
            Self::Jwt => "jwt",
        }
    }
}

/// What an application may do beyond the basic flow, and how it learns of logouts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppOptions {
    #[serde(default)]
    pub access_token_format: TokenFormat,
    /// May ask for `offline_access`: refresh tokens that outlive the session (with the person's consent).
    #[serde(default)]
    pub offline_access: bool,
    /// Asks the person before the first login (for applications of others).
    #[serde(default)]
    pub consent_required: bool,
    /// OpenID Connect Back-Channel Logout 1.0: kernoid posts a logout token here when a session ends.
    #[serde(default)]
    pub backchannel_logout_uri: Option<String>,
    /// OpenID Connect Front-Channel Logout 1.0: loaded in a frame when a session is logged out at kernoid.
    #[serde(default)]
    pub frontchannel_logout_uri: Option<String>,
}

impl DomainEvent for ApplicationEvent {}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Application {
    pub exists: bool,
    pub name: String,
    pub kind: Option<Kind>,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub project: Option<Uuid>,
    pub mfa_required: bool,
    pub active: bool,
    pub options: AppOptions,
}

impl Aggregate for Application {
    const TYPE: &'static str = "application";
    type Event = ApplicationEvent;

    fn apply(&mut self, event: ApplicationEvent) {
        match event {
            ApplicationEvent::Added { name, kind, redirect_uris, post_logout_redirect_uris, project } => {
                *self = Self {
                    exists: true,
                    name,
                    kind: Some(kind),
                    redirect_uris,
                    post_logout_redirect_uris,
                    project,
                    mfa_required: false,
                    active: true,
                    options: AppOptions::default(),
                };
            }
            ApplicationEvent::Renamed { name } => self.name = name,
            ApplicationEvent::ProjectSet { project } => self.project = Some(project),
            ApplicationEvent::RedirectUrisSet { redirect_uris } => self.redirect_uris = redirect_uris,
            ApplicationEvent::PostLogoutRedirectUrisSet { post_logout_redirect_uris } => {
                self.post_logout_redirect_uris = post_logout_redirect_uris;
            }
            ApplicationEvent::SecretChanged => {}
            ApplicationEvent::MfaRequirementSet { required } => self.mfa_required = required,
            ApplicationEvent::Deactivated => self.active = false,
            ApplicationEvent::Reactivated => self.active = true,
            ApplicationEvent::OptionsSet { options } => self.options = options,
        }
    }
}

async fn projection(connection: &mut PgConnection, events: &[Event]) -> std::result::Result<(), Error> {
    for event in events {
        let tenant = event.owner;
        let id = Uuid::parse_str(&event.aggregate.aggregate_id).map_err(|error| Error::Decode {
            event_type: event.event_type.clone(),
            revision: event.revision,
            message: format!("application id: {error}"),
        })?;
        match ApplicationEvent::decode(&event.event_type, event.revision, event.payload.clone())? {
            ApplicationEvent::Added { name, kind, redirect_uris, post_logout_redirect_uris, project } => {
                sqlx::query!(
                    "INSERT INTO applications
                         (id, tenant_id, name, kind, redirect_uris, post_logout_redirect_uris, project_id)
                     VALUES ($1, $2, $3, $4, $5, $6, $7)",
                    id,
                    tenant,
                    name,
                    kind.as_str(),
                    &redirect_uris,
                    &post_logout_redirect_uris,
                    project,
                )
                .execute(&mut *connection)
                .await?;
            }
            ApplicationEvent::Renamed { name } => {
                sqlx::query!("UPDATE applications SET name = $2 WHERE id = $1", id, name)
                    .execute(&mut *connection)
                    .await?;
            }
            ApplicationEvent::ProjectSet { project } => {
                sqlx::query!("UPDATE applications SET project_id = $2 WHERE id = $1", id, project)
                    .execute(&mut *connection)
                    .await?;
            }
            ApplicationEvent::RedirectUrisSet { redirect_uris } => {
                sqlx::query!("UPDATE applications SET redirect_uris = $2 WHERE id = $1", id, &redirect_uris)
                    .execute(&mut *connection)
                    .await?;
            }
            ApplicationEvent::PostLogoutRedirectUrisSet { post_logout_redirect_uris } => {
                sqlx::query!(
                    "UPDATE applications SET post_logout_redirect_uris = $2 WHERE id = $1",
                    id,
                    &post_logout_redirect_uris,
                )
                .execute(&mut *connection)
                .await?;
            }
            ApplicationEvent::SecretChanged => {}
            ApplicationEvent::MfaRequirementSet { required } => {
                sqlx::query!("UPDATE applications SET mfa_required = $2 WHERE id = $1", id, required)
                    .execute(&mut *connection)
                    .await?;
            }
            ApplicationEvent::Deactivated => {
                sqlx::query!("UPDATE applications SET active = false WHERE id = $1", id)
                    .execute(&mut *connection)
                    .await?;
            }
            ApplicationEvent::Reactivated => {
                sqlx::query!("UPDATE applications SET active = true WHERE id = $1", id)
                    .execute(&mut *connection)
                    .await?;
            }
            ApplicationEvent::OptionsSet { options } => {
                sqlx::query!(
                    "UPDATE applications SET access_token_format = $2, offline_access = $3, consent_required = $4,
                         backchannel_logout_uri = $5, frontchannel_logout_uri = $6
                     WHERE id = $1",
                    id,
                    options.access_token_format.as_str(),
                    options.offline_access,
                    options.consent_required,
                    options.backchannel_logout_uri,
                    options.frontchannel_logout_uri,
                )
                .execute(&mut *connection)
                .await?;
            }
        }
    }
    Ok(())
}

/// A redirect URI kernoid accepts: absolute, without fragment; `https`, or `http` only for `localhost` and loopback
/// addresses (native apps, development); or a private scheme with a dot (`org.example.app:/callback`, RFC 8252).
pub fn valid_redirect_uri(value: &str) -> bool {
    let Ok(uri) = url::Url::parse(value) else { return false };
    if uri.fragment().is_some() {
        return false;
    }
    match uri.scheme() {
        "https" => uri.host().is_some(),
        "http" => match uri.host() {
            Some(url::Host::Domain(host)) => host == "localhost" || host.ends_with(".localhost"),
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        },
        scheme => scheme.contains('.'),
    }
}

fn checked_logout_uris(uris: &[String]) -> Result<Vec<String>> {
    if let Some(bad) = uris.iter().find(|uri| !valid_redirect_uri(uri)) {
        return Err(OidcError::InvalidRequest(format!("{bad:?} is not an acceptable redirect URI")));
    }
    Ok(uris.to_vec())
}

/// Redirect URIs; a confidential application may have none – an API that only checks tokens (introspection).
fn checked_uris(uris: &[String], kind: Kind) -> Result<Vec<String>> {
    if uris.is_empty() && kind == Kind::Public {
        return Err(OidcError::InvalidRequest("a public application needs at least one redirect URI".into()));
    }
    if let Some(bad) = uris.iter().find(|uri| !valid_redirect_uri(uri)) {
        return Err(OidcError::InvalidRequest(format!("{bad:?} is not an acceptable redirect URI")));
    }
    Ok(uris.to_vec())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationInfo {
    pub id: Uuid,
    pub tenant: Uuid,
    pub instance: Uuid,
    pub name: String,
    pub kind: Kind,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub project: Option<Uuid>,
    pub mfa_required: bool,
    pub active: bool,
    pub options: AppOptions,
}

fn valid_application_name(name: &str) -> Result<String> {
    let name = name.trim().to_owned();
    if name.is_empty() || name.chars().count() > 200 || name.chars().any(char::is_control) {
        return Err(OidcError::InvalidRequest("a name has 1 to 200 characters".into()));
    }
    Ok(name)
}

fn kind(value: &str) -> Kind {
    if value == "public" { Kind::Public } else { Kind::Confidential }
}

fn command_error(error: CommandError<OidcError>) -> OidcError {
    match error {
        CommandError::Refused(error) => error,
        CommandError::Store(error) => internal(error),
    }
}

impl Oidc {
    /// Registers an application in a project of `tenant`; returns its id (the `client_id`) and, for a confidential
    /// one, its secret – shown this once.
    #[allow(clippy::too_many_arguments)]
    pub async fn add_application(
        &self,
        tenant: Uuid,
        project: Uuid,
        name: &str,
        kind: Kind,
        redirect_uris: &[String],
        post_logout_redirect_uris: &[String],
        creator: &str,
    ) -> Result<(Uuid, Option<String>)> {
        let name = valid_application_name(name)?;
        self.identity.project_of(tenant, project).await?;
        let redirect_uris = checked_uris(redirect_uris, kind)?;
        let post_logout_redirect_uris = checked_logout_uris(post_logout_redirect_uris)?;
        let instance = self.identity.tenant_instance(tenant).await?;
        let id = Uuid::now_v7();
        let secret = match kind {
            Kind::Confidential => Some(random_secret("kcs1.")?),
            Kind::Public => None,
        };
        let secret_hash = secret.as_deref().map(sha256);
        let store = inline(move |connection, events| {
            Box::pin(async move {
                projection(connection, events).await?;
                if let Some(hash) = secret_hash {
                    sqlx::query!(
                        "INSERT INTO application_secrets (application_id, secret_hash) VALUES ($1, $2)",
                        id,
                        &hash[..],
                    )
                    .execute(&mut *connection)
                    .await?;
                }
                Ok(())
            }) as InlineFuture<'_>
        });
        self.events
            .execute_with(
                instance,
                tenant,
                &id.to_string(),
                creator,
                |application: &Application| {
                    if application.exists {
                        return Err(OidcError::InvalidRequest("the application exists already".into()));
                    }
                    let mut events = vec![ApplicationEvent::Added {
                        name: name.clone(),
                        kind,
                        redirect_uris: redirect_uris.clone(),
                        post_logout_redirect_uris: post_logout_redirect_uris.clone(),
                        project: Some(project),
                    }];
                    if kind == Kind::Confidential {
                        events.push(ApplicationEvent::SecretChanged);
                    }
                    Ok(events)
                },
                store,
            )
            .await
            .map_err(command_error)?;
        Ok((id, secret))
    }

    async fn application_command(
        &self,
        application: Uuid,
        creator: &str,
        decide: impl Fn(&Application) -> Result<Vec<ApplicationEvent>>,
    ) -> Result<()> {
        let info = self.application(application).await?;
        self.events
            .execute_with(info.instance, info.tenant, &application.to_string(), creator, decide, |c, e| {
                Box::pin(projection(c, e))
            })
            .await
            .map(drop)
            .map_err(command_error)
    }

    pub async fn rename_application(&self, application: Uuid, name: &str, creator: &str) -> Result<()> {
        let name = valid_application_name(name)?;
        self.application_command(application, creator, |state| {
            Ok(if state.name == name { Vec::new() } else { vec![ApplicationEvent::Renamed { name: name.clone() }] })
        })
        .await
    }

    /// Moves an application to another project of its tenant.
    pub async fn set_application_project(&self, application: Uuid, project: Uuid, creator: &str) -> Result<()> {
        let info = self.application(application).await?;
        self.identity.project_of(info.tenant, project).await?;
        self.application_command(application, creator, |state| {
            Ok(if state.project == Some(project) { Vec::new() } else { vec![ApplicationEvent::ProjectSet { project }] })
        })
        .await
    }

    /// Sets the application's options; logout URIs must be HTTPS (kernoid calls the back-channel one itself, so it
    /// must also be a public address unless the installation allows private networks).
    pub async fn set_application_options(&self, application: Uuid, options: &AppOptions, creator: &str) -> Result<()> {
        let mut options = options.clone();
        for uri in [&mut options.backchannel_logout_uri, &mut options.frontchannel_logout_uri] {
            *uri = uri.as_deref().map(str::trim).filter(|uri| !uri.is_empty()).map(str::to_owned);
        }
        if let Some(uri) = &options.backchannel_logout_uri {
            let url = url::Url::parse(uri).map_err(|_| OidcError::InvalidRequest(format!("{uri:?} is not a URL")))?;
            crate::outbound::check_url(&url, self.allow_private).map_err(OidcError::InvalidRequest)?;
        }
        if let Some(uri) = &options.frontchannel_logout_uri
            && (!valid_redirect_uri(uri) || !uri.starts_with("https://") && !uri.starts_with("http://localhost"))
        {
            return Err(OidcError::InvalidRequest(format!("{uri:?} is not an acceptable front-channel logout URI")));
        }
        self.application_command(application, creator, |state| {
            Ok(if state.options == options {
                Vec::new()
            } else {
                vec![ApplicationEvent::OptionsSet { options: options.clone() }]
            })
        })
        .await
    }

    pub async fn set_redirect_uris(&self, application: Uuid, redirect_uris: &[String], creator: &str) -> Result<()> {
        let kind = self.application(application).await?.kind;
        let redirect_uris = checked_uris(redirect_uris, kind)?;
        self.application_command(application, creator, |_| {
            Ok(vec![ApplicationEvent::RedirectUrisSet { redirect_uris: redirect_uris.clone() }])
        })
        .await
    }

    pub async fn set_post_logout_redirect_uris(&self, application: Uuid, uris: &[String], creator: &str) -> Result<()> {
        let uris = checked_logout_uris(uris)?;
        self.application_command(application, creator, |_| {
            Ok(vec![ApplicationEvent::PostLogoutRedirectUrisSet { post_logout_redirect_uris: uris.clone() }])
        })
        .await
    }

    /// Requires (or no longer requires) a second factor for logins to the application.
    pub async fn set_application_mfa_required(&self, application: Uuid, required: bool, creator: &str) -> Result<()> {
        self.application_command(application, creator, |state| {
            Ok(if state.mfa_required == required {
                Vec::new()
            } else {
                vec![ApplicationEvent::MfaRequirementSet { required }]
            })
        })
        .await
    }

    pub async fn set_application_active(&self, application: Uuid, active: bool, creator: &str) -> Result<()> {
        self.application_command(application, creator, |state| {
            Ok(match (state.active, active) {
                (true, false) => vec![ApplicationEvent::Deactivated],
                (false, true) => vec![ApplicationEvent::Reactivated],
                _ => Vec::new(),
            })
        })
        .await
    }

    /// Replaces the secret of a confidential application; returns the new one – shown this once.
    pub async fn new_client_secret(&self, application: Uuid, creator: &str) -> Result<String> {
        let info = self.application(application).await?;
        if info.kind != Kind::Confidential {
            return Err(OidcError::InvalidRequest("a public application has no secret".into()));
        }
        let secret = random_secret("kcs1.")?;
        let hash = sha256(&secret);
        let store = inline(move |connection, events| {
            Box::pin(async move {
                projection(connection, events).await?;
                sqlx::query!(
                    "INSERT INTO application_secrets (application_id, secret_hash) VALUES ($1, $2)
                     ON CONFLICT (application_id) DO UPDATE SET secret_hash = excluded.secret_hash, changed_at = now()",
                    application,
                    &hash[..],
                )
                .execute(&mut *connection)
                .await?;
                Ok(())
            }) as InlineFuture<'_>
        });
        self.events
            .execute_with(
                info.instance,
                info.tenant,
                &application.to_string(),
                creator,
                |_: &Application| Ok(vec![ApplicationEvent::SecretChanged]),
                store,
            )
            .await
            .map_err(command_error)?;
        Ok(secret)
    }

    pub async fn application(&self, application: Uuid) -> Result<ApplicationInfo> {
        let row = sqlx::query!(
            "SELECT a.id, a.tenant_id, t.instance_id, a.name, a.kind, a.redirect_uris, a.post_logout_redirect_uris, a.project_id, a.mfa_required, a.active,
                    a.access_token_format, a.offline_access, a.consent_required, a.backchannel_logout_uri, a.frontchannel_logout_uri
             FROM applications a JOIN tenants t ON t.id = a.tenant_id WHERE a.id = $1",
            application,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(internal)?
        .ok_or(OidcError::InvalidClient)?;
        Ok(ApplicationInfo {
            id: row.id,
            tenant: row.tenant_id,
            instance: row.instance_id,
            name: row.name,
            kind: kind(&row.kind),
            redirect_uris: row.redirect_uris,
            post_logout_redirect_uris: row.post_logout_redirect_uris,
            project: row.project_id,
            mfa_required: row.mfa_required,
            active: row.active,
            options: AppOptions {
                access_token_format: if row.access_token_format == "jwt" {
                    TokenFormat::Jwt
                } else {
                    TokenFormat::Opaque
                },
                offline_access: row.offline_access,
                consent_required: row.consent_required,
                backchannel_logout_uri: row.backchannel_logout_uri,
                frontchannel_logout_uri: row.frontchannel_logout_uri,
            },
        })
    }

    pub async fn applications(&self, tenant: Uuid) -> Result<Vec<ApplicationInfo>> {
        let rows = sqlx::query!(
            "SELECT a.id, a.tenant_id, t.instance_id, a.name, a.kind, a.redirect_uris, a.post_logout_redirect_uris, a.project_id, a.mfa_required, a.active,
                    a.access_token_format, a.offline_access, a.consent_required, a.backchannel_logout_uri, a.frontchannel_logout_uri
             FROM applications a JOIN tenants t ON t.id = a.tenant_id WHERE a.tenant_id = $1 ORDER BY a.name",
            tenant,
        )
        .fetch_all(self.pool())
        .await
        .map_err(internal)?;
        Ok(rows
            .into_iter()
            .map(|row| ApplicationInfo {
                id: row.id,
                tenant: row.tenant_id,
                instance: row.instance_id,
                name: row.name,
                kind: kind(&row.kind),
                redirect_uris: row.redirect_uris,
                post_logout_redirect_uris: row.post_logout_redirect_uris,
                project: row.project_id,
                mfa_required: row.mfa_required,
                active: row.active,
                options: AppOptions {
                    access_token_format: if row.access_token_format == "jwt" {
                        TokenFormat::Jwt
                    } else {
                        TokenFormat::Opaque
                    },
                    offline_access: row.offline_access,
                    consent_required: row.consent_required,
                    backchannel_logout_uri: row.backchannel_logout_uri,
                    frontchannel_logout_uri: row.frontchannel_logout_uri,
                },
            })
            .collect())
    }

    /// Checks the client of a token request: a confidential one with its secret, a public one without.
    pub(crate) async fn authenticate_client(
        &self,
        instance: Uuid,
        client_id: &str,
        secret: Option<&str>,
    ) -> Result<ApplicationInfo> {
        let id = Uuid::parse_str(client_id).map_err(|_| OidcError::InvalidClient)?;
        let application = self.application(id).await?;
        if application.instance != instance || !application.active {
            return Err(OidcError::InvalidClient);
        }
        match (application.kind, secret) {
            (Kind::Public, None) => Ok(application),
            (Kind::Public, Some(_)) => Err(OidcError::InvalidClient),
            (Kind::Confidential, None) => Err(OidcError::InvalidClient),
            (Kind::Confidential, Some(secret)) => {
                let stored = sqlx::query_scalar!(
                    "SELECT secret_hash FROM application_secrets WHERE application_id = $1",
                    application.id,
                )
                .fetch_optional(self.pool())
                .await
                .map_err(internal)?
                .ok_or(OidcError::InvalidClient)?;
                if crate::constant_time_eq(&stored, &sha256(secret)) {
                    Ok(application)
                } else {
                    Err(OidcError::InvalidClient)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_uris() {
        for good in [
            "https://app.example.org/callback",
            "https://app.example.org/callback?x=1",
            "http://localhost:8080/callback",
            "http://127.0.0.1:4711/cb",
            "http://[::1]/cb",
            "org.example.app:/callback",
        ] {
            assert!(valid_redirect_uri(good), "{good}");
        }
        for bad in [
            "",
            "/callback",
            "https://app.example.org/callback#fragment",
            "http://app.example.org/callback",
            "http://192.168.1.10/cb",
            "javascript:alert(1)",
            "data:text/html,x",
            "myapp:/callback",
        ] {
            assert!(!valid_redirect_uri(bad), "{bad}");
        }
    }
}
