// SPDX-License-Identifier: AGPL-3.0-or-later
//! The module `jitsi`: video meetings in a Jitsi Meet that trusts kernoid's tokens (Jitsi's JWT authentication,
//! `AUTH_TYPE=jwt` with a shared secret). An account of a tenant that uses the module makes a meeting; the link it
//! gets – `<instance>/modules/jitsi/join/<room>` – names only the room and goes into an invitation. Whoever opens it
//! logged in to the instance is sent on to Jitsi with a token kernoid signed for that room, the meeting's owner as
//! moderator; anyone else is sent to the login, or – where Jitsi lets guests in – to the room without a token.
//!
//! The token (Jitsi's `doc/tokens.md` in lib-jitsi-meet): HS256, `iss` the application id, `aud` the audience,
//! `sub` Jitsi's domain, `room` the room, `exp`, and `context.user` with `id`, `name`, `email` (strings only) and
//! `moderator` (`"true"` or `"false"`, as Jitsi as a Service reads it).
//!
//! ```toml
//! [modules.jitsi]
//! enabled = true
//! url = "https://meet.example.org"  # where Jitsi Meet is
//! app_id = "kernoid"                # Jitsi's JWT_APP_ID
//! app_secret = "…"                  # Jitsi's JWT_APP_SECRET – better: KERNOID__MODULES__JITSI__APP_SECRET
//! audience = "kernoid"              # aud; the app id unless set
//! subject = "meet.example.org"      # sub; the host of url unless set
//! token_minutes = 180               # how long a token is good for (Jitsi checks it again when it reconnects)
//! guests = false                    # people without a session join without a token (Jitsi's ENABLE_GUESTS)
//! ```

use std::{
    fmt,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header, request::Parts},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use kernoid_module::{Caller, Context, Module, Sessions};
use serde_json::{Value, json};
use sha2::Sha256;
use sqlx::PgPool;
use uuid::Uuid;

pub const NAME: &str = "jitsi";
const DEFAULT_TOKEN_MINUTES: u64 = 180;
/// Random bytes in a room's name: 96 bits, as hex.
const ROOM_BYTES: usize = 12;

/// Jitsi's shared secret; never shown.
#[derive(Clone)]
struct AppSecret(String);

impl fmt::Debug for AppSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AppSecret(…)")
    }
}

/// A Jitsi Meet and how to sign its tokens.
#[derive(Debug, Clone)]
pub struct Jitsi {
    /// Where Jitsi Meet is, without a trailing `/`.
    pub url: String,
    pub app_id: String,
    secret: AppSecret,
    pub audience: String,
    pub subject: String,
    pub token_lifetime: Duration,
    pub guests: bool,
}

impl Jitsi {
    /// From the module's table (`[modules.jitsi]` without `enabled`).
    pub fn from_config(config: &toml::Table) -> Result<Self, String> {
        const KNOWN: [&str; 7] = ["url", "app_id", "app_secret", "audience", "subject", "token_minutes", "guests"];
        if let Some(unknown) = config.keys().find(|key| !KNOWN.contains(&key.as_str())) {
            return Err(format!("unknown setting {unknown}"));
        }
        let text = |key: &str| config.get(key).and_then(toml::Value::as_str).filter(|value| !value.is_empty());
        let url = text("url").ok_or("url is required")?;
        let parsed = url::Url::parse(url).map_err(|_| "url is not a URL")?;
        if parsed.scheme() != "https" && parsed.host_str() != Some("localhost") {
            return Err("url is an https URL".into());
        }
        let host = parsed.host_str().ok_or("url has no host")?.to_lowercase();
        let app_id = text("app_id").ok_or("app_id is required")?.to_owned();
        let secret = text("app_secret").ok_or("app_secret is required")?;
        if secret.len() < 32 {
            return Err("app_secret has at least 32 characters".into());
        }
        let token_minutes = match config.get("token_minutes") {
            None => DEFAULT_TOKEN_MINUTES,
            Some(toml::Value::Integer(minutes)) if (1..=1440).contains(minutes) => *minutes as u64,
            Some(_) => return Err("token_minutes is 1 to 1440".into()),
        };
        let guests = match config.get("guests") {
            None => false,
            Some(toml::Value::Boolean(guests)) => *guests,
            Some(_) => return Err("guests is true or false".into()),
        };
        Ok(Self {
            url: url.trim_end_matches('/').to_owned(),
            audience: text("audience").map_or_else(|| app_id.clone(), str::to_owned),
            subject: text("subject").map_or(host, str::to_lowercase),
            app_id,
            secret: AppSecret(secret.to_owned()),
            token_lifetime: Duration::from_secs(token_minutes * 60),
            guests,
        })
    }

    /// A token for `room`, for `caller` – as moderator, or not.
    pub fn token(&self, room: &str, caller: &Caller, moderator: bool, now: SystemTime) -> String {
        let now = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let name = if caller.display_name.is_empty() { &caller.address } else { &caller.display_name };
        let mut user = json!({
            "id": caller.account.to_string(),
            "name": name,
            "moderator": if moderator { "true" } else { "false" },
        });
        if caller.address.contains('@') {
            user["email"] = json!(caller.address);
        }
        let claims = json!({
            "iss": self.app_id,
            "aud": self.audience,
            "sub": self.subject,
            "room": room,
            "iat": now,
            "nbf": now.saturating_sub(10),
            "exp": now + self.token_lifetime.as_secs(),
            "context": { "user": user },
        });
        let header = json!({ "alg": "HS256", "typ": "JWT" });
        let encode = |value: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).unwrap_or_default());
        let input = format!("{}.{}", encode(&header), encode(&claims));
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(self.secret.0.as_bytes())
            .expect("HMAC takes a key of any length");
        mac.update(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
    }

    /// Where `room` is in Jitsi, with `token` if one is given.
    pub fn room_url(&self, room: &str, token: Option<&str>) -> String {
        match token {
            Some(token) => format!("{}/{room}?jwt={token}", self.url),
            None => format!("{}/{room}", self.url),
        }
    }
}

/// A room's name: random, lowercase hex.
fn new_room() -> String {
    let mut bytes = [0u8; ROOM_BYTES];
    getrandom::fill(&mut bytes).expect("the system has randomness");
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn problem(status: StatusCode, detail: &str) -> Response {
    let body = json!({
        "type": "about:blank",
        "title": status.canonical_reason().unwrap_or_default(),
        "status": status.as_u16(),
        "detail": detail,
    });
    let mut response = (status, Json(body)).into_response();
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/problem+json"));
    response
}

#[derive(Debug, Clone)]
struct Routes {
    jitsi: Jitsi,
    db: PgPool,
    sessions: Arc<dyn Sessions>,
}

impl Routes {
    /// Whether the tenant uses the module.
    async fn uses(&self, tenant: Uuid) -> Result<bool, sqlx::Error> {
        let on = sqlx::query_scalar!(
            "SELECT EXISTS (SELECT 1 FROM tenant_modules WHERE tenant_id = $1 AND module = $2)",
            tenant,
            NAME,
        )
        .fetch_one(&self.db)
        .await?;
        Ok(on.unwrap_or(false))
    }

    /// The caller, of a tenant that uses the module – or the answer.
    #[allow(clippy::result_large_err, reason = "the error is the finished answer, built once on the error path")]
    async fn member(&self, parts: &Parts) -> Result<Caller, Response> {
        let caller = self.sessions.caller(parts).await.ok_or_else(|| problem(StatusCode::UNAUTHORIZED, "log in"))?;
        match self.uses(caller.tenant).await {
            Ok(true) => Ok(caller),
            Ok(false) => Err(problem(StatusCode::FORBIDDEN, "the tenant does not use video meetings")),
            Err(error) => Err(internal(error)),
        }
    }
}

fn internal(error: sqlx::Error) -> Response {
    tracing::warn!(%error, "the module jitsi");
    problem(StatusCode::INTERNAL_SERVER_ERROR, "something went wrong")
}

/// `GET /modules/jitsi/status`: whether the caller's tenant uses video meetings – for an app to offer them.
async fn status(State(routes): State<Routes>, parts: Parts) -> Response {
    let Some(caller) = routes.sessions.caller(&parts).await else {
        return problem(StatusCode::UNAUTHORIZED, "log in");
    };
    match routes.uses(caller.tenant).await {
        Ok(enabled) => Json(json!({ "enabled": enabled })).into_response(),
        Err(error) => internal(error),
    }
}

/// `POST /modules/jitsi/meetings`: a new meeting, owned by the caller; its link.
async fn create(State(routes): State<Routes>, parts: Parts) -> Response {
    let caller = match routes.member(&parts).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let room = new_room();
    let made = sqlx::query!(
        "INSERT INTO jitsi_rooms (room, instance_id, tenant_id, owner_id) VALUES ($1, $2, $3, $4)",
        room,
        caller.instance,
        caller.tenant,
        caller.account,
    )
    .execute(&routes.db)
    .await;
    if let Err(error) = made {
        return internal(error);
    }
    let url = format!("{}/modules/{NAME}/join/{room}", caller.base.trim_end_matches('/'));
    (StatusCode::CREATED, Json(json!({ "room": room, "url": url }))).into_response()
}

/// `GET /modules/jitsi/join/{room}`: on to the room in Jitsi – with a token for whoever is logged in to the instance
/// (the owner as moderator), to the login for anyone else, or without a token where guests are let in.
async fn join(State(routes): State<Routes>, Path(room): Path<String>, parts: Parts) -> Response {
    let found = sqlx::query!(
        "SELECT r.instance_id, r.owner_id,
                EXISTS (SELECT 1 FROM tenant_modules m WHERE m.tenant_id = r.tenant_id AND m.module = $2) AS uses
         FROM jitsi_rooms r WHERE r.room = $1",
        room,
        NAME,
    )
    .fetch_optional(&routes.db)
    .await;
    let found = match found {
        Ok(Some(found)) if found.uses.unwrap_or(false) => found,
        Ok(_) => return problem(StatusCode::NOT_FOUND, "no such meeting"),
        Err(error) => return internal(error),
    };
    let caller = routes.sessions.caller(&parts).await.filter(|caller| caller.instance == found.instance_id);
    let target = match caller {
        Some(caller) => {
            let token = routes.jitsi.token(&room, &caller, caller.account == found.owner_id, SystemTime::now());
            routes.jitsi.room_url(&room, Some(&token))
        }
        None if routes.jitsi.guests => routes.jitsi.room_url(&room, None),
        None => {
            let here = format!("/modules/{NAME}/join/{room}");
            let next: String = url::form_urlencoded::byte_serialize(here.as_bytes()).collect();
            format!("/login/account?next={next}")
        }
    };
    let mut response = Redirect::to(&target).into_response();
    // The token is in the address: no cache keeps it.
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    response
}

/// The module: its configuration checked at the start, its routes below `/modules/jitsi/`.
#[derive(Debug)]
pub struct JitsiModule;

impl Module for JitsiModule {
    fn name(&self) -> &'static str {
        NAME
    }

    fn check(&self, config: &toml::Table) -> Result<(), String> {
        Jitsi::from_config(config).map(drop)
    }

    fn routes(&self, context: &Context) -> Option<Router> {
        let jitsi = Jitsi::from_config(&context.config).ok()?;
        let sessions = context.sessions.clone()?;
        let routes = Routes { jitsi, db: context.db.clone(), sessions };
        Some(
            Router::new()
                .route("/status", get(status))
                .route("/meetings", post(create))
                .route("/join/{room}", get(join))
                .with_state(routes),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "a-secret-of-at-least-thirty-two-characters";

    fn jitsi(extra: &str) -> Jitsi {
        let toml =
            format!("url = \"https://Meet.Example.org/\"\napp_id = \"kernoid\"\napp_secret = \"{SECRET}\"\n{extra}");
        Jitsi::from_config(&toml::from_str(&toml).unwrap()).unwrap()
    }

    fn caller() -> Caller {
        Caller {
            account: Uuid::nil(),
            tenant: Uuid::nil(),
            instance: Uuid::nil(),
            display_name: "Alice".into(),
            address: "alice@firma.example".into(),
            base: "https://login.firma.example".into(),
        }
    }

    fn part(token: &str, n: usize) -> Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(token.split('.').nth(n).unwrap()).unwrap()).unwrap()
    }

    #[test]
    fn tokens_are_signed_for_one_room() {
        let jitsi = jitsi("");
        let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let token = jitsi.token("0a1b2c", &caller(), true, now);
        assert_eq!(part(&token, 0), json!({ "alg": "HS256", "typ": "JWT" }));
        let claims = part(&token, 1);
        assert_eq!(
            claims,
            json!({
                "iss": "kernoid", "aud": "kernoid", "sub": "meet.example.org", "room": "0a1b2c",
                "iat": 1_800_000_000u64, "nbf": 1_799_999_990u64, "exp": 1_800_010_800u64,
                "context": { "user": {
                    "id": Uuid::nil().to_string(), "name": "Alice", "email": "alice@firma.example", "moderator": "true",
                } },
            })
        );
        let (input, signature) = token.rsplit_once('.').unwrap();
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(SECRET.as_bytes()).unwrap();
        mac.update(input.as_bytes());
        mac.verify_slice(&URL_SAFE_NO_PAD.decode(signature).unwrap()).unwrap();

        let guest = jitsi.token("0a1b2c", &Caller { address: "alice".into(), ..caller() }, false, now);
        assert_eq!(part(&guest, 1)["context"]["user"]["moderator"], "false");
        assert!(part(&guest, 1)["context"]["user"].get("email").is_none());
        assert_eq!(jitsi.room_url("0a1b2c", None), "https://Meet.Example.org/0a1b2c");
    }

    #[test]
    fn the_configuration_is_checked() {
        let set = jitsi("audience = \"jitsi\"\nsubject = \"*\"\ntoken_minutes = 30\nguests = true");
        assert_eq!((set.audience.as_str(), set.subject.as_str()), ("jitsi", "*"));
        assert_eq!((set.token_lifetime, set.guests), (Duration::from_secs(1800), true));
        assert!(!format!("{set:?}").contains(SECRET));
        for wrong in [
            "app_id = \"k\"\napp_secret = \"0123456789abcdef0123456789abcdef\"",
            "url = \"http://meet.example.org\"\napp_id = \"k\"\napp_secret = \"0123456789abcdef0123456789abcdef\"",
            "url = \"https://meet.example.org\"\napp_id = \"k\"\napp_secret = \"short\"",
            "url = \"https://meet.example.org\"\napp_id = \"k\"\napp_secret = \"0123456789abcdef0123456789abcdef\"\nroom = 1",
            "url = \"https://meet.example.org\"\napp_id = \"k\"\napp_secret = \"0123456789abcdef0123456789abcdef\"\ntoken_minutes = 0",
        ] {
            assert!(Jitsi::from_config(&toml::from_str(wrong).unwrap()).is_err(), "{wrong}");
        }
    }

    #[test]
    fn rooms_are_random_and_valid() {
        let (a, b) = (new_room(), new_room());
        assert_ne!(a, b);
        assert_eq!(a.len(), 24);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
}
