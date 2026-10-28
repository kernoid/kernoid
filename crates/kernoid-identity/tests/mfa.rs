// SPDX-License-Identifier: AGPL-3.0-or-later
//! TOTP and passkeys against PostgreSQL; set `DATABASE_URL` as for the other crates' tests. Passkeys are made by
//! webauthn-authenticator-rs' software token.

mod common;

use aws_lc_rs::hmac;
use common::{WHO, tenant_with};
use kernoid_events::EventStore;
use kernoid_identity::{
    Address, Identity, IdentityError,
    passkey::RelyingParty,
    session::{ClientMeta, FAILURES_PER_NAME},
};
use kernoid_store::{MainKeys, crypto::Key};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;
use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};
use webauthn_rs_proto::AllowCredentials;

const PASSWORD: &str = "correct horse battery staple";

struct Setup {
    identity: Identity,
    instance: Uuid,
    account: Uuid,
    token: String,
}

async fn setup(pool: &PgPool) -> Setup {
    let identity =
        Identity::with_secrets(EventStore::new(pool.clone()), MainKeys::new(Key::random().unwrap(), Vec::new()));
    let (instance, tenant) = tenant_with(&identity, "login.firma.de", &["firma.de"]).await;
    let account = identity.add_account(tenant, &Address::parse("alice@firma.de").unwrap(), "Alice", WHO).await.unwrap();
    identity.set_password(account, PASSWORD, WHO).await.unwrap();
    let token = identity
        .create_session(instance, "alice@firma.de", PASSWORD, None, &ClientMeta::default())
        .await
        .unwrap()
        .token;
    Setup { identity, instance, account, token }
}

/// The code an app would show, `offset` steps from now.
fn totp(secret: &str, offset: i64) -> String {
    const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut buffer, mut bits, mut key) = (0u32, 0, Vec::new());
    for c in secret.chars() {
        buffer = (buffer << 5) | ALPHABET.find(c).unwrap() as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            key.push((buffer >> bits) as u8);
        }
    }
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() / 30;
    let step = (now as i64 + offset) as u64;
    let mac = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &key), &step.to_be_bytes());
    let mac = mac.as_ref();
    let at = usize::from(mac[19] & 0x0f);
    let value = u32::from_be_bytes([mac[at] & 0x7f, mac[at + 1], mac[at + 2], mac[at + 3]]) % 1_000_000;
    format!("{value:06}")
}

async fn make_old(pool: &PgPool) {
    sqlx::query!("UPDATE sessions SET created_at = now() - interval '20 minutes'").execute(pool).await.unwrap();
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn totp_from_setup_to_check(pool: PgPool) {
    let s = setup(&pool).await;
    let proposal = s.identity.start_totp(s.instance, &s.token, "kernoid").await.unwrap();
    assert_eq!(proposal.secret.len(), 32);
    assert!(proposal.uri.starts_with("otpauth://totp/kernoid%3Aalice%40firma.de?secret="), "{}", proposal.uri);
    // The QR code is an SVG image the login UI shows as it is.
    let svg = proposal.qr_code.strip_prefix("data:image/svg+xml;base64,").expect("a data URL");
    let svg = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, svg).unwrap();
    let svg = String::from_utf8(svg).unwrap();
    assert!(svg.contains("<svg") && svg.contains("<path") && !svg.contains("<script"), "{svg}");

    assert!(matches!(s.identity.confirm_totp(s.instance, &s.token, "000000").await, Err(IdentityError::InvalidCode)));
    s.identity.confirm_totp(s.instance, &s.token, &totp(&proposal.secret, 0)).await.unwrap();
    assert!(s.identity.session(s.instance, &s.token).await.unwrap().checks.contains(&"totp".to_owned()));
    assert!(matches!(s.identity.start_totp(s.instance, &s.token, "kernoid").await, Err(IdentityError::Exists(_))));

    // Every code works once; the next step's code works, an earlier one no longer.
    let current = totp(&proposal.secret, 0);
    assert!(matches!(s.identity.check_totp(s.instance, &s.token, &current).await, Err(IdentityError::InvalidCode)));
    s.identity.check_totp(s.instance, &s.token, &totp(&proposal.secret, 1)).await.unwrap();
    assert!(matches!(
        s.identity.check_totp(s.instance, &s.token, &totp(&proposal.secret, -1)).await,
        Err(IdentityError::InvalidCode)
    ));

    // The secret is sealed: neither in the table in clear nor in any event.
    let stored: Vec<u8> = sqlx::query_scalar!("SELECT secret_sealed FROM account_totp").fetch_one(&pool).await.unwrap();
    let decoded = {
        let mut out = Vec::new();
        let (mut buffer, mut bits) = (0u32, 0);
        for c in proposal.secret.chars() {
            buffer = (buffer << 5) | "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".find(c).unwrap() as u32;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                out.push((buffer >> bits) as u8);
            }
        }
        out
    };
    assert!(!stored.windows(decoded.len()).any(|window| window == decoded.as_slice()));
    let payloads: Vec<String> =
        sqlx::query_scalar!(r#"SELECT payload::text AS "p!" FROM events"#).fetch_all(&pool).await.unwrap();
    assert!(payloads.iter().all(|payload| !payload.contains(&proposal.secret)));
    let types: Vec<String> =
        sqlx::query_scalar!("SELECT event_type FROM events WHERE aggregate_type = 'session' ORDER BY position")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(types, ["session.created", "session.checked"], "checking totp again records nothing new");
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn totp_needs_a_recent_login_and_limits_guesses(pool: PgPool) {
    let s = setup(&pool).await;
    let proposal = s.identity.start_totp(s.instance, &s.token, "kernoid").await.unwrap();
    s.identity.confirm_totp(s.instance, &s.token, &totp(&proposal.secret, 0)).await.unwrap();

    for _ in 0..FAILURES_PER_NAME {
        let _ = s.identity.check_totp(s.instance, &s.token, "123456").await;
    }
    assert!(matches!(
        s.identity.check_totp(s.instance, &s.token, &totp(&proposal.secret, 1)).await,
        Err(IdentityError::TooManyAttempts { .. })
    ));

    make_old(&pool).await;
    assert!(matches!(s.identity.remove_totp(s.instance, &s.token).await, Err(IdentityError::RecentLoginRequired)));
    assert!(matches!(
        s.identity.start_passkey_registration(&rp(), s.instance, &s.token).await,
        Err(IdentityError::RecentLoginRequired)
    ));

    let fresh =
        s.identity.create_session(s.instance, "alice@firma.de", PASSWORD, None, &ClientMeta::default()).await.unwrap();
    s.identity.remove_totp(s.instance, &fresh.token).await.unwrap();
    assert!(matches!(
        s.identity.check_totp(s.instance, &fresh.token, "123456").await,
        Err(IdentityError::TooManyAttempts { .. }) | Err(IdentityError::Refused(_))
    ));
}

fn rp() -> RelyingParty {
    RelyingParty {
        id: "login.firma.de".into(),
        origins: vec!["https://login.firma.de".parse().unwrap()],
        name: "Firma".into(),
    }
}

/// Registers a passkey with the software token; returns the token and the credential id.
async fn register(s: &Setup, authenticator: &mut WebauthnAuthenticator<SoftPasskey>) -> Vec<u8> {
    let challenge = s.identity.start_passkey_registration(&rp(), s.instance, &s.token).await.unwrap();
    let options: CreationChallengeResponse = serde_json::from_value(challenge.options).unwrap();
    let credential = authenticator.do_registration(rp().origins[0].clone(), options).unwrap();
    let raw_id = credential.raw_id.to_vec();
    let answer = serde_json::to_value(&credential).unwrap();
    s.identity
        .finish_passkey_registration(&rp(), s.instance, &s.token, &challenge.id, "Laptop", &answer)
        .await
        .unwrap();
    raw_id
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn passkeys_register_and_check(pool: PgPool) {
    let s = setup(&pool).await;
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    register(&s, &mut authenticator).await;
    let listed = s.identity.passkeys(s.instance, &s.token).await.unwrap();
    assert_eq!((listed.len(), listed[0].name.as_str()), (1, "Laptop"));

    let challenge = s.identity.start_passkey_check(&rp(), s.instance, &s.token).await.unwrap();
    let options: RequestChallengeResponse = serde_json::from_value(challenge.options).unwrap();
    let answer =
        serde_json::to_value(authenticator.do_authentication(rp().origins[0].clone(), options).unwrap()).unwrap();
    let session = s.identity.finish_passkey_check(&rp(), s.instance, &s.token, &challenge.id, &answer).await.unwrap();
    assert_eq!(session.checks, ["password", "passkey"]);
    // A challenge is used once.
    assert!(matches!(
        s.identity.finish_passkey_check(&rp(), s.instance, &s.token, &challenge.id, &answer).await,
        Err(IdentityError::PasskeyRejected)
    ));
    // Another origin – a phishing page – does not pass.
    let challenge = s.identity.start_passkey_check(&rp(), s.instance, &s.token).await.unwrap();
    let options: RequestChallengeResponse = serde_json::from_value(challenge.options).unwrap();
    let phished = authenticator.do_authentication("https://login.firma.de.evil.example".parse().unwrap(), options);
    if let Ok(phished) = phished {
        let answer = serde_json::to_value(phished).unwrap();
        assert!(matches!(
            s.identity.finish_passkey_check(&rp(), s.instance, &s.token, &challenge.id, &answer).await,
            Err(IdentityError::PasskeyRejected)
        ));
    }

    let id = listed[0].id;
    s.identity.remove_passkey(s.instance, &s.token, id).await.unwrap();
    assert!(s.identity.passkeys(s.instance, &s.token).await.unwrap().is_empty());
    assert!(matches!(
        s.identity.start_passkey_check(&rp(), s.instance, &s.token).await,
        Err(IdentityError::Refused(_))
    ));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn passkey_login_without_password_or_address(pool: PgPool) {
    let s = setup(&pool).await;
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let credential_id = register(&s, &mut authenticator).await;

    let login = |authenticator: &mut WebauthnAuthenticator<SoftPasskey>, options: Value, user: Uuid| {
        // A discoverable passkey: the device knows its credential and the user handle. The software token does not
        // keep resident keys, so the test hands it the credential and sets the handle the device would send.
        let mut options: RequestChallengeResponse = serde_json::from_value(options).unwrap();
        assert!(options.public_key.allow_credentials.is_empty(), "nothing tells which accounts exist");
        options.public_key.allow_credentials =
            vec![AllowCredentials { type_: "public-key".into(), id: credential_id.clone().into(), transports: None }];
        let mut answer = authenticator.do_authentication(rp().origins[0].clone(), options).unwrap();
        answer.response.user_handle = Some(user.as_bytes().to_vec().into());
        serde_json::to_value(answer).unwrap()
    };

    let challenge = s.identity.start_passkey_login(&rp(), s.instance, &ClientMeta::default()).await.unwrap();
    let answer = login(&mut authenticator, challenge.options, s.account);
    let created = s
        .identity
        .finish_passkey_login(&rp(), s.instance, &challenge.id, &answer, None, &ClientMeta::default())
        .await
        .unwrap();
    assert_eq!(created.account.id, s.account);
    let session = s.identity.session(s.instance, &created.token).await.unwrap();
    assert_eq!(session.checks, ["passkey"]);

    // A handle that does not belong to the credential: refused.
    let challenge = s.identity.start_passkey_login(&rp(), s.instance, &ClientMeta::default()).await.unwrap();
    let answer = login(&mut authenticator, challenge.options, Uuid::now_v7());
    assert!(matches!(
        s.identity.finish_passkey_login(&rp(), s.instance, &challenge.id, &answer, None, &ClientMeta::default()).await,
        Err(IdentityError::PasskeyRejected)
    ));

    // An operator resets the second factors of someone who lost their device.
    s.identity.reset_second_factors(s.account, "operator").await.unwrap();
    assert!(s.identity.passkeys(s.instance, &s.token).await.unwrap().is_empty());
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn recovery_codes_work_once(pool: PgPool) {
    let s = setup(&pool).await;
    let codes = s.identity.generate_recovery_codes(s.instance, &s.token).await.unwrap();
    assert_eq!(codes.len(), 10);
    assert_eq!(s.identity.second_factors(s.instance, &s.token).await.unwrap().recovery_codes_left, 10);

    // As typed from paper: upper case, spaces instead of dashes.
    let typed = codes[0].to_uppercase().replace('-', " ");
    let session = s.identity.check_recovery_code(s.instance, &s.token, &typed).await.unwrap();
    assert_eq!(session.checks, ["password", "recovery"]);
    assert!(matches!(
        s.identity.check_recovery_code(s.instance, &s.token, &codes[0]).await,
        Err(IdentityError::InvalidCode)
    ));
    assert_eq!(s.identity.second_factors(s.instance, &s.token).await.unwrap().recovery_codes_left, 9);

    // New codes replace all earlier ones.
    let fresh = s.identity.generate_recovery_codes(s.instance, &s.token).await.unwrap();
    assert!(matches!(
        s.identity.check_recovery_code(s.instance, &s.token, &codes[1]).await,
        Err(IdentityError::InvalidCode)
    ));
    s.identity.check_recovery_code(s.instance, &s.token, &fresh[1]).await.unwrap();

    // Only hashes are stored, and no code is in an event.
    let payloads: Vec<String> =
        sqlx::query_scalar!(r#"SELECT payload::text AS "p!" FROM events"#).fetch_all(&pool).await.unwrap();
    assert!(fresh.iter().all(|code| payloads.iter().all(|payload| !payload.contains(code.as_str()))));
    let stored: Vec<Vec<u8>> =
        sqlx::query_scalar!("SELECT code_hash FROM account_recovery_codes").fetch_all(&pool).await.unwrap();
    assert!(stored.iter().all(|hash| hash.len() == 32));

    // Guessing is limited, and an operator's reset removes the codes.
    for _ in 0..FAILURES_PER_NAME {
        let _ = s.identity.check_recovery_code(s.instance, &s.token, "aaaa-bbbb-cccc-dddd").await;
    }
    assert!(matches!(
        s.identity.check_recovery_code(s.instance, &s.token, &fresh[2]).await,
        Err(IdentityError::TooManyAttempts { .. })
    ));
    s.identity.reset_second_factors(s.account, "operator").await.unwrap();
    assert_eq!(s.identity.second_factors(s.instance, &s.token).await.unwrap().recovery_codes_left, 0);

    make_old(&pool).await;
    assert!(matches!(
        s.identity.generate_recovery_codes(s.instance, &s.token).await,
        Err(IdentityError::RecentLoginRequired)
    ));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn tenants_can_require_a_second_factor(pool: PgPool) {
    let s = setup(&pool).await;
    let tenant = s.identity.account(s.account).await.unwrap().tenant;
    assert!(!s.identity.tenant_requires_mfa(tenant).await.unwrap());
    s.identity.set_tenant_mfa_required(s.instance, tenant, true, WHO).await.unwrap();
    s.identity.set_tenant_mfa_required(s.instance, tenant, true, WHO).await.unwrap();
    assert!(s.identity.tenant_requires_mfa(tenant).await.unwrap());
    let events: i64 =
        sqlx::query_scalar!(r#"SELECT count(*) AS "n!" FROM events WHERE event_type = 'tenant.mfa_requirement_set'"#)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(events, 1, "setting the same value again records nothing");
    assert!(kernoid_identity::session::is_multi_factor(&["password".into(), "totp".into()]));
    assert!(kernoid_identity::session::is_multi_factor(&["passkey".into()]));
    assert!(!kernoid_identity::session::is_multi_factor(&["password".into()]));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn a_grace_period_gives_time_to_set_up_a_second_factor(pool: PgPool) {
    let s = setup(&pool).await;
    let tenant = s.identity.account(s.account).await.unwrap().tenant;
    s.identity.set_tenant_mfa_required(s.instance, tenant, true, WHO).await.unwrap();
    assert!(s.identity.mfa_required_now(s.account).await.unwrap());
    assert!(matches!(s.identity.admin(s.instance, &s.token, None).await, Err(IdentityError::MfaRequired)));

    assert!(s.identity.set_tenant_mfa_grace(s.instance, tenant, 366, WHO).await.is_err());
    s.identity.set_tenant_mfa_grace(s.instance, tenant, 14, WHO).await.unwrap();
    let status = s.identity.mfa_status(s.account).await.unwrap();
    let left = status.grace_until.expect("in the grace period") - chrono::Utc::now();
    assert!(status.required && left > chrono::Duration::days(13) && left <= chrono::Duration::days(14), "{left}");
    assert!(!s.identity.mfa_required_now(s.account).await.unwrap());
    s.identity.admin(s.instance, &s.token, None).await.unwrap();
    let factors = s.identity.second_factors(s.instance, &s.token).await.unwrap();
    assert_eq!((factors.required, factors.setup_due), (true, status.grace_until));

    // Once the account has a second factor, it uses it: the grace period is over for it.
    let setup = s.identity.start_totp(s.instance, &s.token, "Firma").await.unwrap();
    s.identity.confirm_totp(s.instance, &s.token, &totp(&setup.secret, 0)).await.unwrap();
    assert_eq!(s.identity.mfa_status(s.account).await.unwrap().grace_until, None);
    assert!(s.identity.mfa_required_now(s.account).await.unwrap());

    // And it ends: requirement older than the grace period.
    s.identity.reset_second_factors(s.account, WHO).await.unwrap();
    sqlx::query!("UPDATE tenants SET mfa_required_since = now() - interval '15 days'").execute(&pool).await.unwrap();
    sqlx::query!("UPDATE accounts SET created_at = now() - interval '15 days'").execute(&pool).await.unwrap();
    assert!(s.identity.mfa_required_now(s.account).await.unwrap());
}
