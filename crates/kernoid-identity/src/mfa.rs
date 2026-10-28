// SPDX-License-Identifier: AGPL-3.0-or-later
//! TOTP (RFC 6238): a further check of a session with a six-digit code from an app.
//!
//! - **Setting up** needs a recent session (see [`crate::session::RECENT`]): kernoid proposes a secret (160 bits,
//!   sealed with the main key, never in an event), the app shows it as a QR code from the `otpauth://` URI, and the
//!   first correct code confirms it (`account.totp_enabled`).
//! - **Checking:** HMAC-SHA1, six digits, 30-second steps, one step of tolerance either way. Every code works once –
//!   the last accepted step is kept. Failed codes are limited like failed passwords (5 per 15 minutes per account).

use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::hmac;
use kernoid_events::{InlineFuture, aggregate::CommandError, inline};
use uuid::Uuid;

use crate::{
    Identity, IdentityError, Result,
    account::{Account, AccountEvent, project},
    session::{CHECK_TOTP, FAILURES_PER_NAME, SessionInfo},
};

const STEP_SECONDS: u64 = 30;
const DIGITS: u32 = 6;
const SECRET_BYTES: usize = 20;

/// What the app needs to set TOTP up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpSetup {
    /// The secret in base32, for typing it in.
    pub secret: String,
    /// `otpauth://totp/…`, for a QR code.
    pub uri: String,
    /// That URI as a QR code: an SVG image as a `data:` URL, for an `<img>`.
    pub qr_code: String,
}

/// `uri` as a QR code (error correction M), drawn as SVG, in a `data:` URL – drawn by the server, so that a login UI
/// needs no QR library and builds no markup.
fn qr_code(uri: &str) -> Result<String> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let code = qrcode::QrCode::with_error_correction_level(uri.as_bytes(), qrcode::EcLevel::M)
        .map_err(|error| IdentityError::Refused(format!("no QR code: {error}")))?;
    let svg = code
        .render::<qrcode::render::svg::Color<'_>>()
        .min_dimensions(200, 200)
        .dark_color(qrcode::render::svg::Color("#000000"))
        .light_color(qrcode::render::svg::Color("#ffffff"))
        .quiet_zone(true)
        .build();
    Ok(format!("data:image/svg+xml;base64,{}", STANDARD.encode(svg)))
}

fn context(account: Uuid) -> Vec<u8> {
    format!("kernoid/totp/v1/{account}").into_bytes()
}

/// RFC 4648 base32, without padding.
fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let (mut buffer, mut bits) = (0u32, 0);
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// The code for `step` (RFC 4226, 5.3: dynamic truncation of HMAC-SHA1).
fn code(secret: &[u8], step: u64) -> u32 {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let mac = hmac::sign(&key, &step.to_be_bytes());
    let mac = mac.as_ref();
    let offset = usize::from(mac[19] & 0x0f);
    let value = u32::from_be_bytes([mac[offset] & 0x7f, mac[offset + 1], mac[offset + 2], mac[offset + 3]]);
    value % 10u32.pow(DIGITS)
}

fn now_step() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("after 1970").as_secs() / STEP_SECONDS
}

/// The step `given` belongs to, if it is the code of the current step or one next to it.
fn matching_step(secret: &[u8], given: &str, now: u64) -> Option<u64> {
    let given = given.trim();
    if given.len() != DIGITS as usize || !given.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // Every candidate is computed and compared, so the time taken does not tell which one matched.
    let mut found = None;
    for step in [now - 1, now, now + 1] {
        let expected = format!("{:0width$}", code(secret, step), width = DIGITS as usize);
        if crate::constant_time_eq(expected.as_bytes(), given.as_bytes()) {
            found = Some(step);
        }
    }
    found
}

fn command_error(error: CommandError<IdentityError>) -> IdentityError {
    match error {
        CommandError::Refused(error) => error,
        CommandError::Store(error) => IdentityError::Store(error),
    }
}

fn store_error(error: sqlx::Error) -> IdentityError {
    IdentityError::Store(error.into())
}

impl Identity {
    fn secrets(&self) -> Result<&kernoid_store::MainKeys> {
        self.secrets.as_ref().ok_or_else(|| IdentityError::Refused("TOTP is not available here".into()))
    }

    /// Proposes a TOTP secret for the session's account; `issuer` names kernoid in the app.
    pub async fn start_totp(&self, instance: Uuid, token: &str, issuer: &str) -> Result<TotpSetup> {
        let session = self.recent_session(instance, token).await?;
        let account = session.account.id;
        let mut secret = zeroize::Zeroizing::new([0u8; SECRET_BYTES]);
        getrandom::fill(secret.as_mut()).map_err(|_| IdentityError::Refused("no randomness available".into()))?;
        let sealed = self
            .secrets()?
            .seal_secret(&context(account), secret.as_ref())
            .map_err(|error| IdentityError::Refused(format!("cannot seal the secret: {error}")))?;
        let replaced = sqlx::query!(
            "INSERT INTO account_totp (account_id, secret_sealed) VALUES ($1, $2)
             ON CONFLICT (account_id) DO UPDATE SET secret_sealed = excluded.secret_sealed, last_step = NULL
             WHERE account_totp.confirmed_at IS NULL",
            account,
            sealed,
        )
        .execute(self.pool())
        .await
        .map_err(store_error)?
        .rows_affected();
        if replaced == 0 {
            return Err(IdentityError::Exists("TOTP"));
        }
        let encoded = base32(secret.as_ref());
        let label = format!("{issuer}:{}", session.account.address);
        let uri = url::Url::parse_with_params(
            &format!("otpauth://totp/{}", url::form_urlencoded::byte_serialize(label.as_bytes()).collect::<String>()),
            &[
                ("secret", encoded.as_str()),
                ("issuer", issuer),
                ("algorithm", "SHA1"),
                ("digits", "6"),
                ("period", "30"),
            ],
        )
        .map_err(|error| IdentityError::Refused(error.to_string()))?;
        let uri = String::from(uri);
        Ok(TotpSetup { secret: encoded, qr_code: qr_code(&uri)?, uri })
    }

    /// Confirms the proposed secret with a first code; TOTP is then on, and the session has passed it.
    pub async fn confirm_totp(&self, instance: Uuid, token: &str, code: &str) -> Result<()> {
        let session = self.recent_session(instance, token).await?;
        self.consume_code(instance, &session, code, false).await?;
        let account = session.account.id;
        let confirm = inline(move |connection, events| {
            Box::pin(async move {
                project(connection, events).await?;
                sqlx::query!("UPDATE account_totp SET confirmed_at = now() WHERE account_id = $1", account)
                    .execute(&mut *connection)
                    .await?;
                Ok(())
            }) as InlineFuture<'_>
        });
        self.events
            .execute_with(
                instance,
                session.account.tenant,
                &account.to_string(),
                &format!("account:{account}"),
                |state: &Account| Ok(if state.totp { Vec::new() } else { vec![AccountEvent::TotpEnabled] }),
                confirm,
            )
            .await
            .map_err(command_error)?;
        self.add_session_check(instance, &session, CHECK_TOTP).await
    }

    /// Removes TOTP from the session's account.
    pub async fn remove_totp(&self, instance: Uuid, token: &str) -> Result<()> {
        let session = self.recent_session(instance, token).await?;
        self.remove_totp_of(
            instance,
            session.account.tenant,
            session.account.id,
            &format!("account:{}", session.account.id),
        )
        .await
    }

    pub(crate) async fn remove_totp_of(
        &self,
        instance: Uuid,
        tenant: Uuid,
        account: Uuid,
        creator: &str,
    ) -> Result<()> {
        // Also removes a proposed, unconfirmed secret.
        sqlx::query!("DELETE FROM account_totp WHERE account_id = $1 AND confirmed_at IS NULL", account)
            .execute(self.pool())
            .await
            .map_err(store_error)?;
        self.events
            .execute_with(
                instance,
                tenant,
                &account.to_string(),
                creator,
                |state: &Account| Ok(if state.totp { vec![AccountEvent::TotpRemoved] } else { Vec::new() }),
                |c, e| Box::pin(project(c, e)),
            )
            .await
            .map(drop)
            .map_err(command_error)
    }

    /// Checks a TOTP code as a further check of the session.
    pub async fn check_totp(&self, instance: Uuid, token: &str, code: &str) -> Result<SessionInfo> {
        let session = self.session(instance, token).await?;
        self.consume_code(instance, &session, code, true).await?;
        self.add_session_check(instance, &session, CHECK_TOTP).await?;
        self.session(instance, token).await
    }

    /// Accepts `code` once, for a confirmed secret (`confirmed`) or the proposed one; counts failures.
    async fn consume_code(&self, instance: Uuid, session: &SessionInfo, code: &str, confirmed: bool) -> Result<()> {
        let account = session.account.id;
        let key = format!("totp:{account}");
        self.refuse_if_throttled(instance, &key, FAILURES_PER_NAME).await?;
        let sealed = sqlx::query_scalar!(
            "SELECT secret_sealed FROM account_totp WHERE account_id = $1 AND (confirmed_at IS NOT NULL) = $2",
            account,
            confirmed,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(store_error)?
        .ok_or_else(|| IdentityError::Refused("TOTP is not set up".into()))?;
        let (secret, _) = self
            .secrets()?
            .open_secret(&context(account), &sealed)
            .map_err(|error| IdentityError::Refused(format!("cannot open the secret: {error}")))?;
        let accepted = match matching_step(&secret, code, now_step()) {
            // Taken only if no later or equal step was used: a code works once.
            Some(step) => {
                sqlx::query!(
                    "UPDATE account_totp SET last_step = $2
                 WHERE account_id = $1 AND (last_step IS NULL OR last_step < $2)",
                    account,
                    step as i64,
                )
                .execute(self.pool())
                .await
                .map_err(store_error)?
                .rows_affected()
                    == 1
            }
            None => false,
        };
        if !accepted {
            self.count_failure(instance, &key).await?;
            return Err(IdentityError::InvalidCode);
        }
        sqlx::query!("DELETE FROM login_failures WHERE instance_id = $1 AND key = $2", instance, key)
            .execute(self.pool())
            .await
            .map_err(store_error)?;
        Ok(())
    }
}

/// How many recovery codes are generated at a time.
pub const RECOVERY_CODES: u32 = 10;
/// Characters of recovery codes: no 0/o, 1/i/l, so that a code read aloud or written down survives.
const RECOVERY_ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
const RECOVERY_LENGTH: usize = 16;

/// The second factors an account has – for the login UI to know whether to ask for one or to set one up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecondFactors {
    pub totp: bool,
    pub passkeys: i64,
    pub recovery_codes_left: i64,
    /// The tenant requires a second factor.
    pub required: bool,
    /// Without one yet: the end of the tenant's grace period – set one up before.
    pub setup_due: Option<chrono::DateTime<chrono::Utc>>,
}

/// A code as typed: lower case, without dashes and spaces.
fn normalise_recovery(code: &str) -> String {
    code.chars().filter(|c| !matches!(c, '-' | ' ')).flat_map(char::to_lowercase).collect()
}

/// Bound to the account, so that the same code of two accounts has different hashes.
fn recovery_hash(account: Uuid, code: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::new()
        .chain_update(b"kernoid/recovery-code/v1/")
        .chain_update(account.as_bytes())
        .chain_update(normalise_recovery(code).as_bytes())
        .finalize()
        .into()
}

/// `xxxx-xxxx-xxxx-xxxx` from 31 characters: about 79 bits, beyond guessing even offline.
fn new_recovery_code() -> Result<String> {
    let mut code = String::new();
    while code.len() < RECOVERY_LENGTH {
        let mut byte = [0u8; 1];
        getrandom::fill(&mut byte).map_err(|_| IdentityError::Refused("no randomness available".into()))?;
        // Rejection sampling: only bytes that map evenly onto the alphabet.
        if usize::from(byte[0]) < 256 / RECOVERY_ALPHABET.len() * RECOVERY_ALPHABET.len() {
            code.push(RECOVERY_ALPHABET[usize::from(byte[0]) % RECOVERY_ALPHABET.len()] as char);
        }
    }
    Ok(code.as_bytes().chunks(4).map(|part| std::str::from_utf8(part).expect("ascii")).collect::<Vec<_>>().join("-"))
}

impl Identity {
    /// Generates new recovery codes for the session's account (needs a recent session); all earlier ones stop
    /// working. The codes are shown this once.
    pub async fn generate_recovery_codes(&self, instance: Uuid, token: &str) -> Result<Vec<String>> {
        let session = self.recent_session(instance, token).await?;
        let account = session.account.id;
        let codes = (0..RECOVERY_CODES).map(|_| new_recovery_code()).collect::<Result<Vec<_>>>()?;
        let hashes: Vec<Vec<u8>> = codes.iter().map(|code| recovery_hash(account, code).to_vec()).collect();
        let store = inline(move |connection, events| {
            let hashes = hashes.clone();
            Box::pin(async move {
                project(connection, events).await?;
                sqlx::query!("DELETE FROM account_recovery_codes WHERE account_id = $1", account)
                    .execute(&mut *connection)
                    .await?;
                sqlx::query!(
                    "INSERT INTO account_recovery_codes (code_hash, account_id) SELECT unnest($1::bytea[]), $2",
                    &hashes,
                    account,
                )
                .execute(&mut *connection)
                .await?;
                Ok(())
            }) as InlineFuture<'_>
        });
        self.events
            .execute_with(
                instance,
                session.account.tenant,
                &account.to_string(),
                &format!("account:{account}"),
                |_: &Account| Ok(vec![AccountEvent::RecoveryCodesGenerated { count: RECOVERY_CODES }]),
                store,
            )
            .await
            .map_err(command_error)?;
        Ok(codes)
    }

    /// Uses a recovery code as a further check of the session: the code is used up.
    pub async fn check_recovery_code(&self, instance: Uuid, token: &str, code: &str) -> Result<SessionInfo> {
        let session = self.session(instance, token).await?;
        let account = session.account.id;
        let key = format!("recovery:{account}");
        self.refuse_if_throttled(instance, &key, FAILURES_PER_NAME).await?;
        let used = sqlx::query!(
            "UPDATE account_recovery_codes SET used_at = now()
             WHERE code_hash = $1 AND account_id = $2 AND used_at IS NULL",
            &recovery_hash(account, code)[..],
            account,
        )
        .execute(self.pool())
        .await
        .map_err(store_error)?
        .rows_affected();
        if used != 1 {
            self.count_failure(instance, &key).await?;
            return Err(IdentityError::InvalidCode);
        }
        self.add_session_check(instance, &session, crate::session::CHECK_RECOVERY).await?;
        self.session(instance, token).await
    }

    /// The second factors of the session's account.
    pub async fn second_factors(&self, instance: Uuid, token: &str) -> Result<SecondFactors> {
        let session = self.session(instance, token).await?;
        let row = sqlx::query!(
            r#"SELECT EXISTS (SELECT 1 FROM account_totp WHERE account_id = $1 AND confirmed_at IS NOT NULL) AS "totp!",
                      (SELECT count(*) FROM account_passkeys WHERE account_id = $1) AS "passkeys!",
                      (SELECT count(*) FROM account_recovery_codes WHERE account_id = $1 AND used_at IS NULL)
                          AS "recovery!""#,
            session.account.id,
        )
        .fetch_one(self.pool())
        .await
        .map_err(store_error)?;
        let status = self.mfa_status(session.account.id).await?;
        Ok(SecondFactors {
            totp: row.totp,
            passkeys: row.passkeys,
            recovery_codes_left: row.recovery,
            required: status.required,
            setup_due: status.grace_until,
        })
    }

    /// Removes the recovery codes of an account (with the other second factors, by an operator).
    pub(crate) async fn remove_recovery_codes_of(
        &self,
        instance: Uuid,
        tenant: Uuid,
        account: Uuid,
        creator: &str,
    ) -> Result<()> {
        self.events
            .execute_with(
                instance,
                tenant,
                &account.to_string(),
                creator,
                |state: &Account| {
                    Ok(if state.recovery_codes { vec![AccountEvent::RecoveryCodesRemoved] } else { Vec::new() })
                },
                |c, e| Box::pin(project(c, e)),
            )
            .await
            .map(drop)
            .map_err(command_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_base32(value: &str) -> Vec<u8> {
        const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let (mut buffer, mut bits, mut out) = (0u32, 0, Vec::new());
        for c in value.chars() {
            buffer = (buffer << 5) | ALPHABET.find(c).unwrap() as u32;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                out.push((buffer >> bits) as u8);
            }
        }
        out
    }

    #[test]
    fn recovery_codes() {
        let code = new_recovery_code().unwrap();
        assert_eq!(code.len(), 19);
        assert!(code.chars().all(|c| c == '-' || RECOVERY_ALPHABET.contains(&(c as u8))), "{code}");
        assert_ne!(code, new_recovery_code().unwrap());
        let account = Uuid::now_v7();
        assert_eq!(recovery_hash(account, &code), recovery_hash(account, &code.to_uppercase().replace('-', " ")));
        assert_ne!(recovery_hash(account, &code), recovery_hash(Uuid::now_v7(), &code));
    }

    #[test]
    fn rfc_6238_test_vectors() {
        // Appendix B, SHA-1, seed "12345678901234567890", eight digits cut to six.
        let seed = b"12345678901234567890";
        for (time, expected) in
            [(59u64, 94287082u32), (1111111109, 7081804), (1111111111, 14050471), (1234567890, 89005924)]
        {
            assert_eq!(code(seed, time / STEP_SECONDS), expected % 1_000_000, "{time}");
        }
    }

    #[test]
    fn base32_round_trip() {
        assert_eq!(base32(b"12345678901234567890"), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(decode_base32(&base32(&[0xff; 20])), [0xff; 20]);
    }

    #[test]
    fn steps_next_to_now_match() {
        let secret = b"12345678901234567890";
        let now = 1_000_000;
        for offset in [-1i64, 0, 1] {
            let step = (now as i64 + offset) as u64;
            assert_eq!(matching_step(secret, &format!("{:06}", code(secret, step)), now), Some(step));
        }
        assert_eq!(matching_step(secret, &format!("{:06}", code(secret, now + 2)), now), None);
        assert_eq!(matching_step(secret, "12345", now), None);
        assert_eq!(matching_step(secret, "abcdef", now), None);
    }
}
