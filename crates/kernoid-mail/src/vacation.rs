// SPDX-License-Identifier: AGPL-3.0-or-later
//! The vacation response of an account (JMAP, RFC 8621, 8; RFC 0002, 9.4): on, from and to a time, with a subject
//! and a body. While it is on, delivery answers what arrives as a Sieve `vacation` (RFC 5230) does – once per sender
//! in seven days, not to lists, bounces or automatic mail – after the account's own script.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{Mail, MailError, Result};

/// The longest subject and body taken.
const MAX_TEXT: usize = 16 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VacationResponse {
    pub enabled: bool,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
    /// Without one, the reply's subject is "Auto: " and the subject of what it answers.
    pub subject: Option<String>,
    pub text_body: Option<String>,
    pub html_body: Option<String>,
}

impl VacationResponse {
    /// Whether it answers at `now`.
    pub fn answers_at(&self, now: DateTime<Utc>) -> bool {
        self.enabled && self.from_date.is_none_or(|from| from <= now) && self.to_date.is_none_or(|to| now < to)
    }

    /// The Sieve script it runs as at `now`, if it answers then.
    pub(crate) fn script(&self, now: DateTime<Utc>) -> Option<String> {
        if !self.answers_at(now) {
            return None;
        }
        let body = match (&self.text_body, &self.html_body) {
            (Some(text), _) if !text.trim().is_empty() => text.clone(),
            (_, Some(html)) => text_of(html),
            _ => String::new(),
        };
        let subject = self.subject.as_deref().filter(|subject| !subject.trim().is_empty());
        let subject = subject.map(|subject| format!(":subject {} ", quoted(subject))).unwrap_or_default();
        Some(format!("require \"vacation\";\nvacation {subject}{};\n", quoted(&body)))
    }
}

/// A Sieve quoted string (RFC 5228, 2.4.2): backslashes and quotes escaped.
fn quoted(text: &str) -> String {
    format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
}

/// The text of HTML, roughly: tags out, the usual entities back, blocks as lines – a vacation reply is plain text.
fn text_of(html: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    let mut tag = String::new();
    for c in html.chars() {
        match (in_tag, c) {
            (false, '<') => {
                in_tag = true;
                tag.clear();
            }
            (true, '>') => {
                in_tag = false;
                let name = tag.trim_start_matches('/').split_whitespace().next().unwrap_or_default().to_lowercase();
                if ["br", "p", "div", "li", "tr", "h1", "h2", "h3"].contains(&name.as_str()) {
                    out.push('\n');
                }
            }
            (true, c) => tag.push(c),
            (false, c) => out.push(c),
        }
    }
    let out = out
        .replace("&nbsp;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&amp;", "&");
    out.lines().map(str::trim_end).collect::<Vec<_>>().join("\n").trim().to_owned()
}

impl Mail {
    /// The account's vacation response; off if it never had one.
    pub async fn vacation_response(&self, account: Uuid) -> Result<VacationResponse> {
        let row = sqlx::query!(
            "SELECT is_enabled, from_date, to_date, subject, text_body, html_body FROM vacation_responses
             WHERE account_id = $1",
            account,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map_or_else(VacationResponse::default, |row| VacationResponse {
            enabled: row.is_enabled,
            from_date: row.from_date,
            to_date: row.to_date,
            subject: row.subject,
            text_body: row.text_body,
            html_body: row.html_body,
        }))
    }

    pub async fn set_vacation_response(&self, account: Uuid, vacation: &VacationResponse) -> Result<()> {
        let too_long = [&vacation.subject, &vacation.text_body, &vacation.html_body]
            .iter()
            .any(|text| text.as_ref().is_some_and(|text| text.len() > MAX_TEXT));
        if too_long {
            return Err(MailError::Invalid(format!("a vacation response's texts take at most {MAX_TEXT} bytes")));
        }
        if let (Some(from), Some(to)) = (vacation.from_date, vacation.to_date)
            && to <= from
        {
            return Err(MailError::Invalid("toDate is after fromDate".into()));
        }
        sqlx::query!(
            "INSERT INTO vacation_responses (account_id, is_enabled, from_date, to_date, subject, text_body, html_body)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (account_id) DO UPDATE SET is_enabled = $2, from_date = $3, to_date = $4, subject = $5,
                 text_body = $6, html_body = $7, updated_at = now()",
            account,
            vacation.enabled,
            vacation.from_date,
            vacation.to_date,
            vacation.subject,
            vacation.text_body,
            vacation.html_body,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    #[test]
    fn it_answers_within_its_dates_as_a_sieve_vacation() {
        let at = |day| Utc.with_ymd_and_hms(2026, 11, day, 12, 0, 0).unwrap();
        let mut vacation = VacationResponse {
            enabled: true,
            from_date: Some(at(2)),
            to_date: Some(at(9)),
            subject: Some("Away \"till\" Monday".into()),
            text_body: Some("Back on the 9th.\\Bye".into()),
            html_body: None,
        };
        assert_eq!(vacation.script(at(1)), None);
        assert_eq!(vacation.script(at(9)), None);
        let script = vacation.script(at(5)).unwrap();
        assert_eq!(
            script,
            "require \"vacation\";\nvacation :subject \"Away \\\"till\\\" Monday\" \"Back on the 9th.\\\\Bye\";\n"
        );
        crate::scripts::check_script(&script).unwrap();
        vacation.enabled = false;
        assert_eq!(vacation.script(at(5)), None);
    }

    #[test]
    fn html_becomes_text() {
        assert_eq!(text_of("<p>Back <b>Monday</b>.</p><p>Fish &amp; chips</p>"), "Back Monday.\n\nFish & chips");
    }
}
