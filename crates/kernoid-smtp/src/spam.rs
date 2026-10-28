// SPDX-License-Identifier: AGPL-3.0-or-later
//! The basic spam filter (RFC 0002, 9.3): a score added up from the authentication results and from what a message
//! lacks. Transparent on purpose – every test that counted is named in `X-Spam-Status`.

use mail_auth::{DkimResult, DmarcResult, IprevResult, SpfResult};

/// What the filter looks at.
#[derive(Debug, Clone, Default)]
pub struct Signals {
    pub spf_mail_from: Option<SpfResult>,
    pub spf_ehlo: Option<SpfResult>,
    pub dkim: Vec<DkimResult>,
    pub dmarc: Option<DmarcResult>,
    pub iprev: Option<IprevResult>,
    pub has_message_id: bool,
    pub has_date: bool,
    pub has_from: bool,
    /// The `From` domain is one kernoid serves, and nothing (DMARC, DKIM, SPF) shows the message comes from it.
    pub spoofs_local_domain: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub score: f32,
    pub tests: Vec<&'static str>,
}

impl Verdict {
    pub fn is_spam(&self, threshold: f32) -> bool {
        self.score >= threshold
    }

    /// The `X-Spam-Status` header, with its line end.
    pub fn header(&self, threshold: f32) -> String {
        format!(
            "X-Spam-Status: {}, score={:.1} required={:.1} tests={}\r\n",
            if self.is_spam(threshold) { "Yes" } else { "No" },
            self.score,
            threshold,
            if self.tests.is_empty() { "NONE".to_owned() } else { self.tests.join(",") },
        )
    }
}

pub fn score(signals: &Signals) -> Verdict {
    let mut verdict = Verdict { score: 0.0, tests: Vec::new() };
    let mut add = |points: f32, test: &'static str| {
        verdict.score += points;
        verdict.tests.push(test);
    };
    match signals.spf_mail_from {
        Some(SpfResult::Fail) => add(3.0, "SPF_FAIL"),
        Some(SpfResult::SoftFail) => add(1.5, "SPF_SOFTFAIL"),
        _ => {}
    }
    if signals.spf_mail_from.is_none() && signals.spf_ehlo == Some(SpfResult::Fail) {
        add(2.0, "SPF_HELO_FAIL");
    }
    let dkim_pass = signals.dkim.contains(&DkimResult::Pass);
    if !dkim_pass && signals.dkim.iter().any(|result| matches!(result, DkimResult::Fail(_))) {
        add(1.0, "DKIM_FAIL");
    }
    if matches!(signals.dmarc, Some(DmarcResult::Fail(_))) {
        add(2.0, "DMARC_FAIL");
    }
    if matches!(signals.iprev, Some(IprevResult::Fail(_) | IprevResult::PermError(_))) {
        add(1.0, "IPREV_FAIL");
    }
    if !signals.has_message_id {
        add(1.0, "MISSING_MESSAGE_ID");
    }
    if !signals.has_date {
        add(1.0, "MISSING_DATE");
    }
    if !signals.has_from {
        add(2.0, "MISSING_FROM");
    }
    if signals.spoofs_local_domain {
        add(5.0, "FROM_LOCAL_UNAUTHENTICATED");
    }
    verdict
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scores_add_up_and_are_named() {
        let clean = Signals {
            spf_mail_from: Some(SpfResult::Pass),
            dkim: vec![DkimResult::Pass],
            dmarc: Some(DmarcResult::Pass),
            has_message_id: true,
            has_date: true,
            has_from: true,
            ..Signals::default()
        };
        let verdict = score(&clean);
        assert_eq!(verdict.score, 0.0);
        assert_eq!(verdict.header(5.0), "X-Spam-Status: No, score=0.0 required=5.0 tests=NONE\r\n");

        let spoofed = Signals {
            spf_mail_from: Some(SpfResult::Fail),
            has_from: true,
            spoofs_local_domain: true,
            ..Signals::default()
        };
        let verdict = score(&spoofed);
        assert!(verdict.is_spam(5.0));
        assert_eq!(verdict.tests, ["SPF_FAIL", "MISSING_MESSAGE_ID", "MISSING_DATE", "FROM_LOCAL_UNAUTHENTICATED"]);
    }
}
