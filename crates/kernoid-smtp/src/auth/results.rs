// SPDX-License-Identifier: AGPL-3.0-or-later
//! The headers that report the checks: `Authentication-Results` (RFC 8601) – one result per method and signature,
//! each on a line of its own, reasons in comments – and `Received-SPF` (RFC 7208, 9.1).

use std::net::IpAddr;

use super::{
    arc::{ArcOutput, ArcResult},
    dkim::DkimOutput,
    dmarc::{DmarcOutput, DmarcResult},
    iprev::{IprevOutput, IprevResult},
    spf::{Identity, SpfOutput, SpfParameters, SpfResult},
};

/// A comment, without what would end or nest it.
fn comment(text: &str) -> String {
    let text: String = text.chars().filter(|c| !c.is_control() && !matches!(c, '(' | ')' | '\\')).take(200).collect();
    format!(" ({})", text.trim())
}

/// Whether `value` can be written without quotes: a token (RFC 2045, 5.1) or `local@domain` (RFC 8601, 2.2 pvalue).
fn plain(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|c| {
            c.is_ascii_graphic() && !matches!(c, '(' | ')' | '<' | '>' | ',' | ';' | ':' | '\\' | '"' | '/' | '[' | ']' | '?' | '=')
        })
}

/// A value, quoted where it must be.
fn value(value: &str) -> String {
    if plain(value) {
        value.to_owned()
    } else {
        let escaped: String = value
            .chars()
            .filter(|c| !c.is_control())
            .flat_map(|c| if matches!(c, '"' | '\\') { vec!['\\', c] } else { vec![c] })
            .collect();
        format!("\"{escaped}\"")
    }
}

/// `Authentication-Results` of one host.
#[derive(Debug, Clone)]
pub struct AuthenticationResults {
    authserv_id: String,
    results: Vec<String>,
}

impl AuthenticationResults {
    pub fn new(authserv_id: &str) -> Self {
        Self { authserv_id: authserv_id.to_owned(), results: Vec::new() }
    }

    pub fn with_iprev_result(mut self, iprev: &IprevOutput, ip: IpAddr) -> Self {
        let reason = match &iprev.result {
            IprevResult::Fail(reason) | IprevResult::TempError(reason) | IprevResult::PermError(reason) => comment(reason),
            IprevResult::Pass | IprevResult::None => String::new(),
        };
        self.results.push(format!("iprev={}{reason} policy.iprev={ip}", iprev.result.as_str()));
        self
    }

    pub fn with_spf_result(mut self, spf: &SpfOutput, parameters: &SpfParameters) -> Self {
        let property = match parameters.identity {
            Identity::MailFrom => format!("smtp.mailfrom={}", value(&parameters.sender)),
            Identity::Helo => format!("smtp.helo={}", value(&parameters.helo)),
        };
        let reason = spf.explanation.as_deref().map(comment).unwrap_or_default();
        self.results.push(format!("spf={}{reason} {property}", spf.result.as_str()));
        self
    }

    pub fn with_dkim_results(mut self, dkim: &[DkimOutput]) -> Self {
        if dkim.is_empty() {
            self.results.push("dkim=none".into());
        }
        for output in dkim {
            let mut result = format!("dkim={}", output.result.as_str());
            if let Some(reason) = output.result.reason() {
                result.push_str(&comment(reason));
            }
            if let Some(signature) = &output.signature {
                result.push_str(&format!(
                    " header.d={} header.s={} header.i={} header.a={} header.b={}",
                    value(&signature.domain),
                    value(&signature.selector),
                    value(&signature.identity),
                    signature.algorithm.as_str(),
                    value(&signature.b.chars().take(8).collect::<String>()),
                ));
            }
            self.results.push(result);
        }
        self
    }

    pub fn with_arc_result(mut self, arc: &ArcOutput, ip: IpAddr) -> Self {
        let reason = match &arc.result {
            ArcResult::Fail(reason) => comment(reason),
            ArcResult::Pass | ArcResult::None => String::new(),
        };
        let chain = if arc.sets > 0 { format!(" arc.chain={}", arc.sets) } else { String::new() };
        self.results.push(format!("arc={}{reason}{chain} smtp.remote-ip={ip}", arc.result.as_str()));
        self
    }

    pub fn with_dmarc_result(mut self, dmarc: &DmarcOutput) -> Self {
        let policy = if dmarc.result == DmarcResult::Fail { comment(&format!("p={}", dmarc.policy.as_str())) } else { String::new() };
        let from = if dmarc.domain.is_empty() { String::new() } else { format!(" header.from={}", value(&dmarc.domain)) };
        self.results.push(format!("dmarc={}{policy}{from}", dmarc.result.as_str()));
        self
    }

    /// The header, with its line end.
    pub fn to_header(&self) -> String {
        if self.results.is_empty() {
            return format!("Authentication-Results: {}; none\r\n", self.authserv_id);
        }
        format!("Authentication-Results: {};\r\n\t{}\r\n", self.authserv_id, self.results.join(";\r\n\t"))
    }
}

/// `Received-SPF` (RFC 7208, 9.1), with its line end.
pub fn received_spf(spf: &SpfOutput, parameters: &SpfParameters) -> String {
    let ip = parameters.ip;
    let who = &parameters.sender;
    let explanation = match spf.result {
        SpfResult::Pass => format!("domain of {who} designates {ip} as permitted sender"),
        SpfResult::Fail => format!("domain of {who} does not designate {ip} as permitted sender"),
        SpfResult::SoftFail => format!("domain of {who} discourages use of {ip} as permitted sender"),
        SpfResult::Neutral => format!("{ip} is neither permitted nor denied by domain of {who}"),
        SpfResult::None => format!("domain of {who} does not designate permitted sender hosts"),
        SpfResult::TempError => format!("temporary error in processing during lookup of {who}"),
        SpfResult::PermError => format!("permanent error in processing during lookup of {who}"),
    };
    format!(
        "Received-SPF: {}{}\r\n\treceiver={}; client-ip={ip}; envelope-from={}; helo={}; identity={}\r\n",
        spf.result.as_str(),
        comment(&format!("{}: {explanation}", parameters.hostname)),
        value(&parameters.hostname),
        value_quoted(&parameters.sender),
        value(&parameters.helo),
        parameters.identity.as_str(),
    )
}

/// A value that is always quoted.
fn value_quoted(text: &str) -> String {
    let escaped: String =
        text.chars().filter(|c| !c.is_control()).flat_map(|c| if matches!(c, '"' | '\\') { vec!['\\', c] } else { vec![c] }).collect();
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{dkim::DkimResult, dmarc::Policy};

    #[test]
    fn headers_as_written() {
        let ip: IpAddr = "192.0.2.25".parse().unwrap();
        let parameters = SpfParameters::mail_from(ip, "mx.b.example", "mx.kernoid.example", "alice@b.example");
        let spf = SpfOutput { result: SpfResult::Pass, domain: "b.example".into(), explanation: None };
        let dmarc = DmarcOutput {
            result: DmarcResult::Fail,
            domain: "b.example".into(),
            policy: Policy::Reject,
            spf_aligned: false,
            dkim_aligned: false,
        };
        let header = AuthenticationResults::new("mx.kernoid.example")
            .with_iprev_result(&IprevOutput { result: IprevResult::TempError("no answer (now)".into()), ptr: None }, ip)
            .with_spf_result(&spf, &parameters)
            .with_dkim_results(&[DkimOutput { result: DkimResult::PermError("no key".into()), signature: None, testing: false }])
            .with_arc_result(&ArcOutput { result: ArcResult::None, sets: 0 }, ip)
            .with_dmarc_result(&dmarc)
            .to_header();
        assert_eq!(
            header,
            "Authentication-Results: mx.kernoid.example;\r\n\
             \tiprev=temperror (no answer now) policy.iprev=192.0.2.25;\r\n\
             \tspf=pass smtp.mailfrom=alice@b.example;\r\n\
             \tdkim=permerror (no key);\r\n\
             \tarc=none smtp.remote-ip=192.0.2.25;\r\n\
             \tdmarc=fail (p=reject) header.from=b.example\r\n"
        );
        assert_eq!(
            received_spf(&spf, &parameters),
            "Received-SPF: pass (mx.kernoid.example: domain of alice@b.example designates 192.0.2.25 as permitted sender)\r\n\
             \treceiver=mx.kernoid.example; client-ip=192.0.2.25; envelope-from=\"alice@b.example\"; helo=mx.b.example; \
             identity=mailfrom\r\n"
        );
        assert_eq!(value("a/b=="), "\"a/b==\"");
        assert_eq!(value("say \"hi\""), "\"say \\\"hi\\\"\"");
    }
}
