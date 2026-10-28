// SPDX-License-Identifier: AGPL-3.0-or-later
//! Mail client autoconfiguration (Mozilla's `config-v1.1.xml`, which Thunderbird and others look up at
//! `/.well-known/autoconfig/mail/config-v1.1.xml` of the address's domain): where to connect for IMAP and SMTP, with
//! the address as the user name. The web app reads it too, to show the settings. It names the usual ports (993/143,
//! 465/587): kernoid listens on others where a container maps them (`deploy/test`), and cannot know what is published.

use axum::{
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};

use crate::{AppState, Problem};

/// Escapes text for an XML element or attribute.
fn escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

pub(crate) fn document(mail_host: &str, imap: bool) -> String {
    let host = escape(mail_host);
    let server = |kind: &str, port: u16, socket: &str| {
        format!(
            "    <{kind} type=\"{protocol}\">\n      <hostname>{host}</hostname>\n      <port>{port}</port>\n      \
             <socketType>{socket}</socketType>\n      <authentication>password-cleartext</authentication>\n      \
             <username>%EMAILADDRESS%</username>\n    </{kind}>\n",
            protocol = if kind == "incomingServer" { "imap" } else { "smtp" },
        )
    };
    let mut incoming = String::new();
    if imap {
        incoming.push_str(&server("incomingServer", 993, "SSL"));
        incoming.push_str(&server("incomingServer", 143, "STARTTLS"));
    }
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<clientConfig version=\"1.1\">\n  <emailProvider id=\"{host}\">\n    \
         <domain>%EMAILDOMAIN%</domain>\n    <displayName>kernoid</displayName>\n{incoming}{outgoing_tls}{outgoing_starttls}  \
         </emailProvider>\n</clientConfig>\n",
        outgoing_tls = server("outgoingServer", 465, "SSL"),
        outgoing_starttls = server("outgoingServer", 587, "STARTTLS"),
    )
}

/// `GET /.well-known/autoconfig/mail/config-v1.1.xml` (also `/mail/config-v1.1.xml`, for `autoconfig.<domain>`).
pub(crate) async fn config(State(state): State<AppState>) -> Response {
    match &state.mail_host {
        Some(host) => (
            [(header::CONTENT_TYPE, "application/xml; charset=utf-8"), (header::CACHE_CONTROL, "max-age=3600")],
            document(host, state.imap),
        )
            .into_response(),
        None => Problem::new(StatusCode::NOT_FOUND).detail("kernoid handles no mail here").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::document;

    #[test]
    fn names_the_mail_host_and_the_usual_ports() {
        let xml = document("mail.example.org", true);
        assert!(xml.contains("<hostname>mail.example.org</hostname>"));
        assert!(xml.contains("<port>993</port>") && xml.contains("<port>587</port>"));
        assert!(xml.contains("<username>%EMAILADDRESS%</username>"));
        assert!(!document("mail.example.org", false).contains("incomingServer"));
        assert!(document("a&b", true).contains("a&amp;b"));
    }
}
