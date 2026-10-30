// SPDX-License-Identifier: AGPL-3.0-or-later
//! Delivering the queue (RFC 0002, 10.2 and 10.4): a worker leases the due recipients of one domain, finds the route
//! (the relay, or the domain's MX hosts), delivers each message in one connection, and records every recipient's
//! result – delivered, again later, or failed for good with a bounce to the sender.

use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use chrono::{DateTime, Utc};
use kernoid_mail::{Delivery, Leased, Mail, Outgoing, Recipient};
use mail_auth::IpLookupStrategy;
use rustls::pki_types::ServerName;
use tokio_util::sync::CancellationToken;

use crate::{
    Dns,
    client::{self, Client, ClientError},
    dsn::{self, Failure},
};

/// How long a worker holds the recipients it took.
const LEASE: chrono::Duration = chrono::Duration::minutes(10);
/// Recipients taken at once.
const BATCH: i64 = 100;
/// How often the worker looks for due mail when it found none.
const POLL: Duration = Duration::from_secs(15);

/// A server to hand all mail for other servers to (`[smtp.relay]`).
#[derive(Clone)]
pub struct Relay {
    pub host: String,
    pub port: u16,
    /// TLS from the start (port 465) instead of `STARTTLS`.
    pub implicit_tls: bool,
    pub credentials: Option<(String, String)>,
}

impl std::fmt::Debug for Relay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Relay").field("host", &self.host).field("port", &self.port).finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub struct OutboundSettings {
    /// The name kernoid says `EHLO` with.
    pub hostname: String,
    /// The port of other mail servers: 25; tests use another.
    pub port: u16,
    pub relay: Option<Relay>,
    pub timeout: Duration,
    /// Whether mail servers at private addresses may be reached – only where the installation trusts its senders.
    pub allow_private_networks: bool,
}

impl OutboundSettings {
    pub fn from_config(smtp: &kernoid_config::Smtp, outbound: &kernoid_config::Outbound) -> Self {
        Self {
            hostname: smtp.hostname.trim_end_matches('.').to_lowercase(),
            port: 25,
            relay: smtp.relay.as_ref().map(|relay| Relay {
                host: relay.host.clone(),
                port: relay.port,
                implicit_tls: relay.implicit_tls,
                credentials: relay.username.clone().map(|username| {
                    (username, relay.password.as_ref().map(|p| p.expose().to_owned()).unwrap_or_default())
                }),
            }),
            timeout: std::time::Duration::from_secs(smtp.timeout_seconds),
            allow_private_networks: outbound.allow_private_networks,
        }
    }
}

/// When to try again after `attempts` failed tries: 2, 5, 15 and 30 minutes, then hourly, then every four hours.
pub fn retry_after(attempts: i32) -> chrono::Duration {
    match attempts {
        ..=1 => chrono::Duration::minutes(2),
        2 => chrono::Duration::minutes(5),
        3 => chrono::Duration::minutes(15),
        4 => chrono::Duration::minutes(30),
        5..=8 => chrono::Duration::hours(1),
        _ => chrono::Duration::hours(4),
    }
}

/// How a hop is reached.
#[derive(Debug, Clone)]
enum Tls {
    /// `STARTTLS` if offered, the certificate unchecked; plain text otherwise (RFC 7435).
    Opportunistic,
    /// TLS with a certificate valid for the host – the relay, and MX hosts of an MTA-STS policy in `enforce` mode.
    Verified,
    /// TLS with a certificate matching the host's signed TLSA records; `names` for DANE-TA.
    Dane { tlsa: crate::dane::Tlsa, names: Vec<String> },
}

#[derive(Debug, Clone)]
struct Hop {
    host: String,
    addresses: Vec<SocketAddr>,
    implicit_tls: bool,
    tls: Tls,
    credentials: Option<(String, String)>,
}

#[derive(Debug)]
enum RouteError {
    Permanent(String),
    Temporary(String),
}

#[derive(Debug, Clone)]
enum Outcome {
    Delivered,
    Retry(String),
    Failed(Failure),
}

struct Inner {
    settings: OutboundSettings,
    mail: Mail,
    dns: Dns,
    /// Opens the DKIM keys; without, mail leaves unsigned.
    main: Option<kernoid_store::MainKeys>,
}

/// The worker that delivers the queue.
#[derive(Clone)]
pub struct Outbound(Arc<Inner>);

impl std::fmt::Debug for Outbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Outbound").field("settings", &self.0.settings).finish_non_exhaustive()
    }
}

impl Outbound {
    pub fn new(settings: OutboundSettings, mail: Mail, dns: Dns, main: Option<kernoid_store::MainKeys>) -> Self {
        Self(Arc::new(Inner { settings, mail, dns, main }))
    }

    /// The message with the DKIM signatures of its `From` domain prepended, if kernoid has keys for it (RFC 0002, 10.3).
    async fn signed(&self, raw: bytes::Bytes) -> bytes::Bytes {
        let Some(main) = &self.0.main else { return raw };
        let domain = mail_parser::MessageParser::new()
            .parse_headers(&raw[..])
            .and_then(|message| {
                message.from().and_then(|from| from.first()).and_then(|addr| addr.address().map(str::to_owned))
            })
            .and_then(|address| address.rsplit_once('@').map(|(_, domain)| domain.to_lowercase()));
        let Some(domain) = domain else { return raw };
        match crate::dkim::sign(self.0.mail.pool(), main, &domain, &raw).await {
            Ok(signatures) if signatures.is_empty() => raw,
            Ok(signatures) => {
                let mut signed = signatures.concat().into_bytes();
                signed.extend_from_slice(&raw);
                bytes::Bytes::from(signed)
            }
            Err(error) => {
                tracing::warn!(%error, %domain, "DKIM signing failed; sending unsigned");
                raw
            }
        }
    }

    /// The resolver and its caches – tests put records into them.
    pub fn dns(&self) -> &Dns {
        &self.0.dns
    }

    /// Delivers what is due until `stop`.
    pub async fn run(self, stop: CancellationToken) {
        loop {
            match self.deliver_due().await {
                Ok(0) => {}
                Ok(handled) => tracing::debug!(handled, "delivered queued recipients"),
                Err(error) => tracing::warn!(%error, "delivering the queue failed; trying again later"),
            }
            tokio::select! {
                () = stop.cancelled() => return,
                () = tokio::time::sleep(POLL) => {}
            }
        }
    }

    /// Delivers every recipient that is due now; returns how many were handled.
    pub async fn deliver_due(&self) -> Result<usize, kernoid_mail::MailError> {
        let mut handled = 0;
        while let Some(batch) = self.0.mail.lease_due(LEASE, BATCH).await? {
            handled += batch.recipients.len();
            self.deliver_batch(&batch.domain, batch.recipients).await;
        }
        Ok(handled)
    }

    async fn deliver_batch(&self, domain: &str, recipients: Vec<Leased>) {
        let mut by_message: BTreeMap<uuid::Uuid, Vec<Leased>> = BTreeMap::new();
        for recipient in recipients {
            by_message.entry(recipient.message).or_default().push(recipient);
        }
        let mut outcomes: Vec<(Leased, Outcome)> = Vec::new();
        match self.routes(domain).await {
            Err(RouteError::Permanent(reason)) => {
                for recipient in by_message.into_values().flatten() {
                    let failure = Failure {
                        recipient: recipient.address.clone(),
                        remote: None,
                        reason: reason.clone(),
                        code: None,
                    };
                    outcomes.push((recipient, Outcome::Failed(failure)));
                }
            }
            Err(RouteError::Temporary(reason)) => {
                outcomes.extend(by_message.into_values().flatten().map(|r| (r, Outcome::Retry(reason.clone()))));
            }
            Ok(hops) => outcomes = self.deliver_over(&hops, by_message).await,
        }
        self.record(outcomes).await;
    }

    /// Opens a session over the first hop that answers and delivers every message through it.
    async fn deliver_over(&self, hops: &[Hop], messages: BTreeMap<uuid::Uuid, Vec<Leased>>) -> Vec<(Leased, Outcome)> {
        let mut last_error = String::from("no mail server could be reached");
        for hop in hops {
            let Some(mut client) = self.open(hop, &mut last_error).await else { continue };
            let mut outcomes = Vec::new();
            let mut broken = false;
            for (id, recipients) in messages {
                if broken {
                    outcomes.extend(recipients.into_iter().map(|r| (r, Outcome::Retry(last_error.clone()))));
                    continue;
                }
                let tenant = recipients[0].tenant;
                let raw = match self.0.mail.outbound_message(tenant, id).await {
                    Ok(raw) => self.signed(raw).await,
                    Err(error) => {
                        let reason = format!("the message could not be read: {error}");
                        outcomes.extend(recipients.into_iter().map(|r| (r, Outcome::Retry(reason.clone()))));
                        continue;
                    }
                };
                match self.send(&mut client, &hop.host, &raw, recipients).await {
                    Ok(results) => outcomes.extend(results),
                    Err((results, error)) => {
                        last_error = error;
                        broken = true;
                        outcomes.extend(results);
                    }
                }
            }
            if !broken {
                client.quit().await;
            }
            return outcomes;
        }
        messages.into_values().flatten().map(|r| (r, Outcome::Retry(last_error.clone()))).collect()
    }

    /// One message over an open session. On a broken connection, the recipients not done yet come back with the
    /// error as `Err`.
    async fn send(
        &self,
        client: &mut Client,
        host: &str,
        raw: &[u8],
        recipients: Vec<Leased>,
    ) -> Result<Vec<(Leased, Outcome)>, (Vec<(Leased, Outcome)>, String)> {
        let failed = |recipient: &Leased, error: &ClientError| -> Outcome {
            if error.is_permanent() {
                let code = match error {
                    ClientError::Reply(response) => Some(response.code),
                    _ => None,
                };
                Outcome::Failed(Failure {
                    recipient: recipient.address.clone(),
                    remote: Some(host.to_owned()),
                    reason: error.to_string(),
                    code,
                })
            } else {
                Outcome::Retry(format!("{host}: {error}"))
            }
        };
        let from = recipients[0].envelope_from.clone();
        let utf8 = !from.is_ascii() || recipients.iter().any(|r| !r.address.is_ascii());
        if let Err(error) = client.mail_from(&from, raw.len(), utf8).await {
            let broken = !matches!(error, ClientError::Reply(_));
            let results = recipients.iter().map(|r| (r.clone(), failed(r, &error))).collect();
            return if broken { Err((results, error.to_string())) } else { self.reset(client, results).await };
        }
        let mut accepted = Vec::new();
        let mut results = Vec::new();
        for recipient in recipients {
            match client.rcpt_to(&recipient.address).await {
                Ok(response) if (200..300).contains(&response.code) => accepted.push(recipient),
                Ok(response) => {
                    let error = ClientError::Reply(response);
                    let outcome = failed(&recipient, &error);
                    results.push((recipient, outcome));
                }
                Err(error) => {
                    let reason = error.to_string();
                    results.extend(accepted.into_iter().map(|r| (r, Outcome::Retry(reason.clone()))));
                    let outcome = Outcome::Retry(format!("{host}: {reason}"));
                    results.push((recipient, outcome));
                    return Err((results, reason));
                }
            }
        }
        if accepted.is_empty() {
            return self.reset(client, results).await;
        }
        match client.data(raw).await {
            Ok(response) if (200..300).contains(&response.code) => {
                results.extend(accepted.into_iter().map(|r| (r, Outcome::Delivered)));
                Ok(results)
            }
            Ok(response) => {
                let error = ClientError::Reply(response);
                results.extend(accepted.iter().map(|r| (r.clone(), failed(r, &error))));
                self.reset(client, results).await
            }
            Err(error) => {
                let reason = error.to_string();
                results.extend(accepted.iter().map(|r| (r.clone(), failed(r, &error))));
                Err((results, reason))
            }
        }
    }

    async fn reset(
        &self,
        client: &mut Client,
        results: Vec<(Leased, Outcome)>,
    ) -> Result<Vec<(Leased, Outcome)>, (Vec<(Leased, Outcome)>, String)> {
        match client.rset().await {
            Ok(()) => Ok(results),
            Err(error) => Err((results, error.to_string())),
        }
    }

    /// A ready session with `hop`: greeted, `EHLO` said, TLS up where it is to be, logged in for the relay.
    async fn open(&self, hop: &Hop, last_error: &mut String) -> Option<Client> {
        for address in &hop.addresses {
            match self.open_at(hop, *address, true).await {
                Ok(client) => return Some(client),
                // A failed handshake for opportunistic TLS: once more in plain text (RFC 7435).
                Err(ClientError::Tls(error)) if matches!(hop.tls, Tls::Opportunistic) && !hop.implicit_tls => {
                    tracing::info!(host = %hop.host, %error, "TLS failed; delivering without");
                    match self.open_at(hop, *address, false).await {
                        Ok(client) => return Some(client),
                        Err(error) => *last_error = format!("{}: {error}", hop.host),
                    }
                }
                Err(error) => *last_error = format!("{}: {error}", hop.host),
            }
        }
        None
    }

    async fn open_at(&self, hop: &Hop, address: SocketAddr, use_tls: bool) -> Result<Client, ClientError> {
        let settings = &self.0.settings;
        let mut client = Client::connect(address, settings.timeout).await?;
        let name = ServerName::try_from(hop.host.clone()).map_err(|error| ClientError::Tls(error.to_string()))?;
        let config = match hop.tls {
            Tls::Verified => client::verified_tls(),
            // DANE checks the certificate itself, after the handshake.
            Tls::Opportunistic | Tls::Dane { .. } => client::unverified_tls(),
        };
        if hop.implicit_tls {
            client = client.into_tls(config.clone(), name.clone()).await?.0;
        }
        client.greeting().await?;
        let mut ehlo = client.ehlo(&settings.hostname).await?;
        if !hop.implicit_tls {
            let offered = ehlo.has_capability(smtp_proto::EXT_START_TLS);
            let required = !matches!(hop.tls, Tls::Opportunistic);
            if offered && (use_tls || required) {
                let (upgraded, certificates) = client.start_tls(config, name).await?;
                if let Tls::Dane { tlsa, names } = &hop.tls {
                    let names: Vec<&str> = names.iter().map(String::as_str).collect();
                    crate::dane::verify(tlsa, &names, &certificates)
                        .map_err(|error| ClientError::Tls(format!("DANE: {error}")))?;
                }
                client = upgraded;
                ehlo = client.ehlo(&settings.hostname).await?;
            } else if required {
                return Err(ClientError::Tls(format!("{} offers no STARTTLS", hop.host)));
            }
        }
        if let Some((username, password)) = &hop.credentials {
            client.auth_plain(username, password).await?;
        }
        let _ = ehlo;
        Ok(client)
    }

    /// Where mail for `domain` goes.
    async fn routes(&self, domain: &str) -> Result<Vec<Hop>, RouteError> {
        let settings = &self.0.settings;
        if let Some(relay) = &settings.relay {
            let addresses = self.addresses(&relay.host, relay.port).await;
            if addresses.is_empty() {
                return Err(RouteError::Temporary(format!("the relay {} has no address", relay.host)));
            }
            return Ok(vec![Hop {
                host: relay.host.clone(),
                addresses,
                implicit_tls: relay.implicit_tls,
                tls: Tls::Verified,
                credentials: relay.credentials.clone(),
            }]);
        }
        let dns = &self.0.dns;
        let hosts: Vec<String> = match dns.authenticator.mx_lookup(domain, Some(&dns.mx)).await {
            Ok(records) if records.rrset.is_empty() => vec![domain.to_owned()],
            Ok(records) => {
                let mut records: Vec<_> = records.rrset.iter().collect();
                records.sort_by_key(|mx| mx.preference);
                let hosts: Vec<String> = records
                    .iter()
                    .flat_map(|mx| mx.exchanges.iter())
                    .map(|host| host.trim_end_matches('.').to_lowercase())
                    .collect();
                // A null MX (RFC 7505): the domain takes no mail.
                if hosts.iter().all(String::is_empty) {
                    return Err(RouteError::Permanent(format!("{domain} accepts no mail (null MX)")));
                }
                hosts.into_iter().filter(|host| !host.is_empty()).collect()
            }
            Err(mail_auth::Error::Dns(mail_auth::DnsError::RecordNotFound(code))) => {
                if code == mail_auth::hickory_resolver::proto::op::ResponseCode::NXDomain {
                    return Err(RouteError::Permanent(format!("the domain {domain} does not exist")));
                }
                // No MX records: the domain itself is the mail server (RFC 5321, 5.1).
                vec![domain.to_owned()]
            }
            Err(error) => return Err(RouteError::Temporary(format!("looking up the MX of {domain}: {error}"))),
        };
        // What the domain publishes about TLS: DANE for signed MX records, else an MTA-STS policy.
        let policy = crate::mta_sts::lookup(dns, self.0.mail.pool(), settings.allow_private_networks, domain).await;
        let dnssec = match &dns.dnssec {
            Some(resolver) if crate::dane::mx_is_secure(resolver, domain).await => Some(resolver),
            _ => None,
        };
        let mut hops = Vec::new();
        let mut refused = None;
        for host in hosts {
            let mut tls = Tls::Opportunistic;
            if let Some(resolver) = dnssec {
                match crate::dane::lookup(resolver, &host, 25).await {
                    crate::dane::TlsaLookup::Secure(tlsa) => {
                        tls = Tls::Dane { tlsa, names: vec![host.clone(), domain.to_owned()] };
                    }
                    crate::dane::TlsaLookup::Unusable(error) => {
                        refused = Some(format!("{host}: TLSA records unusable: {error}"));
                        continue;
                    }
                    crate::dane::TlsaLookup::None => {}
                }
            }
            if matches!(tls, Tls::Opportunistic)
                && let Some(policy) = policy.as_ref().filter(|policy| policy.enforced())
            {
                if !policy.allows(&host) {
                    refused = Some(format!("{host} is not named by the MTA-STS policy of {domain}"));
                    continue;
                }
                tls = Tls::Verified;
            }
            let addresses = self.addresses(&host, settings.port).await;
            if !addresses.is_empty() {
                hops.push(Hop { host, addresses, implicit_tls: false, tls, credentials: None });
            }
        }
        if hops.is_empty() {
            let reason = refused.unwrap_or_else(|| format!("the mail servers of {domain} have no address"));
            return Err(RouteError::Temporary(reason));
        }
        Ok(hops)
    }

    /// The addresses of `host` that may be reached.
    async fn addresses(&self, host: &str, port: u16) -> Vec<SocketAddr> {
        let dns = &self.0.dns;
        let ips: Vec<IpAddr> = match host.parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => dns
                .authenticator
                .ip_lookup(host, IpLookupStrategy::Ipv4thenIpv6, 4, Some(&dns.ipv4), Some(&dns.ipv6))
                .await
                .unwrap_or_default(),
        };
        ips.into_iter()
            .filter(|ip| self.0.settings.allow_private_networks || kernoid_oidc::outbound::is_public(*ip))
            .map(|ip| SocketAddr::new(ip, port))
            .collect()
    }

    /// Writes each recipient's result, bounces what failed, and removes messages that are done.
    async fn record(&self, outcomes: Vec<(Leased, Outcome)>) {
        let mail = &self.0.mail;
        let mut failures: BTreeMap<uuid::Uuid, (Leased, Vec<Failure>)> = BTreeMap::new();
        let mut messages = std::collections::BTreeSet::new();
        for (recipient, outcome) in outcomes {
            // What happened, for whoever runs kernoid: the recipient's domain only, never the address.
            let domain = recipient.address.rsplit_once('@').map_or("", |(_, domain)| domain).to_owned();
            match &outcome {
                Outcome::Delivered => tracing::info!(%domain, message = %recipient.message, "delivered"),
                Outcome::Retry(reason) => {
                    tracing::info!(%domain, message = %recipient.message, attempt = recipient.attempts + 1, %reason, "delivery deferred")
                }
                Outcome::Failed(failure) => {
                    tracing::warn!(%domain, message = %recipient.message, reason = %failure.reason, "delivery failed; bouncing")
                }
            }
            let result = match outcome {
                Outcome::Delivered => mail.outbound_delivered(recipient.message, &recipient.address).await,
                Outcome::Retry(reason) => {
                    let next: DateTime<Utc> = Utc::now() + retry_after(recipient.attempts + 1);
                    if next > recipient.expires_at {
                        let failure = Failure {
                            recipient: recipient.address.clone(),
                            remote: None,
                            reason: format!("gave up after trying for days: {reason}"),
                            code: None,
                        };
                        let result = mail.outbound_failed(recipient.message, &recipient.address, &failure.reason).await;
                        failures
                            .entry(recipient.message)
                            .or_insert_with(|| (recipient.clone(), Vec::new()))
                            .1
                            .push(failure);
                        result
                    } else {
                        mail.outbound_retry(recipient.message, &recipient.address, &reason, next).await
                    }
                }
                Outcome::Failed(failure) => {
                    let result = mail.outbound_failed(recipient.message, &recipient.address, &failure.reason).await;
                    failures
                        .entry(recipient.message)
                        .or_insert_with(|| (recipient.clone(), Vec::new()))
                        .1
                        .push(failure);
                    result
                }
            };
            if let Err(error) = result {
                tracing::warn!(%error, "recording a delivery result");
            }
            messages.insert(recipient.message);
        }
        // Bounces first: they carry the headers of the message, which goes once it is done.
        for (message, (leased, failed)) in failures {
            if let Err(error) = self.bounce(message, &leased, &failed).await {
                tracing::warn!(%error, "sending a bounce");
            }
        }
        for message in messages {
            if let Err(error) = mail.outbound_finish(message).await {
                tracing::warn!(%error, "removing a delivered message");
            }
        }
    }

    /// Tells the sender which recipients failed – in their inbox if the sender is local, else through the queue.
    async fn bounce(
        &self,
        message: uuid::Uuid,
        leased: &Leased,
        failures: &[Failure],
    ) -> Result<(), kernoid_mail::MailError> {
        let sender = leased.envelope_from.as_str();
        if sender.is_empty() {
            return Ok(());
        }
        let mail = &self.0.mail;
        let original = mail.outbound_message(leased.tenant, message).await.unwrap_or_default();
        let bounce = bytes::Bytes::from(dsn::bounce(&self.0.settings.hostname, sender, &original, failures));
        match mail.resolve_recipient(sender).await? {
            Recipient::Account { account, .. } => {
                mail.deliver(account, bounce, Delivery { from: "", to: sender, junk: false }).await?;
            }
            Recipient::NotLocal => {
                mail.enqueue(Outgoing {
                    tenant: leased.tenant,
                    account: None,
                    from: "",
                    recipients: &[sender.to_owned()],
                    raw: bounce,
                    lifetime: chrono::Duration::days(5),
                })
                .await?;
            }
            // A bounce of a bounce to an SRS address is not sent on: bounces are never bounced.
            Recipient::Group { .. } | Recipient::Disabled | Recipient::Unknown | Recipient::Forwarded { .. } => {
                tracing::info!(%sender, "a bounce has no one to go to");
            }
        }
        Ok(())
    }
}
