// SPDX-License-Identifier: AGPL-3.0-or-later
//! Who is asking: the client's address, the host it asked for and whether it came over HTTPS.
//!
//! Behind a reverse proxy, these come from `Forwarded` (RFC 7239) or `X-Forwarded-For/-Host/-Proto` – but only if
//! the connection comes from a configured trusted proxy. Anyone else could send such headers to pick the host
//! kernoid serves (and thereby the tenant) or the address it logs; ZITADEL had several vulnerabilities of that kind.

use std::net::{IpAddr, SocketAddr};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, header},
    middleware::Next,
    response::Response,
};
use ipnet::IpNet;

/// Added to every request as an extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    pub address: IpAddr,
    /// The host asked for, without port; None if the request named none.
    pub host: Option<String>,
    pub https: bool,
}

/// How this listener is reached.
#[derive(Debug, Clone)]
pub struct Listener {
    pub trusted_proxies: Vec<IpNet>,
    pub tls: bool,
}

pub async fn layer(State(listener): State<Listener>, mut request: Request, next: Next) -> Response {
    let peer = request.extensions().get::<ConnectInfo<SocketAddr>>().map(|info| info.0.ip());
    let client = resolve(peer, request.headers(), &listener);
    request.extensions_mut().insert(client);
    next.run(request).await
}

fn trusted(address: IpAddr, proxies: &[IpNet]) -> bool {
    proxies.iter().any(|net| net.contains(&address))
}

/// Without a known peer (in tests) nothing is trusted.
pub fn resolve(peer: Option<IpAddr>, headers: &HeaderMap, listener: &Listener) -> Client {
    let own_host = headers.get(header::HOST).and_then(|value| value.to_str().ok()).map(strip_port);
    let direct = Client { address: peer.unwrap_or(IpAddr::from([0, 0, 0, 0])), host: own_host, https: listener.tls };
    let Some(peer) = peer.filter(|peer| trusted(*peer, &listener.trusted_proxies)) else {
        return direct;
    };
    let hops = forwarded_hops(headers);
    if hops.is_empty() {
        return Client { address: peer, ..direct };
    }
    // The chain is client, proxy 1, …; read from the end, skip our own proxies, the first other one is the client.
    let address = hops
        .iter()
        .rev()
        .filter_map(|hop| hop.address)
        .find(|address| !trusted(*address, &listener.trusted_proxies))
        .or_else(|| hops.first().and_then(|hop| hop.address))
        .unwrap_or(peer);
    // Host and scheme as the proxy next to us saw them.
    let last = hops.last().expect("not empty");
    Client {
        address,
        host: last.host.clone().map(|host| strip_port(&host)).or(direct.host),
        https: last.https.unwrap_or(direct.https),
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Hop {
    address: Option<IpAddr>,
    host: Option<String>,
    https: Option<bool>,
}

/// The hops of `Forwarded` if present, else of `X-Forwarded-*` (host and scheme belong to the last hop).
fn forwarded_hops(headers: &HeaderMap) -> Vec<Hop> {
    let values = |name: &str| -> Vec<String> {
        headers.get_all(name).iter().filter_map(|value| value.to_str().ok()).map(str::to_owned).collect()
    };
    let forwarded = values("forwarded");
    if !forwarded.is_empty() {
        return forwarded
            .iter()
            .flat_map(|value| value.split(','))
            .map(|element| {
                let mut hop = Hop::default();
                for pair in element.split(';') {
                    let Some((key, value)) = pair.trim().split_once('=') else { continue };
                    let value = value.trim().trim_matches('"');
                    match key.trim().to_ascii_lowercase().as_str() {
                        "for" => hop.address = parse_address(value),
                        "host" => hop.host = Some(value.to_owned()),
                        "proto" => hop.https = Some(value.eq_ignore_ascii_case("https")),
                        _ => {}
                    }
                }
                hop
            })
            .collect();
    }
    let mut hops: Vec<Hop> = values("x-forwarded-for")
        .iter()
        .flat_map(|value| value.split(','))
        .map(|address| Hop { address: parse_address(address.trim()), ..Hop::default() })
        .collect();
    let last_value = |name: &str| values(name).last().and_then(|v| v.rsplit(',').next().map(|v| v.trim().to_owned()));
    let host = last_value("x-forwarded-host");
    let https = last_value("x-forwarded-proto").map(|proto| proto.eq_ignore_ascii_case("https"));
    if hops.is_empty() && (host.is_some() || https.is_some()) {
        hops.push(Hop::default());
    }
    if let Some(last) = hops.last_mut() {
        last.host = host;
        last.https = https;
    }
    hops
}

/// `192.0.2.1`, `192.0.2.1:4711`, `[2001:db8::1]`, `[2001:db8::1]:4711`; obfuscated identifiers yield None.
fn parse_address(value: &str) -> Option<IpAddr> {
    value
        .parse::<IpAddr>()
        .ok()
        .or_else(|| value.parse::<SocketAddr>().ok().map(|socket| socket.ip()))
        .or_else(|| value.strip_prefix('[').and_then(|v| v.strip_suffix(']')).and_then(|v| v.parse().ok()))
}

fn strip_port(host: &str) -> String {
    let host = host.trim().to_ascii_lowercase();
    match host.rsplit_once(':') {
        // An IPv6 literal keeps its colons; a port follows the closing bracket.
        Some((name, port)) if !name.contains(':') || name.ends_with(']') => {
            if port.chars().all(|c| c.is_ascii_digit()) { name.to_owned() } else { host }
        }
        _ => host,
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    fn listener(trusted: &[&str]) -> Listener {
        Listener { trusted_proxies: trusted.iter().map(|net| net.parse().unwrap()).collect(), tls: false }
    }

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn headers_of_untrusted_peers_are_ignored() {
        let forged = headers(&[
            ("host", "mail.example.org:8080"),
            ("x-forwarded-for", "203.0.113.9"),
            ("x-forwarded-host", "victim.example"),
            ("x-forwarded-proto", "https"),
            ("forwarded", "for=203.0.113.9;host=victim.example;proto=https"),
        ]);
        let client = resolve(Some(ip("198.51.100.7")), &forged, &listener(&["10.0.0.0/8"]));
        assert_eq!(client, Client { address: ip("198.51.100.7"), host: Some("mail.example.org".into()), https: false });
        // Without a known peer nothing is trusted either.
        assert_eq!(resolve(None, &forged, &listener(&["0.0.0.0/0"])).host.as_deref(), Some("mail.example.org"));
    }

    #[test]
    fn trusted_proxies_are_believed() {
        let via_proxy = headers(&[
            ("host", "kernoid:8080"),
            ("x-forwarded-for", "203.0.113.9, 10.0.0.2"),
            ("x-forwarded-host", "Mail.Example.org"),
            ("x-forwarded-proto", "https"),
        ]);
        let client = resolve(Some(ip("10.0.0.1")), &via_proxy, &listener(&["10.0.0.0/8"]));
        assert_eq!(client, Client { address: ip("203.0.113.9"), host: Some("mail.example.org".into()), https: true });
    }

    #[test]
    fn a_client_cannot_hide_behind_a_forged_first_hop() {
        // The client sent "X-Forwarded-For: 192.0.2.66" itself; the proxy appended the real address.
        let chain = headers(&[("x-forwarded-for", "192.0.2.66, 203.0.113.9")]);
        let client = resolve(Some(ip("10.0.0.1")), &chain, &listener(&["10.0.0.0/8"]));
        assert_eq!(client.address, ip("203.0.113.9"));
    }

    #[test]
    fn forwarded_header_wins_over_x_forwarded() {
        let both = headers(&[
            ("forwarded", "for=\"[2001:db8::7]:4711\";proto=https;host=mail.example.org"),
            ("x-forwarded-host", "other.example"),
        ]);
        let client = resolve(Some(ip("::1")), &both, &listener(&["::1/128"]));
        assert_eq!(client, Client { address: ip("2001:db8::7"), host: Some("mail.example.org".into()), https: true });
    }

    #[test]
    fn hosts_lose_their_port() {
        assert_eq!(strip_port("Mail.Example.org:443"), "mail.example.org");
        assert_eq!(strip_port("[2001:db8::1]:443"), "[2001:db8::1]");
        assert_eq!(strip_port("2001:db8::1"), "2001:db8::1");
    }
}
