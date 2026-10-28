// SPDX-License-Identifier: AGPL-3.0-or-later
//! Requests kernoid makes to identity providers. Their addresses come from tenant administrators, so unless the
//! installation allows it (`outbound.allow_private_networks`) only HTTPS to public addresses goes out – checked for the
//! URL, for every address DNS gives (so that a name cannot point inside), and for every redirect. Without this, an
//! administrator could make kernoid read services inside the installation's network (server-side request forgery,
//! see the OWASP SSRF Prevention Cheat Sheet).

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use reqwest::{
    Client,
    dns::{Addrs, Name, Resolve, Resolving},
    redirect,
};
use url::Url;

/// How long one request to an identity provider may take.
const TIMEOUT: Duration = Duration::from_secs(10);
/// Largest answer read from an identity provider.
pub(crate) const MAX_BODY: usize = 512 * 1024;

/// Whether an address is reachable on the public internet – not private, loopback, link-local, shared, reserved,
/// documentation or multicast.
pub fn is_public(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => public_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => public_v4(v4),
            None => public_v6(v6),
        },
    }
}

fn public_v4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_broadcast()
        || address.is_multicast()
        || address.is_documentation()
        || a == 0
        || (a == 100 && (64..128).contains(&b)) // shared address space, RFC 6598
        || (a == 192 && b == 0 && c == 0) // IETF protocol assignments, RFC 6890
        || (a == 198 && (18..20).contains(&b)) // benchmarking, RFC 2544
        || a >= 240)
}

fn public_v6(address: Ipv6Addr) -> bool {
    let first = address.segments()[0];
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || (first & 0xfe00) == 0xfc00 // unique local, RFC 4193
        || (first & 0xffc0) == 0xfe80 // link-local
        || (first == 0x2001 && address.segments()[1] == 0x0db8) // documentation, RFC 3849
        || first == 0x0064) // NAT64 with an embedded address, RFC 6052
}

/// Refuses a URL kernoid may not request.
pub fn check_url(url: &Url, allow_private: bool) -> Result<(), String> {
    if allow_private {
        return match url.scheme() {
            "https" | "http" => Ok(()),
            scheme => Err(format!("{scheme} is not HTTP")),
        };
    }
    if url.scheme() != "https" {
        return Err(format!("{url} is not HTTPS"));
    }
    match url.host() {
        Some(url::Host::Ipv4(v4)) if !is_public(IpAddr::V4(v4)) => Err(format!("{url} is not a public address")),
        Some(url::Host::Ipv6(v6)) if !is_public(IpAddr::V6(v6)) => Err(format!("{url} is not a public address")),
        Some(url::Host::Domain(domain))
            if domain.eq_ignore_ascii_case("localhost") || domain.ends_with(".localhost") =>
        {
            Err(format!("{url} is not a public address"))
        }
        None => Err(format!("{url} has no host")),
        _ => Ok(()),
    }
}

/// Resolves names, but keeps only public addresses.
struct PublicResolver;

impl Resolve for PublicResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let found = tokio::net::lookup_host((name.as_str(), 0)).await?;
            let public: Vec<SocketAddr> = found.filter(|address| is_public(address.ip())).collect();
            if public.is_empty() {
                return Err(format!("{} resolves to no public address", name.as_str()).into());
            }
            Ok(Box::new(public.into_iter()) as Addrs)
        })
    }
}

/// The client for identity providers.
pub fn client(allow_private: bool) -> Client {
    let redirects = redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= 3 {
            attempt.error("too many redirects")
        } else if let Err(error) = check_url(attempt.url(), allow_private) {
            attempt.error(error)
        } else {
            attempt.follow()
        }
    });
    build(allow_private, redirects)
}

/// The same, but it follows no redirect – for what must not be redirected, such as MTA-STS policies (RFC 8461, 3.3).
pub fn client_without_redirects(allow_private: bool) -> Client {
    build(allow_private, redirect::Policy::none())
}

fn build(allow_private: bool, redirects: redirect::Policy) -> Client {
    let mut builder = Client::builder()
        .timeout(TIMEOUT)
        .connect_timeout(Duration::from_secs(5))
        .redirect(redirects)
        .user_agent(concat!("kernoid/", env!("CARGO_PKG_VERSION")));
    if !allow_private {
        builder = builder.dns_resolver(Arc::new(PublicResolver)).https_only(true);
    }
    builder.build().expect("the client's settings are valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_public_addresses_count() {
        for private in [
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
            "2001:db8::1",
        ] {
            assert!(!is_public(private.parse().unwrap()), "{private}");
        }
        for public in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"] {
            assert!(is_public(public.parse().unwrap()), "{public}");
        }
    }

    #[test]
    fn urls_must_be_https_and_public() {
        let check = |url: &str, allow| check_url(&Url::parse(url).unwrap(), allow);
        assert!(check("https://login.example.org/x", false).is_ok());
        assert!(check("http://login.example.org/x", false).is_err());
        assert!(check("https://127.0.0.1/", false).is_err());
        assert!(check("https://[::1]/", false).is_err());
        assert!(check("https://169.254.169.254/latest/meta-data", false).is_err());
        assert!(check("https://keycloak.localhost/", false).is_err());
        assert!(check("http://keycloak.internal:8080/", true).is_ok());
        assert!(check("file:///etc/passwd", true).is_err());
    }
}
