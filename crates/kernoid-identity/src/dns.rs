// SPDX-License-Identifier: AGPL-3.0-or-later
//! TXT lookups for domain verification.

use std::future::Future;

use hickory_resolver::{TokioResolver, proto::rr::RData};

/// Looks up TXT records; each record's strings are joined into one value.
pub trait TxtLookup: Send + Sync {
    fn txt(&self, name: &str) -> impl Future<Output = Result<Vec<String>, String>> + Send;
}

/// The system's DNS resolver.
#[derive(Debug, Clone)]
pub struct DnsResolver(TokioResolver);

impl DnsResolver {
    pub fn from_system() -> Result<Self, String> {
        let builder = TokioResolver::builder_tokio().map_err(|error| error.to_string())?;
        Ok(Self(builder.build().map_err(|error| error.to_string())?))
    }
}

impl TxtLookup for DnsResolver {
    async fn txt(&self, name: &str) -> Result<Vec<String>, String> {
        let lookup = self.0.txt_lookup(name).await.map_err(|error| format!("{name}: {error}"))?;
        Ok(lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::TXT(txt) => {
                    Some(txt.txt_data.iter().map(|part| String::from_utf8_lossy(part).into_owned()).collect())
                }
                _ => None,
            })
            .collect())
    }
}
