// SPDX-License-Identifier: MIT
//! Finding the JMAP server of a domain through DNS (RFC 8620, 2.2): the SRV records `_jmap._tcp.<domain>`, asked of
//! the system's name servers (`/etc/resolv.conf`) over UDP – over TCP when the answer was cut. Messages are written
//! and read by hickory-proto; no own DNS parsing.

use std::{
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpStream, UdpSocket},
    time::Duration,
};

use hickory_proto::{
    op::{Message, Query},
    rr::{Name, RData, RecordType},
};

/// A server an SRV record names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub priority: u16,
    pub weight: u16,
}

impl Target {
    /// Where its session is: `https://host[:port]/.well-known/jmap`.
    pub fn session_url(&self) -> String {
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        if self.port == 443 {
            format!("https://{host}/.well-known/jmap")
        } else {
            format!("https://{host}:{}/.well-known/jmap", self.port)
        }
    }
}

/// The name servers of `/etc/resolv.conf`'s text.
pub fn name_servers(resolv_conf: &str) -> Vec<IpAddr> {
    resolv_conf
        .lines()
        .filter_map(|line| line.trim().strip_prefix("nameserver"))
        .filter_map(|rest| rest.split_whitespace().next())
        .filter_map(|address| address.split('%').next()?.parse().ok())
        .collect()
}

/// The question for `_jmap._tcp.<domain>`.
pub fn query(domain: &str, id: u16) -> Result<Vec<u8>, String> {
    let name = Name::from_ascii(format!("_jmap._tcp.{}.", domain.trim_end_matches('.'))).map_err(|e| e.to_string())?;
    let mut message = Message::query();
    message.metadata.id = id;
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name, RecordType::SRV));
    message.to_vec().map_err(|e| e.to_string())
}

/// The targets of an answer, in the order to try them: by priority, then the heavier first (RFC 2782 without the
/// random pick – there is one client). `None` if it was cut and needs TCP; `.` as target means no service.
pub fn targets(answer: &[u8], id: u16) -> Result<Option<Vec<Target>>, String> {
    let message = Message::from_vec(answer).map_err(|e| e.to_string())?;
    if message.metadata.id != id {
        return Err("an answer to another question".into());
    }
    if message.metadata.truncation {
        return Ok(None);
    }
    let mut out: Vec<Target> = message
        .answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::SRV(srv) => Some(Target {
                host: srv.target.to_utf8().trim_end_matches('.').to_owned(),
                port: srv.port,
                priority: srv.priority,
                weight: srv.weight,
            }),
            _ => None,
        })
        .filter(|target| !target.host.is_empty())
        .collect();
    out.sort_by_key(|target| (target.priority, std::cmp::Reverse(target.weight)));
    Ok(Some(out))
}

fn ask(server: IpAddr, question: &[u8], id: u16) -> Result<Vec<Target>, String> {
    let address = SocketAddr::new(server, 53);
    let bind: SocketAddr = if server.is_ipv4() { ([0, 0, 0, 0], 0).into() } else { ([0u16; 8], 0).into() };
    let socket = UdpSocket::bind(bind).map_err(|e| e.to_string())?;
    socket.set_read_timeout(Some(Duration::from_secs(3))).map_err(|e| e.to_string())?;
    socket.send_to(question, address).map_err(|e| e.to_string())?;
    let mut buffer = vec![0; 4096];
    let (read, from) = socket.recv_from(&mut buffer).map_err(|e| e.to_string())?;
    if from != address {
        return Err("an answer from elsewhere".into());
    }
    if let Some(targets) = targets(&buffer[..read], id)? {
        return Ok(targets);
    }
    // Cut: once more over TCP, with the length before each message (RFC 1035, 4.2.2).
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(3)).map_err(|e| e.to_string())?;
    stream.set_read_timeout(Some(Duration::from_secs(3))).map_err(|e| e.to_string())?;
    let length = u16::try_from(question.len()).map_err(|e| e.to_string())?;
    stream.write_all(&length.to_be_bytes()).and_then(|()| stream.write_all(question)).map_err(|e| e.to_string())?;
    let mut length = [0; 2];
    stream.read_exact(&mut length).map_err(|e| e.to_string())?;
    let mut answer = vec![0; u16::from_be_bytes(length) as usize];
    stream.read_exact(&mut answer).map_err(|e| e.to_string())?;
    targets(&answer, id)?.ok_or_else(|| "the answer was cut over TCP too".into())
}

/// The JMAP servers of a domain, best first; empty if it names none.
pub fn lookup(domain: &str) -> Result<Vec<Target>, String> {
    let servers = name_servers(&std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default());
    if servers.is_empty() {
        return Err("no name server in /etc/resolv.conf".into());
    }
    let id = u16::try_from(std::process::id() % 65_536).unwrap_or(1) ^ 0x5a5a;
    let question = query(domain, id)?;
    let mut last = String::new();
    for server in servers {
        match ask(server, &question, id) {
            Ok(targets) => return Ok(targets),
            Err(error) => last = error,
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use hickory_proto::rr::{Record, rdata::SRV};

    use super::*;

    #[test]
    fn resolv_conf() {
        let text = "# x\nnameserver 192.0.2.1\nnameserver fe80::1%en0\nsearch example\nnameserver nonsense\n";
        let servers = name_servers(text);
        assert_eq!(servers, ["192.0.2.1".parse::<IpAddr>().unwrap(), "fe80::1".parse().unwrap()]);
    }

    #[test]
    fn questions_and_answers() {
        let question = query("firma.example", 7).unwrap();
        let mut answer = Message::from_vec(&question).unwrap();
        assert_eq!(answer.queries[0].name().to_utf8(), "_jmap._tcp.firma.example.");
        answer.metadata.message_type = hickory_proto::op::MessageType::Response;
        let name = Name::from_ascii("_jmap._tcp.firma.example.").unwrap();
        for (priority, weight, host) in
            [(20, 0, "b.firma.example."), (10, 1, "a.firma.example."), (10, 5, "c.firma.example.")]
        {
            let srv = SRV::new(priority, weight, 8443, Name::from_ascii(host).unwrap());
            answer.answers.push(Record::from_rdata(name.clone(), 300, RData::SRV(srv)));
        }
        let found = targets(&answer.to_vec().unwrap(), 7).unwrap().unwrap();
        let hosts: Vec<_> = found.iter().map(|t| t.host.as_str()).collect();
        assert_eq!(hosts, ["c.firma.example", "a.firma.example", "b.firma.example"]);
        assert_eq!(found[0].session_url(), "https://c.firma.example:8443/.well-known/jmap");
        assert!(targets(&answer.to_vec().unwrap(), 8).is_err());
        answer.metadata.truncation = true;
        assert_eq!(targets(&answer.to_vec().unwrap(), 7).unwrap(), None);
    }

    /// Asks the real DNS: `cargo test -- --ignored srv` (needs the network).
    #[test]
    #[ignore = "needs the network"]
    fn live() {
        let found = lookup("fastmail.com").unwrap();
        assert!(!found.is_empty(), "fastmail.com publishes _jmap._tcp");
        println!("{found:?}");
    }
}
