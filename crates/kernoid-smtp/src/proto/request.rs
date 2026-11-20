// SPDX-License-Identifier: AGPL-3.0-or-later
//! Commands as the server reads them (RFC 5321, 4.1): a line up to its line end, the verb in any case, the arguments
//! of each command. `MAIL` and `RCPT` take the paths of RFC 5321, 4.1.2 – a source route is accepted and dropped –
//! and the parameters of the extensions kernoid offers: `SIZE` (RFC 1870), `BODY` (RFC 6152, 3030), `SMTPUTF8` (RFC
//! 6531), `RET`/`ENVID`/`NOTIFY`/`ORCPT` (RFC 3461) and `AUTH` (RFC 4954); any other parameter is refused, as RFC
//! 5321, 4.1.1.11 asks.

/// The longest command line taken, its line end included: RFC 5321, 4.5.3.1.4 allows 512 octets, extensions with
/// parameters more (RFC 1869, 4.1.2 adds room for each); this leaves room for all of them and a long `AUTH` line.
pub const MAX_LINE: usize = 4096;

/// The longest path (RFC 5321, 4.5.3.1.3).
const MAX_PATH: usize = 256;

/// SASL mechanisms (RFC 4954), as bits.
pub const AUTH_PLAIN: u64 = 1 << 0;
pub const AUTH_LOGIN: u64 = 1 << 1;
pub const AUTH_OAUTHBEARER: u64 = 1 << 2;
pub const AUTH_XOAUTH2: u64 = 1 << 3;
/// Any mechanism kernoid does not know.
pub const AUTH_OTHER: u64 = 1 << 63;

/// The bit of a mechanism's name.
pub fn mechanism(name: &str) -> u64 {
    match name.to_ascii_uppercase().as_str() {
        "PLAIN" => AUTH_PLAIN,
        "LOGIN" => AUTH_LOGIN,
        "OAUTHBEARER" => AUTH_OAUTHBEARER,
        "XOAUTH2" => AUTH_XOAUTH2,
        _ => AUTH_OTHER,
    }
}

/// The body of a message (`BODY=`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Body {
    #[default]
    SevenBit,
    EightBitMime,
    BinaryMime,
}

/// `MAIL FROM` with its parameters.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MailFrom {
    /// The address without its brackets; empty for the null reverse-path.
    pub address: String,
    /// `SIZE=`, 0 when not given.
    pub size: usize,
    pub body: Body,
    pub smtputf8: bool,
    /// `RET=HDRS` (RFC 3461): bounces carry only the headers.
    pub ret_headers: bool,
    pub envid: Option<String>,
    /// `AUTH=` (RFC 4954, 5).
    pub auth: Option<String>,
}

/// `RCPT TO` with its parameters.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RcptTo {
    pub address: String,
    /// `NOTIFY=` (RFC 3461), as given.
    pub notify: Option<String>,
    pub orcpt: Option<String>,
}

/// A command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Ehlo { host: String },
    Helo { host: String },
    Lhlo { host: String },
    Mail { from: MailFrom },
    Rcpt { to: RcptTo },
    Data,
    Bdat { chunk_size: usize, is_last: bool },
    Auth { mechanism: u64, initial_response: String },
    StartTls,
    Rset,
    Noop,
    Quit,
    Vrfy { value: String },
    Expn { value: String },
    Help { value: String },
    Etrn,
    Atrn,
    Burl,
}

/// Why a command was not taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The line is not complete yet.
    NeedsMoreData,
    UnknownCommand,
    InvalidSenderAddress,
    InvalidRecipientAddress,
    /// The command's arguments are wrong; `syntax` says what was expected.
    SyntaxError {
        syntax: &'static str,
    },
    InvalidParameter {
        param: &'static str,
    },
    UnsupportedParameter {
        param: String,
    },
    /// The line was longer than [`MAX_LINE`]; it was read to its end and dropped.
    LineTooLong,
}

/// Gathers a command line from what arrives, in as many pieces as it comes.
#[derive(Debug, Default)]
pub struct RequestReceiver {
    line: Vec<u8>,
    /// The line went past the limit: what is left of it is dropped.
    too_long: bool,
}

impl RequestReceiver {
    /// Takes bytes from `input` up to the end of a line and parses it; `NeedsMoreData` when `input` ran out first.
    /// Bytes after the line stay in `input`.
    pub fn ingest(&mut self, input: &mut &[u8]) -> Result<Request, Error> {
        let data: &[u8] = input;
        let (taken, complete) = match data.iter().position(|byte| *byte == b'\n') {
            Some(end) => (&data[..=end], true),
            None => (data, false),
        };
        *input = &data[taken.len()..];
        if !self.too_long {
            if self.line.len() + taken.len() > MAX_LINE {
                self.too_long = true;
                self.line = Vec::new();
            } else {
                self.line.extend_from_slice(taken);
            }
        }
        if !complete {
            return Err(Error::NeedsMoreData);
        }
        if std::mem::take(&mut self.too_long) {
            return Err(Error::LineTooLong);
        }
        let line = std::mem::take(&mut self.line);
        parse(&line)
    }
}

/// Parses one command line, its line end included or not.
pub fn parse(line: &[u8]) -> Result<Request, Error> {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    // Commands are ASCII, addresses may be UTF-8 (RFC 6531); nothing else is taken.
    let Ok(line) = std::str::from_utf8(line) else { return Err(Error::UnknownCommand) };
    if line.chars().any(|c| c.is_control() && c != '\t') {
        return Err(Error::UnknownCommand);
    }
    let (verb, rest) = match line.find([' ', '\t']) {
        Some(space) => (&line[..space], line[space + 1..].trim_matches([' ', '\t'])),
        None => (line, ""),
    };
    let no_arguments = |request: Request, syntax: &'static str| {
        if rest.is_empty() { Ok(request) } else { Err(Error::SyntaxError { syntax }) }
    };
    match verb.to_ascii_uppercase().as_str() {
        "EHLO" => hello(rest, "EHLO domain").map(|host| Request::Ehlo { host }),
        "HELO" => hello(rest, "HELO domain").map(|host| Request::Helo { host }),
        "LHLO" => hello(rest, "LHLO domain").map(|host| Request::Lhlo { host }),
        "MAIL" => mail(rest),
        "RCPT" => rcpt(rest),
        "DATA" => no_arguments(Request::Data, "DATA"),
        "BDAT" => bdat(rest),
        "AUTH" => auth(rest),
        "STARTTLS" => no_arguments(Request::StartTls, "STARTTLS"),
        "RSET" => no_arguments(Request::Rset, "RSET"),
        "NOOP" => Ok(Request::Noop),
        "QUIT" => no_arguments(Request::Quit, "QUIT"),
        "VRFY" if !rest.is_empty() => Ok(Request::Vrfy { value: rest.to_owned() }),
        "VRFY" => Err(Error::SyntaxError { syntax: "VRFY string" }),
        "EXPN" if !rest.is_empty() => Ok(Request::Expn { value: rest.to_owned() }),
        "EXPN" => Err(Error::SyntaxError { syntax: "EXPN string" }),
        "HELP" => Ok(Request::Help { value: rest.to_owned() }),
        "ETRN" => Ok(Request::Etrn),
        "ATRN" => Ok(Request::Atrn),
        "BURL" => Ok(Request::Burl),
        _ => Err(Error::UnknownCommand),
    }
}

/// The name in `EHLO`/`HELO`: a domain or an address literal, one word (RFC 5321, 4.1.1.1).
fn hello(rest: &str, syntax: &'static str) -> Result<String, Error> {
    let mut words = rest.split_ascii_whitespace();
    let (Some(host), None) = (words.next(), words.next()) else { return Err(Error::SyntaxError { syntax }) };
    let literal = host.starts_with('[') && host.ends_with(']') && host.len() > 2;
    let domain = host.trim_end_matches('.').split('.').all(|label| {
        !label.is_empty() && label.len() <= 63 && label.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    });
    if host.len() > 255 || !(literal || domain) {
        return Err(Error::SyntaxError { syntax });
    }
    Ok(host.to_owned())
}

/// `FROM:` or `TO:` in any case, a space after the colon tolerated; the path and the parameters after it.
fn after_keyword<'a>(rest: &'a str, keyword: &str) -> Option<&'a str> {
    let head = rest.get(..keyword.len())?;
    head.eq_ignore_ascii_case(keyword).then(|| rest[keyword.len()..].trim_start_matches([' ', '\t']))
}

/// A path in angle brackets (RFC 5321, 4.1.2), and what follows it. The address comes back without a source route.
fn path(input: &str) -> Option<(String, &str)> {
    let inner = input.strip_prefix('<')?;
    // The closing bracket, outside a quoted local part.
    let mut quoted = false;
    let mut escaped = false;
    let mut end = None;
    for (index, c) in inner.char_indices() {
        if escaped {
            escaped = false;
        } else if quoted && c == '\\' {
            escaped = true;
        } else if c == '"' {
            quoted = !quoted;
        } else if c == '>' && !quoted {
            end = Some(index);
            break;
        }
    }
    let end = end?;
    let (mut address, rest) = (&inner[..end], &inner[end + 1..]);
    if !rest.is_empty() && !rest.starts_with([' ', '\t']) {
        return None;
    }
    // A source route, `@a,@b:` (RFC 5321, 4.1.2), is accepted and ignored.
    if address.starts_with('@') {
        let colon = address.find(':')?;
        let route = &address[..colon];
        if !route.split(',').all(|hop| hop.len() > 1 && hop.starts_with('@')) {
            return None;
        }
        address = &address[colon + 1..];
    }
    if address.len() > MAX_PATH || !mailbox(address) {
        return None;
    }
    Some((address.to_owned(), rest.trim_start_matches([' ', '\t'])))
}

/// Whether `address` is empty or a mailbox: a local part (dot-string or quoted string, UTF-8 allowed, RFC 6531), `@`
/// and a domain or address literal – or `postmaster` alone (RFC 5321, 4.1.1.3).
fn mailbox(address: &str) -> bool {
    if address.is_empty() || address.eq_ignore_ascii_case("postmaster") {
        return true;
    }
    let Some(at) = address.rfind('@') else { return false };
    let (local, domain) = (&address[..at], &address[at + 1..]);
    let local_ok = if local.starts_with('"') {
        local.len() >= 2 && local.ends_with('"') && local.chars().all(|c| c == ' ' || !c.is_whitespace())
    } else {
        !local.is_empty()
            && !local.starts_with('.')
            && !local.ends_with('.')
            && !local.contains("..")
            && local.chars().all(|c| {
                !c.is_whitespace()
                    && !matches!(c, '<' | '>' | '(' | ')' | ',' | ';' | ':' | '"' | '[' | ']' | '\\' | '@')
            })
    };
    let domain_ok = if domain.starts_with('[') {
        domain.ends_with(']') && domain.len() > 2
    } else {
        !domain.is_empty()
            && domain
                .trim_end_matches('.')
                .split('.')
                .all(|label| !label.is_empty() && label.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_'))
    };
    local_ok && domain_ok
}

/// The parameters after a path: `keyword[=value]`, separated by spaces (RFC 5321, 4.1.2).
fn parameters(input: &str) -> Result<Vec<(String, Option<&str>)>, Error> {
    let mut parameters = Vec::new();
    for parameter in input.split_ascii_whitespace() {
        let (keyword, value) = match parameter.split_once('=') {
            Some((keyword, value)) => (keyword, Some(value)),
            None => (parameter, None),
        };
        let keyword_ok = keyword.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
            && keyword.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
        if !keyword_ok || value.is_some_and(|value| value.is_empty()) {
            return Err(Error::SyntaxError { syntax: "parameter keyword[=value]" });
        }
        parameters.push((keyword.to_ascii_uppercase(), value));
    }
    Ok(parameters)
}

fn mail(rest: &str) -> Result<Request, Error> {
    let Some(rest) = after_keyword(rest, "FROM:") else {
        return Err(Error::SyntaxError { syntax: "MAIL FROM:<address>" });
    };
    let Some((address, rest)) = path(rest) else { return Err(Error::InvalidSenderAddress) };
    if address.eq_ignore_ascii_case("postmaster") {
        return Err(Error::InvalidSenderAddress);
    }
    let mut from = MailFrom { address, ..MailFrom::default() };
    for (keyword, value) in parameters(rest)? {
        match (keyword.as_str(), value) {
            ("SIZE", Some(value)) => {
                from.size = value
                    .parse::<u64>()
                    .ok()
                    .filter(|_| value.len() <= 20)
                    .map(|size| usize::try_from(size).unwrap_or(usize::MAX))
                    .ok_or(Error::InvalidParameter { param: "SIZE" })?;
            }
            ("BODY", Some(value)) => {
                from.body = match value.to_ascii_uppercase().as_str() {
                    "7BIT" => Body::SevenBit,
                    "8BITMIME" => Body::EightBitMime,
                    "BINARYMIME" => Body::BinaryMime,
                    _ => return Err(Error::InvalidParameter { param: "BODY" }),
                };
            }
            ("SMTPUTF8", None) => from.smtputf8 = true,
            ("RET", Some(value)) => {
                from.ret_headers = match value.to_ascii_uppercase().as_str() {
                    "HDRS" => true,
                    "FULL" => false,
                    _ => return Err(Error::InvalidParameter { param: "RET" }),
                };
            }
            ("ENVID", Some(value)) if value.len() <= 100 => from.envid = Some(value.to_owned()),
            ("ENVID", _) => return Err(Error::InvalidParameter { param: "ENVID" }),
            ("AUTH", Some(value)) => from.auth = Some(value.to_owned()),
            ("SIZE" | "BODY" | "RET" | "AUTH", None) => {
                return Err(Error::SyntaxError { syntax: "parameter keyword=value" });
            }
            _ => return Err(Error::UnsupportedParameter { param: keyword }),
        }
    }
    Ok(Request::Mail { from })
}

fn rcpt(rest: &str) -> Result<Request, Error> {
    let Some(rest) = after_keyword(rest, "TO:") else {
        return Err(Error::SyntaxError { syntax: "RCPT TO:<address>" });
    };
    let Some((address, rest)) = path(rest).filter(|(address, _)| !address.is_empty()) else {
        return Err(Error::InvalidRecipientAddress);
    };
    let mut to = RcptTo { address, ..RcptTo::default() };
    for (keyword, value) in parameters(rest)? {
        match (keyword.as_str(), value) {
            ("NOTIFY", Some(value)) => {
                let valid = value.split(',').all(|word| {
                    matches!(word.to_ascii_uppercase().as_str(), "NEVER" | "SUCCESS" | "FAILURE" | "DELAY")
                });
                if !valid || (value.to_ascii_uppercase().contains("NEVER") && value.contains(',')) {
                    return Err(Error::InvalidParameter { param: "NOTIFY" });
                }
                to.notify = Some(value.to_ascii_uppercase());
            }
            ("ORCPT", Some(value)) if value.contains(';') && value.len() <= 500 => to.orcpt = Some(value.to_owned()),
            ("ORCPT", _) => return Err(Error::InvalidParameter { param: "ORCPT" }),
            ("NOTIFY", None) => return Err(Error::SyntaxError { syntax: "parameter keyword=value" }),
            _ => return Err(Error::UnsupportedParameter { param: keyword }),
        }
    }
    Ok(Request::Rcpt { to })
}

/// `BDAT chunk-size [LAST]` (RFC 3030, 2).
fn bdat(rest: &str) -> Result<Request, Error> {
    const SYNTAX: &str = "BDAT chunk-size [LAST]";
    let mut words = rest.split_ascii_whitespace();
    let size = words
        .next()
        .filter(|size| size.len() <= 20 && size.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|size| size.parse::<u64>().ok())
        .ok_or(Error::SyntaxError { syntax: SYNTAX })?;
    let is_last = match words.next() {
        None => false,
        Some(word) if word.eq_ignore_ascii_case("LAST") => true,
        Some(_) => return Err(Error::SyntaxError { syntax: SYNTAX }),
    };
    if words.next().is_some() {
        return Err(Error::SyntaxError { syntax: SYNTAX });
    }
    Ok(Request::Bdat { chunk_size: usize::try_from(size).unwrap_or(usize::MAX), is_last })
}

/// `AUTH mechanism [initial-response]` (RFC 4954, 4); `=` is an empty initial response.
fn auth(rest: &str) -> Result<Request, Error> {
    const SYNTAX: &str = "AUTH mechanism [initial-response]";
    let mut words = rest.split_ascii_whitespace();
    let name = words.next().ok_or(Error::SyntaxError { syntax: SYNTAX })?;
    let initial = words.next().unwrap_or_default();
    if words.next().is_some() || name.len() > 20 {
        return Err(Error::SyntaxError { syntax: SYNTAX });
    }
    let initial_response = if initial == "=" { String::new() } else { initial.to_owned() };
    Ok(Request::Auth { mechanism: mechanism(name), initial_response })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(line: &str) -> Result<Request, Error> {
        let mut receiver = RequestReceiver::default();
        let mut input = line.as_bytes();
        let result = receiver.ingest(&mut input);
        assert!(input.is_empty() || result.is_ok(), "{line}");
        result
    }

    #[test]
    fn commands_are_read_in_any_case_and_in_pieces() {
        let mut receiver = RequestReceiver::default();
        let mut input: &[u8] = b"eh";
        assert_eq!(receiver.ingest(&mut input), Err(Error::NeedsMoreData));
        let mut input: &[u8] = b"lo mx.example\r\nNOOP\r\n";
        assert_eq!(receiver.ingest(&mut input), Ok(Request::Ehlo { host: "mx.example".into() }));
        assert_eq!(input, b"NOOP\r\n");
        assert_eq!(receiver.ingest(&mut input), Ok(Request::Noop));
        assert_eq!(one("HELO [192.0.2.1]\r\n"), Ok(Request::Helo { host: "[192.0.2.1]".into() }));
        assert_eq!(one("quit\n"), Ok(Request::Quit));
        assert_eq!(one("DATA\r\n"), Ok(Request::Data));
        assert_eq!(one("STARTTLS now\r\n"), Err(Error::SyntaxError { syntax: "STARTTLS" }));
        assert_eq!(one("FROB\r\n"), Err(Error::UnknownCommand));
        assert_eq!(one("EHLO\r\n"), Err(Error::SyntaxError { syntax: "EHLO domain" }));
        assert_eq!(one("EHLO a b\r\n"), Err(Error::SyntaxError { syntax: "EHLO domain" }));
    }

    #[test]
    fn mail_and_rcpt_take_paths_and_parameters() {
        let Ok(Request::Mail { from }) =
            one("MAIL FROM:<Alice@Firma.Example> SIZE=42 BODY=8BITMIME SMTPUTF8 RET=HDRS ENVID=x+2B AUTH=<>\r\n")
        else {
            panic!()
        };
        assert_eq!(from.address, "Alice@Firma.Example");
        assert_eq!((from.size, from.body, from.smtputf8, from.ret_headers), (42, Body::EightBitMime, true, true));
        assert_eq!(from.envid.as_deref(), Some("x+2B"));
        assert_eq!(one("mail from:<>\r\n"), Ok(Request::Mail { from: MailFrom::default() }));
        let Ok(Request::Mail { from }) = one("MAIL FROM: <@relay.example,@b.example:bob@b.example>\r\n") else {
            panic!()
        };
        assert_eq!(from.address, "bob@b.example");
        let Ok(Request::Mail { from }) = one("MAIL FROM:<\"a > b\"@x.example>\r\n") else { panic!() };
        assert_eq!(from.address, "\"a > b\"@x.example");
        let Ok(Request::Rcpt { to }) = one("RCPT TO:<jörg@bücher.example> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;x@y\r\n")
        else {
            panic!()
        };
        assert_eq!(to.address, "jörg@bücher.example");
        assert_eq!(to.notify.as_deref(), Some("SUCCESS,FAILURE"));
        assert_eq!(
            one("RCPT TO:<postmaster>\r\n"),
            Ok(Request::Rcpt { to: RcptTo { address: "postmaster".into(), ..RcptTo::default() } })
        );

        assert_eq!(one("MAIL FROM:alice@x.example\r\n"), Err(Error::InvalidSenderAddress));
        assert_eq!(one("MAIL FROM:<a b@x.example>\r\n"), Err(Error::InvalidSenderAddress));
        assert_eq!(one("MAIL FROM:<a@x.example>junk\r\n"), Err(Error::InvalidSenderAddress));
        assert_eq!(one("MAIL TO:<a@x.example>\r\n"), Err(Error::SyntaxError { syntax: "MAIL FROM:<address>" }));
        assert_eq!(one("MAIL FROM:<a@x.example> SIZE=big\r\n"), Err(Error::InvalidParameter { param: "SIZE" }));
        assert_eq!(
            one("MAIL FROM:<a@x.example> FROB=1\r\n"),
            Err(Error::UnsupportedParameter { param: "FROB".into() })
        );
        assert_eq!(one("RCPT TO:<>\r\n"), Err(Error::InvalidRecipientAddress));
        assert_eq!(
            one("RCPT TO:<a@x.example> NOTIFY=NEVER,DELAY\r\n"),
            Err(Error::InvalidParameter { param: "NOTIFY" })
        );
        assert_eq!(one(&format!("RCPT TO:<{}@x.example>\r\n", "a".repeat(300))), Err(Error::InvalidRecipientAddress));
    }

    #[test]
    fn bdat_and_auth() {
        assert_eq!(one("BDAT 100 LAST\r\n"), Ok(Request::Bdat { chunk_size: 100, is_last: true }));
        assert_eq!(one("bdat 0\r\n"), Ok(Request::Bdat { chunk_size: 0, is_last: false }));
        assert!(one("BDAT -1\r\n").is_err());
        assert!(one("BDAT 1 FIRST\r\n").is_err());
        assert_eq!(
            one("AUTH plain AGEAYg==\r\n"),
            Ok(Request::Auth { mechanism: AUTH_PLAIN, initial_response: "AGEAYg==".into() })
        );
        assert_eq!(
            one("AUTH LOGIN =\r\n"),
            Ok(Request::Auth { mechanism: AUTH_LOGIN, initial_response: String::new() })
        );
        assert_eq!(
            one("AUTH CRAM-MD5\r\n"),
            Ok(Request::Auth { mechanism: AUTH_OTHER, initial_response: String::new() })
        );
    }

    #[test]
    fn long_lines_are_read_to_their_end_and_refused() {
        let mut receiver = RequestReceiver::default();
        let long = vec![b'A'; MAX_LINE * 3];
        let mut input: &[u8] = &long;
        assert_eq!(receiver.ingest(&mut input), Err(Error::NeedsMoreData));
        let mut input: &[u8] = b"AAAA\r\nNOOP\r\n";
        assert_eq!(receiver.ingest(&mut input), Err(Error::LineTooLong));
        assert_eq!(receiver.ingest(&mut input), Ok(Request::Noop));
    }

    /// Whatever arrives, the parser answers without panicking.
    #[test]
    fn arbitrary_input_never_panics() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let alphabet = b"MAIL FROM:<>@\"\\ RCPT TO:BDAT LAST AUTH=,;:.\r\n\t\x00\xff\xc3\xa4[]0123456789SIZE";
        for _ in 0..20_000 {
            let length = (next() % 80) as usize;
            let line: Vec<u8> = (0..length).map(|_| alphabet[(next() % alphabet.len() as u64) as usize]).collect();
            let _ = parse(&line);
            let mut receiver = RequestReceiver::default();
            let mut input: &[u8] = &line;
            while !input.is_empty() {
                let _ = receiver.ingest(&mut input);
            }
        }
    }
}
