// SPDX-License-Identifier: MIT
//! Address lists (RFC 5322, 3.4, with the obsolete forms of 4.4 and UTF-8 of RFC 6532): mailboxes – a display name
//! and an address, or an address with its name in a comment – and groups. Words without an `@` are a name without
//! an address. Display names are decoded (RFC 2047, also
//! inside quotes, as mail programs write them); addresses stay as written, without white space and comments.

use crate::words;

/// A name and an address; either may be missing in what real mail has.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Mailbox {
    pub name: Option<String>,
    pub address: Option<String>,
}

impl Mailbox {
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn address(&self) -> Option<&str> {
        self.address.as_deref()
    }
}

/// A group (`Team: a@x, b@y;`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Group {
    pub name: Option<String>,
    pub mailboxes: Vec<Mailbox>,
}

impl Group {
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn mailboxes(&self) -> impl Iterator<Item = &Mailbox> {
        self.mailboxes.iter()
    }
}

/// One item of an address list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    Mailbox(Mailbox),
    Group(Group),
}

/// An address list as written.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AddressList(pub Vec<Address>);

impl AddressList {
    pub fn iter(&self) -> impl Iterator<Item = &Address> {
        self.0.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Every mailbox, those of groups included, in order.
    pub fn mailboxes(&self) -> impl Iterator<Item = &Mailbox> {
        self.0.iter().flat_map(|item| match item {
            Address::Mailbox(mailbox) => std::slice::from_ref(mailbox).iter(),
            Address::Group(group) => group.mailboxes.iter(),
        })
    }

    /// The first mailbox.
    pub fn first(&self) -> Option<&Mailbox> {
        self.mailboxes().next()
    }

    /// The list as groups (RFC 8621, 4.1.2.4): each group, and each run of mailboxes outside groups as a group without
    /// a name.
    pub fn groups(&self) -> Vec<(Option<&str>, Vec<&Mailbox>)> {
        let mut out: Vec<(Option<&str>, Vec<&Mailbox>)> = Vec::new();
        let mut loose = false;
        for item in &self.0 {
            match item {
                Address::Mailbox(mailbox) => {
                    if loose {
                        out.last_mut().expect("a run").1.push(mailbox);
                    } else {
                        out.push((None, vec![mailbox]));
                        loose = true;
                    }
                }
                Address::Group(group) => {
                    out.push((group.name(), group.mailboxes.iter().collect()));
                    loose = false;
                }
            }
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Word(String),
    Quoted(String),
    Comment(String),
    Special(char),
}

/// Tokens, each with whether white space came before it.
fn tokens(text: &str) -> Vec<(Token, bool)> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut space = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            space = true;
            i += 1;
            continue;
        }
        let token = match c {
            '(' => {
                let mut depth = 0;
                let mut comment = String::new();
                while i < chars.len() {
                    match chars[i] {
                        '\\' if i + 1 < chars.len() => {
                            comment.push(chars[i + 1]);
                            i += 2;
                            continue;
                        }
                        '(' => {
                            if depth > 0 {
                                comment.push('(');
                            }
                            depth += 1;
                        }
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                i += 1;
                                break;
                            }
                            comment.push(')');
                        }
                        c => comment.push(c),
                    }
                    i += 1;
                }
                Token::Comment(comment)
            }
            '"' => {
                let mut quoted = String::new();
                i += 1;
                while i < chars.len() {
                    match chars[i] {
                        '"' => {
                            i += 1;
                            break;
                        }
                        '\\' if i + 1 < chars.len() => {
                            quoted.push(chars[i + 1]);
                            i += 1;
                        }
                        '\r' | '\n' => {}
                        c => quoted.push(c),
                    }
                    i += 1;
                }
                Token::Quoted(quoted)
            }
            '<' | '>' | ',' | ':' | ';' | '@' => {
                i += 1;
                Token::Special(c)
            }
            '[' => {
                let mut literal = String::new();
                while i < chars.len() {
                    literal.push(chars[i]);
                    i += 1;
                    if literal.ends_with(']') {
                        break;
                    }
                }
                Token::Word(literal)
            }
            _ => {
                let mut word = String::new();
                while i < chars.len() && !chars[i].is_whitespace() && !"()\"<>,:;@[".contains(chars[i]) {
                    word.push(chars[i]);
                    i += 1;
                }
                if word.is_empty() {
                    // A stray `)`.
                    word.push(chars[i]);
                    i += 1;
                }
                Token::Word(word)
            }
        };
        out.push((token, space));
        space = false;
    }
    out
}

/// A display name from its tokens: words with single spaces, encoded words decoded.
fn phrase(tokens: &[(Token, bool)]) -> Option<String> {
    let mut text = String::new();
    for (token, space) in tokens {
        let piece = match token {
            Token::Word(word) => word.clone(),
            Token::Quoted(quoted) => quoted.clone(),
            Token::Special(c) => c.to_string(),
            Token::Comment(_) => continue,
        };
        if *space && !text.is_empty() {
            text.push(' ');
        }
        text.push_str(&piece);
    }
    let text = words::decode(text.trim());
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

/// An address from its tokens, without white space and comments.
fn addr_spec(tokens: &[(Token, bool)]) -> Option<String> {
    let mut text = String::new();
    for (token, _) in tokens {
        match token {
            Token::Word(word) => text.push_str(word),
            Token::Quoted(quoted) if quoted.contains([' ', '"', '\\', ',', '@', '<', '>', ':', ';']) => {
                text.push('"');
                text.push_str(&quoted.replace('\\', "\\\\").replace('"', "\\\""));
                text.push('"');
            }
            Token::Quoted(quoted) => text.push_str(quoted),
            Token::Special(c) => text.push(*c),
            Token::Comment(_) => {}
        }
    }
    (!text.is_empty()).then_some(text)
}

fn last_comment(tokens: &[(Token, bool)]) -> Option<String> {
    tokens.iter().rev().find_map(|(token, _)| match token {
        Token::Comment(comment) => {
            let text = words::decode(comment.trim());
            let text = text.trim();
            (!text.is_empty()).then(|| text.to_owned())
        }
        _ => None,
    })
}

/// One mailbox from its tokens.
fn mailbox(tokens: &[(Token, bool)]) -> Option<Mailbox> {
    if tokens.iter().all(|(token, _)| matches!(token, Token::Comment(_))) {
        return None;
    }
    if let Some(open) = tokens.iter().position(|(token, _)| *token == Token::Special('<')) {
        let close = tokens[open..]
            .iter()
            .position(|(token, _)| *token == Token::Special('>'))
            .map_or(tokens.len(), |c| open + c);
        let mut inside = &tokens[open + 1..close];
        // An obsolete route (`<@a,@b:x@y>`).
        if let Some(colon) = inside.iter().position(|(token, _)| *token == Token::Special(':')) {
            inside = &inside[colon + 1..];
        }
        let name = phrase(&tokens[..open]).or_else(|| last_comment(tokens));
        return Some(Mailbox { name, address: addr_spec(inside) });
    }
    // No angle brackets: an address, perhaps with words before it.
    let at = tokens.iter().position(|(token, _)| *token == Token::Special('@'));
    let Some(at) = at else {
        // Without `@` there is no address (RFC 5322, 3.4.1), only words.
        return Some(Mailbox { name: phrase(tokens).or_else(|| last_comment(tokens)), address: None });
    };
    // The address is the run of tokens around `@` without white space inside it.
    let mut start = at;
    while start > 0 && !tokens[start].1 && !matches!(tokens[start - 1].0, Token::Comment(_)) {
        start -= 1;
    }
    let mut end = at + 1;
    while end < tokens.len() && (end == at + 1 || !tokens[end].1) && !matches!(tokens[end].0, Token::Comment(_)) {
        end += 1;
    }
    let name = phrase(&tokens[..start]).or_else(|| last_comment(tokens));
    Some(Mailbox { name, address: addr_spec(&tokens[start..end]) })
}

/// Reads an address list.
pub fn parse(text: &str) -> AddressList {
    let tokens = tokens(text);
    let mut items = Vec::new();
    let mut group: Option<Group> = None;
    let mut start = 0;
    let mut angle = false;
    let finish = |range: &[(Token, bool)], group: &mut Option<Group>, items: &mut Vec<Address>| {
        if let Some(mailbox) = mailbox(range) {
            match group {
                Some(group) => group.mailboxes.push(mailbox),
                None => items.push(Address::Mailbox(mailbox)),
            }
        }
    };
    for i in 0..tokens.len() {
        match tokens[i].0 {
            Token::Special('<') => angle = true,
            Token::Special('>') => angle = false,
            Token::Special(':') if !angle && group.is_none() => {
                group = Some(Group { name: phrase(&tokens[start..i]), mailboxes: Vec::new() });
                start = i + 1;
            }
            Token::Special(',') if !angle => {
                finish(&tokens[start..i], &mut group, &mut items);
                start = i + 1;
            }
            Token::Special(';') if !angle => {
                finish(&tokens[start..i], &mut group, &mut items);
                if let Some(group) = group.take() {
                    items.push(Address::Group(group));
                }
                start = i + 1;
            }
            _ => {}
        }
    }
    finish(&tokens[start..], &mut group, &mut items);
    if let Some(group) = group {
        items.push(Address::Group(group));
    }
    AddressList(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mailbox(name: Option<&str>, address: Option<&str>) -> Mailbox {
        Mailbox { name: name.map(str::to_owned), address: address.map(str::to_owned) }
    }

    fn mailboxes(text: &str) -> Vec<Mailbox> {
        parse(text).mailboxes().cloned().collect()
    }

    #[test]
    fn addresses_of_rfc_5322() {
        // RFC 5322, A.1.
        assert_eq!(
            mailboxes("John Doe <jdoe@machine.example>"),
            [mailbox(Some("John Doe"), Some("jdoe@machine.example"))]
        );
        assert_eq!(
            mailboxes("\"Joe Q. Public\" <john.q.public@example.com>"),
            [mailbox(Some("Joe Q. Public"), Some("john.q.public@example.com"))]
        );
        assert_eq!(
            mailboxes("Mary Smith <mary@x.test>, jdoe@example.org, Who? <one@y.test>"),
            [
                mailbox(Some("Mary Smith"), Some("mary@x.test")),
                mailbox(None, Some("jdoe@example.org")),
                mailbox(Some("Who?"), Some("one@y.test"))
            ]
        );
        assert_eq!(
            mailboxes("<boss@nil.test>, \"Giant; \\\"Big\\\" Box\" <sysservices@example.net>"),
            [
                mailbox(None, Some("boss@nil.test")),
                mailbox(Some("Giant; \"Big\" Box"), Some("sysservices@example.net"))
            ]
        );
        let list = parse("A Group:Ed Jones <c@a.test>,joe@where.test,John <jdoe@one.test>;");
        let Address::Group(group) = &list.0[0] else { panic!("a group") };
        assert_eq!(group.name(), Some("A Group"));
        assert_eq!(group.mailboxes.len(), 3);
        let list = parse("Undisclosed recipients:;");
        assert_eq!(list.0, [Address::Group(Group { name: Some("Undisclosed recipients".into()), mailboxes: vec![] })]);
        // A.5: comments everywhere.
        assert_eq!(
            mailboxes("Pete(A nice \\) chap) <pete(his account)@silly.test(his host)>"),
            [mailbox(Some("Pete"), Some("pete@silly.test"))]
        );
        let list = parse(
            "A Group(Some people)\r\n     :Chris Jones <c@(Chris's host.)public.example>,\r\n joe@example.org,\r\n John <jdoe@one.test> (my dear friend); (the end of the group)",
        );
        assert_eq!(list.mailboxes().count(), 3);
        assert_eq!(list.mailboxes().next().unwrap().address(), Some("c@public.example"));
        // A.6.1: an obsolete route.
        assert_eq!(mailboxes("<@a.test,@b.test:joe@c.test>"), [mailbox(None, Some("joe@c.test"))]);
    }

    #[test]
    fn addresses_as_mail_programs_write_them() {
        assert_eq!(mailboxes("alice@x.example (Alice A.)"), [mailbox(Some("Alice A."), Some("alice@x.example"))]);
        assert_eq!(
            mailboxes("=?UTF-8?Q?J=C3=BCrgen?= <juergen@remote.example>"),
            [mailbox(Some("Jürgen"), Some("juergen@remote.example"))]
        );
        assert_eq!(
            mailboxes("\"=?utf-8?B?SsO8cmdlbg==?= M.\" <j@x.example>"),
            [mailbox(Some("Jürgen M."), Some("j@x.example"))]
        );
        assert_eq!(mailboxes("Jürgen Müller <j@x.example>"), [mailbox(Some("Jürgen Müller"), Some("j@x.example"))]);
        assert_eq!(mailboxes("\"Doe, John\" <john@x.example>,"), [mailbox(Some("Doe, John"), Some("john@x.example"))]);
        assert_eq!(mailboxes("postmaster"), [mailbox(Some("postmaster"), None)]);
        assert_eq!(mailboxes("not an address"), [mailbox(Some("not an address"), None)]);
        assert_eq!(mailboxes("Broken Name bob@x.example"), [mailbox(Some("Broken Name"), Some("bob@x.example"))]);
        assert_eq!(mailboxes("<a@x.example"), [mailbox(None, Some("a@x.example"))]);
        assert_eq!(mailboxes("用户 <用户@例子.广告>"), [mailbox(Some("用户"), Some("用户@例子.广告"))]);
        assert!(parse("").is_empty() && parse(" , ,").is_empty());
        assert_eq!(mailboxes("a) <b@x>"), [mailbox(Some("a)"), Some("b@x"))]);
        let list = parse("a@x, Team: b@y;, c@z, d@w");
        let groups = list.groups();
        assert_eq!(groups.len(), 3);
        assert_eq!((groups[0].0, groups[0].1.len()), (None, 1));
        assert_eq!((groups[1].0, groups[1].1.len()), (Some("Team"), 1));
        assert_eq!((groups[2].0, groups[2].1.len()), (None, 2));
    }
}
