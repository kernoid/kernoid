// SPDX-License-Identifier: AGPL-3.0-or-later
//! Cutting the client's bytes into commands (RFC 9051, 2.2 and 4.3): a command is a line, unless the line ends in a
//! literal's announcement – `{n}` (the client waits for `+`), `{n+}` (LITERAL+, RFC 7888) or `~{n}`/`~{n+}` (a
//! binary literal, RFC 3516) – after which `n` octets and the rest of the command follow. Lines and literals have
//! limits; a literal over its limit is refused, a line over it ends the session.

/// The longest line, and the longest literal of commands other than `APPEND`.
pub(crate) const MAX_LINE: usize = 64 * 1024;
/// The most literals one command may carry (MULTIAPPEND sends one per message).
const MAX_LITERALS: usize = 1000;

/// A whole command: the text of its lines, and the literals between them – `lines.len() == literals.len() + 1`.
/// A line keeps everything but the literal's announcement and its line break.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Frame {
    pub lines: Vec<Vec<u8>>,
    pub literals: Vec<Vec<u8>>,
}

/// What the framer found in what it was given.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Next {
    Command(Frame),
    /// The client waits for `+ ` before it sends a literal.
    Continue,
    /// The command was refused while it was read (a literal too large); `tag` is what the line began with.
    Refused {
        tag: Option<String>,
        text: &'static str,
    },
    /// The client broke the limits in a way the session cannot recover from.
    Fatal(&'static str),
    /// More bytes are needed.
    More,
}

/// A literal being read.
#[derive(Debug, Clone, Copy)]
struct Wanted {
    remaining: usize,
    /// Read and thrown away: the command is refused already.
    discard: bool,
}

#[derive(Debug, Default)]
struct Partial {
    frame: Frame,
    wanted: Option<Wanted>,
    /// The bytes of literals so far.
    total: usize,
    /// The command was refused; it is read to its end and dropped.
    refused: Option<&'static str>,
}

#[derive(Debug)]
pub(crate) struct Framer {
    buffer: Vec<u8>,
    /// How far `buffer` was searched for a line break.
    scanned: usize,
    partial: Option<Partial>,
    /// The largest message `APPEND` takes.
    max_message: usize,
}

/// `{n}`, `{n+}`, `~{n}` or `~{n+}` at the end of a line: what comes before it, the size, and whether the client
/// waits for the continuation.
fn announcement(line: &[u8]) -> Option<(usize, u64, bool)> {
    let inner = line.strip_suffix(b"}")?;
    let open = inner.iter().rposition(|&b| b == b'{')?;
    let (digits, sync) = match inner[open + 1..].strip_suffix(b"+") {
        Some(digits) => (digits, false),
        None => (&inner[open + 1..], true),
    };
    if digits.is_empty() || digits.len() > 19 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let size = std::str::from_utf8(digits).ok()?.parse().ok()?;
    let start = if open > 0 && inner[open - 1] == b'~' { open - 1 } else { open };
    Some((start, size, sync))
}

/// The tag a command's first line starts with, for answering it.
fn tag_of(line: &[u8]) -> Option<String> {
    let end = line.iter().position(|&b| b == b' ').unwrap_or(line.len());
    let tag = &line[..end];
    (!tag.is_empty() && tag.iter().all(|&b| b.is_ascii_graphic() && b != b'+' && b != b'{'))
        .then(|| String::from_utf8_lossy(tag).into_owned())
}

/// Whether the command on this first line is `APPEND`, whose literals are messages.
fn is_append(line: &[u8]) -> bool {
    let mut words = line.split(|&b| b == b' ').filter(|word| !word.is_empty());
    words.next();
    words.next().is_some_and(|word| word.eq_ignore_ascii_case(b"APPEND"))
}

impl Framer {
    pub fn new(max_message: usize) -> Self {
        Self { buffer: Vec::new(), scanned: 0, partial: None, max_message }
    }

    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// Drops whatever the client sent ahead – after `STARTTLS`, nothing said in plain text may count.
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.scanned = 0;
        self.partial = None;
    }

    /// The next line without its line break, outside a command (`AUTHENTICATE`'s responses, `DONE`); `Err` when it
    /// is too long.
    pub fn line(&mut self) -> Option<Result<Vec<u8>, ()>> {
        match self.buffer[self.scanned..].iter().position(|&b| b == b'\n') {
            Some(offset) => {
                let end = self.scanned + offset;
                let mut line: Vec<u8> = self.buffer.drain(..=end).collect();
                self.scanned = 0;
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                Some(if line.len() > MAX_LINE { Err(()) } else { Ok(line) })
            }
            None => {
                self.scanned = self.buffer.len();
                (self.buffer.len() > MAX_LINE).then_some(Err(()))
            }
        }
    }

    pub fn next(&mut self) -> Next {
        loop {
            let partial = self.partial.get_or_insert_with(Partial::default);
            if let Some(wanted) = &mut partial.wanted {
                let take = wanted.remaining.min(self.buffer.len());
                if wanted.discard {
                    self.buffer.drain(..take);
                    wanted.remaining -= take;
                    if wanted.remaining > 0 {
                        return Next::More;
                    }
                } else {
                    if self.buffer.len() < wanted.remaining {
                        return Next::More;
                    }
                    let literal = self.buffer.drain(..take).collect();
                    partial.frame.literals.push(literal);
                }
                partial.wanted = None;
                self.scanned = 0;
                continue;
            }
            let Some(offset) = self.buffer[self.scanned..].iter().position(|&b| b == b'\n') else {
                self.scanned = self.buffer.len();
                if self.buffer.len() > MAX_LINE {
                    self.clear();
                    return Next::Fatal("Line too long");
                }
                return Next::More;
            };
            let end = self.scanned + offset;
            self.scanned = 0;
            if end > MAX_LINE {
                self.clear();
                return Next::Fatal("Line too long");
            }
            let mut line: Vec<u8> = self.buffer.drain(..=end).collect();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            // Empty lines between commands are ignored.
            if line.is_empty() && partial.frame.lines.is_empty() {
                continue;
            }
            let first = partial.frame.lines.first().unwrap_or(&line);
            let tag = tag_of(first);
            let limit = if is_append(first) { self.max_message } else { MAX_LINE };
            match announcement(&line) {
                Some((start, size, sync)) => {
                    line.truncate(start);
                    partial.frame.lines.push(line);
                    let size_ok = usize::try_from(size).is_ok_and(|size| {
                        size <= limit && partial.total + size <= self.max_message.saturating_mul(4).max(MAX_LINE)
                    });
                    if partial.refused.is_none() && (!size_ok || partial.frame.literals.len() >= MAX_LITERALS) {
                        partial.refused = Some("Literal too large");
                    }
                    if partial.refused.is_some() && sync {
                        // The client sends nothing more of this command.
                        let text = partial.refused.unwrap_or_default();
                        self.partial = None;
                        return Next::Refused { tag, text };
                    }
                    let discard = partial.refused.is_some();
                    let remaining = if discard { usize::try_from(size).unwrap_or(usize::MAX) } else { size as usize };
                    partial.total = partial.total.saturating_add(if discard { 0 } else { remaining });
                    partial.wanted = Some(Wanted { remaining, discard });
                    if sync {
                        return Next::Continue;
                    }
                }
                None => {
                    partial.frame.lines.push(line);
                    let partial = self.partial.take().unwrap_or_default();
                    return match partial.refused {
                        Some(text) => Next::Refused { tag, text },
                        None => Next::Command(partial.frame),
                    };
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frames(input: &[u8], max_message: usize) -> Vec<Next> {
        let mut framer = Framer::new(max_message);
        framer.push(input);
        let mut out = Vec::new();
        loop {
            match framer.next() {
                Next::More => return out,
                next => out.push(next),
            }
        }
    }

    fn command(lines: &[&str], literals: &[&str]) -> Next {
        Next::Command(Frame {
            lines: lines.iter().map(|line| line.as_bytes().to_vec()).collect(),
            literals: literals.iter().map(|literal| literal.as_bytes().to_vec()).collect(),
        })
    }

    #[test]
    fn lines_and_literals() {
        assert_eq!(frames(b"a NOOP\r\n\r\nb NOOP\nc", 100), [command(&["a NOOP"], &[]), command(&["b NOOP"], &[])]);
        assert_eq!(
            frames(b"a LOGIN {5}\r\nalice {3+}\r\npw!\r\n", 100),
            [Next::Continue, command(&["a LOGIN ", " ", ""], &["alice", "pw!"])]
        );
        assert_eq!(
            frames(b"a APPEND INBOX ~{4+}\r\n\0\r\n\x01\r\n", 100),
            [command(&["a APPEND INBOX ", ""], &["\0\r\n\x01"])]
        );
        // A literal that is not complete yet.
        let mut framer = Framer::new(100);
        framer.push(b"a APPEND INBOX {10}\r\n0123");
        assert_eq!(framer.next(), Next::Continue);
        assert_eq!(framer.next(), Next::More);
        framer.push(b"456789\r\n");
        assert_eq!(framer.next(), command(&["a APPEND INBOX ", ""], &["0123456789"]));
    }

    #[test]
    fn limits() {
        // APPEND takes literals up to the message size, others up to a line's length.
        assert_eq!(
            frames(b"a APPEND INBOX {101}\r\n", 100),
            [Next::Refused { tag: Some("a".into()), text: "Literal too large" }]
        );
        let huge = format!("a LOGIN {{{}}}\r\n", MAX_LINE + 1);
        assert!(matches!(frames(huge.as_bytes(), 10_000_000)[0], Next::Refused { .. }));
        // A non-synchronizing literal that is too large is read and thrown away.
        assert_eq!(
            frames(b"a APPEND INBOX {5+}\r\n12345 FOO\r\nb NOOP\r\n", 4),
            [Next::Refused { tag: Some("a".into()), text: "Literal too large" }, command(&["b NOOP"], &[])]
        );
        assert_eq!(
            frames(b"a APPEND INBOX {99999999999999999999}\r\n", 4),
            [command(&["a APPEND INBOX {99999999999999999999}"], &[])]
        );
        let long = vec![b'a'; MAX_LINE + 2];
        assert_eq!(frames(&long, 100), [Next::Fatal("Line too long")]);
    }

    #[test]
    fn raw_lines() {
        let mut framer = Framer::new(100);
        framer.push(b"DONE\r\nx");
        assert_eq!(framer.line(), Some(Ok(b"DONE".to_vec())));
        assert_eq!(framer.line(), None);
        framer.clear();
        assert_eq!(framer.line(), None);
    }
}
