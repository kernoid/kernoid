// SPDX-License-Identifier: AGPL-3.0-or-later
//! The message after `DATA` (RFC 5321, 4.5.2) and `BDAT` (RFC 3030).
//!
//! After `DATA` the message ends with a line holding a dot alone, and a dot that starts a line is removed – the
//! client doubled it. Only `CRLF . CRLF` ends the message: a bare LF is no line end here, so that `LF . LF` or
//! `LF . CRLF` cannot end a message early and smuggle a second one in behind it (as mail servers that read it as the
//! end did, "SMTP smuggling", 2023). A `BDAT` chunk is exactly as long as its command said, nothing in it is special.

/// Where the receiver of `DATA` stands within a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Position {
    /// At the start of a line (after CRLF, or at the start of the message).
    #[default]
    LineStart,
    /// A dot at the start of a line.
    Dot,
    /// A dot and CR at the start of a line.
    DotCr,
    /// Within a line.
    Text,
    /// Within a line, after a CR.
    Cr,
}

/// Reads the message after `DATA`.
#[derive(Debug, Clone, Default)]
pub struct DataReceiver {
    position: Position,
}

impl DataReceiver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes bytes from `input` into `message` (without the doubled dots) up to the end of the message; true once the
    /// end was read. Bytes after it stay in `input`.
    pub fn ingest(&mut self, input: &mut &[u8], message: &mut Vec<u8>) -> bool {
        self.read(input, Some(message))
    }

    fn read(&mut self, input: &mut &[u8], mut message: Option<&mut Vec<u8>>) -> bool {
        let data: &[u8] = input;
        let mut push = |bytes: &[u8]| {
            if let Some(message) = message.as_deref_mut() {
                message.extend_from_slice(bytes);
            }
        };
        for (index, &byte) in data.iter().enumerate() {
            self.position = match (self.position, byte) {
                (Position::LineStart, b'.') => Position::Dot,
                (Position::Dot, b'\r') => Position::DotCr,
                (Position::DotCr, b'\n') => {
                    *input = &data[index + 1..];
                    self.position = Position::LineStart;
                    return true;
                }
                // The doubled dot is gone; what follows it is the line.
                (Position::Dot, byte) => {
                    push(&[byte]);
                    Position::Text
                }
                // `.` CR and something else: the CR was text, and the byte starts over after it.
                (Position::DotCr, b'\r') => {
                    push(b"\r\r");
                    Position::Cr
                }
                (Position::DotCr, byte) => {
                    push(&[b'\r', byte]);
                    Position::Text
                }
                (Position::LineStart | Position::Text, b'\r') => {
                    push(b"\r");
                    Position::Cr
                }
                (Position::Cr, b'\n') => {
                    push(b"\n");
                    Position::LineStart
                }
                (Position::Cr, b'\r') => {
                    push(b"\r");
                    Position::Cr
                }
                (_, byte) => {
                    push(&[byte]);
                    Position::Text
                }
            };
        }
        *input = &data[data.len()..];
        false
    }
}

/// Reads one `BDAT` chunk.
#[derive(Debug, Clone)]
pub struct BdatReceiver {
    remaining: usize,
    pub is_last: bool,
}

impl BdatReceiver {
    pub fn new(size: usize, is_last: bool) -> Self {
        Self { remaining: size, is_last }
    }

    /// Takes the chunk's bytes from `input` into `message`; true once the chunk is complete.
    pub fn ingest(&mut self, input: &mut &[u8], message: &mut Vec<u8>) -> bool {
        let data: &[u8] = input;
        let taken = self.remaining.min(data.len());
        message.extend_from_slice(&data[..taken]);
        *input = &data[taken..];
        self.remaining -= taken;
        self.remaining == 0
    }
}

/// Data that is read to its end but not kept: a message too large, or a chunk refused.
#[derive(Debug, Clone)]
pub enum Discard {
    Data(DataReceiver),
    Bdat(usize),
}

impl Discard {
    /// True once the end was read.
    pub fn ingest(&mut self, input: &mut &[u8]) -> bool {
        match self {
            Self::Data(receiver) => receiver.read(input, None),
            Self::Bdat(remaining) => {
                let data: &[u8] = input;
                let taken = (*remaining).min(data.len());
                *input = &data[taken..];
                *remaining -= taken;
                *remaining == 0
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_all(pieces: &[&[u8]]) -> (Vec<u8>, bool, Vec<u8>) {
        let mut receiver = DataReceiver::new();
        let mut message = Vec::new();
        for (index, piece) in pieces.iter().enumerate() {
            let mut input = *piece;
            if receiver.ingest(&mut input, &mut message) {
                let mut rest = input.to_vec();
                for piece in &pieces[index + 1..] {
                    rest.extend_from_slice(piece);
                }
                return (message, true, rest);
            }
        }
        (message, false, Vec::new())
    }

    #[test]
    fn dots_are_undoubled_and_only_crlf_dot_crlf_ends() {
        let (message, done, rest) = read_all(&[b"Subject: x\r\n\r\n..Hello.\r\n.\r\nQUIT\r\n"]);
        assert!(done);
        assert_eq!(message, b"Subject: x\r\n\r\n.Hello.\r\n");
        assert_eq!(rest, b"QUIT\r\n");
        // The end in any number of pieces.
        let text = b"a\r\n.b\r\n.\r\n";
        let pieces: Vec<&[u8]> = text.chunks(1).collect();
        let (message, done, _) = read_all(&pieces);
        assert!(done);
        assert_eq!(message, b"a\r\nb\r\n");
        // The empty message.
        let (message, done, _) = read_all(&[b".\r\n"]);
        assert!(done && message.is_empty());
    }

    #[test]
    fn bare_line_feeds_do_not_end_the_message() {
        for smuggled in [&b"a\n.\nMAIL FROM:<x@y>\r\n"[..], b"a\n.\r\nMAIL", b"a\r\n.\nMAIL", b"a\r\n.\r\r\nb"] {
            let (message, done, _) = read_all(&[smuggled]);
            assert!(!done, "{}", String::from_utf8_lossy(smuggled));
            assert!(!message.is_empty());
        }
        let (message, done, _) = read_all(&[b"a\r\n.\rx\r\n.\r\n"]);
        assert!(done);
        assert_eq!(message, b"a\r\n\rx\r\n");
    }

    #[test]
    fn chunks_are_exactly_their_size() {
        let mut receiver = BdatReceiver::new(5, true);
        let mut message = Vec::new();
        let mut input: &[u8] = b"From:";
        assert!(receiver.ingest(&mut input, &mut message));
        let mut receiver = BdatReceiver::new(4, false);
        let mut input: &[u8] = b"ab";
        assert!(!receiver.ingest(&mut input, &mut message));
        let mut input: &[u8] = b"cdNOOP\r\n";
        assert!(receiver.ingest(&mut input, &mut message));
        assert_eq!(message, b"From:abcd");
        assert_eq!(input, b"NOOP\r\n");
        let mut discard = Discard::Bdat(3);
        let mut input: &[u8] = b"xyzRSET";
        assert!(discard.ingest(&mut input));
        assert_eq!(input, b"RSET");
        let mut discard = Discard::Data(DataReceiver::new());
        let mut input: &[u8] = b"lots\r\n.\r\nNOOP";
        assert!(discard.ingest(&mut input));
        assert_eq!(input, b"NOOP");
    }
}
