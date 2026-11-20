// SPDX-License-Identifier: AGPL-3.0-or-later
//! Tokens of a script (RFC 5228, 2 and 8.1): identifiers, tags, numbers with quantifiers, quoted and multi-line
//! strings, the punctuation; comments and white space are dropped.

use crate::{CompileError, Position};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Token {
    Identifier(String),
    /// Without its colon, in lower case.
    Tag(String),
    Number(u64),
    String(String),
    LeftBracket,
    RightBracket,
    LeftBrace,
    RightBrace,
    LeftParen,
    RightParen,
    Comma,
    Semicolon,
}

impl Token {
    pub(crate) fn describe(&self) -> String {
        match self {
            Token::Identifier(name) => format!("'{name}'"),
            Token::Tag(tag) => format!("':{tag}'"),
            Token::Number(number) => format!("the number {number}"),
            Token::String(_) => "a string".into(),
            Token::LeftBracket => "'['".into(),
            Token::RightBracket => "']'".into(),
            Token::LeftBrace => "'{'".into(),
            Token::RightBrace => "'}'".into(),
            Token::LeftParen => "'('".into(),
            Token::RightParen => "')'".into(),
            Token::Comma => "','".into(),
            Token::Semicolon => "';'".into(),
        }
    }
}

struct Cursor {
    chars: Vec<char>,
    at: usize,
    line: u32,
    column: u32,
}

impl Cursor {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.at).copied()
    }

    fn peek_at(&self, ahead: usize) -> Option<char> {
        self.chars.get(self.at + ahead).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.at += 1;
        if c == '\n' {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        Some(c)
    }

    fn position(&self) -> Position {
        Position { line: self.line, column: self.column }
    }

    fn identifier(&mut self) -> String {
        let mut name = String::new();
        while let Some(c) = self.peek().filter(|c| c.is_ascii_alphanumeric() || *c == '_') {
            name.push(c);
            self.bump();
        }
        name
    }
}

fn starts_identifier(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

pub(crate) fn tokenize(source: &str) -> Result<Vec<(Token, Position)>, CompileError> {
    let mut cursor = Cursor { chars: source.chars().collect(), at: 0, line: 1, column: 1 };
    let mut tokens = Vec::new();
    while let Some(c) = cursor.peek() {
        let position = cursor.position();
        let single = match c {
            ' ' | '\t' | '\r' | '\n' => {
                cursor.bump();
                continue;
            }
            '#' => {
                while cursor.bump().is_some_and(|c| c != '\n') {}
                continue;
            }
            '/' if cursor.peek_at(1) == Some('*') => {
                cursor.bump();
                cursor.bump();
                loop {
                    match cursor.bump() {
                        Some('*') if cursor.peek() == Some('/') => {
                            cursor.bump();
                            break;
                        }
                        Some(_) => {}
                        None => return Err(CompileError::at(position, "a comment is not closed")),
                    }
                }
                continue;
            }
            '[' => Some(Token::LeftBracket),
            ']' => Some(Token::RightBracket),
            '{' => Some(Token::LeftBrace),
            '}' => Some(Token::RightBrace),
            '(' => Some(Token::LeftParen),
            ')' => Some(Token::RightParen),
            ',' => Some(Token::Comma),
            ';' => Some(Token::Semicolon),
            _ => None,
        };
        if let Some(token) = single {
            cursor.bump();
            tokens.push((token, position));
            continue;
        }
        let token = match c {
            '"' => {
                cursor.bump();
                Token::String(quoted(&mut cursor, position)?)
            }
            ':' => {
                cursor.bump();
                if !cursor.peek().is_some_and(starts_identifier) {
                    return Err(CompileError::at(position, "a tag needs a name after ':'"));
                }
                Token::Tag(cursor.identifier().to_ascii_lowercase())
            }
            c if c.is_ascii_digit() => number(&mut cursor, position)?,
            c if starts_identifier(c) => {
                let name = cursor.identifier();
                if name.eq_ignore_ascii_case("text") && cursor.peek() == Some(':') {
                    cursor.bump();
                    Token::String(multi_line(&mut cursor, position)?)
                } else {
                    Token::Identifier(name)
                }
            }
            other => return Err(CompileError::at(position, format!("unexpected character '{other}'"))),
        };
        tokens.push((token, position));
    }
    Ok(tokens)
}

/// A quoted string after its opening quote: `\"` and `\\` stand for themselves, and a backslash before any other
/// character is dropped (RFC 5228, 2.4.2).
fn quoted(cursor: &mut Cursor, start: Position) -> Result<String, CompileError> {
    let mut text = String::new();
    loop {
        match cursor.bump() {
            Some('"') => return Ok(text),
            Some('\\') => match cursor.bump() {
                Some(c) => text.push(c),
                None => break,
            },
            Some(c) => text.push(c),
            None => break,
        }
    }
    Err(CompileError::at(start, "a string is not closed"))
}

/// A multi-line string after `text:`: the rest of the line holds only white space or a comment; lines follow up to
/// one that is a single `.`, and a leading `.` of a line is dropped (dot-stuffing). Lines end in CRLF.
fn multi_line(cursor: &mut Cursor, start: Position) -> Result<String, CompileError> {
    while matches!(cursor.peek(), Some(' ' | '\t')) {
        cursor.bump();
    }
    match cursor.peek() {
        Some('#') => while cursor.bump().is_some_and(|c| c != '\n') {},
        Some('\r') if cursor.peek_at(1) == Some('\n') => {
            cursor.bump();
            cursor.bump();
        }
        Some('\n') => {
            cursor.bump();
        }
        _ => return Err(CompileError::at(start, "'text:' must end its line")),
    }
    let mut text = String::new();
    loop {
        let mut line = String::new();
        let mut ended = false;
        while let Some(c) = cursor.bump() {
            if c == '\n' {
                ended = true;
                break;
            }
            line.push(c);
        }
        if line.ends_with('\r') {
            line.pop();
        }
        if line == "." {
            return Ok(text);
        }
        if !ended {
            return Err(CompileError::at(start, "a multi-line string is not closed with a line of '.'"));
        }
        text.push_str(line.strip_prefix('.').unwrap_or(&line));
        text.push_str("\r\n");
    }
}

fn number(cursor: &mut Cursor, start: Position) -> Result<Token, CompileError> {
    let too_large = || CompileError::at(start, "the number is too large");
    let mut value: u64 = 0;
    while let Some(digit) = cursor.peek().and_then(|c| c.to_digit(10)) {
        cursor.bump();
        value = value.checked_mul(10).and_then(|v| v.checked_add(u64::from(digit))).ok_or_else(too_large)?;
    }
    let shift = match cursor.peek() {
        Some('k' | 'K') => 10,
        Some('m' | 'M') => 20,
        Some('g' | 'G') => 30,
        _ => 0,
    };
    if shift > 0 {
        cursor.bump();
        value = value.checked_mul(1 << shift).ok_or_else(too_large)?;
    }
    if cursor.peek().is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(CompileError::at(start, "a number is followed by letters"));
    }
    Ok(Token::Number(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(source: &str) -> Vec<Token> {
        tokenize(source).unwrap().into_iter().map(|(token, _)| token).collect()
    }

    #[test]
    fn identifiers_tags_numbers_and_punctuation() {
        assert_eq!(
            tokens("if size :OVER 100K { discard; } # gone\r\n/* a\ncomment */ [\"a\", \"b\"] (x)"),
            [
                Token::Identifier("if".into()),
                Token::Identifier("size".into()),
                Token::Tag("over".into()),
                Token::Number(100 * 1024),
                Token::LeftBrace,
                Token::Identifier("discard".into()),
                Token::Semicolon,
                Token::RightBrace,
                Token::LeftBracket,
                Token::String("a".into()),
                Token::Comma,
                Token::String("b".into()),
                Token::RightBracket,
                Token::LeftParen,
                Token::Identifier("x".into()),
                Token::RightParen,
            ]
        );
        assert_eq!(tokens("1M 2g 0"), [Token::Number(1 << 20), Token::Number(2 << 30), Token::Number(0)]);
    }

    #[test]
    fn quoted_strings_unescape() {
        assert_eq!(tokens(r#""a\"b\\c\d""#), [Token::String("a\"b\\cd".into())]);
        assert_eq!(tokens("\"two\r\nlines\""), [Token::String("two\r\nlines".into())]);
    }

    #[test]
    fn multi_line_strings_unstuff_dots() {
        assert_eq!(
            tokens("text: # comment\r\nHello\r\n..dot\r\n.\r\n;"),
            [Token::String("Hello\r\n.dot\r\n".into()), Token::Semicolon]
        );
        assert_eq!(tokens("TEXT:\nbare\n.\n"), [Token::String("bare\r\n".into())]);
    }

    #[test]
    fn errors_say_where() {
        let error = tokenize("keep;\n  \"open").unwrap_err();
        assert_eq!(error.position, Some(Position { line: 2, column: 3 }));
        assert_eq!(error.to_string(), "line 2, column 3: a string is not closed");
        assert!(tokenize("/* never closed").is_err());
        assert!(tokenize("text: x\r\n.\r\n").is_err());
        assert!(tokenize("text:\r\nno end\r\n").is_err());
        assert!(tokenize("99999999999999999999").is_err());
        assert!(tokenize("20000000000G").is_err());
        assert!(tokenize("10x").is_err());
        assert!(tokenize(": x").is_err());
        assert!(tokenize("@").is_err());
    }
}
