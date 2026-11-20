// SPDX-License-Identifier: AGPL-3.0-or-later
//! The grammar of RFC 5228, 8.2: commands with arguments, tests and blocks – before anything knows what a command
//! means.

use crate::{CompileError, Position, lexer::Token};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Argument {
    /// A string, or a list of them in brackets (`list`).
    Strings {
        values: Vec<String>,
        list: bool,
        position: Position,
    },
    Number(u64, Position),
    Tag(String, Position),
}

impl Argument {
    pub(crate) fn position(&self) -> Position {
        match self {
            Argument::Strings { position, .. } | Argument::Number(_, position) | Argument::Tag(_, position) => {
                *position
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Tests {
    None,
    One(Box<Test>),
    /// In parentheses.
    List(Vec<Test>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Test {
    /// In lower case.
    pub name: String,
    pub position: Position,
    pub arguments: Vec<Argument>,
    pub tests: Tests,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Command {
    /// In lower case.
    pub name: String,
    pub position: Position,
    pub arguments: Vec<Argument>,
    pub tests: Tests,
    pub block: Option<Vec<Command>>,
}

struct Parser {
    tokens: Vec<(Token, Position)>,
    at: usize,
    max_nesting: usize,
    end: Position,
}

pub(crate) fn parse(tokens: Vec<(Token, Position)>, max_nesting: usize) -> Result<Vec<Command>, CompileError> {
    let end = tokens.last().map(|(_, position)| *position).unwrap_or(Position { line: 1, column: 1 });
    let mut parser = Parser { tokens, at: 0, max_nesting, end };
    parser.commands(0)
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at).map(|(token, _)| token)
    }

    fn position(&self) -> Position {
        self.tokens.get(self.at).map_or(self.end, |(_, position)| *position)
    }

    fn next(&mut self) -> Option<(Token, Position)> {
        let token = self.tokens.get(self.at).cloned();
        self.at += 1;
        token
    }

    fn unexpected(&self, wanted: &str) -> CompileError {
        match self.peek() {
            Some(token) => {
                CompileError::at(self.position(), format!("{wanted} was expected, not {}", token.describe()))
            }
            None => CompileError::at(self.position(), format!("{wanted} was expected at the end of the script")),
        }
    }

    fn deeper(&self, depth: usize) -> Result<usize, CompileError> {
        if depth >= self.max_nesting {
            return Err(CompileError::at(self.position(), "blocks or tests are nested too deeply"));
        }
        Ok(depth + 1)
    }

    /// Commands up to the end of the script (`depth` 0) or of a block.
    fn commands(&mut self, depth: usize) -> Result<Vec<Command>, CompileError> {
        let mut commands = Vec::new();
        loop {
            match self.peek() {
                None if depth == 0 => return Ok(commands),
                Some(Token::RightBrace) if depth > 0 => {
                    self.next();
                    return Ok(commands);
                }
                Some(Token::Identifier(_)) => commands.push(self.command(depth)?),
                _ => return Err(self.unexpected(if depth > 0 { "a command or '}'" } else { "a command" })),
            }
        }
    }

    fn command(&mut self, depth: usize) -> Result<Command, CompileError> {
        let Some((Token::Identifier(name), position)) = self.next() else {
            unreachable!("commands() saw an identifier");
        };
        let name = name.to_ascii_lowercase();
        let arguments = self.arguments()?;
        let tests = self.tests(depth)?;
        let block = match self.peek() {
            Some(Token::Semicolon) => {
                self.next();
                None
            }
            Some(Token::LeftBrace) => {
                let depth = self.deeper(depth)?;
                self.next();
                Some(self.commands(depth)?)
            }
            _ => return Err(self.unexpected(&format!("';' or a block after '{name}'"))),
        };
        Ok(Command { name, position, arguments, tests, block })
    }

    fn arguments(&mut self) -> Result<Vec<Argument>, CompileError> {
        let mut arguments = Vec::new();
        loop {
            let position = self.position();
            let argument = match self.peek() {
                Some(Token::String(_)) => {
                    let Some((Token::String(value), _)) = self.next() else { unreachable!() };
                    Argument::Strings { values: vec![value], list: false, position }
                }
                Some(Token::Number(number)) => {
                    let number = *number;
                    self.next();
                    Argument::Number(number, position)
                }
                Some(Token::Tag(tag)) => {
                    let tag = tag.clone();
                    self.next();
                    Argument::Tag(tag, position)
                }
                Some(Token::LeftBracket) => {
                    self.next();
                    let mut values = Vec::new();
                    loop {
                        match self.next() {
                            Some((Token::String(value), _)) => values.push(value),
                            _ => {
                                self.at -= 1;
                                return Err(self.unexpected("a string in the list"));
                            }
                        }
                        match self.next() {
                            Some((Token::Comma, _)) => {}
                            Some((Token::RightBracket, _)) => break,
                            _ => {
                                self.at -= 1;
                                return Err(self.unexpected("',' or ']'"));
                            }
                        }
                    }
                    Argument::Strings { values, list: true, position }
                }
                _ => return Ok(arguments),
            };
            arguments.push(argument);
        }
    }

    fn tests(&mut self, depth: usize) -> Result<Tests, CompileError> {
        match self.peek() {
            Some(Token::Identifier(_)) => Ok(Tests::One(Box::new(self.test(depth)?))),
            Some(Token::LeftParen) => {
                let depth = self.deeper(depth)?;
                self.next();
                let mut tests = Vec::new();
                loop {
                    if !matches!(self.peek(), Some(Token::Identifier(_))) {
                        return Err(self.unexpected("a test"));
                    }
                    tests.push(self.test(depth)?);
                    match self.next() {
                        Some((Token::Comma, _)) => {}
                        Some((Token::RightParen, _)) => return Ok(Tests::List(tests)),
                        _ => {
                            self.at -= 1;
                            return Err(self.unexpected("',' or ')'"));
                        }
                    }
                }
            }
            _ => Ok(Tests::None),
        }
    }

    fn test(&mut self, depth: usize) -> Result<Test, CompileError> {
        let depth = self.deeper(depth)?;
        let Some((Token::Identifier(name), position)) = self.next() else {
            unreachable!("tests() saw an identifier");
        };
        let arguments = self.arguments()?;
        let tests = self.tests(depth)?;
        Ok(Test { name: name.to_ascii_lowercase(), position, arguments, tests })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::tokenize;

    fn parsed(source: &str) -> Result<Vec<Command>, CompileError> {
        parse(tokenize(source)?, 8)
    }

    #[test]
    fn commands_with_arguments_tests_and_blocks() {
        let commands = parsed("IF anyof (true, header :is [\"a\", \"b\"] \"c\") { keep; } else { discard; }").unwrap();
        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0].name, "if");
        let Tests::One(test) = &commands[0].tests else { panic!() };
        assert_eq!(test.name, "anyof");
        let Tests::List(list) = &test.tests else { panic!() };
        assert_eq!(list.len(), 2);
        assert_eq!(list[1].arguments.len(), 3);
        assert!(matches!(&list[1].arguments[1], Argument::Strings { values, list: true, .. } if values.len() == 2));
        assert_eq!(commands[0].block.as_ref().unwrap()[0].name, "keep");
        assert_eq!(commands[1].name, "else");
    }

    #[test]
    fn errors_say_where_and_what() {
        assert_eq!(
            parsed("keep").unwrap_err().to_string(),
            "line 1, column 1: ';' or a block after 'keep' was expected at the end of the script"
        );
        assert_eq!(
            parsed("keep;\nfileinto \"x\" }").unwrap_err().to_string(),
            "line 2, column 14: ';' or a block after 'fileinto' was expected, not '}'"
        );
        assert!(parsed("if true { keep;").is_err());
        assert!(parsed("x [];").is_err());
        assert!(parsed("x [\"a\" \"b\"];").is_err());
        assert!(parsed("if anyof (true, ) {}").is_err());
        assert!(parsed("if anyof () {}").is_err());
        assert!(parsed("\"string\";").is_err());
        assert!(parsed("}").is_err());
    }

    #[test]
    fn nesting_is_limited() {
        let deep = "if true {".repeat(9) + &"}".repeat(9);
        assert!(parsed(&deep).is_err());
        let fine = "if true {".repeat(8) + &"}".repeat(8);
        assert!(parsed(&fine).is_ok());
        let tests = "not ".repeat(10);
        assert!(parsed(&format!("if {tests} true {{}}")).is_err());
    }
}
