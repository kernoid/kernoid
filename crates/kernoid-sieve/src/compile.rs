// SPDX-License-Identifier: AGPL-3.0-or-later
//! From the grammar to what runs: each command and test checked against its definition – arguments, tags,
//! capabilities that must be required – into typed commands.

use std::collections::{HashSet, VecDeque};

use crate::{
    CAPABILITIES, CompileError, Position,
    matching::{Comparator, MatchType, Matcher, Relation},
    message::{BodyTransform, single_address},
    parser::{self, Argument, Tests},
    strings::{self, Modifier, Value},
};

#[derive(Debug, Clone)]
pub(crate) enum Command {
    If { branches: Vec<(Test, Vec<Command>)>, otherwise: Option<Vec<Command>> },
    Stop,
    Keep { flags: Option<Vec<Value>> },
    Discard,
    FileInto { mailbox: Value, flags: Option<Vec<Value>>, create: bool, copy: bool },
    Redirect { address: Value, copy: bool },
    Reject { reason: Value, extended: bool },
    Vacation(Box<VacationCommand>),
    Set { name: String, value: Value, modifiers: Vec<Modifier> },
    Flags { op: FlagOp, variable: Option<String>, flags: Vec<Value> },
    Notify(Box<NotifyCommand>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlagOp {
    Set,
    Add,
    Remove,
}

#[derive(Debug, Clone)]
pub(crate) struct VacationCommand {
    /// How long a sender is not answered again, in seconds.
    pub seconds: u64,
    pub subject: Option<Value>,
    pub from: Option<Value>,
    pub addresses: Vec<Value>,
    pub mime: bool,
    pub handle: Option<Value>,
    pub reason: Value,
}

#[derive(Debug, Clone)]
pub(crate) struct NotifyCommand {
    pub method: Value,
    pub from: Option<Value>,
    pub importance: Option<Value>,
    pub options: Vec<Value>,
    pub message: Option<Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AddressPart {
    All,
    LocalPart,
    Domain,
    User,
    Detail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DatePart {
    Year,
    Month,
    Day,
    Date,
    Julian,
    Hour,
    Minute,
    Second,
    Time,
    Iso8601,
    Std11,
    Zone,
    Weekday,
}

impl DatePart {
    fn from_name(name: &str) -> Option<DatePart> {
        Some(match name.to_ascii_lowercase().as_str() {
            "year" => DatePart::Year,
            "month" => DatePart::Month,
            "day" => DatePart::Day,
            "date" => DatePart::Date,
            "julian" => DatePart::Julian,
            "hour" => DatePart::Hour,
            "minute" => DatePart::Minute,
            "second" => DatePart::Second,
            "time" => DatePart::Time,
            "iso8601" => DatePart::Iso8601,
            "std11" => DatePart::Std11,
            "zone" => DatePart::Zone,
            "weekday" => DatePart::Weekday,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Zone {
    /// The context's zone.
    Local,
    /// Seconds east of UTC.
    Fixed(i32),
    /// The zone the date was written in.
    Original,
}

#[derive(Debug, Clone)]
pub(crate) enum DuplicateSource {
    Header(Value),
    UniqueId(Value),
}

/// The fields of `index` (RFC 5260, 4): from 1, from the end with `last`.
pub(crate) type Index = Option<(usize, bool)>;

#[derive(Debug, Clone)]
pub(crate) enum Test {
    True,
    False,
    Not(Box<Test>),
    AllOf(Vec<Test>),
    AnyOf(Vec<Test>),
    Exists(Vec<Value>),
    Size { over: bool, limit: u64 },
    Header { names: Vec<Value>, keys: Vec<Value>, matcher: Matcher, index: Index },
    Address { names: Vec<Value>, keys: Vec<Value>, matcher: Matcher, part: AddressPart, index: Index },
    Envelope { parts: Vec<Value>, keys: Vec<Value>, matcher: Matcher, part: AddressPart },
    Body { transform: BodyTransform, keys: Vec<Value>, matcher: Matcher },
    String { sources: Vec<Value>, keys: Vec<Value>, matcher: Matcher },
    HasFlag { variables: Vec<String>, keys: Vec<Value>, matcher: Matcher },
    Date { name: Value, part: DatePart, zone: Zone, keys: Vec<Value>, matcher: Matcher, index: Index },
    CurrentDate { part: DatePart, zone: Zone, keys: Vec<Value>, matcher: Matcher },
    MailboxExists(Vec<Value>),
    Duplicate { handle: Option<Value>, source: DuplicateSource, seconds: u64, last: bool },
    ValidNotifyMethod(Vec<Value>),
    NotifyMethodCapability { uri: Value, capability: Value, keys: Vec<Value>, matcher: Matcher },
}

/// The arguments of one command or test, taken from the front.
struct Args {
    items: VecDeque<Argument>,
    owner: String,
    position: Position,
}

impl Args {
    fn new(owner: &str, position: Position, items: Vec<Argument>) -> Self {
        Args { items: items.into(), owner: owner.to_owned(), position }
    }

    fn error(&self, position: Position, message: impl std::fmt::Display) -> CompileError {
        CompileError::at(position, format!("{}: {message}", self.owner))
    }

    fn tag(&mut self) -> Option<(String, Position)> {
        match self.items.front() {
            Some(Argument::Tag(..)) => match self.items.pop_front() {
                Some(Argument::Tag(tag, position)) => Some((tag, position)),
                _ => None,
            },
            _ => None,
        }
    }

    fn strings(&mut self, what: &str) -> Result<(Vec<String>, Position), CompileError> {
        match self.items.pop_front() {
            Some(Argument::Strings { values, position, .. }) => Ok((values, position)),
            Some(other) => Err(self.error(other.position(), format!("{what} was expected"))),
            None => Err(self.error(self.position, format!("{what} is missing"))),
        }
    }

    fn string(&mut self, what: &str) -> Result<(String, Position), CompileError> {
        match self.items.pop_front() {
            Some(Argument::Strings { mut values, list: false, position }) => Ok((values.remove(0), position)),
            Some(other) => Err(self.error(other.position(), format!("{what} (one string) was expected"))),
            None => Err(self.error(self.position, format!("{what} is missing"))),
        }
    }

    fn number(&mut self, what: &str) -> Result<u64, CompileError> {
        match self.items.pop_front() {
            Some(Argument::Number(number, _)) => Ok(number),
            Some(other) => Err(self.error(other.position(), format!("{what} (a number) was expected"))),
            None => Err(self.error(self.position, format!("{what} is missing"))),
        }
    }

    /// Positional arguments left.
    fn left(&self) -> usize {
        self.items.len()
    }

    fn done(self) -> Result<(), CompileError> {
        match self.items.front() {
            None => Ok(()),
            Some(Argument::Tag(tag, position)) => Err(self.error(*position, format!("':{tag}' is not known here"))),
            Some(other) => Err(self.error(other.position(), "too many arguments")),
        }
    }
}

/// The tags many tests share: comparator, match type, address part, index.
#[derive(Default)]
struct Common {
    kind: Option<MatchType>,
    comparator: Option<Comparator>,
    part: Option<AddressPart>,
    index: Option<u64>,
    last: bool,
}

struct Compiler {
    capabilities: HashSet<&'static str>,
}

pub(crate) fn compile(commands: Vec<parser::Command>) -> Result<Vec<Command>, CompileError> {
    let mut compiler = Compiler { capabilities: HashSet::new() };
    compiler.commands(commands, true)
}

impl Compiler {
    fn has(&self, capability: &str) -> bool {
        self.capabilities.contains(capability)
    }

    fn need(&self, capability: &str, position: Position, what: &str) -> Result<(), CompileError> {
        if self.has(capability) {
            Ok(())
        } else {
            Err(CompileError::at(position, format!("{what} needs require \"{capability}\"")))
        }
    }

    /// A string of the script: encoded characters decoded, variables found.
    fn value(&self, text: String, position: Position) -> Result<Value, CompileError> {
        let text = self.constant(text, position)?;
        Ok(if self.has("variables") { strings::template(text) } else { Value::Constant(text) })
    }

    fn values(&self, texts: Vec<String>, position: Position) -> Result<Vec<Value>, CompileError> {
        texts.into_iter().map(|text| self.value(text, position)).collect()
    }

    /// A string that never takes variables.
    fn constant(&self, text: String, position: Position) -> Result<String, CompileError> {
        if self.has("encoded-character") {
            strings::decode_encoded(&text).map_err(|message| CompileError::at(position, message))
        } else {
            Ok(text)
        }
    }

    fn commands(&mut self, commands: Vec<parser::Command>, top: bool) -> Result<Vec<Command>, CompileError> {
        let mut out: Vec<Command> = Vec::new();
        // Whether the last command is an `if` that may still take `elsif` or `else`.
        let mut open_if = false;
        let mut requires_allowed = top;
        for command in commands {
            let position = command.position;
            let name = command.name.clone();
            if name == "require" {
                if !requires_allowed {
                    return Err(CompileError::at(position, "require must come before any other command"));
                }
                self.require(command)?;
                continue;
            }
            requires_allowed = false;
            match name.as_str() {
                "elsif" | "else" => {
                    let Some(Command::If { branches, otherwise }) = out.last_mut().filter(|_| open_if) else {
                        return Err(CompileError::at(position, format!("{name} must follow if or elsif")));
                    };
                    let (test, block) = self.conditional(command)?;
                    match test {
                        Some(test) => branches.push((test, block)),
                        None => {
                            *otherwise = Some(block);
                            open_if = false;
                        }
                    }
                }
                "if" => {
                    let (test, block) = self.conditional(command)?;
                    let test = test.ok_or_else(|| CompileError::at(position, "if needs a test"))?;
                    out.push(Command::If { branches: vec![(test, block)], otherwise: None });
                    open_if = true;
                }
                _ => {
                    out.push(self.command(command)?);
                    open_if = false;
                }
            }
        }
        Ok(out)
    }

    fn require(&mut self, command: parser::Command) -> Result<(), CompileError> {
        if command.block.is_some() || command.tests != Tests::None {
            return Err(CompileError::at(command.position, "require takes only a list of capabilities"));
        }
        let mut args = Args::new("require", command.position, command.arguments);
        let (names, position) = args.strings("the capabilities")?;
        args.done()?;
        for name in names {
            let name = self.constant(name, position)?;
            let Some(known) = CAPABILITIES.iter().find(|known| known.eq_ignore_ascii_case(&name)) else {
                return Err(CompileError::at(position, format!("the capability \"{name}\" is not supported")));
            };
            self.capabilities.insert(known);
            if *known == "vacation-seconds" {
                self.capabilities.insert("vacation");
            }
        }
        Ok(())
    }

    /// `if`, `elsif` (with a test) or `else` (without): the test and the block.
    fn conditional(&mut self, command: parser::Command) -> Result<(Option<Test>, Vec<Command>), CompileError> {
        let position = command.position;
        let name = command.name;
        if let Some(argument) = command.arguments.first() {
            return Err(CompileError::at(argument.position(), format!("{name} takes no arguments")));
        }
        let test = match (name.as_str(), command.tests) {
            ("else", Tests::None) => None,
            ("else", _) => return Err(CompileError::at(position, "else takes no test")),
            (_, Tests::One(test)) => Some(self.test(*test)?),
            _ => return Err(CompileError::at(position, format!("{name} needs one test"))),
        };
        let block = command.block.ok_or_else(|| CompileError::at(position, format!("{name} needs a block")))?;
        Ok((test, self.commands(block, false)?))
    }

    fn command(&mut self, command: parser::Command) -> Result<Command, CompileError> {
        let position = command.position;
        let name = command.name.as_str();
        if command.block.is_some() {
            return Err(CompileError::at(position, format!("{name} takes no block")));
        }
        if command.tests != Tests::None {
            return Err(CompileError::at(position, format!("{name} takes no test")));
        }
        let mut args = Args::new(name, position, command.arguments);
        let compiled = match name {
            "stop" => Command::Stop,
            "discard" => Command::Discard,
            "keep" => {
                let mut flags = None;
                while let Some((tag, at)) = args.tag() {
                    match tag.as_str() {
                        "flags" if flags.is_none() => flags = Some(self.flags_argument(&mut args, at)?),
                        _ => return Err(args.error(at, format!("':{tag}' is not known here"))),
                    }
                }
                Command::Keep { flags }
            }
            "fileinto" => {
                self.need("fileinto", position, "fileinto")?;
                let (mut flags, mut create, mut copy) = (None, false, false);
                while let Some((tag, at)) = args.tag() {
                    match tag.as_str() {
                        "flags" if flags.is_none() => flags = Some(self.flags_argument(&mut args, at)?),
                        "create" if !create => {
                            self.need("mailbox", at, ":create")?;
                            create = true;
                        }
                        "copy" if !copy => {
                            self.need("copy", at, ":copy")?;
                            copy = true;
                        }
                        _ => return Err(args.error(at, format!("':{tag}' is not known here or given twice"))),
                    }
                }
                let (mailbox, at) = args.string("the mailbox")?;
                let mailbox = self.value(mailbox, at)?;
                if mailbox.constant().is_some_and(str::is_empty) {
                    return Err(args.error(at, "the mailbox has no name"));
                }
                Command::FileInto { mailbox, flags, create, copy }
            }
            "redirect" => {
                let mut copy = false;
                while let Some((tag, at)) = args.tag() {
                    match tag.as_str() {
                        "copy" if !copy => {
                            self.need("copy", at, ":copy")?;
                            copy = true;
                        }
                        _ => return Err(args.error(at, format!("':{tag}' is not known here or given twice"))),
                    }
                }
                let (address, at) = args.string("the address")?;
                let address = self.value(address, at)?;
                if address.constant().is_some_and(|address| single_address(address).is_none()) {
                    return Err(args.error(at, "the address is not valid"));
                }
                Command::Redirect { address, copy }
            }
            "reject" | "ereject" => {
                self.need(name, position, name)?;
                let (reason, at) = args.string("the reason")?;
                Command::Reject { reason: self.value(reason, at)?, extended: name == "ereject" }
            }
            "vacation" => {
                self.need("vacation", position, "vacation")?;
                Command::Vacation(Box::new(self.vacation(&mut args)?))
            }
            "set" => {
                self.need("variables", position, "set")?;
                let mut modifiers: Vec<Modifier> = Vec::new();
                while let Some((tag, at)) = args.tag() {
                    let Some(modifier) = Modifier::from_tag(&tag) else {
                        return Err(args.error(at, format!("':{tag}' is not known here")));
                    };
                    if modifier == Modifier::EncodeUrl {
                        self.need("enotify", at, ":encodeurl")?;
                    }
                    if modifiers.iter().any(|other| other.precedence() == modifier.precedence()) {
                        return Err(args.error(at, "two modifiers of the same precedence"));
                    }
                    modifiers.push(modifier);
                }
                modifiers.sort_by_key(|modifier| std::cmp::Reverse(modifier.precedence()));
                let (variable, at) = args.string("the variable's name")?;
                let variable = self.constant(variable, at)?;
                if !strings::is_identifier(&variable) {
                    return Err(args.error(at, format!("\"{variable}\" is not a variable's name")));
                }
                let (value, at) = args.string("the value")?;
                Command::Set { name: variable.to_ascii_lowercase(), value: self.value(value, at)?, modifiers }
            }
            "setflag" | "addflag" | "removeflag" => {
                self.need("imap4flags", position, name)?;
                let op = match name {
                    "setflag" => FlagOp::Set,
                    "addflag" => FlagOp::Add,
                    _ => FlagOp::Remove,
                };
                if let Some((tag, at)) = args.tag() {
                    return Err(args.error(at, format!("':{tag}' is not known here")));
                }
                let variable = if args.left() > 1 {
                    let (variable, at) = args.string("the variable's name")?;
                    Some(self.variable_name(variable, at)?)
                } else {
                    None
                };
                let (flags, at) = args.strings("the flags")?;
                Command::Flags { op, variable, flags: self.values(flags, at)? }
            }
            "notify" => {
                self.need("enotify", position, "notify")?;
                let mut notify = NotifyCommand {
                    method: Value::Constant(String::new()),
                    from: None,
                    importance: None,
                    options: Vec::new(),
                    message: None,
                };
                let mut seen = HashSet::new();
                while let Some((tag, at)) = args.tag() {
                    if !seen.insert(tag.clone()) {
                        return Err(args.error(at, format!("':{tag}' is given twice")));
                    }
                    match tag.as_str() {
                        "from" => {
                            let (from, at) = args.string("the sender")?;
                            notify.from = Some(self.value(from, at)?);
                        }
                        "importance" => {
                            let (importance, at) = args.string("the importance")?;
                            let importance = self.value(importance, at)?;
                            if importance.constant().is_some_and(|i| !matches!(i, "1" | "2" | "3")) {
                                return Err(args.error(at, "the importance is \"1\", \"2\" or \"3\""));
                            }
                            notify.importance = Some(importance);
                        }
                        "options" => {
                            let (options, at) = args.strings("the options")?;
                            notify.options = self.values(options, at)?;
                        }
                        "message" => {
                            let (message, at) = args.string("the message")?;
                            notify.message = Some(self.value(message, at)?);
                        }
                        _ => return Err(args.error(at, format!("':{tag}' is not known here"))),
                    }
                }
                let (method, at) = args.string("the method")?;
                notify.method = self.value(method, at)?;
                if notify.method.constant().is_some_and(|method| !valid_uri(method)) {
                    return Err(args.error(at, "the method is not a URI"));
                }
                Command::Notify(Box::new(notify))
            }
            _ => return Err(CompileError::at(position, format!("the command '{name}' is not known"))),
        };
        args.done()?;
        Ok(compiled)
    }

    fn flags_argument(&self, args: &mut Args, at: Position) -> Result<Vec<Value>, CompileError> {
        self.need("imap4flags", at, ":flags")?;
        let (flags, at) = args.strings("the flags")?;
        self.values(flags, at)
    }

    fn variable_name(&self, name: String, at: Position) -> Result<String, CompileError> {
        self.need("variables", at, "a variable's name")?;
        let name = self.constant(name, at)?;
        if !strings::is_identifier(&name) {
            return Err(CompileError::at(at, format!("\"{name}\" is not a variable's name")));
        }
        Ok(name.to_ascii_lowercase())
    }

    fn vacation(&self, args: &mut Args) -> Result<VacationCommand, CompileError> {
        let mut vacation = VacationCommand {
            seconds: 7 * 86_400,
            subject: None,
            from: None,
            addresses: Vec::new(),
            mime: false,
            handle: None,
            reason: Value::Constant(String::new()),
        };
        let mut seen = HashSet::new();
        while let Some((tag, at)) = args.tag() {
            let period = matches!(tag.as_str(), "days" | "seconds");
            if !seen.insert(if period { "period".to_owned() } else { tag.clone() }) {
                return Err(args.error(at, format!("':{tag}' is given twice, or with ':days'/':seconds'")));
            }
            match tag.as_str() {
                // At least a day, at most a year (RFC 5230, 4.1); the seconds of RFC 6131 at least a minute.
                "days" => vacation.seconds = args.number("the days")?.clamp(1, 365) * 86_400,
                "seconds" => {
                    self.need("vacation-seconds", at, ":seconds")?;
                    vacation.seconds = args.number("the seconds")?.clamp(60, 365 * 86_400);
                }
                "subject" => {
                    let (subject, at) = args.string("the subject")?;
                    vacation.subject = Some(self.value(subject, at)?);
                }
                "from" => {
                    let (from, at) = args.string("the sender")?;
                    let from = self.value(from, at)?;
                    if from.constant().is_some_and(|from| single_address(from).is_none()) {
                        return Err(args.error(at, "the sender is not a valid address"));
                    }
                    vacation.from = Some(from);
                }
                "addresses" => {
                    let (addresses, at) = args.strings("the addresses")?;
                    vacation.addresses = self.values(addresses, at)?;
                }
                "mime" => vacation.mime = true,
                "handle" => {
                    let (handle, at) = args.string("the handle")?;
                    vacation.handle = Some(self.value(handle, at)?);
                }
                _ => return Err(args.error(at, format!("':{tag}' is not known here"))),
            }
        }
        let (reason, at) = args.string("the reason")?;
        vacation.reason = self.value(reason, at)?;
        Ok(vacation)
    }

    /// Takes `tag` if it is one of the shared tags the test allows; `false` if it is not.
    fn common(
        &self,
        common: &mut Common,
        tag: &str,
        at: Position,
        args: &mut Args,
        address_parts: bool,
        index: bool,
    ) -> Result<bool, CompileError> {
        let twice = || args.error(at, format!("':{tag}' is given twice, or with another of its kind"));
        match tag {
            "is" | "contains" | "matches" | "count" | "value" => {
                if common.kind.is_some() {
                    return Err(twice());
                }
                common.kind = Some(match tag {
                    "is" => MatchType::Is,
                    "contains" => MatchType::Contains,
                    "matches" => MatchType::Matches,
                    _ => {
                        self.need("relational", at, &format!(":{tag}"))?;
                        let (relation, at) = args.string("the relation")?;
                        let relation = self.constant(relation, at)?;
                        let relation = Relation::from_name(&relation)
                            .ok_or_else(|| args.error(at, format!("\"{relation}\" is no relation")))?;
                        if tag == "count" { MatchType::Count(relation) } else { MatchType::Value(relation) }
                    }
                });
            }
            "comparator" => {
                if common.comparator.is_some() {
                    return Err(twice());
                }
                let (name, at) = args.string("the comparator")?;
                let name = self.constant(name, at)?;
                let comparator =
                    Comparator::from_name(&name).ok_or_else(|| args.error(at, format!("\"{name}\" is not known")))?;
                if comparator == Comparator::AsciiNumeric {
                    self.need("comparator-i;ascii-numeric", at, "the comparator")?;
                }
                common.comparator = Some(comparator);
            }
            "all" | "localpart" | "domain" | "user" | "detail" if address_parts => {
                if common.part.is_some() {
                    return Err(twice());
                }
                common.part = Some(match tag {
                    "all" => AddressPart::All,
                    "localpart" => AddressPart::LocalPart,
                    "domain" => AddressPart::Domain,
                    _ => {
                        self.need("subaddress", at, &format!(":{tag}"))?;
                        if tag == "user" { AddressPart::User } else { AddressPart::Detail }
                    }
                });
            }
            "index" if index => {
                self.need("index", at, ":index")?;
                if common.index.is_some() {
                    return Err(twice());
                }
                let n = args.number("the index")?;
                if n == 0 {
                    return Err(args.error(at, "the index counts from 1"));
                }
                common.index = Some(n);
            }
            "last" if index => {
                self.need("index", at, ":last")?;
                if common.last {
                    return Err(twice());
                }
                common.last = true;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn finish(&self, common: Common, position: Position) -> Result<(Matcher, AddressPart, Index), CompileError> {
        let matcher = Matcher {
            kind: common.kind.unwrap_or(MatchType::Is),
            comparator: common.comparator.unwrap_or(Comparator::AsciiCaseMap),
        };
        if matcher.comparator == Comparator::AsciiNumeric
            && matches!(matcher.kind, MatchType::Contains | MatchType::Matches)
        {
            return Err(CompileError::at(position, "i;ascii-numeric only compares whole values"));
        }
        if common.last && common.index.is_none() {
            return Err(CompileError::at(position, ":last needs :index"));
        }
        let index = common.index.map(|n| (usize::try_from(n).unwrap_or(usize::MAX), common.last));
        Ok((matcher, common.part.unwrap_or(AddressPart::All), index))
    }

    fn header_names(&self, args: &mut Args) -> Result<Vec<Value>, CompileError> {
        let (names, at) = args.strings("the header names")?;
        let names = self.values(names, at)?;
        for name in &names {
            if let Some(name) = name.constant()
                && !valid_field_name(name)
            {
                return Err(args.error(at, format!("\"{name}\" is not a header name")));
            }
        }
        Ok(names)
    }

    fn keys(&self, args: &mut Args) -> Result<Vec<Value>, CompileError> {
        let (keys, at) = args.strings("the keys")?;
        self.values(keys, at)
    }

    fn zone(&self, args: &mut Args) -> Result<Zone, CompileError> {
        let (zone, at) = args.string("the zone")?;
        let zone = self.constant(zone, at)?;
        parse_zone(&zone).map(Zone::Fixed).ok_or_else(|| args.error(at, format!("\"{zone}\" is no zone like +0100")))
    }

    fn date_part(&self, args: &mut Args) -> Result<DatePart, CompileError> {
        let (part, at) = args.string("the date part")?;
        let part = self.constant(part, at)?;
        DatePart::from_name(&part).ok_or_else(|| args.error(at, format!("\"{part}\" is not a date part")))
    }

    fn test(&mut self, test: parser::Test) -> Result<Test, CompileError> {
        let position = test.position;
        let name = test.name.as_str();
        match (name, test.tests) {
            ("not", Tests::One(inner)) if test.arguments.is_empty() => {
                return Ok(Test::Not(Box::new(self.test(*inner)?)));
            }
            ("allof" | "anyof", Tests::List(tests)) if test.arguments.is_empty() => {
                let tests = tests.into_iter().map(|test| self.test(test)).collect::<Result<Vec<_>, _>>()?;
                return Ok(if name == "allof" { Test::AllOf(tests) } else { Test::AnyOf(tests) });
            }
            ("not", _) => return Err(CompileError::at(position, "not takes one test")),
            ("allof" | "anyof", _) => return Err(CompileError::at(position, format!("{name} takes a list of tests"))),
            (_, Tests::None) => {}
            _ => return Err(CompileError::at(position, format!("{name} takes no tests"))),
        }
        let mut args = Args::new(name, position, test.arguments);
        let mut common = Common::default();
        let compiled = match name {
            "true" => Test::True,
            "false" => Test::False,
            "exists" => Test::Exists(self.header_names(&mut args)?),
            "size" => {
                let over = match args.tag() {
                    Some((tag, _)) if tag == "over" => true,
                    Some((tag, _)) if tag == "under" => false,
                    _ => return Err(args.error(position, "size needs :over or :under")),
                };
                Test::Size { over, limit: args.number("the limit")? }
            }
            "header" | "address" | "envelope" | "string" | "body" | "hasflag" => {
                let gate = match name {
                    "envelope" => Some("envelope"),
                    "string" => Some("variables"),
                    "body" => Some("body"),
                    "hasflag" => Some("imap4flags"),
                    _ => None,
                };
                if let Some(gate) = gate {
                    self.need(gate, position, name)?;
                }
                let parts = matches!(name, "address" | "envelope");
                let index = matches!(name, "header" | "address");
                let mut transform = None;
                while let Some((tag, at)) = args.tag() {
                    if self.common(&mut common, &tag, at, &mut args, parts, index)? {
                        continue;
                    }
                    match tag.as_str() {
                        "raw" | "text" | "content" if name == "body" && transform.is_none() => {
                            transform = Some(match tag.as_str() {
                                "raw" => BodyTransform::Raw,
                                "text" => BodyTransform::Text,
                                _ => {
                                    let (types, at) = args.strings("the content types")?;
                                    let types = types
                                        .into_iter()
                                        .map(|t| self.constant(t, at))
                                        .collect::<Result<Vec<_>, _>>()?;
                                    BodyTransform::Content(types)
                                }
                            });
                        }
                        _ => return Err(args.error(at, format!("':{tag}' is not known here or given twice"))),
                    }
                }
                let (matcher, part, index) = self.finish(common, position)?;
                match name {
                    "header" => {
                        let names = self.header_names(&mut args)?;
                        Test::Header { names, keys: self.keys(&mut args)?, matcher, index }
                    }
                    "address" => {
                        let names = self.header_names(&mut args)?;
                        Test::Address { names, keys: self.keys(&mut args)?, matcher, part, index }
                    }
                    "envelope" => {
                        let (parts, at) = args.strings("the envelope parts")?;
                        let parts = self.values(parts, at)?;
                        for part in parts.iter().filter_map(Value::constant) {
                            if !part.eq_ignore_ascii_case("from") && !part.eq_ignore_ascii_case("to") {
                                return Err(args.error(at, format!("the envelope part \"{part}\" is not known")));
                            }
                        }
                        Test::Envelope { parts, keys: self.keys(&mut args)?, matcher, part }
                    }
                    "string" => {
                        let (sources, at) = args.strings("the source strings")?;
                        Test::String { sources: self.values(sources, at)?, keys: self.keys(&mut args)?, matcher }
                    }
                    "body" => Test::Body {
                        transform: transform.unwrap_or(BodyTransform::Text),
                        keys: self.keys(&mut args)?,
                        matcher,
                    },
                    _ => {
                        let variables = if args.left() > 1 {
                            let (names, at) = args.strings("the variables")?;
                            names.into_iter().map(|name| self.variable_name(name, at)).collect::<Result<_, _>>()?
                        } else {
                            Vec::new()
                        };
                        Test::HasFlag { variables, keys: self.keys(&mut args)?, matcher }
                    }
                }
            }
            "date" | "currentdate" => {
                self.need("date", position, name)?;
                let mut zone = None;
                while let Some((tag, at)) = args.tag() {
                    if self.common(&mut common, &tag, at, &mut args, false, name == "date")? {
                        continue;
                    }
                    match tag.as_str() {
                        "zone" if zone.is_none() => zone = Some(self.zone(&mut args)?),
                        "originalzone" if zone.is_none() && name == "date" => zone = Some(Zone::Original),
                        _ => return Err(args.error(at, format!("':{tag}' is not known here or given twice"))),
                    }
                }
                let (matcher, _, index) = self.finish(common, position)?;
                let zone = zone.unwrap_or(Zone::Local);
                if name == "date" {
                    let (header, at) = args.string("the header name")?;
                    let header = self.value(header, at)?;
                    if header.constant().is_some_and(|name| !valid_field_name(name)) {
                        return Err(args.error(at, "not a header name"));
                    }
                    let part = self.date_part(&mut args)?;
                    Test::Date { name: header, part, zone, keys: self.keys(&mut args)?, matcher, index }
                } else {
                    let part = self.date_part(&mut args)?;
                    Test::CurrentDate { part, zone, keys: self.keys(&mut args)?, matcher }
                }
            }
            "mailboxexists" => {
                self.need("mailbox", position, name)?;
                let (names, at) = args.strings("the mailboxes")?;
                Test::MailboxExists(self.values(names, at)?)
            }
            "duplicate" => {
                self.need("duplicate", position, name)?;
                let (mut handle, mut source, mut seconds, mut last) = (None, None, None, false);
                while let Some((tag, at)) = args.tag() {
                    match tag.as_str() {
                        "handle" if handle.is_none() => {
                            let (text, at) = args.string("the handle")?;
                            handle = Some(self.value(text, at)?);
                        }
                        "header" if source.is_none() => {
                            let (text, at) = args.string("the header name")?;
                            source = Some(DuplicateSource::Header(self.value(text, at)?));
                        }
                        "uniqueid" if source.is_none() => {
                            let (text, at) = args.string("the unique id")?;
                            source = Some(DuplicateSource::UniqueId(self.value(text, at)?));
                        }
                        "seconds" if seconds.is_none() => seconds = Some(args.number("the seconds")?),
                        "last" if !last => last = true,
                        _ => return Err(args.error(at, format!("':{tag}' is not known here or given twice"))),
                    }
                }
                Test::Duplicate {
                    handle,
                    source: source.unwrap_or(DuplicateSource::Header(Value::Constant("Message-ID".into()))),
                    // A week, at most a year.
                    seconds: seconds.unwrap_or(7 * 86_400).min(365 * 86_400),
                    last,
                }
            }
            "valid_notify_method" => {
                self.need("enotify", position, name)?;
                let (uris, at) = args.strings("the URIs")?;
                Test::ValidNotifyMethod(self.values(uris, at)?)
            }
            "notify_method_capability" => {
                self.need("enotify", position, name)?;
                while let Some((tag, at)) = args.tag() {
                    if !self.common(&mut common, &tag, at, &mut args, false, false)? {
                        return Err(args.error(at, format!("':{tag}' is not known here")));
                    }
                }
                let (matcher, _, _) = self.finish(common, position)?;
                let (uri, at) = args.string("the URI")?;
                let uri = self.value(uri, at)?;
                let (capability, at) = args.string("the capability")?;
                let capability = self.value(capability, at)?;
                Test::NotifyMethodCapability { uri, capability, keys: self.keys(&mut args)?, matcher }
            }
            _ => return Err(CompileError::at(position, format!("the test '{name}' is not known"))),
        };
        args.done()?;
        Ok(compiled)
    }
}

/// A header field's name (RFC 5322, 3.6.8): printable ASCII without a colon.
pub(crate) fn valid_field_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| (33..=126).contains(&b) && b != b':')
}

/// `+hhmm` or `-hhmm`, in seconds east of UTC.
pub(crate) fn parse_zone(zone: &str) -> Option<i32> {
    let bytes = zone.as_bytes();
    if bytes.len() != 5 || !matches!(bytes[0], b'+' | b'-') || !bytes[1..].iter().all(u8::is_ascii_digit) {
        return None;
    }
    let hours: i32 = zone[1..3].parse().ok()?;
    let minutes: i32 = zone[3..5].parse().ok()?;
    if hours > 23 || minutes > 59 {
        return None;
    }
    let seconds = hours * 3600 + minutes * 60;
    Some(if bytes[0] == b'-' { -seconds } else { seconds })
}

/// A URI as far as a notification method needs (RFC 3986, 3.1): a scheme, a colon and something after it.
pub(crate) fn valid_uri(uri: &str) -> bool {
    match uri.split_once(':') {
        Some((scheme, rest)) => {
            scheme.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
                && scheme.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
                && !rest.is_empty()
                && !rest.chars().any(|c| c.is_whitespace() || c.is_control())
        }
        None => false,
    }
}
