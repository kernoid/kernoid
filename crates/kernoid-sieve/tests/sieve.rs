// SPDX-License-Identifier: AGPL-3.0-or-later
//! The language and its extensions, command by command and test by test, with the examples of the RFCs.

use kernoid_sieve::{Action, Context, Environment, Limits, Outcome, Script};

const MESSAGE: &str = "Return-Path: <coyote@desert.example.org>\r\n\
Received: from a.example by mx.example; Fri, 18 Jan 2008 15:30:20 +0100\r\n\
Date: Fri, 18 Jan 2008 07:30:20 -0800\r\n\
From: \"Wile E. Coyote\" <coyote@desert.example.org>\r\n\
Sender: owner-ietf-mta-filters@imc.org\r\n\
To: roadrunner+birds@acme.example.com, me@example.com\r\n\
Cc: friends: a@x.example, b@y.example;\r\n\
Subject: I have a present for you\r\n\
Message-ID: <present@desert.example.org>\r\n\
List-ID: Coyotes <coyotes@lists.example.org>\r\n\
X-Caffeine: C8H10N4O2\r\n\
X-Priority: 1\r\n\
X-Priority: 5\r\n\
\r\n\
Look, I'm sorry about the whole anvil thing, and I really\r\n\
didn't mean to try and drop it on you from the top of the\r\n\
cliff.  I want to try to make it up to you.\r\n";

#[derive(Default)]
struct Env {
    mailboxes: Vec<String>,
    seen: Vec<String>,
}

impl Environment for Env {
    fn mailbox_exists(&self, name: &str) -> bool {
        name == "INBOX" || self.mailboxes.iter().any(|known| known == name)
    }

    fn duplicate(&mut self, key: &str, _: u64, _: bool) -> bool {
        if self.seen.iter().any(|seen| seen == key) {
            return true;
        }
        self.seen.push(key.to_owned());
        false
    }
}

fn context() -> Context<'static> {
    Context {
        envelope_from: "coyote@desert.example.org",
        envelope_to: "roadrunner+birds@acme.example.com",
        user_addresses: vec!["roadrunner@acme.example.com".into()],
        // 2008-01-18 15:30:20 UTC.
        now: 1_200_670_220,
        zone: 0,
    }
}

fn compile(script: &str) -> Script {
    Script::compile(script, &Limits::default()).unwrap_or_else(|error| panic!("{error}\n{script}"))
}

fn run_on(script: &str, message: &str) -> Outcome {
    compile(script).run(message.as_bytes(), &context(), &mut Env::default()).unwrap()
}

fn actions(script: &str) -> Vec<Action> {
    run_on(script, MESSAGE).actions
}

fn keep() -> Action {
    Action::Keep { flags: vec![] }
}

fn file(mailbox: &str) -> Action {
    Action::FileInto { mailbox: mailbox.into(), flags: vec![], create: false, copy: false }
}

/// Whether `test` holds on [`MESSAGE`], with `require` for the extensions it needs.
fn holds(require: &str, test: &str) -> bool {
    let require = if require.is_empty() { String::new() } else { format!("require [{require}];") };
    let script = format!("{require} if {test} {{ discard; }}");
    actions(&script).is_empty()
}

fn error(script: &str) -> String {
    Script::compile(script, &Limits::default()).unwrap_err().to_string()
}

#[test]
fn the_implicit_keep_discard_and_stop() {
    assert_eq!(actions(""), [keep()]);
    assert_eq!(actions("# nothing\r\n/* at all */"), [keep()]);
    assert_eq!(actions("keep;"), [keep()]);
    assert!(actions("discard;").is_empty());
    // An explicit keep stays after a discard.
    assert_eq!(actions("keep; discard;"), [keep()]);
    assert!(actions("discard; stop; keep;").is_empty());
    assert_eq!(actions("stop; discard;"), [keep()]);
}

#[test]
fn if_elsif_else() {
    let script = |test: &str| {
        format!(
            "require \"fileinto\"; if {test} {{ fileinto \"a\"; }} elsif true {{ fileinto \"b\"; }} else {{ fileinto \"c\"; }}"
        )
    };
    assert_eq!(actions(&script("true")), [file("a")]);
    assert_eq!(actions(&script("false")), [file("b")]);
    assert_eq!(actions("require \"fileinto\"; if false { } elsif false { } else { fileinto \"c\"; }"), [file("c")]);
    assert_eq!(actions("if false { discard; } if true { discard; }"), []);
    assert!(error("else { keep; }").contains("else must follow if or elsif"));
    assert!(error("if true { } else { } else { }").contains("must follow if"));
    assert!(error("if true { } keep; elsif true { }").contains("must follow if"));
    assert!(error("if true;").contains("if needs a block"));
    assert!(error("if (true) { }").contains("if needs one test"));
    assert!(error("if true { } else true { }").contains("else takes no test"));
    assert!(error("keep { }").contains("keep takes no block"));
}

#[test]
fn rfc_5228_example_script() {
    let script = r#"
#
# Example Sieve Filter
# Declare any optional features or extension used by the script
#
require ["fileinto"];

#
# Handle messages from known mailing lists
# Move messages from IETF filter discussion list to filter mailbox
#
if header :is "Sender" "owner-ietf-mta-filters@example.com"
        {
        fileinto "filter";  # move to "filter" mailbox
        }
#
# Keep all messages to or from people in my company
#
elsif address :DOMAIN :is ["From", "To"] "example.com"
        {
        keep;               # keep in "In" mailbox
        }

#
# Try and catch unsolicited email.  If a message is not to me,
# or it contains a subject known to be spam, file it away.
#
elsif anyof (NOT address :all :contains
               ["To", "Cc", "Bcc"] "me@example.com",
             header :matches "subject"
               ["*make*money*fast*", "*university*dipl*mas*"])
        {
        fileinto "spam";   # move to "spam" mailbox
        }
else
        {
        # Move all other (non-company) mail to "personal"
        # mailbox.
        fileinto "personal";
        }
"#;
    let message = |sender: &str, to: &str, subject: &str| {
        format!(
            "Sender: {sender}\r\nFrom: someone@else.example\r\nTo: x@else.example\r\nCc: {to}\r\nSubject: {subject}\r\n\r\nHi\r\n"
        )
    };
    let run = |m: String| run_on(script, &m).actions;
    assert_eq!(run(message("owner-ietf-mta-filters@example.com", "x@y.example", "Hi")), [file("filter")]);
    let company = "Sender: a@b.example\r\nFrom: boss@example.com\r\nTo: x@else.example\r\n\r\nHi\r\n";
    assert_eq!(run(company.to_owned()), [keep()]);
    assert_eq!(run(message("a@b.example", "other@else.example", "Hi")), [file("spam")]);
    assert_eq!(run(message("a@b.example", "me@example.org, me@example.com", "MAKE big MONEY fast")), [file("spam")]);
    assert_eq!(run(message("a@b.example", "me@example.com", "Lunch")), [file("personal")]);
}

#[test]
fn require_and_unknown_things() {
    assert!(error("fileinto \"x\";").contains("fileinto needs require \"fileinto\""));
    assert!(error("require \"nonsense\";").contains("the capability \"nonsense\" is not supported"));
    assert!(error("require \"regex\";").contains("not supported"));
    assert!(error("keep; require \"fileinto\";").contains("require must come before any other command"));
    assert!(error("if true { require \"fileinto\"; }").contains("require must come before"));
    assert!(error("frobnicate;").contains("the command 'frobnicate' is not known"));
    assert!(error("if frobnicate { }").contains("the test 'frobnicate' is not known"));
    assert!(error("if true false { }").contains("true takes no tests"));
    assert!(error("keep :frob;").contains("':frob' is not known here"));
    assert!(error("discard \"x\";").contains("too many arguments"));
    assert!(error("this is not sieve").contains("line 1, column"));
    // Capabilities are case-insensitive, and so are commands and tags.
    assert_eq!(actions("REQUIRE \"FileInto\"; FILEINTO \"x\";"), [file("x")]);
    let capabilities = kernoid_sieve::CAPABILITIES.iter().map(|c| format!("\"{c}\"")).collect::<Vec<_>>().join(", ");
    compile(&format!("require [{capabilities}];"));
}

#[test]
fn errors_say_line_and_column() {
    assert_eq!(
        error("require \"fileinto\";\r\nif header :is \"subject\" \"x\" {\r\n  fileinto;\r\n}"),
        "line 3, column 3: fileinto: the mailbox is missing"
    );
    assert_eq!(
        error("if size :over 10 {\n  keep\n}"),
        "line 3, column 1: ';' or a block after 'keep' was expected, not '}'"
    );
    assert_eq!(
        error("if header :is :contains \"a\" \"b\" {}"),
        "line 1, column 15: header: ':contains' is given twice, or with another of its kind"
    );
    assert_eq!(error("redirect \"not an address\";"), "line 1, column 10: redirect: the address is not valid");
}

#[test]
fn header_with_comparators_and_match_types() {
    assert!(holds("", r#"header :is "Subject" "I have a present for you""#));
    assert!(holds("", r#"header :is "subject" "I HAVE A PRESENT FOR YOU""#));
    assert!(!holds("", r#"header :comparator "i;octet" :is "subject" "I HAVE A PRESENT FOR YOU""#));
    assert!(holds("", r#"header :contains ["X-Nothing", "Subject"] "present""#));
    assert!(!holds("", r#"header :contains "X-Nothing" """#));
    assert!(holds("", r#"header :matches "Subject" "I have*for ?ou""#));
    assert!(!holds("", r#"header :matches "Subject" "have*""#));
    assert!(holds("", r#"header :is "x-priority" ["5"]"#));
    // RFC 5228, 5.7: a header that exists with an empty key.
    assert!(holds("", r#"header :contains "X-Caffeine" """#));
    assert!(error("if header :is \"bad:name\" \"x\" {}").contains("is not a header name"));
    assert!(error("if header :comparator \"i;fancy\" \"a\" \"b\" {}").contains("\"i;fancy\" is not known"));
    assert!(error("if header :comparator \"i;ascii-numeric\" \"a\" \"b\" {}").contains("needs require"));
    assert!(
        error(
            "require \"comparator-i;ascii-numeric\"; if header :contains :comparator \"i;ascii-numeric\" \"a\" \"b\" {}"
        )
        .contains("only compares whole values")
    );
}

#[test]
fn address_and_envelope() {
    assert!(holds("", r#"address :is "from" "coyote@desert.example.org""#));
    assert!(holds("", r#"address :localpart "from" "COYOTE""#));
    assert!(holds("", r#"address :domain :is "from" "desert.example.org""#));
    assert!(holds("", r#"address :all :is "cc" "b@y.example""#));
    assert!(!holds("", r#"address :is "from" "Wile E. Coyote""#));
    assert!(holds("\"envelope\"", r#"envelope :domain "from" "desert.example.org""#));
    assert!(holds("\"envelope\"", r#"envelope :is "to" "roadrunner+birds@acme.example.com""#));
    assert!(!holds("\"envelope\"", r#"envelope :is "from" "someone@else""#));
    assert!(error("if envelope \"from\" \"x\" {}").contains("needs require \"envelope\""));
    assert!(error("require \"envelope\"; if envelope \"auth\" \"x\" {}").contains("not known"));
    // A bounce: the empty sender.
    let bounce = Context { envelope_from: "", ..context() };
    let script = compile("require \"envelope\"; if envelope :all :is \"from\" \"\" { discard; }");
    assert!(script.run(MESSAGE.as_bytes(), &bounce, &mut ()).unwrap().actions.is_empty());
}

#[test]
fn subaddress() {
    assert!(holds("\"subaddress\"", r#"address :user "to" "roadrunner""#));
    assert!(holds("\"subaddress\"", r#"address :detail "to" "birds""#));
    assert!(holds("\"subaddress\", \"envelope\"", r#"envelope :detail "to" "birds""#));
    // Without a detail, :detail sees nothing.
    assert!(!holds("\"subaddress\"", r#"address :detail :matches "from" "*""#));
    assert!(error("if address :user \"to\" \"x\" {}").contains("needs require \"subaddress\""));
}

#[test]
fn exists_size_and_logic() {
    assert!(holds("", r#"exists ["From", "X-Caffeine"]"#));
    assert!(!holds("", r#"exists ["From", "X-Decaf"]"#));
    let size = MESSAGE.len();
    assert!(holds("", &format!("size :over {}", size - 1)));
    assert!(!holds("", &format!("size :over {size}")));
    assert!(holds("", &format!("size :under {}", size + 1)));
    assert!(!holds("", "size :under 1"));
    assert!(holds("", "size :under 1M"));
    assert!(error("if size 10 {}").contains("size needs :over or :under"));
    assert!(holds("", "allof (true, not false, anyof (false, true))"));
    assert!(!holds("", "allof (true, false)"));
    assert!(!holds("", "anyof (false, false)"));
    assert!(holds("", "not not true"));
    assert!(error("if allof true {}").contains("allof takes a list of tests"));
    assert!(error("if not (true, false) {}").contains("not takes one test"));
}

#[test]
fn fileinto_copy_and_mailbox() {
    assert_eq!(actions("require \"fileinto\"; fileinto \"Lists/dev\";"), [file("Lists/dev")]);
    assert_eq!(
        actions("require [\"fileinto\", \"copy\"]; fileinto :copy \"Archive\";"),
        [Action::FileInto { mailbox: "Archive".into(), flags: vec![], create: false, copy: true }, keep()]
    );
    assert_eq!(
        actions("require [\"fileinto\", \"mailbox\"]; fileinto :create \"New\";"),
        [Action::FileInto { mailbox: "New".into(), flags: vec![], create: true, copy: false }]
    );
    assert!(error("require \"fileinto\"; fileinto :create \"x\";").contains("needs require \"mailbox\""));
    assert!(error("require \"fileinto\"; fileinto :copy \"x\";").contains("needs require \"copy\""));
    assert!(error("require \"fileinto\"; fileinto \"\";").contains("no name"));

    let script = compile("require \"mailbox\"; if mailboxexists [\"INBOX\", \"Work\"] { discard; }");
    let mut env = Env::default();
    assert_eq!(script.run(MESSAGE.as_bytes(), &context(), &mut env).unwrap().actions, [keep()]);
    env.mailboxes.push("Work".into());
    assert!(script.run(MESSAGE.as_bytes(), &context(), &mut env).unwrap().actions.is_empty());
}

#[test]
fn redirect() {
    let redirect = |address: &str, copy| Action::Redirect { address: address.into(), copy };
    assert_eq!(actions("redirect \"bob@example.org\";"), [redirect("bob@example.org", false)]);
    // The same address once.
    assert_eq!(
        actions("redirect \"bob@example.org\"; redirect \"BOB@example.org\";"),
        [redirect("bob@example.org", false)]
    );
    assert_eq!(
        actions("require \"copy\"; redirect :copy \"Bob <bob@example.org>\";"),
        [redirect("bob@example.org", true), keep()]
    );
    let many = (0..6).map(|n| format!("redirect \"r{n}@example.org\";")).collect::<String>();
    let failed = compile(&many).run(MESSAGE.as_bytes(), &context(), &mut ()).unwrap_err();
    assert_eq!(failed.to_string(), "the script redirected too often");
    // An address made at run time is checked then.
    let script = compile("require \"variables\"; set \"a\" \"nobody\"; redirect \"${a}\";");
    assert!(script.run(MESSAGE.as_bytes(), &context(), &mut ()).is_err());
}

#[test]
fn reject_and_ereject() {
    assert_eq!(
        actions("require \"reject\"; reject text:\r\nNo thanks.\r\n.\r\n;"),
        [Action::Reject { reason: "No thanks.\r\n".into(), extended: false }]
    );
    assert_eq!(
        actions("require \"ereject\"; ereject \"No.\";"),
        [Action::Reject { reason: "No.".into(), extended: true }]
    );
    assert!(error("reject \"No.\";").contains("needs require \"reject\""));
}

#[test]
fn imap4flags() {
    let flagged = |flags: &[&str]| Action::Keep { flags: flags.iter().map(|f| (*f).to_owned()).collect() };
    assert_eq!(actions("require \"imap4flags\"; setflag \"\\\\Seen\";"), [flagged(&["\\Seen"])]);
    assert_eq!(
        actions(
            "require \"imap4flags\"; setflag \"\\\\Seen\"; addflag [\"\\\\Flagged \\\\seen\", \"$Work\"]; removeflag \"\\\\SEEN\";"
        ),
        [flagged(&["\\Flagged", "$Work"])]
    );
    assert_eq!(actions("require \"imap4flags\"; addflag \"a\"; keep :flags \"b c\";"), [flagged(&["b", "c"])]);
    assert_eq!(
        actions("require [\"imap4flags\", \"fileinto\"]; addflag \"a\"; fileinto \"x\"; addflag \"b\"; keep;"),
        [
            Action::FileInto { mailbox: "x".into(), flags: vec!["a".into()], create: false, copy: false },
            flagged(&["a", "b"])
        ]
    );
    assert!(holds("\"imap4flags\"", "anyof (false, true)"));
    assert!(!holds("\"imap4flags\"", "hasflag \"\\\\Seen\""));
    assert!(actions("require \"imap4flags\"; addflag \"\\\\Seen $X\"; if hasflag :is \"$x\" { discard; }").is_empty());
    assert!(actions("require [\"imap4flags\", \"relational\", \"comparator-i;ascii-numeric\"]; addflag \"a b c\"; if hasflag :count \"eq\" :comparator \"i;ascii-numeric\" \"3\" { discard; }").is_empty());
    assert!(error("setflag \"x\";").contains("needs require \"imap4flags\""));
    assert!(error("keep :flags \"x\";").contains("needs require \"imap4flags\""));

    // RFC 5232, 7: flags kept in a variable.
    let script = r#"require ["imap4flags", "fileinto", "variables"];
        if header :contains "from" "coyote@desert.example.org" {
            setflag "flagvar" "\\Flagged";
            fileinto :flags "${flagvar}" "INBOX.From Boss";
        }
        if hasflag "flagvar" "\\flagged" { addflag "flagvar" "\\Answered"; keep :flags "${flagvar}"; }"#;
    assert_eq!(
        actions(script),
        [
            Action::FileInto {
                mailbox: "INBOX.From Boss".into(),
                flags: vec!["\\Flagged".into()],
                create: false,
                copy: false
            },
            flagged(&["\\Flagged", "\\Answered"]),
        ]
    );
}

#[test]
fn variables_rfc_5229() {
    let script = r#"require ["variables", "reject"];
set "honorific"  "Mr";
set "first_name" "Wile";
set "last_name"  "Coyote";
set "vacation" text:
Dear ${HONORIFIC} ${last_name},
I'm out, please leave a message after the meep.
.
;
reject "${vacation}";"#;
    assert_eq!(
        actions(script),
        [Action::Reject {
            reason: "Dear Mr Coyote,\r\nI'm out, please leave a message after the meep.\r\n".into(),
            extended: false
        }]
    );
    let set = |modifiers: &str, value: &str| -> String {
        let script =
            format!("require [\"variables\", \"reject\"]; set {modifiers} \"v\" \"{value}\"; reject \"${{v}}\";");
        match &actions(&script)[0] {
            Action::Reject { reason, .. } => reason.clone(),
            other => panic!("{other:?}"),
        }
    };
    assert_eq!(set(":upper", "juMBlEd lETteRS"), "JUMBLED LETTERS");
    assert_eq!(set(":lower :upperfirst", "juMBlEd lETteRS"), "Jumbled letters");
    assert_eq!(set(":upperfirst :lower", "juMBlEd lETteRS"), "Jumbled letters");
    assert_eq!(set(":quotewildcard", "Rock*"), "Rock\\*");
    assert_eq!(set(":length", "Rock*"), "5");
    assert!(error("require \"variables\"; set :lower :upper \"a\" \"b\";").contains("same precedence"));
    assert!(error("require \"variables\"; set \"a.b\" \"c\";").contains("is not a variable's name"));
    assert!(error("set \"a\" \"b\";").contains("needs require \"variables\""));
    // Without `variables`, `${…}` is text.
    assert_eq!(
        actions("require \"reject\"; reject \"${a}\";"),
        [Action::Reject { reason: "${a}".into(), extended: false }]
    );
    // Unknown variables are empty; numbers above nine are never set.
    let script = "require [\"variables\", \"reject\"]; reject \"[${nothing}${10}]\";";
    assert_eq!(actions(script), [Action::Reject { reason: "[]".into(), extended: false }]);
}

#[test]
fn match_variables() {
    let script = r#"require ["variables", "fileinto"];
        if header :matches "List-ID" "*<*@*" {
            fileinto "INBOX.lists.${2}"; stop;
        }"#;
    assert_eq!(actions(script), [file("INBOX.lists.coyotes")]);
    let script = r#"require ["variables", "fileinto"];
        if address :matches "from" "*@*.example.org" { fileinto "${0}|${1}|${2}|${3}"; }"#;
    assert_eq!(actions(script), [file("coyote@desert.example.org|coyote|desert|")]);
    // A test that fails leaves them as they were.
    let script = r#"require ["variables", "fileinto"];
        if header :matches "Subject" "I * a *" { }
        if header :matches "Subject" "nothing*" { }
        fileinto "${1}/${2}";"#;
    assert_eq!(actions(script), [file("have/present for you")]);
}

#[test]
fn string_test() {
    assert!(holds("\"variables\"", r#"string :is "a" ["b", "a"]"#));
    assert!(holds("\"variables\"", r#"string :matches "Frob" "f*b""#));
    assert!(!holds("\"variables\"", r#"string :is "" "x""#));
    // :count counts the strings that are not empty.
    assert!(holds("\"variables\", \"relational\"", r#"string :count "eq" ["a", "", "b"] "2""#));
    assert!(error("if string \"a\" \"b\" {}").contains("needs require \"variables\""));
}

#[test]
fn relational_rfc_5231() {
    let numeric = "\"relational\", \"comparator-i;ascii-numeric\"";
    assert!(holds(numeric, r#"header :value "gt" :comparator "i;ascii-numeric" "x-priority" "3""#));
    assert!(holds(numeric, r#"header :value "lt" :comparator "i;ascii-numeric" "x-priority" "3""#));
    assert!(!holds(numeric, r#"header :value "gt" :comparator "i;ascii-numeric" "x-priority" "5""#));
    assert!(holds(numeric, r#"header :count "eq" :comparator "i;ascii-numeric" "x-priority" "2""#));
    assert!(holds(numeric, r#"address :count "ge" :comparator "i;ascii-numeric" ["to", "cc"] "4""#));
    assert!(holds(numeric, r#"address :count "eq" :comparator "i;ascii-numeric" "bcc" "0""#));
    assert!(holds("\"relational\"", r#"header :value "ge" "subject" "I""#));
    assert!(error("if header :count \"eq\" \"a\" \"1\" {}").contains("needs require \"relational\""));
    assert!(error("require \"relational\"; if header :count \"about\" \"a\" \"1\" {}").contains("is no relation"));
}

#[test]
fn body_rfc_5173() {
    let multipart = "From: a@b.example\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\n\
Content-Type: text/plain\r\n\r\nPlease see the MAKE MONEY FAST attachment.\r\n--x\r\n\
Content-Type: application/pdf\r\nContent-Transfer-Encoding: base64\r\n\r\nUERG\r\n--x--\r\n";
    let holds_on =
        |test: &str| run_on(&format!("require \"body\"; if {test} {{ discard; }}"), multipart).actions.is_empty();
    assert!(holds_on(r#"body :contains "make money fast""#));
    assert!(holds_on(r#"body :text :contains "MAKE MONEY""#));
    assert!(!holds_on(r#"body :text :contains "PDF""#));
    assert!(holds_on(r#"body :content "application/pdf" :is "PDF""#));
    assert!(holds_on(r#"body :content "application" :contains "PD""#));
    assert!(holds_on(r#"body :raw :contains "UERG""#));
    assert!(!holds_on(r#"body :content "image" :contains """#));
    assert!(holds("\"body\"", r#"body :contains "anvil""#));
    assert!(error("if body \"x\" {}").contains("needs require \"body\""));
}

#[test]
fn date_currentdate_and_index_rfc_5260() {
    let date = "\"date\", \"relational\"";
    assert!(holds(date, r#"date :zone "-0800" "date" "date" "2008-01-18""#));
    assert!(holds(date, r#"date :originalzone "date" "hour" "07""#));
    assert!(holds(date, r#"date "date" "hour" "15""#));
    assert!(holds(date, r#"date :zone "+0900" "date" "weekday" "6""#));
    assert!(holds(date, r#"date "received" "time" "14:30:20""#));
    assert!(holds(date, r#"date :originalzone "received" "zone" "+0100""#));
    assert!(holds(date, r#"date :value "ge" "date" "date" "2008-01-01""#));
    assert!(!holds(date, r#"date "subject" "year" "2008""#));
    assert!(holds(date, r#"currentdate "iso8601" "2008-01-18T15:30:20+00:00""#));
    assert!(holds(date, r#"currentdate :zone "+0100" "std11" "Fri, 18 Jan 2008 16:30:20 +0100""#));
    assert!(holds(date, r#"currentdate :value "lt" "julian" "60000""#));
    // In the context's zone without :zone.
    let script = compile("require \"date\"; if currentdate \"hour\" \"16\" { discard; }");
    let berlin = Context { zone: 3600, ..context() };
    assert!(script.run(MESSAGE.as_bytes(), &berlin, &mut ()).unwrap().actions.is_empty());
    assert!(error("require \"date\"; if date \"date\" \"fortnight\" \"1\" {}").contains("is not a date part"));
    assert!(error("require \"date\"; if date :zone \"CET\" \"date\" \"year\" \"1\" {}").contains("is no zone"));
    assert!(error("require \"date\"; if currentdate :originalzone \"year\" \"1\" {}").contains("not known here"));

    let index = "\"index\"";
    assert!(holds(index, r#"header :index 1 "x-priority" "1""#));
    assert!(holds(index, r#"header :index 2 "x-priority" "5""#));
    assert!(holds(index, r#"header :index 1 :last "x-priority" "5""#));
    assert!(!holds(index, r#"header :index 3 "x-priority" "5""#));
    assert!(holds(index, r#"address :index 1 :domain "to" "acme.example.com""#));
    assert!(holds("\"index\", \"date\"", r#"date :index 1 :originalzone "received" "hour" "15""#));
    assert!(error("require \"index\"; if header :last \"a\" \"b\" {}").contains(":last needs :index"));
    assert!(error("require \"index\"; if header :index 0 \"a\" \"b\" {}").contains("counts from 1"));
    assert!(error("if header :index 1 \"a\" \"b\" {}").contains("needs require \"index\""));
}

#[test]
fn encoded_character_rfc_5228() {
    assert!(holds("\"encoded-character\"", r#"header :contains "subject" "${hex:70 72 65}sent""#));
    assert!(holds("\"encoded-character\"", r#"header :contains "subject" "${unicode:70}resent""#));
    // Only with the capability.
    assert!(!holds("", r#"header :contains "subject" "${hex:70}resent""#));
    assert!(
        error("require \"encoded-character\"; if header :is \"a\" \"${unicode:D800}\" {}")
            .contains("is not a character")
    );
}

#[test]
fn vacation_rfc_5230() {
    let plain = MESSAGE.replace("List-ID: Coyotes <coyotes@lists.example.org>\r\n", "");
    let outcome = run_on(r#"require "vacation"; vacation :days 3 :subject "Gone" "I am away.";"#, &plain).actions;
    assert_eq!(outcome.len(), 2);
    let Action::Vacation(reply) = &outcome[0] else { panic!("{outcome:?}") };
    assert_eq!(reply.to, "coyote@desert.example.org");
    assert_eq!(reply.seconds, 3 * 86_400);
    let text = String::from_utf8_lossy(&reply.message);
    assert!(
        text.contains("Subject: Gone") && text.contains("I am away.") && text.contains("Auto-Submitted: auto-replied")
    );
    assert_eq!(outcome[1], keep());

    let outcome = run_on(r#"require "vacation-seconds"; vacation :seconds 1 "Away";"#, &plain).actions;
    let Action::Vacation(reply) = &outcome[0] else { panic!("{outcome:?}") };
    assert_eq!(reply.seconds, 60);
    let outcome = run_on(r#"require "vacation"; vacation :days 0 "Away";"#, &plain).actions;
    let Action::Vacation(reply) = &outcome[0] else { panic!("{outcome:?}") };
    assert_eq!(reply.seconds, 86_400);
    // Lists are not answered: this message has a List-ID.
    assert_eq!(run_on(r#"require "vacation"; vacation "Away";"#, MESSAGE).actions, [keep()]);

    assert!(error(r#"require "vacation"; vacation :seconds 10 "x";"#).contains("needs require \"vacation-seconds\""));
    assert!(error(r#"require "vacation-seconds"; vacation :days 1 :seconds 10 "x";"#).contains("given twice"));
    assert!(error(r#"require "vacation"; vacation :from "nobody" "x";"#).contains("not a valid address"));
    let twice = compile(r#"require "vacation"; vacation "a"; vacation "b";"#);
    assert!(twice.run(plain.as_bytes(), &context(), &mut ()).is_err());
}

#[test]
fn enotify_rfc_5435() {
    let outcome = actions(
        r#"require ["enotify", "variables"];
           set :encodeurl "s" "a b";
           notify :importance "1" :message "Hi ${s}" "mailto:alice@example.org";"#,
    );
    let Action::Notify(notify) = &outcome[0] else { panic!("{outcome:?}") };
    assert_eq!(notify.method, "mailto:alice@example.org");
    assert_eq!(notify.importance, 1);
    assert_eq!(notify.message.as_deref(), Some("Hi a%20b"));
    assert_eq!(outcome[1], keep());
    assert!(holds("\"enotify\"", r#"valid_notify_method "mailto:alice@example.org""#));
    assert!(!holds("\"enotify\"", r#"valid_notify_method "xmpp:alice@example.org""#));
    assert!(holds("\"enotify\"", r#"notify_method_capability "mailto:a@b.example" "Online" "maybe""#));
    assert!(error("require \"enotify\"; notify \"no uri\";").contains("not a URI"));
    assert!(error("require \"enotify\"; notify :importance \"4\" \"mailto:a@b.example\";").contains("importance"));
}

#[test]
fn duplicate_rfc_7352() {
    let script = compile(r#"require "duplicate"; if duplicate { discard; }"#);
    let mut env = Env::default();
    assert_eq!(script.run(MESSAGE.as_bytes(), &context(), &mut env).unwrap().actions, [keep()]);
    assert!(script.run(MESSAGE.as_bytes(), &context(), &mut env).unwrap().actions.is_empty());
    let script = compile(r#"require "duplicate"; if duplicate :header "X-Missing" { discard; }"#);
    assert_eq!(script.run(MESSAGE.as_bytes(), &context(), &mut env).unwrap().actions, [keep()]);
    let unique = compile(r#"require "duplicate"; if duplicate :uniqueid "x" :handle "h" :seconds 60 { discard; }"#);
    assert_eq!(unique.run(MESSAGE.as_bytes(), &context(), &mut env).unwrap().actions, [keep()]);
    assert!(unique.run(MESSAGE.as_bytes(), &context(), &mut env).unwrap().actions.is_empty());
}

#[test]
fn limits() {
    let small = Limits { max_script_size: 10, ..Limits::default() };
    assert_eq!(
        Script::compile("keep; keep; keep;", &small).unwrap_err().to_string(),
        "the script has more than 10 bytes"
    );

    let shallow = Limits { max_nesting: 2, ..Limits::default() };
    assert!(Script::compile("if true { if true { if true { } } }", &shallow).is_err());

    // Work: many comparisons on a long value.
    let busy = Limits { max_instructions: 1000, ..Limits::default() };
    let keys = (0..2000).map(|n| format!("\"k{n}\"")).collect::<Vec<_>>().join(",");
    let script = Script::compile(&format!("if header :contains \"subject\" [{keys}] {{ discard; }}"), &busy).unwrap();
    assert_eq!(
        script.run(MESSAGE.as_bytes(), &context(), &mut ()).unwrap_err().to_string(),
        "the script did too much work"
    );

    let few = Limits { max_actions: 2, ..Limits::default() };
    let script =
        Script::compile("require \"fileinto\"; fileinto \"a\"; fileinto \"b\"; fileinto \"c\";", &few).unwrap();
    assert!(script.run(MESSAGE.as_bytes(), &context(), &mut ()).is_err());

    let vars = Limits { max_variables: 2, max_variable_size: 4, ..Limits::default() };
    let script =
        Script::compile("require [\"variables\", \"reject\"]; set \"a\" \"123456\"; reject \"${a}\";", &vars).unwrap();
    assert_eq!(
        script.run(MESSAGE.as_bytes(), &context(), &mut ()).unwrap().actions,
        [Action::Reject { reason: "1234".into(), extended: false }]
    );
    let script =
        Script::compile("require \"variables\"; set \"a\" \"1\"; set \"b\" \"2\"; set \"c\" \"3\";", &vars).unwrap();
    assert!(script.run(MESSAGE.as_bytes(), &context(), &mut ()).is_err());

    let strings = Limits { max_string_size: 8, ..Limits::default() };
    let script =
        Script::compile("require [\"variables\", \"reject\"]; set \"a\" \"12345\"; reject \"${a}${a}${a}\";", &strings)
            .unwrap();
    assert_eq!(
        script.run(MESSAGE.as_bytes(), &context(), &mut ()).unwrap().actions,
        [Action::Reject { reason: "12345123".into(), extended: false }]
    );
}

#[test]
fn a_message_that_does_not_parse_still_runs() {
    let outcome = compile("if header :contains \"subject\" \"x\" { discard; }")
        .run(b"\x00\x01 not mail", &context(), &mut ())
        .unwrap();
    assert_eq!(outcome.actions, [keep()]);
}
