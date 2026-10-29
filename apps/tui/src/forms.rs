// SPDX-License-Identifier: MIT
//! Events and contacts written in the user's editor, like messages (`compose`): header lines, a blank line, then the
//! text – the description of an event, the note of a contact. Lines starting with `#` are hints and are ignored.

use chrono::{NaiveDate, NaiveDateTime};

use crate::jmap::{
    calendars::{EventForm, FREQUENCIES},
    contacts::{CONTEXTS, CardForm, FEATURES, Labelled},
};

/// The header lines and the text after the first blank line; `#` lines left out.
fn split(text: &str) -> Result<(Vec<(String, String)>, String), String> {
    let (header, body) = text.split_once("\n\n").unwrap_or((text, ""));
    let mut fields = Vec::new();
    for line in header.lines().filter(|line| !line.trim_start().starts_with('#') && !line.trim().is_empty()) {
        let (name, value) = line.split_once(':').ok_or_else(|| format!("not a header line: {line}"))?;
        fields.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }
    Ok((fields, body.trim_end().to_owned()))
}

fn time(text: &str) -> Result<NaiveDateTime, String> {
    let text = text.trim();
    NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M")
        .or_else(|_| NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M"))
        .or_else(|_| {
            NaiveDate::parse_from_str(text, "%Y-%m-%d").map(|date| date.and_hms_opt(0, 0, 0).unwrap_or_default())
        })
        .map_err(|_| format!("not a time (YYYY-MM-DD HH:MM): {text}"))
}

fn yes(text: &str) -> Result<bool, String> {
    match text.trim().to_ascii_lowercase().as_str() {
        "yes" | "y" | "true" | "ja" => Ok(true),
        "no" | "n" | "false" | "nein" | "" => Ok(false),
        other => Err(format!("yes or no, not {other}")),
    }
}

/// The text the editor opens with for an event in `calendar`; `calendars` are the names to choose from.
pub fn render_event(form: &EventForm, calendar: &str, calendars: &[String]) -> String {
    let format = if form.all_day { "%Y-%m-%d" } else { "%Y-%m-%d %H:%M" };
    let mut out = String::new();
    out.push_str(&format!("Title: {}\n", form.title));
    out.push_str(&format!("Calendar: {calendar}\n"));
    if calendars.len() > 1 {
        out.push_str(&format!("# Calendars: {}\n", calendars.join(", ")));
    }
    out.push_str(&format!("Start: {}\n", form.start.format(format)));
    out.push_str(&format!("End: {}\n", form.end.format(format)));
    out.push_str(&format!("All day: {}\n", if form.all_day { "yes" } else { "no" }));
    out.push_str(&format!("Time zone: {}\n", form.time_zone.clone().unwrap_or_default()));
    out.push_str(&format!("Repeat: {}\n", form.repeat.clone().unwrap_or_else(|| "none".into())));
    out.push_str(&format!("# Repeat: none, {}\n", FREQUENCIES.join(", ")));
    out.push_str(&format!("Location: {}\n", form.location));
    out.push_str(&format!("Participants: {}\n", form.participants.join(", ")));
    out.push_str("# Participants are invited by email; the description follows the blank line.\n\n");
    out.push_str(&form.description);
    if !form.description.is_empty() {
        out.push('\n');
    }
    out
}

/// Reads back an event: the form and the name of the calendar chosen.
pub fn parse_event(text: &str, form: &EventForm) -> Result<(EventForm, String), String> {
    let (fields, body) = split(text)?;
    let mut out = form.clone();
    let mut calendar = String::new();
    let (mut start, mut end) = (None, None);
    for (name, value) in fields {
        match name.as_str() {
            "title" => out.title = value,
            "calendar" => calendar = value,
            "start" => start = Some(time(&value)?),
            "end" => end = Some(time(&value)?),
            "all day" => out.all_day = yes(&value)?,
            "time zone" => out.time_zone = (!value.is_empty()).then_some(value),
            "repeat" => {
                let value = value.to_ascii_lowercase();
                out.repeat = match value.as_str() {
                    "" | "none" | "no" => None,
                    frequency if FREQUENCIES.contains(&frequency) => Some(value),
                    other => return Err(format!("repeat: none or {}, not {other}", FREQUENCIES.join(", "))),
                }
            }
            "location" => out.location = value,
            "participants" => {
                out.participants =
                    value.split([',', ';']).map(|p| p.trim().to_owned()).filter(|p| !p.is_empty()).collect();
                if let Some(bad) = out.participants.iter().find(|p| !p.contains('@')) {
                    return Err(format!("not an address: {bad}"));
                }
            }
            other => return Err(format!("unknown header: {other}")),
        }
    }
    out.start = start.unwrap_or(out.start);
    out.end = end.unwrap_or(out.end);
    if out.title.trim().is_empty() {
        return Err("the event needs a title".into());
    }
    if out.end < out.start {
        return Err("it ends before it starts".into());
    }
    out.description = body;
    Ok((out, calendar))
}

/// The text the editor opens with for a contact in `book`.
pub fn render_card(form: &CardForm, book: &str, books: &[String]) -> String {
    let mut out = String::new();
    out.push_str(&format!("Name: {}\n", form.name));
    // One line per value – an empty one to fill in where there is none; more lines, more values.
    let lines = |name: &str, values: Vec<String>| -> String {
        let values = if values.is_empty() { vec![String::new()] } else { values };
        values.iter().map(|value| format!("{name}: {value}\n")).collect()
    };
    out.push_str(&lines("Email", form.emails.iter().map(Labelled::render).collect()));
    out.push_str(&lines("Phone", form.phones.iter().map(Labelled::render).collect()));
    out.push_str(&lines("Organization", form.organizations.clone()));
    out.push_str(&format!("Address book: {book}\n"));
    if books.len() > 1 {
        out.push_str(&format!("# Address books: {}\n", books.join(", ")));
    }
    out.push_str("# Labels in brackets: (work), (private); for phones also mobile, voice, text, video, fax, pager.\n");
    out.push_str("# A note follows the blank line.\n\n");
    out.push_str(&form.note);
    if !form.note.is_empty() {
        out.push('\n');
    }
    out
}

/// Reads back a contact: the form and the name of the address book chosen.
pub fn parse_card(text: &str) -> Result<(CardForm, String), String> {
    let (fields, body) = split(text)?;
    let mut out = CardForm::default();
    let mut book = String::new();
    for (name, value) in fields {
        match name.as_str() {
            "name" => out.name = value,
            _ if value.is_empty() && ["email", "phone", "organization", "organisation"].contains(&name.as_str()) => {}
            "email" => out.emails.push(Labelled::parse(&value, &CONTEXTS)?),
            "phone" => {
                let allowed: Vec<&str> = CONTEXTS.iter().chain(FEATURES.iter()).copied().collect();
                out.phones.push(Labelled::parse(&value, &allowed)?);
            }
            "organization" | "organisation" => out.organizations.push(value),
            "address book" => book = value,
            other => return Err(format!("unknown header: {other}")),
        }
    }
    if out.name.trim().is_empty() && out.emails.is_empty() {
        return Err("the contact needs a name or an address".into());
    }
    if let Some(wrong) = out.emails.iter().find(|email| !email.value.contains('@')) {
        return Err(format!("not an address: {}", wrong.value));
    }
    out.note = body;
    Ok((out, book))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form() -> EventForm {
        let at = |s: &str| NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M").unwrap();
        EventForm {
            title: String::new(),
            all_day: false,
            start: at("2026-10-29 10:00"),
            end: at("2026-10-29 11:00"),
            time_zone: Some("Europe/Berlin".into()),
            location: String::new(),
            description: String::new(),
            participants: Vec::new(),
            repeat: None,
            answers: Vec::new(),
            was: None,
        }
    }

    #[test]
    fn events() {
        let calendars = vec!["Calendar".to_owned(), "Team".to_owned()];
        let text = render_event(&form(), "Calendar", &calendars);
        assert!(text.contains("# Calendars: Calendar, Team\n"));
        let edited = text
            .replace("Title: \n", "Title: Plans\n")
            .replace("Calendar: Calendar\n", "Calendar: Team\n")
            .replace("End: 2026-10-29 11:00", "End: 2026-10-29 11:30")
            .replace("Repeat: none", "Repeat: Weekly")
            .replace("Participants: \n", "Participants: bob@x.example; carol@x.example\n")
            + "Bring coffee.\n";
        let (parsed, calendar) = parse_event(&edited, &form()).unwrap();
        assert_eq!(calendar, "Team");
        assert_eq!(parsed.title, "Plans");
        assert_eq!(parsed.end.format("%H:%M").to_string(), "11:30");
        assert_eq!(parsed.repeat.as_deref(), Some("weekly"));
        assert_eq!(parsed.participants, ["bob@x.example", "carol@x.example"]);
        assert_eq!(parsed.description, "Bring coffee.");
        // All day with dates only.
        let all_day =
            edited.replace("All day: no", "All day: yes").replace("Start: 2026-10-29 10:00", "Start: 2026-10-29");
        let (parsed, _) = parse_event(&all_day, &form()).unwrap();
        assert!(parsed.all_day);
        assert!(parse_event(&edited.replace("Title: Plans", "Title: "), &form()).is_err());
        assert!(parse_event(&edited.replace("Start: 2026-10-29 10:00", "Start: tomorrow"), &form()).is_err());
        assert!(parse_event(&edited.replace("Start: 2026-10-29 10:00", "Start: 2026-10-30 10:00"), &form()).is_err());
        assert!(parse_event(&edited.replace("Repeat: Weekly", "Repeat: hourly"), &form()).is_err());
    }

    #[test]
    fn cards() {
        let books = vec!["Contacts".to_owned()];
        let form = CardForm { name: "Bob".into(), note: "line 1\nline 2".into(), ..CardForm::default() };
        let text = render_card(&form, "Contacts", &books);
        let (parsed, book) = parse_card(&text.replace("Email: \n", "Email: bob@x.example\n")).unwrap();
        assert_eq!(book, "Contacts");
        assert_eq!(parsed.emails, [Labelled { value: "bob@x.example".into(), labels: Vec::new() }]);
        // Several of each, with labels; a label that does not fit is refused.
        let many = text
            .replace("Email: \n", "Email: bob@x.example (work)\nEmail: bob@home.example (private)\n")
            .replace("Phone: \n", "Phone: +49 170 1 (mobile, work)\nPhone: +49 30 2\n")
            .replace("Organization: \n", "Organization: falkOSS\nOrganization: kernoid\n");
        let (parsed, _) = parse_card(&many).unwrap();
        assert_eq!(parsed.emails[1], Labelled { value: "bob@home.example".into(), labels: vec!["private".into()] });
        assert_eq!(parsed.phones[0].labels, ["mobile", "work"]);
        assert_eq!(parsed.organizations, ["falkOSS", "kernoid"]);
        let again = render_card(&parsed, "Contacts", &books);
        assert!(again.contains("Phone: +49 170 1 (mobile, work)\nPhone: +49 30 2\n"), "{again}");
        assert!(parse_card(&many.replace("(work)", "(office)")).is_err());
        assert_eq!(parsed.note, "line 1\nline 2");
        assert!(parse_card("Name: \nEmail: \n\n").is_err());
        assert!(parse_card("Name: X\nEmail: nope\n\n").is_err());
        assert!(parse_card("Nickname: X\n\n").is_err());
    }
}
