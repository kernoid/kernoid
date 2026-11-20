// SPDX-License-Identifier: MIT
//! Files as calendar and address book programs write them – shapes of Outlook, Google, Apple and Thunderbird
//! exports, written for these tests – read, expanded, converted and written back.

use jiff::tz::TimeZone;
use kernoid_pim::{
    expand, ical, jscalendar, jscontact,
    time::{format_utc, parse_utc},
    vcard::{self, Version},
};
use serde_json::json;

const OUTLOOK: &str = "BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nPRODID:Microsoft Exchange Server 2010\r\nVERSION:2.0\r\n\
BEGIN:VTIMEZONE\r\nTZID:W. Europe Standard Time\r\nBEGIN:STANDARD\r\nDTSTART:16010101T030000\r\nTZOFFSETFROM:+0200\r\n\
TZOFFSETTO:+0100\r\nRRULE:FREQ=YEARLY;INTERVAL=1;BYDAY=-1SU;BYMONTH=10\r\nEND:STANDARD\r\nBEGIN:DAYLIGHT\r\n\
DTSTART:16010101T020000\r\nTZOFFSETFROM:+0100\r\nTZOFFSETTO:+0200\r\nRRULE:FREQ=YEARLY;INTERVAL=1;BYDAY=-1SU;BYMONTH=3\r\n\
END:DAYLIGHT\r\nEND:VTIMEZONE\r\nBEGIN:VEVENT\r\nORGANIZER;CN=\"Doe, John\":mailto:john@example.com\r\n\
ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;CN=\"Roe, Jane\":mailto:jane@example.org\r\n\
DESCRIPTION;LANGUAGE=de-DE:Hallo\\,\\n\\nbis Montag.\\n\r\nUID:040000008200E00074C5B7101A82E00800000000\r\n\
SUMMARY;LANGUAGE=de-DE:Jour fixe\r\nDTSTART;TZID=W. Europe Standard Time:20261102T100000\r\n\
DTEND;TZID=W. Europe Standard Time:20261102T103000\r\nRRULE:FREQ=WEEKLY;UNTIL=20261130T090000Z;INTERVAL=1;BYDAY=MO;WKST=MO\r\n\
EXDATE;TZID=W. Europe Standard Time:20261116T100000\r\nCLASS:PUBLIC\r\nPRIORITY:5\r\nDTSTAMP:20261020T120000Z\r\n\
TRANSP:OPAQUE\r\nSTATUS:CONFIRMED\r\nSEQUENCE:0\r\nLOCATION;LANGUAGE=de-DE:Raum 4.12\r\n\
X-MICROSOFT-CDO-APPT-SEQUENCE:0\r\nX-MICROSOFT-CDO-BUSYSTATUS:TENTATIVE\r\nX-MICROSOFT-CDO-INTENDEDSTATUS:BUSY\r\n\
X-MICROSOFT-DISALLOW-COUNTER:FALSE\r\nX-ALT-DESC;FMTTYPE=text/html:<html><body><p>Hallo</p></body></html>\r\n\
BEGIN:VALARM\r\nDESCRIPTION:REMINDER\r\nTRIGGER;RELATED=START:-PT15M\r\nACTION:DISPLAY\r\nEND:VALARM\r\nEND:VEVENT\r\n\
END:VCALENDAR\r\n";

const GOOGLE: &str = "BEGIN:VCALENDAR\r\nPRODID:-//Google Inc//Google Calendar 70.9054//EN\r\nVERSION:2.0\r\n\
CALSCALE:GREGORIAN\r\nX-WR-CALNAME:Work\r\nX-WR-TIMEZONE:Europe/Berlin\r\nBEGIN:VTIMEZONE\r\nTZID:Europe/Berlin\r\n\
X-LIC-LOCATION:Europe/Berlin\r\nBEGIN:DAYLIGHT\r\nTZOFFSETFROM:+0100\r\nTZOFFSETTO:+0200\r\nTZNAME:CEST\r\n\
DTSTART:19700329T020000\r\nRRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU\r\nEND:DAYLIGHT\r\nBEGIN:STANDARD\r\n\
TZOFFSETFROM:+0200\r\nTZOFFSETTO:+0100\r\nTZNAME:CET\r\nDTSTART:19701025T030000\r\nRRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU\r\n\
END:STANDARD\r\nEND:VTIMEZONE\r\nBEGIN:VEVENT\r\nDTSTART;TZID=Europe/Berlin:20261005T090000\r\n\
DTEND;TZID=Europe/Berlin:20261005T091500\r\nRRULE:FREQ=WEEKLY;BYDAY=MO,WE,FR\r\nDTSTAMP:20261020T120000Z\r\n\
UID:abc123@google.com\r\nCREATED:20260901T080000Z\r\nLAST-MODIFIED:20261001T080000Z\r\nSEQUENCE:2\r\nSTATUS:CONFIRMED\r\n\
SUMMARY:Standup\r\nTRANSP:OPAQUE\r\nCONFERENCE;VALUE=URI;FEATURE=VIDEO;LABEL=meet.google.com/abc-defg-hij:https://meet\r\n \
.google.com/abc-defg-hij\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nDTSTART;TZID=Europe/Berlin:20261009T100000\r\n\
DTEND;TZID=Europe/Berlin:20261009T101500\r\nDTSTAMP:20261020T120000Z\r\nUID:abc123@google.com\r\n\
RECURRENCE-ID;TZID=Europe/Berlin:20261009T090000\r\nSEQUENCE:2\r\nSTATUS:CONFIRMED\r\nSUMMARY:Standup (later)\r\n\
TRANSP:OPAQUE\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

const APPLE: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Apple Inc.//macOS 15.0//EN\r\nCALSCALE:GREGORIAN\r\n\
BEGIN:VEVENT\r\nCREATED:20261020T120000Z\r\nDTEND;VALUE=DATE:20261226\r\nDTSTAMP:20261020T120000Z\r\n\
DTSTART;VALUE=DATE:20261224\r\nLAST-MODIFIED:20261020T120000Z\r\nRRULE:FREQ=YEARLY\r\nSEQUENCE:0\r\nSUMMARY:Christmas\r\n\
TRANSP:TRANSPARENT\r\nUID:9F3E4C2A-1B2C-4D5E-8F90-ABCDEF012345\r\n\
X-APPLE-STRUCTURED-LOCATION;VALUE=URI;X-ADDRESS=\"Main St 1, Berlin\";X-APPLE-RADIUS=70;X-TITLE=Home:geo:52.5,13.4\r\n\
X-APPLE-TRAVEL-ADVISORY-BEHAVIOR:AUTOMATIC\r\nBEGIN:VALARM\r\nACTION:AUDIO\r\nATTACH;VALUE=URI:Chord\r\n\
TRIGGER;VALUE=DATE-TIME:19760401T005545Z\r\nX-APPLE-DEFAULT-ALARM:TRUE\r\nX-WR-ALARMUID:5E1D\r\nEND:VALARM\r\nEND:VEVENT\r\n\
END:VCALENDAR\r\n";

const THUNDERBIRD: &str = "BEGIN:VCALENDAR\nPRODID:-//Mozilla.org/NONSGML Mozilla Calendar V1.1//EN\nVERSION:2.0\n\
BEGIN:VTIMEZONE\nTZID:/mozilla.org/20070129_1/America/New_York\nX-LIC-LOCATION:America/New_York\nBEGIN:STANDARD\n\
TZOFFSETFROM:-0400\nTZOFFSETTO:-0500\nTZNAME:EST\nDTSTART:19701101T020000\nRRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=11\n\
END:STANDARD\nEND:VTIMEZONE\nBEGIN:VTODO\nCREATED:20261020T120000Z\nLAST-MODIFIED:20261020T120000Z\nDTSTAMP:20261020T120000Z\n\
UID:moz-1\nSUMMARY:File taxes\nDUE;TZID=/mozilla.org/20070129_1/America/New_York:20270415T170000\nSTATUS:IN-PROCESS\n\
PERCENT-COMPLETE:30\nX-MOZ-GENERATION:4\nEND:VTODO\nEND:VCALENDAR\n";

#[test]
fn outlook_invitations() {
    let calendar = ical::parse(OUTLOOK).unwrap();
    assert_eq!(calendar.method().as_deref(), Some("REQUEST"));
    let event = calendar.schedulable().next().unwrap();
    assert_eq!(event.property("ORGANIZER").unwrap().param("CN"), Some("Doe, John"));
    assert_eq!(event.text("DESCRIPTION").as_deref(), Some("Hallo,\n\nbis Montag.\n"));
    // Mondays 2, 9, 23 and 30 November (16 left out), 10:00 Berlin; UNTIL is 30 November 09:00 UTC.
    let instances = expand::expand(&calendar, &TimeZone::UTC, None, 100).instances;
    let starts: Vec<String> = instances.iter().map(|i| format_utc(i.start)).collect();
    assert_eq!(
        starts,
        ["2026-11-02T09:00:00Z", "2026-11-09T09:00:00Z", "2026-11-23T09:00:00Z", "2026-11-30T09:00:00Z"]
    );
    assert_eq!(instances[0].end.as_second() - instances[0].start.as_second(), 1800);

    let objects = jscalendar::from_icalendar(&calendar);
    let object = &objects[0];
    assert_eq!(object["timeZone"], "Europe/Berlin");
    assert_eq!(object["recurrenceRule"]["until"], "2026-11-30T10:00:00");
    assert_eq!(object["recurrenceOverrides"], json!({ "2026-11-16T10:00:00": { "excluded": true } }));
    assert_eq!(object["method"], "request");
    let back = jscalendar::to_icalendar(&objects, "-//test//EN").unwrap();
    let text = back.to_string().replace("\r\n ", "");
    for line in [
        "METHOD:REQUEST",
        "X-MICROSOFT-CDO-BUSYSTATUS:TENTATIVE",
        "X-ALT-DESC;FMTTYPE=text/html:<html><body><p>Hallo</p></body></html>",
        "RRULE:FREQ=WEEKLY;UNTIL=20261130T090000Z;BYDAY=MO",
        "ORGANIZER;CN=\"Doe, John\":mailto:john@example.com",
    ] {
        assert!(text.contains(line), "{line}\n{text}");
    }
    let again = expand::expand(&back, &TimeZone::UTC, None, 100).instances;
    assert_eq!(again.iter().map(|i| format_utc(i.start)).collect::<Vec<_>>(), starts);
}

#[test]
fn google_exports() {
    let calendar = ical::parse(GOOGLE).unwrap();
    assert_eq!(ical::parse(&calendar.to_string()).unwrap(), calendar);
    let range = (parse_utc("2026-10-05T00:00:00Z").unwrap(), parse_utc("2026-10-12T00:00:00Z").unwrap());
    let instances = expand::expand(&calendar, &TimeZone::UTC, Some(range), 100).instances;
    let starts: Vec<String> = instances.iter().map(|i| format_utc(i.start)).collect();
    assert_eq!(starts, ["2026-10-05T07:00:00Z", "2026-10-07T07:00:00Z", "2026-10-09T08:00:00Z"]);
    let objects = jscalendar::from_icalendar(&calendar);
    assert_eq!(objects.len(), 1);
    assert_eq!(objects[0]["virtualLocations"]["v1"]["uri"], "https://meet.google.com/abc-defg-hij");
    assert_eq!(
        objects[0]["recurrenceOverrides"]["2026-10-09T09:00:00"],
        // The instance has neither the meeting nor the series' other properties: Google writes it so.
        json!({ "start": "2026-10-09T10:00:00", "title": "Standup (later)", "virtualLocations": null, "iCalProps": null })
    );
    let text = jscalendar::to_icalendar(&objects, "-//test//EN").unwrap().to_string();
    assert!(text.contains("CONFERENCE;VALUE=URI;FEATURE=VIDEO;LABEL=meet.google.com/abc-defg-hij:"), "{text}");
    assert!(text.contains("LAST-MODIFIED:20261001T080000Z"), "{text}");
}

#[test]
fn apple_all_day_events_and_alarms() {
    let calendar = ical::parse(APPLE).unwrap();
    let event = calendar.schedulable().next().unwrap();
    assert_eq!(event.property("X-APPLE-STRUCTURED-LOCATION").unwrap().param("X-ADDRESS"), Some("Main St 1, Berlin"));
    let berlin = TimeZone::get("Europe/Berlin").unwrap();
    let instances = expand::expand(&calendar, &berlin, None, 3).instances;
    assert_eq!(format_utc(instances[1].start), "2027-12-23T23:00:00Z");
    assert_eq!(format_utc(instances[1].end), "2027-12-25T23:00:00Z");
    let objects = jscalendar::from_icalendar(&calendar);
    assert_eq!(objects[0]["showWithoutTime"], true);
    assert_eq!(objects[0]["duration"], "P2D");
    assert_eq!(objects[0]["freeBusyStatus"], "free");
    let text = jscalendar::to_icalendar(&objects, "-//test//EN").unwrap().to_string().replace("\r\n ", "");
    assert!(text.contains("DTSTART;VALUE=DATE:20261224\r\nDTEND;VALUE=DATE:20261226"), "{text}");
    assert!(text.contains("X-APPLE-STRUCTURED-LOCATION;VALUE=URI;X-ADDRESS=\"Main St 1, Berlin\""), "{text}");
    assert!(text.contains("ACTION:AUDIO") && text.contains("X-WR-ALARMUID:5E1D"), "{text}");
    assert!(text.contains("TRIGGER;VALUE=DATE-TIME:19760401T005545Z"), "{text}");
}

#[test]
fn thunderbird_tasks() {
    let calendar = ical::parse(THUNDERBIRD).unwrap();
    let instances = expand::expand(&calendar, &TimeZone::UTC, None, 3).instances;
    assert_eq!(format_utc(instances[0].start), "2027-04-15T21:00:00Z");
    let objects = jscalendar::from_icalendar(&calendar);
    assert_eq!(objects[0]["@type"], "Task");
    assert_eq!(objects[0]["timeZone"], "America/New_York");
    assert_eq!(objects[0]["percentComplete"], 30);
    let text = jscalendar::to_icalendar(&objects, "-//test//EN").unwrap().to_string();
    assert!(text.contains("DUE;TZID=America/New_York:20270415T170000"), "{text}");
    assert!(text.contains("X-MOZ-GENERATION:4"), "{text}");
}

#[test]
fn address_books_of_apple_and_old_phones() {
    let apple = "BEGIN:VCARD\r\nVERSION:3.0\r\nPRODID:-//Apple Inc.//macOS 15.0//EN\r\nN:Example;Erika;;;\r\n\
        FN:Erika Example\r\nORG:Example GmbH;\r\nitem1.EMAIL;type=INTERNET;type=pref:erika@example.org\r\n\
        item1.X-ABLabel:_$!<Other>!$_\r\nTEL;type=CELL;type=VOICE;type=pref:+49 170 1234567\r\n\
        item2.ADR;type=HOME;type=pref:;;Hauptstr. 5;Berlin;;10115;Germany\r\nitem2.X-ABADR:de\r\nBDAY;VALUE=date:1980-02-29\r\n\
        PHOTO;ENCODING=b;TYPE=JPEG:/9j/4AAQSkZJRgABAQAAAQABAAD\r\n X/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkS\r\n\
        UID:5C0E2A9B-0000-4000-8000-000000000001\r\nX-ABUID:5C0E2A9B:ABPerson\r\nEND:VCARD\r\n";
    let card = vcard::parse(apple).unwrap();
    let json = jscontact::from_vcard(&card);
    assert_eq!(json["emails"]["e1"]["address"], "erika@example.org");
    assert_eq!(json["emails"]["e1"]["pref"], 1);
    assert_eq!(json["emails"]["e1"]["vCardParams"]["group"], "item1");
    assert_eq!(json["phones"]["p1"]["features"], json!({ "mobile": true, "voice": true }));
    assert_eq!(
        json["media"]["m1"]["uri"],
        "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAADX/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkS"
    );
    assert_eq!(json["anniversaries"]["d1"]["date"]["day"], 29);
    let back = jscontact::to_vcard(&json).unwrap();
    let v3 = back.write(Version::V3_0);
    assert!(v3.contains("item1.EMAIL;TYPE=pref:erika@example.org") || v3.contains("item1.EMAIL;TYPE=pref"), "{v3}");
    assert!(v3.contains("item1.X-ABLABEL:_$!<Other>!$_"), "{v3}");
    assert!(v3.contains("PHOTO;ENCODING=b;TYPE=JPEG:/9j/"), "{v3}");
    assert!(v3.contains("X-ABUID:5C0E2A9B:ABPerson"), "{v3}");

    let phone = "BEGIN:VCARD\r\nVERSION:2.1\r\nN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:M=C3=BCller;J=C3=BCrgen;;;\r\n\
        FN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:J=C3=BCrgen M=C3=BCller\r\nTEL;CELL;PREF:+491701234567\r\n\
        NOTE;ENCODING=QUOTED-PRINTABLE:Zeile eins=0D=0A=\r\nZeile zwei\r\nEND:VCARD\r\n";
    let card = vcard::parse(phone).unwrap();
    assert_eq!(card.version, Version::V2_1);
    let json = jscontact::from_vcard(&card);
    assert_eq!(json["name"]["full"], "Jürgen Müller");
    assert_eq!(json["notes"]["n1"]["note"], "Zeile eins\nZeile zwei");
    assert_eq!(json["phones"]["p1"]["pref"], 1);
    let v4 = card.write(Version::V4_0);
    assert!(v4.contains("N:Müller;Jürgen;;;") && v4.contains("TEL;TYPE=cell;PREF=1:+491701234567"), "{v4}");
}
