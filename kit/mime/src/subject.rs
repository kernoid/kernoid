// SPDX-License-Identifier: MIT
//! The base subject (RFC 5256, 2.1): what is left of a subject without reply and forward markers and list tags – for
//! threads and for sorting. Besides `Re:`, `Fw:` and `Fwd:`, the markers mail programs write in other languages are
//! taken off too (`AW:`, `WG:`, `SV:`, `Antw:` …), and counters (`Re[2]:`, `Re(2):`).

/// Reply and forward markers, in lower case; RFC 5256 names `re`, `fw` and `fwd`.
const MARKERS: [&str; 39] = [
    "re",
    "fw",
    "fwd",
    "aw",
    "wg",
    "sv",
    "vs",
    "vb",
    "antw",
    "doorst",
    "rif",
    "odp",
    "pd",
    "ynt",
    "ilt",
    "enc",
    "res",
    "tr",
    "rv",
    "ref",
    "vl",
    "fs",
    "vá",
    "továbbítás",
    "trs",
    "réf",
    "wtrs",
    "atb",
    "pārs",
    "ats",
    "persiųsta",
    "απ",
    "σχετ",
    "πρθ",
    "השב",
    "הועבר",
    "回复",
    "转发",
    "回覆",
];

/// A marker at the start of `text` (with a counter and the colon): what follows it.
fn marker(text: &str) -> Option<&str> {
    for marker in MARKERS {
        if !text.get(..marker.len()).is_some_and(|start| start.to_lowercase() == marker) {
            continue;
        }
        let mut rest = &text[marker.len()..];
        if let Some(open) = rest.strip_prefix(['[', '(']) {
            let close = open.find([']', ')'])?;
            if !open[..close].chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            rest = &open[close + 1..];
        }
        let rest = rest.trim_start();
        if let Some(rest) = rest.strip_prefix([':', '：']) {
            return Some(rest);
        }
    }
    None
}

/// A list tag (`[list] `) at the start of `text`: what follows it.
fn blob(text: &str) -> Option<&str> {
    let rest = text.strip_prefix('[')?;
    let close = rest.find(']')?;
    if rest[..close].contains('[') {
        return None;
    }
    Some(rest[close + 1..].trim_start())
}

/// The base subject of a subject (decoded already).
pub fn base_subject(subject: &str) -> String {
    // (1) White space as single spaces.
    let mut text: String = subject.split_whitespace().collect::<Vec<_>>().join(" ");
    loop {
        let before = text.clone();
        // (2) Trailers: `(fwd)`.
        loop {
            let trimmed = text.trim_end();
            match trimmed.len().checked_sub(5).filter(|at| trimmed.is_char_boundary(*at)) {
                Some(at) if trimmed[at..].eq_ignore_ascii_case("(fwd)") => text = trimmed[..at].to_owned(),
                _ => {
                    text = trimmed.to_owned();
                    break;
                }
            }
        }
        // (3) Leaders: markers, each perhaps after list tags; (4) a list tag before a non-empty rest.
        loop {
            let trimmed = text.trim_start();
            let mut rest = trimmed;
            while let Some(after) = blob(rest) {
                rest = after;
            }
            if let Some(after) = marker(rest) {
                text = after.trim_start().to_owned();
                continue;
            }
            match blob(trimmed) {
                Some(after) if !after.is_empty() => text = after.to_owned(),
                _ => {
                    text = trimmed.to_owned();
                    break;
                }
            }
        }
        // (6) `[fwd: …]`.
        if text.len() > 6
            && text.get(..5).is_some_and(|start| start.eq_ignore_ascii_case("[fwd:"))
            && text.ends_with(']')
        {
            text = text[5..text.len() - 1].trim().to_owned();
        }
        if text == before {
            return text;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_subjects() {
        for (subject, base) in [
            ("Lunch", "Lunch"),
            ("Re: Fwd: Lunch", "Lunch"),
            ("RE:  re:Lunch", "Lunch"),
            ("Re[2]: Lunch", "Lunch"),
            ("Re(3) : Lunch", "Lunch"),
            ("[team] Re: [team] Lunch", "Lunch"),
            ("Lunch (fwd)", "Lunch"),
            ("[Fwd: Re: Lunch]", "Lunch"),
            ("AW: WG: Treffen am   Montag", "Treffen am Montag"),
            ("SV: Antw: Möte", "Möte"),
            ("[only a tag]", "[only a tag]"),
            ("Re:", ""),
            ("", ""),
            ("Reply needed: soon", "Reply needed: soon"),
            ("Regarding x", "Regarding x"),
            ("回复：会议", "会议"),
        ] {
            assert_eq!(base_subject(subject), base, "{subject}");
        }
    }
}
