// SPDX-License-Identifier: AGPL-3.0-or-later
//! Drawing the app: tabs on top, the tab's panes, a status line, and a popup or input line over them.

use chrono::{Local, NaiveDate};
use ratatui::{
    Frame,
    layout::{Constraint, Flex, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, BorderType, Clear, List, ListItem, ListState, Paragraph, Tabs, Wrap},
};

use kernoid_tui::jmap::{
    files::{LinkMode, StoreKind},
    mail::{Conversation, Sealed, format_addresses},
};

use crate::app::{self, App, FilesFocus, MailFocus, Pane, Popup, PopupRegion, Tab};

/// Mint of the brand, for what is selected and focused.
const ACCENT: Color = Color::Rgb(0x3D, 0xDC, 0x97);
const DIM: Color = Color::DarkGray;

fn pane(title: &str, focused: bool) -> Block<'_> {
    let block = Block::bordered().border_type(BorderType::Rounded).title(format!(" {title} "));
    if focused { block.border_style(Style::new().fg(ACCENT)) } else { block.border_style(Style::new().fg(DIM)) }
}

fn highlight() -> Style {
    Style::new().bg(Color::Rgb(0x1E, 0x3A, 0x30)).add_modifier(Modifier::BOLD)
}

pub fn draw(frame: &mut Frame, app: &mut App) {
    app.regions = app::Regions::default();
    let [top, main, status] =
        Layout::vertical([Constraint::Length(1), Constraint::Min(3), Constraint::Length(1)]).areas(frame.area());
    draw_tabs(frame, app, top);
    match app.tab {
        Tab::Mail => draw_mail(frame, app, main),
        Tab::Files => draw_files(frame, app, main),
        Tab::Calendar => draw_calendar(frame, app, main),
        Tab::Contacts => draw_contacts(frame, app, main),
    }
    draw_status(frame, app, status);
    if let Some(popup) = app.popup.clone() {
        let mut region = None;
        draw_popup(frame, app, &popup, &mut region);
        app.regions.popup = region;
    }
}

/// Notes where a list was drawn and its first visible row, for clicks.
fn reachable(app: &mut App, area: Rect, pane: Pane, offset: usize) {
    app.regions.lists.push((area, pane, offset));
}

fn draw_tabs(frame: &mut Frame, app: &mut App, area: Rect) {
    // Where each title lands, as Tabs draws them: a space, the title, a space, the divider.
    let mut x = area.x;
    for (i, tab) in Tab::ALL.iter().enumerate() {
        let width = format!("{} {}", i + 1, tab.title()).chars().count() as u16 + 2;
        app.regions.tabs.push((Rect::new(x, area.y, width, 1), *tab));
        x += width + 1;
    }
    let titles = Tab::ALL.iter().enumerate().map(|(i, tab)| format!("{} {}", i + 1, tab.title()));
    let index = Tab::ALL.iter().position(|t| *t == app.tab).unwrap_or(0);
    let user = format!("{} {} ", if app.online { "●" } else { "○" }, app.client.session.username);
    let [left, right] =
        Layout::horizontal([Constraint::Min(10), Constraint::Length(user.chars().count() as u16)]).areas(area);
    let tabs = Tabs::new(titles).select(index).highlight_style(Style::new().fg(ACCENT).bold()).divider("│");
    frame.render_widget(tabs, left);
    let color = if app.online { ACCENT } else { DIM };
    frame.render_widget(Paragraph::new(Line::from(user).fg(color)), right);
}

fn draw_status(frame: &mut Frame, app: &App, area: Rect) {
    if let Some(input) = &app.input {
        let line = Line::from(vec![
            Span::from(format!("{}: ", input.label)).fg(ACCENT),
            Span::from(if input.secret { "•".repeat(input.text.chars().count()) } else { input.text.clone() }),
            "█".into(),
        ]);
        frame.render_widget(Paragraph::new(line), area);
        return;
    }
    let mut spans = Vec::new();
    for transfer in &app.transfers {
        let progress = match transfer.total {
            Some(total) if total > 0 => format!("{}%", transfer.done * 100 / total),
            _ => app::size_text(transfer.done),
        };
        spans.push(Span::from(format!("{} {progress}  ", transfer.label)).fg(ACCENT));
    }
    if !app.status.is_empty() {
        let style = if app.error { Style::new().fg(Color::Red) } else { Style::new() };
        spans.push(Span::styled(app.status.clone(), style));
    } else if spans.is_empty() {
        spans.push(Span::from(hint(app)).fg(DIM));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn hint(app: &App) -> &'static str {
    match app.tab {
        Tab::Mail => match app.mail_focus {
            MailFocus::Reader => {
                "r reply  R all  f forward  A attachments  m move  d delete  n/p next/prev  Esc back  ? help"
            }
            _ => "Enter open  c write  / search  r reply  m move  d delete  u read  s flag  t threads  ? help",
        },
        Tab::Files => {
            "Enter open  ← up  / search  d download  u upload  v versions  i info  S share  L links  m copy/move  n folder  R rename  D delete"
        }
        Tab::Calendar => {
            "Enter details  n new  e edit  E edit this one  D delete  a accept  m maybe  x decline  [ ] week  t today"
        }
        Tab::Contacts => "/ search  n new  e edit  D delete  c write to  X save .vcf  I import  ? help",
    }
}

fn draw_mail(frame: &mut Frame, app: &mut App, area: Rect) {
    let [boxes, rest] = Layout::horizontal([Constraint::Length(24), Constraint::Min(20)]).areas(area);
    let account = app.mail.accounts.get(app.mail.account).map(|(_, name)| name.clone()).unwrap_or_default();
    let items: Vec<ListItem> = app
        .mail
        .mailboxes
        .iter()
        .map(|mailbox| {
            let depth = if mailbox.parent_id.is_some() { "  " } else { "" };
            let mut line = Line::from(format!("{depth}{}", mailbox.name));
            if mailbox.unread_emails > 0 {
                line.push_span(Span::from(format!(" {}", mailbox.unread_emails)).fg(ACCENT).bold());
            }
            ListItem::new(line)
        })
        .collect();
    let title = if app.mail.accounts.len() > 1 { format!("{account} (a)") } else { account };
    let list =
        List::new(items).block(pane(&title, app.mail_focus == MailFocus::Mailboxes)).highlight_style(highlight());
    frame.render_stateful_widget(list, boxes, &mut app.mail.boxes);
    let offset = app.mail.boxes.offset();
    reachable(app, boxes, Pane::Mailboxes, offset);

    let reading = !app.mail.open.is_empty() && app.mail_focus == MailFocus::Reader;
    let (list_area, reader_area) = if reading {
        let [list, reader] = Layout::vertical([Constraint::Percentage(35), Constraint::Percentage(65)]).areas(rest);
        (list, Some(reader))
    } else {
        (rest, None)
    };
    let width = list_area.width.saturating_sub(2) as usize;
    // In Sent and Drafts the recipients matter, elsewhere the sender.
    let to = app.mailbox().and_then(|m| m.role.as_deref()).is_some_and(|role| role == "sent" || role == "drafts");
    let items: Vec<ListItem> = app.mail.emails.iter().map(|row| email_line(row, width, to)).collect();
    let mailbox = app.mailbox().map(|m| m.name.clone()).unwrap_or_default();
    let mut title = format!("{mailbox} – {}", app.mail.total);
    if app.mail.threads {
        title.push_str(" conversations");
    }
    if !app.mail.search.is_empty() {
        title.push_str(&format!(" – “{}”", app.mail.search));
    }
    let list = List::new(items).block(pane(&title, app.mail_focus == MailFocus::List)).highlight_style(highlight());
    frame.render_stateful_widget(list, list_area, &mut app.mail.list);
    let offset = app.mail.list.offset();
    reachable(app, list_area, Pane::Emails, offset);

    if let Some(area) = reader_area {
        app.reader_width = area.width as usize;
        app.regions.reader = Some(area);
        let field =
            |name: &str, value: String| Line::from(vec![Span::from(format!("{name:<8}")).fg(DIM), Span::from(value)]);
        let mut text = Text::default();
        let many = app.mail.open.len() > 1;
        for (index, email) in app.mail.open.iter().enumerate() {
            if index > 0 {
                text.push_line(Line::default());
                text.push_line(Line::from("─".repeat(area.width.saturating_sub(2) as usize)).fg(DIM));
            }
            let mut lines = vec![
                field("From", format_addresses(email.summary.from.as_deref().unwrap_or_default())).bold(),
                field("To", format_addresses(email.summary.to.as_deref().unwrap_or_default())),
            ];
            if let Some(cc) = email.cc.as_ref().filter(|cc| !cc.is_empty()) {
                lines.push(field("Cc", format_addresses(cc)));
            }
            lines.push(field("Date", app::time_text(email.sent_at.as_deref().unwrap_or(&email.summary.received_at))));
            if index == 0 || !many {
                lines.push(field("Subject", email.summary.subject.clone().unwrap_or_default()).bold());
            }
            if let Some(sealed) = email.sealed {
                let state = match sealed {
                    Sealed { locked: true, .. } if app.e2e.is_unlocked() => {
                        "end-to-end encrypted – not to your key".to_owned()
                    }
                    Sealed { locked: true, .. } => "end-to-end encrypted – locked; K unlocks your key".to_owned(),
                    Sealed { verified: true, .. } => "end-to-end encrypted, signed by the sender".to_owned(),
                    Sealed { signed: true, .. } => {
                        "end-to-end encrypted, signed – not by a key of the sender".to_owned()
                    }
                    Sealed { .. } => "end-to-end encrypted, not signed".to_owned(),
                };
                let line = field("E2E", state);
                lines.push(if sealed.locked || !sealed.verified { line.fg(Color::Yellow) } else { line.fg(ACCENT) });
            }
            if !email.attachments.is_empty() {
                let names: Vec<String> = email
                    .attachments
                    .iter()
                    .map(|a| format!("{} ({})", a.name.as_deref().unwrap_or("attachment"), app::size_text(a.size)))
                    .collect();
                lines.push(field("Files", names.join(", ")).fg(ACCENT));
            }
            lines.push(Line::default());
            for line in lines {
                text.push_line(line);
            }
            text.extend(Text::raw(app.mail.texts.get(index).cloned().unwrap_or_default()));
        }
        let title =
            if many { format!("Conversation – {} messages", app.mail.open.len()) } else { "Message".to_owned() };
        let reader =
            Paragraph::new(text).block(pane(&title, true)).wrap(Wrap { trim: false }).scroll((app.mail.scroll, 0));
        frame.render_widget(reader, area);
    }
}

fn email_line(row: &Conversation, width: usize, to: bool) -> ListItem<'static> {
    let email = &row.latest;
    // The people of a conversation: its senders (or recipients), newest first, each once.
    let mut people: Vec<String> = Vec::new();
    for message in row.emails.iter().rev() {
        let list = if to { &message.to } else { &message.from };
        for address in list.iter().flatten() {
            let name = address.name.clone().filter(|n| !n.is_empty()).unwrap_or_else(|| address.email.clone());
            let first = name.split_whitespace().next().unwrap_or(&name).to_owned();
            let name = if row.emails.len() > 1 { first } else { name };
            if !people.contains(&name) {
                people.push(name);
            }
        }
    }
    let unread = row.unread();
    let marks = format!(
        "{}{}{}",
        if unread { "●" } else { " " },
        if row.flagged() { "★" } else { " " },
        if row.emails.iter().any(|e| e.has_attachment) || email.has_attachment { "📎" } else { "  " }
    );
    let date = app::time_text(&email.received_at);
    let from: String = people.join(", ").chars().take(22).collect();
    let count = if row.emails.len() > 1 { format!("({}) ", row.emails.len()) } else { String::new() };
    let used = 4 + 1 + 22 + 1 + date.chars().count() + 1 + count.chars().count();
    let room = width.saturating_sub(used);
    // An encrypted email whose summary is not decrypted here: its subject outside is only `[...]`.
    let subject = match (email.encrypted, email.opened) {
        (true, false) => "🔒 encrypted".to_owned(),
        (true, true) => format!("🔒 {}", email.subject.clone().unwrap_or_default()),
        _ => email.subject.clone().unwrap_or_default(),
    };
    // The lock is two columns wide.
    let room = room.saturating_sub(usize::from(email.encrypted));
    let subject: String = subject.chars().take(room).collect();
    let subject = format!("{subject:<room$}");
    let style = if unread { Style::new().bold() } else { Style::new() };
    ListItem::new(Line::from(vec![
        Span::from(marks).fg(ACCENT),
        Span::from(format!(" {from:<22} ")),
        Span::from(count).fg(ACCENT),
        Span::from(subject),
        Span::from(format!(" {date}")).fg(DIM),
    ]))
    .style(style)
}

fn draw_files(frame: &mut Frame, app: &mut App, area: Rect) {
    let [stores, rest] = Layout::horizontal([Constraint::Length(28), Constraint::Min(20)]).areas(area);
    let items: Vec<ListItem> = app
        .files
        .stores
        .iter()
        .map(|store| match store.kind {
            StoreKind::Own => ListItem::new("My files"),
            StoreKind::Drive => ListItem::new(format!("▣ {}", store.name)),
            StoreKind::Shared => ListItem::new(format!("⇆ {}", store.name)),
        })
        .collect();
    let list =
        List::new(items).block(pane("Stores", app.files_focus == FilesFocus::Stores)).highlight_style(highlight());
    frame.render_stateful_widget(list, stores, &mut app.files.store_list);
    let offset = app.files.store_list.offset();
    reachable(app, stores, Pane::Stores, offset);

    let mut path = app.store().map(app::store_title).unwrap_or_default();
    if app.files.search.is_empty() {
        for node in &app.files.path {
            path.push_str(" / ");
            path.push_str(&node.name);
        }
    } else {
        path = format!("{path}: “{}” (Esc or ← ends the search)", app.files.search);
    }
    let searching = !app.files.search.is_empty();
    let width = rest.width.saturating_sub(2) as usize;
    let items: Vec<ListItem> = app
        .files
        .nodes
        .iter()
        .enumerate()
        .map(|(index, node)| {
            let size =
                if node.is_directory() { String::new() } else { node.size.map(app::size_text).unwrap_or_default() };
            // A hit of a search shows where it is instead of when it changed.
            let modified = match app.files.found.get(index).filter(|_| searching) {
                Some(hit) if hit.path.is_empty() => "/".to_owned(),
                Some(hit) => hit.path.iter().map(|folder| folder.name.as_str()).collect::<Vec<_>>().join("/"),
                None => node.modified.as_deref().map(app::time_text).unwrap_or_default(),
            };
            // A long place keeps its end: the folder it is in.
            let skip = modified.chars().count().saturating_sub(24);
            let modified =
                if skip > 0 { format!("…{}", modified.chars().skip(skip + 1).collect::<String>()) } else { modified };
            let shared = if node.share_with.as_ref().is_some_and(|s| !s.is_empty()) { " ⇆" } else { "" };
            let icon = if node.role.as_deref() == Some("trash") {
                "🗑 "
            } else if node.is_directory() {
                "▸ "
            } else {
                "  "
            };
            let right = format!("{size:>9}  {modified:>12}");
            let name: String = format!("{icon}{}{shared}", node.name);
            let room = width.saturating_sub(right.chars().count() + 1);
            let name: String = name.chars().take(room).collect();
            let pad = room.saturating_sub(name.chars().count());
            let line = Line::from(vec![Span::from(name), Span::from(" ".repeat(pad + 1)), Span::from(right).fg(DIM)]);
            if node.is_directory() { ListItem::new(line).bold() } else { ListItem::new(line) }
        })
        .collect();
    let list = List::new(items).block(pane(&path, app.files_focus == FilesFocus::Nodes)).highlight_style(highlight());
    frame.render_stateful_widget(list, rest, &mut app.files.list);
    let offset = app.files.list.offset();
    reachable(app, rest, Pane::Nodes, offset);
}

fn draw_calendar(frame: &mut Frame, app: &mut App, area: Rect) {
    let (start, end) = app.calendar_window();
    let title = format!(
        "{} – {}",
        start.with_timezone(&Local).format("%a %d %b %Y"),
        (end - chrono::Duration::days(1)).with_timezone(&Local).format("%a %d %b %Y")
    );
    let mut items = Vec::new();
    let mut day: Option<NaiveDate> = None;
    // One row per event; the day is written on the first event of each day.
    for event in &app.calendar.events {
        let starts = event
            .starts()
            .map(|s| if event.show_without_time { s.date_naive() } else { s.with_timezone(&Local).date_naive() });
        let label = match starts {
            Some(date) if day != Some(date) => {
                day = Some(date);
                date.format("%a %d %b").to_string()
            }
            _ => String::new(),
        };
        let time = match (event.show_without_time, event.starts(), event.ends()) {
            (true, _, _) => "all day".to_owned(),
            (false, Some(start), Some(end)) => {
                format!("{}–{}", start.with_timezone(&Local).format("%H:%M"), end.with_timezone(&Local).format("%H:%M"))
            }
            (false, Some(start), None) => start.with_timezone(&Local).format("%H:%M").to_string(),
            _ => String::new(),
        };
        let mut line = Line::from(vec![
            Span::from(format!("{label:<11}")).fg(ACCENT),
            Span::from(format!("{time:<12}")).fg(DIM),
            if event.is_cancelled() {
                Span::from(event.title.clone().unwrap_or_else(|| "(no title)".into())).crossed_out().fg(DIM)
            } else {
                Span::from(event.title.clone().unwrap_or_else(|| "(no title)".into()))
            },
        ]);
        if event.is_cancelled() {
            line.push_span(Span::from("  cancelled").fg(Color::Red));
        }
        if let Some(location) = event.location() {
            line.push_span(Span::from(format!("  @ {location}")).fg(DIM));
        }
        items.push(ListItem::new(line));
    }
    if items.is_empty() {
        items.push(ListItem::new(Line::from("no events in these two weeks").fg(DIM)));
    }
    let list = List::new(items).block(pane(&title, true)).highlight_style(highlight());
    frame.render_stateful_widget(list, area, &mut app.calendar.list);
    let offset = app.calendar.list.offset();
    reachable(app, area, Pane::Events, offset);
}

fn draw_contacts(frame: &mut Frame, app: &mut App, area: Rect) {
    let [left, right] = Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)]).areas(area);
    let items: Vec<ListItem> = app.contacts.cards.iter().map(|card| ListItem::new(card.full_name())).collect();
    let mut title = format!("Contacts – {}", app.contacts.cards.len());
    if !app.contacts.search.is_empty() {
        title.push_str(&format!(" – “{}”", app.contacts.search));
    }
    let list = List::new(items).block(pane(&title, true)).highlight_style(highlight());
    frame.render_stateful_widget(list, left, &mut app.contacts.list);
    let offset = app.contacts.list.offset();
    reachable(app, left, Pane::Cards, offset);
    let mut lines = Vec::new();
    if let Some(card) = app.contacts.list.selected().and_then(|i| app.contacts.cards.get(i)) {
        lines.push(Line::from(card.full_name()).bold());
        if let Some(organization) = card.organization() {
            lines.push(Line::from(organization).fg(DIM));
        }
        lines.push(Line::default());
        for email in card.emails() {
            lines.push(Line::from(vec![Span::from("Mail   ").fg(DIM), Span::from(email)]));
        }
        for phone in card.phones() {
            lines.push(Line::from(vec![Span::from("Phone  ").fg(DIM), Span::from(phone)]));
        }
        for note in card.notes() {
            lines.push(Line::default());
            lines.extend(note.lines().map(|l| Line::from(l.to_owned())));
        }
    }
    frame.render_widget(Paragraph::new(lines).block(pane("Card", false)).wrap(Wrap { trim: false }), right);
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let [area] = Layout::horizontal([Constraint::Length(width.min(area.width))]).flex(Flex::Center).areas(area);
    let [area] = Layout::vertical([Constraint::Length(height.min(area.height))]).flex(Flex::Center).areas(area);
    area
}

fn list_popup(
    frame: &mut Frame,
    region: &mut Option<PopupRegion>,
    title: &str,
    items: Vec<ListItem>,
    selected: usize,
    footer: &str,
) {
    let heights: Vec<usize> = items.iter().map(ListItem::height).collect();
    let height = heights.iter().sum::<usize>() as u16 + 3;
    let area = centered(frame.area(), 70, height.max(5));
    frame.render_widget(Clear, area);
    let mut state = ListState::default().with_selected(Some(selected));
    let block = pane(title, true).title_bottom(Line::from(format!(" {footer} ")).fg(DIM));
    frame.render_stateful_widget(List::new(items).block(block).highlight_style(highlight()), area, &mut state);
    *region = Some(PopupRegion { area, list: true, offset: state.offset(), heights, first: 0 });
}

fn text_popup(frame: &mut Frame, region: &mut Option<PopupRegion>, title: &str, text: Text, footer: &str) {
    let height = text.lines.len() as u16 + 2;
    let area = centered(frame.area(), 76, height.clamp(5, 30));
    *region = Some(PopupRegion { area, ..PopupRegion::default() });
    frame.render_widget(Clear, area);
    let block = pane(title, true).title_bottom(Line::from(format!(" {footer} ")).fg(DIM));
    frame.render_widget(Paragraph::new(text).block(block).wrap(Wrap { trim: false }), area);
}

fn draw_popup(frame: &mut Frame, app: &App, popup: &Popup, region: &mut Option<PopupRegion>) {
    match popup {
        Popup::Help => text_popup(frame, region, "Keys", Text::raw(HELP), "any key closes"),
        Popup::Info { title, text } => text_popup(frame, region, title, Text::raw(text.clone()), "any key closes"),
        Popup::Move { selected, .. } => {
            let items = app.mail.mailboxes.iter().map(|m| ListItem::new(m.name.clone())).collect();
            list_popup(frame, region, "Move to", items, *selected, "Enter move  Esc cancel");
        }
        Popup::Attachments { selected } => {
            let items = app
                .mail
                .open
                .iter()
                .flat_map(|e| e.attachments.iter())
                .map(|a| {
                    ListItem::new(format!(
                        "{}  {}  {}",
                        a.name.as_deref().unwrap_or("attachment"),
                        app::size_text(a.size),
                        a.kind
                    ))
                })
                .collect();
            list_popup(frame, region, "Attachments", items, *selected, "Enter save  Esc close");
        }
        Popup::Versions { node, list, selected } => {
            let items = list
                .iter()
                .map(|v| {
                    let when =
                        v.modified.as_deref().or(v.created.as_deref()).map(app::exact_time_text).unwrap_or_default();
                    let current = if v.is_current { "  (current)" } else { "" };
                    ListItem::new(format!("{when:<20} {:>9}{current}", app::size_text(v.size)))
                })
                .collect();
            list_popup(
                frame,
                region,
                &format!("Versions of {}", node.name),
                items,
                *selected,
                "Enter save  r restore  Esc close",
            );
        }
        Popup::Written { message, error, encryption } => {
            let mut lines = vec![
                Line::from(format!("From:    {}", message.from)),
                Line::from(format!("To:      {}", format_addresses(&message.draft.to))),
            ];
            if !message.draft.cc.is_empty() {
                lines.push(Line::from(format!("Cc:      {}", format_addresses(&message.draft.cc))));
            }
            if !message.draft.bcc.is_empty() {
                lines.push(Line::from(format!("Bcc:     {}", format_addresses(&message.draft.bcc))));
            }
            lines.push(Line::from(format!("Subject: {}", message.draft.subject)));
            let files = message.draft.attachments.len() + message.files.len();
            if files > 0 {
                lines.push(Line::from(format!("Files:   {files}")));
            }
            if let Some(encryption) = encryption {
                let sealed = encryption.starts_with("end-to-end");
                let line = Line::from(format!("{}  {encryption}", if sealed { "🔒" } else { "  " }));
                lines.push(if sealed { line.fg(ACCENT) } else { line.fg(DIM) });
            }
            if let Some(error) = error {
                lines.push(Line::default());
                lines.push(Line::from(error.clone()).fg(Color::Red));
            }
            text_popup(
                frame,
                region,
                "Send this message?",
                Text::from(lines),
                "s send  d keep as draft  e edit  c drop",
            );
        }
        Popup::Confirm { text, .. } => text_popup(frame, region, "Sure?", Text::raw(text.clone()), "y yes  n no"),
        Popup::Unsaved { edit, error } => {
            let what = match edit {
                app::Edit::Message(_) => "message",
                app::Edit::Event { .. } => "event",
                app::Edit::Card { .. } => "contact",
                app::Edit::Vacation(_) => "vacation response",
            };
            let text = Text::from(vec![Line::from(error.clone()).fg(Color::Red)]);
            text_popup(frame, region, &format!("The {what} was not saved"), text, "e edit again  c drop");
        }
        Popup::Share(sharing) => {
            let mut items: Vec<ListItem> = sharing
                .entries
                .iter()
                .map(|(principal, level)| {
                    let who = match &principal.email {
                        Some(email) if !principal.name.is_empty() => format!("{} <{email}>", principal.name),
                        Some(email) => email.clone(),
                        None => principal.name.clone(),
                    };
                    ListItem::new(Line::from(vec![
                        Span::from(format!("{who:<50} ")),
                        Span::from(level.name()).fg(ACCENT),
                    ]))
                })
                .collect();
            if items.is_empty() {
                items.push(ListItem::new(Line::from("shared with nobody – a adds someone").fg(DIM)));
            }
            let title = format!("Share {}", sharing.node.name);
            list_popup(
                frame,
                region,
                &title,
                items,
                sharing.selected,
                "a add  Enter level  x remove  s save  Esc cancel",
            );
        }
        Popup::Links(linking) => {
            // The address of a link just made comes first – it is not shown again.
            // Wrapped to the popup's width, so that the whole address can be copied.
            let mut items: Vec<ListItem> = linking
                .made
                .iter()
                .map(|url| {
                    let chars: Vec<char> = url.chars().collect();
                    let mut lines = vec![Line::from("new link:").fg(DIM)];
                    lines.extend(chars.chunks(66).map(|part| Line::from(part.iter().collect::<String>()).fg(ACCENT)));
                    ListItem::new(lines)
                })
                .collect();
            for link in &linking.list {
                let until = match &link.expires {
                    Some(date) => format!("until {}", date.get(..10).unwrap_or(date)),
                    None => "no expiry".into(),
                };
                let password = if link.has_password { " · password" } else { "" };
                items.push(ListItem::new(Line::from(vec![
                    Span::from(format!("{:<30} ", LinkMode::of(link).name())).fg(ACCENT),
                    Span::from(format!("{until}{password}")),
                ])));
            }
            if linking.list.is_empty() {
                items.push(ListItem::new(Line::from("no links yet – n makes one").fg(DIM)));
            }
            let offset = usize::from(linking.made.is_some());
            let title = format!("Links to {}", linking.node.name);
            let footer = format!("n new ({})  m mode  x remove  Esc close", linking.mode.name());
            list_popup(frame, region, &title, items, linking.selected + offset, &footer);
            if let Some(region) = region.as_mut() {
                region.first = offset;
            }
        }
        Popup::Destination(destination) => {
            let mut place = app.files.stores.get(destination.store).map(app::store_title).unwrap_or_default();
            for folder in &destination.path {
                place.push_str(" / ");
                place.push_str(&folder.name);
            }
            let mut items: Vec<ListItem> =
                destination.folders.iter().map(|folder| ListItem::new(format!("▸ {}", folder.name)).bold()).collect();
            if items.is_empty() {
                items.push(ListItem::new(Line::from("no folders here").fg(DIM)));
            }
            let same = app.files.stores.get(destination.store).is_some_and(|store| store.id == destination.from);
            let keys = if same {
                "Enter open  ← up  Tab store  m move here  Esc cancel"
            } else {
                "Enter open  ← up  Tab store  c copy here  m move here  Esc cancel"
            };
            let title = format!("{} → {place}", destination.node.name);
            list_popup(frame, region, &title, items, destination.selected, keys);
        }
        Popup::Pick { found, selected, .. } => {
            let items = found
                .iter()
                .map(|p| {
                    let kind = if p.kind == "group" { " (group)" } else { "" };
                    ListItem::new(format!("{}{kind}  {}", p.name, p.email.as_deref().unwrap_or_default()))
                })
                .collect();
            list_popup(frame, region, "Share with whom?", items, *selected, "Enter choose  Esc back");
        }
    }
}

const HELP: &str = "\
Everywhere   1–4 or Tab: Mail, Files, Calendar, Contacts    g or F5: load again
             ?: this help    q or Ctrl-C: quit    Esc: back
Lists        j/k or ↑/↓ move, Enter or l open, h or ← back, PgUp/PgDn
Mouse        a click chooses (a second one opens), the wheel moves; Shift+drag selects text

Mail         c write   / search (Esc clears)   r reply   R reply to all
             f forward   m move   d delete (to the trash; there: for good)
             u read/unread   s flag   t conversations or single emails
             a next account (in the mailboxes)   V vacation response
             K unlock your key with the recovery code (end-to-end
               encrypted mail; again: lock it)
Reading      Space/PgDn scroll   n/p next/previous   A attachments
Writing      in $VISUAL or $EDITOR; header lines, a blank line, the text.
             Attach: <path> adds a file; remove an Attached: line to drop one.

Files        Enter open folder / versions of a file   ← or Backspace up
             d download   u upload (a file of that name gets a new version)
             v versions (Enter save, r restore)   i details and sharing
             n new folder   R rename   D delete (to the trash)
             / search names and contents (Enter goes to a hit)
             m copy or move (Tab another store, Enter a folder, c copy, m move)
             S share a folder (a add, Enter level, x remove, s save)
             L links for people without an account (n new, m view /
               view and add / only add – a drop box –, x remove)

Calendar     [ ] or ←/→ a week back/on   t today   Enter details
             n new   e edit   E edit one of a series   D delete   a accept   m maybe   x decline
Contacts     / search   n new   e or Enter edit   D delete   c write to
Events and contacts are written in the editor like messages.";
