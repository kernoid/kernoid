// SPDX-License-Identifier: MIT
//! `kernoid-tui`: logs in with an address and an app password over JMAP and opens the app in the terminal.

mod app;
mod ui;

use std::{
    io::Write,
    path::PathBuf,
    process::ExitCode,
    sync::mpsc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::Parser;
use kernoid_tui::{
    config,
    jmap::{self, Client, push},
};
use ratatui::crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyEventKind},
    execute,
};

use crate::app::{App, Background};

/// kernoid in the terminal: mail, files, calendars and contacts.
///
/// The password is an app password (made in the account settings); it comes from KERNOID_PASSWORD, from
/// --password-command, or is asked for – never give it as an argument. End-to-end encrypted mail is read once the
/// account's key is unlocked with its recovery code: from KERNOID_RECOVERY_CODE, or asked for in the app (K).
#[derive(Debug, Parser)]
#[command(version)]
struct Args {
    /// The address to log in with.
    #[arg(long, short, env = "KERNOID_ADDRESS")]
    address: Option<String>,
    /// The server, e.g. https://login.example.org; without it, the domain of the address.
    #[arg(long, short, env = "KERNOID_SERVER")]
    server: Option<String>,
    /// A command that prints the password, e.g. `security find-generic-password -s kernoid -w`.
    #[arg(long)]
    password_command: Option<String>,
    /// Where downloads go (default: the download directory).
    #[arg(long)]
    downloads: Option<PathBuf>,
    /// Allow plain HTTP to hosts other than this machine – the password travels readable.
    #[arg(long)]
    allow_http: bool,
    /// The settings file (default: ~/.config/kernoid/tui.toml).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Log in, list the accounts of the session and quit.
    #[arg(long)]
    check: bool,
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("kernoid-tui: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> Result<(), String> {
    let path = args.config.clone().or_else(config::path);
    let file = config::load(path.as_deref())?;
    let address = args.address.or(file.address).ok_or("give an address: --address or `address` in the settings")?;
    let server = args.server.or(file.server);
    let session_url = jmap::session_url(server.as_deref(), &address).map_err(|e| e.to_string())?;
    let password = config::password(args.password_command.as_deref().or(file.password_command.as_deref()), &address)?;
    let options = jmap::Options { allow_http: args.allow_http || file.allow_http };
    let client = log_in(&session_url, server.is_none(), &address, &password, &options)?;
    drop(password);
    if args.check {
        println!("logged in to {} as {}", client.origin(), client.session.username);
        for (id, account) in &client.session.accounts {
            let mut capabilities: Vec<&str> = account
                .account_capabilities
                .keys()
                .map(|c| c.strip_prefix("urn:ietf:params:jmap:").unwrap_or(c))
                .collect();
            capabilities.sort_unstable();
            let drive = if account.drive { " (drive)" } else { "" };
            println!("{id}  {}{drive}  {}", account.name, capabilities.join(" "));
        }
        return Ok(());
    }
    let downloads = config::downloads(args.downloads.or(file.downloads));
    let (sender, receiver) = mpsc::channel();
    let pushed = sender.clone();
    push::listen(client.clone(), move |event| pushed.send(Background::Push(event)).is_ok());
    let mut app = App::new(client, downloads, sender, config::recovery_code());
    let mut terminal = ratatui::try_init().map_err(|e| e.to_string())?;
    // Clicks and the wheel (app.rs, `mouse`); while it is on, Shift and drag selects text in most terminals.
    let mouse = |on: bool| {
        let mut out = std::io::stdout();
        if on { execute!(out, EnableMouseCapture) } else { execute!(out, DisableMouseCapture) }
    };
    mouse(true).map_err(|e| e.to_string())?;
    let result = (|| -> Result<(), String> {
        while !app.quit {
            terminal.draw(|frame| ui::draw(frame, &mut app)).map_err(|e| e.to_string())?;
            if let Some(edited) = app.edit.take() {
                mouse(false).map_err(|e| e.to_string())?;
                ratatui::restore();
                let text = edit(&app.edit_text(&edited));
                terminal = ratatui::try_init().map_err(|e| e.to_string())?;
                mouse(true).map_err(|e| e.to_string())?;
                terminal.clear().map_err(|e| e.to_string())?;
                app.edited(edited, text);
                continue;
            }
            while let Ok(event) = receiver.try_recv() {
                app.background(event);
            }
            if event::poll(Duration::from_millis(150)).map_err(|e| e.to_string())? {
                match event::read().map_err(|e| e.to_string())? {
                    Event::Key(key) if key.kind == KeyEventKind::Press => app.key(key),
                    Event::Mouse(mouse) => app.mouse(mouse),
                    _ => {}
                }
            }
        }
        Ok(())
    })();
    let _ = mouse(false);
    ratatui::restore();
    result
}

/// Logs in at `session_url`; when no server was given and the domain of the address serves no JMAP, at the servers
/// its SRV records `_jmap._tcp` name (RFC 8620, 2.2).
fn log_in(
    session_url: &str,
    discover: bool,
    address: &str,
    password: &str,
    options: &jmap::Options,
) -> Result<Client, String> {
    let refused = |url: &str, error: jmap::Error| match error {
        jmap::Error::Unauthorized => format!("{address}: the address or app password was not accepted"),
        error => format!("{url}: {error}"),
    };
    let first = match Client::connect(session_url, address, password, options) {
        Ok(client) => return Ok(client),
        Err(jmap::Error::Unauthorized) => return Err(refused(session_url, jmap::Error::Unauthorized)),
        Err(error) if !discover => return Err(refused(session_url, error)),
        Err(error) => refused(session_url, error),
    };
    let domain = address.rsplit_once('@').map(|(_, domain)| domain).unwrap_or_default();
    let targets = match jmap::srv::lookup(domain) {
        Ok(targets) if !targets.is_empty() => targets,
        Ok(_) => return Err(format!("{first}; and _jmap._tcp.{domain} names no server")),
        Err(error) => return Err(format!("{first}; and _jmap._tcp.{domain}: {error}")),
    };
    let mut errors = vec![first];
    for target in targets {
        let url = target.session_url();
        match Client::connect(&url, address, password, options) {
            Ok(client) => return Ok(client),
            Err(jmap::Error::Unauthorized) => return Err(refused(&url, jmap::Error::Unauthorized)),
            Err(error) => errors.push(refused(&url, error)),
        }
    }
    Err(errors.join("; "))
}

/// Opens a text – a message, an event, a contact – in `$VISUAL` or `$EDITOR` (`vi` without either); what the user
/// wrote, once the editor closed.
fn edit(text: &str) -> Result<String, String> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or_default();
    let path = std::env::temp_dir().join(format!("kernoid-message-{}-{stamp}.eml", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let result = (|| {
        let mut file = options.open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        file.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
        drop(file);
        let editor = std::env::var("VISUAL")
            .or_else(|_| std::env::var("EDITOR"))
            .ok()
            .filter(|e| !e.trim().is_empty())
            .unwrap_or_else(|| if cfg!(windows) { "notepad".into() } else { "vi".into() });
        let status = if cfg!(windows) {
            std::process::Command::new(&editor).arg(&path).status()
        } else {
            // The path is passed as an argument of the shell, so it needs no quoting.
            std::process::Command::new("sh").arg("-c").arg(format!("{editor} \"$1\"")).arg("sh").arg(&path).status()
        };
        let status = status.map_err(|e| format!("{editor}: {e}"))?;
        if !status.success() {
            return Err(format!("{editor} ended with {status}"));
        }
        std::fs::read_to_string(&path).map_err(|e| e.to_string())
    })();
    let _ = std::fs::remove_file(&path);
    result
}
