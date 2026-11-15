#![forbid(unsafe_code)]

#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let Some(mode) = args.next() else {
        return Err(usage().into());
    };
    if mode == "--help" || mode == "-h" {
        println!("{}", usage());
        return Ok(());
    }
    if mode == "capabilities" {
        if args.next().is_some() {
            return Err(usage().into());
        }
        let value = aegis_tui::CAPABILITIES;
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema": value.schema, "peer": value.peer,
                "interactive": value.interactive, "headless": value.headless
            }))?
        );
        return Ok(());
    }
    if mode != "interactive" && mode != "headless" {
        return Err(usage().into());
    }
    let socket = match args.next() {
        Some(value) if args.next().is_none() => std::path::PathBuf::from(value),
        _ if mode == "headless" => return failure("configuration_refused", usage()),
        _ => return Err(usage().into()),
    };
    let (session, port) = match aegis_tui_local_client::connect(
        socket,
        aegis_wire::LimitsV1::default(),
        std::time::Duration::from_secs(5),
    ) {
        Ok(value) => value,
        Err(error) if mode == "headless" => {
            return failure("connect_refused", &format!("{error:?}"));
        }
        Err(error) => return Err(std::io::Error::other(format!("{error:?}")).into()),
    };
    if mode == "interactive" {
        interactive(aegis_tui::Component::new(session, port))
    } else {
        headless(session, port)
    }
}

#[cfg(unix)]
fn interactive(mut component: aegis_tui::Component) -> Result<(), Box<dyn std::error::Error>> {
    use crossterm::event::{self, Event};
    use std::time::Duration;
    ratatui::run(|terminal| -> Result<(), Box<dyn std::error::Error>> {
        loop {
            component.poll();
            terminal.draw(|frame| component.draw_in(frame, frame.area(), true))?;
            if event::poll(Duration::from_millis(50))?
                && let Event::Key(key) = event::read()?
                && let Some(input) = aegis_tui::translate_key(key)
                && component.update(input, true) == aegis_tui::Lifecycle::CloseRequested
            {
                break;
            }
        }
        Ok(())
    })
}

#[cfg(unix)]
fn headless(
    session: aegis_protocol::SessionHandleV1,
    port: aegis_tui_local_client::LocalPort,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = aegis_client::ReadOnlyClient::new(session, port, aegis_tui::PAGE_LIMIT)
        .map_err(|_| std::io::Error::other("invalid read-only client limit"))?;
    match aegis_tui::observe(&mut client) {
        Ok(value) => {
            let manifest = aegis_tui::CAPABILITIES;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "version": 1, "mode": "headless", "complete": true,
                    "peer": manifest.peer, "capability": manifest.headless[0], "status": "current",
                    "epoch": value.status.epoch, "active_grants": value.status.active_grants,
                    "retained_decisions": value.status.retained_decisions,
                    "page_grants": value.grants.len(), "more_grants": value.more_grants,
                    "page_decisions": value.decisions.len(), "more_decisions": value.more_decisions
                }))?
            );
            Ok(())
        }
        Err(error) => failure("unavailable", &error),
    }
}

#[cfg(unix)]
fn failure(status: &str, message: &str) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = aegis_tui::CAPABILITIES;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "version": 1, "mode": "headless", "complete": false,
            "peer": manifest.peer, "capability": manifest.headless[0], "status": status
        }))?
    );
    Err(std::io::Error::other(message).into())
}

fn usage() -> &'static str {
    "usage: aegis-tui capabilities | aegis-tui <interactive|headless> SOCKET\nheadless emits one bounded versioned authority.observe.v1 observation without constructing TUI or mutation state"
}

#[cfg(not(unix))]
fn main() {
    eprintln!("aegis-tui requires Unix");
    std::process::exit(1);
}
