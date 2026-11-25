//! Shared desktop GUI for l2tunnel (egui/eframe, docs/modules/desktop-gui.md).
//!
//! A nonprivileged frontend over local API version 5. The platform binaries
//! (`l2tunnel-linux-gui`, `l2tunnel-windows-gui`) only call [`main_entry`].
//! On Windows `--socket` takes the service pipe name (for example
//! `\\.\pipe\l2tunnel`). The GUI never owns tunnel devices or sockets, and
//! closing the window never disconnects.
use std::process::ExitCode;

#[cfg(any(unix, windows))]
mod app;
#[cfg(any(unix, windows))]
mod browse;
#[cfg(test)]
mod fixture;
pub mod model;
#[cfg(any(unix, windows))]
mod pages;
pub mod present;
pub mod profile_fields;
#[cfg(any(unix, windows))]
mod profiles;
#[cfg(any(unix, windows))]
mod socks_panel;
#[cfg(any(unix, windows))]
mod start;
pub mod stats;
pub mod test_panel;
#[cfg(any(unix, windows))]
mod tuning_panel;
#[cfg(any(unix, windows))]
pub mod worker;

/// Run the GUI binary `name` with its command-line arguments (without `argv[0]`).
#[cfg(any(unix, windows))]
pub fn main_entry(name: &'static str, args: impl IntoIterator<Item = String>) -> ExitCode {
    let usage = format!(
        "usage: {name} [--socket CONTROL_SOCKET] [--page overview|connection|devices|routes|socks5|statistics|management|events]"
    );
    let mut socket = String::new();
    let mut page = pages::Page::Overview;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match (arg.as_str(), args.next()) {
            ("--socket", Some(path)) => socket = path,
            ("--page", Some(name)) => match pages::Page::parse(&name) {
                Some(selected) => page = selected,
                None => {
                    eprintln!("{usage}");
                    return ExitCode::from(2);
                }
            },
            ("--help" | "-h", None) => {
                println!("{usage}");
                return ExitCode::SUCCESS;
            }
            ("--version", None) => {
                println!("{name} {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            _ => {
                eprintln!("{usage}");
                return ExitCode::from(2);
            }
        }
    }
    if socket.is_empty() {
        // Attach to this user's service (the one Start service installs);
        // when it is not running the window offers to start it.
        socket = l2tunnel_client_core::local::elevate::StartRequest::new(Default::default())
            .socket
            .display()
            .to_string();
    }
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("l2tunnel")
            .with_inner_size([1100.0, 780.0])
            .with_min_inner_size([640.0, 480.0]),
        ..Default::default()
    };
    let result = eframe::run_native(
        name,
        options,
        Box::new(move |creation| {
            let context = creation.egui_ctx.clone();
            let worker = worker::Worker::start(move || context.request_repaint())?;
            Ok(Box::new(app::App::new(worker, socket, page)))
        }),
    );
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{name}: {error}");
            ExitCode::from(1)
        }
    }
}

/// The local API transport is not implemented on this platform yet.
#[cfg(not(any(unix, windows)))]
pub fn main_entry(name: &'static str, _args: impl IntoIterator<Item = String>) -> ExitCode {
    eprintln!("{name}: the local API transport is not implemented on this platform");
    ExitCode::from(6)
}
