//! Windows configuration and explicit execution capability reporting.
use l2tunnel_windows::cli::{self, Command};
use std::{
    io::{self, Write},
    process::ExitCode,
};

fn execute() -> io::Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    #[cfg(windows)]
    if arguments.is_empty()
        && let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let gui = dir.join("l2tunnel-windows-gui.exe");
        if gui.is_file() {
            std::process::Command::new(gui).spawn()?;
            return Ok(());
        }
    }
    if let Some(command) = l2tunnel_windows::service::parse(&arguments) {
        return l2tunnel_windows::service::execute(command?);
    }
    match cli::parse(&arguments)? {
        Command::Help => writeln!(io::stdout().lock(), "{}", cli::HELP),
        Command::Version => writeln!(
            io::stdout().lock(),
            "l2tunnel-windows {}",
            env!("CARGO_PKG_VERSION")
        ),
        Command::Plan => writeln!(
            io::stdout().lock(),
            "Windows multi-profile service daemon (cross-compiled; native Windows hardware qualification remains open) serves local API v1/v4/v5 on a protected named pipe and owns pinned Wintun L3 adapters, Windows IP Helper routes, live MTU tuning, DPAPI secret unsealing, Event Log + service.log diagnostics, sleep/network-change reconnect, and UDP/OpenVPN-like/TCP-TLS/QUIC Common carriers. Windows TAP/VXLAN L2 and native hardware receipts remain open.\n{}",
            l2tunnel::IMPLEMENTATION_STATUS
        ),
        Command::Connect(plan) => {
            #[cfg(windows)]
            {
                l2tunnel_windows::native::execute(*plan)
            }
            #[cfg(not(windows))]
            {
                plan.check_runtime_support()
            }
        }
    }
}
fn main() -> ExitCode {
    match execute() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "l2tunnel-windows: {error}");
            ExitCode::from(2)
        }
    }
}
