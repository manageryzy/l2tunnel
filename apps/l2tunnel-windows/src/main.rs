//! Windows configuration and explicit execution capability reporting.
use l2tunnel_windows::cli::{self, Command};
use std::{
    io::{self, Write},
    process::ExitCode,
};

fn execute() -> io::Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.first().is_some_and(|arg| arg == "common-worker") {
        return l2tunnel_windows::worker::execute(&arguments[1..]);
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
            "Windows original UDP Common worker supports provisioned API4 lifecycle and a pinned Wintun L3 device. Start the packaged local host to use the GUI. Windows TAP, alternate carriers, credential vault, sleep/recovery and native hardware qualification remain open.\n{}",
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
