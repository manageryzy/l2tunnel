//! Explicit Wintun foreground entry point; native qualification is separate.
use l2tunnel_windows::cli::{self, Command};
use std::{
    io::{self, Write},
    process::ExitCode,
};

fn execute() -> io::Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match cli::parse(&arguments)? {
        Command::Help => writeln!(io::stdout().lock(), "{}", cli::HELP),
        Command::Version => writeln!(
            io::stdout().lock(),
            "l2tunnel-windows {}",
            env!("CARGO_PKG_VERSION")
        ),
        Command::Plan => writeln!(
            io::stdout().lock(),
            "Windows foreground: explicit Wintun L3 + retained TCP/TLS frame. Implementation is separate from native qualification. Windows service/named pipes, TAP L2, credential vault, sleep/recovery, and full carrier/mode qualification remain open.\n{}",
            l2tunnel::IMPLEMENTATION_STATUS
        ),
        Command::Connect(plan) => {
            #[cfg(windows)]
            {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?
                    .block_on(l2tunnel_windows::native::execute(*plan))
            }
            #[cfg(not(windows))]
            {
                drop(plan);
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Wintun execution requires native Windows; plan/help and cross-compilation are not tunnel execution",
                ))
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
