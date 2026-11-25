//! `service start` of the grouped CLI (owner decisions 2026-11-24: elevated
//! start through an installer). Shares `local::elevate` with the GUI: the
//! approval prompt (pkexec or UAC) installs or starts the platform service,
//! then this waits until it answers on the local API.
use super::{Exit, Usage, note, usage};
use crate::local::elevate::{self, StartError, StartRequest};
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;

/// Options with values accepted by `service start`.
pub(super) const VALUES: &[&str] = &[
    "--program",
    "--wait",
    "--profile-dir",
    "--wintun-dll",
    "--wintun-sha256",
    "--address",
];
/// Windows host options and their `l2tunnel-windows service install` names.
const HOST: &[(&str, &str)] = &[
    ("--profile-dir", "--profile"),
    ("--wintun-dll", "--wintun-dll"),
    ("--wintun-sha256", "--wintun-sha256"),
    ("--address", "--address"),
];

/// Build the start request from parsed options.
pub(super) fn request(
    options: &BTreeMap<String, String>,
    socket: Option<&PathBuf>,
    install: bool,
) -> Result<StartRequest, Usage> {
    let mut request = match options.get("--program") {
        Some(program) => StartRequest::new(PathBuf::from(program)),
        None => StartRequest::defaults()
            .map_err(|error| usage(format!("{error}; give --program PATH")))?,
    };
    if let Some(socket) = socket {
        request.socket = socket.clone();
    }
    if let Some(text) = options.get("--wait") {
        let seconds: u64 = text.parse().map_err(|_| usage("invalid --wait"))?;
        if seconds == 0 || seconds > elevate::MAXIMUM_WAIT.as_secs() {
            return Err(usage(format!(
                "--wait must be 1..{}",
                elevate::MAXIMUM_WAIT.as_secs()
            )));
        }
        request.wait = Duration::from_secs(seconds);
    }
    let host: Vec<String> = HOST
        .iter()
        .filter_map(|(option, name)| {
            options
                .get(*option)
                .map(|value| [(*name).to_owned(), value.clone()])
        })
        .flatten()
        .collect();
    if !host.is_empty() && !install {
        return Err(usage("Windows host options need --install"));
    }
    if install {
        if cfg!(windows) {
            if host.len() != HOST.len() * 2 {
                return Err(usage(
                    "--install needs --profile-dir, --wintun-dll, --wintun-sha256 and --address",
                ));
            }
            if let Some(socket) = socket {
                request.install = Some(
                    host.into_iter()
                        .chain(["--pipe".to_owned(), socket.display().to_string()])
                        .collect(),
                );
            } else {
                request.install = Some(host);
            }
        } else if !host.is_empty() {
            return Err(usage("Windows host options are Windows-only"));
        } else {
            request.install = Some(Vec::new());
        }
    }
    request.terminal = true;
    Ok(request)
}

/// Run the elevated start and report it.
pub(super) async fn run(request: StartRequest, json: bool) -> Exit {
    match elevate::start(&request).await {
        Ok(started) => {
            let mut out = io::stdout().lock();
            let _written = if json {
                writeln!(
                    out,
                    "{}",
                    serde_json::json!({
                        "socket": started.socket,
                        "already_running": started.already_running,
                        "installed": started.installed,
                    })
                )
            } else if started.already_running {
                writeln!(
                    out,
                    "service already running; --control-socket {}",
                    started.socket.display()
                )
            } else {
                writeln!(
                    out,
                    "service {}; --control-socket {}",
                    if started.installed {
                        "installed and started"
                    } else {
                        "started"
                    },
                    started.socket.display()
                )
            };
            Exit::Completed
        }
        Err(error) => {
            note(&error);
            match error {
                StartError::Invalid(_) => Exit::Usage,
                StartError::Launch(error) if error.kind() == io::ErrorKind::NotFound => {
                    Exit::Unsupported
                }
                StartError::Timeout => Exit::Running,
                _ => Exit::Failed,
            }
        }
    }
}
