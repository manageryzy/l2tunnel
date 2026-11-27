//! Elevated service start (owner decisions 2026-11-24: "elevated start",
//! then "just start an installer").
//!
//! The unprivileged GUI and CLI never run the service themselves. The
//! platform approval prompt runs a short installer/starter, and the service
//! manager runs the service:
//!
//! - Linux: `pkexec PROGRAM system-service install|start --uid UID`. The
//!   installer copies PROGRAM to the root-owned [`LINUX_PROGRAM`] (so the user
//!   cannot swap the binary that receives the capability) and writes the
//!   systemd unit [`linux_unit`]: the service runs as UID with only
//!   CAP_NET_ADMIN (ambient and bounding set), `NoNewPrivileges`, a read-only
//!   system and home, and serves [`linux_socket`] in a private runtime
//!   directory, so the existing same-UID socket rule applies unchanged. It is
//!   started on request, never at boot.
//! - Windows: a UAC prompt runs `l2tunnel-windows.exe service start`, or
//!   `service install-start ENCODED` to register the service first.
//!
//! The frontend then waits until the service answers on the local API. A
//! service that already answers is reported without a prompt.
use super::{OperationAction, OperationRequest, request_operation};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Default bound for the approval prompt plus service startup.
pub const DEFAULT_WAIT: Duration = Duration::from_secs(120);
/// Longest accepted bound.
pub const MAXIMUM_WAIT: Duration = Duration::from_secs(600);
/// Linux: root-owned copy of the service program the unit runs.
pub const LINUX_PROGRAM: &str = "/usr/local/libexec/l2tunnel/l2tunnel-linux";
/// Linux: directory of systemd system units.
pub const LINUX_UNIT_DIRECTORY: &str = "/etc/systemd/system";

/// Windows: default administrator-owned installation directory (`%ProgramFiles%\l2tunnel`).
pub fn windows_install_dir() -> PathBuf {
    std::env::var_os("ProgramFiles")
        .map(|root| PathBuf::from(root).join("l2tunnel"))
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files\l2tunnel"))
}

/// Windows: default administrator-owned copy of the service program
/// (`%ProgramFiles%\l2tunnel\l2tunnel-windows.exe`).
pub fn windows_program() -> PathBuf {
    windows_install_dir().join("l2tunnel-windows.exe")
}

/// Windows: default state directory for the multi-profile daemon service
/// (`%ProgramData%\l2tunnel\state`).
pub fn windows_state_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(|root| PathBuf::from(root).join("l2tunnel").join("state"))
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData\l2tunnel\state"))
}

/// Windows: diagnostic file recording the last elevated `service start` /
/// `install-start` error so unprivileged callers (GUI/CLI) can display why
/// UAC-elevated startup failed (since `ShellExecuteExW` does not pipe stderr).
pub fn windows_start_error_log() -> PathBuf {
    windows_state_dir()
        .parent()
        .map(|parent| parent.join("last-start-error.txt"))
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData\l2tunnel\last-start-error.txt"))
}
/// Bound of one readiness probe.
const PROBE: Duration = Duration::from_secs(2);
/// Readiness polling period.
const POLL: Duration = Duration::from_millis(150);
/// Installer output kept for the error text.
#[cfg(any(unix, test))]
const OUTPUT_LIMIT: usize = 2048;
/// Windows `service install-start` argument encoding limit (hex characters).
const ENCODED_LIMIT: usize = 16 * 1024;

/// Linux: systemd unit name of the service for `uid`.
pub fn linux_unit_name(uid: u32) -> String {
    format!("l2tunnel-{uid}.service")
}
/// Linux: control socket of the service for `uid`.
pub fn linux_socket(uid: u32) -> PathBuf {
    PathBuf::from(format!("/run/l2tunnel-{uid}/api.sock"))
}
/// Linux: state directory (profiles, device/route record) of the service
/// for `uid`.
pub fn linux_state_dir(uid: u32) -> PathBuf {
    PathBuf::from(format!("/var/lib/l2tunnel-{uid}"))
}
/// Linux: the systemd unit running [`LINUX_PROGRAM`] as `uid` with only
/// CAP_NET_ADMIN. Devices and routes use rtnetlink, which needs nothing more.
pub fn linux_unit(uid: u32) -> String {
    format!(
        "# Written by `l2tunnel-linux system-service install`; do not edit.
[Unit]
Description=l2tunnel local service for UID {uid}
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User={uid}
ExecStart={LINUX_PROGRAM} daemon --control-socket {socket} --state-dir {state}
RuntimeDirectory=l2tunnel-{uid}
RuntimeDirectoryMode=0700
StateDirectory=l2tunnel-{uid}
StateDirectoryMode=0700
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
UMask=0077
Restart=no
",
        socket = linux_socket(uid).display(),
        state = linux_state_dir(uid).display(),
    )
}

/// What to start. Every path is absolute.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartRequest {
    /// Linux: the service program to install (`l2tunnel-linux` or
    /// `l2tunneld`); an installed service starts from [`LINUX_PROGRAM`].
    /// Windows: `l2tunnel-windows.exe`.
    pub program: PathBuf,
    /// Control socket (Linux: must be [`linux_socket`] of this user) or pipe
    /// name (Windows) the service serves.
    pub socket: PathBuf,
    /// Install (or reinstall) before starting. Linux: must be empty; a
    /// missing unit is installed anyway. Windows: the host options
    /// (`--profile DIR --wintun-dll DLL --wintun-sha256 HEX --address A/L`).
    pub install: Option<Vec<String>>,
    /// Bound for the approval prompt plus service startup.
    pub wait: Duration,
    /// Linux: let polkit prompt on this terminal and show installer output
    /// there (CLI). Otherwise (GUI) the output is kept for the error text.
    pub terminal: bool,
}

/// A service answering on the socket.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Started {
    /// Socket or pipe to attach to.
    pub socket: PathBuf,
    /// It already answered; nothing was launched.
    pub already_running: bool,
    /// The service was installed (or reinstalled) first.
    pub installed: bool,
}

/// Why no service answers.
#[derive(Debug)]
pub enum StartError {
    /// The request is unusable on this platform.
    Invalid(String),
    /// The elevation prompt could not be launched.
    Launch(io::Error),
    /// The approval prompt was dismissed (Linux), or elevation was declined
    /// or failed (Windows UAC does not tell the two apart).
    Dismissed,
    /// Authorization was refused or could not be obtained.
    NotAuthorized,
    /// The elevated installer/starter failed.
    Failed {
        /// Exit code, if any.
        code: Option<i32>,
        /// Last installer output lines, if captured.
        output: String,
    },
    /// Nothing answered within the bound; the prompt or the service may
    /// still be pending.
    Timeout,
}
impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "{reason}"),
            Self::Launch(error) => write!(f, "could not launch the administrator prompt: {error}"),
            Self::Dismissed if cfg!(windows) => {
                write!(f, "the administrator prompt was declined or failed")
            }
            Self::Dismissed => write!(f, "the administrator prompt was dismissed"),
            Self::NotAuthorized => write!(f, "administrator authorization was refused"),
            Self::Failed { code, output } => {
                match code {
                    Some(code) => write!(f, "starting the service failed (exit code {code})")?,
                    None => write!(f, "starting the service was terminated")?,
                }
                if !output.is_empty() {
                    write!(f, ": {output}")?;
                }
                Ok(())
            }
            Self::Timeout => write!(
                f,
                "no service answered in time; the prompt or the service may still be starting"
            ),
        }
    }
}
impl std::error::Error for StartError {}

impl StartRequest {
    /// Platform defaults for the current user: the service program next to
    /// the running executable and this user's socket or pipe.
    pub fn defaults() -> io::Result<Self> {
        let directory = std::env::current_exe()?
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| io::Error::other("the running executable has no directory"))?;
        Ok(Self::new(platform::program(&directory)?))
    }
    /// Platform defaults with an explicit service program.
    pub fn new(program: PathBuf) -> Self {
        Self {
            program,
            socket: platform::socket(),
            install: None,
            wait: DEFAULT_WAIT,
            terminal: false,
        }
    }
    fn check(&self) -> Result<(), StartError> {
        if self.wait.is_zero() || self.wait > MAXIMUM_WAIT {
            return Err(StartError::Invalid(format!(
                "the wait bound must be 1..{} seconds",
                MAXIMUM_WAIT.as_secs()
            )));
        }
        if !self.program.is_absolute() {
            return Err(StartError::Invalid(
                "the service program must be an absolute path".into(),
            ));
        }
        platform::check(self)
    }
}

/// Start the service unless one already answers, and wait until it answers.
pub async fn start(request: &StartRequest) -> Result<Started, StartError> {
    request.check()?;
    if request.install.is_none() && answers(&request.socket).await {
        return Ok(Started {
            socket: request.socket.clone(),
            already_running: true,
            installed: false,
        });
    }
    let installed = platform::start(request).await?;
    let deadline = tokio::time::Instant::now() + request.wait;
    loop {
        if answers(&request.socket).await {
            return Ok(Started {
                socket: request.socket.clone(),
                already_running: false,
                installed,
            });
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(StartError::Timeout);
        }
        tokio::time::sleep(POLL).await;
    }
}

/// Whether a local API v5 service answers `status` on `socket`.
pub async fn answers(socket: &Path) -> bool {
    let request = OperationRequest::new(OperationAction::Status {});
    matches!(
        tokio::time::timeout(PROBE, request_operation(socket, &request)).await,
        Ok(Ok(reply)) if reply.ok
    )
}

/// Encode Windows host options as one argument with no characters that need
/// command-line quoting (the UAC launch passes one flat command line).
pub fn encode_arguments(arguments: &[String]) -> io::Result<String> {
    let mut bytes = Vec::new();
    for (index, argument) in arguments.iter().enumerate() {
        if argument.contains('\0') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "an argument contains NUL",
            ));
        }
        if index > 0 {
            bytes.push(0);
        }
        bytes.extend_from_slice(argument.as_bytes());
    }
    let encoded: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    if encoded.is_empty() || encoded.len() > ENCODED_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "install options are empty or too long",
        ));
    }
    Ok(encoded)
}

/// Decode [`encode_arguments`] output.
pub fn decode_arguments(encoded: &str) -> io::Result<Vec<String>> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "invalid encoded arguments");
    if encoded.is_empty() || encoded.len() > ENCODED_LIMIT || !encoded.len().is_multiple_of(2) {
        return Err(invalid());
    }
    let bytes = (0..encoded.len())
        .step_by(2)
        .map(|at| {
            encoded
                .get(at..at + 2)
                .filter(|pair| pair.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(invalid)
        })
        .collect::<io::Result<Vec<u8>>>()?;
    bytes
        .split(|byte| *byte == 0)
        .map(|part| String::from_utf8(part.to_vec()).map_err(|_| invalid()))
        .collect()
}

/// Last lines of captured installer output, bounded.
#[cfg(any(unix, test))]
fn tail(bytes: &[u8]) -> String {
    let start = bytes.len().saturating_sub(OUTPUT_LIMIT);
    let text = String::from_utf8_lossy(&bytes[start..]);
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    lines[lines.len().saturating_sub(4)..].join(" | ")
}

#[cfg(unix)]
mod platform {
    use super::{POLL, StartError, StartRequest, linux_socket, linux_unit_name, tail};
    use std::io::{self, Read};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use tokio::time::Instant;

    /// pkexec: the user dismissed the authentication dialog.
    const DISMISSED: i32 = 126;
    /// pkexec: not authorized, or authentication could not be obtained.
    const NOT_AUTHORIZED: i32 = 127;

    pub(super) fn program(directory: &Path) -> io::Result<PathBuf> {
        ["l2tunnel-linux", "l2tunneld"]
            .iter()
            .map(|name| directory.join(name))
            .find(|path| path.is_file())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "no l2tunnel-linux or l2tunneld next to {}",
                        directory.display()
                    ),
                )
            })
    }
    pub(super) fn socket() -> PathBuf {
        linux_socket(rustix::process::getuid().as_raw())
    }

    pub(super) fn check(request: &StartRequest) -> Result<(), StartError> {
        if request
            .install
            .as_ref()
            .is_some_and(|options| !options.is_empty())
        {
            return Err(StartError::Invalid(
                "Linux installs take no host options".into(),
            ));
        }
        let socket = linux_socket(rustix::process::getuid().as_raw());
        if request.socket != socket {
            return Err(StartError::Invalid(format!(
                "the installed service serves {}",
                socket.display()
            )));
        }
        Ok(())
    }

    /// Reap the elevated process in the background once it ends.
    fn reap(mut child: Child) {
        let _reaper = std::thread::Builder::new()
            .name("l2tunnel-elevation-reaper".into())
            .spawn(move || {
                let _status = child.wait();
            });
    }

    /// Run the installer or starter through pkexec. Returns whether it
    /// installed.
    pub(super) async fn start(request: &StartRequest) -> Result<bool, StartError> {
        let uid = rustix::process::getuid().as_raw();
        let unit = Path::new(super::LINUX_UNIT_DIRECTORY).join(linux_unit_name(uid));
        let install = request.install.is_some() || !unit.exists();
        let (program, verb) = if install {
            (request.program.clone(), "install")
        } else {
            (PathBuf::from(super::LINUX_PROGRAM), "start")
        };
        let mut command = Command::new("pkexec");
        command
            .arg(&program)
            .args(["system-service", verb, "--uid"])
            .arg(uid.to_string())
            .stdout(Stdio::null());
        if !request.terminal {
            command.stdin(Stdio::null()).stderr(Stdio::piped());
        }
        let mut child = command.spawn().map_err(StartError::Launch)?;
        let deadline = Instant::now() + request.wait;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => tokio::time::sleep(POLL).await,
                Ok(None) => {
                    reap(child);
                    return Err(StartError::Timeout);
                }
                Err(error) => {
                    reap(child);
                    return Err(StartError::Launch(error));
                }
            }
        };
        let mut output = Vec::new();
        if let Some(mut stderr) = child.stderr.take() {
            let _read = stderr.read_to_end(&mut output);
        }
        match status.code() {
            Some(0) => Ok(install),
            Some(DISMISSED) => Err(StartError::Dismissed),
            Some(NOT_AUTHORIZED) => Err(StartError::NotAuthorized),
            code => Err(StartError::Failed {
                code,
                output: tail(&output),
            }),
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::{StartError, StartRequest, encode_arguments};
    use std::io;
    use std::path::{Path, PathBuf};

    /// ShellExecuteExW failed (UAC declined, or the program did not start).
    const ELEVATION_FAILED: i32 = -1;

    pub(super) fn program(directory: &Path) -> io::Result<PathBuf> {
        let program = directory.join("l2tunnel-windows.exe");
        if !program.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no l2tunnel-windows.exe next to {}", directory.display()),
            ));
        }
        Ok(program)
    }
    pub(super) fn socket() -> PathBuf {
        PathBuf::from(r"\\.\pipe\l2tunnel")
    }

    pub(super) fn check(request: &StartRequest) -> Result<(), StartError> {
        if let Some(options) = &request.install
            && !options.is_empty()
        {
            encode_arguments(options).map_err(|error| StartError::Invalid(error.to_string()))?;
        }
        Ok(())
    }

    /// Run `service start` (which automatically installs the service if missing)
    /// or `service install-start [ENCODED]` through UAC.
    pub(super) async fn start(request: &StartRequest) -> Result<bool, StartError> {
        let missing_installed = !super::windows_program().is_file();
        let arguments = match &request.install {
            None => vec!["service".to_owned(), "start".to_owned()],
            Some(options) if options.is_empty() => {
                vec!["service".to_owned(), "install-start".to_owned()]
            }
            Some(options) => vec![
                "service".to_owned(),
                "install-start".to_owned(),
                encode_arguments(options)
                    .map_err(|error| StartError::Invalid(error.to_string()))?,
            ],
        };
        let program = request.program.clone();
        // ShellExecuteExW (inside the maintained `runas` crate, which owns
        // the FFI) blocks until the elevated process exits.
        let status = tokio::task::spawn_blocking(move || {
            runas::Command::new(&program)
                .args(&arguments)
                .show(false)
                .status()
        })
        .await
        .map_err(|error| StartError::Launch(io::Error::other(error)))?
        .map_err(StartError::Launch)?;
        match status.code() {
            Some(0) => Ok(request.install.is_some() || missing_installed),
            Some(ELEVATION_FAILED) => Err(StartError::Dismissed),
            code => {
                let output = std::fs::read_to_string(super::windows_start_error_log())
                    .map(|text| text.trim().chars().take(512).collect::<String>())
                    .unwrap_or_default();
                Err(StartError::Failed { code, output })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_arguments_round_trip_without_quoting_characters() {
        let arguments: Vec<String> = [
            "--profile",
            r"C:\Program Files\l2tunnel\profile",
            "--wintun-dll",
            r#"C:\odd "dir"\wintun.dll"#,
            "",
        ]
        .map(str::to_owned)
        .to_vec();
        let encoded = encode_arguments(&arguments).unwrap_or_default();
        assert!(encoded.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(decode_arguments(&encoded).ok(), Some(arguments));
        for bad in ["", "0", "zz", "0G", "41FF", &"41".repeat(ENCODED_LIMIT)] {
            assert!(decode_arguments(bad).is_err(), "{bad:.8}");
        }
        assert!(encode_arguments(&["a\0b".into()]).is_err());
        assert!(encode_arguments(&[]).is_err());
    }

    #[test]
    fn the_linux_unit_grants_only_cap_net_admin_to_the_user() {
        let unit = linux_unit(1000);
        assert_eq!(linux_unit_name(1000), "l2tunnel-1000.service");
        for line in [
            "User=1000",
            "AmbientCapabilities=CAP_NET_ADMIN",
            "CapabilityBoundingSet=CAP_NET_ADMIN",
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "ProtectHome=read-only",
            "RuntimeDirectoryMode=0700",
            "StateDirectoryMode=0700",
            "Restart=no",
            "ExecStart=/usr/local/libexec/l2tunnel/l2tunnel-linux daemon --control-socket /run/l2tunnel-1000/api.sock --state-dir /var/lib/l2tunnel-1000",
        ] {
            assert!(unit.lines().any(|candidate| candidate == line), "{line}");
        }
        // Started on request only: no [Install] section, never at boot.
        assert!(!unit.contains("[Install]"));
        assert_eq!(tail(b"a\n\nb\nc\nd\ne\n"), "b | c | d | e");
    }

    #[cfg(unix)]
    fn request() -> StartRequest {
        StartRequest {
            program: PathBuf::from("/opt/l2tunnel/l2tunnel-linux"),
            socket: linux_socket(rustix::process::getuid().as_raw()),
            install: None,
            wait: DEFAULT_WAIT,
            terminal: false,
        }
    }

    #[cfg(unix)]
    #[test]
    fn requests_are_checked_before_any_prompt() {
        assert!(request().check().is_ok());
        let mut socket = request();
        socket.socket = PathBuf::from("/tmp/elsewhere.sock");
        assert!(matches!(socket.check(), Err(StartError::Invalid(_))));
        let mut program = request();
        program.program = PathBuf::from("l2tunnel-linux");
        assert!(matches!(program.check(), Err(StartError::Invalid(_))));
        let mut install = request();
        install.install = Some(vec!["--profile".into()]);
        assert!(matches!(install.check(), Err(StartError::Invalid(_))));
        install.install = Some(Vec::new());
        assert!(install.check().is_ok());
        for wait in [Duration::ZERO, MAXIMUM_WAIT + Duration::from_secs(1)] {
            let mut bounded = request();
            bounded.wait = wait;
            assert!(matches!(bounded.check(), Err(StartError::Invalid(_))));
        }
    }
}
