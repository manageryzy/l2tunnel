//! `system-service install|start|uninstall --uid UID` (Linux; owner decision
//! 2026-11-24, "just start an installer"). Run as root only through the
//! approval prompt (`local::elevate`, pkexec). It installs or starts the
//! per-user systemd unit; the service itself runs as UID with only
//! CAP_NET_ADMIN and never as root. Nothing here touches devices or routes.
use crate::local::elevate::{
    LINUX_PROGRAM, LINUX_UNIT_DIRECTORY, linux_socket, linux_unit, linux_unit_name,
};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, ExitCode};
use std::time::{Duration, Instant};

/// Bound for the unit to create its socket after `systemctl start`.
const READY: Duration = Duration::from_secs(20);

pub(super) const HELP: &str =
    "system-service install|start|uninstall --uid UID   (Linux, run as root through pkexec by
      `l2tunnelctl service start` or the GUI: install copies this program to
      /usr/local/libexec/l2tunnel/l2tunnel-linux and writes l2tunnel-UID.service, which runs
      the daemon as UID with only CAP_NET_ADMIN; start starts it; uninstall stops and
      removes the unit and keeps the program and the state directory)";

fn fail(message: impl std::fmt::Display) -> ExitCode {
    let _written = writeln!(io::stderr().lock(), "l2tunnel system-service: {message}");
    ExitCode::from(1)
}

/// Parse and run one `system-service` command (arguments after the word).
pub(super) fn main(args: &[String]) -> ExitCode {
    let (verb, uid) = match args {
        [verb, flag, uid]
            if flag == "--uid" && matches!(verb.as_str(), "install" | "start" | "uninstall") =>
        {
            (verb.as_str(), uid)
        }
        _ => {
            let _written = writeln!(io::stderr().lock(), "usage: {HELP}");
            return ExitCode::from(2);
        }
    };
    let Ok(uid) = uid.parse::<u32>() else {
        return fail("--uid must be a numeric UID");
    };
    if uid == 0 {
        return fail("the service never runs as root; give the desktop user's UID");
    }
    if !rustix::process::geteuid().is_root() {
        return fail("must run as root (through pkexec)");
    }
    let result = match verb {
        "install" => install(uid).and_then(|()| start(uid, true)),
        "start" => start(uid, false),
        _ => uninstall(uid),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => fail(error),
    }
}

/// A root-owned directory no one else can write.
fn check_root_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} must be a root-owned directory", path.display()),
        ));
    }
    Ok(())
}

/// Write `bytes` to `target` atomically (new file in the same directory,
/// then rename), with `mode`.
fn replace(target: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let directory = target
        .parent()
        .ok_or_else(|| io::Error::other("target has no directory"))?;
    check_root_directory(directory)?;
    let name = target
        .file_name()
        .ok_or_else(|| io::Error::other("target has no name"))?;
    let temporary = directory.join(format!(".{}.new", name.to_string_lossy()));
    match fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, target)
}

fn systemctl(args: &[&str]) -> io::Result<()> {
    let status = Command::new("systemctl").args(args).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "systemctl {} failed ({status})",
            args.join(" ")
        )))
    }
}

fn install(uid: u32) -> io::Result<()> {
    let source = std::env::current_exe()?;
    let program = Path::new(LINUX_PROGRAM);
    let directory = program
        .parent()
        .ok_or_else(|| io::Error::other("program has no directory"))?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(directory)?;
    if fs::canonicalize(&source).ok() != fs::canonicalize(program).ok() {
        // A root-owned copy, so the user cannot swap the binary that
        // receives CAP_NET_ADMIN.
        replace(program, &fs::read(&source)?, 0o755)?;
    }
    replace(
        &Path::new(LINUX_UNIT_DIRECTORY).join(linux_unit_name(uid)),
        linux_unit(uid).as_bytes(),
        0o644,
    )?;
    systemctl(&["daemon-reload"])
}

fn start(uid: u32, restart: bool) -> io::Result<()> {
    let unit = linux_unit_name(uid);
    if !Path::new(LINUX_UNIT_DIRECTORY).join(&unit).is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{unit} is not installed"),
        ));
    }
    systemctl(&[if restart { "restart" } else { "start" }, &unit])?;
    let socket = linux_socket(uid);
    let deadline = Instant::now() + READY;
    loop {
        if fs::symlink_metadata(&socket).is_ok() {
            return Ok(());
        }
        let active = Command::new("systemctl")
            .args(["is-active", "--quiet", &unit])
            .status()
            .is_ok_and(|status| status.success());
        if !active || Instant::now() >= deadline {
            let log = Command::new("journalctl")
                .args([
                    "--unit",
                    &unit,
                    "--lines",
                    "4",
                    "--no-pager",
                    "--output",
                    "cat",
                ])
                .output()
                .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
                .unwrap_or_default();
            let state = if active {
                "has no socket yet"
            } else {
                "stopped"
            };
            return Err(io::Error::other(format!("{unit} {state}: {log}")));
        }
        std::thread::sleep(Duration::from_millis(150));
    }
}

fn uninstall(uid: u32) -> io::Result<()> {
    let unit = linux_unit_name(uid);
    let path = Path::new(LINUX_UNIT_DIRECTORY).join(&unit);
    if !path.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{unit} is not installed"),
        ));
    }
    // Stopping an inactive unit succeeds.
    systemctl(&["stop", &unit])?;
    fs::remove_file(&path)?;
    systemctl(&["daemon-reload"])
}
