//! Windows service installation, DPAPI secret sealing, and service-control-manager entry
//! (docs/modules/windows-local-service.md, WLS-04/WLS-05/WLS-08, CL-27).
//!
//! Command parsing is portable. Installing, removing and running as a service
//! use the maintained `windows-service` crate, which owns the native service
//! FFI; this application contains no `unsafe` code.
use crate::host::{DaemonOptions, Options};
use l2tunnel_platform_windows::dpapi::Scope;
use std::io;
use std::path::PathBuf;

/// Service name registered with the service control manager.
pub const SERVICE_NAME: &str = "l2tunnel";
/// Display name shown by the Services console.
pub const DISPLAY_NAME: &str = "l2tunnel local service";
/// Service description.
pub const DESCRIPTION: &str = "Owns the l2tunnel Wintun tunnel, Windows routes, and multi-profile store, serving local API v5 on a protected named pipe to l2tunnelctl and l2tunnel-windows-gui.";
/// Service-specific exit code reported when serving failed.
pub const FAILED_EXIT_CODE: u32 = 1;

/// A host-mode command. Parsing performs no I/O.
#[derive(Debug, Eq, PartialEq)]
pub enum HostCommand {
    /// Serve one profile in this console until Ctrl+C (testing; requires elevation).
    Foreground(Options),
    /// Serve the multi-profile daemon in this console until Ctrl+C (testing; requires elevation).
    Daemon(DaemonOptions),
    /// Register the single-profile service to run `service run` with these options.
    Install(Options),
    /// Register the multi-profile daemon service to run `service run-daemon` with these options.
    InstallDaemon(DaemonOptions),
    /// Register the single-profile service and start it (UAC entry).
    InstallStart(Options),
    /// Register the multi-profile daemon service and start it (UAC entry).
    InstallStartDaemon(DaemonOptions),
    /// Automatically install/update the default multi-profile daemon service
    /// under `%ProgramFiles%\l2tunnel` and start (or restart) it (UAC entry).
    AutoInstallStart,
    /// Start the registered service (auto-installing if missing) and wait until it runs.
    Start,
    /// Stop (if running) and remove the registered service.
    Uninstall,
    /// Single-profile entry used by the service control manager only.
    Run(Options),
    /// Multi-profile daemon entry used by the service control manager only.
    RunDaemon(DaemonOptions),
    /// Seal a private key file using Windows DPAPI (`L2DP` envelope).
    SealSecret {
        /// Plaintext secret file path.
        input: PathBuf,
        /// Destination sealed file path (created exclusively).
        output: PathBuf,
        /// DPAPI scope (`LocalMachine` for LocalSystem service, or `CurrentUser`).
        scope: Scope,
    },
}

fn parse_dpapi_seal(arguments: &[String]) -> io::Result<HostCommand> {
    let mut input: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut scope = Scope::LocalMachine;
    let mut iter = arguments.iter();
    while let Some(arg) = iter.next() {
        let Some(val) = iter.next() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "dpapi seal option requires a value",
            ));
        };
        match arg.as_str() {
            "--input" if input.is_none() => input = Some(PathBuf::from(val)),
            "--output" if output.is_none() => output = Some(PathBuf::from(val)),
            "--scope" => {
                scope = match val.as_str() {
                    "machine" => Scope::LocalMachine,
                    "user" => Scope::CurrentUser,
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "--scope must be machine or user",
                        ));
                    }
                };
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "use: dpapi seal --input FILE --output FILE [--scope machine|user]",
                ));
            }
        }
    }
    let input =
        input.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing --input"))?;
    let output =
        output.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing --output"))?;
    if input == output {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--input and --output must be distinct files",
        ));
    }
    Ok(HostCommand::SealSecret {
        input,
        output,
        scope,
    })
}

/// Parse a host-mode command, or `None` when `arguments` is not one.
pub fn parse(arguments: &[String]) -> Option<io::Result<HostCommand>> {
    let words: Vec<&str> = arguments.iter().take(2).map(String::as_str).collect();
    Some(match words.as_slice() {
        ["foreground", ..] => Options::parse(&arguments[1..]).map(HostCommand::Foreground),
        ["daemon", ..] => DaemonOptions::parse(&arguments[1..]).map(HostCommand::Daemon),
        ["dpapi", "seal"] => parse_dpapi_seal(&arguments[2..]),
        ["dpapi", ..] => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "use: dpapi seal --input FILE --output FILE [--scope machine|user]",
        )),
        ["service", "install"] => {
            if arguments[2..].iter().any(|a| a == "--state-dir") {
                DaemonOptions::parse(&arguments[2..]).map(HostCommand::InstallDaemon)
            } else {
                Options::parse(&arguments[2..]).map(HostCommand::Install)
            }
        }
        ["service", "run"] => Options::parse(&arguments[2..]).map(HostCommand::Run),
        ["service", "run-daemon"] => {
            DaemonOptions::parse(&arguments[2..]).map(HostCommand::RunDaemon)
        }
        ["service", "start"] if arguments.len() == 2 => Ok(HostCommand::Start),
        // Zero-arg `service install-start` reinstalls from the current binary
        // into `%ProgramFiles%\l2tunnel` and restarts (parity with Linux GUI).
        ["service", "install-start"] if arguments.len() == 2 => Ok(HostCommand::AutoInstallStart),
        // One hex argument: the UAC launch passes a flat command line, and
        // paths with spaces or quotes would not survive its quoting.
        ["service", "install-start"] if arguments.len() == 3 => {
            l2tunnel_client_core::local::elevate::decode_arguments(&arguments[2]).and_then(
                |options| {
                    if options.iter().any(|a| a == "--state-dir") {
                        DaemonOptions::parse(&options).map(HostCommand::InstallStartDaemon)
                    } else {
                        Options::parse(&options).map(HostCommand::InstallStart)
                    }
                },
            )
        }
        ["service", "uninstall"] if arguments.len() == 2 => Ok(HostCommand::Uninstall),
        ["service", ..] => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "use: service install OPTIONS | service start | service uninstall | service run|run-daemon OPTIONS",
        )),
        _ => return None,
    })
}

/// Execute a parsed host command.
#[cfg(windows)]
pub fn execute(command: HostCommand) -> io::Result<()> {
    match command {
        HostCommand::Foreground(options) => {
            let pipe = options.pipe().to_owned();
            crate::host::serve(
                &options,
                move || {
                    eprintln!("l2tunnel-windows: serving the local API on {pipe}; Ctrl+C stops")
                },
                async {
                    if tokio::signal::ctrl_c().await.is_err() {
                        std::future::pending::<()>().await;
                    }
                },
                None,
            )
        }
        HostCommand::Daemon(options) => {
            let pipe = options.pipe().to_owned();
            crate::host::serve_daemon(
                &options,
                move || {
                    eprintln!("l2tunnel-windows: daemon serving local API on {pipe}; Ctrl+C stops")
                },
                async {
                    if tokio::signal::ctrl_c().await.is_err() {
                        std::future::pending::<()>().await;
                    }
                },
                None,
            )
        }
        HostCommand::Install(options) => native::install_single(&options),
        HostCommand::InstallDaemon(options) => native::install_daemon(&options),
        HostCommand::InstallStart(options) => {
            native::install_single(&options)?;
            native::start_existing()
        }
        HostCommand::InstallStartDaemon(options) => {
            native::install_daemon(&options)?;
            native::start_existing()
        }
        HostCommand::AutoInstallStart => native::auto_install_and_start(),
        HostCommand::Start => native::start_or_auto_install(),
        HostCommand::Uninstall => native::uninstall(),
        HostCommand::Run(options) => native::run_single(options),
        HostCommand::RunDaemon(options) => native::run_daemon(options),
        HostCommand::SealSecret {
            input,
            output,
            scope,
        } => {
            use std::io::Write;
            use zeroize::Zeroizing;
            let raw = Zeroizing::new(std::fs::read(&input)?);
            let sealed = l2tunnel_platform_windows::dpapi::protect_secret(&raw, scope)?;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output)?;
            file.write_all(&sealed)?;
            file.sync_all()?;
            eprintln!(
                "l2tunnel-windows: sealed {} -> {}",
                input.display(),
                output.display()
            );
            Ok(())
        }
    }
}

/// Service hosting requires Windows; inputs were validated without side effects.
#[cfg(not(windows))]
pub fn execute(_command: HostCommand) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the l2tunnel Windows service host requires Windows",
    ))
}

#[cfg(windows)]
mod native {
    use super::{DESCRIPTION, DISPLAY_NAME, FAILED_EXIT_CODE, SERVICE_NAME};
    use crate::host::{DaemonOptions, Options};
    use l2tunnel_platform_windows::{MtuController, event_log::ServiceLogger};
    use std::ffi::OsString;
    use std::io;
    use std::sync::OnceLock;
    use std::time::Duration;
    use windows_service::service::{
        PowerEventParam, ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl,
        ServiceExitCode, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::{define_windows_service, service_dispatcher};

    enum ServiceMode {
        Single(Options),
        Daemon(DaemonOptions),
    }

    static MODE: OnceLock<ServiceMode> = OnceLock::new();
    const WAIT_HINT: Duration = Duration::from_secs(15);
    /// Win32 `ERROR_SERVICE_DOES_NOT_EXIST`.
    const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;

    fn service_error(error: windows_service::Error) -> io::Error {
        match error {
            windows_service::Error::Winapi(error) => error,
            other => io::Error::new(io::ErrorKind::InvalidInput, other.to_string()),
        }
    }

    fn is_service_missing(error: &windows_service::Error) -> bool {
        matches!(
            error,
            windows_service::Error::Winapi(io_err)
                if io_err.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST)
        )
    }

    fn register_or_update_service(
        executable_path: std::path::PathBuf,
        launch_arguments: Vec<OsString>,
    ) -> io::Result<()> {
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .map_err(service_error)?;
        let info = ServiceInfo {
            name: SERVICE_NAME.into(),
            display_name: DISPLAY_NAME.into(),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::OnDemand,
            error_control: ServiceErrorControl::Normal,
            executable_path,
            launch_arguments,
            dependencies: Vec::new(),
            account_name: None,
            account_password: None,
        };
        let service = match manager.open_service(SERVICE_NAME, ServiceAccess::CHANGE_CONFIG) {
            Ok(existing) => {
                existing.change_config(&info).map_err(service_error)?;
                existing
            }
            Err(err) if is_service_missing(&err) => manager
                .create_service(&info, ServiceAccess::CHANGE_CONFIG)
                .map_err(service_error)?,
            Err(err) => return Err(service_error(err)),
        };
        service.set_description(DESCRIPTION).map_err(service_error)
    }

    fn stop_if_running() -> io::Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(service_error)?;
        let service = match manager.open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP,
        ) {
            Ok(service) => service,
            Err(err) if is_service_missing(&err) => return Ok(()),
            Err(err) => return Err(service_error(err)),
        };
        if service.query_status().map_err(service_error)?.current_state == ServiceState::Stopped {
            return Ok(());
        }
        let _ = service.stop();
        let deadline = std::time::Instant::now() + WAIT_HINT;
        while std::time::Instant::now() < deadline {
            if service.query_status().map_err(service_error)?.current_state == ServiceState::Stopped
            {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        Ok(())
    }

    fn harden_acl(path: &std::path::Path, grants: &[&str]) -> io::Result<()> {
        let mut cmd = std::process::Command::new("icacls.exe");
        cmd.arg(path).arg("/inheritance:r").arg("/grant:r");
        for grant in grants {
            cmd.arg(grant);
        }
        let output = cmd.output()?;
        if !output.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "icacls failed on {}: {}",
                    path.display(),
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            ));
        }
        Ok(())
    }

    fn copy_if_different(src: &std::path::Path, dst: &std::path::Path) -> io::Result<()> {
        let same = std::fs::canonicalize(src)
            .ok()
            .zip(std::fs::canonicalize(dst).ok())
            .is_some_and(|(a, b)| a == b);
        if !same {
            std::fs::copy(src, dst)?;
        }
        Ok(())
    }

    fn record_start_outcome(result: &io::Result<()>) {
        let log_path = l2tunnel_client_core::local::elevate::windows_start_error_log();
        match result {
            Ok(()) => {
                let _ = std::fs::remove_file(&log_path);
            }
            Err(err) => {
                if let Some(parent) = log_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::fs::write(&log_path, format!("{err}\n"));
            }
        }
    }

    /// Automatically install (or update) the default multi-profile daemon
    /// service under `%ProgramFiles%\l2tunnel` and `%ProgramData%\l2tunnel\state`
    /// (with `WLS-08` admin-only ACLs), then start it. Mirrors Linux's
    /// `system-service install`.
    pub fn auto_install_and_start() -> io::Result<()> {
        let logger = ServiceLogger::new(SERVICE_NAME, None);
        let result = (|| -> io::Result<()> {
            stop_if_running()?;
            let install_dir = l2tunnel_client_core::local::elevate::windows_install_dir();
            let state_dir = l2tunnel_client_core::local::elevate::windows_state_dir();
            let target_exe = l2tunnel_client_core::local::elevate::windows_program();
            let target_dll = install_dir.join("wintun.dll");

            std::fs::create_dir_all(&install_dir)?;
            std::fs::create_dir_all(&state_dir)?;

            // Lock down directories with locale-independent SIDs (WLS-08):
            // SYSTEM + Administrators full control; Interactive Users RX on install_dir only.
            harden_acl(
                &state_dir,
                &["*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"],
            )?;
            harden_acl(
                &install_dir,
                &[
                    "*S-1-5-18:(OI)(CI)F",
                    "*S-1-5-32-544:(OI)(CI)F",
                    "*S-1-5-4:(OI)(CI)RX",
                ],
            )?;

            let source_exe = std::env::current_exe()?;
            copy_if_different(&source_exe, &target_exe)?;

            if let Some(source_dir) = source_exe.parent() {
                let source_dll = source_dir.join("wintun.dll");
                if source_dll.is_file() {
                    copy_if_different(&source_dll, &target_dll)?;
                }
                let source_ctl = source_dir.join("l2tunnelctl.exe");
                if source_ctl.is_file() {
                    let _ = copy_if_different(&source_ctl, &install_dir.join("l2tunnelctl.exe"));
                }
            }

            let mut args = vec!["--state-dir".to_owned(), state_dir.display().to_string()];
            if target_dll.is_file() {
                let sha = crate::host::sha256_file(&target_dll)?;
                args.push("--wintun-dll".to_owned());
                args.push(target_dll.display().to_string());
                args.push("--wintun-sha256".to_owned());
                args.push(sha);
            }
            let options = DaemonOptions::parse(&args)?;
            crate::host::audit_install_directories(
                Some(&install_dir),
                options.state_dir(),
                options.wintun_dll(),
                false,
            )?;
            register_or_update_service(target_exe, options.launch_arguments())?;
            start_existing()
        })();
        record_start_outcome(&result);
        if let Err(err) = &result {
            logger.error(&format!("auto-install/start failed: {err}"));
        }
        result
    }

    /// Register the single-profile service after validating configuration and ACLs.
    pub fn install_single(options: &Options) -> io::Result<()> {
        crate::host::audit_install_directories(
            None,
            options.profile(),
            Some(options.wintun_dll()),
            false,
        )?;
        crate::host::prepare(options, MtuController::new())?;
        register_or_update_service(std::env::current_exe()?, options.launch_arguments())
    }

    /// Register the multi-profile daemon service after validating ACLs and state dir.
    pub fn install_daemon(options: &DaemonOptions) -> io::Result<()> {
        std::fs::create_dir_all(options.state_dir())?;
        crate::host::audit_install_directories(
            None,
            options.state_dir(),
            options.wintun_dll(),
            options.skip_acl_check(),
        )?;
        register_or_update_service(std::env::current_exe()?, options.launch_arguments())
    }

    /// Start the registered service (auto-installing it under `%ProgramFiles%\l2tunnel`
    /// if the Windows service does not exist yet), then wait until it reports running.
    pub fn start_or_auto_install() -> io::Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(service_error)?;
        let result = match manager.open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::START,
        ) {
            Ok(_) => start_existing(),
            Err(err) if is_service_missing(&err) => return auto_install_and_start(),
            Err(err) => Err(service_error(err)),
        };
        record_start_outcome(&result);
        result
    }

    /// Start the registered service and wait until it reports running.
    pub fn start_existing() -> io::Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(service_error)?;
        let service = manager
            .open_service(
                SERVICE_NAME,
                ServiceAccess::QUERY_STATUS | ServiceAccess::START,
            )
            .map_err(service_error)?;
        if service.query_status().map_err(service_error)?.current_state != ServiceState::Running {
            service
                .start::<&std::ffi::OsStr>(&[])
                .map_err(service_error)?;
        }
        let deadline = std::time::Instant::now() + WAIT_HINT + WAIT_HINT;
        loop {
            let status = service.query_status().map_err(service_error)?;
            match status.current_state {
                ServiceState::Running => return Ok(()),
                ServiceState::Stopped => {
                    return Err(io::Error::other(format!(
                        "the service stopped while starting ({:?})",
                        status.exit_code
                    )));
                }
                _ if std::time::Instant::now() >= deadline => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "the service did not report running in time",
                    ));
                }
                _ => std::thread::sleep(Duration::from_millis(200)),
            }
        }
    }

    /// Request a stop when running, then mark the service for deletion.
    pub fn uninstall() -> io::Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(service_error)?;
        let service = manager
            .open_service(
                SERVICE_NAME,
                ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
            )
            .map_err(service_error)?;
        if service.query_status().map_err(service_error)?.current_state != ServiceState::Stopped {
            service.stop().map_err(service_error)?;
        }
        service.delete().map_err(service_error)
    }

    pub fn run_single(options: Options) -> io::Result<()> {
        MODE.set(ServiceMode::Single(options))
            .map_err(|_| io::Error::other("service options were already set"))?;
        service_dispatcher::start(SERVICE_NAME, ffi_service_main).map_err(service_error)
    }

    pub fn run_daemon(options: DaemonOptions) -> io::Result<()> {
        MODE.set(ServiceMode::Daemon(options))
            .map_err(|_| io::Error::other("service options were already set"))?;
        service_dispatcher::start(SERVICE_NAME, ffi_service_main).map_err(service_error)
    }

    define_windows_service!(ffi_service_main, service_main);

    fn status(state: ServiceState, exit: u32, controls: ServiceControlAccept) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: controls,
            exit_code: if exit == 0 {
                ServiceExitCode::Win32(0)
            } else {
                ServiceExitCode::ServiceSpecific(exit)
            },
            checkpoint: 0,
            wait_hint: if matches!(
                state,
                ServiceState::StartPending | ServiceState::StopPending
            ) {
                WAIT_HINT
            } else {
                Duration::ZERO
            },
            process_id: None,
        }
    }

    fn service_main(_arguments: Vec<OsString>) {
        if let Err(err) = run_service() {
            let logger = ServiceLogger::new(SERVICE_NAME, None);
            logger.error(&format!("Windows service dispatcher failed: {err}"));
        }
    }

    fn run_service() -> windows_service::Result<()> {
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let (power_tx, power_rx) = tokio::sync::mpsc::unbounded_channel();
        let handler = move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _sent = stop.send(true);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::PowerEvent(
                PowerEventParam::ResumeAutomatic
                | PowerEventParam::ResumeSuspend
                | PowerEventParam::ResumeCritical,
            ) => {
                let _ = power_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::PowerEvent(_) | ServiceControl::Interrogate => {
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let handle = service_control_handler::register(SERVICE_NAME, handler)?;
        handle.set_service_status(status(
            ServiceState::StartPending,
            0,
            ServiceControlAccept::empty(),
        ))?;
        let running = handle;
        let on_ready = move || {
            let _reported = running.set_service_status(status(
                ServiceState::Running,
                0,
                ServiceControlAccept::STOP
                    | ServiceControlAccept::SHUTDOWN
                    | ServiceControlAccept::POWER_EVENT,
            ));
        };
        let stop_future = async move {
            let mut stopped = stopped;
            if stopped.wait_for(|stop| *stop).await.is_err() {
                std::future::pending::<()>().await;
            }
        };
        let result = match MODE.get() {
            Some(ServiceMode::Single(options)) => {
                crate::host::serve(options, on_ready, stop_future, Some(power_rx))
            }
            Some(ServiceMode::Daemon(options)) => {
                crate::host::serve_daemon(options, on_ready, stop_future, Some(power_rx))
            }
            None => Err(io::Error::other("service options missing")),
        };
        let exit = if result.is_ok() { 0 } else { FAILED_EXIT_CODE };
        handle.set_service_status(status(
            ServiceState::Stopped,
            exit,
            ServiceControlAccept::empty(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }
    fn options() -> String {
        let root = if cfg!(windows) { r"C:\l2t" } else { "/l2t" };
        format!(
            "--profile {root}/profile --wintun-dll {root}/wintun.dll --wintun-sha256 {} --address 10.81.0.2/24",
            "ab".repeat(32)
        )
    }
    fn daemon_options() -> String {
        let root = if cfg!(windows) { r"C:\l2t" } else { "/l2t" };
        format!(
            "--state-dir {root}/state --wintun-dll {root}/wintun.dll --wintun-sha256 {}",
            "ab".repeat(32)
        )
    }

    #[test]
    fn host_commands_are_explicit_and_validated_before_io() {
        assert!(parse(&words("plan")).is_none());
        assert!(parse(&words("connect --carrier tcp-tls")).is_none());
        assert!(parse(&[]).is_none());
        for command in ["foreground", "service install", "service run"] {
            let parsed = parse(&words(&format!("{command} {}", options())));
            assert!(matches!(parsed, Some(Ok(_))), "{command}");
            assert!(matches!(parse(&words(command)), Some(Err(_))), "{command}");
        }
        assert!(matches!(
            parse(&words(&format!("daemon {}", daemon_options()))),
            Some(Ok(HostCommand::Daemon(_)))
        ));
        assert!(matches!(
            parse(&words(&format!("service install {}", daemon_options()))),
            Some(Ok(HostCommand::InstallDaemon(_)))
        ));
        assert!(matches!(
            parse(&words(&format!("service run-daemon {}", daemon_options()))),
            Some(Ok(HostCommand::RunDaemon(_)))
        ));
        assert!(matches!(
            parse(&words(
                "dpapi seal --input a.key --output a.dpapi --scope machine"
            )),
            Some(Ok(HostCommand::SealSecret {
                scope: Scope::LocalMachine,
                ..
            }))
        ));
        assert!(matches!(
            parse(&words("service uninstall")),
            Some(Ok(HostCommand::Uninstall))
        ));
        assert!(matches!(
            parse(&words("service start")),
            Some(Ok(HostCommand::Start))
        ));
        assert!(matches!(
            parse(&words("service install-start")),
            Some(Ok(HostCommand::AutoInstallStart))
        ));
        let encoded = l2tunnel_client_core::local::elevate::encode_arguments(&words(&options()))
            .unwrap_or_default();
        assert!(matches!(
            parse(&words(&format!("service install-start {encoded}"))),
            Some(Ok(HostCommand::InstallStart(_)))
        ));
        let encoded_d =
            l2tunnel_client_core::local::elevate::encode_arguments(&words(&daemon_options()))
                .unwrap_or_default();
        assert!(matches!(
            parse(&words(&format!("service install-start {encoded_d}"))),
            Some(Ok(HostCommand::InstallStartDaemon(_)))
        ));
        for refused in [
            "service",
            "service start now",
            "service install-start zz",
            "service install-start 2d2d",
            "service uninstall --pipe x",
            "common-worker --profile x",
            "dpapi seal --input same --output same",
        ] {
            assert!(!matches!(parse(&words(refused)), Some(Ok(_))), "{refused}");
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn hosting_outside_windows_fails_explicitly() {
        let error = execute(HostCommand::Uninstall)
            .err()
            .map(|error| error.kind());
        assert_eq!(error, Some(io::ErrorKind::Unsupported));
    }
}
