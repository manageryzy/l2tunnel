//! Windows service installation and service-control-manager entry
//! (docs/modules/windows-local-service.md, WLS-04/WLS-05).
//!
//! Command parsing is portable. Installing, removing and running as a service
//! use the maintained `windows-service` crate, which owns the native service
//! FFI; this application contains no `unsafe` code.
use crate::host::Options;
use std::io;

/// Service name registered with the service control manager.
pub const SERVICE_NAME: &str = "l2tunnel";
/// Display name shown by the Services console.
pub const DISPLAY_NAME: &str = "l2tunnel local service";
/// Service description.
pub const DESCRIPTION: &str = "Owns the l2tunnel Wintun tunnel and serves the local API named pipe to the nonprivileged l2tunnelctl and l2tunnel-windows-gui frontends.";
/// Service-specific exit code reported when serving failed.
pub const FAILED_EXIT_CODE: u32 = 1;

/// A host-mode command. Parsing performs no I/O.
#[derive(Debug, Eq, PartialEq)]
pub enum HostCommand {
    /// Serve in this console until Ctrl+C (testing; requires elevation).
    Foreground(Options),
    /// Register the service to run `service run` with these options.
    Install(Options),
    /// Register the service with these options, then start it (the
    /// frontends' UAC prompt, `local::elevate`).
    InstallStart(Options),
    /// Start the registered service and wait until it runs.
    Start,
    /// Stop (if running) and remove the registered service.
    Uninstall,
    /// Entry used by the service control manager only.
    Run(Options),
}

/// Parse a host-mode command, or `None` when `arguments` is not one.
pub fn parse(arguments: &[String]) -> Option<io::Result<HostCommand>> {
    let words: Vec<&str> = arguments.iter().take(2).map(String::as_str).collect();
    Some(match words.as_slice() {
        ["foreground", ..] => Options::parse(&arguments[1..]).map(HostCommand::Foreground),
        ["service", "install"] => Options::parse(&arguments[2..]).map(HostCommand::Install),
        ["service", "run"] => Options::parse(&arguments[2..]).map(HostCommand::Run),
        ["service", "start"] if arguments.len() == 2 => Ok(HostCommand::Start),
        // One hex argument: the UAC launch passes a flat command line, and
        // paths with spaces or quotes would not survive its quoting.
        ["service", "install-start"] if arguments.len() == 3 => {
            l2tunnel_client_core::local::elevate::decode_arguments(&arguments[2])
                .and_then(|options| Options::parse(&options))
                .map(HostCommand::InstallStart)
        }
        ["service", "uninstall"] if arguments.len() == 2 => Ok(HostCommand::Uninstall),
        ["service", ..] => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "use: service install OPTIONS | service start | service uninstall | service run OPTIONS",
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
                        // Without a console handler only process termination stops it.
                        std::future::pending::<()>().await;
                    }
                },
            )
        }
        HostCommand::Install(options) => native::install(&options),
        HostCommand::InstallStart(options) => {
            native::install(&options)?;
            native::start()
        }
        HostCommand::Start => native::start(),
        HostCommand::Uninstall => native::uninstall(),
        HostCommand::Run(options) => native::run(options),
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
    use crate::host::Options;
    use std::ffi::OsString;
    use std::io;
    use std::sync::OnceLock;
    use std::time::Duration;
    use windows_service::service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
        ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::{define_windows_service, service_dispatcher};

    /// Options of this process's `service run`, read by the dispatcher thread.
    static OPTIONS: OnceLock<Options> = OnceLock::new();
    /// Wait hint while starting or stopping (profile load and disconnect bound).
    const WAIT_HINT: Duration = Duration::from_secs(15);

    fn service_error(error: windows_service::Error) -> io::Error {
        match error {
            windows_service::Error::Winapi(error) => error,
            other => io::Error::new(io::ErrorKind::InvalidInput, other.to_string()),
        }
    }

    /// Register the service (manual start, LocalSystem) after validating the
    /// complete configuration, including loading the profile.
    pub fn install(options: &Options) -> io::Result<()> {
        crate::host::prepare(options)?;
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
            executable_path: std::env::current_exe()?,
            launch_arguments: options.launch_arguments(),
            dependencies: Vec::new(),
            account_name: None,
            account_password: None,
        };
        let service = manager
            .create_service(&info, ServiceAccess::CHANGE_CONFIG)
            .map_err(service_error)?;
        service.set_description(DESCRIPTION).map_err(service_error)
    }

    /// Start the registered service and wait until it reports running.
    pub fn start() -> io::Result<()> {
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

    /// Hand this process to the service control manager. Fails explicitly
    /// when not started by it; use `foreground` for console testing.
    pub fn run(options: Options) -> io::Result<()> {
        OPTIONS
            .set(options)
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
        // The service has no console; the exit code is its failure signal
        // until Windows event logging exists (CL-27).
        let _reported = run_service();
    }

    fn run_service() -> windows_service::Result<()> {
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let handler = move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _sent = stop.send(true);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let handle = service_control_handler::register(SERVICE_NAME, handler)?;
        handle.set_service_status(status(
            ServiceState::StartPending,
            0,
            ServiceControlAccept::empty(),
        ))?;
        let running = handle;
        let result = match OPTIONS.get() {
            Some(options) => crate::host::serve(
                options,
                move || {
                    let _reported = running.set_service_status(status(
                        ServiceState::Running,
                        0,
                        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
                    ));
                },
                async move {
                    let mut stopped = stopped;
                    if stopped.wait_for(|stop| *stop).await.is_err() {
                        std::future::pending::<()>().await;
                    }
                },
            ),
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
            parse(&words("service uninstall")),
            Some(Ok(HostCommand::Uninstall))
        ));
        assert!(matches!(
            parse(&words("service start")),
            Some(Ok(HostCommand::Start))
        ));
        let encoded = l2tunnel_client_core::local::elevate::encode_arguments(&words(&options()))
            .unwrap_or_default();
        assert!(matches!(
            parse(&words(&format!("service install-start {encoded}"))),
            Some(Ok(HostCommand::InstallStart(_)))
        ));
        for refused in [
            "service",
            "service start now",
            "service install-start",
            "service install-start zz",
            "service install-start 2d2d",
            "service uninstall --pipe x",
            "common-worker --profile x",
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
