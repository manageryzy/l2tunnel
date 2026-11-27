//! The Windows local service host (docs/modules/windows-local-service.md).
//!
//! One process owns the shared service [`Handle`] and its lifecycle [`Run`]
//! and serves local API versions 1, 4 and 5 on the local API named pipe.
//! Supports both:
//! - Legacy single-profile mode (`--profile DIR --wintun-dll DLL --wintun-sha256 HEX --address IP/LEN`)
//! - Full-parity multi-profile daemon mode (`--state-dir DIR --wintun-dll DLL --wintun-sha256 HEX [--address IP/LEN] [--pipe NAME]`)
//!   with stored profiles (`FileStore`), Windows IP Helper routing (`WindowsHost`),
//!   all cross-platform Common carriers (`quic-like`, `media-like`, `tls-like`,
//!   `openvpn-like`, `tcp`, `quic`), live Wintun MTU (`WindowsDevice`), DPAPI key
//!   unsealing, Event Log + rotating `service.log` diagnostics, and debounced
//!   network-change / sleep-resume auto-reconnect.
//!
//! [`Handle`]: l2tunnel_client_core::service::Handle
//! [`Run`]: l2tunnel_client_core::service::Run
use l2tunnel_platform_windows::local_pipe::{DEFAULT_PIPE_NAME, validate_pipe_name};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Bound for the orderly disconnect when the host is asked to stop.
pub const STOP_LIMIT: Duration = Duration::from_secs(10);
/// Default Wintun IPv4 address used by multi-profile daemon mode when a profile
/// does not specify `--tun-address` / `--address`.
pub const DEFAULT_TUN_ADDRESS: &str = "10.236.0.2/30";
const REQUIRED: [&str; 4] = ["--profile", "--wintun-dll", "--wintun-sha256", "--address"];
const OPTIONAL: [&str; 1] = ["--pipe"];
const DAEMON_REQUIRED: [&str; 1] = ["--state-dir"];
const DAEMON_OPTIONAL: [&str; 4] = ["--wintun-dll", "--wintun-sha256", "--address", "--pipe"];
const MAX_VALUE: usize = 4096;

/// Validated single-profile host inputs. Parsing opens no file, pipe or device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Options {
    profile: PathBuf,
    wintun_dll: String,
    wintun_sha256: String,
    address: String,
    pipe: String,
}

/// Validated multi-profile Windows daemon inputs. Parsing opens no file, pipe or device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonOptions {
    state_dir: PathBuf,
    wintun_dll: Option<String>,
    wintun_sha256: Option<String>,
    address: String,
    pipe: String,
    skip_acl_check: bool,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

impl Options {
    /// Parse `--profile DIR --wintun-dll DLL --wintun-sha256 HEX64 --address
    /// IPV4/PREFIX [--pipe \\.\pipe\NAME]`. The profile path must be absolute
    /// (a service starts in the system directory); the device inputs are
    /// checked for shape here and completely once the profile is loaded.
    pub fn parse(arguments: &[String]) -> io::Result<Self> {
        let mut values = BTreeMap::new();
        if !arguments.len().is_multiple_of(2)
            || arguments.len() > (REQUIRED.len() + OPTIONAL.len()) * 2
        {
            return Err(invalid("invalid service host options; use --help"));
        }
        for pair in arguments.chunks_exact(2) {
            let (key, value) = (pair[0].as_str(), pair[1].as_str());
            if !(REQUIRED.contains(&key) || OPTIONAL.contains(&key))
                || value.is_empty()
                || value.len() > MAX_VALUE
                || value.contains('\0')
                || value.starts_with("--")
                || values.insert(key, value).is_some()
            {
                return Err(invalid("invalid service host options; use --help"));
            }
        }
        let pipe = values
            .remove("--pipe")
            .unwrap_or(DEFAULT_PIPE_NAME)
            .to_owned();
        let mut get = |key| {
            values
                .remove(key)
                .map(str::to_owned)
                .ok_or_else(|| invalid("missing required service host option; use --help"))
        };
        let profile = PathBuf::from(get("--profile")?);
        if !profile.is_absolute() {
            return Err(invalid("--profile must be an absolute directory path"));
        }
        let options = Self {
            profile,
            wintun_dll: get("--wintun-dll")?,
            wintun_sha256: get("--wintun-sha256")?,
            address: get("--address")?,
            pipe,
        };
        validate_pipe_name(&options.pipe)?;
        crate::cli::device_shape(
            &options.wintun_dll,
            &options.wintun_sha256,
            &options.address,
        )?;
        Ok(options)
    }

    /// Local API pipe this host serves.
    pub fn pipe(&self) -> &str {
        &self.pipe
    }

    /// Profile directory loaded when serving starts.
    pub fn profile(&self) -> &Path {
        &self.profile
    }

    /// Wintun DLL path.
    pub fn wintun_dll(&self) -> &Path {
        Path::new(&self.wintun_dll)
    }

    /// Arguments the service control manager passes to `service run`, so an
    /// installed service reproduces exactly these options.
    pub fn launch_arguments(&self) -> Vec<OsString> {
        let mut arguments: Vec<OsString> = vec!["service".into(), "run".into()];
        for (key, value) in [
            ("--profile", self.profile.as_os_str()),
            ("--wintun-dll", self.wintun_dll.as_ref()),
            ("--wintun-sha256", self.wintun_sha256.as_ref()),
            ("--address", self.address.as_ref()),
            ("--pipe", self.pipe.as_ref()),
        ] {
            arguments.push(key.into());
            arguments.push(value.to_owned());
        }
        arguments
    }
}

impl DaemonOptions {
    /// Parse `--state-dir DIR [--wintun-dll DLL --wintun-sha256 HEX64] [--address IPV4/PREFIX] [--pipe \\.\pipe\NAME] [--skip-acl-check]`.
    pub fn parse(arguments: &[String]) -> io::Result<Self> {
        let mut values = BTreeMap::new();
        let mut skip_acl_check = false;
        let mut iter = arguments.iter();
        while let Some(arg) = iter.next() {
            if arg == "--skip-acl-check" {
                if skip_acl_check {
                    return Err(invalid("duplicate --skip-acl-check"));
                }
                skip_acl_check = true;
                continue;
            }
            let key = arg.as_str();
            if !(DAEMON_REQUIRED.contains(&key) || DAEMON_OPTIONAL.contains(&key)) {
                return Err(invalid("invalid daemon host option; use --help"));
            }
            let Some(value) = iter.next() else {
                return Err(invalid("missing daemon host option value; use --help"));
            };
            if value.is_empty()
                || value.len() > MAX_VALUE
                || value.contains('\0')
                || value.starts_with("--")
                || values.insert(key, value.as_str()).is_some()
            {
                return Err(invalid("invalid daemon host option value; use --help"));
            }
        }
        let pipe = values
            .remove("--pipe")
            .unwrap_or(DEFAULT_PIPE_NAME)
            .to_owned();
        let address = values
            .remove("--address")
            .unwrap_or(DEFAULT_TUN_ADDRESS)
            .to_owned();
        let wintun_dll = values.remove("--wintun-dll").map(str::to_owned);
        let wintun_sha256 = values.remove("--wintun-sha256").map(str::to_owned);
        let state_dir = values
            .remove("--state-dir")
            .map(PathBuf::from)
            .ok_or_else(|| invalid("missing required --state-dir option; use --help"))?;
        if !state_dir.is_absolute() {
            return Err(invalid("--state-dir must be an absolute directory path"));
        }
        validate_pipe_name(&pipe)?;
        match (&wintun_dll, &wintun_sha256) {
            (Some(dll), Some(sha)) => crate::cli::device_shape(dll, sha, &address)?,
            (None, None) => crate::cli::address_shape(&address)?,
            _ => {
                return Err(invalid(
                    "--wintun-dll and --wintun-sha256 must be provided together or both omitted",
                ));
            }
        }
        Ok(Self {
            state_dir,
            wintun_dll,
            wintun_sha256,
            address,
            pipe,
            skip_acl_check,
        })
    }

    /// Local API pipe this daemon serves.
    pub fn pipe(&self) -> &str {
        &self.pipe
    }

    /// State directory holding `profiles/`, `host-state.json`, and `service.log`.
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// Pinned Wintun DLL path, if configured at install time.
    pub fn wintun_dll(&self) -> Option<&Path> {
        self.wintun_dll.as_deref().map(Path::new)
    }

    /// Default Wintun IPv4 address/prefix.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Whether administrator-only directory ACL enforcement was explicitly bypassed.
    pub fn skip_acl_check(&self) -> bool {
        self.skip_acl_check
    }

    /// Arguments the service control manager passes to `service run-daemon`.
    pub fn launch_arguments(&self) -> Vec<OsString> {
        let mut arguments: Vec<OsString> = vec![
            "service".into(),
            "run-daemon".into(),
            "--state-dir".into(),
            self.state_dir.as_os_str().to_owned(),
        ];
        if let (Some(dll), Some(sha)) = (&self.wintun_dll, &self.wintun_sha256) {
            arguments.push("--wintun-dll".into());
            arguments.push(dll.into());
            arguments.push("--wintun-sha256".into());
            arguments.push(sha.into());
        }
        arguments.push("--address".into());
        arguments.push(self.address.as_str().into());
        arguments.push("--pipe".into());
        arguments.push(self.pipe.as_str().into());
        if self.skip_acl_check {
            arguments.push("--skip-acl-check".into());
        }
        arguments
    }
}

#[cfg(windows)]
pub use native::{audit_install_directories, prepare, serve, serve_daemon, sha256_file};

#[cfg(windows)]
mod native {
    use super::{DaemonOptions, Options, STOP_LIMIT};
    use l2tunnel_client_core::{
        local::{self, ProfileDocument},
        native::Native,
        secure_udp::native_client::{UdpClientProfile, prepare_profile_document},
        service::{
            self, Attachment, AutoRecoveryPolicy, Handle, Phase, Prepared, Run,
            device_mtu::WindowsDevice, host::Host, host_windows::WindowsHost,
            profile_store::FileStore, profiles::ProfileStore,
        },
    };
    use l2tunnel_device::PacketLayer;
    use l2tunnel_platform_windows::{
        Device, MtuController,
        event_log::ServiceLogger,
        net_watch::{HighResTimerGuard, InterfaceWatcher, TransitionLimiter},
        security::require_admin_only_directory,
    };
    use std::future::Future;
    use std::io;
    use std::path::Path;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// Audit service executable directory, data/state directory, and optional
    /// DLL parent directory (`WLS-08`).
    pub fn audit_install_directories(
        exe_dir: Option<&Path>,
        data_dir: &Path,
        dll_path: Option<&Path>,
        skip_acl_check: bool,
    ) -> io::Result<()> {
        if skip_acl_check {
            return Ok(());
        }
        if let Some(dir) = exe_dir {
            require_admin_only_directory(dir)?;
        } else if let Ok(exe) = std::env::current_exe()
            && let Some(dir) = exe.parent()
        {
            require_admin_only_directory(dir)?;
        }
        if data_dir.exists() {
            require_admin_only_directory(data_dir)?;
        }
        if let Some(dll_dir) = dll_path.and_then(Path::parent) {
            require_admin_only_directory(dll_dir)?;
        }
        Ok(())
    }

    fn deferred_wintun_attachment(
        dll: String,
        sha256: String,
        address: String,
        mtu: u16,
        peer: std::net::SocketAddr,
        mtu_ctrl: MtuController,
    ) -> io::Result<Attachment> {
        let device = crate::cli::device_config(&dll, &sha256, &address, mtu, peer)?;
        let mtu_host = Arc::new(WindowsDevice::new(mtu_ctrl.clone()));
        Ok(Attachment::deferred_native(PacketLayer::Ip, move || {
            let config = device.clone();
            let ctrl = mtu_ctrl.clone();
            async move {
                let mut creating =
                    crate::setup::Setup::spawn(move || Device::open_with_mtu(&config, Some(ctrl)))?;
                creating.finish().await.map(Native::new)
            }
        })
        .with_device_mtu(mtu_host))
    }

    /// Load the provisioned single-profile directory and complete device validation.
    pub fn prepare(options: &Options, mtu_ctrl: MtuController) -> io::Result<Prepared> {
        let profile = UdpClientProfile::load(&options.profile)?;
        let mtu = u16::try_from(profile.tun_mtu()).map_err(io::Error::other)?;
        let attachment = deferred_wintun_attachment(
            options.wintun_dll.clone(),
            options.wintun_sha256.clone(),
            options.address.clone(),
            mtu,
            profile.peer(),
            mtu_ctrl,
        )?;
        profile.prepare(attachment)
    }

    /// Serve one fixed profile on the local API pipe until `stop` resolves.
    pub fn serve(
        options: &Options,
        ready: impl FnOnce(),
        stop: impl Future<Output = ()> + Send,
        power_events: Option<tokio::sync::mpsc::UnboundedReceiver<()>>,
    ) -> io::Result<()> {
        let logger = Arc::new(ServiceLogger::new(
            "l2tunnel",
            Some(options.profile.join("service.log")),
        ));
        let _timer_guard = HighResTimerGuard::acquire();
        let mtu_ctrl = MtuController::new();
        let watch_mtu = mtu_ctrl.clone();
        let plan = prepare(options, mtu_ctrl).inspect_err(|e| {
            logger.error(&format!("single-profile prepare failed: {e}"));
        })?;
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(4)
            .build()?
            .block_on(async move {
                let server = local::Server::bind(options.pipe()).inspect_err(|e| {
                    logger.error(&format!("named pipe bind failed: {e}"));
                })?;
                let (handle, mut owner) = service::channel_with_plan(plan);
                handle.set_auto_recovery(AutoRecoveryPolicy::default_enabled());
                let _watcher = spawn_transition_watcher(
                    handle.clone(),
                    logger.clone(),
                    watch_mtu,
                    power_events,
                );
                logger.info(&format!("serving local API on {}", options.pipe()));
                ready();
                let res = tokio::select! {
                    result = &mut owner => result,
                    result = server.serve_service(handle.clone()) => result,
                    () = stop => release(&handle, &mut owner).await,
                };
                if let Err(e) = &res {
                    logger.error(&format!("service terminated with error: {e}"));
                } else {
                    logger.info("service stopped cleanly");
                }
                res
            })
    }

    /// Serve the full-parity multi-profile Windows daemon (`--state-dir`) with
    /// stored profiles, all cross-platform carriers, Wintun live MTU, Windows
    /// IP Helper routing, Event Log + file logging, and sleep/network reconnect.
    pub fn serve_daemon(
        options: &DaemonOptions,
        ready: impl FnOnce(),
        stop: impl Future<Output = ()> + Send,
        power_events: Option<tokio::sync::mpsc::UnboundedReceiver<()>>,
    ) -> io::Result<()> {
        std::fs::create_dir_all(&options.state_dir)?;
        let logger = Arc::new(ServiceLogger::new(
            "l2tunnel",
            Some(options.state_dir.join("service.log")),
        ));
        let mtu_ctrl = MtuController::new();
        let pinned_wintun = options
            .wintun_dll
            .clone()
            .zip(options.wintun_sha256.clone());
        let skip_acl_check = options.skip_acl_check;
        let default_addr = options.address.clone();
        let prep_mtu = mtu_ctrl.clone();
        let preparer = Arc::new(move |doc: &ProfileDocument| {
            let pinned_wintun = pinned_wintun.clone();
            let default_addr = default_addr.clone();
            let ctrl = prep_mtu.clone();
            prepare_profile_document(doc, move |mtu, peer, addr_override| {
                let address = addr_override.unwrap_or(&default_addr).to_owned();
                if let Some((dll, sha256)) = pinned_wintun {
                    deferred_wintun_attachment(dll, sha256, address, mtu, peer, ctrl)
                } else {
                    let mtu_host = Arc::new(WindowsDevice::new(ctrl.clone()));
                    Ok(Attachment::deferred_native(PacketLayer::Ip, move || {
                        let address = address.clone();
                        let ctrl = ctrl.clone();
                        async move {
                            let (dll, sha256) = discover_wintun(skip_acl_check)?;
                            let config =
                                crate::cli::device_config(&dll, &sha256, &address, mtu, peer)?;
                            let mut creating = crate::setup::Setup::spawn(move || {
                                Device::open_with_mtu(&config, Some(ctrl))
                            })?;
                            creating.finish().await.map(Native::new)
                        }
                    })
                    .with_device_mtu(mtu_host))
                }
            })
        });

        let _timer_guard = HighResTimerGuard::acquire();
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(4)
            .build()?
            .block_on(async move {
                let server = local::Server::bind(options.pipe()).inspect_err(|e| {
                    logger.error(&format!("named pipe bind failed: {e}"));
                })?;
                let (handle, mut owner) = service::channel();
                handle.set_auto_recovery(AutoRecoveryPolicy::default_enabled());
                let watch_mtu = mtu_ctrl.clone();
                let win_host = WindowsHost::open(&options.state_dir, mtu_ctrl)
                    .await
                    .inspect_err(|e| {
                        logger.error(&format!("WindowsHost open failed: {e}"));
                    })?;
                if handle.attach_host(win_host.clone()).is_err() {
                    return Err(io::Error::other("a device/route host is already attached"));
                }
                let store = FileStore::open(&options.state_dir, preparer).inspect_err(|e| {
                    logger.error(&format!("FileStore open failed: {e}"));
                })?;
                if handle.attach_profiles(store.clone()).is_err() {
                    return Err(io::Error::other("a profile store is already attached"));
                }
                if let Some(name) = ProfileStore::default_profile(&*store)
                    && let Ok(key) = handle.next_key()
                {
                    if let Err(err) = handle.connect_profile(&name, false, key) {
                        logger.warn(&format!(
                            "default profile {name} did not auto-connect: {err:?}"
                        ));
                    } else {
                        logger.info(&format!("auto-connecting default profile {name}"));
                    }
                }
                let mut stop_op = handle.enable_stop();
                let _watcher = spawn_transition_watcher(
                    handle.clone(),
                    logger.clone(),
                    watch_mtu,
                    power_events,
                );
                logger.info(&format!(
                    "daemon serving local API on {} (state: {})",
                    options.pipe(),
                    options.state_dir().display()
                ));
                ready();
                let res = tokio::select! {
                    result = &mut owner => result,
                    result = server.serve_service(handle.clone()) => result,
                    _ = stop_op.wait_for(|stopping| *stopping) => {
                        win_host.release().await;
                        Ok(())
                    }
                    () = stop => {
                        let r = release(&handle, &mut owner).await;
                        win_host.release().await;
                        r
                    }
                };
                if let Err(e) = &res {
                    logger.error(&format!("daemon terminated with error: {e}"));
                } else {
                    logger.info("daemon stopped cleanly");
                }
                res
            })
    }

    fn spawn_transition_watcher(
        handle: Handle,
        logger: Arc<ServiceLogger>,
        mtu_ctrl: MtuController,
        power_events: Option<tokio::sync::mpsc::UnboundedReceiver<()>>,
    ) -> Option<InterfaceWatcher> {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Option<u32>>();
        if let Some(mut power_rx) = power_events {
            let ptx = tx.clone();
            tokio::spawn(async move {
                while power_rx.recv().await.is_some() {
                    let _ = ptx.send(None);
                }
            });
        }
        let watcher = InterfaceWatcher::start(tx).ok();
        tokio::spawn(async move {
            let mut limiter = TransitionLimiter::default();
            let mut tick = tokio::time::interval(Duration::from_millis(500));
            loop {
                tokio::select! {
                    msg = rx.recv() => {
                        let Some(if_index) = msg else {
                            break;
                        };
                        // Ignore notifications for our own Wintun adapter and ignore
                        // interface chatter while not connected (e.g., adapter bring-up).
                        if handle.snapshot().phase != Phase::Connected {
                            continue;
                        }
                        if if_index.is_some() && if_index == mtu_ctrl.if_index() {
                            continue;
                        }
                        limiter.note_event(Instant::now());
                    }
                    _ = tick.tick() => {
                        if limiter.poll_trigger(Instant::now())
                            && handle.snapshot().phase == Phase::Connected
                            && let Ok(key) = handle.next_key()
                        {
                            let reply = handle
                                .operations_request(local::OperationRequest::new(
                                    local::OperationAction::Reconnect {
                                        request_key: key.value(),
                                    },
                                ))
                                .await;
                            if reply.ok {
                                logger.info(
                                    "network or power-resume transition detected; submitted debounced reconnect",
                                );
                            }
                        }
                    }
                }
            }
        });
        watcher
    }

    /// Compute lowercase hex SHA-256 of `path`.
    pub fn sha256_file(path: &Path) -> io::Result<String> {
        let bytes = std::fs::read(path)?;
        let digest = ring::digest::digest(&ring::digest::SHA256, &bytes);
        let mut hex = String::with_capacity(64);
        for b in digest.as_ref() {
            use std::fmt::Write as _;
            let _ = write!(hex, "{b:02x}");
        }
        Ok(hex)
    }

    /// Locate `wintun.dll` in the administrator-owned installation directory and
    /// compute its SHA-256. Enforces `WLS-08` admin-only parent directory ACLs
    /// unless `skip_acl_check` is true.
    fn discover_wintun(skip_acl_check: bool) -> io::Result<(String, String)> {
        let mut candidates = Vec::new();
        if let Ok(exe) = std::env::current_exe()
            && let Some(dir) = exe.parent()
        {
            candidates.push(dir.join("wintun.dll"));
        }
        candidates
            .push(l2tunnel_client_core::local::elevate::windows_install_dir().join("wintun.dll"));
        let Some(dll_path) = candidates.into_iter().find(|p| p.is_file()) else {
            let install_dir = l2tunnel_client_core::local::elevate::windows_install_dir();
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "wintun.dll not found in {}. Download official amd64 wintun.dll from https://www.wintun.net/ and place it there.",
                    install_dir.display()
                ),
            ));
        };
        if !skip_acl_check && let Some(parent) = dll_path.parent() {
            require_admin_only_directory(parent)?;
        }
        let hex = sha256_file(&dll_path)?;
        Ok((dll_path.display().to_string(), hex))
    }

    /// Orderly stop: the pipe server is already dropped, so no new request
    /// races the disconnect. The owner keeps running while it completes.
    async fn release(handle: &Handle, owner: &mut Run) -> io::Result<()> {
        let disconnect = async {
            let Ok(key) = handle.next_key() else { return };
            let Ok(accepted) = handle.disconnect(key) else {
                return;
            };
            let _completed = handle.wait(accepted.operation).await;
        };
        tokio::select! {
            result = owner => result,
            () = disconnect => Ok(()),
            () = tokio::time::sleep(STOP_LIMIT) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "disconnect did not complete before the stop bound; owners dropped",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn absolute(name: &str) -> String {
        if cfg!(windows) {
            format!(r"C:\ProgramData\l2tunnel\{name}")
        } else {
            format!("/etc/l2tunnel/{name}")
        }
    }
    fn arguments() -> Vec<String> {
        vec![
            "--profile".into(),
            absolute("profile"),
            "--wintun-dll".into(),
            absolute("wintun.dll"),
            "--wintun-sha256".into(),
            "ab".repeat(32),
            "--address".into(),
            "10.81.0.2/24".into(),
        ]
    }
    fn daemon_arguments() -> Vec<String> {
        vec![
            "--state-dir".into(),
            absolute("state"),
            "--wintun-dll".into(),
            absolute("wintun.dll"),
            "--wintun-sha256".into(),
            "ab".repeat(32),
        ]
    }

    #[test]
    fn options_are_strict_and_default_to_the_documented_pipe() -> io::Result<()> {
        let options = Options::parse(&arguments())?;
        assert_eq!(options.pipe(), DEFAULT_PIPE_NAME);
        assert_eq!(options.profile(), Path::new(&absolute("profile")));
        let mut custom = arguments();
        custom.extend([r"--pipe".into(), r"\\.\pipe\l2tunnel-test".into()]);
        assert_eq!(Options::parse(&custom)?.pipe(), r"\\.\pipe\l2tunnel-test");
        for (key, value) in [
            ("--profile", "relative\\profile"),
            ("--wintun-sha256", "zz"),
            ("--address", "10.81.0.2/33"),
            ("--address", "10.81.0.2"),
            ("--wintun-dll", "wintun.dll"),
        ] {
            let mut changed = arguments();
            if let Some(index) = changed.iter().position(|argument| argument == key) {
                changed[index + 1] = value.into();
            }
            assert!(Options::parse(&changed).is_err(), "{key} {value}");
        }
        for extra in [
            vec!["--pipe", r"\\server\pipe\l2tunnel"],
            vec!["--pipe", "l2tunnel"],
            vec!["--pipe", "--profile"],
            vec!["--control", "stdin"],
            vec!["--address", "10.81.0.3/24"],
            vec!["--pipe"],
            vec!["--pipe", "\\\\.\\pipe\\x\0"],
        ] {
            let mut changed = arguments();
            changed.extend(extra.iter().map(|value| (*value).to_owned()));
            assert!(Options::parse(&changed).is_err(), "{extra:?}");
        }
        for missing in REQUIRED {
            let mut changed = arguments();
            if let Some(index) = changed.iter().position(|argument| argument == missing) {
                changed.drain(index..index + 2);
            }
            assert!(Options::parse(&changed).is_err(), "{missing}");
        }
        let mut oversized = arguments();
        oversized[1] = absolute(&"p".repeat(MAX_VALUE));
        assert!(Options::parse(&oversized).is_err());
        Ok(())
    }

    #[test]
    fn daemon_options_parse_and_round_trip_launch_arguments() -> io::Result<()> {
        let opts = DaemonOptions::parse(&daemon_arguments())?;
        assert_eq!(opts.pipe(), DEFAULT_PIPE_NAME);
        assert_eq!(opts.address(), DEFAULT_TUN_ADDRESS);
        assert!(!opts.skip_acl_check());
        let launch: Vec<String> = opts
            .launch_arguments()
            .into_iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(launch[..2], ["service", "run-daemon"]);
        assert_eq!(DaemonOptions::parse(&launch[2..])?, opts);

        let mut custom = daemon_arguments();
        custom.extend([
            "--address".into(),
            "10.99.0.2/24".into(),
            "--pipe".into(),
            r"\\.\pipe\l2tunnel-d".into(),
            "--skip-acl-check".into(),
        ]);
        let opts2 = DaemonOptions::parse(&custom)?;
        assert_eq!(opts2.address(), "10.99.0.2/24");
        assert!(opts2.skip_acl_check());
        let launch2: Vec<String> = opts2
            .launch_arguments()
            .into_iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(DaemonOptions::parse(&launch2[2..])?, opts2);

        // Unpinned daemon options (--state-dir only) are valid and round-trip.
        let unpinned = DaemonOptions::parse(&["--state-dir".into(), absolute("state")])?;
        assert!(unpinned.wintun_dll().is_none());
        let launch_unpinned: Vec<String> = unpinned
            .launch_arguments()
            .into_iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(DaemonOptions::parse(&launch_unpinned[2..])?, unpinned);
        // Half-specified wintun pair is rejected.
        assert!(
            DaemonOptions::parse(&[
                "--state-dir".into(),
                absolute("state"),
                "--wintun-dll".into(),
                absolute("wintun.dll"),
            ])
            .is_err()
        );
        Ok(())
    }

    fn launch(options: &Options) -> Vec<String> {
        options
            .launch_arguments()
            .into_iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn launch_arguments_reproduce_the_installed_options() -> io::Result<()> {
        let mut custom = arguments();
        custom.extend(["--pipe".into(), r"\\.\pipe\l2tunnel-two".into()]);
        for options in [Options::parse(&custom)?, Options::parse(&arguments())?] {
            let launch = launch(&options);
            assert_eq!(launch[..2], ["service", "run"]);
            assert!(launch.iter().any(|argument| argument == "--pipe"));
            assert_eq!(Options::parse(&launch[2..])?, options);
        }
        Ok(())
    }
}
