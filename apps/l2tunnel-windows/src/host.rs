//! The Windows local service host (docs/modules/windows-local-service.md).
//!
//! One process owns the shared service [`Handle`] and its lifecycle [`Run`]
//! and serves local API versions 1, 4 and 5 on the local API named pipe. The
//! former private `common-worker` child (framed API4 on stdio behind a GUI
//! host) is replaced: hosting the handle directly keeps exactly one service
//! owner, lets version-5 operations reach it unchanged, and removes a second
//! process and IPC hop that could only relay status, reconnect and disconnect.
//!
//! Option parsing is portable and side-effect-free. Loading the profile and
//! serving are Windows-only; no Wintun adapter opens until a connect or
//! reconnect operation is accepted.
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
const REQUIRED: [&str; 4] = ["--profile", "--wintun-dll", "--wintun-sha256", "--address"];
const OPTIONAL: [&str; 1] = ["--pipe"];
const MAX_VALUE: usize = 4096;

/// Validated host inputs. Parsing opens no file, pipe or device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Options {
    profile: PathBuf,
    wintun_dll: String,
    wintun_sha256: String,
    address: String,
    pipe: String,
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

#[cfg(windows)]
pub use native::{prepare, serve};

#[cfg(windows)]
mod native {
    use super::{Options, STOP_LIMIT};
    use l2tunnel_client_core::{
        local,
        native::Native,
        secure_udp::native_client::UdpClientProfile,
        service::{self, Attachment, Handle, Prepared, Run},
    };
    use l2tunnel_device::PacketLayer;
    use l2tunnel_platform_windows::Device;
    use std::future::Future;
    use std::io;

    /// Load the provisioned profile and complete device validation. No socket
    /// or adapter opens here; the attachment opens Wintun only when the
    /// service accepts a connect or reconnect.
    pub fn prepare(options: &Options) -> io::Result<Prepared> {
        let profile = UdpClientProfile::load(&options.profile)?;
        let mtu = u16::try_from(profile.tun_mtu()).map_err(io::Error::other)?;
        let device = crate::cli::device_config(
            &options.wintun_dll,
            &options.wintun_sha256,
            &options.address,
            mtu,
            profile.peer(),
        )?;
        let attachment = Attachment::deferred_native(PacketLayer::Ip, move || {
            let config = device.clone();
            async move {
                let mut creating = crate::setup::Setup::spawn(move || Device::open(&config))?;
                creating.finish().await.map(Native::new)
            }
        });
        profile.prepare(attachment)
    }

    /// Serve the local API on the options' pipe until `stop` resolves, the
    /// service owner ends, or the pipe server fails. `ready` runs once the
    /// pipe exists. Stopping first submits a disconnect and waits up to
    /// [`STOP_LIMIT`] for its actual completion, then drops the owner.
    pub fn serve(
        options: &Options,
        ready: impl FnOnce(),
        stop: impl Future<Output = ()> + Send,
    ) -> io::Result<()> {
        let plan = prepare(options)?;
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .build()?
            .block_on(async move {
                let server = local::Server::bind(options.pipe())?;
                let (handle, mut owner) = service::channel_with_plan(plan);
                ready();
                tokio::select! {
                    result = &mut owner => result,
                    result = server.serve_service(handle.clone()) => result,
                    () = stop => release(&handle, &mut owner).await,
                }
            })
    }

    /// Orderly stop: the pipe server is already dropped, so no new request
    /// races the disconnect. The owner keeps running while it completes.
    async fn release(handle: &Handle, owner: &mut Run) -> io::Result<()> {
        let disconnect = async {
            // Idle or already stopping services refuse; there is nothing to release.
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
            // The installed command always records the pipe explicitly.
            assert!(launch.iter().any(|argument| argument == "--pipe"));
            assert_eq!(Options::parse(&launch[2..])?, options);
        }
        Ok(())
    }
}
