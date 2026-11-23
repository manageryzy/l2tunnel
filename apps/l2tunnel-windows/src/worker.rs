//! Windows original-UDP service worker behind an already authenticated local host.
use std::io;

#[cfg(windows)]
fn run(plan: l2tunnel_client_core::service::Prepared) -> io::Result<()> {
    use l2tunnel_client_core::{local, service};
    let (handle, owner) = service::channel_with_plan(plan);
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()?
        .block_on(async move {
            tokio::select! {
                result = owner => result,
                result = local::serve_private_common_stream(tokio::io::stdin(), tokio::io::stdout(), &handle) => result,
            }
        })
}

/// Start the provisioned native worker. No adapter opens before authentication.
#[cfg(windows)]
pub fn execute(arguments: &[String]) -> io::Result<()> {
    use l2tunnel_client_core::{
        native::Native, secure_udp::native_client::UdpClientProfile, service::Attachment,
    };
    use l2tunnel_device::PacketLayer;
    use l2tunnel_platform_windows::Device;
    use std::path::Path;
    let options = options(arguments)?;
    let profile = UdpClientProfile::load(Path::new(options["--profile"]))?;
    let mtu = u16::try_from(profile.tun_mtu()).map_err(io::Error::other)?;
    let device = crate::cli::device_config(
        options["--wintun-dll"],
        options["--wintun-sha256"],
        options["--address"],
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
    run(profile.prepare(attachment)?)
}

/// Validate the worker invocation on other hosts without opening native resources.
#[cfg(not(windows))]
pub fn execute(arguments: &[String]) -> io::Result<()> {
    options(arguments)?;
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the Wintun worker requires Windows",
    ))
}

fn options(arguments: &[String]) -> io::Result<std::collections::BTreeMap<&str, &str>> {
    const KEYS: [&str; 4] = ["--profile", "--wintun-dll", "--wintun-sha256", "--address"];
    let mut options = std::collections::BTreeMap::new();
    if arguments.len() == KEYS.len() * 2 {
        for pair in arguments.chunks_exact(2) {
            let key = pair[0].as_str();
            let value = pair[1].as_str();
            if !KEYS.contains(&key)
                || value.is_empty()
                || value.len() > 4096
                || value.contains('\0')
                || value.starts_with("--")
                || options.insert(key, value).is_some()
            {
                break;
            }
        }
    }
    if options.len() != KEYS.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid native worker options",
        ));
    }
    Ok(options)
}
