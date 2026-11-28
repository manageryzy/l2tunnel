//! Shared desktop GUI for l2tunnel (egui/eframe, docs/modules/desktop-gui.md).
//!
//! A nonprivileged frontend over local API version 5. The platform binaries
//! (`l2tunnel-linux-gui`, `l2tunnel-windows-gui`) only call [`main_entry`].
//! On Windows `--socket` takes the service pipe name (for example
//! `\\.\pipe\l2tunnel`). The GUI never owns tunnel devices or sockets, and
//! closing the window never disconnects.
use std::process::ExitCode;

#[cfg(any(unix, windows))]
mod app;
#[cfg(any(unix, windows))]
mod browse;
#[cfg(test)]
mod fixture;
pub mod model;
#[cfg(any(unix, windows))]
mod pages;
#[cfg(any(unix, windows))]
mod policy_panel;
pub mod present;
pub mod profile_fields;
#[cfg(any(unix, windows))]
mod profiles;
#[cfg(any(unix, windows))]
mod socks_panel;
#[cfg(any(unix, windows))]
mod start;
pub mod stats;
pub mod test_panel;
#[cfg(any(unix, windows))]
mod tuning_panel;
#[cfg(any(unix, windows))]
mod wizard_panel;
#[cfg(any(unix, windows))]
mod worker;

/// Run the GUI binary `name` with its command-line arguments (without `argv[0]`).
#[cfg(any(unix, windows))]
pub fn main_entry(name: &'static str, args: impl IntoIterator<Item = String>) -> ExitCode {
    match main_entry_result(name, args) {
        Ok(()) => ExitCode::SUCCESS,
        Err((code, msg)) => {
            if !msg.is_empty() {
                eprintln!("{msg}");
            }
            code
        }
    }
}

/// Run the GUI binary `name` and return any startup/CLI error message so the
/// caller (such as `l2tunnel-windows-gui` under `windows_subsystem = "windows"`)
/// can display a native error dialog and log it.
#[cfg(any(unix, windows))]
pub fn main_entry_result(
    name: &'static str,
    args: impl IntoIterator<Item = String>,
) -> Result<(), (ExitCode, String)> {
    let usage = format!(
        "usage: {name} [--socket CONTROL_SOCKET] [--page overview|connection|devices|routes|socks5|statistics|management|events] [--renderer wgpu|glow] [--import-uri l2tunnel://... | l2tunnel://...]"
    );
    let raw_args: Vec<String> = args.into_iter().collect();
    let mut socket = String::new();
    let mut page = pages::Page::Overview;
    let mut import_uri: Option<String> = None;
    let mut requested_renderer: Option<String> = None;
    let mut args = raw_args.iter().cloned().peekable();
    while let Some(arg) = args.next() {
        if arg.starts_with("l2tunnel://") {
            import_uri = Some(arg);
            page = pages::Page::Management;
            continue;
        }
        match arg.as_str() {
            "--socket" => match args.next() {
                Some(path) => socket = path,
                None => return Err((ExitCode::from(2), usage)),
            },
            "--page" => match args.next().and_then(|name| pages::Page::parse(&name)) {
                Some(selected) => page = selected,
                None => return Err((ExitCode::from(2), usage)),
            },
            "--renderer" => match args.next() {
                Some(r) if matches!(r.as_str(), "wgpu" | "glow") => requested_renderer = Some(r),
                _ => return Err((ExitCode::from(2), usage)),
            },
            "--import-uri" => match args.next() {
                Some(uri) if uri.starts_with("l2tunnel://") => {
                    import_uri = Some(uri);
                    page = pages::Page::Management;
                }
                _ => return Err((ExitCode::from(2), usage)),
            },
            "--help" | "-h" => {
                println!("{usage}");
                return Ok(());
            }
            "--version" => {
                println!("{name} {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            _ => return Err((ExitCode::from(2), usage)),
        }
    }
    if socket.is_empty() {
        // Attach to this user's service (the one Start service installs);
        // when it is not running the window offers to start/auto-install it.
        socket = l2tunnel_client_core::local::elevate::StartRequest::new(Default::default())
            .socket
            .display()
            .to_string();
    }
    let run_once = |renderer: eframe::Renderer,
                    socket: String,
                    import_uri: Option<String>|
     -> Result<(), eframe::Error> {
        #[allow(unused_mut)]
        let mut options = eframe::NativeOptions {
            renderer,
            viewport: eframe::egui::ViewportBuilder::default()
                .with_title("l2tunnel")
                .with_inner_size([1100.0, 780.0])
                .with_min_inner_size([640.0, 480.0]),
            ..Default::default()
        };
        #[cfg(windows)]
        {
            // When WGPU is used (fallback or `--renderer wgpu`), avoid DX12
            // AutoVsync + frame_latency=1 stutter and discrete-GPU wake lag.
            options.wgpu_options.surface = eframe::SurfaceConfig {
                present_mode: eframe::wgpu::PresentMode::AutoNoVsync,
                desired_maximum_frame_latency: Some(2),
            };
            if let eframe::egui_wgpu::WgpuSetup::CreateNew(ref mut setup) =
                options.wgpu_options.wgpu_setup
            {
                setup.power_preference = eframe::wgpu::PowerPreference::LowPower;
            }
        }
        eframe::run_native(
            name,
            options,
            Box::new(move |creation| {
                let context = creation.egui_ctx.clone();
                let worker = worker::Worker::start(move || context.request_repaint())?;
                let mut app = app::App::new(worker, socket, page);
                if let Some(uri) = import_uri {
                    app.prefill_share_uri(uri);
                }
                Ok(Box::new(app))
            }),
        )
    };

    #[cfg(windows)]
    {
        // Prefer Glow (hardware OpenGL) on Windows for smooth, low-latency UI
        // frame pacing without DX12 swapchain stutter; automatically respawn
        // cleanly with `--renderer wgpu` (DX12 / DX11 / Vulkan / Microsoft WARP)
        // on hosts/VMs/RDP sessions that lack an OpenGL 3.2+ driver.
        let renderer = match requested_renderer.as_deref() {
            Some("wgpu") => eframe::Renderer::Wgpu,
            _ => eframe::Renderer::Glow,
        };
        match run_once(renderer, socket, import_uri) {
            Ok(()) => Ok(()),
            Err(err) => {
                if requested_renderer.is_none()
                    && let Ok(exe) = std::env::current_exe()
                {
                    let mut child_args = vec!["--renderer".to_owned(), "wgpu".to_owned()];
                    child_args.extend(raw_args);
                    if std::process::Command::new(exe)
                        .args(child_args)
                        .spawn()
                        .is_ok()
                    {
                        return Ok(());
                    }
                }
                Err((
                    ExitCode::from(1),
                    format!("{name}: failed to initialize graphics window ({renderer:?}): {err}"),
                ))
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = requested_renderer;
        run_once(eframe::Renderer::Glow, socket, import_uri)
            .map_err(|error| (ExitCode::from(1), format!("{name}: {error}")))
    }
}

/// The local API transport is not implemented on this platform yet.
#[cfg(not(any(unix, windows)))]
pub fn main_entry(name: &'static str, _args: impl IntoIterator<Item = String>) -> ExitCode {
    eprintln!("{name}: the local API transport is not implemented on this platform");
    ExitCode::from(6)
}
