//! `l2tunnel-windows-gui`: nonprivileged Windows desktop GUI over local API v5
//! (docs/modules/desktop-gui.md, docs/modules/windows-local-service.md).
//!
//! Mirrors `l2tunnel-linux-gui`: stays completely unprivileged, connects to the
//! local API named pipe (`\\.\pipe\l2tunnel` by default), and when no service
//! answers offers a one-click "Start service…" button that triggers UAC to
//! auto-install (if missing) and start the LocalSystem service.
//!
//! Uses `glow` (hardware OpenGL) first for smooth, low-latency frame pacing with
//! automatic clean-process `--renderer wgpu` (DX12 / DX11 / Vulkan / Microsoft
//! WARP software fallback) on hosts/VMs/RDP sessions without OpenGL 3.2+, and
//! displays a native Win32 `MessageBoxW` plus `%LOCALAPPDATA%\l2tunnel\gui-startup.log`
//! on startup errors so failures are never silent under `windows_subsystem = "windows"`.
#![cfg_attr(windows, windows_subsystem = "windows")]

use std::process::ExitCode;

#[cfg(windows)]
fn record_gui_error(message: &str) {
    if let Some(local_app) = std::env::var_os("LOCALAPPDATA") {
        let dir = std::path::PathBuf::from(local_app).join("l2tunnel");
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(dir.join("gui-startup.log"), format!("{message}\n"));
    }
    l2tunnel_platform_windows::event_log::show_error_dialog(
        "l2tunnel GUI failed to start",
        message,
    );
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match l2tunnel_desktop_ui::main_entry_result("l2tunnel-windows-gui", args) {
        Ok(()) => ExitCode::SUCCESS,
        Err((code, msg)) => {
            if !msg.is_empty() {
                #[cfg(windows)]
                record_gui_error(&msg);
                #[cfg(not(windows))]
                eprintln!("{msg}");
            }
            code
        }
    }
}
