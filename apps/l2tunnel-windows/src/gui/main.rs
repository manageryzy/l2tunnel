//! `l2tunnel-windows-gui`: nonprivileged Windows desktop GUI over local API v5
//! (docs/modules/desktop-gui.md). `--socket` takes the service pipe name, for
//! example `\\.\pipe\l2tunnel`. All behavior lives in `l2tunnel-desktop-ui`.
//!
//! The binary uses the Windows GUI subsystem, so no console window opens;
//! `--help`/`--version` text and startup errors are therefore not visible when
//! it is started from Explorer.
#![cfg_attr(windows, windows_subsystem = "windows")]
fn main() -> std::process::ExitCode {
    l2tunnel_desktop_ui::main_entry("l2tunnel-windows-gui", std::env::args().skip(1))
}
