//! `l2tunnel-linux-gui`: nonprivileged Linux desktop GUI over local API v5
//! (docs/modules/desktop-gui.md). All behavior lives in `l2tunnel-desktop-ui`.
fn main() -> std::process::ExitCode {
    l2tunnel_desktop_ui::main_entry("l2tunnel-linux-gui", std::env::args().skip(1))
}
