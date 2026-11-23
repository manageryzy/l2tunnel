//! Isolated, pre-provisioned Linux TUN/UDP measurement endpoint.
#[cfg(target_os = "linux")]
#[path = "path_bundle_lab/endpoint.rs"]
mod endpoint;

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    endpoint::run()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("path-bundle-lab requires a named Linux network namespace");
    std::process::exit(1);
}
