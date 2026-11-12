//! Bounded offline geometry and visible-payload structural inspection.
//!
//! No sockets, credentials, tag verification, replay admission or native delivery.
//! Complete-packet aggregation counts exact TUN raw IP and conservatively bounded
//! TAP raw Ethernet units. Contexts and codec fragments cannot satisfy that metric.

#[path = "packed_capture_audit/audit.rs"]
mod audit;
#[path = "packed_capture_audit/config.rs"]
mod config;
#[path = "packed_capture_audit/ethernet.rs"]
mod ethernet;
#[cfg(test)]
#[path = "packed_capture_audit/tests.rs"]
mod tests;

use std::{fs::File, io::Read, path::Path};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const CONFIG_LIMIT: usize = 8192;
const INPUT_LIMIT: usize = 8 * 1024 * 1024;
const RECORD_LIMIT: usize = 4096;

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    // Reject nonregular local files observed here. This metadata check cannot
    // prevent path replacement races; the caller also bounds this offline process.
    if !path.metadata()?.is_file() {
        return Err("input must be a regular file".into());
    }
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err("input changed to a nonregular file".into());
    }
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("input byte limit exceeded".into());
    }
    Ok(bytes)
}

fn execute(args: &[String]) -> Result<serde_json::Value> {
    if args.len() == 1 && matches!(args[0].as_str(), "--help" | "-h") {
        return Ok(serde_json::json!({"version":1,"status":"help",
            "usage":"validate --config PATH | audit --config PATH --input PATH",
            "scope":"offline-only",
            "limitations":"IPv4 placeholder geometry; no identity or tag verification; audit only custom UDP integrity; complete TUN IP or bounded TAP Ethernet only, never codec contexts/fragments"}));
    }
    let command = match args {
        [command, flag, _] if command == "validate" && flag == "--config" => "validate",
        [command, flag, _, input, _]
            if command == "audit" && flag == "--config" && input == "--input" =>
        {
            "audit"
        }
        _ => {
            return Err(
                "expected validate --config PATH or audit --config PATH --input PATH".into(),
            );
        }
    };
    let bytes = read_bounded(Path::new(&args[2]), CONFIG_LIMIT)?;
    let config = config::Configuration::parse(&bytes)?;
    let derived = config.derive()?;
    if command == "validate" {
        Ok(
            serde_json::json!({"version":1,"status":"passed", "scope":"configuration-only", "geometry":derived.geometry}),
        )
    } else {
        config.audit_profile()?;
        let input = read_bounded(Path::new(&args[4]), INPUT_LIMIT)?;
        audit::inspect(&config, &derived, &input)
    }
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).take(6).collect();
    match execute(&args) {
        Ok(value) => println!("{value}"),
        Err(error) => {
            let message: String = error.to_string().chars().take(512).collect();
            println!(
                "{}",
                serde_json::json!({"version":1,"status":"failed","scope":"offline-only","error":message})
            );
            std::process::exit(1);
        }
    }
}
