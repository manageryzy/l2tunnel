//! Explicit CLI naming policy shared by the actual maintained TLS readers.

use super::*;

pub(super) fn policy(options: &BTreeMap<String, String>) -> io::Result<auth::ClientSni> {
    match options.get("--sni") {
        Some(name) => auth::ClientSni::named(name)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error)),
        None => Ok(auth::ClientSni::Disabled),
    }
}

pub(super) fn pin(options: &BTreeMap<String, String>) -> io::Result<Option<auth::ServerIdentity>> {
    match options.get("--server-pin") {
        Some(hex) => auth::ServerIdentity::from_hex(hex)
            .map(Some)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error)),
        None => Ok(None),
    }
}

pub(super) fn preflight(command: &str, options: &BTreeMap<String, String>) -> io::Result<()> {
    let has_sni = options.contains_key("--sni");
    let has_pin = options.contains_key("--server-pin");
    if !has_sni && !has_pin {
        return Ok(());
    }
    if has_sni {
        policy(options)?;
    }
    if has_pin {
        pin(options)?;
    }
    let inspection = command == "inspect-common-transaction-plan";
    if command != "connect"
        && !(inspection && options.get("--role").map(String::as_str) == Some("connect"))
    {
        return Err(input(
            "--sni and --server-pin are client-only TLS trust/naming policies",
        ));
    }
    let carrier = options
        .get("--carrier")
        .map(String::as_str)
        .unwrap_or("tcp");
    let records = options
        .get("--record-profile")
        .map(String::as_str)
        .unwrap_or("frame");
    if has_sni {
        let sni_supported = match carrier {
            "tcp" => {
                (!inspection && records == "frame")
                    || (records == "common" && options.contains_key("--maintained-policy"))
            }
            "raw-packet" if records == "common" => {
                options.contains_key("--common-transaction-plan")
            }
            "raw-packet" if !inspection => records == "frame",
            "openvpn-like" => {
                records == "common" && options.contains_key("--common-transaction-plan")
            }
            _ => false,
        };
        if !sni_supported {
            return Err(input(
                "--sni requires an explicitly supported TLS credential reader",
            ));
        }
    }
    if has_pin {
        let pin_supported = match carrier {
            "tcp" => {
                (!inspection && records == "frame")
                    || (records == "common" && options.contains_key("--maintained-policy"))
            }
            "quic" => records == "common" && options.contains_key("--maintained-policy"),
            "raw-packet" if records == "common" => {
                options.contains_key("--common-transaction-plan")
            }
            "raw-packet" if !inspection => records == "frame",
            "openvpn-like" => {
                records == "common" && options.contains_key("--common-transaction-plan")
            }
            _ => false,
        };
        if !pin_supported {
            return Err(input(
                "--server-pin requires an explicitly supported TLS or QUIC carrier",
            ));
        }
    }
    verification_name(options)?;
    Ok(())
}

fn verification_name(options: &BTreeMap<String, String>) -> io::Result<&str> {
    let identity = required(options, "--server-name")?;
    if identity.is_empty() || identity.len() > 253 || identity.as_bytes().contains(&0) {
        return Err(input(
            "TLS verification name exceeds the naming observation bound",
        ));
    }
    Ok(identity)
}

/// This is configuration only. Neither parser nor offline inspection authenticates TLS.
pub(super) fn requested(
    options: &BTreeMap<String, String>,
) -> io::Result<Option<serde_json::Value>> {
    let auth::ClientSni::Named(name) = policy(options)? else {
        return Ok(None);
    };
    Ok(Some(serde_json::json!({
        "event":"tls_name_policy","schema":1,
        "requested":{"sni":name,"verification_name":verification_name(options)?},
        "effective":null,"authenticated":false
    })))
}

pub(super) fn report_requested(options: &BTreeMap<String, String>) -> io::Result<()> {
    if let Some(value) = requested(options)? {
        let mut stderr = io::stderr().lock();
        serde_json::to_writer(&mut stderr, &value).map_err(io::Error::other)?;
        writeln!(stderr)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn client(options: &BTreeMap<String, String>) -> io::Result<ClientTls> {
    policy(options)?;
    let roots = [bounded_file(required(options, "--ca")?, 65536)?];
    from_roots(options, &roots)
}

#[cfg(target_os = "linux")]
pub(super) fn from_roots(
    options: &BTreeMap<String, String>,
    roots: &[Vec<u8>],
) -> io::Result<ClientTls> {
    ClientTls::from_der_roots_with_policy(roots, policy(options)?, pin(options)?)
        .map_err(auth_error)
}

#[cfg(test)]
#[path = "cli_tls_tests.rs"]
mod tests;
