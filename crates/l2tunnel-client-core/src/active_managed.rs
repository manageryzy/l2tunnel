//! Shared authenticated lifecycle and strict catalog for active policy transactions.
use super::*;
use l2tunnel_runtime::active_management as runtime;
use serde::{Deserialize, Serialize};

/// Actual managed runtime types; no alternate state machine lives in the client.
pub use l2tunnel_runtime::active_management::{Config, Mode};

/// Maximum complete JSON catalog input, checked before deserialization.
pub const MAX_CATALOG_BYTES: usize = 32_768;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    version: u16,
    policies: Vec<Policy>,
    #[serde(default, deserialize_with = "present_transaction")]
    transaction: Option<Transaction>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Transaction {
    retry_ms: u64,
    phase_timeout_ms: u64,
    reconcile_timeout_ms: u64,
}
fn present_transaction<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Transaction>, D::Error> {
    Transaction::deserialize(deserializer).map(Some)
}
/// Complete serializable policy shared by catalog files, CLI and future GUI.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Negotiated MUX channel count, in 1..=256.
    pub channels: u16,
    /// Exactly 64 weights, each in 1..=1024; no implicit partial update.
    pub dscp_weights: Vec<u32>,
}
impl Policy {
    /// Validate before converting a local request into a complete runtime mode.
    pub fn mode(&self) -> io::Result<Mode> {
        if !(1..=256).contains(&self.channels)
            || self
                .dscp_weights
                .iter()
                .any(|weight| !(1..=1024).contains(weight))
        {
            return Err(invalid("active policy channel or weight outside bound"));
        }
        let dscp_weights: [u32; 64] = self
            .dscp_weights
            .as_slice()
            .try_into()
            .map_err(|_| invalid("active policy requires exactly 64 DSCP weights"))?;
        Ok(Mode {
            channels: self.channels,
            dscp_weights,
        })
    }
    /// Serialize an actual complete committed mode without exposing runtime internals.
    pub fn from_mode(mode: Mode) -> Self {
        Self {
            channels: mode.channels,
            dscp_weights: mode.dscp_weights.to_vec(),
        }
    }
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// Parse bounded version-one JSON and validate the complete negotiated policy catalog.
/// This function performs no credential, filesystem, socket or device operation.
pub fn catalog_from_json(
    input: &[u8],
    connection: ConnectionConfig,
    initial: super::active::Settings,
) -> io::Result<Config> {
    if input.is_empty() || input.len() > MAX_CATALOG_BYTES {
        return Err(invalid("active catalog input exceeds bound"));
    }
    let parsed: Catalog =
        serde_json::from_slice(input).map_err(|_| invalid("invalid active catalog JSON"))?;
    if parsed.version != 1 || !(1..=16).contains(&parsed.policies.len()) {
        return Err(invalid("active catalog version or count"));
    }
    if initial.duplex != connection.duplex {
        return Err(invalid("active managed duplex mismatch"));
    }
    let supported = parsed
        .policies
        .into_iter()
        .map(|policy| policy.mode())
        .collect::<io::Result<Vec<_>>>()?;
    let mut settings = Config {
        initial,
        supported,
        transaction: Default::default(),
    };
    if let Some(transaction) = parsed.transaction {
        settings.transaction.retry_ms = transaction.retry_ms;
        settings.transaction.phase_timeout_ms = transaction.phase_timeout_ms;
        settings.transaction.reconcile_timeout_ms = transaction.reconcile_timeout_ms;
    }
    connection.session()?;
    settings.validate(connection.runtime())?;
    Ok(settings)
}

/// Authenticate and retain full/paired-half lanes with the actual managed catalog digest.
pub async fn connect(
    address: SocketAddr,
    tls: &ClientTls,
    server_name: &str,
    identity: &MemberKey,
    connection: ConnectionConfig,
    config: &Config,
) -> io::Result<Link> {
    if config.initial.duplex != connection.duplex {
        return Err(invalid("active managed duplex mismatch"));
    }
    let session = runtime::session_config(connection.runtime(), config)?;
    connect_session(address, tls, server_name, identity, connection, session).await
}

/// Accept the same authenticated catalog before opening any native device.
pub async fn accept(
    listener: &TcpListener,
    tls: &ServerTls,
    allowlist: &MemberAllowlist,
    connection: ConnectionConfig,
    config: &Config,
) -> io::Result<Link> {
    if config.initial.duplex != connection.duplex {
        return Err(invalid("active managed duplex mismatch"));
    }
    let session = runtime::session_config(connection.runtime(), config)?;
    accept_session(listener, tls, allowlist, connection, session).await
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    fn connection() -> ConnectionConfig {
        ConnectionConfig {
            layer: PacketLayer::Ip,
            duplex: Duplex::Half,
            max_packet: 1600,
            compression: Compression::None,
            handshake_timeout: Duration::from_secs(30),
        }
    }
    fn policy(channels: u16) -> serde_json::Value {
        serde_json::json!({"channels": channels, "dscp_weights": vec![1u32; 64]})
    }
    fn document(policies: Vec<serde_json::Value>) -> Vec<u8> {
        serde_json::json!({"version":1, "policies":policies})
            .to_string()
            .into_bytes()
    }
    #[test]
    fn exact_catalog_uses_managed_digest_and_order_is_not_semantic() -> TestResult {
        let connection = connection();
        let initial = super::super::active::Settings::new(connection.runtime(), connection.duplex)?;
        let a = catalog_from_json(&document(vec![policy(4), policy(1)]), connection, initial)?;
        let b = catalog_from_json(&document(vec![policy(1), policy(4)]), connection, initial)?;
        let digest = runtime::session_config(connection.runtime(), &a)?;
        assert_eq!(digest, runtime::session_config(connection.runtime(), &b)?);
        assert_ne!(
            digest,
            l2tunnel_runtime::active::session_config(connection.runtime(), initial)?
        );
        Ok(())
    }
    #[test]
    fn schema_limits_and_duplicates_fail_before_io() -> TestResult {
        let connection = connection();
        let initial = super::super::active::Settings::new(connection.runtime(), connection.duplex)?;
        for bytes in [
            Vec::new(),
            vec![b' '; MAX_CATALOG_BYTES + 1],
            br#"{"version":2,"policies":[]}"#.to_vec(),
            br#"{"version":1,"version":1,"policies":[]}"#.to_vec(),
            br#"{"version":1,"policies":[],"extra":1}"#.to_vec(),
            document(vec![]),
            document(vec![policy(1)]),
            document(vec![policy(4); 17]),
            document(vec![policy(4), policy(4)]),
        ] {
            assert!(catalog_from_json(&bytes, connection, initial).is_err());
        }
        for length in [0, 63, 65] {
            let bad = serde_json::json!({"channels":4,"dscp_weights":vec![1u32;length]});
            assert!(catalog_from_json(&document(vec![bad]), connection, initial).is_err());
        }
        for weight in [0, 1025] {
            let bad = serde_json::json!({"channels":4,"dscp_weights":vec![weight;64]});
            assert!(catalog_from_json(&document(vec![bad]), connection, initial).is_err());
        }
        for channels in [0, 257] {
            assert!(
                catalog_from_json(&document(vec![policy(channels)]), connection, initial).is_err()
            );
        }
        let mut wrong = initial;
        wrong.duplex = Duplex::Full;
        assert!(catalog_from_json(&document(vec![policy(4)]), connection, wrong).is_err());
        Ok(())
    }

    #[test]
    fn explicit_transaction_timing_is_strict_bounded_and_authentication_bound() -> TestResult {
        let connection = connection();
        let initial = super::super::active::Settings::new(connection.runtime(), connection.duplex)?;
        let legacy = catalog_from_json(&document(vec![policy(4)]), connection, initial)?;
        let digest = runtime::session_config(connection.runtime(), &legacy)?;
        let parse = |timing: &str| {
            let input = format!(
                r#"{{"version":1,"policies":[{}],"transaction":{timing}}}"#,
                policy(4)
            );
            catalog_from_json(input.as_bytes(), connection, initial)
        };
        let explicit =
            parse(r#"{"retry_ms":100,"phase_timeout_ms":5000,"reconcile_timeout_ms":15000}"#)?;
        assert_eq!(explicit.transaction, legacy.transaction);
        assert_eq!(
            runtime::session_config(connection.runtime(), &explicit)?,
            digest
        );
        for (retry, phase, reconcile) in
            [(250, 5000, 15000), (100, 30000, 60000), (100, 5000, 60000)]
        {
            let changed = parse(&format!(
                r#"{{"retry_ms":{retry},"phase_timeout_ms":{phase},"reconcile_timeout_ms":{reconcile}}}"#
            ))?;
            assert_ne!(
                runtime::session_config(connection.runtime(), &changed)?,
                digest
            );
        }
        for malformed in [
            "null",
            "{}",
            r#"{"retry_ms":0,"phase_timeout_ms":5000,"reconcile_timeout_ms":15000}"#,
            r#"{"retry_ms":5001,"phase_timeout_ms":5000,"reconcile_timeout_ms":15000}"#,
            r#"{"retry_ms":100,"phase_timeout_ms":15001,"reconcile_timeout_ms":15000}"#,
            r#"{"retry_ms":100,"phase_timeout_ms":5000,"reconcile_timeout_ms":86400001}"#,
            r#"{"retry_ms":-1,"phase_timeout_ms":5000,"reconcile_timeout_ms":15000}"#,
            r#"{"retry_ms":100,"retry_ms":100,"phase_timeout_ms":5000,"reconcile_timeout_ms":15000}"#,
            r#"{"retry_ms":100,"phase_timeout_ms":5000,"reconcile_timeout_ms":15000,"extra":1}"#,
        ] {
            assert!(parse(malformed).is_err(), "accepted {malformed}");
        }
        let duplicate = format!(
            r#"{{"version":1,"policies":[{}],"transaction":{{"retry_ms":100,"phase_timeout_ms":5000,"reconcile_timeout_ms":15000}},"transaction":{{"retry_ms":100,"phase_timeout_ms":5000,"reconcile_timeout_ms":15000}}}}"#,
            policy(4)
        );
        assert!(catalog_from_json(duplicate.as_bytes(), connection, initial).is_err());
        Ok(())
    }
}
