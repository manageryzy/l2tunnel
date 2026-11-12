//! Canonical negotiated active-TUN switching policies.
//!
//! Policies are authenticated before the bounded runtime transaction can select them.
use super::{Duplex, RuntimeConfig, active, invalid};
use l2tunnel_auth::SessionConfig;
use l2tunnel_core::{ConfigDigest, Epoch};
use l2tunnel_management::transaction::{self, Configuration, configuration_digest};
use std::io;

const POLICY_BYTES: usize = 296;
const MAX_MODES: usize = 16;

mod runtime;
pub use runtime::{ControlError, ControlHandle, ControlReceiver, Status, channel, run};

/// Compatible mutable policy; every old flow must retire before it takes effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mode {
    /// CRC-affinity channel count in 1..=256.
    pub channels: u16,
    /// Trusted first-packet flow weight for each DSCP, each in 1..=1024.
    pub dscp_weights: [u32; 64],
}
impl Mode {
    /// Extract exactly the mutable fields from an existing active configuration.
    pub fn from_settings(settings: active::Settings) -> Self {
        Self {
            channels: settings.channels,
            dscp_weights: settings.dscp_weights,
        }
    }
    fn validate(self) -> Result<(), transaction::Error> {
        if !(1..=256).contains(&self.channels)
            || self
                .dscp_weights
                .iter()
                .any(|weight| !(1..=1024).contains(weight))
        {
            return Err(transaction::Error::Configuration(
                "active policy channel or weight",
            ));
        }
        Ok(())
    }
}

/// Initial immutable settings and finite pre-authenticated policy catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    /// Initial active configuration; only channels and DSCP weights can later change.
    pub initial: active::Settings,
    /// Unique supported policies, including initial, in a validated count 1..=16.
    pub supported: Vec<Mode>,
    /// Finite existing management retry/precommit/reconciliation limits.
    pub transaction: transaction::Settings,
}
impl Config {
    /// Validate every bound and initial-catalog membership without network I/O.
    pub fn validate(&self, runtime: RuntimeConfig) -> io::Result<()> {
        self.catalog(runtime).map(|_| ())
    }
    fn catalog(&self, runtime: RuntimeConfig) -> io::Result<Catalog> {
        if self.supported.is_empty() || self.supported.len() > MAX_MODES {
            return Err(invalid("active management catalog count"));
        }
        self.transaction.validate().map_err(io::Error::other)?;
        active::session_config(runtime, self.initial)?;
        // Normalize only the two mutable fields. Every actual derived target,
        // observation and fixed runtime bound remains in the active v3 digest.
        let immutable = active::session_config(
            runtime,
            active::Settings {
                channels: 1,
                dscp_weights: [1; 64],
                ..self.initial
            },
        )?
        .digest;
        let initial = Policy {
            immutable,
            duplex: self.initial.duplex,
            mode: Mode::from_settings(self.initial),
        };
        let mut policies = Vec::with_capacity(self.supported.len());
        for mode in &self.supported {
            mode.validate().map_err(io::Error::other)?;
            if policies.iter().any(|policy: &Policy| policy.mode == *mode) {
                return Err(invalid("duplicate active management policy"));
            }
            policies.push(Policy {
                immutable,
                duplex: self.initial.duplex,
                mode: *mode,
            });
        }
        if !policies.contains(&initial) {
            return Err(invalid(
                "initial active management policy missing from catalog",
            ));
        }
        Ok(Catalog { initial, policies })
    }
}

/// Authoritatively completed policy result, for the future transaction runtime.
/// Constructing this value alone never applies a switch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SwitchOutcome {
    /// Active epoch after both barriers, commit acknowledgment and retirement.
    pub epoch: Epoch,
    /// Digest of the complete immutable-bound active policy.
    pub digest: ConfigDigest,
    /// Effective mutable channel/weight policy.
    pub mode: Mode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Policy {
    immutable: ConfigDigest,
    duplex: Duplex,
    mode: Mode,
}
struct Catalog {
    initial: Policy,
    policies: Vec<Policy>,
}
impl Configuration for Policy {
    const ENCODED_LEN: usize = POLICY_BYTES;
    const DIGEST_DOMAIN: &'static [u8] = b"l2tunnel/active-management/policy/v1\0";
    fn validate(&self) -> Result<(), transaction::Error> {
        self.mode.validate()
    }
    fn encode_into(&self, output: &mut [u8]) -> Result<(), transaction::Error> {
        self.validate()?;
        if output.len() != POLICY_BYTES {
            return Err(transaction::Error::Malformed);
        }
        output[..4].copy_from_slice(b"LATM");
        output[4] = 1;
        output[5] = match self.duplex {
            Duplex::Half => 1,
            Duplex::Full => 2,
        };
        output[6..8].copy_from_slice(&self.mode.channels.to_be_bytes());
        output[8..40].copy_from_slice(&self.immutable.0);
        for (slot, weight) in output[40..].chunks_exact_mut(4).zip(self.mode.dscp_weights) {
            slot.copy_from_slice(&weight.to_be_bytes());
        }
        Ok(())
    }
    fn decode(input: &[u8]) -> Result<Self, transaction::Error> {
        if input.len() != POLICY_BYTES || &input[..4] != b"LATM" || input[4] != 1 {
            return Err(transaction::Error::Malformed);
        }
        let duplex = match input[5] {
            1 => Duplex::Half,
            2 => Duplex::Full,
            _ => return Err(transaction::Error::Malformed),
        };
        let channels = u16::from_be_bytes(
            input[6..8]
                .try_into()
                .map_err(|_| transaction::Error::Malformed)?,
        );
        let immutable = ConfigDigest(
            input[8..40]
                .try_into()
                .map_err(|_| transaction::Error::Malformed)?,
        );
        let mut dscp_weights = [0; 64];
        for (weight, slot) in dscp_weights.iter_mut().zip(input[40..].chunks_exact(4)) {
            *weight =
                u32::from_be_bytes(slot.try_into().map_err(|_| transaction::Error::Malformed)?);
        }
        let value = Self {
            immutable,
            duplex,
            mode: Mode {
                channels,
                dscp_weights,
            },
        };
        value.validate()?;
        Ok(value)
    }
    fn channels(&self) -> u16 {
        self.mode.channels
    }
    fn duplex(&self) -> Duplex {
        self.duplex
    }
}

/// Exact initial managed binding, incompatible with unmanaged active sessions.
/// Catalog order is not semantic; every policy value and finite deadline is.
pub fn session_config(runtime: RuntimeConfig, config: &Config) -> io::Result<SessionConfig> {
    let catalog = config.catalog(runtime)?;
    let mut digests = catalog
        .policies
        .iter()
        .map(configuration_digest)
        .collect::<Result<Vec<_>, _>>()
        .map_err(io::Error::other)?;
    digests.sort_unstable_by_key(|digest| digest.0);
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    hash.update(b"l2tunnel/active-management/session/v1/active-wire-v1/frame-v1/management-v1\0");
    hash.update(&catalog.initial.immutable.0);
    hash.update(
        &configuration_digest(&catalog.initial)
            .map_err(io::Error::other)?
            .0,
    );
    for value in [
        config.transaction.retry_ms,
        config.transaction.phase_timeout_ms,
        config.transaction.reconcile_timeout_ms,
        MAX_MODES as u64,
        1,    // Queued local proposals.
        2,    // Current plus staged engines.
        8,    // Per-class carrier queue slots.
        256,  // Authenticated parser channel ceiling; actor checks epoch policy.
        4096, // Maximum complete management body.
        digests.len() as u64,
    ] {
        hash.update(&value.to_be_bytes());
    }
    for digest in digests {
        hash.update(&digest.0);
    }
    let mut digest = [0; 32];
    digest.copy_from_slice(hash.finish().as_ref());
    Ok(SessionConfig {
        layer: runtime.layer,
        digest: ConfigDigest(digest),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn runtime() -> RuntimeConfig {
        RuntimeConfig {
            layer: crate::PacketLayer::Ip,
            max_packet: 1600,
            queue_packets: 16,
            compression: crate::Compression::None,
            poll_interval: std::time::Duration::from_millis(1),
        }
    }
    fn config() -> io::Result<Config> {
        let initial = active::Settings::new(runtime(), Duplex::Half)?;
        let old = Mode::from_settings(initial);
        let mut next = old;
        next.channels = 16;
        next.dscp_weights[8] = 4;
        Ok(Config {
            initial,
            supported: vec![old, next],
            transaction: transaction::Settings::default(),
        })
    }
    #[test]
    fn policy_codec_exact_offsets_bounds_and_full_weight_digest() -> io::Result<()> {
        let policy = Policy {
            immutable: ConfigDigest([7; 32]),
            duplex: Duplex::Full,
            mode: Mode {
                channels: 256,
                dscp_weights: [1024; 64],
            },
        };
        let mut bytes = [0; POLICY_BYTES];
        policy.encode_into(&mut bytes).map_err(io::Error::other)?;
        assert_eq!(&bytes[..8], b"LATM\x01\x02\x01\x00");
        assert_eq!(&bytes[8..40], &[7; 32]);
        assert!(
            bytes[40..]
                .chunks_exact(4)
                .all(|slot| slot == 1024_u32.to_be_bytes())
        );
        assert_eq!(Policy::decode(&bytes).map_err(io::Error::other)?, policy);
        for length in 0..POLICY_BYTES {
            assert!(Policy::decode(&bytes[..length]).is_err());
        }
        let mut extra = bytes.to_vec();
        extra.push(0);
        assert!(Policy::decode(&extra).is_err());
        for index in [0, 4, 5, 6, 40, 292] {
            let mut invalid = bytes;
            invalid[index] = 0xff;
            assert!(Policy::decode(&invalid).is_err());
        }
        for index in 0..64 {
            let mut changed = policy.clone();
            changed.mode.dscp_weights[index] = 1;
            assert_ne!(
                configuration_digest(&changed),
                configuration_digest(&policy)
            );
        }
        Ok(())
    }
    #[test]
    fn catalog_is_canonical_bounded_and_binds_immutable_and_transaction_policy() -> io::Result<()> {
        let config = config()?;
        let expected = session_config(runtime(), &config)?;
        assert_ne!(expected, active::session_config(runtime(), config.initial)?);
        let mut reordered = config.clone();
        reordered.supported.reverse();
        assert_eq!(session_config(runtime(), &reordered)?, expected);
        let mut duplicate = config.clone();
        duplicate.supported.push(duplicate.supported[0]);
        assert!(duplicate.validate(runtime()).is_err());
        let mut missing = config.clone();
        missing.supported.remove(0);
        assert!(missing.validate(runtime()).is_err());
        let mut oversized = config.clone();
        oversized.supported = vec![oversized.supported[0]; 17];
        assert!(oversized.validate(runtime()).is_err());
        let mut bad = config.clone();
        bad.supported[1].dscp_weights[63] = 0;
        assert!(bad.validate(runtime()).is_err());
        for change in [
            |value: &mut Config| value.initial.adaptive = true,
            |value: &mut Config| {
                value.initial.idle_flow_timeout += std::time::Duration::from_millis(1)
            },
            |value: &mut Config| value.initial.max_flows -= 1,
            |value: &mut Config| value.supported[1].dscp_weights[0] = 2,
            |value: &mut Config| value.transaction.retry_ms += 1,
            |value: &mut Config| value.transaction.phase_timeout_ms += 1,
            |value: &mut Config| value.transaction.reconcile_timeout_ms += 1,
        ] {
            let mut changed = config.clone();
            change(&mut changed);
            assert_ne!(session_config(runtime(), &changed)?, expected);
        }
        Ok(())
    }
}
