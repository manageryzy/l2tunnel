use super::*;
use l2tunnel_auth::SessionConfig;
use l2tunnel_core::ConfigDigest;
use l2tunnel_device::PacketLayer;
use l2tunnel_recovery::{ArqConfig, EndpointRole, RecoveryContext, SelectiveRepeat};
use l2tunnel_udp_control::{Config as GateConfig, Path};
use std::time::Duration;

/// Single shared finite admission allowance for control, data, feedback and retries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WireBudget {
    /// Refill interval; unused allowance does not accumulate.
    pub interval: Duration,
    /// Complete datagrams admitted per interval.
    pub packets: usize,
    /// Complete configured IP bytes admitted per interval.
    pub ip_bytes: usize,
    /// Packet slots data cannot spend.
    pub reserved_control_packets: usize,
    /// IP bytes data cannot spend.
    pub reserved_control_bytes: usize,
    /// Total control packet ceiling, including TLS sources and all recovery ACKs.
    pub maximum_control_packets: usize,
}

/// Canonically bound standalone runtime policy; no secrets or learned peer address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Upper-layer packet and configuration binding.
    pub base: SessionConfig,
    /// Initial gate/control bounds. Its original base digest also enters binding.
    pub bootstrap: GateConfig,
    /// Data protection, path and full/half lane policy; OpenVPN-like cover only.
    pub profile: Profile,
    /// Data recovery budget; one source is one complete upper-layer packet.
    pub arq: ArqConfig,
    /// Total actual TLS/member authentication bound, within gate lifetime.
    pub authentication_timeout: Duration,
    /// Total authenticated two-lane join deadline, including preparation of both lanes.
    pub pairing_timeout: Duration,
    /// One-shot retained lifetime, default one hour and at most 24 hours.
    pub authenticated_lease: Duration,
    /// Maximum age of actual fresh decrypted internal TLS input.
    pub inactivity_timeout: Duration,
    /// Maximum periodic heartbeat spacing, at most one third of inactivity.
    pub heartbeat_interval: Duration,
    /// Bounded explicit drain/close attempt.
    pub close_timeout: Duration,
    /// Application packet slots in each direction, including a held receive packet.
    pub packet_slots: usize,
    /// Fixed worst-case application queue capacity per direction.
    pub packet_bytes: usize,
    /// Each direction of the TLS/control duplex byte adapter.
    pub stream_bytes: usize,
    /// Driver's maximum timer spacing.
    pub poll_interval: Duration,
    /// Maximum datagram/recovery work per actor iteration.
    pub work_limit: usize,
    /// Shared complete-wire admission policy; also subject to control's own budget.
    pub wire_budget: WireBudget,
}

impl Config {
    /// Recompute dependent source/queue/wire byte bounds for a whole-IP MTU.
    ///
    /// Count limits and timers are preserved. This replaces their associated
    /// byte reservations; call before applying any separately reviewed byte caps.
    /// No existing `new` default or canonical profile changes implicitly.
    pub fn with_path_mtu(mut self, mtu: usize) -> Result<Self, Error> {
        let product = |count: usize, bytes: usize| {
            count
                .checked_mul(bytes)
                .ok_or(Error::Configuration("MTU capacity overflow"))
        };
        let control = mtu
            .checked_sub(self.bootstrap.outer_overhead)
            .and_then(|value| value.checked_sub(l2tunnel_udp_control::CONTROL_OVERHEAD))
            .and_then(|value| value.checked_sub(l2tunnel_recovery::DATA_HEADER_BYTES))
            .ok_or(Error::Configuration("control MTU"))?;
        let protected = match self.profile.protection {
            Protection::ChaCha20Poly1305 => 64,
            Protection::HmacSha256 => 80,
        };
        let payload = mtu
            .checked_sub(self.bootstrap.outer_overhead)
            .and_then(|value| value.checked_sub(protected))
            .ok_or(Error::Configuration("protected MTU"))?;
        let data = payload
            .checked_sub(l2tunnel_recovery::DATA_HEADER_BYTES)
            .ok_or(Error::Configuration("recovery MTU"))?;
        self.bootstrap.path_mtu = mtu;
        self.bootstrap.arq.max_source_bytes = control;
        self.bootstrap.arq.send_bytes = product(self.bootstrap.arq.send_records, control)?;
        self.bootstrap.arq.receive_bytes = product(self.bootstrap.arq.receive_records, control)?;
        self.bootstrap.control_bytes = product(self.bootstrap.control_packets as usize, mtu)?;
        self.profile.path_mtu = mtu;
        self.profile.max_payload_bytes = payload;
        self.arq.max_source_bytes = data;
        self.arq.send_bytes = product(self.arq.send_records, data)?;
        self.arq.receive_bytes = product(self.arq.receive_records, data)?;
        self.packet_bytes = product(self.packet_slots, data)?;
        self.wire_budget.ip_bytes = product(self.wire_budget.packets, mtu)?;
        self.wire_budget.reserved_control_bytes =
            product(self.wire_budget.reserved_control_packets, mtu)?;
        self.validate()?;
        Ok(self)
    }
    /// Checked finite defaults for one full-duplex fixed endpoint pair.
    pub fn new(path: Path, base: SessionConfig, protection: Protection) -> Result<Self, Error> {
        let bootstrap = GateConfig::new(path, base.digest.0, 1)?;
        let overhead = match protection {
            Protection::ChaCha20Poly1305 => 64,
            Protection::HmacSha256 => 80,
        };
        let maximum = bootstrap.path_mtu - bootstrap.outer_overhead - overhead;
        let source = maximum - l2tunnel_recovery::DATA_HEADER_BYTES;
        let arq = ArqConfig {
            max_source_bytes: source,
            send_bytes: source * 32,
            receive_bytes: source * 32,
            send_records: 32,
            receive_records: 32,
            ..ArqConfig::default()
        };
        let value = Self {
            base,
            bootstrap,
            profile: Profile {
                traffic: Traffic::FullDuplex,
                cover: CoverProfile::OpenVpnLike,
                protection,
                lane: LaneId(0),
                generation: KeyGeneration(0),
                path_mtu: bootstrap.path_mtu,
                outer_overhead_bytes: bootstrap.outer_overhead,
                max_payload_bytes: maximum,
                max_packets_per_key: 1 << 24,
                max_payload_bytes_per_key: 1 << 32,
            },
            arq,
            authentication_timeout: Duration::from_secs(10),
            pairing_timeout: Duration::from_secs(30),
            authenticated_lease: Duration::from_secs(3600),
            inactivity_timeout: Duration::from_secs(3),
            heartbeat_interval: Duration::from_millis(250),
            close_timeout: Duration::from_secs(5),
            packet_slots: 32,
            packet_bytes: source * 32,
            stream_bytes: 8192,
            poll_interval: Duration::from_millis(2),
            work_limit: 32,
            wire_budget: WireBudget {
                interval: Duration::from_millis(10),
                packets: 16,
                ip_bytes: 16 * 1200,
                reserved_control_packets: 4,
                reserved_control_bytes: 4 * 1200,
                maximum_control_packets: 8,
            },
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate finite products and transport agreement before allocating runtime state.
    pub fn validate(self) -> Result<(), Error> {
        self.bootstrap.profile_digest()?;
        self.profile
            .canonical()
            .map_err(|_| Error::Configuration("data profile"))?;
        let budget = self.wire_budget;
        let mtu = self.bootstrap.path_mtu;
        if self.profile.cover != CoverProfile::OpenVpnLike
            || self.profile.path_mtu != mtu
            || self.profile.outer_overhead_bytes != self.bootstrap.outer_overhead
            || self
                .arq
                .max_source_bytes
                .checked_add(l2tunnel_recovery::DATA_HEADER_BYTES)
                .is_none_or(|bytes| bytes > self.profile.max_payload_bytes)
            || self.arq.send_bytes > 4 * 1024 * 1024
            || self.arq.receive_bytes > 4 * 1024 * 1024
            || self.arq.max_retries > 1024
            || self.authentication_timeout.is_zero()
            || self.authentication_timeout > self.bootstrap.handshake_timeout
            || self.pairing_timeout.is_zero()
            || self.pairing_timeout > Duration::from_secs(120)
            || self.authenticated_lease.is_zero()
            || self.authenticated_lease > Duration::from_secs(86_400)
            || self.inactivity_timeout < Duration::from_millis(20)
            || self.inactivity_timeout > self.authenticated_lease
            || self.heartbeat_interval.is_zero()
            || self
                .heartbeat_interval
                .checked_mul(3)
                .is_none_or(|v| v > self.inactivity_timeout)
            || self.close_timeout.is_zero()
            || self.close_timeout > Duration::from_secs(120)
            || !(1..=1024).contains(&self.packet_slots)
            || self.packet_bytes > 4 * 1024 * 1024
            || self
                .packet_slots
                .checked_mul(self.arq.max_source_bytes)
                .is_none_or(|bytes| bytes > self.packet_bytes)
            || !(1024..=1_048_576).contains(&self.stream_bytes)
            || self.poll_interval.is_zero()
            || self.poll_interval > self.heartbeat_interval
            || !(1..=1024).contains(&self.work_limit)
            || budget.interval.is_zero()
            || budget.interval > Duration::from_secs(1)
            || !(4..=4096).contains(&budget.packets)
            || budget.ip_bytes > 16 * 1024 * 1024
            || !(2..budget.packets).contains(&budget.reserved_control_packets)
            || budget.reserved_control_bytes < 2 * mtu
            || budget.reserved_control_bytes >= budget.ip_bytes
            || budget
                .reserved_control_bytes
                .checked_add(mtu)
                .is_none_or(|bytes| bytes > budget.ip_bytes)
            || budget.maximum_control_packets < budget.reserved_control_packets
            || budget.maximum_control_packets >= budget.packets
        {
            return Err(Error::Configuration(
                "inconsistent or excessive runtime bounds",
            ));
        }
        for time in [
            self.authentication_timeout,
            self.pairing_timeout,
            self.authenticated_lease,
            self.inactivity_timeout,
            self.heartbeat_interval,
            self.close_timeout,
            self.poll_interval,
            budget.interval,
            self.arq.initial_rto,
            self.arq.maximum_rto,
            self.arq.ack_delay,
        ] {
            micros(time)?;
        }
        SelectiveRepeat::new(
            self.arq,
            RecoveryContext {
                session: 1,
                epoch: 1,
                role: EndpointRole::Initiator,
            },
        )?;
        Ok(())
    }

    /// Exact effective gate profile, binding every runtime policy before ARQ allocation.
    pub fn gate_config(self) -> Result<GateConfig, Error> {
        self.validate()?;
        let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
        hash.update(b"l2tunnel/openvpn-like/runtime-profile/v1\0");
        hash.update(&[match self.base.layer {
            PacketLayer::Ethernet => 1,
            PacketLayer::Ip => 2,
        }]);
        hash.update(&self.base.digest.0);
        hash.update(&self.bootstrap.profile_digest()?);
        hash.update(
            &self
                .profile
                .canonical()
                .map_err(|_| Error::Configuration("data profile"))?,
        );
        for value in [
            self.arq.max_source_bytes as u64,
            self.arq.send_bytes as u64,
            self.arq.receive_bytes as u64,
            self.arq.send_records as u64,
            self.arq.receive_records as u64,
            micros(self.arq.initial_rto)?,
            micros(self.arq.maximum_rto)?,
            micros(self.arq.ack_delay)?,
            u64::from(self.arq.max_retries),
            micros(self.authentication_timeout)?,
            micros(self.pairing_timeout)?,
            micros(self.authenticated_lease)?,
            micros(self.inactivity_timeout)?,
            micros(self.heartbeat_interval)?,
            micros(self.close_timeout)?,
            self.packet_slots as u64,
            self.packet_bytes as u64,
            self.stream_bytes as u64,
            micros(self.poll_interval)?,
            self.work_limit as u64,
            micros(self.wire_budget.interval)?,
            self.wire_budget.packets as u64,
            self.wire_budget.ip_bytes as u64,
            self.wire_budget.reserved_control_packets as u64,
            self.wire_budget.reserved_control_bytes as u64,
            self.wire_budget.maximum_control_packets as u64,
        ] {
            hash.update(&value.to_be_bytes());
        }
        let mut gate = self.bootstrap;
        gate.base_profile.copy_from_slice(hash.finish().as_ref());
        Ok(gate)
    }

    /// Actual TLS member digest includes the complete effective gate/runtime profile.
    pub fn session_config(self) -> Result<SessionConfig, Error> {
        Ok(SessionConfig {
            layer: self.base.layer,
            digest: ConfigDigest(self.gate_config()?.profile_digest()?),
        })
    }
}

fn micros(value: Duration) -> Result<u64, Error> {
    if !value.subsec_nanos().is_multiple_of(1000) {
        return Err(Error::Configuration("sub-microsecond policy"));
    }
    u64::try_from(value.as_micros()).map_err(|_| Error::Configuration("duration overflow"))
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    fn config() -> Result<Config, Box<dyn std::error::Error>> {
        Ok(Config::new(
            Path {
                client: "127.0.0.1:30001".parse()?,
                server: "127.0.0.1:30002".parse()?,
            },
            SessionConfig {
                layer: PacketLayer::Ip,
                digest: ConfigDigest([8; 32]),
            },
            Protection::ChaCha20Poly1305,
        )?)
    }
    #[test]
    fn mtu_derivation_preserves_default_and_checks_all_reservations() -> TestResult {
        let original = config()?;
        assert_eq!(original.with_path_mtu(1200)?, original);
        let changed = original.with_path_mtu(1500)?;
        assert_eq!(changed.bootstrap.arq.max_source_bytes, 1500 - 28 - 64 - 44);
        assert_eq!(changed.arq.max_source_bytes, 1500 - 28 - 64 - 44);
        assert_eq!(
            changed.packet_bytes,
            changed.packet_slots * changed.arq.max_source_bytes
        );
        assert_eq!(
            changed.wire_budget.ip_bytes,
            changed.wire_budget.packets * 1500
        );
        assert_ne!(original.session_config()?, changed.session_config()?);
        for mtu in [0, 1, 100, 65_536, usize::MAX] {
            assert!(original.with_path_mtu(mtu).is_err());
        }
        let mut invalid = original;
        invalid.bootstrap.outer_overhead = usize::MAX;
        assert!(invalid.with_path_mtu(1500).is_err());
        invalid = original;
        invalid.packet_slots = usize::MAX;
        assert!(invalid.with_path_mtu(1500).is_err());
        Ok(())
    }
    #[test]
    fn runtime_policy_changes_bind_gate_and_member_before_activation() -> TestResult {
        let original = config()?;
        let baseline = original.session_config()?;
        for field in 0..9 {
            let mut changed = original;
            match field {
                0 => changed.authenticated_lease += Duration::from_secs(1),
                1 => changed.packet_bytes += 1,
                2 => changed.stream_bytes += 1,
                3 => {
                    changed.profile.traffic = Traffic::HalfDuplex {
                        sender: l2tunnel_datagram::Direction::ClientToServer,
                    }
                }
                4 => changed.wire_budget.ip_bytes += 1,
                5 => changed.inactivity_timeout += Duration::from_secs(1),
                6 => changed.bootstrap.key_id += 1,
                7 => changed.arq.max_retries += 1,
                _ => changed.pairing_timeout += Duration::from_secs(1),
            }
            assert_ne!(changed.session_config()?, baseline);
            assert_ne!(
                changed.gate_config()?.profile_digest()?,
                original.gate_config()?.profile_digest()?
            );
        }
        Ok(())
    }
    #[test]
    fn impossible_limits_and_cover_mismatch_fail_before_runtime_allocation() -> TestResult {
        let original = config()?;
        for field in 0..8 {
            let mut changed = original;
            match field {
                0 => changed.packet_slots = usize::MAX,
                1 => changed.packet_bytes = 1,
                2 => changed.arq.max_source_bytes = usize::MAX,
                3 => changed.profile.cover = CoverProfile::QuicLike,
                4 => changed.wire_budget.reserved_control_bytes = usize::MAX,
                5 => changed.heartbeat_interval = changed.inactivity_timeout,
                6 => changed.authenticated_lease = Duration::from_secs(86_401),
                _ => {
                    changed.authentication_timeout =
                        changed.bootstrap.handshake_timeout + Duration::from_secs(1)
                }
            }
            assert!(changed.session_config().is_err());
        }
        Ok(())
    }
}
