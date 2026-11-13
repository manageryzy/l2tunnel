//! Immutable global carrier/Swift construction contract shared by all frontends.
use super::{Settings, establish, security};
use crate::{Compression, ConnectionConfig};
use l2tunnel_core::{ConfigDigest, Duplex};
use l2tunnel_device::PacketLayer;
use l2tunnel_runtime::secure_udp::transport;
use l2tunnel_swift::{control::Policy, policy, records};
use ring::digest;
use std::io;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// Exact global role policies retained from validation through authentication/run.
#[derive(Clone, Copy, Debug)]
pub struct Profile {
    connection: ConnectionConfig,
    seed: ConfigDigest,
    session: Settings,
    initiator: transport::Config,
    responder: transport::Config,
}
impl Profile {
    /// Validate both complete role contracts before network/device work.
    pub fn new(
        connection: ConnectionConfig,
        session: Settings,
        initiator: transport::Config,
        responder: transport::Config,
    ) -> io::Result<Self> {
        Self::build(
            connection,
            session.application,
            session,
            initiator,
            responder,
        )
    }
    fn build(
        connection: ConnectionConfig,
        seed: ConfigDigest,
        mut session: Settings,
        initiator: transport::Config,
        responder: transport::Config,
    ) -> io::Result<Self> {
        let base = connection.session()?;
        if connection.duplex != Duplex::Full || connection.compression != Compression::None {
            return Err(invalid(
                "secure UDP Swift requires explicit full duplex and no record compression",
            ));
        }
        initiator.validate()?;
        responder.validate()?;
        if initiator.send != responder.receive || initiator.receive != responder.send {
            return Err(invalid("global Swift directions are not complementary"));
        }
        let forward = initiator.send;
        let reverse = initiator.receive;
        if !(576..=9000).contains(&initiator.path_mtu)
            || !(1..=64).contains(&forward.records.channels)
            || forward.records.channels != reverse.records.channels
            || forward.records.codec.window != reverse.records.codec.window
            || forward.records.codec.repair_numerator != reverse.records.codec.repair_numerator
            || forward.records.codec.window > 255
        {
            return Err(invalid(
                "selected startup policy is not representable by complete shared Swift policy fields",
            ));
        }
        for direction in [forward, reverse] {
            if direction.bytes_per_second % 125 != 0
                || !(64..=10_000_000).contains(&(direction.bytes_per_second / 125))
                || direction.records.codec.repair_denominator != 1000
                || direction.records.codec.repair_numerator > 1000
            {
                return Err(invalid(
                    "selected Swift policy requires exact kilobits and repair permille without rounding",
                ));
            }
        }
        let mut fixed = responder;
        fixed.send = initiator.send;
        fixed.receive = initiator.receive;
        // Each role owns its own fixed byte-credit capacity. Both original
        // values are validated and hashed below; other fixed resources match.
        fixed.wire.burst_bytes = initiator.wire.burst_bytes;
        if fixed.canonical_digest()? != initiator.canonical_digest()? {
            return Err(invalid(
                "role contracts differ in immutable control/security/resource policy",
            ));
        }
        let layer = match connection.layer {
            PacketLayer::Ethernet => records::Layer::Ethernet,
            PacketLayer::Ip => records::Layer::Ip,
        };
        let header = match session.cover.appearance {
            l2tunnel_cover::Appearance::QuicLike => 13,
            l2tunnel_cover::Appearance::MediaLike => 14,
        };
        let overhead = 9
            + security::COMMON_PREFIX_BYTES
            + 16
            + header
            + if session.gate.path.client.is_ipv6() {
                48
            } else {
                28
            };
        let body = initiator
            .path_mtu
            .checked_sub(overhead)
            .ok_or_else(|| invalid("startup MTU cannot hold common framing"))?;
        for direction in [
            initiator.send,
            initiator.receive,
            responder.send,
            responder.receive,
        ] {
            if direction.records.layer != layer
                || direction.records.max_native != connection.max_packet
                || direction.records.codec.datagram_bytes != body
            {
                return Err(invalid(
                    "Swift native contract differs from the prepared attachment",
                ));
            }
        }
        for (role, config) in [
            (security::Role::Initiator, initiator),
            (security::Role::Responder, responder),
        ] {
            config.validate_cover(
                session.cover.config(role)?,
                session.gate.path.client.is_ipv6(),
            )?;
        }
        let mut hash = digest::Context::new(&digest::SHA256);
        hash.update(b"l2tunnel/shared-service/secure-udp-swift-profile/v1\0");
        hash.update(&seed.0);
        hash.update(&base.digest.0);
        hash.update(&connection.handshake_timeout.as_nanos().to_be_bytes());
        hash.update(&initiator.canonical_digest()?.0);
        hash.update(&responder.canonical_digest()?.0);
        session.application = ConfigDigest(super::finish(hash));
        Ok(Self {
            connection,
            seed,
            session,
            initiator,
            responder,
        })
    }
    /// Original complete base native contract.
    pub fn connection(&self) -> ConnectionConfig {
        self.connection
    }
    /// Carrier settings with the actual globally derived application digest.
    pub fn settings(&self) -> Settings {
        self.session
    }
    /// Actual retained role-specific transport policy.
    pub fn runtime(&self, role: security::Role) -> transport::Config {
        match role {
            security::Role::Initiator => self.initiator,
            security::Role::Responder => self.responder,
        }
    }
    /// Complete carrier/profile/member/pin digest authenticated before device work.
    pub fn configuration(&self, peers: establish::Peers) -> io::Result<security::ConfigDigest> {
        self.session.configuration(peers)
    }
    /// Full global policy resolution within the originally admitted ceilings.
    pub fn resolve(
        &self,
        selected: &Policy,
        role: security::Role,
        peers: establish::Peers,
    ) -> Option<policy::Resolved> {
        let next = self.with_policy(selected).ok()?;
        let config = next.runtime(role);
        Some(policy::Resolved {
            send: config.send,
            receive: config.receive,
            digest: policy::Digest(next.configuration(peers).ok()?.0),
        })
    }
    /// Validate one complete proposal without changing a running or prepared owner.
    pub fn with_policy(&self, selected: &Policy) -> io::Result<Self> {
        if !(576..=9000).contains(&selected.path_mtu)
            || !(64..=10_000_000).contains(&selected.forward_kbit)
            || !(64..=10_000_000).contains(&selected.reverse_kbit)
            || !(1..=64).contains(&selected.channels)
            || selected.window == 0
            || selected.repair_permille > 1000
        {
            return Err(invalid("requested complete Swift policy is out of range"));
        }
        let ipv6 = self.session.gate.path.client.is_ipv6();
        let header = match self.session.cover.appearance {
            l2tunnel_cover::Appearance::QuicLike => 13,
            l2tunnel_cover::Appearance::MediaLike => 14,
        };
        let overhead = 9 + security::COMMON_PREFIX_BYTES + 16 + header + if ipv6 { 48 } else { 28 };
        let body = usize::from(selected.path_mtu)
            .checked_sub(overhead)
            .ok_or_else(|| invalid("policy MTU cannot hold record framing"))?;
        let update =
            |mut value: policy::Direction, forward: bool| -> io::Result<policy::Direction> {
                value.records.codec.datagram_bytes = body;
                value.records.channels = usize::from(selected.channels);
                value.records.codec.window = usize::from(selected.window);
                value.records.codec.repair_numerator = u32::from(selected.repair_permille);
                value.records.codec.repair_denominator = 1000;
                value.bytes_per_second = u64::from(if forward {
                    selected.forward_kbit
                } else {
                    selected.reverse_kbit
                }) * 125;
                value.validate().map_err(io::Error::other)?;
                Ok(value)
            };
        let mut initiator = self.initiator;
        let mut responder = self.responder;
        initiator.path_mtu = usize::from(selected.path_mtu);
        responder.path_mtu = usize::from(selected.path_mtu);
        initiator.send = update(initiator.send, true)?;
        initiator.receive = update(initiator.receive, false)?;
        responder.send = update(responder.send, false)?;
        responder.receive = update(responder.receive, true)?;
        Self::build(
            self.connection,
            self.seed,
            self.session,
            initiator,
            responder,
        )
    }
    /// Current startup policy expressed in the existing complete command grammar.
    pub fn initial_policy(&self) -> io::Result<Policy> {
        Ok(Policy {
            path_mtu: u16::try_from(self.initiator.path_mtu)
                .map_err(|_| invalid("path MTU conversion"))?,
            forward_kbit: u32::try_from(self.initiator.send.bytes_per_second / 125)
                .map_err(|_| invalid("forward budget conversion"))?,
            reverse_kbit: u32::try_from(self.initiator.receive.bytes_per_second / 125)
                .map_err(|_| invalid("reverse budget conversion"))?,
            channels: u8::try_from(self.initiator.send.records.channels)
                .map_err(|_| invalid("channel conversion"))?,
            window: u8::try_from(self.initiator.send.records.codec.window)
                .map_err(|_| invalid("window conversion"))?,
            repair_permille: u16::try_from(
                u64::from(self.initiator.send.records.codec.repair_numerator) * 1000
                    / u64::from(self.initiator.send.records.codec.repair_denominator),
            )
            .map_err(|_| invalid("repair conversion"))?,
        })
    }
}

#[cfg(test)]
#[path = "profile_tests.rs"]
pub(crate) mod tests;
