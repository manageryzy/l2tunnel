//! Original-owner raw carrier configuration for the Common service entry.
#[cfg(unix)]
use l2tunnel_core::Duplex;
#[cfg(unix)]
use l2tunnel_raw_io::{
    PacketIo,
    handoff::{
        MessageLimits, SwitchLimits,
        pairing::{
            PairConfig, RawInput, RawInputs,
            packet::{PacketPhaseConfig, PacketPolicy, Protection},
        },
    },
};
#[cfg(unix)]
use l2tunnel_raw_tcp::{Config as RawConfig, Role};
#[cfg(unix)]
use ring::rand::{SecureRandom, SystemRandom};
#[cfg(unix)]
use serde::Deserialize;
#[cfg(unix)]
use std::{io, net::SocketAddrV4};
#[cfg(unix)]
use tokio::time::Instant;

#[cfg(unix)]
pub mod common;
mod status;
pub use status::NativeFlight;
/// Entire untrusted carrier policy bound, checked before JSON parsing.
pub const MAX_POLICY_BYTES: usize = 65_536;

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Endpoints {
    local: SocketAddrV4,
    peer: SocketAddrV4,
}
#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PayloadProtection {
    Aead,
    Integrity,
}
#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Packet {
    mtu: u16,
    protection: PayloadProtection,
    queue_packets: u16,
    horizon_bytes: u32,
    minimum_transfer_bytes: u32,
    bytes_per_second: u64,
    packets_per_second: u32,
    burst_bytes: u32,
    burst_packets: u16,
    max_key_packets: u64,
    max_key_bytes: u64,
}
#[cfg(unix)]
impl Packet {
    fn policy(self) -> PacketPolicy {
        PacketPolicy {
            mtu: self.mtu,
            protection: match self.protection {
                PayloadProtection::Aead => Protection::ChaCha20Poly1305,
                PayloadProtection::Integrity => Protection::HmacSha256,
            },
            queue_packets: self.queue_packets,
            horizon_bytes: self.horizon_bytes,
            minimum_transfer_bytes: self.minimum_transfer_bytes,
            bytes_per_second: self.bytes_per_second,
            packets_per_second: self.packets_per_second,
            burst_bytes: self.burst_bytes,
            burst_packets: self.burst_packets,
            max_key_packets: self.max_key_packets,
            max_key_bytes: self.max_key_bytes,
        }
    }
}
#[cfg(unix)]
fn raw_config(endpoints: Endpoints, packet: Packet) -> io::Result<RawConfig> {
    let mtu = usize::from(packet.mtu);
    let receive_bytes = usize::try_from(packet.horizon_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "raw receive horizon overflow"))?
        .max(32768);
    // Reserve actual packet slots for the unscaled receive capacity, including
    // the maximum IPv4/TCP header size. A scaled window field is not a byte cap.
    let packet_payload = mtu
        .checked_sub(80)
        .filter(|value| *value != 0)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "raw packet MTU is too small")
        })?;
    let packet_slots = receive_bytes
        .checked_add(packet_payload - 1)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "raw packet capacity overflow")
        })?
        / packet_payload;
    let config = RawConfig {
        local: endpoints.local,
        peer: endpoints.peer,
        mtu,
        send_bytes: 32768,
        receive_bytes,
        packet_slots: packet_slots.max(16),
        random_seed: 1,
        ack_delay_millis: 1,
        keepalive_millis: 1000,
        idle_timeout_millis: 30000,
    };
    l2tunnel_raw_tcp::IpConfig::from(config)
        .validate()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    Ok(config)
}
#[cfg(unix)]
fn invalid(text: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, text)
}
#[cfg(unix)]
fn expired() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "raw original setup deadline")
}
#[cfg(unix)]
fn check(end: Instant) -> io::Result<()> {
    if Instant::now() >= end {
        Err(expired())
    } else {
        Ok(())
    }
}
#[cfg(unix)]
fn inputs_for<I: PacketIo>(
    forward: Endpoints,
    reverse: Option<Endpoints>,
    packet: Packet,
    role: Role,
    end: Instant,
    mut open: impl FnMut(RawConfig, Role) -> io::Result<I>,
) -> io::Result<RawInputs<I>> {
    let mut lane = |endpoints| {
        check(end)?;
        let mut config = raw_config(endpoints, packet)?;
        let mut seed = [0; 8];
        SystemRandom::new()
            .fill(&mut seed)
            .map_err(|_| io::Error::other("raw seed randomness"))?;
        config.random_seed = u64::from_ne_bytes(seed).max(1);
        let result = open(config, role);
        check(end)?;
        let io = result?;
        Ok::<_, io::Error>(RawInput { config, io })
    };
    let forward = lane(forward)?;
    Ok(match reverse {
        Some(reverse) => RawInputs::Half {
            forward,
            reverse: lane(reverse)?,
        },
        None => RawInputs::Full(forward),
    })
}

#[cfg(all(test, unix))]
mod tests;
