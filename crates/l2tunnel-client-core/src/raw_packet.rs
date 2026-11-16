//! Explicit original-owner raw packet factories shared by CLI and GUI callers.
use crate::ConnectionConfig;
use l2tunnel_auth::{ClientTls, MemberAllowlist, MemberKey, ServerTls};
use l2tunnel_core::Duplex;
use l2tunnel_device::PacketDevice;
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
use l2tunnel_raw_tcp::{Config as RawConfig, Role};
use l2tunnel_runtime::raw_packet as runtime;
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use std::{
    future::Future,
    io,
    net::SocketAddrV4,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};

pub mod common;
mod status;
pub use status::{
    Capabilities, Carrier, Cover, NativeFlight, Observer, RecoveryWindow, Selection, Snapshot,
    Traffic,
};
/// Entire untrusted policy bound, checked before JSON parsing.
pub const MAX_POLICY_BYTES: usize = 65_536;
/// Exact separately selected startup profile.
pub const PROFILE: &str = "raw-packet-runtime-v2";
/// Validated immutable operator policy; factories revalidate connection-dependent bounds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Settings(Document);
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u16,
    profile: String,
    forward: Endpoints,
    reverse: Option<Endpoints>,
    channels: u16,
    packet: Packet,
    recovery: Recovery,
    delivery: crate::delivery::Policy,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Endpoints {
    local: SocketAddrV4,
    peer: SocketAddrV4,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PayloadProtection {
    Aead,
    Integrity,
}
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
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
enum Recovery {
    SelectiveRepeat,
    Cauchy {
        sources: usize,
        repairs: usize,
        flush_micros: u64,
    },
}
impl Settings {
    /// Strict required-field, duplicate/unknown rejecting JSON; no I/O is performed.
    pub fn from_json(bytes: &[u8]) -> io::Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES {
            return Err(invalid("raw policy input bound"));
        }
        let value: Document =
            serde_json::from_slice(bytes).map_err(|_| invalid("invalid strict raw policy JSON"))?;
        if value.version != 2 || value.profile != PROFILE {
            return Err(invalid("raw policy version/profile"));
        }
        value.delivery.config(40)?;
        value
            .packet
            .policy()
            .max_record_bytes()
            .map_err(|_| invalid("raw packet policy"))?;
        l2tunnel_raw_tcp::IpConfig::from(raw_config(value.forward, value.packet.mtu))
            .validate()
            .map_err(|_| invalid("raw forward tuple"))?;
        if let Some(reverse) = value.reverse {
            l2tunnel_raw_tcp::IpConfig::from(raw_config(reverse, value.packet.mtu))
                .validate()
                .map_err(|_| invalid("raw reverse tuple"))?;
            if reverse.local == value.forward.local || reverse.peer == value.forward.peer {
                return Err(invalid(
                    "raw half lanes require distinct local and peer tuples",
                ));
            }
        }
        Ok(Self(value))
    }
    /// Explicit first native tuple, for matching the shared --remote/--listen flags.
    pub fn forward(&self) -> (SocketAddrV4, SocketAddrV4) {
        (self.0.forward.local, self.0.forward.peer)
    }
    /// Complete authenticated native/MUX/recovery configuration, without opening I/O.
    pub fn runtime_config(&self, connection: ConnectionConfig) -> io::Result<runtime::Config> {
        let us = connection.handshake_timeout.as_micros();
        if !(1000..=30_000_000).contains(&us)
            || !connection
                .handshake_timeout
                .subsec_nanos()
                .is_multiple_of(1000)
        {
            return Err(invalid("raw setup timeout outside exact 1ms..30s"));
        }
        if (connection.duplex == Duplex::Half) != self.0.reverse.is_some() {
            return Err(invalid("raw endpoint shape differs from duplex"));
        }
        let transport = PacketPhaseConfig {
            pair: PairConfig {
                session: connection.session()?,
                messages: MessageLimits::default(),
                driver: SwitchLimits::default(),
                timeout: connection.handshake_timeout,
            },
            packet: self.0.packet.policy(),
        };
        runtime::Config::new(
            connection.runtime(),
            transport,
            connection.duplex,
            self.0.channels,
            self.0.delivery.config(connection.max_packet)?,
        )?
        .with_recovery(match self.0.recovery {
            Recovery::SelectiveRepeat => runtime::RecoveryMode::SelectiveRepeat,
            Recovery::Cauchy {
                sources,
                repairs,
                flush_micros,
            } => runtime::RecoveryMode::Cauchy {
                sources,
                repairs,
                flush_after: Duration::from_micros(flush_micros),
            },
        })
    }
}
fn raw_config(endpoints: Endpoints, mtu: u16) -> RawConfig {
    RawConfig {
        local: endpoints.local,
        peer: endpoints.peer,
        mtu: usize::from(mtu),
        send_bytes: 32768,
        receive_bytes: 32768,
        packet_slots: 16,
        random_seed: 1,
        ack_delay_millis: 1,
        keepalive_millis: 1000,
        idle_timeout_millis: 30000,
    }
}
fn invalid(text: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, text)
}
fn expired() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "raw original setup deadline")
}
fn check(end: Instant) -> io::Result<()> {
    if Instant::now() >= end {
        Err(expired())
    } else {
        Ok(())
    }
}
fn inputs<I: PacketIo>(
    settings: &Settings,
    role: Role,
    end: Instant,
    open: impl FnMut(RawConfig, Role) -> io::Result<I>,
) -> io::Result<RawInputs<I>> {
    inputs_for(
        settings.0.forward,
        settings.0.reverse,
        settings.0.packet,
        role,
        end,
        open,
    )
}
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
        let mut config = raw_config(endpoints, packet.mtu);
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
/// Owns the actual original setup and one absolute factory-to-authentication deadline.
/// Cancellation drops all original inputs; it is never successful drain.
pub struct Setup<'a, I: PacketIo + Send + 'static> {
    inner: Option<runtime::Setup<'a, I>>,
    timer: Pin<Box<Sleep>>,
    end: Instant,
    observer: Observer,
}
impl<I: PacketIo + Send + 'static> Setup<'_, I> {
    /// Coalesced actual setup phase with no effective carrier before authentication.
    pub fn observer(&self) -> Observer {
        self.observer.clone()
    }
}
impl<I: PacketIo + Send + 'static> Future for Setup<'_, I> {
    type Output = io::Result<Session<I>>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.inner.is_none() {
            return Poll::Ready(Err(invalid("raw setup already completed")));
        }
        if this.timer.as_mut().poll(cx).is_ready() || check(this.end).is_err() {
            this.inner.take();
            return Poll::Ready(Err(expired()));
        }
        let result = match this.inner.as_mut() {
            Some(inner) => Pin::new(inner).poll(cx),
            None => return Poll::Ready(Err(invalid("raw setup already completed"))),
        };
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(value) => {
                this.inner.take();
                if check(this.end).is_err() {
                    return Poll::Ready(Err(expired()));
                }
                Poll::Ready(value.map(|link| Session { link }))
            }
        }
    }
}
/// Original authenticated raw runtime link, never constructed from adopted TLS.
pub struct Session<I: PacketIo + Send + 'static> {
    link: runtime::Link<I>,
}
impl<I: PacketIo + Send + 'static> Session<I> {
    /// Immutable authenticated runtime configuration.
    pub fn config(&self) -> runtime::Config {
        self.link.config()
    }
    /// Actual authenticated physical lanes and common profile digest.
    pub fn info(&self) -> Option<&l2tunnel_raw_io::handoff::pairing::PairInfo> {
        self.link.info()
    }
    /// Actual status with effective selection only after original setup succeeded.
    pub fn observer(&self) -> Observer {
        Observer::new(self.link.subscribe(), self.link.info().map(|i| i.profile.0))
    }
    /// Drive retained control when another peer's setup is still pending.
    pub fn poll_progress(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.link.poll_progress(cx)
    }
    /// Consume the actual link in the existing common-MUX/native-confirmation loop.
    pub async fn run<D: PacketDevice<Error = io::Error>>(self, device: D) -> io::Result<()> {
        runtime::run(device, self.link).await
    }
}
/// Start the actual client using a caller-injected original packet opener.
///
/// # Panics
/// Requires a current Tokio runtime with time enabled.
pub fn begin_client_with<'a, I: PacketIo + Send + 'static>(
    settings: &Settings,
    connection: ConnectionConfig,
    tls: &'a ClientTls,
    name: &'a str,
    member: &'a MemberKey,
    open: impl FnMut(RawConfig, Role) -> io::Result<I>,
) -> io::Result<Setup<'a, I>> {
    let end = Instant::now()
        .checked_add(connection.handshake_timeout)
        .ok_or_else(|| invalid("raw setup deadline overflow"))?;
    let config = settings.runtime_config(connection)?;
    let original = inputs(settings, Role::Client, end, open)?;
    let result = runtime::begin_client(original, tls, name, member, config);
    check(end)?;
    let inner = result.map_err(|f| f.error)?;
    let observer = Observer::new(inner.subscribe(), None);
    Ok(Setup {
        inner: Some(inner),
        timer: Box::pin(tokio::time::sleep_until(end)),
        end,
        observer,
    })
}
/// Start the actual server with the same original deadline and opener ownership.
///
/// # Panics
/// Requires a current Tokio runtime with time enabled.
pub fn begin_server_with<'a, I: PacketIo + Send + 'static>(
    settings: &Settings,
    connection: ConnectionConfig,
    tls: &'a ServerTls,
    members: &'a MemberAllowlist,
    open: impl FnMut(RawConfig, Role) -> io::Result<I>,
) -> io::Result<Setup<'a, I>> {
    let end = Instant::now()
        .checked_add(connection.handshake_timeout)
        .ok_or_else(|| invalid("raw setup deadline overflow"))?;
    let config = settings.runtime_config(connection)?;
    let original = inputs(settings, Role::Server, end, open)?;
    let result = runtime::begin_server(original, tls, members, config);
    check(end)?;
    let inner = result.map_err(|f| f.error)?;
    let observer = Observer::new(inner.subscribe(), None);
    Ok(Setup {
        inner: Some(inner),
        timer: Box::pin(tokio::time::sleep_until(end)),
        end,
        observer,
    })
}
#[cfg(test)]
mod tests;
