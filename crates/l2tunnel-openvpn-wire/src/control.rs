//! Bounded reset/ACK/TLS-byte transport using the existing reserved selective repeat.
//! Only standard OpenVPN fields and actual TLS bytes reach the wire. The private
//! L2AR translation buffers never leave this owner and supply no authentication.
use crate::{Opcode, Packet, SessionId, decode, encode_control};
use l2tunnel_recovery::{
    self as recovery, ArqConfig, EndpointRole, PacketView, RecoveryContext, RecoveryEngine,
    SelectiveRepeat,
};
use std::time::Duration;

/// Fixed endpoint role; sockets and final TLS/member trust remain external.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// Sends the initial client hard reset.
    Client,
    /// Replies to the configured client's reset on the same UDP tuple.
    Server,
}

/// Actual control resource and original lifetime inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Locally generated original eight-byte control-session ID.
    pub local: SessionId,
    /// Complete UDP-payload ceiling, excluding IP/UDP overhead.
    pub max_datagram_bytes: usize,
    /// Existing bounded TLS-fragment recovery; never applied to user packets.
    pub arq: ArqConfig,
    /// Original total control lifetime, never renewed by retries or reset duplicates.
    pub lifetime: Duration,
}
impl Config {
    /// Validate standard maximum headers and actual authoritative ARQ geometry.
    pub fn validate(self) -> Result<(), Error> {
        self.arq.validate().map_err(Error::Recovery)?;
        if !(256..=65507).contains(&self.max_datagram_bytes)
            || self.lifetime.is_zero()
            || self
                .arq
                .max_source_bytes
                .checked_add(26)
                .is_none_or(|n| n > self.max_datagram_bytes)
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}
/// Structural, bounded transport, original deadline or real reservation refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid local geometry or lifetime.
    Configuration,
    /// Actual standard outer grammar refused.
    Wire(crate::Error),
    /// Existing selective-repeat operation refused.
    Recovery(recovery::RecoveryError),
    /// Actual reserved recovery construction refused.
    Storage(recovery::storage::Error),
    /// Additional bounded translation/read scratch could not be reserved.
    Allocation,
    /// Wrong session, reflected reset, key ID or remote-session ACK binding.
    Peer,
    /// TLS bytes were submitted before the original reset exchange.
    State,
    /// Nonwrapping 32-bit control packet space or checked arithmetic exhausted.
    Exhausted,
    /// Injected time moved backwards.
    Time,
    /// Original absolute owner lifetime expired.
    Expired,
    /// Complete caller output is too small before consuming an attempt.
    Output,
    /// Bounded pending ACK storage is full.
    Capacity,
}
impl std::fmt::Display for Error {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "OpenVPN control: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<crate::Error> for Error {
    fn from(error: crate::Error) -> Self {
        Self::Wire(error)
    }
}

fn bytes(count: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(count)
        .map_err(|_| Error::Allocation)?;
    bytes.resize(count, 0);
    Ok(bytes)
}
fn context(role: Role) -> RecoveryContext {
    RecoveryContext {
        session: 1,
        epoch: 1,
        role: if role == Role::Client {
            EndpointRole::Initiator
        } else {
            EndpointRole::Responder
        },
    }
}
fn opposite(role: Role) -> Role {
    if role == Role::Client {
        Role::Server
    } else {
        Role::Client
    }
}
fn internal_header(out: &mut [u8], sender: Role, kind: u8) {
    out[..4].copy_from_slice(b"L2AR");
    out[4] = 1;
    out[5] = 1;
    out[6] = kind;
    out[7] = if sender == Role::Client { 0 } else { 1 };
    out[8..24].copy_from_slice(&1u128.to_be_bytes());
    out[24..32].copy_from_slice(&1u64.to_be_bytes());
}

/// One actual reset exchange and reserved reliable TLS byte stream, without I/O.
pub struct Transport {
    config: Config,
    role: Role,
    peer: Option<SessionId>,
    recovery: SelectiveRepeat,
    last: Duration,
    expires: Duration,
    next_reset: Duration,
    resets: u32,
    reset_confirmed: bool,
    next_source: u64,
    ack_prefix: u64,
    ack_bits: u64,
    pending_acks: [u32; 65],
    ack_count: usize,
    outgoing: Vec<u8>,
    incoming: Vec<u8>,
    partial: Vec<u8>,
    partial_start: usize,
    partial_end: usize,
}
impl Transport {
    /// Fallibly construct actual bounded recovery and complete scratch before reset output.
    pub fn new(config: Config, role: Role, now: Duration) -> Result<Self, Error> {
        config.validate()?;
        let expires = now.checked_add(config.lifetime).ok_or(Error::Exhausted)?;
        let plan = recovery::storage::DuplexPlan::for_arq(config.arq, config.arq)
            .map_err(Error::Storage)?;
        let recovery = SelectiveRepeat::new_reserved(
            config.arq,
            context(role),
            recovery::storage::Limits {
                capacity_bytes: plan.capacity_bytes(),
            },
        )
        .map_err(Error::Storage)?;
        let scratch = recovery::DATA_HEADER_BYTES
            .checked_add(config.arq.max_source_bytes)
            .ok_or(Error::Exhausted)?
            .max(recovery::ACK_PACKET_BYTES);
        Ok(Self {
            config,
            role,
            peer: None,
            recovery,
            last: now,
            expires,
            next_reset: now,
            resets: 0,
            reset_confirmed: false,
            next_source: 0,
            ack_prefix: 0,
            ack_bits: 0,
            pending_acks: [0; 65],
            ack_count: 0,
            outgoing: bytes(scratch)?,
            incoming: bytes(scratch)?,
            partial: bytes(config.arq.max_source_bytes)?,
            partial_start: 0,
            partial_end: 0,
        })
    }
    fn time(&mut self, now: Duration) -> Result<(), Error> {
        if now < self.last {
            return Err(Error::Time);
        }
        if now >= self.expires {
            return Err(Error::Expired);
        }
        self.last = now;
        Ok(())
    }
    /// Whether both original session IDs are known; this is not TLS authentication.
    pub const fn ready(&self) -> bool {
        self.peer.is_some()
    }
    /// Exact locally supplied limits, including the complete original lifetime.
    pub const fn config(&self) -> Config {
        self.config
    }
    /// Original absolute expiry, unchanged by control retries.
    pub const fn expires(&self) -> Duration {
        self.expires
    }
    fn acknowledge(&mut self, id: u32) -> Result<(), Error> {
        if self.pending_acks[..self.ack_count].contains(&id) {
            return Ok(());
        }
        if self.ack_count == self.pending_acks.len() {
            return Err(Error::Capacity);
        }
        self.pending_acks[self.ack_count] = id;
        self.ack_count += 1;
        Ok(())
    }
    /// Consume standard reset/ACK/control fields; data belongs to the separate datagram path.
    pub fn receive(&mut self, packet: &[u8], now: Duration) -> Result<(), Error> {
        if packet.len() > self.config.max_datagram_bytes {
            return Err(Error::Configuration);
        }
        let Packet::Control(packet) = decode(packet)? else {
            return Err(Error::State);
        };
        if packet.key_id != 0 {
            return Err(Error::Peer);
        }
        let reset = match self.role {
            Role::Client => Opcode::HardResetServerV2,
            Role::Server => Opcode::HardResetClientV2,
        };
        if packet.opcode == reset {
            if packet.packet_id != Some(0) || self.peer.is_some_and(|peer| peer != packet.session) {
                return Err(Error::Peer);
            }
            match self.role {
                Role::Client
                    if packet.remote != Some(self.config.local)
                        || packet.acks.len() != 1
                        || packet.acks.iter().next() != Some(0) =>
                {
                    return Err(Error::Peer);
                }
                Role::Server if !packet.acks.is_empty() || packet.remote.is_some() => {
                    return Err(Error::Peer);
                }
                _ => {}
            }
            self.time(now)?;
            self.peer = Some(packet.session);
            if self.role == Role::Client {
                self.reset_confirmed = true;
                self.acknowledge(0)?;
            }
            return Ok(());
        }
        if !matches!(packet.opcode, Opcode::Control | Opcode::Ack)
            || self.peer != Some(packet.session)
            || (!packet.acks.is_empty() && packet.remote != Some(self.config.local))
        {
            return Err(Error::Peer);
        }
        if packet.payload.len() > self.config.arq.max_source_bytes {
            return Err(Error::Configuration);
        }
        if packet.packet_id == Some(0) {
            return Err(Error::Peer);
        }
        if packet.packet_id.is_some() && self.ack_count == self.pending_acks.len() {
            return Err(Error::Capacity);
        }
        let (mut prefix, mut bits) = (self.ack_prefix, self.ack_bits);
        let mut reset_confirmed = self.reset_confirmed;
        let mut has_ack = false;
        for id in packet.acks.iter() {
            if id == 0 {
                reset_confirmed = true;
                continue;
            }
            let source = u64::from(id - 1);
            if source < prefix {
                continue;
            }
            let offset = source - prefix;
            if offset >= 64 {
                return Err(Error::Peer);
            }
            bits |= 1u64 << offset;
            while bits & 1 != 0 {
                prefix = prefix.checked_add(1).ok_or(Error::Exhausted)?;
                bits >>= 1;
            }
            has_ack = true;
        }
        self.time(now)?;
        if has_ack {
            internal_header(&mut self.incoming, opposite(self.role), 2);
            self.incoming[32..40].copy_from_slice(&prefix.to_be_bytes());
            self.incoming[40..48].copy_from_slice(&bits.to_be_bytes());
            self.recovery
                .receive(&self.incoming[..48], now)
                .map_err(Error::Recovery)?;
            self.ack_prefix = prefix;
            self.ack_bits = bits;
        }
        if let Some(id) = packet.packet_id {
            internal_header(&mut self.incoming, opposite(self.role), 1);
            self.incoming[32..40].copy_from_slice(&u64::from(id - 1).to_be_bytes());
            self.incoming[40..44].copy_from_slice(&(packet.payload.len() as u32).to_be_bytes());
            self.incoming[44..44 + packet.payload.len()].copy_from_slice(packet.payload);
            self.recovery
                .receive(&self.incoming[..44 + packet.payload.len()], now)
                .map_err(Error::Recovery)?;
            self.acknowledge(id)?;
        }
        self.reset_confirmed = reset_confirmed;
        Ok(())
    }
    /// Admit an actual TLS ciphertext prefix; output is never custom ARQ bytes.
    pub fn write_tls(&mut self, input: &[u8], now: Duration) -> Result<usize, Error> {
        if !self.ready() {
            return Err(Error::State);
        }
        if self.next_source >= u64::from(u32::MAX) {
            return Err(Error::Exhausted);
        }
        self.time(now)?;
        if input.is_empty() {
            return Ok(0);
        }
        let count = input.len().min(self.config.arq.max_source_bytes);
        let id = self
            .recovery
            .submit(&input[..count], now)
            .map_err(Error::Recovery)?;
        if id != self.next_source {
            return Err(Error::State);
        }
        self.next_source += 1;
        Ok(count)
    }
    /// Read contiguous TLS bytes, retaining partial source custody; zero is not EOF.
    pub fn read_tls(&mut self, output: &mut [u8], now: Duration) -> Result<usize, Error> {
        self.time(now)?;
        if output.is_empty() {
            return Ok(0);
        }
        if self.partial_start == self.partial_end {
            let Some((_, length)) = self
                .recovery
                .poll_delivered(&mut self.partial)
                .map_err(Error::Recovery)?
            else {
                return Ok(0);
            };
            self.partial_start = 0;
            self.partial_end = length;
        }
        let length = output.len().min(self.partial_end - self.partial_start);
        output[..length]
            .copy_from_slice(&self.partial[self.partial_start..self.partial_start + length]);
        self.partial_start += length;
        Ok(length)
    }
    /// Emit one real standard reset, ACK or TLS control fragment into caller storage.
    /// The caller retains that exact datagram through socket WouldBlock.
    pub fn poll(&mut self, now: Duration, output: &mut [u8]) -> Result<Option<usize>, Error> {
        if output.len() < self.config.max_datagram_bytes {
            return Err(Error::Output);
        }
        self.time(now)?;
        if !self.reset_confirmed
            && now >= self.next_reset
            && (self.role == Role::Client || self.peer.is_some())
        {
            if self.resets > u32::from(self.config.arq.max_retries) {
                return Err(Error::Expired);
            }
            let (opcode, acks, remote) = if self.role == Role::Client {
                (Opcode::HardResetClientV2, &[][..], None)
            } else {
                (Opcode::HardResetServerV2, &[0][..], self.peer)
            };
            let attempts = self.resets.checked_add(1).ok_or(Error::Exhausted)?;
            let next_reset = now
                .checked_add(self.config.arq.initial_rto)
                .ok_or(Error::Exhausted)?;
            let length = encode_control(
                opcode,
                0,
                self.config.local,
                acks,
                remote,
                Some(0),
                &[],
                output,
            )?;
            self.resets = attempts;
            self.next_reset = next_reset;
            return Ok(Some(length));
        }
        // Only OpenVPN's explicit ACK array reaches the wire, not this private bitmap.
        self.recovery
            .poll_feedback(now, &mut self.outgoing)
            .map_err(Error::Recovery)?;
        if self.ack_count > 0 {
            let count = self
                .ack_count
                .min((self.config.max_datagram_bytes - 18) / 4);
            let length = encode_control(
                Opcode::Ack,
                0,
                self.config.local,
                &self.pending_acks[..count],
                self.peer,
                None,
                &[],
                output,
            )?;
            self.pending_acks.copy_within(count..self.ack_count, 0);
            self.ack_count -= count;
            return Ok(Some(length));
        }
        if !self.ready() {
            return Ok(None);
        }
        let Some(length) = self
            .recovery
            .poll_source(now, &mut self.outgoing)
            .map_err(Error::Recovery)?
        else {
            return Ok(None);
        };
        let PacketView::Data { source, payload } = recovery::inspect_packet(
            &self.outgoing[..length],
            context(opposite(self.role)),
            self.config.arq.max_source_bytes,
        )
        .map_err(Error::Recovery)?
        else {
            return Err(Error::State);
        };
        let id = u32::try_from(source.0.checked_add(1).ok_or(Error::Exhausted)?)
            .map_err(|_| Error::Exhausted)?;
        Ok(Some(encode_control(
            Opcode::Control,
            0,
            self.config.local,
            &[],
            None,
            Some(id),
            payload,
            output,
        )?))
    }
}

#[cfg(test)]
mod tests;
