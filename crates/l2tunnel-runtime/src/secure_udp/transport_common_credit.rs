//! Session receiver credit on the Common runtime (`docs/modules/receiver-credit.md`).
//!
//! The receive side counts every finished authenticated data datagram and
//! issues an unreliable Credit control record; the send side folds the peer's
//! newest Credit into the data eligibility of `prepare_common_wire_for`.
//! Control and data feedback are never gated or counted.
use super::*;
use l2tunnel_flow_control::session_credit::{self as sc, Applied, Gate};

/// Half of Linux's default 212,992-byte receive buffer: the grant's allowance
/// term when the data socket's real buffer cannot be read back (raw and carrier
/// paths), and its cap otherwise. The allowance is how far the grant may run
/// ahead of the measured drain; a larger socket buffer is headroom for receiver
/// stalls, not a reason to let more data into the path (a 16 MiB allowance
/// flooded the bottleneck queue in the 2026-11-24 native cells).
const FALLBACK_ALLOWANCE: u64 = 106_496;
/// Largest receive buffer requested (1 GiB): Linux doubles it into an `int`.
const MAX_RECEIVE_BUFFER: usize = 1 << 30;

fn at(micros: u64) -> Duration {
    Duration::from_micros(micros)
}
fn micros(value: Duration) -> u64 {
    u64::try_from(value.as_micros()).unwrap_or(u64::MAX)
}
fn credit_error(error: sc::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

/// Observation-only counters beside the pure state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Counters {
    pub(crate) rejected: u64,
    pub(crate) sender_restarts: u64,
    pub(crate) unrecorded: u64,
    pub(crate) allowance_readback: bool,
    /// Receive buffer requested from the data socket (`ceiling_bytes`), once.
    pub(crate) requested_receive_buffer: Option<u64>,
    /// The kernel's raw `SO_RCVBUF` read-back after that request.
    pub(crate) receive_buffer_readback: Option<u64>,
}

/// Requested and effective session credit at one observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreditSnapshot {
    /// Authenticated configuration (requested).
    pub configured: sc::Config,
    /// What runs: `configured` fitted to the record-receive range
    /// ([`sc::Config::fit_range`]); differs only when that range is small.
    pub effective: sc::Config,
    /// Receive buffer this endpoint requested from its UDP data socket.
    pub requested_receive_buffer: Option<u64>,
    /// The kernel's raw read-back (Linux reports twice the granted value).
    pub receive_buffer_readback: Option<u64>,
    /// Receive direction: what this endpoint grants.
    pub receiver: sc::ReceiverStatus,
    /// Send direction: what the peer granted; absent before the first data.
    pub sender: Option<sc::SenderStatus>,
    /// Malformed Credit bodies received.
    pub rejected: u64,
    /// Sender restarts after a packet-number regression.
    pub sender_restarts: u64,
    /// Sent data datagrams outside the window (not expected).
    pub unrecorded: u64,
    /// Whether the allowance comes from the socket's real receive buffer.
    pub allowance_readback: bool,
}

/// Both directions of one session's credit.
#[derive(Debug)]
pub(crate) struct State {
    requested: sc::Config,
    config: sc::Config,
    max_datagram: u64,
    send_rate: u64,
    burst: u64,
    range: u64,
    receiver: sc::Receiver,
    sender: Option<sc::Sender>,
    last_sent: Option<u64>,
    pacing_wake: Option<u64>,
    counters: Counters,
}
impl State {
    pub(crate) fn new(
        config: sc::Config,
        path_mtu: usize,
        send_rate: u64,
        burst: u64,
        range: u64,
    ) -> io::Result<Self> {
        let max_datagram = u64::try_from(path_mtu).map_err(invalid)?;
        let requested = config;
        let config = config
            .fit_range(range)
            .map_err(|_| invalid("record-receive range below 64 datagrams"))?;
        if config != requested {
            eprintln!(
                "l2tunnel: warning: record-receive range {range} (min of packets_per_key and \
                 max_forward_packets) is below 4 x credit ceiling_datagrams {}; running with \
                 ceiling_datagrams {}. Raise max_forward_packets and packets_per_key to at least \
                 {} to keep the configured ceiling.",
                requested.ceiling_datagrams,
                config.ceiling_datagrams,
                requested.ceiling_datagrams.saturating_mul(4),
            );
        }
        Ok(Self {
            requested,
            config,
            max_datagram,
            send_rate,
            burst,
            range,
            receiver: sc::Receiver::new(config, max_datagram, FALLBACK_ALLOWANCE)
                .map_err(credit_error)?,
            sender: None,
            last_sent: None,
            pacing_wake: None,
            counters: Counters::default(),
        })
    }
    /// Replace the fallback allowance with half the socket's real buffer, at
    /// most the fallback, before any data was processed.
    pub(crate) fn observe_receive_buffer(&mut self, bytes: usize) -> io::Result<()> {
        if self.counters.allowance_readback || self.receiver.status(Duration::ZERO).processed != 0 {
            return Ok(());
        }
        let allowance = u64::try_from(bytes / 2)
            .map_err(invalid)?
            .min(FALLBACK_ALLOWANCE);
        self.receiver =
            sc::Receiver::new(self.config, self.max_datagram, allowance).map_err(credit_error)?;
        self.counters.allowance_readback = true;
        Ok(())
    }
    fn sender_for(&mut self, number: u64) -> io::Result<&mut sc::Sender> {
        let restart = self.last_sent.is_some_and(|last| number <= last);
        if self.sender.is_none() || restart {
            if restart {
                self.counters.sender_restarts = self.counters.sender_restarts.saturating_add(1);
                self.last_sent = None;
            }
            self.sender = Some(
                sc::Sender::new(
                    self.config,
                    self.max_datagram,
                    number,
                    self.send_rate,
                    self.burst,
                    self.range,
                )
                .map_err(credit_error)?,
            );
        }
        self.sender
            .as_mut()
            .ok_or_else(|| protocol("session credit sender"))
    }
    fn min_rtt(&self, now: u64) -> Option<Duration> {
        self.sender
            .as_ref()
            .and_then(|sender| sender.min_rtt(at(now)))
    }
    /// Update the configured send rate cap (bytes per second) live.
    pub(crate) fn set_send_rate(&mut self, send_rate: u64) {
        if send_rate == 0 {
            return;
        }
        self.send_rate = send_rate;
        self.burst = self.burst.max(send_rate / 100).min(4 << 20);
        if let Some(sender) = &mut self.sender {
            sender.set_configured_rate(send_rate);
        }
    }
    /// Raise the credit datagram and byte ceilings live when the negotiated
    /// speed budget exceeds the 100 Mbit/s baseline so high-BDP (200-1000 Mb/s
    /// at 70 ms RTT + 15% loss) sessions never stall on the initial plan cap.
    pub(crate) fn raise_ceiling_for_rates(&mut self, send_rate: u64, receive_rate: u64) {
        let peak = send_rate.max(receive_rate);
        if peak <= 12_500_000 {
            return;
        }
        // ~300 ms of packets at 1200 B/datagram (~3x BDP at 70 ms RTT + loss),
        // bounded to [8192, 32768] and fitted to `range / 4`.
        let target_datagrams = (peak / 4_000).clamp(8_192, 32_768).min(self.range / 4);
        let target_bytes = (peak / 2).clamp(16 << 20, 64 << 20);
        let next_datagrams = target_datagrams.max(self.config.ceiling_datagrams);
        let next_bytes = target_bytes.max(self.config.ceiling_bytes);
        self.config.ceiling_datagrams = next_datagrams;
        self.config.ceiling_bytes = next_bytes;
        self.receiver.raise_ceiling(next_datagrams, next_bytes);
        if let Some(sender) = &mut self.sender {
            sender.raise_ceiling(next_datagrams);
        }
    }
    /// Observation only.
    pub(crate) fn snapshot(&self, now: u64) -> CreditSnapshot {
        CreditSnapshot {
            configured: self.requested,
            effective: self.config,
            requested_receive_buffer: self.counters.requested_receive_buffer,
            receive_buffer_readback: self.counters.receive_buffer_readback,
            receiver: self.receiver.status(at(now)),
            sender: self.sender.as_ref().map(|sender| sender.status(at(now))),
            rejected: self.counters.rejected,
            sender_restarts: self.counters.sender_restarts,
            unrecorded: self.counters.unrecorded,
            allowance_readback: self.counters.allowance_readback,
        }
    }
}

const CREDIT_WINDOW_KEY: crate::buffer_metrics::Key = crate::buffer_metrics::Key {
    site: crate::buffer_metrics::Site::CreditWindow,
    lane: crate::buffer_metrics::Lane::Shared,
    class: crate::buffer_metrics::Class::User,
};

fn record_credit_wait(
    metrics: Option<&mut crate::buffer_metrics::Observer>,
    blocked: Option<crate::buffer_metrics::Reason>,
    now: u64,
) {
    use crate::buffer_metrics::Reason;
    let Some(metrics) = metrics.filter(|observer| !observer.is_finished()) else {
        return;
    };
    let collector = metrics.collector();
    for reason in [
        Reason::PeerCredit,
        Reason::PolicyPacing,
        Reason::PolicyCredit,
    ] {
        let _ = if blocked == Some(reason) {
            collector.blocked(CREDIT_WINDOW_KEY, reason, now)
        } else {
            collector.progress(CREDIT_WINDOW_KEY, reason, now)
        };
    }
}

impl Driver {
    fn credit(&mut self) -> Option<&mut State> {
        self.common
            .as_deref_mut()
            .and_then(|runtime| runtime.credit.as_mut())
    }
    /// Once, before data: ask the UDP data socket for a receive buffer of the
    /// credit byte ceiling, then read back what the kernel granted. Credit may
    /// let up to `ceiling_bytes` be in flight; a buffer that holds it keeps a
    /// receiver stall from overflowing the socket. The kernel charges only
    /// queued bytes, so an idle large buffer costs nothing. Without
    /// `CAP_NET_ADMIN` Linux caps the request at `net.core.rmem_max`; the
    /// read-back allowance then follows the smaller buffer.
    pub(super) fn credit_observe_udp(&mut self, socket: &tokio::net::UdpSocket) -> io::Result<()> {
        let Some(state) = self.credit() else {
            return Ok(());
        };
        if state.counters.allowance_readback {
            return Ok(());
        }
        #[cfg(any(unix, windows))]
        {
            let target = usize::try_from(state.config.ceiling_bytes)
                .unwrap_or(usize::MAX)
                .min(MAX_RECEIVE_BUFFER);
            let sock = socket2::SockRef::from(socket);
            if state.counters.requested_receive_buffer.is_none() {
                state.counters.requested_receive_buffer = u64::try_from(target).ok();
                // Failures leave the kernel default; the read-back shows it.
                let _ = sock.set_recv_buffer_size(target);
                // Also raise SO_SNDBUF (up to 4 MiB) so high-rate UDP bursts
                // do not stall on Linux's default 212 KiB send buffer.
                let _ = sock.set_send_buffer_size(target.min(4 << 20));
                #[cfg(target_os = "linux")]
                if sock
                    .recv_buffer_size()
                    .is_ok_and(|granted| granted / 2 < target)
                {
                    let _ = rustix::net::sockopt::set_socket_recv_buffer_size_force(socket, target);
                }
            }
            if let Ok(bytes) = sock.recv_buffer_size() {
                state.counters.receive_buffer_readback = u64::try_from(bytes).ok();
                state.observe_receive_buffer(bytes)?;
            }
        }
        #[cfg(not(any(unix, windows)))]
        let _ = socket;
        Ok(())
    }
    /// Receive buffer requested from the UDP data socket, if any.
    pub(super) fn credit_requested_receive_buffer(&self) -> Option<u64> {
        self.common
            .as_deref()
            .and_then(|runtime| runtime.credit.as_ref())
            .and_then(|state| state.counters.requested_receive_buffer)
    }
    /// Whether data datagram `number` may be prepared now.
    ///
    /// `has_demand` indicates whether the active engine currently has unsent
    /// or unconfirmed work. Timed wait episodes on `Site::CreditWindow` are
    /// opened only while `has_demand` is true so idle intervals never fabricate
    /// credit blocking.
    pub(super) fn credit_gate(
        &mut self,
        number: u64,
        now: u64,
        has_demand: bool,
    ) -> io::Result<bool> {
        use crate::buffer_metrics::Reason;
        let Some(runtime) = self.common.as_deref_mut() else {
            return Ok(true);
        };
        let (Some(state), metrics) = (runtime.credit.as_mut(), runtime.buffer_metrics.as_mut())
        else {
            return Ok(true);
        };
        state.pacing_wake = None;
        let sender = state.sender_for(number)?;
        let range_before = sender.range_blocked();
        let gate = sender.gate(number, at(now)).map_err(credit_error)?;
        let range_refused = sender.range_blocked() > range_before;
        let (allowed, reason) = match gate {
            Gate::Open => (true, None),
            Gate::Credit => (
                false,
                Some(if range_refused {
                    Reason::PolicyCredit
                } else {
                    Reason::PeerCredit
                }),
            ),
            Gate::Pacing(ready) => {
                state.pacing_wake = Some(micros(ready));
                (false, Some(Reason::PolicyPacing))
            }
        };
        record_credit_wait(metrics, if has_demand { reason } else { None }, now);
        Ok(allowed)
    }
    /// Record one sealed data datagram.
    pub(super) fn credit_sent(&mut self, number: u64, bytes: usize, now: u64) -> io::Result<()> {
        let Some(state) = self.credit() else {
            return Ok(());
        };
        let bytes = u64::try_from(bytes).map_err(invalid)?;
        let result = state.sender_for(number)?.sent(number, bytes, at(now));
        match result {
            Ok(()) => {}
            // Gated in the same turn; a mismatch only loses this observation.
            Err(sc::Error::Window) => {
                state.counters.unrecorded = state.counters.unrecorded.saturating_add(1);
            }
            Err(error) => return Err(credit_error(error)),
        }
        state.last_sent = Some(number);
        Ok(())
    }
    /// Count one finished authenticated data datagram, whatever its outcome.
    pub(super) fn credit_processed(
        &mut self,
        number: u64,
        bytes: usize,
        now: u64,
    ) -> io::Result<()> {
        let Some(state) = self.credit() else {
            return Ok(());
        };
        let bytes = u64::try_from(bytes).map_err(invalid)?;
        state
            .receiver
            .processed(number, bytes, at(now))
            .map_err(credit_error)
    }
    /// Apply an authenticated Control plaintext if it is a Credit.
    /// Returns false for every other control body.
    pub(super) fn credit_receive(&mut self, plain: &[u8], now: u64) -> io::Result<bool> {
        if !sc::Credit::is_tagged(plain) {
            return Ok(false);
        }
        let Some(state) = self.credit() else {
            return Err(protocol("session credit without a Common owner"));
        };
        let credit = match sc::Credit::decode(plain) {
            Ok(credit) => credit,
            Err(error) => {
                state.counters.rejected = state.counters.rejected.saturating_add(1);
                return Err(credit_error(error));
            }
        };
        let first = credit.processed;
        let sender = state.sender_for(state.last_sent.map_or(first, |last| last + 1))?;
        if sender.apply(credit, at(now)).map_err(credit_error)? == Applied::Stale {
            return Ok(true);
        }
        state.pacing_wake = None;
        Ok(true)
    }
    /// Exact full-wire charge of one Credit control record.
    fn credit_charge(&self) -> io::Result<usize> {
        self.records
            .capacity_for(record::compact::Kind::Control, sc::WIRE_BYTES)
            .map_err(record_error)?
            .packet_bytes
            .checked_add(self.ip)
            .ok_or_else(exhausted)
    }
    /// Issue the next Credit body when one is due and the shared allowance
    /// can pay for it; returns the body and its exact full-wire charge.
    pub(super) fn due_credit_body(
        &mut self,
        now: u64,
    ) -> io::Result<Option<([u8; sc::WIRE_BYTES], usize)>> {
        let frozen = !self.native.can_acquire();
        let Some(state) = self.credit() else {
            return Ok(None);
        };
        let min_rtt = state.min_rtt(now);
        state.receiver.set_frozen(frozen);
        if state
            .receiver
            .due(at(now), min_rtt)
            .is_none_or(|due| due > at(now))
        {
            return Ok(None);
        }
        let charge = self.credit_charge()?;
        if self.bucket.allowance() < charge {
            return Ok(None);
        }
        let state = self
            .credit()
            .ok_or_else(|| protocol("session credit owner"))?;
        let body = state
            .receiver
            .issue(at(now), min_rtt)
            .and_then(|credit| credit.encode())
            .map_err(credit_error)?;
        Ok(Some((body, charge)))
    }
    /// Seal one due Credit as a Control record into the shared wire buffer.
    pub(super) fn prepare_credit(&mut self, now: u64) -> io::Result<Option<usize>> {
        let Some((body, charge)) = self.due_credit_body(now)? else {
            return Ok(None);
        };
        let sealed = self
            .records
            .seal(
                Class::Control,
                meta(self.outer, cover::Phase::Established),
                &body,
                &mut self.buffers.seal,
                &mut self.buffers.wire,
            )
            .map_err(record_error)?;
        if sealed.bytes + self.ip != charge {
            return Err(protocol("session credit full-wire accounting mismatch"));
        }
        self.counters.control_number = Some(sealed.number);
        self.counters.control_generation = Some(sealed.generation);
        Ok(Some(sealed.bytes))
    }
    /// Earliest credit wake: the next due Credit, or pacing reopening data.
    pub(super) fn credit_wake(&self, now: u64) -> Option<u64> {
        let state = self.common.as_deref()?.credit.as_ref()?;
        let due = state.receiver.due(at(now), state.min_rtt(now)).map(micros);
        match (due, state.pacing_wake) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}
