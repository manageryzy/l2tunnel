//! Authenticated in-band live speed-budget tuning (`ProfileTag::RateBudgetV1`).
//!
//! Carried on the authenticated `Liveness` control stream (`Control` scope)
//! under whole-message custody with the same MUX admission and channel budget
//! as other control traffic. Both ends validate bounds (`1 Mbit/s ..= 10 Gbit/s`)
//! and apply the new wire-pacing budget only after peer confirmation.

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};

use tokio::sync::oneshot;

/// Minimum live speed budget per direction: 1 Mbit/s (`125_000` bytes/s).
pub const MIN_RATE_BYTES_PER_SEC: u64 = 125_000;
/// Maximum live speed budget per direction: 10 Gbit/s (`1_250_000_000` bytes/s).
pub const MAX_RATE_BYTES_PER_SEC: u64 = 1_250_000_000;
/// Exact encoded wire length of one `RateBudgetV1` frame.
pub const FRAME_BYTES: usize = 24;

const VERSION: u8 = 1;
const KIND_REQUEST: u8 = 1;
const KIND_ACK: u8 = 2;
const KIND_REFUSAL: u8 = 3;

const CODE_OK: u8 = 0;
const CODE_OUT_OF_BOUNDS: u8 = 1;

const DEADLINE_US: u64 = 2_000_000;
const MAX_OUTGOING: usize = 4;

/// Failure of one live speed-budget update.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RateBudgetError {
    /// Requested upload or download rate is outside `[1 Mbit/s ..= 10 Gbit/s]`.
    InvalidRate,
    /// Another speed-budget update is already in flight.
    Busy,
    /// Peer did not confirm within 2 seconds (e.g. older build).
    Timeout,
    /// Peer explicitly refused the requested bounds.
    PeerRefused,
    /// Peer sent a malformed reply.
    Malformed,
    /// The session ended before the update completed.
    Closed,
}

/// Whether `rate` (bytes/s) lies within the allowed live-tuning bounds.
pub fn valid_rate(rate: u64) -> bool {
    (MIN_RATE_BYTES_PER_SEC..=MAX_RATE_BYTES_PER_SEC).contains(&rate)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WireFrame {
    kind: u8,
    code: u8,
    id: u32,
    initiator_send_rate: u64,
    peer_send_rate: u64,
}

impl WireFrame {
    fn encode(self) -> [u8; FRAME_BYTES] {
        let mut out = [0_u8; FRAME_BYTES];
        out[0] = VERSION;
        out[1] = self.kind;
        out[2] = self.code;
        out[3] = 0;
        out[4..8].copy_from_slice(&self.id.to_be_bytes());
        out[8..16].copy_from_slice(&self.initiator_send_rate.to_be_bytes());
        out[16..24].copy_from_slice(&self.peer_send_rate.to_be_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != FRAME_BYTES || bytes[0] != VERSION || bytes[3] != 0 {
            return None;
        }
        let kind = bytes[1];
        if !matches!(kind, KIND_REQUEST | KIND_ACK | KIND_REFUSAL) {
            return None;
        }
        let id = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if id == 0 {
            return None;
        }
        let initiator_send_rate = u64::from_be_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        let peer_send_rate = u64::from_be_bytes([
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]);
        Some(Self {
            kind,
            code: bytes[2],
            id,
            initiator_send_rate,
            peer_send_rate,
        })
    }
}

type Outcome = Result<(u64, u64), RateBudgetError>;

struct Pending {
    id: u32,
    send_rate: u64,
    receive_rate: u64,
    reply: oneshot::Sender<Outcome>,
}

struct SharedState {
    next_id: u32,
    queued: Option<Pending>,
    in_flight: Option<oneshot::Sender<Outcome>>,
    closed: bool,
}

impl Default for SharedState {
    fn default() -> Self {
        Self {
            next_id: 1,
            queued: None,
            in_flight: None,
            closed: false,
        }
    }
}

/// Shared service-to-runtime handle for live speed-budget updates (at most one
/// update in flight per session).
#[derive(Default)]
pub(super) struct Shared {
    state: Mutex<SharedState>,
}

impl Shared {
    pub(super) fn request(
        &self,
        send_rate: u64,
        receive_rate: u64,
    ) -> Result<oneshot::Receiver<Outcome>, RateBudgetError> {
        if !valid_rate(send_rate) || !valid_rate(receive_rate) {
            return Err(RateBudgetError::InvalidRate);
        }
        let Ok(mut state) = self.state.lock() else {
            return Err(RateBudgetError::Closed);
        };
        if state.closed {
            return Err(RateBudgetError::Closed);
        }
        if state.queued.is_some() || state.in_flight.is_some() {
            return Err(RateBudgetError::Busy);
        }
        let id = state.next_id;
        state.next_id = state.next_id.wrapping_add(1).max(1);
        let (tx, rx) = oneshot::channel();
        state.queued = Some(Pending {
            id,
            send_rate,
            receive_rate,
            reply: tx,
        });
        Ok(rx)
    }

    fn take_queued(&self) -> Option<(u32, u64, u64)> {
        let mut state = self.state.lock().ok()?;
        let pending = state.queued.take()?;
        state.in_flight = Some(pending.reply);
        Some((pending.id, pending.send_rate, pending.receive_rate))
    }

    fn finish(&self, result: Result<(u64, u64), RateBudgetError>) {
        if let Ok(mut state) = self.state.lock()
            && let Some(sender) = state.in_flight.take()
        {
            let _sent = sender.send(result);
        }
    }

    fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.closed = true;
            if let Some(queued) = state.queued.take() {
                let _sent = queued.reply.send(Err(RateBudgetError::Closed));
            }
            if let Some(sender) = state.in_flight.take() {
                let _sent = sender.send(Err(RateBudgetError::Closed));
            }
        }
    }
}

struct ActiveRequest {
    id: u32,
    send_rate: u64,
    receive_rate: u64,
    deadline_us: u64,
    frame: [u8; FRAME_BYTES],
    submitted: bool,
}

/// Session-loop side of live speed-budget updates.
pub(super) struct Port {
    shared: Option<Arc<Shared>>,
    active: Option<ActiveRequest>,
    outgoing: VecDeque<([u8; FRAME_BYTES], u64)>,
}

impl Port {
    pub(super) fn new(shared: Option<Arc<Shared>>) -> Self {
        Self {
            shared,
            active: None,
            outgoing: VecDeque::with_capacity(MAX_OUTGOING),
        }
    }

    fn complete_active(&mut self, result: Result<(u64, u64), RateBudgetError>) {
        self.active = None;
        if let Some(shared) = &self.shared {
            shared.finish(result);
        }
    }

    fn push_outgoing(&mut self, frame: [u8; FRAME_BYTES], deadline_us: u64) {
        if self.outgoing.len() < MAX_OUTGOING {
            self.outgoing.push_back((frame, deadline_us));
        }
    }

    fn wake_at(&self) -> Option<u64> {
        let active = self.active.as_ref().map(|req| req.deadline_us);
        let reply = self.outgoing.front().map(|(_, dl)| *dl);
        match (active, reply) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

impl Drop for Port {
    fn drop(&mut self) {
        if let Some(shared) = &self.shared {
            shared.close();
        }
    }
}

impl super::Driver {
    pub(super) fn install_rate_budget(&mut self, requests: &super::Requests) {
        if self.common.is_none() {
            return;
        }
        let super::Requests::Common(requests) = requests;
        let shared = requests.as_ref().map(|req| req.4.clone());
        self.rate_budget = Some(Box::new(Port::new(shared)));
    }

    pub(super) fn apply_rate_budget(
        &mut self,
        now: u64,
        send_rate: u64,
        receive_rate: u64,
    ) -> io::Result<()> {
        self.bucket.refill(now)?;
        self.bucket.rate = send_rate;
        // Scale burst to 10 ms of wire budget (bounded to [64 KiB, 4 MiB]) so
        // 1-2 ms event-loop wakeups never discard wire tokens at 200-1000 Mb/s.
        let scaled_burst = usize::try_from(send_rate / 100)
            .unwrap_or(4 << 20)
            .clamp(64 << 10, 4 << 20);
        self.bucket.burst = self.bucket.burst.max(scaled_burst).min(4 << 20);
        self.bucket.tokens = self
            .bucket
            .tokens
            .min(self.bucket.burst as u128 * super::SCALE);
        if send_rate.max(receive_rate) > 12_500_000 {
            self.config.work.receive_packets = self.config.work.receive_packets.clamp(1024, 4096);
            self.config.work.send_batch = self.config.work.send_batch.clamp(256, 4096);
            self.config.work.native_read_batch =
                self.config.work.native_read_batch.clamp(256, 4096);
            self.config.work.native_write_batch =
                self.config.work.native_write_batch.clamp(256, 4096);
        }
        if let Some(runtime) = self.common.as_deref_mut() {
            if let Some(serializer) = runtime.serializer.as_mut() {
                serializer.observe(now, send_rate)?;
            }
            if let Some(credit) = runtime.credit.as_mut() {
                credit.set_send_rate(send_rate);
                credit.raise_ceiling_for_rates(send_rate, receive_rate);
            }
            runtime.rate_override = Some((send_rate, receive_rate));
            runtime.observation_dirty = true;
        }
        Ok(())
    }

    pub(super) fn service_rate_budget(&mut self, now: u64) -> io::Result<()> {
        let Some(mut port) = self.rate_budget.take() else {
            return Ok(());
        };
        let result = self.drive_rate_budget(&mut port, now);
        self.rate_budget = Some(port);
        result
    }

    fn drive_rate_budget(&mut self, port: &mut Port, now: u64) -> io::Result<()> {
        if let Some(active) = &port.active
            && now >= active.deadline_us
        {
            port.complete_active(Err(RateBudgetError::Timeout));
        }

        if port.active.is_none()
            && let Some(shared) = port.shared.clone()
            && let Some((id, send_rate, receive_rate)) = shared.take_queued()
        {
            let frame = WireFrame {
                kind: KIND_REQUEST,
                code: CODE_OK,
                id,
                initiator_send_rate: send_rate,
                peer_send_rate: receive_rate,
            }
            .encode();
            port.active = Some(ActiveRequest {
                id,
                send_rate,
                receive_rate,
                deadline_us: now.saturating_add(DEADLINE_US),
                frame,
                submitted: false,
            });
        }

        if let Some(active) = &mut port.active
            && !active.submitted
        {
            let deadline = active.deadline_us.min(self.lease);
            let submitted = self.submit(
                now,
                self.records.control_scope(),
                super::control::Body::ProfileControl {
                    tag: super::control::ProfileTag::RateBudgetV1,
                    bytes: &active.frame,
                },
                deadline,
                true,
            )?;
            if submitted.is_some() {
                active.submitted = true;
            }
        }

        while let Some((frame, deadline_us)) = port.outgoing.pop_front() {
            if now >= deadline_us {
                continue;
            }
            let deadline = deadline_us.min(self.lease);
            let submitted = self.submit(
                now,
                self.records.control_scope(),
                super::control::Body::ProfileControl {
                    tag: super::control::ProfileTag::RateBudgetV1,
                    bytes: &frame,
                },
                deadline,
                true,
            )?;
            if submitted.is_none() {
                port.outgoing.push_front((frame, deadline_us));
                break;
            }
        }
        Ok(())
    }

    pub(super) fn receive_rate_budget(&mut self, now: u64, bytes: &[u8]) -> io::Result<()> {
        let Some(mut port) = self.rate_budget.take() else {
            return Ok(());
        };
        let deadline_us = now.saturating_add(DEADLINE_US);
        let result = match WireFrame::decode(bytes) {
            Some(frame) if frame.kind == KIND_REQUEST => {
                if valid_rate(frame.initiator_send_rate) && valid_rate(frame.peer_send_rate) {
                    let applied = self.apply_rate_budget(
                        now,
                        frame.peer_send_rate,
                        frame.initiator_send_rate,
                    );
                    if applied.is_ok() {
                        let ack = WireFrame {
                            kind: KIND_ACK,
                            code: CODE_OK,
                            ..frame
                        }
                        .encode();
                        port.push_outgoing(ack, deadline_us);
                    }
                    applied
                } else {
                    let refusal = WireFrame {
                        kind: KIND_REFUSAL,
                        code: CODE_OUT_OF_BOUNDS,
                        ..frame
                    }
                    .encode();
                    port.push_outgoing(refusal, deadline_us);
                    Ok(())
                }
            }
            Some(frame) if frame.kind == KIND_ACK => {
                if let Some(active) = &port.active
                    && active.id == frame.id
                {
                    if frame.initiator_send_rate == active.send_rate
                        && frame.peer_send_rate == active.receive_rate
                    {
                        let (send_rate, receive_rate) = (active.send_rate, active.receive_rate);
                        match self.apply_rate_budget(now, send_rate, receive_rate) {
                            Ok(()) => {
                                port.complete_active(Ok((send_rate, receive_rate)));
                                Ok(())
                            }
                            Err(err) => {
                                port.complete_active(Err(RateBudgetError::Closed));
                                Err(err)
                            }
                        }
                    } else {
                        port.complete_active(Err(RateBudgetError::Malformed));
                        Ok(())
                    }
                } else {
                    Ok(())
                }
            }
            Some(frame) if frame.kind == KIND_REFUSAL => {
                if port.active.as_ref().is_some_and(|a| a.id == frame.id) {
                    port.complete_active(Err(RateBudgetError::PeerRefused));
                }
                Ok(())
            }
            _ => Ok(()),
        };
        self.rate_budget = Some(port);
        result
    }

    pub(super) fn rate_budget_wake(&self) -> Option<u64> {
        self.rate_budget.as_deref()?.wake_at()
    }
}
