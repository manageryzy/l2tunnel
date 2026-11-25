//! In-band remote CSR meter reads (`docs/modules/meter-csr.md`, MCSR-09).
//!
//! Carried on the authenticated `Liveness` control stream (`ProfileTag::MetersV1`,
//! `Control` scope) under whole-message custody, with the same MUX admission and
//! channel budget as other control traffic. Enforces single-in-flight reads,
//! `MIN_INTERVAL_MS` (250 ms) rate gating, `DEADLINE_MS` (2 s) deadlines, and
//! stream-bounded reply paging (`answer_bounded`). Decode errors and refusals
//! never panic and never alter session state.

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};

use l2tunnel_meters::wire::{
    self, Code, DEADLINE_MS, MAX_REPLY_BYTES, Message, RateGate, Refusal, Request,
};
use tokio::sync::oneshot;

/// Most queued outbound replies/refusals waiting for control-stream space.
const MAX_OUTGOING_RESPONSES: usize = 2;

/// One completed remote CSR meter page from the authenticated peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteMeterReply {
    /// Peer session generation reported in the reply.
    pub generation: u64,
    /// Register `(path, value)` pairs in strictly increasing order.
    pub entries: Vec<(String, u64)>,
    /// Last path when more matching entries follow.
    pub next: Option<String>,
}

/// Failure of one remote CSR meter read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteMeterError {
    /// Another read is in flight or faster than `MIN_INTERVAL_MS` (250 ms).
    Busy,
    /// Peer did not answer within `DEADLINE_MS` (2 s).
    Timeout,
    /// Peer answered with a typed refusal.
    PeerRefused(Code),
    /// Request or reply failed wire validation.
    Malformed,
    /// The session ended before the read completed.
    Closed,
}

struct PendingClient {
    id: u32,
    prefix: String,
    cursor: Option<String>,
    limit: u16,
    reply: oneshot::Sender<Result<RemoteMeterReply, RemoteMeterError>>,
}

struct SharedState {
    next_id: u32,
    queued: Option<PendingClient>,
    in_flight: Option<oneshot::Sender<Result<RemoteMeterReply, RemoteMeterError>>>,
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

/// Shared service-to-runtime handle for remote CSR meter reads (at most one
/// read in flight per session).
#[derive(Default)]
pub(super) struct Shared {
    state: Mutex<SharedState>,
}

impl Shared {
    /// Queue one remote read; returns `Busy` when one is already pending.
    pub(super) fn request(
        &self,
        prefix: String,
        cursor: Option<String>,
        limit: u16,
    ) -> Result<oneshot::Receiver<Result<RemoteMeterReply, RemoteMeterError>>, RemoteMeterError>
    {
        let Ok(mut state) = self.state.lock() else {
            return Err(RemoteMeterError::Closed);
        };
        if state.closed {
            return Err(RemoteMeterError::Closed);
        }
        if state.queued.is_some() || state.in_flight.is_some() {
            return Err(RemoteMeterError::Busy);
        }
        let id = state.next_id;
        state.next_id = state.next_id.wrapping_add(1).max(1);
        let (tx, rx) = oneshot::channel();
        state.queued = Some(PendingClient {
            id,
            prefix,
            cursor,
            limit,
            reply: tx,
        });
        Ok(rx)
    }

    fn take_queued(&self) -> Option<(u32, String, Option<String>, u16)> {
        let mut state = self.state.lock().ok()?;
        let pending = state.queued.take()?;
        state.in_flight = Some(pending.reply);
        Some((pending.id, pending.prefix, pending.cursor, pending.limit))
    }

    fn finish(&self, result: Result<RemoteMeterReply, RemoteMeterError>) {
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
                let _sent = queued.reply.send(Err(RemoteMeterError::Closed));
            }
            if let Some(sender) = state.in_flight.take() {
                let _sent = sender.send(Err(RemoteMeterError::Closed));
            }
        }
    }
}

struct ActiveRequest {
    id: u32,
    prefix: String,
    cursor: Option<String>,
    limit: u16,
    deadline_us: u64,
    encoded: Vec<u8>,
    submitted: bool,
}

/// Session-loop side of remote CSR meter reads.
pub(super) struct Port {
    shared: Option<Arc<Shared>>,
    outbound_gate: RateGate,
    inbound_gate: RateGate,
    active: Option<ActiveRequest>,
    outgoing_responses: VecDeque<(Vec<u8>, u64)>,
}

impl Port {
    pub(super) fn new(shared: Option<Arc<Shared>>) -> Self {
        Self {
            shared,
            outbound_gate: RateGate::default(),
            inbound_gate: RateGate::default(),
            active: None,
            outgoing_responses: VecDeque::with_capacity(MAX_OUTGOING_RESPONSES),
        }
    }

    fn queue_refusal(&mut self, id: u32, code: Code, deadline_us: u64) {
        if self.outgoing_responses.len() >= MAX_OUTGOING_RESPONSES {
            return;
        }
        let mut encoded = Vec::new();
        if (Refusal { id, code }).encode(&mut encoded).is_ok() {
            self.outgoing_responses.push_back((encoded, deadline_us));
        }
    }

    fn complete_active(&mut self, result: Result<RemoteMeterReply, RemoteMeterError>) {
        self.active = None;
        if let Some(shared) = &self.shared {
            shared.finish(result);
        }
    }

    fn wake_at(&self) -> Option<u64> {
        let active = self.active.as_ref().map(|req| req.deadline_us);
        let response = self.outgoing_responses.front().map(|(_, dl)| *dl);
        match (active, response) {
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
    pub(super) fn install_remote_meters(&mut self, requests: &super::Requests) {
        if self.common.is_none() {
            return;
        }
        let super::Requests::Common(requests) = requests;
        let shared = requests.as_ref().map(|req| req.3.clone());
        self.remote_meters = Some(Box::new(Port::new(shared)));
    }

    pub(super) fn service_remote_meters(&mut self, now: u64) -> io::Result<()> {
        let Some(mut port) = self.remote_meters.take() else {
            return Ok(());
        };
        let result = self.drive_remote_meters(&mut port, now);
        self.remote_meters = Some(port);
        result
    }

    fn drive_remote_meters(&mut self, port: &mut Port, now: u64) -> io::Result<()> {
        if let Some(active) = &port.active
            && now >= active.deadline_us
        {
            port.complete_active(Err(RemoteMeterError::Timeout));
        }

        if port.active.is_none()
            && let Some(shared) = port.shared.clone()
            && let Some((id, prefix, cursor, limit)) = shared.take_queued()
        {
            let now_ms = now / 1000;
            if !port.outbound_gate.admit(now_ms) {
                shared.finish(Err(RemoteMeterError::Busy));
            } else {
                let mut encoded = Vec::new();
                let req = Request {
                    id,
                    limit,
                    prefix: &prefix,
                    cursor: cursor.as_deref(),
                };
                if req.encode(&mut encoded).is_err() {
                    shared.finish(Err(RemoteMeterError::Malformed));
                } else {
                    let deadline_us = now.saturating_add(DEADLINE_MS.saturating_mul(1000));
                    port.active = Some(ActiveRequest {
                        id,
                        prefix,
                        cursor,
                        limit,
                        deadline_us,
                        encoded,
                        submitted: false,
                    });
                }
            }
        }

        if let Some(active) = &mut port.active
            && !active.submitted
        {
            let deadline = active.deadline_us.min(self.lease);
            let submitted = self.submit(
                now,
                self.records.control_scope(),
                super::control::Body::ProfileControl {
                    tag: super::control::ProfileTag::MetersV1,
                    bytes: &active.encoded,
                },
                deadline,
                true,
            )?;
            if submitted.is_some() {
                active.submitted = true;
            }
        }

        while let Some((encoded, deadline_us)) = port.outgoing_responses.pop_front() {
            if now >= deadline_us {
                continue;
            }
            let deadline = deadline_us.min(self.lease);
            let submitted = self.submit(
                now,
                self.records.control_scope(),
                super::control::Body::ProfileControl {
                    tag: super::control::ProfileTag::MetersV1,
                    bytes: &encoded,
                },
                deadline,
                true,
            )?;
            if submitted.is_none() {
                port.outgoing_responses.push_front((encoded, deadline_us));
                break;
            }
        }
        Ok(())
    }

    pub(super) fn receive_remote_meters(&mut self, now: u64, bytes: &[u8]) {
        let Some(mut port) = self.remote_meters.take() else {
            return;
        };
        let deadline_us = now.saturating_add(DEADLINE_MS.saturating_mul(1000));
        match Message::decode(bytes) {
            Ok(Message::Request(req)) => {
                let now_ms = now / 1000;
                if !port.inbound_gate.admit(now_ms) {
                    port.queue_refusal(req.id, Code::Busy, deadline_us);
                } else if port.outgoing_responses.len() >= MAX_OUTGOING_RESPONSES {
                    // Already saturated with queued replies; drop excess.
                } else if let Some(table) = self.current_meters_table(now) {
                    let cap = self.control.liveness_max_body_bytes().min(MAX_REPLY_BYTES);
                    let mut out = Vec::new();
                    let generation = self.source_scope.epoch.0;
                    match wire::answer_bounded(&table, generation, &req, cap, &mut out) {
                        Ok(()) => port.outgoing_responses.push_back((out, deadline_us)),
                        Err(wire::Error::Limits) => {
                            port.queue_refusal(req.id, Code::Limits, deadline_us);
                        }
                        Err(_) => {
                            port.queue_refusal(req.id, Code::Malformed, deadline_us);
                        }
                    }
                } else {
                    port.queue_refusal(req.id, Code::NotRunning, deadline_us);
                }
            }
            Ok(Message::Reply(reply)) => {
                if let Some(active) = &port.active
                    && active.id == reply.id
                {
                    let req = Request {
                        id: active.id,
                        limit: active.limit,
                        prefix: &active.prefix,
                        cursor: active.cursor.as_deref(),
                    };
                    if reply.check(&req).is_ok() {
                        let next = reply
                            .more
                            .then(|| reply.entries.last().map(|(path, _)| path.clone()))
                            .flatten();
                        port.complete_active(Ok(RemoteMeterReply {
                            generation: reply.generation,
                            entries: reply.entries,
                            next,
                        }));
                    } else {
                        port.complete_active(Err(RemoteMeterError::Malformed));
                    }
                }
            }
            Ok(Message::Refusal(refusal)) => {
                if port.active.as_ref().is_some_and(|a| a.id == refusal.id) {
                    port.complete_active(Err(RemoteMeterError::PeerRefused(refusal.code)));
                }
            }
            Err(error) => {
                if let Some(id) = Message::id_of(bytes) {
                    if port.active.as_ref().is_some_and(|a| a.id == id) {
                        port.complete_active(Err(RemoteMeterError::Malformed));
                    } else {
                        let code = match error {
                            wire::Error::Limits => Code::Limits,
                            _ => Code::Malformed,
                        };
                        port.queue_refusal(id, code, deadline_us);
                    }
                }
            }
        }
        self.remote_meters = Some(port);
    }

    pub(super) fn remote_meters_wake(&self) -> Option<u64> {
        self.remote_meters.as_deref()?.wake_at()
    }
}
