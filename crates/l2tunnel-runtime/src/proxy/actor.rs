use super::arbiter::{Arbiter, Owner, Selected};
use super::transport::{Direction, Event, Output, Progress};
use super::wire::{ControlFrame as Frame, Credit, Fence, Start};
use super::*;
use l2tunnel_tcp_proxy::admission::{Inspection, inspect_open, inspect_syn};
use l2tunnel_tcp_proxy::{adaptive, measurement};
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::{BTreeMap, BTreeSet};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::{Instant, interval, timeout_at};

#[derive(Clone, Copy)]
struct Binding {
    key: FlowKey,
    weight: u16,
}
struct Writer {
    control: mpsc::Sender<Output>,
    users: mpsc::Sender<Vec<u8>>,
    progress: watch::Receiver<Progress>,
    start: Start,
    ready: bool,
    last_ping: Instant,
    next_ping: u64,
    outstanding: Option<(u64, Instant)>,
    pending_pong: Option<u64>,
    queued_pong: u64,
    credit_due: Instant,
    close: bool,
}
impl Writer {
    fn control(&self, frame: Frame) -> io::Result<bool> {
        match self.control.try_send(Output::Control(frame)) {
            Ok(()) => Ok(true),
            Err(mpsc::error::TrySendError::Full(_)) => Ok(false),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(invalid("proxy writer stopped")),
        }
    }
}
#[cfg(unix)]
pub(super) type CommonRetirement = super::common_bridge::Bridge;
#[cfg(not(unix))]
#[derive(Clone)]
pub(super) enum CommonRetirement {}
#[cfg(not(unix))]
impl CommonRetirement {
    pub(super) fn timing_enabled(&self) -> bool {
        match *self {}
    }
    pub(super) fn timing_event(&self, _event: super::timing::Event) {
        match *self {}
    }
    fn timing_enter(&self, _stage: super::timing::Stage, _now: Instant) {
        match *self {}
    }
    fn timing_finish(&self, _now: Instant) {
        match *self {}
    }

    pub(super) async fn prepare_user_receipt(&self, _ordinal: u64) -> io::Result<()> {
        match *self {}
    }
    pub(super) fn take_physical_receipt(&self) -> io::Result<super::transport::PhysicalWrite> {
        match *self {}
    }
    fn acknowledge_user_receipts(&self, _count: u64) -> io::Result<()> {
        match *self {}
    }
    fn retained_user_receipts(
        &self,
    ) -> io::Result<(
        u64,
        [Option<super::transport::PhysicalWrite>; super::transport::PHYSICAL_SLOTS],
    )> {
        match *self {}
    }
    fn set_drain_cap(&self, _cap: Instant) -> io::Result<()> {
        match *self {}
    }
    async fn wait_retired(&self) -> io::Result<()> {
        match *self {}
    }
}
struct Actor {
    retirement: Option<CommonRetirement>,
    config: Config,
    logical: [u8; 16],
    originator: bool,
    table: session::Table,
    measured: Option<measured::State>,
    wire: Arbiter,
    native: Arbiter,
    bindings: BTreeMap<u64, Binding>,
    announced: BTreeSet<u64>,
    scheduled: BTreeSet<u64>,
    native_scheduled: BTreeSet<u64>,
    selected_native: Option<Selected>,
    input: Option<Vec<u8>>,
    input_transparent: bool,
    incoming: Option<Vec<u8>>,
    writers: Vec<Writer>,
    starts: Vec<bool>,
    ready: Vec<bool>,
    peer_ping: Vec<u64>,
    eof: Vec<bool>,
    closed: Vec<bool>,
    started: bool,
    start: Instant,
    deadline: Option<Instant>,
    peer_quiesce: bool,
    peer_quiesce_users: u64,
    quiesce_queued: bool,
    frozen: bool,
    closing: bool,
    sent: Credit,
    peer_credit: Credit,
    received: Credit,
    delivered: Credit,
    queued_credit: Credit,
    sent_records: u64,
    received_records: u64,
    local_fence: Option<Fence>,
    peer_fence: Option<Fence>,
    peer_ack: Option<Fence>,
    ack_queued: bool,
    reply: Option<Reply>,
}
fn error(e: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::other(e)
}
fn increment(n: u64) -> io::Result<u64> {
    n.checked_add(1)
        .ok_or_else(|| invalid("proxy counter exhausted"))
}
impl Actor {
    fn micros(&self) -> io::Result<measurement::Micros> {
        Ok(measurement::Micros(
            self.start.elapsed().as_micros().try_into().map_err(error)?,
        ))
    }
    fn bind(&mut self, id: u64, binding: Binding) -> io::Result<()> {
        if let std::collections::btree_map::Entry::Vacant(entry) = self.bindings.entry(id) {
            if let Some(state) = &mut self.measured {
                state
                    .controller
                    .bind_flow(adaptive::FlowWeight {
                        flow: id,
                        weight: binding.weight,
                    })
                    .map_err(error)?;
            }
            entry.insert(binding);
        }
        Ok(())
    }
    fn envelope(
        &self,
        channel: u16,
        flow: u64,
        body: &[u8],
        measurement: bool,
    ) -> io::Result<Vec<u8>> {
        if self.measured.is_none() {
            return wire::user(channel, flow, body);
        }
        let kind = if measurement {
            measured::envelope::Kind::Measurement
        } else if flow == 0 {
            measured::envelope::Kind::Transparent
        } else {
            measured::envelope::Kind::Proxy
        };
        let mut bytes = vec![0; measured::envelope::HEADER_BYTES + body.len()];
        measured::envelope::encode_fixed(
            &self.config,
            measured::envelope::StructuralEnvelope {
                kind,
                channel,
                flow,
                body,
            },
            &mut bytes,
        )?;
        Ok(bytes)
    }
    fn millis(&self) -> io::Result<Millis> {
        Ok(Millis(
            self.start.elapsed().as_millis().try_into().map_err(error)?,
        ))
    }
    fn scope(&self, id: u64) -> proxy::Scope {
        proxy::Scope {
            session: self.logical,
            epoch: 1,
            flow: id,
        }
    }
    fn binding(&self, bytes: &[u8]) -> io::Result<Binding> {
        let c = self.config.classify(bytes)?;
        Ok(Binding {
            key: c.key,
            weight: self.config.mux.dscp_weights[c.ip.map_or(0, |ip| ip.dscp) as usize],
        })
    }
    fn drain(&mut self, at: Instant) -> io::Result<()> {
        let end = at
            .checked_add(self.config.timeouts.shutdown)
            .ok_or_else(|| invalid("proxy shutdown deadline overflow"))?;
        self.deadline = Some(self.deadline.map_or(end, |old| old.min(end)));
        if let Some(retirement) = &self.retirement {
            retirement.set_drain_cap(
                self.deadline
                    .ok_or_else(|| invalid("proxy drain cap missing"))?,
            )?;
        }
        let now = self.micros()?;
        if let Some(state) = &mut self.measured {
            state.controller.quiesce(now).map_err(error)?;
        }
        Ok(())
    }
    fn check_shutdown_deadline(&self, now: Instant) -> io::Result<()> {
        if self.deadline.is_some_and(|end| now >= end) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "proxy original shutdown deadline",
            ));
        }
        Ok(())
    }
    fn snapshot(&self, failure: Option<String>) -> Status {
        let mut active = 0;
        let mut stopped = 0;
        let mut retired = 0;
        for id in 1..=self.table.status().flows as u64 {
            if let Some(s) = self.table.flow_status(id) {
                match s.phase {
                    session::FlowPhase::Opening(_) | session::FlowPhase::Active => active += 1,
                    session::FlowPhase::Stopped(_) => stopped += 1,
                    session::FlowPhase::Retired => retired += 1,
                }
            }
        }
        let (wb, wp) = self.wire.usage();
        let (nb, np) = self.native.usage();
        Status {
            phase: if failure.is_some() {
                Phase::Failed
            } else if self.closing {
                Phase::Closing
            } else if self.deadline.is_some() {
                Phase::Quiescing
            } else if self.started {
                Phase::Forwarding
            } else {
                Phase::Starting
            },
            flows: self.table.status().flows,
            active,
            stopped,
            retired,
            queued_bytes: wb + nb + self.selected_native.as_ref().map_or(0, |p| p.bytes.len()),
            queued_records: wp + np + usize::from(self.selected_native.is_some()),
            transparent_admitted_bytes: self.sent.bytes,
            transparent_admitted_packets: self.sent.packets,
            native_confirmed_packets: self.delivered.packets,
            failure,
        }
    }
    fn publish(&mut self, sink: &StatusSink, status: Status, force: bool) -> io::Result<()> {
        match sink {
            StatusSink::Fixed(sender) => {
                sender.send_replace(Some(status));
            }
            StatusSink::Measured(sender) => {
                let now = self.micros()?;
                let state = self
                    .measured
                    .as_mut()
                    .ok_or_else(|| invalid("measured status lacks Controller"))?;
                if force || state.publish_due(status.phase, now)? {
                    sender.send_replace(Some(measured::Status {
                        runtime: status,
                        measurement: state.snapshot(&self.table, now)?,
                    }));
                }
            }
        }
        Ok(())
    }
    fn settled(&self) -> bool {
        (1..=self.table.status().flows as u64).all(|id| {
            self.table.flow_status(id).is_some_and(|s| {
                matches!(
                    s.phase,
                    session::FlowPhase::Retired | session::FlowPhase::Stopped(_)
                ) && s.native.is_none()
                    && s.pending_native_bytes == 0
                    && s.pending_record_bytes == 0
            })
        })
    }
    fn event(&mut self, event: Event) -> io::Result<()> {
        match event {
            Event::Eof(i) => {
                if self.deadline.is_none() {
                    return Err(invalid("proxy TLS EOF before drain"));
                }
                self.eof[i] = true;
            }
            Event::WriteClosed(i) => self.closed[i] = true,
            Event::Control(i, frame, preceding_users) => match frame {
                Frame::Start(_) => self.starts[i] = true,
                Frame::Ready(_) => self.ready[i] = true,
                Frame::Credit(c) => {
                    if !c.contains(self.peer_credit) || !self.sent.contains(c) {
                        return Err(invalid("proxy invalid cumulative native credit"));
                    }
                    self.peer_credit = c;
                }
                Frame::Ping(n) => {
                    if n <= self.peer_ping[i] {
                        return Err(invalid("proxy heartbeat replay"));
                    }
                    self.peer_ping[i] = n;
                    let w = if self.writers.len() == 1 { 0 } else { 1 - i };
                    let writer = &mut self.writers[w];
                    if writer.pending_pong.is_some()
                        || writer.queued_pong != writer.progress.borrow().pong
                    {
                        return Err(invalid("proxy overlapping heartbeat request"));
                    }
                    writer.pending_pong = Some(n);
                }
                Frame::Pong(n) => {
                    let w = if self.writers.len() == 1 { 0 } else { 1 - i };
                    if self.writers[w].outstanding.map(|p| p.0) != Some(n) {
                        return Err(invalid("proxy unmatched heartbeat response"));
                    }
                    self.writers[w].outstanding = None;
                }
                Frame::Quiesce => {
                    self.peer_quiesce = true;
                    self.peer_quiesce_users = preceding_users;
                    self.drain(Instant::now())?;
                }
                Frame::Barrier(f) => {
                    if f.flows > self.config.relay.max_flows as u64
                        || f.records < self.received_records
                        || !f.transparent.contains(self.received)
                    {
                        return Err(invalid("proxy invalid final peer fence"));
                    }
                    self.peer_fence = Some(f);
                }
                Frame::Ack(f) => {
                    if self.local_fence != Some(f) {
                        return Err(invalid("proxy final ACK mismatch"));
                    }
                    self.peer_ack = Some(f);
                }
            },
        }
        Ok(())
    }
    fn service_control(&mut self) -> io::Result<()> {
        let now = Instant::now();
        self.measured_deadlines(now)?;
        if self.starts.iter().all(|x| *x) {
            for writer in &mut self.writers {
                if !writer.ready && writer.control(Frame::Ready(writer.start))? {
                    writer.ready = true;
                }
            }
        }
        self.started = self.ready.iter().all(|x| *x)
            && self
                .writers
                .iter()
                .all(|w| w.ready && w.progress.borrow().ready);
        if !self.started {
            if now.duration_since(self.start) >= self.config.timeouts.startup {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "proxy Start/Ready deadline",
                ));
            }
            return Ok(());
        }
        if self.closing {
            return Ok(());
        }
        for writer in &mut self.writers {
            if let Some((_, at)) = writer.outstanding
                && now.duration_since(at) >= self.config.timeouts.control_idle
            {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "proxy heartbeat deadline",
                ));
            }
            if let Some(n) = writer.pending_pong
                && writer.control(Frame::Pong(n))?
            {
                writer.pending_pong = None;
                writer.queued_pong = n;
            }
            if !self.closing
                && writer.outstanding.is_none()
                && now.duration_since(writer.last_ping) >= self.config.timeouts.control_idle / 3
            {
                let n = writer.next_ping;
                if writer.control(Frame::Ping(n))? {
                    writer.next_ping = increment(n)?;
                    writer.outstanding = Some((n, now));
                    writer.last_ping = now;
                }
            }
        }
        if !self.closing
            && now >= self.writers[0].credit_due
            && self.delivered != self.queued_credit
            && self.writers[0].progress.borrow().credit == self.queued_credit
            && self.writers[0].control(Frame::Credit(self.delivered))?
        {
            self.queued_credit = self.delivered;
            self.writers[0].credit_due = now
                .checked_add(
                    transport::control_interval(self.config.control_rate)?
                        .checked_mul(4)
                        .ok_or_else(|| invalid("proxy credit pacing interval overflow"))?,
                )
                .ok_or_else(|| invalid("proxy credit pacing deadline overflow"))?;
        }
        Ok(())
    }
    fn poll_table(&mut self) -> io::Result<()> {
        let now = self.millis()?;
        self.table
            .poll(now, self.config.flow_poll_work, self.config.stack_poll_work)
            .map_err(error)?;
        for id in 1..=self.table.status().flows as u64 {
            if self.originator
                && !self.announced.contains(&id)
                && self.table.flow_status(id).is_some_and(|s| {
                    matches!(
                        s.phase,
                        session::FlowPhase::Stopped(_) | session::FlowPhase::Retired
                    )
                })
            {
                return Err(invalid(
                    "unannounced proxy ID expired before carrier ownership",
                ));
            }
            if matches!(self.table.retire_clean(id),Err(e) if e!=session::Error::State) {
                return Err(invalid("proxy clean retirement failed"));
            }
        }
        Ok(())
    }
    fn schedule_table(&mut self) -> io::Result<()> {
        let now = self.start.elapsed();
        for id in 1..=self.table.status().flows as u64 {
            let binding = *self
                .bindings
                .get(&id)
                .ok_or_else(|| invalid("proxy owner lacks flow binding"))?;
            if self.measured.is_none()
                && !self.scheduled.contains(&id)
                && let Some(body) = self.table.pending_record(id)
            {
                let channel = self.wire.channel(binding.key, now)?;
                let bytes = wire::user(channel, id, body)?;
                match self
                    .wire
                    .push(binding.key, binding.weight, bytes, Owner::Proxy(id), now)
                {
                    Ok(()) => {
                        self.scheduled.insert(id);
                    }
                    Err(e) if e.pressure => {}
                    Err(e) => return Err(e.error),
                }
            }
            if !self.native_scheduled.contains(&id)
                && let Some(body) = self.table.pending_native(id)
            {
                match self.native.push(
                    binding.key,
                    binding.weight,
                    body.to_vec(),
                    Owner::NativeProxy(id),
                    now,
                ) {
                    Ok(()) => {
                        self.native_scheduled.insert(id);
                    }
                    Err(e) if e.pressure => {
                        if let Some(state) = &mut self.measured {
                            state.receiver_pressure = true;
                        }
                    }
                    Err(e) => return Err(e.error),
                }
            }
        }
        Ok(())
    }
    // Fact import has no Controller callback, semantic flush, or slot release.
    // Terminal import reads the actual fixed Bridge ring atomically even when
    // the original cleanup cap cannot wait for an aborted writer to join.
    fn observe_measured_physical(&mut self, terminal: bool) -> io::Result<Progress> {
        let mut progress = *self.writers[0].progress.borrow();
        let Some(bridge) = &self.retirement else {
            return Ok(progress);
        };
        let Some(state) = &mut self.measured else {
            return Ok(progress);
        };
        if terminal {
            let (count, physical) = bridge.retained_user_receipts()?;
            progress.users = count;
            progress.physical = physical;
        }
        if bridge.timing_enabled() {
            state.observe_physical_diagnosed(
                progress.users,
                progress.physical,
                self.start,
                Instant::now(),
                terminal,
                |event| bridge.timing_event(event),
            )?;
        } else {
            state.observe_physical(
                progress.users,
                progress.physical,
                self.start,
                Instant::now(),
            )?;
        }
        Ok(progress)
    }
    fn measured_callbacks(&mut self) -> io::Result<()> {
        // Use the same copied watermark for import and semantic callback; a new
        // watch value may arrive concurrently after this bounded observation.
        let progress = self.observe_measured_physical(false)?;
        self.measured_deadlines(Instant::now())?;
        let now = self.micros()?;
        if let Some(state) = &mut self.measured {
            if let Some(bridge) = &self.retirement {
                if bridge.timing_enabled() {
                    state.callbacks_physical_diagnosed(
                        &self.table,
                        progress.users,
                        self.start,
                        Instant::now(),
                        |event| bridge.timing_event(event),
                    )?;
                } else {
                    state.callbacks_physical(
                        &self.table,
                        progress.users,
                        self.start,
                        Instant::now(),
                    )?;
                }
                bridge.acknowledge_user_receipts(progress.users)?;
            } else {
                state.callbacks(&self.table, progress.users, now)?;
            }
        }
        Ok(())
    }
    fn timing_enter(&self, stage: super::timing::Stage) {
        if let Some(bridge) = &self.retirement
            && bridge.timing_enabled()
        {
            bridge.timing_enter(stage, Instant::now());
        }
    }
    fn timing_finish(&self, now: Instant) {
        if let Some(bridge) = &self.retirement
            && bridge.timing_enabled()
        {
            if let Some(state) = &self.measured {
                bridge.timing_event(super::timing::Event::TerminalLedger);
                state
                    .ledger
                    .visit_timing_pending(self.start, now, true, &mut |event| {
                        bridge.timing_event(event)
                    });
            }
            bridge.timing_finish(now);
        }
    }
    async fn wait_service(&mut self, tick: &mut tokio::time::Interval, deadline: Option<Instant>) {
        // An actual whole-write completion must wake its measured callback;
        // waiting for a periodic tick can consume the remaining original cap.
        let progress = &mut self.writers[0].progress;
        let observe_writer = self.measured.is_some() && progress.has_changed().is_ok();
        if let Some(at) = deadline {
            tokio::select! {
                _ = tick.tick() => {},
                _ = tokio::time::sleep_until(at) => {},
                _ = progress.changed(), if observe_writer => {},
            }
        } else {
            tokio::select! {
                _ = tick.tick() => {},
                _ = progress.changed(), if observe_writer => {},
            }
        }
    }
    async fn cooperate_after_turn(&mut self) {
        if self.measured.is_some() && self.retirement.is_some() {
            // Ready ticks/watch changes can otherwise chain several bounded
            // turns in one poll, delaying the Common sibling and spawned writer.
            tokio::task::yield_now().await;
        }
    }
    fn measured_deadlines(&self, now: Instant) -> io::Result<()> {
        if self.measured.is_none() {
            return Ok(());
        }
        let startup = self
            .start
            .checked_add(self.config.timeouts.startup)
            .ok_or_else(|| invalid("measured startup deadline overflow"))?;
        if (!self.started && now >= startup) || self.deadline.is_some_and(|end| now >= end) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "measured original startup/drain deadline",
            ));
        }
        Ok(())
    }
    async fn join_original(
        &self,
        tasks: &mut JoinSet<io::Result<()>>,
        end: Instant,
    ) -> io::Result<()> {
        self.measured_deadlines(Instant::now())?;
        match timeout_at(end, async {
            while let Some(result) = tasks.join_next().await {
                result.map_err(error)??;
            }
            Ok::<_, io::Error>(())
        })
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "proxy TLS join exceeded original deadline",
                ));
            }
        }
        // timeout_at polls a ready inner future first: explicit observation is
        // required even when the JoinSet was already empty at the boundary.
        self.measured_deadlines(Instant::now())
    }
    fn measured_service(&mut self) -> io::Result<()> {
        let now = self.micros()?;
        let queue_age = self.wire.oldest_age(self.start.elapsed())?;
        if let Some(state) = &mut self.measured {
            let writer_age = state.ledger.writer_age(now)?;
            let age = u64::try_from(queue_age.as_micros())
                .map_err(error)?
                .max(writer_age);
            let pressure = measurement::LocalPressure {
                queue_delay_micros: age,
                receiver_pressure: state.receiver_pressure,
                carrier_pressure: state.wire_pressure
                    || writer_age
                        >= state
                            .config
                            .measured
                            .allocation
                            .target
                            .queue_delay_target_micros,
            };
            state.service(&mut self.table, pressure, now)?;
        }
        Ok(())
    }
    fn schedule_measured(&mut self) -> io::Result<()> {
        let Some(state) = &self.measured else {
            return Ok(());
        };
        let count = self.config.relay.max_flows;
        let work = state.config.service.admission_work_per_turn;
        for _ in 0..work {
            let state = self
                .measured
                .as_mut()
                .ok_or_else(|| invalid("missing measured actor"))?;
            let slot = state.admission_cursor;
            state.admission_cursor = (slot + 1) % (count + 2);
            let now = self.start.elapsed();
            if slot < count {
                let id = slot as u64 + 1;
                if self.scheduled.contains(&id) {
                    continue;
                }
                let Some(body) = self.table.pending_record(id) else {
                    continue;
                };
                let binding = *self
                    .bindings
                    .get(&id)
                    .ok_or_else(|| invalid("measured proxy lacks binding"))?;
                let channel = self.wire.channel(binding.key, now)?;
                let bytes = self.envelope(channel, id, body, false)?;
                match self
                    .wire
                    .push(binding.key, binding.weight, bytes, Owner::Proxy(id), now)
                {
                    Ok(()) => {
                        self.scheduled.insert(id);
                    }
                    Err(e) if e.pressure => {
                        self.measured
                            .as_mut()
                            .ok_or_else(|| invalid("missing measured actor"))?
                            .wire_pressure = true
                    }
                    Err(e) => return Err(e.error),
                }
            } else if slot == count {
                if !self.input_transparent {
                    continue;
                }
                let bytes = self
                    .input
                    .as_ref()
                    .ok_or_else(|| invalid("transparent reservation missing"))?;
                let binding = self.binding(bytes)?;
                let channel = self.wire.channel(binding.key, now)?;
                let framed = self.envelope(channel, 0, bytes, false)?;
                match self.wire.push(
                    binding.key,
                    binding.weight,
                    framed,
                    Owner::Transparent(bytes.len()),
                    now,
                ) {
                    Ok(()) => {
                        self.input = None;
                        self.input_transparent = false;
                    }
                    Err(e) if e.pressure => {
                        self.measured
                            .as_mut()
                            .ok_or_else(|| invalid("missing measured actor"))?
                            .wire_pressure = true
                    }
                    Err(e) => return Err(e.error),
                }
            } else {
                let at = self.micros()?;
                let state = self
                    .measured
                    .as_mut()
                    .ok_or_else(|| invalid("missing measured actor"))?;
                let Some(pending) = state.controller.pending(&self.table, at).map_err(error)?
                else {
                    continue;
                };
                let binding = *self
                    .bindings
                    .get(&pending.flow)
                    .ok_or_else(|| invalid("measurement lacks lifetime binding"))?;
                let channel = self.wire.channel(binding.key, now)?;
                let Some(admission) = state.ledger.prepare_admission(&pending, channel, at)? else {
                    continue;
                };
                let kind = match measurement::wire::decode(pending.bytes)
                    .map_err(error)?
                    .body
                {
                    measurement::wire::Body::Demand(_) => 0,
                    measurement::wire::Body::EchoRequest { .. } => 1,
                    measurement::wire::Body::EchoReply { .. } => 2,
                };
                let mut bytes = vec![0; measured::envelope::HEADER_BYTES + pending.bytes.len()];
                measured::envelope::encode_fixed(
                    &self.config,
                    measured::envelope::StructuralEnvelope {
                        kind: measured::envelope::Kind::Measurement,
                        channel,
                        flow: pending.flow,
                        body: pending.bytes,
                    },
                    &mut bytes,
                )?;
                let framed = state
                    .framed_bytes
                    .checked_add((bytes.len() + super::record::FRAME_OVERHEAD) as u64)
                    .ok_or_else(|| invalid("measurement byte counter exhausted"))?;
                let admitted = increment(state.admitted[kind])?;
                match self.wire.push(
                    binding.key,
                    binding.weight,
                    bytes,
                    Owner::Measurement(admission.id()),
                    now,
                ) {
                    Ok(()) => {
                        state
                            .controller
                            .confirm_admission(admission.token(), at)
                            .map_err(error)?;
                        state.ledger.admit(admission)?;
                        state.admitted[kind] = admitted;
                        state.framed_bytes = framed;
                    }
                    Err(e) if e.pressure => state.wire_pressure = true,
                    Err(e) => return Err(e.error),
                }
            }
        }
        Ok(())
    }
    fn send_user(&mut self) -> io::Result<()> {
        if self.local_fence.is_some()
            || self.quiesce_queued && !self.writers[0].progress.borrow().quiesce
        {
            return Ok(());
        }
        let now = self.micros()?;
        if let Some(state) = &self.measured
            && state.ledger.prepare_send(None, now)?.is_none()
        {
            return Ok(());
        }
        let permit = match self.writers[0].users.clone().try_reserve_owned() {
            Ok(p) => p,
            Err(mpsc::error::TrySendError::Full(_)) => return Ok(()),
            Err(_) => return Err(invalid("proxy user writer stopped")),
        };
        let outstanding = Credit {
            bytes: self.sent.bytes - self.peer_credit.bytes,
            packets: self.sent.packets - self.peer_credit.packets,
        };
        let cap = self.config.delivery;
        let selected = self.wire.pop(|owner, _| match owner {
            Owner::Transparent(n) => {
                outstanding.bytes.saturating_add(n as u64) <= cap.transparent_bytes as u64
                    && outstanding.packets < cap.transparent_packets as u64
            }
            Owner::Proxy(_) | Owner::Measurement(_) => true,
            _ => false,
        })?;
        let Some(selected) = selected else {
            return Ok(());
        };
        let user = wire::decode_profile(&selected.bytes, &self.config, self.measured.is_some())?;
        if user.channel != selected.channel {
            return Err(invalid("proxy scheduler channel binding"));
        }
        if let Owner::Proxy(id) = selected.owner {
            self.scheduled.remove(&id);
            if self.table.pending_record(id) != Some(user.body) {
                return Ok(());
            }
        }
        let send = if let Some(state) = &self.measured {
            let id = if let Owner::Measurement(id) = selected.owner {
                state
                    .ledger
                    .check_selected(id, user.flow, user.channel, user.body)?;
                Some(id)
            } else {
                None
            };
            Some(
                state
                    .ledger
                    .prepare_send(id, now)?
                    .ok_or_else(|| invalid("measured writer slot lost"))?,
            )
        } else {
            None
        };
        let timeline_enabled = self
            .retirement
            .as_ref()
            .is_some_and(|bridge| bridge.timing_enabled());
        // Bound the real send; another thread may dequeue before the upper sample.
        let enqueue_before = timeline_enabled.then(Instant::now);
        let enqueue_after;
        match selected.owner {
            Owner::Proxy(id) => {
                let next = increment(self.sent_records)?;
                permit.send(selected.bytes);
                enqueue_after = timeline_enabled.then(Instant::now);
                self.table
                    .confirm_record_sent(id, self.millis()?)
                    .map_err(error)?;
                self.announced.insert(id);
                self.sent_records = next;
            }
            Owner::Transparent(n) => {
                let next = self.sent.add(n)?;
                let records = increment(self.sent_records)?;
                permit.send(selected.bytes);
                enqueue_after = timeline_enabled.then(Instant::now);
                self.sent = next;
                self.sent_records = records;
            }
            Owner::Measurement(_) => {
                let next = increment(self.sent_records)?;
                permit.send(selected.bytes);
                enqueue_after = timeline_enabled.then(Instant::now);
                self.sent_records = next;
            }
            _ => return Err(invalid("proxy user ownership class")),
        }
        if let Some(send) = send {
            let state = self
                .measured
                .as_mut()
                .ok_or_else(|| invalid("missing measured actor"))?;
            let ordinal = state.ledger.sent(send)?;
            if ordinal != self.sent_records {
                return Err(invalid("measured all-user ordinal mismatch"));
            }
            if let Some((before, after)) = enqueue_before.zip(enqueue_after)
                && let Some(bridge) = &self.retirement
            {
                bridge.timing_event(
                    state
                        .ledger
                        .timing_handoff(ordinal, self.start, before, after),
                );
            }
        }
        Ok(())
    }
    fn receive_user(&mut self, bytes: Vec<u8>) -> io::Result<Option<Vec<u8>>> {
        let user = wire::decode_profile(&bytes, &self.config, self.measured.is_some())?;
        let now = self.millis()?;
        if let Some(f) = self.peer_fence
            && self.received_records >= f.records
        {
            return Err(invalid("proxy user exceeds final fence"));
        }
        if user.measurement {
            let binding = self
                .bindings
                .get(&user.flow)
                .ok_or_else(|| invalid("measurement for unknown lifetime flow"))?;
            if self.wire.channel(binding.key, self.start.elapsed())? != user.channel {
                return Err(invalid("measurement channel mismatch"));
            }
            let at = self.micros()?;
            self.measured
                .as_mut()
                .ok_or_else(|| invalid("measurement outside explicit profile"))?
                .controller
                .receive_authenticated(&self.table, user.body, at)
                .map_err(error)?;
        } else if user.flow == 0 {
            if user.body.len() > self.config.runtime.max_packet
                || !super::super::packet_valid(PacketLayer::Ip, user.body)
            {
                return Err(invalid("proxy transparent packet size/shape"));
            }
            let packet = user.body.to_vec();
            let binding = self.binding(&packet)?;
            if self.wire.channel(binding.key, self.start.elapsed())? != user.channel {
                return Err(invalid("proxy transparent channel mismatch"));
            }
            let received = self.received.add(packet.len())?;
            if received.bytes - self.delivered.bytes > self.config.delivery.transparent_bytes as u64
                || received.packets - self.delivered.packets
                    > self.config.delivery.transparent_packets as u64
            {
                return Err(invalid("peer exceeded transparent native credit"));
            }
            self.table
                .observe_transparent(&packet, now)
                .map_err(error)?;
            match self.native.push(
                binding.key,
                binding.weight,
                packet,
                Owner::NativeTransparent,
                self.start.elapsed(),
            ) {
                Ok(()) => self.received = received,
                Err(e) if e.pressure => {
                    if let Some(state) = &mut self.measured {
                        state.receiver_pressure = true;
                    }
                    return Ok(Some(bytes));
                }
                Err(e) => return Err(e.error),
            }
        } else {
            if user.body.get(32..40) != Some(user.flow.to_be_bytes().as_slice()) {
                return Err(invalid("proxy outer/inner flow mismatch"));
            }
            if user.body.get(..6) == Some(b"LTPA\x01\x01") {
                let syn = inspect_open(self.scope(user.flow), user.body).map_err(error)?;
                let binding = self.binding(syn.bytes())?;
                if self.bindings.contains_key(&user.flow)
                    || self.wire.channel(binding.key, self.start.elapsed())? != user.channel
                {
                    return Err(invalid("proxy Open identity/channel"));
                }
                let permit = self.config.routes.permits(syn.source(), syn.destination());
                self.table
                    .receive_authenticated(user.body, permit, now)
                    .map_err(error)?;
                self.bind(user.flow, binding)?;
            } else {
                let binding = self
                    .bindings
                    .get(&user.flow)
                    .ok_or_else(|| invalid("unknown proxy owner"))?;
                if self.wire.channel(binding.key, self.start.elapsed())? != user.channel {
                    return Err(invalid("proxy owner channel mismatch"));
                }
                self.table
                    .receive_authenticated(user.body, false, now)
                    .map_err(error)?;
            }
        }
        self.received_records = increment(self.received_records)?;
        Ok(None)
    }
    fn receive_native(&mut self, bytes: Vec<u8>) -> io::Result<Option<Vec<u8>>> {
        if bytes.len() > self.config.runtime.max_packet
            || !super::super::packet_valid(PacketLayer::Ip, &bytes)
        {
            return Err(invalid("proxy native packet size/shape"));
        }
        let binding = self.binding(&bytes)?;
        let permit = if self.deadline.is_none() {
            match inspect_syn(&bytes, self.config.runtime.max_packet).map_err(error)? {
                Inspection::Candidate(syn) => {
                    self.config.routes.permits(syn.source(), syn.destination())
                }
                Inspection::Bypass(_) => false,
            }
        } else {
            false
        };
        match self
            .table
            .ingest_native(&bytes, permit, self.millis()?)
            .map_err(error)?
        {
            session::Disposition::Owned(id) => {
                self.bind(id, binding)?;
                Ok(None)
            }
            session::Disposition::Backpressure(_) => Ok(Some(bytes)),
            session::Disposition::Transparent => {
                if self.measured.is_some() {
                    self.input_transparent = true;
                    return Ok(Some(bytes));
                }
                let channel = self.wire.channel(binding.key, self.start.elapsed())?;
                let record = wire::user(channel, 0, &bytes)?;
                match self.wire.push(
                    binding.key,
                    binding.weight,
                    record,
                    Owner::Transparent(bytes.len()),
                    self.start.elapsed(),
                ) {
                    Ok(()) => Ok(None),
                    Err(e) if e.pressure => Ok(Some(bytes)),
                    Err(e) => Err(e.error),
                }
            }
        }
    }
    fn deliver<D: PacketDevice<Error = io::Error>>(&mut self, device: &mut D) -> io::Result<()> {
        if self.selected_native.is_none() {
            self.selected_native = self.native.pop(|_, _| true)?;
        }
        let Some(selected) = self.selected_native.as_ref() else {
            return Ok(());
        };
        if let Owner::NativeProxy(id) = selected.owner
            && self.table.pending_native(id) != Some(selected.bytes.as_slice())
        {
            return Err(invalid("proxy native retained output changed"));
        }
        match device.transmit(&selected.bytes) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Some(state) = &mut self.measured {
                    state.receiver_pressure = true;
                }
                return Ok(());
            }
            result => result?,
        }
        let selected = self
            .selected_native
            .take()
            .ok_or_else(|| invalid("proxy native handoff lost"))?;
        match selected.owner {
            Owner::NativeTransparent => {
                self.delivered = self.delivered.add(selected.bytes.len())?
            }
            Owner::NativeProxy(id) => {
                self.table.confirm_native_written(id).map_err(error)?;
                self.native_scheduled.remove(&id);
            }
            _ => return Err(invalid("proxy native ownership class")),
        }
        Ok(())
    }
    fn shutdown(&mut self) -> io::Result<Option<CloseReport>> {
        if self.deadline.is_none() || !self.started {
            return Ok(None);
        }
        // Existing reservations retain their deadlines and ordered IDs. Every
        // original Open must obtain reliable ownership before Quiesce can pass it.
        let announced = !self.originator || self.announced.len() == self.table.status().flows;
        if !self.quiesce_queued && announced && self.writers[0].control(Frame::Quiesce)? {
            self.quiesce_queued = true;
        }
        if self.peer_quiesce && self.received_records >= self.peer_quiesce_users && self.settled() {
            self.frozen = true;
        }
        let progress = *self.writers[0].progress.borrow();
        if self.frozen
            && self.input.is_none()
            && self.wire.usage().1 == 0
            && progress.quiesce
            && progress.users == self.sent_records
            && self
                .measured
                .as_ref()
                .is_none_or(|state| state.controller.drained() && state.ledger.counts() == (0, 0))
            && self.local_fence.is_none()
        {
            let f = Fence {
                records: self.sent_records,
                transparent: self.sent,
                flows: self.table.status().flows as u64,
            };
            if self.writers[0].control(Frame::Barrier(f))? {
                self.local_fence = Some(f);
            }
        }
        if let Some(f) = self.peer_fence {
            if self.received_records > f.records || !f.transparent.contains(self.received) {
                return Err(invalid("proxy peer exceeded final accounting"));
            }
            if self.received_records == f.records && self.incoming.is_none() {
                if self.received != f.transparent || self.table.status().flows as u64 != f.flows {
                    return Err(invalid("proxy final user/flow accounting mismatch"));
                }
                if self.delivered == f.transparent
                    && self.settled()
                    && self.native.usage().1 == 0
                    && self.selected_native.is_none()
                    && !self.ack_queued
                    && self.local_fence.is_some()
                    && self.queued_credit == self.delivered
                    && self.writers[0].control(Frame::Ack(f))?
                {
                    self.ack_queued = true;
                }
            }
        }
        let progress = *self.writers[0].progress.borrow();
        if self.local_fence.is_some()
            && progress.barrier == self.local_fence
            && self.peer_ack == self.local_fence
            && self.ack_queued
            && progress.ack == self.peer_fence
        {
            self.closing = true;
            for writer in &mut self.writers {
                if !writer.close {
                    match writer.control.try_send(Output::Close) {
                        Ok(()) => writer.close = true,
                        Err(mpsc::error::TrySendError::Full(_)) => {}
                        Err(_) => return Err(invalid("proxy writer closed before shutdown")),
                    }
                }
            }
        }
        if self.closing && self.eof.iter().all(|x| *x) && self.closed.iter().all(|x| *x) {
            let status = self.snapshot(None);
            return Ok(Some(CloseReport {
                local_user_records: self.sent_records,
                peer_user_records: self.received_records,
                local_transparent_packets: self.sent.packets,
                native_confirmed_packets: self.delivered.packets,
                clean_flows: status.retired,
                stopped_flows: status.stopped,
                tls_lanes_closed: self.writers.len(),
            }));
        }
        Ok(None)
    }
}

pub(super) async fn run<D: PacketDevice<Error = io::Error>>(
    device: D,
    link: Link,
    config: Config,
    control: Control,
) -> io::Result<CloseReport> {
    run_profile(device, link, config, control, None).await
}
pub(super) async fn run_profile<D: PacketDevice<Error = io::Error>>(
    device: D,
    link: Link,
    config: Config,
    control: Control,
    measured_config: Option<measured::Config>,
) -> io::Result<CloseReport> {
    run_profile_owned(device, link, config, control, measured_config, false).await
}
pub(super) fn run_profile_owned<D: PacketDevice<Error = io::Error>>(
    device: D,
    link: Link,
    config: Config,
    control: Control,
    measured_config: Option<measured::Config>,
    owned_cleanup: bool,
) -> impl std::future::Future<Output = io::Result<CloseReport>> {
    run_profile_selected(
        device,
        link,
        config,
        control,
        measured_config,
        owned_cleanup,
        None,
    )
}
pub(super) async fn run_profile_selected<D: PacketDevice<Error = io::Error>>(
    mut device: D,
    link: Link,
    config: Config,
    mut control: Control,
    measured_config: Option<measured::Config>,
    owned_cleanup: bool,
    retirement: Option<CommonRetirement>,
) -> io::Result<CloseReport> {
    config.validate()?;
    let binding = measured_config
        .as_ref()
        .map(measured::session_config)
        .transpose()?
        .unwrap_or(session_config(&config)?);
    if link.binding != binding
        || device.layer() != PacketLayer::Ip
        || link.inner.layer != PacketLayer::Ip
        || link.inner.reverse_reader.is_some()
            != (config.duplex == Duplex::Half && !link.common_ordered)
        || link.inner.reverse_writer.is_some()
            != (config.duplex == Duplex::Half && !link.common_ordered)
    {
        return Err(invalid("proxy retained link/device mismatch"));
    }
    let mut seed = [0; 8];
    SystemRandom::new()
        .fill(&mut seed)
        .map_err(|_| invalid("proxy native random seed unavailable"))?;
    let seed = u64::from_be_bytes(seed);
    if seed == 0 {
        return Err(invalid("proxy zero native seed"));
    }
    let start = Instant::now();
    let count = if config.duplex == Duplex::Half && !link.common_ordered {
        2
    } else {
        1
    };
    let (events_tx, mut events) = mpsc::channel(8);
    let (users_tx, mut users) = mpsc::channel(config.runtime.queue_packets);
    let (quiesce_tx, quiesce) = watch::channel(None);
    let table = session::Table::new(config.table(link.logical, link.originator, seed), Millis(0))
        .map_err(error)?;
    let mut measured = measured_config
        .as_ref()
        .map(|config| measured::State::new(config.clone(), &table))
        .transpose()?;
    if retirement.is_some()
        && let Some(state) = &mut measured
    {
        state.enable_physical_receipts()?;
    }
    let wire = Arbiter::new(&config, false)?;
    let native = Arbiter::new(&config, true)?;
    let is_measured = measured_config.is_some();
    let mut tasks = JoinSet::new();
    let send_lane = u8::from(config.duplex == Duplex::Half && !link.originator);
    let receive_lane = u8::from(config.duplex == Duplex::Half && link.originator);
    let mut readers = vec![(
        link.inner.reader,
        Direction {
            index: 0,
            lane: receive_lane,
            bulk: true,
        },
    )];
    let mut outputs = vec![(
        link.inner.writer,
        Direction {
            index: 0,
            lane: send_lane,
            bulk: true,
        },
    )];
    if let (Some(reader), Some(writer)) = (link.inner.reverse_reader, link.inner.reverse_writer) {
        readers.push((
            reader,
            Direction {
                index: 1,
                lane: send_lane,
                bulk: false,
            },
        ));
        outputs.push((
            writer,
            Direction {
                index: 1,
                lane: receive_lane,
                bulk: false,
            },
        ));
    }
    let mut writers = Vec::new();
    let mut pending_writers = Vec::new();
    for (writer, direction) in outputs {
        let (ctx, crx) = mpsc::channel(8);
        let (utx, urx) = mpsc::channel(1);
        let (ptx, prx) = watch::channel(Progress::default());
        let hello = Start {
            digest: link.binding.digest.0,
            session: link.logical,
            originator: link.originator,
            duplex: config.duplex,
            lane: direction.lane,
        };
        ctx.try_send(Output::Control(Frame::Start(hello)))
            .map_err(error)?;
        pending_writers.push(transport::writer_selected(
            writer,
            direction,
            config.control_rate,
            crx,
            urx,
            ptx,
            events_tx.clone(),
            retirement
                .as_ref()
                .filter(|_| is_measured && direction.bulk)
                .cloned(),
        ));
        writers.push(Writer {
            control: ctx,
            users: utx,
            progress: prx,
            start: hello,
            ready: false,
            last_ping: start,
            next_ping: 1,
            outstanding: None,
            pending_pong: None,
            queued_pong: 0,
            credit_due: start,
            close: false,
        });
    }
    for (reader, direction) in readers {
        let expected = Start {
            digest: link.binding.digest.0,
            session: link.logical,
            originator: !link.originator,
            duplex: config.duplex,
            lane: direction.lane,
        };
        tasks.spawn(transport::reader(
            reader,
            direction,
            expected,
            (config.clone(), is_measured),
            events_tx.clone(),
            users_tx.clone(),
            quiesce_tx.clone(),
        ));
    }
    for writer in pending_writers {
        tasks.spawn(writer);
    }
    drop(events_tx);
    drop(users_tx);
    drop(quiesce_tx);
    let mut actor = Actor {
        retirement,
        logical: link.logical,
        originator: link.originator,
        table,
        measured,
        wire,
        native,
        config,
        bindings: BTreeMap::new(),
        announced: BTreeSet::new(),
        scheduled: BTreeSet::new(),
        native_scheduled: BTreeSet::new(),
        selected_native: None,
        input: None,
        input_transparent: false,
        incoming: None,
        writers,
        starts: vec![false; count],
        ready: vec![false; count],
        peer_ping: vec![0; count],
        eof: vec![false; count],
        closed: vec![false; count],
        started: false,
        start,
        deadline: None,
        peer_quiesce: false,
        peer_quiesce_users: 0,
        quiesce_queued: false,
        frozen: false,
        closing: false,
        sent: Credit::default(),
        peer_credit: Credit::default(),
        received: Credit::default(),
        delivered: Credit::default(),
        queued_credit: Credit::default(),
        sent_records: 0,
        received_records: 0,
        local_fence: None,
        peer_fence: None,
        peer_ack: None,
        ack_queued: false,
        reply: None,
    };
    let mut buffer = vec![0; l2tunnel_device::READ_BUFFER_BYTES];
    let mut tick = interval(actor.config.runtime.poll_interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut abort: Option<(Instant, AbortReply)> = None;
    let outcome = async {
        loop {
            let now = actor.micros()?;
            let mut deadline = actor
                .measured
                .as_ref()
                .and_then(|state| state.next_deadline(now))
                .map(|at| {
                    actor
                        .start
                        .checked_add(Duration::from_micros(at.0))
                        .ok_or_else(|| invalid("measured owned wake overflow"))
                })
                .transpose()?;
            if actor.measured.is_some() {
                let startup = (!actor.started)
                    .then(|| {
                        actor
                            .start
                            .checked_add(actor.config.timeouts.startup)
                            .ok_or_else(|| invalid("measured startup deadline overflow"))
                    })
                    .transpose()?;
                deadline = deadline
                    .into_iter()
                    .chain(startup)
                    .chain(actor.deadline)
                    .min();
            }
            actor.timing_enter(super::timing::Stage::Wait);
            actor.wait_service(&mut tick, deadline).await;
            actor.timing_enter(super::timing::Stage::Import);
            // Keep already completed physical facts before abort, expiry, or any
            // other terminal branch can bypass the semantic callback phase.
            actor.observe_measured_physical(false)?;
            actor.measured_deadlines(Instant::now())?;
            actor.timing_enter(super::timing::Stage::BeforeCallback);
            if let Some(at) = *quiesce.borrow() {
                actor.drain(at)?;
            }
            match control.receiver.try_recv() {
                Ok(Command::Drain(reply)) => {
                    if actor.reply.is_some() {
                        let _ = reply.send(Err("proxy drain already requested".into()));
                    } else {
                        actor.reply = Some(reply);
                        actor.drain(Instant::now())?;
                    }
                }
                Ok(Command::Abort { deadline, reply }) => {
                    abort = Some((deadline, reply));
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "proxy owner requested abort",
                    ));
                }
                Err(mpsc::error::TryRecvError::Empty) => {}
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "proxy local controller dropped",
                    ));
                }
            }
            actor.check_shutdown_deadline(Instant::now())?;
            while let Some(result) = tasks.try_join_next() {
                result.map_err(error)??;
            }
            for _ in 0..4 {
                match events.try_recv() {
                    Ok(e) => actor.event(e)?,
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) if actor.closing => break,
                    Err(_) => return Err(invalid("proxy retained tasks stopped")),
                }
            }
            actor.service_control()?;
            actor.timing_enter(super::timing::Stage::Callback);
            actor.measured_callbacks()?;
            actor.timing_enter(super::timing::Stage::UserAndNative);
            if actor.started && !actor.closing {
                if let Some(state) = &mut actor.measured {
                    state.wire_pressure = false;
                    state.receiver_pressure = false;
                }
                actor.poll_table()?;
                if actor.incoming.is_none() {
                    actor.incoming = users.try_recv().ok();
                }
                if let Some(bytes) = actor.incoming.take() {
                    actor.incoming = actor.receive_user(bytes)?;
                }
                if actor.input.is_none() && !actor.frozen {
                    match device.receive(&mut buffer) {
                        Ok(Some(n)) if n <= buffer.len() => {
                            actor.input = Some(buffer[..n].to_vec())
                        }
                        Ok(Some(_)) => {
                            return Err(invalid("proxy device violated receive capacity"));
                        }
                        Ok(None) => {}
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                        Err(e) => return Err(e),
                    }
                }
                if !actor.input_transparent
                    && let Some(bytes) = actor.input.take()
                {
                    actor.input = actor.receive_native(bytes)?;
                }
                actor.schedule_table()?;
                actor.schedule_measured()?;
                actor.send_user()?;
                actor.deliver(&mut device)?;
                actor.measured_service()?;
                // Final credit is admitted before the matching fence ACK.
                actor.service_control()?;
            }
            actor.timing_enter(super::timing::Stage::Publish);
            actor.publish(&control.status, actor.snapshot(None), false)?;
            if let Some(report) = actor.shutdown()? {
                return Ok(report);
            }
            actor.timing_enter(super::timing::Stage::Yield);
            actor.cooperate_after_turn().await;
        }
    }
    .await;
    let mut outcome = match outcome {
        Ok(report) => {
            let end = actor
                .deadline
                .ok_or_else(|| invalid("proxy close lacks original deadline"))?;
            actor.join_original(&mut tasks, end).await.map(|()| report)
        }
        Err(e) => Err(e),
    };
    if outcome.is_err() {
        #[cfg(debug_assertions)]
        if std::env::var_os("L2TUNNEL_MEASURED_TRACE").is_some()
            && let Some(state) = &actor.measured
        {
            let progress = *actor.writers[0].progress.borrow();
            eprintln!(
                "MEASURED_ACTOR_FAILURE originator={} error={:?} start={:?} handoff_cap={} writer_ready={} writer_users={} writer_capacity={} wire_records={} wire_bytes={}",
                actor.originator,
                outcome.as_ref().err(),
                actor.start,
                state.config.measured.ownership.handoff_timeout_micros,
                progress.ready,
                progress.users,
                actor.writers[0].users.capacity(),
                actor.wire.usage().1,
                actor.wire.usage().0,
            );
            if let Ok(now) = actor.micros() {
                state.ledger.trace_failure(now);
            }
            #[cfg(unix)]
            if let Some(bridge) = &actor.retirement {
                bridge.trace_measured_failure();
            }
        }
        tasks.abort_all();
        if owned_cleanup || abort.is_some() {
            // Keep the same actual children owned after an operation cap expires.
            // The service can report that expiry while continuing this cleanup;
            // it must not publish release or start a replacement before return.
            while tasks.join_next().await.is_some() {}
        } else {
            let end = actor.deadline.unwrap_or_else(Instant::now);
            let _ = timeout_at(end, async { while tasks.join_next().await.is_some() {} }).await;
        }
        // The Bridge ring retains exact facts across writer transfer, including
        // when an already expired original cleanup cap cannot await child joins.
        // Observation failure must never replace the original terminal error.
        let _ = actor.observe_measured_physical(true);
    }
    // Common EOF physical completion is not peer receipt. Keep the actual
    // Common receiver alive under the same drain cap before publishing Closed
    // or replying to the administrative waiter. TLS/default owners skip this.
    if outcome.is_ok()
        && let Some(retirement) = &actor.retirement
    {
        match retirement.wait_retired().await {
            Ok(()) => {
                if let Ok(report) = &mut outcome {
                    report.tls_lanes_closed = 0;
                }
            }
            Err(error) => outcome = Err(error),
        }
    }
    if abort
        .as_ref()
        .is_some_and(|(deadline, _)| Instant::now() >= *deadline)
    {
        outcome = Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "original proxy abort deadline",
        ));
    }
    actor.timing_finish(Instant::now());
    let mut status = actor.snapshot(
        outcome
            .as_ref()
            .err()
            .map(|e| e.to_string().chars().take(256).collect()),
    );
    if outcome.is_ok() {
        status.phase = Phase::Closed;
    }
    // Preserve the original transport/ownership error if diagnostics also fail.
    let publication = actor.publish(&control.status, status, true);
    let outcome = outcome.and_then(|report| publication.map(|()| report));
    if let Some((deadline, reply)) = abort {
        let result = if Instant::now() >= deadline {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original proxy abort deadline",
            ))
        } else {
            Ok(())
        };
        let _ = reply.send(result);
    }
    if let Some(reply) = actor.reply {
        let _ = reply.send(
            outcome
                .as_ref()
                .map(Clone::clone)
                .map_err(ToString::to_string),
        );
    }
    outcome
}

#[cfg(test)]
#[path = "actor_tests.rs"]
mod tests;
