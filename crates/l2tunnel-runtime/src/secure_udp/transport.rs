//! Native Swift transport and fixed authenticated control on one retained UDP socket.
//!
//! Device creation and privilege belong to the caller. This Unix driver owns no
//! side channel and never turns a local configuration edit into a peer switch.

use super::{control as control_owner, establish, member};
use l2tunnel::secure_record::{self as record, Class, Scope};
use l2tunnel_core as core;
use l2tunnel_cover as cover;
use l2tunnel_device::{PacketDevice, PacketLayer, READ_BUFFER_BYTES};
use l2tunnel_management::{
    self as mg, control_streams as streams, delivery, session_control as control, transaction,
};
use l2tunnel_recovery as recovery;
use l2tunnel_security as security;
use l2tunnel_swift::{self as swift, policy, records};
use ring::digest;
use std::{future::Future, io, os::fd::AsRawFd, time::Duration};
use tokio::{
    io::{Interest, unix::AsyncFd},
    sync::{mpsc, oneshot},
    time::{Instant, sleep_until},
};

const SCALE: u128 = 1_000_000;
const MAX_QUEUE: usize = 16 * 1024 * 1024;
const LANE: u32 = 0;

#[path = "transport_performance.rs"]
mod performance;

#[path = "transport_native.rs"]
mod native_storage;
pub use performance::Performance;

/// Immutable authenticated full-wire bucket, including control and feedback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WireBudget {
    /// Complete IP bytes retained as burst credit; no separate hidden data rate.
    pub burst_bytes: usize,
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod tests;

/// Run one complete authenticated native session on the original connected socket.
///
/// The caller retains the immutable configuration that produced
/// `expected_configuration`. The observer must be nonblocking. No child I/O task,
/// fallback transport, implicit device setup or peer-confirmed close is created.
#[allow(clippy::too_many_arguments)] // Frozen ownership boundary keeps each resource explicit.
pub async fn run<D>(
    device: D,
    parts: member::Parts,
    expected_configuration: security::ConfigDigest,
    config: Config,
    requests: Option<ControlRequests>,
    resolve: Resolver,
    shutdown: impl Future<Output = ()> + Send,
    observe: impl FnMut(&Snapshot) + Send,
) -> io::Result<Stopped>
where
    D: PacketDevice<Error = io::Error> + AsRawFd + Send,
{
    run_clock(
        device,
        parts,
        expected_configuration,
        config,
        requests,
        resolve,
        shutdown,
        observe,
        Instant::now,
    )
    .await
}

#[allow(clippy::too_many_arguments)] // Private clock seam exercises the production loop.
async fn run_clock<D>(
    device: D,
    parts: member::Parts,
    expected_configuration: security::ConfigDigest,
    config: Config,
    mut requests: Option<ControlRequests>,
    resolve: Resolver,
    shutdown: impl Future<Output = ()> + Send,
    mut observe: impl FnMut(&Snapshot) + Send,
    mut sample: impl FnMut() -> Instant + Send,
) -> io::Result<Stopped>
where
    D: PacketDevice<Error = io::Error> + AsRawFd + Send,
{
    let layer = match config.send.records.layer {
        records::Layer::Ethernet => PacketLayer::Ethernet,
        records::Layer::Ip => PacketLayer::Ip,
    };
    if device.layer() != layer {
        return Err(invalid(
            "authenticated native layer differs from actual device",
        ));
    }
    let setup_deadline = parts.deadline;
    let origin = sample();
    let (socket, mut driver) = Driver::new(parts, expected_configuration, config, origin)?;
    let mut device = AsyncFd::with_interest(device, Interest::READABLE.add(Interest::WRITABLE))?;
    let ready = sample();
    if ready >= setup_deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "original setup deadline before native readiness",
        ));
    }
    let mut native = vec![0; READ_BUFFER_BYTES];
    let mut datagram = vec![0; driver.cover.limits().max_packet_bytes + 1];
    tokio::pin!(shutdown);
    observe(&driver.snapshot(clock(origin, ready)?, true));
    let mut native_first = true;
    let result:io::Result<StopReason>=async {
        loop {
            let instant=sample();let now=clock(origin,instant)?;
            driver.performance.counters.loop_turns=driver.performance.counters.loop_turns.saturating_add(1);
            if !driver.check_expiry(now)? {break Ok(driver.terminal.ok_or_else(||protocol("terminal expiry missing"))?);}
            driver.collect_native(now)?;
            driver.progress(now)?;
            if let Some(reason)=driver.terminal {break Ok(reason);}
            driver.service_control(now,&resolve)?;
            driver.submit_control(now)?;
            driver.send(&socket,now,instant)?;
            let native_before=driver.performance.counters.native_write_batch_packets;
            let native_spent=driver.flush_native_ready(&mut device,||clock(origin,sample())).await?;
            let native_write_remaining=driver.config.work.native_write_batch.saturating_sub(native_spent);
            if let Some(reason)=driver.terminal {break Ok(reason);}
            if driver.next_report.is_some_and(|at|now>=at) {
                let reported=clock(origin,sample())?;
                observe(&driver.snapshot(reported,true));
                driver.next_report=driver.config.report_interval.map(|interval|add(reported,interval)).transpose()?;
            }
            let read_native=driver.coordinator.admission_allowed() && driver.swift.has_room();
            let write_native=!driver.native.is_empty();
            let interest=if read_native && write_native {Interest::READABLE.add(Interest::WRITABLE)}else if write_native {Interest::WRITABLE}else{Interest::READABLE};
            let mut wake=driver.wake(now)?;
            if native_spent>0 || (driver.swift.deliverable() && driver.native_room()) {wake=wake.min(sample());}
            tokio::select! {
                biased;
                ()=&mut shutdown=>break Ok(StopReason::Cancelled),
                request=next_request(&mut requests),if requests.is_some()=>{
                    driver.performance.counters.request_events=driver.performance.counters.request_events.saturating_add(1);
                    match request {Some((requested,reply))=>driver.request(clock(origin,sample())?,requested,reply,&resolve)?,None=>requests=None}
                },
                event=next_io(&socket,&mut device,interest,read_native || write_native,driver.ingress.left>0,wake,native_first)=>match event? {
                IoEvent::Udp=>{
                    native_first=true;
                    driver.performance.counters.udp_ready_events=driver.performance.counters.udp_ready_events.saturating_add(1);
                    let maximum=driver.config.work.receive_packets.min(driver.ingress.left);
                    let mut batch=0u64;
                    for _ in 0..maximum {
                        if !driver.check_expiry(clock(origin,sample())?)? {break;}
                        driver.ingress.left-=1;
                        match socket.try_recv(&mut datagram) {
                            Ok(length)=>{
                                batch+=1;
                                driver.performance.counters.udp_batch_packets=driver.performance.counters.udp_batch_packets.saturating_add(1);
                                if batch==u64::from(maximum) {driver.performance.counters.udp_batch_limit_hits=driver.performance.counters.udp_batch_limit_hits.saturating_add(1);}
                                let at=sample();let time=clock(origin,at)?;
                                if !driver.check_expiry(time)? {break;}
                                if length>driver.cover.limits().max_packet_bytes {driver.counters.received_packets=driver.counters.received_packets.saturating_add(1);driver.counters.rejected_packets=driver.counters.rejected_packets.saturating_add(1);}else{driver.receive(&datagram[..length],time,at,&resolve)?;}
                            },
                            Err(error) if error.kind()==io::ErrorKind::WouldBlock=>break,
                            Err(error) if establish::path_loss(&error)=>{driver.counters.socket_receive_errors=driver.counters.socket_receive_errors.saturating_add(1);break;},
                            Err(error)=>return Err(error),
                        }
                    }
                },
                IoEvent::Native(mut ready)=>{
                    native_first=false;
                    driver.performance.counters.native_ready_events=driver.performance.counters.native_ready_events.saturating_add(1);
                    if ready.ready().is_writable() && write_native && native_write_remaining>0 {
                        for _ in 0..native_write_remaining {
                            let step=driver.write_native(&mut ready,||clock(origin,sample()));
                            if driver.performance.counters.native_write_batch_packets.saturating_sub(native_before)==driver.config.work.native_write_batch as u64 {driver.performance.counters.native_write_batch_limit_hits=driver.performance.counters.native_write_batch_limit_hits.saturating_add(1);}
                            if !step? {break;}
                        }
                    }
                    if ready.ready().is_readable() && read_native {
                        let mut batch=0u64;
                        for _ in 0..driver.config.work.native_read_batch {
                            let before=driver.performance.counters.native_read_batch_packets;
                            let step=driver.read_native(&mut ready,&mut native,||clock(origin,sample()));
                            batch+=driver.performance.counters.native_read_batch_packets.saturating_sub(before);
                            if batch==driver.config.work.native_read_batch as u64 {driver.performance.counters.native_read_batch_limit_hits=driver.performance.counters.native_read_batch_limit_hits.saturating_add(1);}
                            if !step? {break;}
                        }
                    }
                },
                IoEvent::Timer=>{driver.performance.counters.timer_events=driver.performance.counters.timer_events.saturating_add(1);},
                },
            }
        }
    }.await;
    let now = clock(origin, sample()).unwrap_or(u64::MAX);
    let reason = match &result {
        Ok(reason) => *reason,
        Err(error) => driver.terminal.unwrap_or(
            if error.get_ref().is_some_and(|cause| cause.is::<Exhausted>()) {
                StopReason::CounterExhausted
            } else if error.kind() == io::ErrorKind::InvalidData {
                StopReason::Protocol
            } else {
                StopReason::Io(error.kind())
            },
        ),
    };
    driver.terminal = Some(reason);
    if let Some(reply) = driver.waiting.take() {
        let _ = reply.send(Err(SwitchError::Closed));
    }
    let snapshot = driver.snapshot(now, false);
    observe(&snapshot);
    result.map(|reason| Stopped { reason, snapshot })
}

enum IoEvent<'a, D: AsRawFd> {
    Udp,
    Native(tokio::io::unix::AsyncFdReadyMutGuard<'a, D>),
    Timer,
}

// The caller polls shutdown and control first. Alternate ready I/O priorities so
// elapsed receive work cannot renew UDP's quota ahead of every native read.
async fn next_io<'a, D: AsRawFd>(
    socket: &tokio::net::UdpSocket,
    device: &'a mut AsyncFd<D>,
    interest: Interest,
    native: bool,
    udp: bool,
    wake: Instant,
    native_first: bool,
) -> io::Result<IoEvent<'a, D>> {
    if native_first {
        tokio::select! {
            biased;
            ready = device.ready_mut(interest), if native => ready.map(IoEvent::Native),
            ready = socket.readable(), if udp => ready.map(|()| IoEvent::Udp),
            () = sleep_until(wake) => Ok(IoEvent::Timer),
        }
    } else {
        tokio::select! {
            biased;
            ready = socket.readable(), if udp => ready.map(|()| IoEvent::Udp),
            ready = device.ready_mut(interest), if native => ready.map(IoEvent::Native),
            () = sleep_until(wake) => Ok(IoEvent::Timer),
        }
    }
}

async fn next_request(
    requests: &mut Option<ControlRequests>,
) -> Option<(swift::control::Policy, Reply)> {
    match requests {
        Some(requests) => requests.0.recv().await,
        None => std::future::pending().await,
    }
}

fn try_native_write<D: PacketDevice<Error = io::Error> + AsRawFd>(
    ready: &mut tokio::io::unix::AsyncFdReadyMutGuard<'_, D>,
    packet: &[u8],
) -> io::Result<bool> {
    match ready.get_inner_mut().transmit(packet) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            ready.clear_ready_matching(tokio::io::Ready::WRITABLE);
            Ok(false)
        }
        Err(error) => Err(error),
    }
}
fn try_native_read<D: PacketDevice<Error = io::Error> + AsRawFd>(
    ready: &mut tokio::io::unix::AsyncFdReadyMutGuard<'_, D>,
    output: &mut [u8],
) -> io::Result<Option<usize>> {
    match ready.get_inner_mut().receive(output) {
        Ok(Some(bytes)) => Ok(Some(bytes)),
        Ok(None) => {
            ready.clear_ready_matching(tokio::io::Ready::READABLE);
            Ok(None)
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            ready.clear_ready_matching(tokio::io::Ready::READABLE);
            Ok(None)
        }
        Err(error) => Err(error),
    }
}
/// Finite work admitted before another event/timer/cancellation turn.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkBudget {
    /// Positive receive-work refill period, at most one second.
    pub receive_interval: Duration,
    /// Received datagrams/errors admitted per refill, within 1..=4096.
    pub receive_packets: u32,
    /// Maximum complete send attempts in one turn, within 1..=4096.
    pub send_batch: usize,
    /// Maximum native reads per turn, within 1..=4096.
    pub native_read_batch: usize,
    /// Maximum native writes per turn, within 1..=4096.
    pub native_write_batch: usize,
}
/// Native output ownership, independent of Swift recovery retention.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeBudget {
    /// Complete pending native packets, within 1..=1024.
    pub pending_packets: usize,
    /// Complete pending native bytes, at most 16 MiB and at least one native MTU.
    pub pending_bytes: usize,
    /// One original deadline for the oldest blocked native output.
    pub stall_timeout: Duration,
}
/// Established lifetime, separate from setup, tails and policy transactions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Lifetime {
    /// Explicit positive common-control/session lease; never renewed by traffic.
    pub lease: Duration,
    /// Delay between completed authenticated round-trip challenges.
    pub ping_interval: Duration,
    /// Original total bound for one queued challenge, including local congestion.
    pub pong_timeout: Duration,
}
/// Immutable generic transaction and combined retained-storage contract.
/// This value is explicitly authenticated by the client plan; it does not select
/// the backend or reserve engines/native/control storage by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionSettings {
    /// Generic retry, phase and uncertainty timing, in injected milliseconds.
    pub protocol: transaction::Settings,
    /// Maximum original operation duration, never renewed by retries or phases.
    pub max_operation_ms: u64,
    /// Combined current/prepared/draining engines and associated custody ceiling.
    pub retained_bytes: usize,
}
impl TransactionSettings {
    /// Check the exact authenticated limits against an actual runtime template.
    pub fn validate(self, runtime: Config) -> io::Result<()> {
        self.protocol.validate().map_err(invalid)?;
        if self.max_operation_ms == 0
            || u128::from(self.max_operation_ms) > runtime.lifetime.lease.as_millis()
            || self.retained_bytes == 0
        {
            return Err(invalid("transaction lifetime or retained-storage contract"));
        }
        u64::try_from(self.retained_bytes).map_err(invalid)?;
        Ok(())
    }
}

/// Immutable local half of the parent's globally ordered authenticated contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Complete admitted IP datagram ceiling; no automatic geometry shrinking.
    pub path_mtu: usize,
    /// Full outgoing Swift record/rate policy.
    pub send: policy::Direction,
    /// Full incoming Swift record/rate policy.
    pub receive: policy::Direction,
    /// Original policy transaction and bounded output ledger settings.
    pub policy: policy::Settings,
    /// Common AEAD body/key-generation ceilings.
    pub security: security::Limits,
    /// Fixed reliable control retention, retry and wire service bounds.
    pub control: delivery::Settings,
    /// Explicit authenticated independent-stream selection; None preserves the
    /// legacy control bytes and global envelope sequence without fallback.
    pub streams: Option<control_owner::Settings>,
    /// Immutable nonzero common control scope epoch.
    pub control_epoch: security::Epoch,
    /// Nonzero base common data epoch; logical policy epochs are added to it.
    pub data_epoch: security::Epoch,
    /// Shared complete-wire burst bound.
    pub wire: WireBudget,
    /// Socket/native work bounds.
    pub work: WorkBudget,
    /// Independent retained native output bounds.
    pub native: NativeBudget,
    /// Explicit active lease and authenticated round-trip timers.
    pub lifetime: Lifetime,
    /// Local coalesced reporting cadence; excluded from peer configuration bytes.
    pub report_interval: Option<Duration>,
}
impl Config {
    /// Validate finite scalar/algorithm bounds without network, keys or clocks.
    pub fn validate(&self) -> io::Result<()> {
        self.send.validate().map_err(invalid)?;
        self.receive.validate().map_err(invalid)?;
        if !(256..=65_535).contains(&self.path_mtu)
            || self.send.records.layer != self.receive.records.layer
            || self.send.records.max_native != self.receive.records.max_native
            || !(1..=65_535).contains(&self.send.records.max_native)
            || self.send.records.codec.datagram_bytes
                < swift::FEEDBACK_HEADER + 2 * swift::MAX_REQUESTS
            || self.receive.records.codec.datagram_bytes
                < swift::FEEDBACK_HEADER + 2 * swift::MAX_REQUESTS
            || self.control_epoch.0 == 0
            || self.data_epoch.0 == 0
            || self.policy.transaction_micros == 0
            || !(1..=64).contains(&self.policy.max_outbound)
            || !(1..=1024).contains(&self.native.pending_packets)
            || !(self.send.records.max_native..=MAX_QUEUE).contains(&self.native.pending_bytes)
            || self.native.stall_timeout.is_zero()
            || self.work.receive_interval.is_zero()
            || self.work.receive_interval > Duration::from_secs(1)
            || !(1..=4096).contains(&self.work.receive_packets)
            || [
                self.work.send_batch,
                self.work.native_read_batch,
                self.work.native_write_batch,
            ]
            .iter()
            .any(|value| !(1..=4096).contains(value))
            || self.wire.burst_bytes > MAX_QUEUE
            || self.lifetime.lease.is_zero()
            || self.lifetime.ping_interval.is_zero()
            || self.lifetime.pong_timeout.is_zero()
            || self.report_interval.is_some_and(|value| value.is_zero())
            || !(1..=security::MAX_BODY_BYTES).contains(&self.security.max_body_bytes)
            || !(1..=security::MAX_PACKETS_PER_KEY).contains(&self.security.packets_per_key)
            || !(1..=security::MAX_BODY_BYTES_PER_KEY)
                .contains(&self.security.max_body_bytes_per_key)
            || self.security.max_body_bytes as u64 > self.security.max_body_bytes_per_key
            || self.control.recovery.max_source_bytes < control::HEADER_BYTES + mg::HEADER_LEN
        {
            return Err(invalid("secure UDP transport resource/format bounds"));
        }
        for direction in [self.send, self.receive] {
            if direction.records.codec.datagram_bytes > self.security.max_body_bytes {
                return Err(invalid("Swift exceeds declared common body ceiling"));
            }
            direction
                .records
                .channels
                .checked_mul(direction.records.codec.flow_sources)
                .and_then(|count| count.checked_mul(direction.records.codec.datagram_bytes))
                .ok_or_else(|| invalid("Swift aggregate retention overflow"))?;
        }
        let maximum = self
            .control
            .recovery
            .max_source_bytes
            .checked_add(recovery::DATA_HEADER_BYTES + self.control_wrapper_bytes())
            .ok_or_else(|| invalid("control source size overflow"))?;
        if maximum > self.security.max_body_bytes {
            return Err(invalid("control exceeds declared common body ceiling"));
        }
        for duration in [
            self.lifetime.lease,
            self.lifetime.ping_interval,
            self.lifetime.pong_timeout,
            self.native.stall_timeout,
        ] {
            u64::try_from(duration.as_micros()).map_err(invalid)?;
        }
        if [
            self.lifetime.lease,
            self.lifetime.ping_interval,
            self.lifetime.pong_timeout,
            self.native.stall_timeout,
            self.work.receive_interval,
        ]
        .into_iter()
        .chain(self.report_interval)
        .any(|value| value.as_micros() == 0)
        {
            return Err(invalid(
                "runtime timers require at least one effective microsecond",
            ));
        }
        // Reuse maintained recovery/service validation without reserving crypto owners.
        delivery::Service::new(
            self.control,
            delivery::Binding {
                session: mg::SessionId([1; 16]),
                lane: mg::LaneId(LANE),
                local_role: mg::Role::Client,
                control_epoch: self.control_epoch.0,
            },
            Duration::ZERO,
            self.lifetime.lease,
        )
        .map_err(invalid)?;
        if let Some(settings) = self.streams {
            settings.validate(self.control, self.path_mtu, self.lifetime.lease)?;
            for stream in streams::Stream::ALL {
                streams::delivery_binding(
                    delivery::Binding {
                        session: mg::SessionId([1; 16]),
                        lane: mg::LaneId(LANE),
                        local_role: mg::Role::Client,
                        control_epoch: self.control_epoch.0,
                    },
                    stream,
                )
                .map_err(invalid)?;
            }
        }
        Ok(())
    }
    /// Validate actual selected cover and family against full admitted wire limits.
    pub fn validate_cover(&self, selected: cover::Config, ipv6: bool) -> io::Result<()> {
        self.validate()?;
        let ip = if ipv6 { 48 } else { 28 };
        let protected = self
            .security
            .max_body_bytes
            .checked_add(
                record::ROUTE_BYTES + security::Protection::ChaCha20Poly1305.overhead_bytes(),
            )
            .ok_or_else(|| invalid("common packet size overflow"))?;
        let overhead = selected
            .overhead(cover::Phase::Established, protected)
            .map_err(invalid)?;
        let packet = protected
            .checked_add(overhead)
            .ok_or_else(|| invalid("cover size overflow"))?;
        if packet > selected.limits().max_packet_bytes {
            return Err(invalid(
                "common packet exceeds admitted cover/storage ceiling",
            ));
        }
        let fixed = ip
            + record::ROUTE_BYTES
            + security::Protection::ChaCha20Poly1305.overhead_bytes()
            + overhead;
        let current = self
            .send
            .records
            .codec
            .datagram_bytes
            .max(self.receive.records.codec.datagram_bytes)
            .max(
                self.control.recovery.max_source_bytes
                    + recovery::DATA_HEADER_BYTES
                    + self.control_wrapper_bytes(),
            );
        if current
            .checked_add(fixed)
            .is_none_or(|bytes| bytes > self.path_mtu)
        {
            return Err(invalid("current records exceed explicit active path MTU"));
        }
        let reserve = self
            .control
            .recovery
            .max_source_bytes
            .checked_add(recovery::DATA_HEADER_BYTES + recovery::ACK_PACKET_BYTES)
            .and_then(|bytes| bytes.checked_add(2 * (fixed + self.control_wrapper_bytes())))
            .ok_or_else(|| invalid("control reserve overflow"))?;
        if self.control.wire_overhead != fixed
            || self
                .path_mtu
                .checked_add(reserve)
                .is_none_or(|required| required > self.wire.burst_bytes)
        {
            return Err(invalid(
                "exact control overhead/shared reserve/burst geometry",
            ));
        }
        Ok(())
    }
    /// Canonical local contract; the parent combines both roles in global order.
    pub fn canonical_digest(&self) -> io::Result<core::ConfigDigest> {
        self.contract_digest(false)
    }
    /// Fixed runtime inventory independent of explicitly mutable data policy.
    /// Native layer/packet limits remain bound. The caller must also bind the
    /// actual carrier, trust, catalog and preparation resources in its envelope.
    /// This local digest alone is not authenticated peer or staging authority.
    pub fn immutable_contract_digest(&self) -> io::Result<core::ConfigDigest> {
        self.contract_digest(true)
    }
    fn contract_digest(&self, normalized: bool) -> io::Result<core::ConfigDigest> {
        self.validate()?;
        let mut hash = digest::Context::new(&digest::SHA256);
        let domain: &[u8] = match (normalized, self.streams.is_some()) {
            (false, false) => b"l2tunnel/secure-udp-native-contract/v1\0",
            (false, true) => b"l2tunnel/secure-udp-native-contract/streamed-v1\0",
            (true, false) => b"l2tunnel/secure-udp-native-envelope/v1\0",
            (true, true) => b"l2tunnel/secure-udp-native-envelope/streamed-v1\0",
        };
        hash.update(domain);
        let mut number = |value: u64| hash.update(&value.to_be_bytes());
        for direction in [self.send, self.receive] {
            let r = direction.records;
            let c = r.codec;
            // One inventory preserves legacy bytes and explicitly classifies
            // every field for the separate fixed-envelope digest.
            for (value, mutable) in [
                (r.channels as u64, true),
                (
                    if r.layer == records::Layer::Ethernet {
                        1
                    } else {
                        2
                    },
                    false,
                ),
                (r.max_native as u64, false),
                (direction.bytes_per_second, true),
                (c.datagram_bytes as u64, true),
                (c.window as u64, true),
                (u64::from(c.repair_numerator), true),
                (u64::from(c.repair_denominator), true),
                (c.flow_sources as u64, true),
                (c.queue_bytes as u64, true),
                (c.max_packet as u64, false),
                (c.flush_micros, true),
                (c.feedback_micros, true),
                (c.tail_micros, true),
                (c.min_rto_micros, true),
                (c.max_rto_micros, true),
            ] {
                number(if normalized && mutable { 0 } else { value });
            }
        }
        let a = self.control.recovery;
        for value in [
            if normalized { 0 } else { self.path_mtu as u64 },
            self.policy.transaction_micros,
            self.policy.max_outbound as u64,
            self.security.max_body_bytes as u64,
            self.security.packets_per_key,
            self.security.max_body_bytes_per_key,
            self.control_epoch.0,
            self.data_epoch.0,
            self.wire.burst_bytes as u64,
            self.work.receive_packets as u64,
            self.work.send_batch as u64,
            self.work.native_read_batch as u64,
            self.work.native_write_batch as u64,
            self.native.pending_packets as u64,
            self.native.pending_bytes as u64,
            a.max_source_bytes as u64,
            a.send_bytes as u64,
            a.receive_bytes as u64,
            a.send_records as u64,
            a.receive_records as u64,
            a.max_retries as u64,
            self.control.packets_per_interval as u64,
            self.control.bytes_per_interval as u64,
            self.control.wire_overhead as u64,
        ] {
            number(value);
        }
        for duration in [
            self.work.receive_interval,
            self.native.stall_timeout,
            self.lifetime.lease,
            self.lifetime.ping_interval,
            self.lifetime.pong_timeout,
            self.control.interval,
            a.initial_rto,
            a.maximum_rto,
            a.ack_delay,
        ] {
            number(duration.as_secs());
            number(u64::from(duration.subsec_nanos()));
        }
        if let Some(settings) = self.streams {
            number(u64::from(streams::VERSION));
            number(streams::HEADER_BYTES as u64);
            for (stream, entry) in streams::Stream::ALL.into_iter().zip(settings.streams) {
                number(stream as u64);
                let binding = streams::delivery_binding(
                    delivery::Binding {
                        session: mg::SessionId([1; 16]),
                        lane: mg::LaneId(LANE),
                        local_role: mg::Role::Client,
                        control_epoch: self.control_epoch.0,
                    },
                    stream,
                )
                .map_err(invalid)?;
                number(binding.control_epoch);
                // Delivery fields equal the already hashed global base except
                // this exact wrapper charge; validate rejects any divergence.
                for value in [
                    entry.delivery.wire_overhead as u64,
                    if normalized { 0 } else { entry.path_mtu as u64 },
                    entry.max_message_bytes as u64,
                    entry.max_outbound_messages as u64,
                    entry.max_outbound_bytes as u64,
                    u64::from(entry.max_fragments),
                    entry.max_reassembly_bytes as u64,
                    entry.max_incomplete_messages as u64,
                    entry.work_per_call as u64,
                    entry.message_lifetime.as_secs(),
                    u64::from(entry.message_lifetime.subsec_nanos()),
                ] {
                    number(value);
                }
            }
        }
        let mut bytes = [0; 32];
        bytes.copy_from_slice(hash.finish().as_ref());
        Ok(core::ConfigDigest(bytes))
    }
    fn control_wrapper_bytes(&self) -> usize {
        if self.streams.is_some() {
            streams::HEADER_BYTES
        } else {
            0
        }
    }
}

/// Bounded terminal category; no peer-provided error text is retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopReason {
    /// Explicit local cancellation; no peer-confirmed close is claimed.
    Cancelled,
    /// Original established lease ended.
    LeaseExpired,
    /// Original authenticated challenge deadline ended.
    PeerTimeout,
    /// Oldest retained native packet could not be written before its bound.
    NativeStall,
    /// Original distributed policy transaction deadline ended.
    PolicyTimeout,
    /// Authenticated protocol/state mismatch.
    Protocol,
    /// A checked sequence/key/clock space was exhausted.
    CounterExhausted,
    /// Native I/O failed with this bounded local category.
    Io(io::ErrorKind),
}
/// Complete-wire, authority and native observations; never protocol authority.
#[derive(Clone, Copy, Debug, Default)]
pub struct Counters {
    /// Admitted full-wire attempts.
    pub wire_packets: u64,
    /// Charged IP bytes including failed attempts.
    pub wire_bytes: u64,
    /// Datagrams accepted by the native UDP socket.
    pub socket_accepted_packets: u64,
    /// IP bytes accepted by the socket, not measured physical transmission.
    pub socket_accepted_ip_bytes: u64,
    /// Transient native UDP send failures.
    pub socket_drops: u64,
    /// Charged transient receive failures.
    pub socket_receive_errors: u64,
    /// Complete received datagrams examined.
    pub received_packets: u64,
    /// Unauthenticated, unregistered or intentionally obsolete input.
    pub rejected_packets: u64,
    /// Authenticated security replay rejections.
    pub replay_rejections: u64,
    /// Native packets admitted to Swift.
    pub native_read: u64,
    /// Complete native packets accepted by the device.
    pub native_written: u64,
    /// Complete native reads outside the configured size.
    pub native_oversize: u64,
    /// User sources/repairs withheld before Swift admission under native pressure.
    pub native_backpressure_drops: u64,
    /// Complete retained native packets.
    pub native_pending_packets: usize,
    /// Exact retained native bytes.
    pub native_pending_bytes: usize,
    /// Actual requested native-pool heap layouts, including all empty buffers.
    /// Excludes allocator overhead, inline owners, RSS and kernel storage.
    pub native_storage_capacity_bytes: usize,
    /// Last actual User sealing identity.
    pub user_number: Option<security::PacketNumber>,
    /// Last actual Control sealing identity.
    pub control_number: Option<security::PacketNumber>,
    /// Actual outgoing User key generation.
    pub user_generation: Option<security::KeyGeneration>,
    /// Actual outgoing Control key generation.
    pub control_generation: Option<security::KeyGeneration>,
}
/// Authenticated round-trip observations, with one unchanged challenge deadline.
#[derive(Clone, Copy, Debug, Default)]
pub struct Liveness {
    /// The one outstanding challenge, if any.
    pub outstanding: Option<u64>,
    /// Original challenge deadline in driver microseconds.
    pub deadline_micros: Option<u64>,
    /// Last fresh common protected record, excluding replay/cache input.
    pub last_verified_micros: Option<u64>,
    /// Last new correctly matching authenticated Pong.
    pub last_pong_micros: Option<u64>,
}
/// Coalesced actual running/terminal state, without keys or native handles.
#[derive(Clone, Debug)]
pub struct Snapshot {
    /// True only after complete native runtime attachment.
    pub running: bool,
    /// Time since the one driver origin.
    pub elapsed_micros: u64,
    /// Actual completed membership and original endpoints.
    pub info: member::Info,
    /// Actual full authenticated configuration digest.
    pub configuration: security::ConfigDigest,
    /// Selected independent Liveness/SwiftPolicyV1 framing. Generic Management
    /// and DataFeedback remain unsupported by this Swift runtime. This runtime
    /// observation does not upgrade the legacy local API schema.
    pub control_streams: bool,
    /// Original policy deadline retained through final message custody.
    pub policy_deadline_micros: Option<u64>,
    /// A policy source or applied incoming command still awaits custody release.
    pub policy_receipt_pending: bool,
    /// Current outgoing records/rate.
    pub send: policy::Direction,
    /// Current incoming records/rate.
    pub receive: policy::Direction,
    /// Completed local distributed policy observation.
    pub committed: policy::Committed,
    /// The original active transaction, if any.
    pub pending: Option<policy::Pending>,
    /// Full Swift/header observations across resets.
    pub swift: records::Stats,
    /// Current unconfirmed recovery source count.
    pub swift_unconfirmed: usize,
    /// Bounded per-channel observations, without changing protocol state.
    pub channels: Vec<records::ChannelStats>,
    /// Actual scheduling, wire-credit and native-pressure observations.
    pub performance: Performance,
    /// Fixed reliable control retention.
    pub control: recovery::Retained,
    /// Wire, security and native counters.
    pub counters: Counters,
    /// Fixed-control challenge observations.
    pub liveness: Liveness,
    /// Explicit terminal category, absent while running.
    pub terminal: Option<StopReason>,
}
/// Explicit local stop; not a peer-confirmed clean shutdown.
#[derive(Clone, Debug)]
pub struct Stopped {
    /// Original local termination reason.
    pub reason: StopReason,
    /// Final bounded observation.
    pub snapshot: Snapshot,
}
/// Local policy request failure; teardown cannot imply rollback.
pub use crate::swift::SwitchError;
type Reply = oneshot::Sender<Result<u64, SwitchError>>;
/// Shared bounded policy request producer; dropping a waiter never cancels it.
#[derive(Clone)]
pub struct ControlHandle(mpsc::Sender<(swift::control::Policy, Reply)>);
/// Unique bounded local request owner for the driver.
pub struct ControlRequests(mpsc::Receiver<(swift::control::Policy, Reply)>);
/// Allocate exactly one queued policy request.
pub fn channel() -> (ControlHandle, ControlRequests) {
    let (tx, rx) = mpsc::channel(1);
    (ControlHandle(tx), ControlRequests(rx))
}
impl ControlHandle {
    /// Wait for actual peer-coordinated completion, not local configuration change.
    pub async fn switch(&self, requested: swift::control::Policy) -> Result<u64, SwitchError> {
        let (tx, rx) = oneshot::channel();
        self.0
            .try_send((requested, tx))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => SwitchError::Busy,
                mpsc::error::TrySendError::Closed(_) => SwitchError::Closed,
            })?;
        rx.await.unwrap_or(Err(SwitchError::Closed))
    }
}
/// Trusted deterministic policy resolution; every result is revalidated at use.
pub type Resolver = Box<dyn Fn(&swift::control::Policy) -> Option<policy::Resolved> + Send + Sync>;

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}
fn protocol(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
fn envelope_scope(scope: Scope) -> control::Scope {
    control::Scope {
        epoch: core::Epoch(scope.epoch.0),
        digest: core::ConfigDigest(scope.configuration.0),
    }
}
fn policy_reply(outcome: policy::Outcome) -> Result<u64, SwitchError> {
    match outcome {
        policy::Outcome::Applied(epoch) => Ok(epoch.0),
        policy::Outcome::Rejected => Err(SwitchError::Rejected),
    }
}
#[derive(Debug)]
struct Exhausted;
impl std::fmt::Display for Exhausted {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("checked session counter space exhausted")
    }
}
impl std::error::Error for Exhausted {}
fn exhausted() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, Exhausted)
}
fn record_error(error: record::Error) -> io::Error {
    match error {
        record::Error::Security(
            security::Error::CounterExhausted | security::Error::KeyUsageExhausted,
        ) => exhausted(),
        _ => protocol(error),
    }
}
fn native_record_error(error: records::Error) -> io::Error {
    match error {
        records::Error::CounterExhausted => exhausted(),
        _ => protocol(error),
    }
}
fn clock(origin: Instant, now: Instant) -> io::Result<u64> {
    u64::try_from(
        now.checked_duration_since(origin)
            .ok_or_else(|| protocol("driver time regression"))?
            .as_micros(),
    )
    .map_err(invalid)
}
fn duration(value: u64) -> Duration {
    Duration::from_micros(value)
}
fn add(now: u64, after: Duration) -> io::Result<u64> {
    now.checked_add(u64::try_from(after.as_micros()).map_err(invalid)?)
        .ok_or_else(exhausted)
}
fn meta(number: u32, phase: cover::Phase) -> cover::PacketMeta {
    cover::PacketMeta {
        phase,
        packet_number: cover::PacketNumber(number),
        media_timestamp: cover::MediaTimestamp(number),
    }
}

struct Bucket {
    rate: u64,
    burst: usize,
    tokens: u128,
    last: u64,
    generated: u128,
    discarded: u128,
}
impl Bucket {
    fn new(rate: u64, burst: usize) -> Self {
        Self {
            rate,
            burst,
            tokens: burst as u128 * SCALE,
            last: 0,
            generated: 0,
            discarded: 0,
        }
    }
    fn refill(&mut self, now: u64) -> io::Result<()> {
        let elapsed = now
            .checked_sub(self.last)
            .ok_or_else(|| protocol("wire clock regression"))?;
        let generated = u128::from(self.rate) * u128::from(elapsed);
        let available = self.tokens.saturating_add(generated);
        let cap = self.burst as u128 * SCALE;
        self.generated = self.generated.saturating_add(generated);
        self.discarded = self.discarded.saturating_add(available.saturating_sub(cap));
        self.tokens = available.min(cap);
        self.last = now;
        Ok(())
    }
    fn allowance(&self) -> usize {
        (self.tokens / SCALE) as usize
    }
    fn charge(&mut self, bytes: usize) -> io::Result<()> {
        self.tokens = self
            .tokens
            .checked_sub(bytes as u128 * SCALE)
            .ok_or_else(|| protocol("wire allowance was not reserved"))?;
        Ok(())
    }
    fn ready_at(&self, bytes: usize) -> io::Result<u64> {
        if bytes > self.burst {
            return Err(invalid("packet exceeds wire burst"));
        }
        let missing = (bytes as u128 * SCALE).saturating_sub(self.tokens);
        self.last
            .checked_add(u64::try_from(missing.div_ceil(u128::from(self.rate))).map_err(invalid)?)
            .ok_or_else(|| protocol("wire wake overflow"))
    }
}

struct IngressBudget {
    left: u32,
    refill: u64,
}
/// Original authenticated User generation, independent of any native flow hash.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NativeOrigin {
    binding: security::SessionBinding,
    lane: security::LaneId,
    direction: security::Direction,
    scope: Scope,
}
impl NativeOrigin {
    fn new(info: &member::Info, scope: Scope, half: records::Direction) -> Self {
        let direction = match (info.role, half) {
            (security::Role::Initiator, records::Direction::Send)
            | (security::Role::Responder, records::Direction::Receive) => {
                security::Direction::InitiatorToResponder
            }
            (security::Role::Responder, records::Direction::Send)
            | (security::Role::Initiator, records::Direction::Receive) => {
                security::Direction::ResponderToInitiator
            }
        };
        Self {
            binding: info.binding,
            lane: security::LaneId(LANE),
            direction,
            scope,
        }
    }
}

/// Local native count witness, never proof of a peer's physical completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NativeBoundary {
    origin: NativeOrigin,
    direction: records::Direction,
    channels: usize,
    counts: [u64; swift::MAX_CHANNELS],
}
impl NativeBoundary {
    fn capture(
        engine: &records::Engine,
        origin: NativeOrigin,
        direction: records::Direction,
    ) -> io::Result<Self> {
        let channels = match direction {
            records::Direction::Send => engine.send_config().channels,
            records::Direction::Receive => engine.receive_config().channels,
        };
        if !(1..=swift::MAX_CHANNELS).contains(&channels) {
            return Err(protocol("native boundary channel width"));
        }
        let mut counts = [0; swift::MAX_CHANNELS];
        for (index, count) in counts.iter_mut().take(channels).enumerate() {
            let channel = records::ChannelId::new(index)
                .ok_or_else(|| protocol("native boundary channel"))?;
            *count = engine
                .boundary(direction, channel)
                .ok_or_else(|| protocol("native boundary absent channel"))?
                .count
                .0;
        }
        Ok(Self {
            origin,
            direction,
            channels,
            counts,
        })
    }
    fn canonical_for(
        &self,
        expected_origin: NativeOrigin,
        local_direction: records::Direction,
    ) -> bool {
        self.origin == expected_origin
            && self.direction == local_direction
            && (1..=swift::MAX_CHANNELS).contains(&self.channels)
            && self
                .counts
                .get(self.channels..)
                .is_some_and(|tail| tail.iter().all(|count| *count == 0))
    }
}

/// Physical complete-device writes, separate from admitted/extracted records.
struct NativeWritten {
    origin: NativeOrigin,
    channels: usize,
    counts: [u64; swift::MAX_CHANNELS],
}
struct NativeCompletion {
    channel: usize,
    count: u64,
}
impl NativeWritten {
    fn new(origin: NativeOrigin, channels: usize) -> io::Result<Self> {
        if !(1..=swift::MAX_CHANNELS).contains(&channels) {
            return Err(protocol("native completion channel width"));
        }
        Ok(Self {
            origin,
            channels,
            counts: [0; swift::MAX_CHANNELS],
        })
    }
    fn same_generation(&self, engine: &records::Engine, origin: NativeOrigin) -> bool {
        self.origin == origin && self.channels == engine.receive_config().channels
    }
    fn matches_extracted(&self, engine: &records::Engine, origin: NativeOrigin) -> bool {
        self.same_generation(engine, origin)
            && (0..self.channels).all(|index| {
                records::ChannelId::new(index)
                    .and_then(|channel| engine.boundary(records::Direction::Receive, channel))
                    .is_some_and(|boundary| boundary.count.0 == self.counts[index])
            })
    }
    fn boundary(&self) -> NativeBoundary {
        NativeBoundary {
            origin: self.origin,
            direction: records::Direction::Receive,
            channels: self.channels,
            counts: self.counts,
        }
    }
    fn preflight(
        &self,
        origin: NativeOrigin,
        identity: records::NativeIdentity,
    ) -> io::Result<NativeCompletion> {
        let channel = identity.channel.index();
        if self.origin != origin
            || channel >= self.channels
            || self.counts[channel] != identity.record.0
        {
            return Err(protocol("native completion origin or ordered identity"));
        }
        let count = self.counts[channel].checked_add(1).ok_or_else(exhausted)?;
        Ok(NativeCompletion { channel, count })
    }
    fn complete(&mut self, completion: NativeCompletion) {
        // Only preflight constructs this bounded token, and this sole owner
        // performs no state transition while the synchronous device call runs.
        self.counts[completion.channel] = completion.count;
    }
}

struct Native {
    origin: NativeOrigin,
    identity: records::NativeIdentity,
}
struct PendingPolicy {
    id: policy::OutboundId,
    source: control_owner::Token,
}
struct Challenge {
    nonce: u64,
    deadline: u64,
    submitted: bool,
}
struct Driver {
    config: Config,
    info: member::Info,
    cover: cover::Config,
    origin: Instant,
    bootstrap: establish::BootstrapTail,
    joining: member::JoiningTail,
    outer: u32,
    records: record::Records,
    swift: records::Engine,
    coordinator: policy::Coordinator,
    send: policy::Direction,
    receive: policy::Direction,
    source_scope: Scope,
    feedback_scope: Scope,
    target: Option<Scope>,
    transaction_origin: Option<Scope>,
    resolved: Option<policy::Resolved>,
    control: control_owner::Owner,
    policy_source: Option<PendingPolicy>,
    policy_cap: Option<u64>,
    pending_outcome: Option<policy::Outcome>,
    control_work: bool,
    waiting: Option<Reply>,
    wire: Vec<u8>,
    seal: Vec<u8>,
    open: Vec<u8>,
    plain: Vec<u8>,
    control_wire: Vec<u8>,
    control_input: Vec<u8>,
    frame: Vec<u8>,
    envelope_rx: u64,
    native: native_storage::Queue<Native>,
    written: NativeWritten,
    retired_send: Option<NativeBoundary>,
    retired_receive: Option<NativeBoundary>,
    bucket: Bucket,
    reserve: usize,
    ip: usize,
    ingress: IngressBudget,
    counters: Counters,
    performance: performance::State,
    live: Liveness,
    challenge: Option<Challenge>,
    pong: Option<u64>,
    pong_deadline: Option<u64>,
    remote_ping: u64,
    next_nonce: u64,
    next_ping: u64,
    lease: u64,
    next_report: Option<u64>,
    terminal: Option<StopReason>,
}

struct Hooks<'a> {
    info: &'a member::Info,
    engine: &'a mut records::Engine,
    written: &'a mut NativeWritten,
    retired_send: &'a mut Option<NativeBoundary>,
    retired_receive: &'a mut Option<NativeBoundary>,
    send: &'a mut policy::Direction,
    receive: &'a mut policy::Direction,
    source: &'a mut Scope,
    feedback: &'a mut Scope,
    target: Option<Scope>,
    next: records::RecordNumber,
    native_pending: bool,
    bucket: &'a mut Bucket,
}
impl policy::Hooks for Hooks<'_> {
    type Error = io::Error;
    fn status(&self) -> policy::Status {
        policy::Status {
            send_drained: self.engine.send_drained(),
            receive_deliverable: self.engine.deliverable() || self.native_pending,
            receive_drained: self.engine.receive_drained()
                && !self.native_pending
                && self.written.matches_extracted(
                    self.engine,
                    NativeOrigin::new(self.info, *self.feedback, records::Direction::Receive),
                ),
            next_number: self.next,
        }
    }
    fn replace_send(
        &mut self,
        now: policy::Time,
        direction: policy::Direction,
        feedback_from: records::RecordNumber,
    ) -> io::Result<()> {
        let target = self
            .target
            .ok_or_else(|| protocol("missing staged source policy scope"))?;
        if self.retired_send.is_some() {
            return Err(protocol("previous native send boundary still retained"));
        }
        let boundary = NativeBoundary::capture(
            self.engine,
            NativeOrigin::new(self.info, *self.source, records::Direction::Send),
            records::Direction::Send,
        )?;
        self.engine
            .replace_send(direction.records, feedback_from)
            .map_err(protocol)?;
        *self.retired_send = Some(boundary);
        self.bucket.refill(now.0)?;
        self.bucket.rate = direction.bytes_per_second;
        *self.send = direction;
        *self.source = target;
        Ok(())
    }
    fn replace_receive(
        &mut self,
        direction: policy::Direction,
        source_from: records::RecordNumber,
    ) -> io::Result<()> {
        let target = self
            .target
            .ok_or_else(|| protocol("missing staged feedback policy scope"))?;
        let origin = NativeOrigin::new(self.info, *self.feedback, records::Direction::Receive);
        if self.native_pending
            || !self.engine.receive_drained()
            || !self.written.matches_extracted(self.engine, origin)
        {
            return Err(protocol("native receive completion has not drained"));
        }
        if self.retired_receive.is_some() {
            return Err(protocol("previous native receive boundary still retained"));
        }
        let boundary = self.written.boundary();
        let written = NativeWritten::new(
            NativeOrigin::new(self.info, target, records::Direction::Receive),
            direction.records.channels,
        )?;
        self.engine
            .replace_receive(direction.records, source_from)
            .map_err(protocol)?;
        *self.retired_receive = Some(boundary);
        *self.written = written;
        *self.receive = direction;
        *self.feedback = target;
        Ok(())
    }
}

impl Driver {
    fn new(
        parts: member::Parts,
        expected: security::ConfigDigest,
        config: Config,
        origin: Instant,
    ) -> io::Result<(tokio::net::UdpSocket, Self)> {
        if origin >= parts.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original setup deadline before runtime readiness",
            ));
        }
        if parts.info.authenticated.configuration != expected.0
            || parts.info.binding != parts.root.binding()
            || parts.info.role != parts.root.role()
            || parts.info.authenticated.session != parts.info.binding.session
            || parts.socket.local_addr()? != parts.info.local_addr
            || parts.socket.peer_addr()? != parts.info.peer_addr
        {
            return Err(invalid(
                "actual authenticated runtime session/configuration/role/path",
            ));
        }
        let ipv6 = parts.socket.local_addr()?.is_ipv6();
        config.validate_cover(parts.cover, ipv6)?;
        let ip = if ipv6 { 48 } else { 28 };
        let control_scope = Scope {
            epoch: config.control_epoch,
            configuration: expected,
        };
        let data_scope = Scope {
            epoch: config.data_epoch,
            configuration: expected,
        };
        let records = record::Records::new(
            parts.root,
            security::LaneId(LANE),
            config.security,
            security::Protection::ChaCha20Poly1305,
            parts.cover,
            control_scope,
            data_scope,
        )
        .map_err(invalid)?;
        let mut swift = records::Engine::new(config.send.records).map_err(invalid)?;
        swift
            .replace_receive(config.receive.records, records::RecordNumber(0))
            .map_err(invalid)?;
        let coordinator = policy::Coordinator::new(
            if parts.info.role == security::Role::Initiator {
                policy::Authority::Coordinator
            } else {
                policy::Authority::Participant
            },
            policy::Committed {
                epoch: policy::Epoch(0),
                policy: None,
            },
            config.policy,
            policy::Time(0),
        )
        .map_err(invalid)?;
        let role = if parts.info.role == security::Role::Initiator {
            mg::Role::Client
        } else {
            mg::Role::Server
        };
        let control = control_owner::Owner::new(
            config.control,
            config.streams,
            delivery::Binding {
                session: mg::SessionId(parts.info.binding.session.0),
                lane: mg::LaneId(LANE),
                local_role: role,
                control_epoch: config.control_epoch.0,
            },
            envelope_scope(control_scope),
            envelope_scope(data_scope),
            Duration::ZERO,
            config.lifetime.lease,
        )
        .map_err(invalid)?;
        let capacity = records
            .capacity(config.security.max_body_bytes)
            .map_err(invalid)?;
        let reserve = config.control.recovery.max_source_bytes
            + recovery::DATA_HEADER_BYTES
            + recovery::ACK_PACKET_BYTES
            + 2 * (config.control.wire_overhead + config.control_wrapper_bytes());
        let control_packet = control.max_packet_bytes();
        let control_message =
            config
                .streams
                .map_or(config.control.recovery.max_source_bytes, |settings| {
                    settings
                        .streams
                        .iter()
                        .map(|entry| entry.max_message_bytes)
                        .max()
                        .unwrap_or(0)
                });
        let lease = add(0, config.lifetime.lease)?;
        origin
            .checked_add(config.lifetime.lease)
            .ok_or_else(|| invalid("active lease exceeds runtime clock"))?;
        let next_report = config
            .report_interval
            .map(|interval| add(0, interval))
            .transpose()?;
        Ok((
            parts.socket,
            Self {
                config,
                info: parts.info,
                cover: parts.cover,
                origin,
                bootstrap: parts.bootstrap,
                joining: parts.joining,
                outer: parts.next_outer,
                records,
                swift,
                coordinator,
                send: config.send,
                receive: config.receive,
                source_scope: data_scope,
                feedback_scope: data_scope,
                target: None,
                transaction_origin: None,
                resolved: None,
                control,
                policy_source: None,
                policy_cap: None,
                pending_outcome: None,
                control_work: false,
                waiting: None,
                wire: vec![0; parts.cover.limits().max_packet_bytes],
                seal: vec![0; capacity.seal_workspace_bytes],
                open: vec![0; capacity.open_workspace_bytes],
                plain: vec![0; config.security.max_body_bytes],
                control_wire: vec![0; control_packet],
                control_input: vec![0; control_message],
                frame: Vec::with_capacity(swift::control::MAX_FRAME),
                envelope_rx: 1,
                native: native_storage::Queue::new(
                    config.native.pending_packets,
                    config.native.pending_bytes,
                    config.send.records.max_native,
                )?,
                written: NativeWritten::new(
                    NativeOrigin::new(&parts.info, data_scope, records::Direction::Receive),
                    config.receive.records.channels,
                )?,
                retired_send: None,
                retired_receive: None,
                bucket: Bucket::new(config.send.bytes_per_second, config.wire.burst_bytes),
                reserve,
                ip,
                ingress: IngressBudget {
                    left: config.work.receive_packets,
                    refill: add(0, config.work.receive_interval)?,
                },
                counters: Counters::default(),
                performance: performance::State::default(),
                live: Liveness::default(),
                challenge: None,
                pong: None,
                pong_deadline: None,
                remote_ping: 0,
                next_nonce: 1,
                next_ping: add(0, config.lifetime.ping_interval)?,
                lease,
                next_report,
                terminal: None,
            },
        ))
    }
    fn role(&self) -> mg::Role {
        if self.info.role == security::Role::Initiator {
            mg::Role::Client
        } else {
            mg::Role::Server
        }
    }
    fn remote(&self) -> mg::Role {
        if self.role() == mg::Role::Client {
            mg::Role::Server
        } else {
            mg::Role::Client
        }
    }
    fn snapshot(&self, now: u64, running: bool) -> Snapshot {
        let mut counters = self.counters;
        counters.native_pending_packets = self.native.len();
        counters.native_pending_bytes = self.native.bytes();
        counters.native_storage_capacity_bytes = self.native.capacity_bytes();
        Snapshot {
            running,
            elapsed_micros: now,
            info: self.info,
            configuration: security::ConfigDigest(self.info.authenticated.configuration),
            control_streams: self.config.streams.is_some(),
            policy_deadline_micros: self
                .policy_cap
                .or_else(|| self.coordinator.deadline().map(|deadline| deadline.0)),
            policy_receipt_pending: self.policy_source.is_some() || self.control.has_dispatched(),
            send: self.send,
            receive: self.receive,
            committed: self.coordinator.committed(),
            pending: self.coordinator.pending(),
            swift: self.swift.stats(),
            swift_unconfirmed: self.swift.unconfirmed(),
            channels: (0..self
                .send
                .records
                .channels
                .max(self.receive.records.channels))
                .filter_map(|index| self.swift.channel_stats(index))
                .collect(),
            performance: self.performance.snapshot(now, &self.bucket),
            control: self.control.retained(),
            counters,
            liveness: self.live,
            terminal: self.terminal,
        }
    }
    fn validate_resolution(
        &self,
        requested: &swift::control::Policy,
        resolved: policy::Resolved,
    ) -> io::Result<()> {
        resolved.validate().map_err(invalid)?;
        for direction in [resolved.send, resolved.receive] {
            if direction.records.layer != self.config.send.records.layer
                || direction.records.max_native != self.config.send.records.max_native
                || direction.records.codec.datagram_bytes
                    < swift::FEEDBACK_HEADER + 2 * swift::MAX_REQUESTS
                || direction.records.codec.datagram_bytes > self.config.security.max_body_bytes
            {
                return Err(invalid(
                    "policy changes immutable native format or admitted body ceiling",
                ));
            }
            let cost = self
                .records
                .capacity(direction.records.codec.datagram_bytes)
                .map_err(invalid)?
                .packet_bytes
                + self.ip;
            if cost > usize::from(requested.path_mtu)
                || cost
                    .checked_add(self.reserve)
                    .is_none_or(|total| total > self.config.wire.burst_bytes)
            {
                return Err(invalid("policy exceeds requested MTU/shared burst"));
            }
        }
        let control = self.config.control.recovery.max_source_bytes
            + recovery::DATA_HEADER_BYTES
            + self.config.control.wire_overhead
            + self.config.control_wrapper_bytes();
        if control > usize::from(requested.path_mtu) {
            return Err(invalid(
                "policy cannot retain stable control packet service",
            ));
        }
        Ok(())
    }
    fn stage(&mut self) -> io::Result<()> {
        if let Some(pending) = self.coordinator.pending() {
            let scope = Scope {
                epoch: security::Epoch(
                    self.config
                        .data_epoch
                        .0
                        .checked_add(pending.epoch.0)
                        .ok_or_else(exhausted)?,
                ),
                configuration: security::ConfigDigest(pending.digest.0),
            };
            if self.target == Some(scope) {
                return Ok(());
            }
            if self.target.is_some() {
                return Err(protocol("another data reader still retained"));
            }
            self.records.stage_data(scope).map_err(protocol)?;
            self.target = Some(scope);
        }
        Ok(())
    }
    fn settle_scope(&mut self) -> io::Result<()> {
        if self.coordinator.pending().is_some()
            || self.coordinator.outbound().is_some()
            || self.policy_source.is_some()
            || self.control.has_dispatched()
        {
            return Ok(());
        }
        if let Some(target) = self.target {
            if self.source_scope == target && self.feedback_scope == target {
                let old = self.records.active_data();
                if self.retired_send.as_ref().is_none_or(|boundary| {
                    !boundary.canonical_for(
                        NativeOrigin::new(&self.info, old, records::Direction::Send),
                        records::Direction::Send,
                    )
                }) || self.retired_receive.as_ref().is_none_or(|boundary| {
                    !boundary.canonical_for(
                        NativeOrigin::new(&self.info, old, records::Direction::Receive),
                        records::Direction::Receive,
                    )
                }) {
                    return Err(protocol("settled policy lacks original native boundaries"));
                }
                self.control.advance_scope(envelope_scope(target))?;
                match self.control.retire_draining(envelope_scope(old)) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                    Err(error) => return Err(error),
                }
                self.records.activate_data(target).map_err(protocol)?;
                self.records.retire_data(old).map_err(protocol)?;
                self.retired_send = None;
                self.retired_receive = None;
            } else if self.source_scope == self.records.active_data()
                && self.feedback_scope == self.records.active_data()
            {
                if self.retired_send.is_some() || self.retired_receive.is_some() {
                    return Err(protocol("rejected policy retains native boundary changes"));
                }
                self.records.cancel_staged_data(target).map_err(protocol)?;
            } else {
                return Err(protocol(
                    "policy retired before directional ownership settled",
                ));
            }
            self.target = None;
        }
        self.transaction_origin = None;
        self.resolved = None;
        self.policy_cap = None;
        Ok(())
    }
    // This guard has no delivery, policy-completion or refill side effects.
    // Event branches must check fresh time before removing any original expiry.
    fn check_expiry(&mut self, now: u64) -> io::Result<bool> {
        self.check_expiry_with_native(now, self.native.front().map(|packet| packet.since()))
    }
    fn check_expiry_with_native(
        &mut self,
        now: u64,
        native_since: Option<u64>,
    ) -> io::Result<bool> {
        if self.terminal.is_some() {
            return Ok(false);
        }
        if now >= self.lease {
            self.terminal = Some(StopReason::LeaseExpired);
            return Ok(false);
        }
        if self
            .challenge
            .as_ref()
            .is_some_and(|challenge| now >= challenge.deadline)
        {
            self.terminal = Some(StopReason::PeerTimeout);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "authenticated liveness challenge expired",
            ));
        }
        if native_since.is_some_and(|since| {
            add(since, self.config.native.stall_timeout).is_ok_and(|end| now >= end)
        }) {
            self.terminal = Some(StopReason::NativeStall);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original native output stall deadline",
            ));
        }
        if self.policy_cap.is_some_and(|deadline| now >= deadline) {
            self.terminal = Some(StopReason::PolicyTimeout);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original streamed policy custody deadline",
            ));
        }
        if self
            .coordinator
            .deadline()
            .is_some_and(|deadline| now >= deadline.0)
        {
            self.terminal = Some(StopReason::PolicyTimeout);
        }
        self.coordinator
            .check(policy::Time(now))
            .map_err(protocol)?;
        Ok(true)
    }
    fn progress(&mut self, now: u64) -> io::Result<()> {
        if !self.check_expiry(now)? {
            return Ok(());
        }
        if let Some(pending) = &self.policy_source
            && self.control.confirmed(pending.source, duration(now))?
        {
            self.coordinator
                .complete_outbound(policy::Time(now), pending.id)
                .map_err(protocol)?;
            self.control.retire(pending.source, duration(now))?;
            self.policy_source = None;
        }
        let target = self.target;
        let next = records::RecordNumber(self.records.next_number(Class::User).0);
        let native_pending = !self.native.is_empty();
        let mut hooks = Hooks {
            info: &self.info,
            written: &mut self.written,
            retired_send: &mut self.retired_send,
            retired_receive: &mut self.retired_receive,
            engine: &mut self.swift,
            send: &mut self.send,
            receive: &mut self.receive,
            source: &mut self.source_scope,
            feedback: &mut self.feedback_scope,
            target,
            next,
            native_pending,
            bucket: &mut self.bucket,
        };
        self.coordinator
            .progress(policy::Time(now), &mut hooks)
            .map_err(protocol)?;
        if let Some(outcome) = self.coordinator.take_outcome() {
            if self.config.streams.is_some() {
                if self.pending_outcome.replace(outcome).is_some() {
                    return Err(protocol("another policy outcome still owns custody"));
                }
            } else if let Some(reply) = self.waiting.take() {
                let _ = reply.send(policy_reply(outcome));
            }
        }
        self.settle_scope()?;
        if self.config.streams.is_some()
            && self.policy_cap.is_none()
            && let Some(outcome) = self.pending_outcome.take()
            && let Some(reply) = self.waiting.take()
        {
            let _ = reply.send(policy_reply(outcome));
        }
        self.bucket.refill(now)?;
        if now >= self.ingress.refill {
            self.ingress.left = self.config.work.receive_packets;
            self.ingress.refill = add(now, self.config.work.receive_interval)?;
        }
        Ok(())
    }
    fn request(
        &mut self,
        now: u64,
        requested: swift::control::Policy,
        reply: Reply,
        resolve: &Resolver,
    ) -> io::Result<()> {
        match self.check_expiry(now) {
            Ok(true) => {}
            Ok(false) => {
                let _ = reply.send(Err(SwitchError::Closed));
                return Ok(());
            }
            Err(error) => {
                let _ = reply.send(Err(SwitchError::Closed));
                return Err(error);
            }
        }
        if self.waiting.is_some() {
            let _ = reply.send(Err(SwitchError::Busy));
            return Ok(());
        }
        let resolved = resolve(&requested)
            .filter(|candidate| self.validate_resolution(&requested, *candidate).is_ok());
        match self
            .coordinator
            .request(policy::Time(now), requested, resolved)
        {
            Ok(()) => {
                self.waiting = Some(reply);
                self.retain_policy_cap();
                if self.coordinator.pending().is_some() {
                    self.resolved = resolved;
                    self.transaction_origin = Some(self.source_scope);
                    self.stage()?;
                }
            }
            Err(error) => {
                let _ = reply.send(Err(match error {
                    policy::RequestError::Busy => SwitchError::Busy,
                    policy::RequestError::NotCoordinator => SwitchError::NotCoordinator,
                    policy::RequestError::Invalid => SwitchError::Invalid,
                }));
            }
        }
        Ok(())
    }
    fn envelope_limits(&self) -> control::Limits {
        control::Limits {
            max_frame_bytes: self.control_input.len(),
            max_management_bytes: mg::HEADER_LEN,
            max_feedback_bytes: 1,
        }
    }
    fn scope_registered(&self, scope: Scope) -> bool {
        self.records.active_data() == scope
            || self
                .records
                .additional_data()
                .is_some_and(|reader| reader.scope == scope)
    }
    fn submit(
        &mut self,
        now: u64,
        scope: Scope,
        body: control::Body<'_>,
        deadline: u64,
        auto_retire: bool,
    ) -> io::Result<Option<control_owner::Token>> {
        self.control.submit(
            envelope_scope(scope),
            body,
            duration(now),
            duration(deadline),
            auto_retire,
        )
    }
    fn retain_policy_cap(&mut self) {
        if self.config.streams.is_some() {
            let deadline = self.coordinator.deadline().map(|deadline| deadline.0);
            self.policy_cap = self.policy_cap.into_iter().chain(deadline).min();
        }
    }
    fn submit_control(&mut self, now: u64) -> io::Result<()> {
        // Retain each policy token until the selected backend proves its exact
        // custody: legacy source ACK or streamed complete-message confirmation.
        if self.policy_source.is_none()
            && let Some(outbound) = self.coordinator.outbound()
        {
            let origin = self
                .transaction_origin
                .ok_or_else(|| protocol("policy output without originating data scope"))?;
            self.frame.clear();
            outbound.message.encode(&mut self.frame);
            let mut bytes = [0; swift::control::MAX_FRAME];
            let length = self.frame.len();
            bytes[..length].copy_from_slice(&self.frame);
            if let Some(source) = self.submit(
                now,
                origin,
                control::Body::ProfileControl {
                    tag: control::ProfileTag::SwiftPolicyV1,
                    bytes: &bytes[..length],
                },
                self.policy_cap
                    .or_else(|| self.coordinator.deadline().map(|deadline| deadline.0))
                    .unwrap_or(self.lease),
                false,
            )? {
                self.policy_source = Some(PendingPolicy {
                    id: outbound.id,
                    source,
                });
                self.retain_policy_cap();
            }
        }
        if let Some(nonce) = self.pong
            && self
                .submit(
                    now,
                    self.records.control_scope(),
                    control::Body::Pong { nonce },
                    self.pong_deadline.unwrap_or(self.lease),
                    true,
                )?
                .is_some()
        {
            self.pong = None;
            self.pong_deadline = None;
        }
        if self.challenge.is_none() && now >= self.next_ping {
            let nonce = self.next_nonce;
            self.next_nonce = self.next_nonce.checked_add(1).ok_or_else(exhausted)?;
            let deadline = add(now, self.config.lifetime.pong_timeout)?;
            self.challenge = Some(Challenge {
                nonce,
                deadline,
                submitted: false,
            });
            self.live.outstanding = Some(nonce);
            self.live.deadline_micros = Some(deadline);
        }
        if let Some((nonce, deadline)) = self
            .challenge
            .as_ref()
            .filter(|challenge| !challenge.submitted)
            .map(|challenge| (challenge.nonce, challenge.deadline))
            && self
                .submit(
                    now,
                    self.records.control_scope(),
                    control::Body::Ping { nonce },
                    deadline,
                    true,
                )?
                .is_some()
            && let Some(challenge) = &mut self.challenge
        {
            challenge.submitted = true;
        }
        Ok(())
    }
    fn profile(
        &mut self,
        now: u64,
        scope: Scope,
        message: swift::control::Message,
        resolve: &Resolver,
    ) -> io::Result<()> {
        if !self.scope_registered(scope)
            || self
                .transaction_origin
                .is_some_and(|origin| origin != scope)
        {
            return Err(protocol("profile command has another data-policy origin"));
        }
        if self.config.streams.is_some() && self.policy_cap.is_none() {
            self.policy_cap = Some(
                now.checked_add(self.config.policy.transaction_micros)
                    .ok_or_else(exhausted)?
                    .min(self.lease),
            );
        }
        let was_pending = self.coordinator.pending().is_some();
        let candidate = if let swift::control::Message::Propose { policy, .. } = message {
            resolve(&policy).filter(|value| self.validate_resolution(&policy, *value).is_ok())
        } else {
            None
        };
        let mut hooks = Hooks {
            info: &self.info,
            written: &mut self.written,
            retired_send: &mut self.retired_send,
            retired_receive: &mut self.retired_receive,
            next: records::RecordNumber(self.records.next_number(Class::User).0),
            engine: &mut self.swift,
            send: &mut self.send,
            receive: &mut self.receive,
            source: &mut self.source_scope,
            feedback: &mut self.feedback_scope,
            target: self.target,
            native_pending: !self.native.is_empty(),
            bucket: &mut self.bucket,
        };
        self.coordinator
            .receive(policy::Time(now), message, |_| candidate, &mut hooks)
            .map_err(protocol)?;
        self.retain_policy_cap();
        if self.transaction_origin.is_none() {
            self.transaction_origin = Some(scope);
        }
        if !was_pending && self.coordinator.pending().is_some() {
            self.resolved = candidate;
            self.stage()?;
        }
        Ok(())
    }
    fn service_control(&mut self, now: u64, resolve: &Resolver) -> io::Result<()> {
        if self.config.streams.is_some()
            && (self.control_work
                || self
                    .control
                    .ready_for_dispatch(self.target.map(envelope_scope))?)
        {
            self.delivered_control(now, resolve)?;
        }
        Ok(())
    }
    fn delivered_control(&mut self, now: u64, resolve: &Resolver) -> io::Result<()> {
        self.control_work = false;
        // ARQ receive retention bounds this whole loop. All delivered commands are
        // validated/applied before any poll is allowed to encode their receipts.
        for _ in 0..self.config.control.recovery.receive_records {
            if self.config.streams.is_some() {
                self.progress(now)?;
            }
            let deferred = self.target.map(envelope_scope);
            let Some(incoming) = self.control.next_with_deferred_scope(
                duration(now),
                &mut self.control_input,
                deferred,
            )?
            else {
                if self.config.streams.is_some() {
                    let before = self.target;
                    self.progress(now)?;
                    if before.is_some() && self.target.is_none() {
                        continue;
                    }
                }
                return Ok(());
            };
            let length = incoming.bytes;
            let envelope =
                control::Envelope::decode(&self.control_input[..length], self.envelope_limits())
                    .map_err(protocol)?;
            let binding = envelope.binding;
            if binding.session != mg::SessionId(self.info.binding.session.0)
                || binding.lane != mg::LaneId(LANE)
                || binding.sender != self.remote()
                || (incoming.stream.is_none() && binding.packet.0 != self.envelope_rx)
            {
                return Err(protocol("ordered authenticated control binding"));
            }
            let scope = Scope {
                epoch: security::Epoch(binding.scope.epoch.0),
                configuration: security::ConfigDigest(binding.scope.digest.0),
            };
            enum Command {
                Ping(u64),
                Pong(u64),
                Profile(swift::control::Message),
            }
            let command = match envelope.body {
                control::Body::Ping { nonce } if scope == self.records.control_scope() => {
                    Command::Ping(nonce)
                }
                control::Body::Pong { nonce } if scope == self.records.control_scope() => {
                    Command::Pong(nonce)
                }
                control::Body::ProfileControl {
                    tag: control::ProfileTag::SwiftPolicyV1,
                    bytes,
                } => {
                    let Some((message, used)) =
                        swift::control::Message::decode(bytes).map_err(protocol)?
                    else {
                        return Err(protocol("incomplete authenticated Swift command"));
                    };
                    if used != bytes.len() {
                        return Err(protocol("trailing authenticated Swift command"));
                    }
                    Command::Profile(message)
                }
                _ => {
                    return Err(protocol(
                        "unsupported or mis-scoped authenticated control body",
                    ));
                }
            };
            if incoming.stream.is_none() {
                self.envelope_rx = self.envelope_rx.checked_add(1).ok_or_else(exhausted)?;
            }
            match command {
                Command::Ping(nonce) => {
                    if nonce > self.remote_ping {
                        self.remote_ping = nonce;
                        self.pong = Some(nonce);
                        self.pong_deadline =
                            Some(add(now, self.config.lifetime.pong_timeout)?.min(self.lease));
                    }
                }
                Command::Pong(nonce) => {
                    if self.challenge.as_ref().is_some_and(|challenge| {
                        challenge.submitted && challenge.nonce == nonce && now < challenge.deadline
                    }) {
                        self.challenge = None;
                        self.live.outstanding = None;
                        self.live.deadline_micros = None;
                        self.live.last_pong_micros = Some(now);
                        self.next_ping = add(now, self.config.lifetime.ping_interval)?;
                    }
                }
                Command::Profile(message) => self.profile(now, scope, message, resolve)?,
            }
            self.control.accepted(incoming, duration(now))?;
            self.retain_policy_cap();
        }
        self.control_work = self.config.streams.is_some();
        Ok(())
    }
    fn receive(
        &mut self,
        packet: &[u8],
        now: u64,
        instant: Instant,
        resolve: &Resolver,
    ) -> io::Result<()> {
        self.counters.received_packets = self.counters.received_packets.saturating_add(1);
        let decoded = match self.cover.decode(packet) {
            Ok(decoded) => decoded,
            Err(_) => {
                self.counters.rejected_packets = self.counters.rejected_packets.saturating_add(1);
                return Ok(());
            }
        };
        if self.bootstrap.receive(decoded, instant).map_err(protocol)?
            || self.joining.receive(decoded, instant)?
        {
            return Ok(());
        }
        let opened = match self.records.open(packet, &mut self.open, &mut self.plain) {
            Ok(opened) => opened,
            Err(record::Error::Security(security::Error::Replay)) => {
                self.counters.replay_rejections = self.counters.replay_rejections.saturating_add(1);
                return Ok(());
            }
            // Receive-side usage/generation guards inspect unauthenticated
            // lengths/numbers. They cannot make a peer-origin terminal claim.
            Err(
                error @ record::Error::Security(
                    security::Error::Crypto | security::Error::CounterExhausted,
                ),
            ) => return Err(record_error(error)),
            Err(_) => {
                self.counters.rejected_packets = self.counters.rejected_packets.saturating_add(1);
                return Ok(());
            }
        };
        self.live.last_verified_micros = Some(now);
        match opened.class {
            Class::Control => {
                self.control
                    .receive(
                        mg::Ingress::AuthenticatedManagement {
                            session: mg::SessionId(self.info.binding.session.0),
                            lane: mg::LaneId(LANE),
                            sender: self.remote(),
                        },
                        &self.plain[..opened.bytes],
                        duration(now),
                    )
                    .map_err(protocol)?;
                self.delivered_control(now, resolve)?;
            }
            Class::User => {
                let lead = self
                    .plain
                    .get(..opened.bytes)
                    .and_then(|body| body.first())
                    .ok_or_else(|| protocol("empty authenticated Swift body"))?;
                let kind = lead & swift::KIND_MASK;
                if !matches!(
                    kind,
                    swift::KIND_SOURCE | swift::KIND_REPAIR | swift::KIND_FEEDBACK
                ) {
                    return Err(protocol("unknown authenticated Swift kind"));
                }
                let feedback = kind == swift::KIND_FEEDBACK;
                if opened.scope
                    != if feedback {
                        self.source_scope
                    } else {
                        self.feedback_scope
                    }
                {
                    self.counters.rejected_packets =
                        self.counters.rejected_packets.saturating_add(1);
                    return Ok(());
                }
                if !feedback && !self.native_room() {
                    self.counters.native_backpressure_drops =
                        self.counters.native_backpressure_drops.saturating_add(1);
                    return Ok(());
                }
                if !feedback
                    && !self.written.same_generation(
                        &self.swift,
                        NativeOrigin::new(&self.info, opened.scope, records::Direction::Receive),
                    )
                {
                    return Err(protocol("authenticated native receive generation mismatch"));
                }
                self.swift
                    .accept(
                        now,
                        records::RecordNumber(opened.number.0),
                        &mut self.plain[..opened.bytes],
                    )
                    .map_err(protocol)?;
            }
        }
        Ok(())
    }
    fn native_room(&self) -> bool {
        self.native.can_acquire()
    }
    fn collect_native(&mut self, now: u64) -> io::Result<()> {
        // Every source/repair admitted to this installed receive engine passed
        // the exact opened.scope == feedback_scope check. Its scope cannot move
        // until that engine and the complete native FIFO have physically drained.
        let origin =
            NativeOrigin::new(&self.info, self.feedback_scope, records::Direction::Receive);
        if !self.written.same_generation(&self.swift, origin) {
            return Err(protocol("native collection generation mismatch"));
        }
        for _ in 0..self.config.work.native_write_batch {
            if !self.native_room() {
                self.performance.counters.native_output_full_polls = self
                    .performance
                    .counters
                    .native_output_full_polls
                    .saturating_add(1);
                break;
            }
            // Acquire actual existing output storage before advancing extraction.
            // The lease returns its buffer on empty/error paths automatically.
            let lease = self
                .native
                .acquire()
                .ok_or_else(|| protocol("native lease disappeared"))?;
            let Some(packet) = self.swift.pop_identified().map_err(native_record_error)? else {
                break;
            };
            lease.copy(
                Native {
                    origin,
                    identity: packet.identity,
                },
                now,
                packet.bytes,
            )?;
            self.performance.counters.native_pending_packets_high = self
                .performance
                .counters
                .native_pending_packets_high
                .max(self.native.len() as u64);
            self.performance.counters.native_pending_bytes_high = self
                .performance
                .counters
                .native_pending_bytes_high
                .max(self.native.bytes() as u64);
        }
        Ok(())
    }
    fn read_native<D: PacketDevice<Error = io::Error> + AsRawFd>(
        &mut self,
        ready: &mut tokio::io::unix::AsyncFdReadyMutGuard<'_, D>,
        output: &mut [u8],
        mut now: impl FnMut() -> io::Result<u64>,
    ) -> io::Result<bool> {
        if !self.check_expiry(now()?)?
            || !self.coordinator.admission_allowed()
            || !self.swift.has_room()
        {
            return Ok(false);
        }
        let received = try_native_read(ready, output);
        match &received {
            Ok(Some(_)) => {
                self.performance.counters.native_read_batch_packets = self
                    .performance
                    .counters
                    .native_read_batch_packets
                    .saturating_add(1)
            }
            Ok(None) => {
                self.performance.counters.native_read_would_block = self
                    .performance
                    .counters
                    .native_read_would_block
                    .saturating_add(1)
            }
            Err(_) => {}
        }
        let now = now()?;
        if !self.check_expiry(now)? {
            return Ok(false);
        }
        let Some(length) = received? else {
            return Ok(false);
        };
        if length == 0 || length > self.config.send.records.max_native || length > output.len() {
            self.counters.native_oversize = self.counters.native_oversize.saturating_add(1);
            return Ok(true);
        }
        match self
            .swift
            .offer_identified(now, &output[..length])
            .map_err(native_record_error)?
        {
            records::IdentifiedAdmission::Accepted(_) => {
                self.counters.native_read = self.counters.native_read.saturating_add(1);
            }
            records::IdentifiedAdmission::PacketSize => {
                self.counters.native_oversize = self.counters.native_oversize.saturating_add(1);
            }
            records::IdentifiedAdmission::Full => {
                return Err(protocol("Swift admission changed without another producer"));
            }
        }
        Ok(true)
    }
    async fn flush_native_ready<D: PacketDevice<Error = io::Error> + AsRawFd>(
        &mut self,
        device: &mut AsyncFd<D>,
        mut now: impl FnMut() -> io::Result<u64>,
    ) -> io::Result<usize> {
        if self.native.is_empty() {
            return Ok(0);
        }
        // Observe cached writable readiness once without awaiting the device.
        // The guard never escapes this closure and Pending returns immediately,
        // so blocked output cannot hold opposite-direction input or control.
        std::future::poll_fn(|cx| {
            use std::task::Poll;
            let mut ready = match device.poll_write_ready_mut(cx) {
                Poll::Pending => return Poll::Ready(Ok(0)),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(ready)) => ready,
            };
            self.performance.counters.native_ready_events = self
                .performance
                .counters
                .native_ready_events
                .saturating_add(1);
            let before = self.performance.counters.native_write_batch_packets;
            let mut attempts = 0;
            for _ in 0..self.config.work.native_write_batch {
                if self.native.is_empty() {
                    break;
                }
                attempts += 1;
                let step = self.write_native(&mut ready, &mut now);
                if self
                    .performance
                    .counters
                    .native_write_batch_packets
                    .saturating_sub(before)
                    == self.config.work.native_write_batch as u64
                {
                    self.performance.counters.native_write_batch_limit_hits = self
                        .performance
                        .counters
                        .native_write_batch_limit_hits
                        .saturating_add(1);
                }
                match step {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(error) => return Poll::Ready(Err(error)),
                }
            }
            Poll::Ready(Ok(attempts))
        })
        .await
    }
    fn write_native<D: PacketDevice<Error = io::Error> + AsRawFd>(
        &mut self,
        ready: &mut tokio::io::unix::AsyncFdReadyMutGuard<'_, D>,
        mut now: impl FnMut() -> io::Result<u64>,
    ) -> io::Result<bool> {
        if !self.check_expiry(now()?)? {
            return Ok(false);
        }
        let Some(packet) = self.native.front() else {
            return Ok(false);
        };
        let completion = self
            .written
            .preflight(packet.metadata().origin, packet.metadata().identity)?;
        let packet_bytes = packet.bytes().len();
        let packet_since = packet.since();
        if packet_bytes > self.native.bytes() {
            return Err(protocol("native output byte ownership mismatch"));
        }
        let result = try_native_write(ready, packet.bytes());
        if matches!(&result, Ok(true)) {
            // Commit irreversible complete-device acceptance before sampling a
            // fresh clock or returning any later expiry/invariant failure.
            self.written.complete(completion);
            self.counters.native_written = self.counters.native_written.saturating_add(1);
            self.performance.counters.native_write_batch_packets = self
                .performance
                .counters
                .native_write_batch_packets
                .saturating_add(1);
            self.native.complete_front()?;
        }
        if matches!(&result, Ok(false)) {
            self.performance.counters.native_write_would_block = self
                .performance
                .counters
                .native_write_would_block
                .saturating_add(1);
        }
        // Preserve the original front age for the completion check even after
        // a successful write removes the FIFO entry; it cannot erase its expiry.
        let expiry = now().and_then(|now| self.check_expiry_with_native(now, Some(packet_since)));
        if !expiry? {
            return Ok(false);
        }
        result
    }
    fn handed(
        &mut self,
        socket: &tokio::net::UdpSocket,
        bytes: usize,
        kind: performance::WireKind,
    ) -> io::Result<()> {
        let cost = bytes
            .checked_add(self.ip)
            .ok_or_else(|| protocol("wire charge overflow"))?;
        self.bucket.charge(cost)?;
        self.performance.sent(kind, cost);
        self.outer = self.outer.checked_add(1).ok_or_else(exhausted)?;
        self.counters.wire_packets = self.counters.wire_packets.saturating_add(1);
        self.counters.wire_bytes = self.counters.wire_bytes.saturating_add(cost as u64);
        match socket.try_send(&self.wire[..bytes]) {
            Ok(sent) if sent == bytes => {
                self.counters.socket_accepted_packets =
                    self.counters.socket_accepted_packets.saturating_add(1);
                self.counters.socket_accepted_ip_bytes = self
                    .counters
                    .socket_accepted_ip_bytes
                    .saturating_add(cost as u64);
                Ok(())
            }
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial UDP datagram handoff",
            )),
            Err(error) if establish::path_loss(&error) => {
                self.counters.socket_drops = self.counters.socket_drops.saturating_add(1);
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
    fn tail(&mut self, instant: Instant) -> io::Result<Option<usize>> {
        if self.outer == u32::MAX {
            return Err(exhausted());
        }
        let bootstrap_max = self.bootstrap.max_packet_bytes();
        let enough = self.bucket.allowance() >= bootstrap_max + self.ip;
        let result = self.bootstrap.poll(
            instant,
            meta(self.outer, cover::Phase::Handshake),
            if enough { &mut self.wire } else { &mut [] },
        );
        match result {
            Ok(Some(bytes)) => return Ok(Some(bytes)),
            Ok(None) => {}
            Err(establish::Error::OutputTooSmall) if !enough => {}
            Err(error) => return Err(protocol(error)),
        }
        let enough = self.bucket.allowance() >= self.joining.max_packet_bytes() + self.ip;
        let result = self.joining.poll(
            instant,
            meta(self.outer, cover::Phase::Established),
            if enough { &mut self.wire } else { &mut [] },
        );
        match result {
            Ok(result) => Ok(result),
            Err(error)
                if !enough
                    && error
                        .get_ref()
                        .and_then(|cause| cause.downcast_ref::<cover::Error>())
                        == Some(&cover::Error::OutputTooSmall) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
    fn send(
        &mut self,
        socket: &tokio::net::UdpSocket,
        now: u64,
        instant: Instant,
    ) -> io::Result<()> {
        self.performance.counters.send_calls =
            self.performance.counters.send_calls.saturating_add(1);
        self.performance.checked(now);
        let mut emitted = 0;
        for _ in 0..self.config.work.send_batch {
            if let Some(bytes) = self.tail(instant)? {
                self.handed(socket, bytes, performance::WireKind::Bootstrap)?;
                emitted += 1;
                continue;
            }
            if self.outer == u32::MAX {
                return Err(exhausted());
            }
            if let Some(emission) = self
                .control
                .poll(
                    duration(now),
                    self.bucket.allowance(),
                    &mut self.control_wire,
                )
                .map_err(protocol)?
            {
                let sealed = self
                    .records
                    .seal(
                        Class::Control,
                        meta(self.outer, cover::Phase::Established),
                        &self.control_wire[..emission.bytes],
                        &mut self.seal,
                        &mut self.wire,
                    )
                    .map_err(record_error)?;
                if sealed.bytes + self.ip != emission.wire_bytes {
                    return Err(protocol("control service full-wire accounting mismatch"));
                }
                self.counters.control_number = Some(sealed.number);
                self.counters.control_generation = Some(sealed.generation);
                self.handed(socket, sealed.bytes, performance::WireKind::Control)?;
                emitted += 1;
                continue;
            }
            let maximum = self
                .send
                .records
                .codec
                .datagram_bytes
                .max(self.receive.records.codec.datagram_bytes);
            let required = self
                .records
                .capacity(maximum)
                .map_err(protocol)?
                .packet_bytes
                + self.ip;
            if self.bucket.allowance() < required + self.reserve {
                if self.swift.data_ready(now) || self.swift.feedback_ready(now) {
                    self.performance
                        .blocked(now, self.bucket.ready_at(required + self.reserve)?);
                }
                break;
            }
            let number = self.records.next_number(Class::User);
            let Some(body) = self
                .swift
                .poll(now, records::RecordNumber(number.0), true)
                .map_err(protocol)?
            else {
                self.performance.counters.user_not_ready_polls = self
                    .performance
                    .counters
                    .user_not_ready_polls
                    .saturating_add(1);
                break;
            };
            let feedback = body
                .first()
                .is_some_and(|lead| lead & swift::KIND_MASK == swift::KIND_FEEDBACK);
            let scope = if feedback {
                self.feedback_scope
            } else {
                self.source_scope
            };
            let sealed = self
                .records
                .seal_user_in(
                    scope,
                    meta(self.outer, cover::Phase::Established),
                    body,
                    &mut self.seal,
                    &mut self.wire,
                )
                .map_err(record_error)?;
            if sealed.number != number {
                return Err(protocol(
                    "Swift coefficient seed/security identity mismatch",
                ));
            }
            self.counters.user_number = Some(sealed.number);
            self.counters.user_generation = Some(sealed.generation);
            self.handed(
                socket,
                sealed.bytes,
                if feedback {
                    performance::WireKind::Feedback
                } else {
                    performance::WireKind::Data
                },
            )?;
            emitted += 1;
        }
        if emitted == self.config.work.send_batch {
            self.performance.counters.send_batch_limit_hits = self
                .performance
                .counters
                .send_batch_limit_hits
                .saturating_add(1);
        }
        Ok(())
    }
    fn wake(&self, now: u64) -> io::Result<Instant> {
        let mut wake = self.lease;
        if self.config.streams.is_some()
            && (self.control_work
                || self
                    .control
                    .ready_for_dispatch(self.target.map(envelope_scope))?)
        {
            wake = wake.min(now);
        }
        for at in [
            self.challenge.as_ref().map(|value| value.deadline),
            self.coordinator.deadline().map(|value| value.0),
            self.policy_cap,
            Some(u64::try_from(self.control.expiry().as_micros()).map_err(invalid)?),
            self.control
                .pending_deadline()
                .map(|deadline| u64::try_from(deadline.as_micros()).map_err(invalid))
                .transpose()?,
            self.native
                .front()
                .map(|packet| add(packet.since(), self.config.native.stall_timeout))
                .transpose()?,
            self.next_report,
        ]
        .into_iter()
        .flatten()
        {
            wake = wake.min(at);
        }
        if self.challenge.is_none() {
            wake = wake.min(self.next_ping);
        }
        if self.ingress.left == 0 {
            wake = wake.min(self.ingress.refill);
        }
        let control_ready = self.bucket.ready_at(self.reserve)?;
        let control_at = u64::try_from(self.control.deadline().as_micros())
            .map_err(invalid)?
            .max(control_ready);
        wake = wake.min(control_at);
        let user_max = self
            .records
            .capacity(
                self.send
                    .records
                    .codec
                    .datagram_bytes
                    .max(self.receive.records.codec.datagram_bytes),
            )
            .map_err(protocol)?
            .packet_bytes
            + self.ip
            + self.reserve;
        let user_ready = self.bucket.ready_at(user_max)?;
        // Queued retransmissions and earned repairs are ready work even when
        // the next idle-probe deadline is later than available wire credit.
        if self.swift.data_ready(now) {
            wake = wake.min(user_ready);
        } else if let Some(at) = self.swift.data_deadline() {
            wake = wake.min(at.max(user_ready));
        }
        if let Some(at) = self.swift.feedback_deadline() {
            wake = wake.min(at.max(user_ready));
        }
        let mut instant = self
            .origin
            .checked_add(duration(wake))
            .ok_or_else(|| protocol("runtime wake overflow"))?;
        for (at, bytes) in [
            (
                self.bootstrap.deadline(),
                self.bootstrap.max_packet_bytes() + self.ip,
            ),
            (
                self.joining.deadline(),
                self.joining.max_packet_bytes() + self.ip,
            ),
        ] {
            if let Some(at) = at {
                let ready = self
                    .origin
                    .checked_add(duration(self.bucket.ready_at(bytes)?))
                    .ok_or_else(|| protocol("tail wire wake overflow"))?;
                instant = instant.min(at.max(ready));
            }
        }
        // A pure engine may retain a due source while a local quota blocks it.
        // Bound re-observation and never let a past deadline make select spin.
        let floor = self
            .origin
            .checked_add(duration(now.checked_add(100).ok_or_else(exhausted)?))
            .ok_or_else(exhausted)?;
        Ok(instant.max(floor))
    }
}
