//! Common native records and authenticated control on the selected retained carrier.
//!
//! Device creation and privilege belong to the caller. This driver owns no
//! side channel and never turns a local configuration edit into a peer switch.

use super::{control as control_owner, establish, member};
use l2tunnel::secure_record::{self as record, Class, Scope};
use l2tunnel_core as core;
use l2tunnel_cover as cover;
#[cfg(all(test, unix))]
use l2tunnel_device::PacketDevice;
use l2tunnel_device::{PacketLayer, READ_BUFFER_BYTES};
use l2tunnel_management::{
    self as mg, control_streams as streams, delivery, session_control as control, transaction,
};
use l2tunnel_raw_io::handoff::pairing::packet::compact as raw_compact;
use l2tunnel_recovery as recovery;
use l2tunnel_security as security;
use l2tunnel_swift::{self as swift, policy, records};
use ring::digest;
#[cfg(all(test, unix))]
use std::os::fd::AsRawFd;
use std::{future::Future, io, time::Duration};
#[cfg(all(test, unix))]
use tokio::io::unix::AsyncFd;
use tokio::{
    io::Interest,
    sync::{mpsc, oneshot},
    time::{Instant, sleep_until},
};

#[path = "transport_native_ready.rs"]
mod native_ready;
pub use native_ready::NativeDevice;
use native_ready::{NativeGuard, NativeReady};

const SCALE: u128 = 1_000_000;
const MAX_QUEUE: usize = 16 * 1024 * 1024;
const LANE: u32 = 0;

#[path = "transport_performance.rs"]
mod performance;

#[path = "transport_native.rs"]
mod native_storage;

#[path = "transport_owner.rs"]
mod owner;

#[path = "transport_buffers.rs"]
mod buffers;

#[path = "transport_transaction.rs"]
mod transactions;

#[path = "transport_transaction_family.rs"]
mod transaction_family;

#[path = "transport_common_engines.rs"]
mod common_engines;

pub use performance::Performance;
#[path = "transport_carrier.rs"]
mod carrier;
#[path = "transport_common_research_order.rs"]
mod common_research_order;
#[path = "transport_maintained_carrier.rs"]
mod maintained_carrier;
#[path = "transport_raw_send.rs"]
mod raw_send;
use super::raw_carrier_io as raw_carrier;
#[path = "transport_common.rs"]
mod common;
#[cfg(unix)]
pub(crate) use common::{
    run_common_proxy_records, run_common_proxy_records_on_maintained,
    run_common_proxy_records_on_raw,
};
#[path = "transport_common_actions.rs"]
mod common_actions;
#[path = "transport_common_connections.rs"]
mod common_connections;
#[path = "transport_common_reuse.rs"]
mod common_reuse;
pub use common_reuse::{
    ConnectionReuseError, ConnectionReuseOutcome, ConnectionReusePhase, ConnectionReuseSnapshot,
};
#[path = "transport_buffer_metrics.rs"]
mod buffer_metrics;
#[path = "transport_common_contract.rs"]
mod common_contract;
#[path = "transport_common_fragments.rs"]
mod common_fragments;
#[path = "transport_common_ingress.rs"]
mod common_ingress;
#[path = "transport_common_io.rs"]
mod common_io;
#[path = "transport_common_native.rs"]
mod common_native;
#[path = "transport_common_native_window.rs"]
mod common_native_window;
pub use common::{
    CommonControlHandle, CommonControlRequests, CommonSnapshot, CommonStopped,
    NativeDeliverySnapshot, SameFlowRecovery, common_channel, run_common, run_common_on_carrier,
    run_common_on_maintained, run_common_on_raw,
};
pub use common_connections::{ConnectionIngressLimits, ConnectionIngressSnapshot};
pub use common_contract::CommonTransactionContract;
// The sole loop returns no snapshot payload, keeping constructor and readiness
// poll frames independent of the size of Common observations.
struct LoopCompletion {
    reason: StopReason,
    at: u64,
}
enum Requests {
    Common(Option<CommonControlRequests>),
}
// One bounded complete canonical request crosses the channel without a new heap owner.
#[allow(clippy::large_enum_variant)]
enum Request {
    Common(common::Command),
}
impl Requests {
    fn enabled(&self) -> bool {
        match self {
            Self::Common(value) => value.is_some(),
        }
    }
    fn close(&mut self) {
        match self {
            Self::Common(value) => *value = None,
        }
    }
}

/// Immutable authenticated full-wire bucket, including control and feedback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WireBudget {
    /// Complete IP bytes retained as burst credit; no separate hidden data rate.
    pub burst_bytes: usize,
}

#[cfg(all(test, unix))]
#[path = "transport_tests.rs"]
mod tests;

// The one existing loop borrows its actual Driver. Common constructs its cell
// before polling, so construction frames do not nest inside readiness polling.
#[allow(clippy::too_many_arguments)] // The original loop's owners and deadline remain explicit.
async fn run_driver_clock<D, R: raw_carrier::RawBacking>(
    device: D,
    mut socket: carrier::IoOwner<R>,
    driver: &mut Driver,
    setup_deadline: Instant,
    mut requests: Requests,
    shutdown: impl Future<Output = ()> + Send,
    mut observe: impl FnMut(&Driver, u64, bool) -> io::Result<()> + Send,
    mut sample: impl FnMut() -> Instant + Send,
) -> io::Result<LoopCompletion>
where
    D: NativeDevice + Send,
{
    let origin = driver.origin;
    let mut device =
        NativeReady::with_interest(device, Interest::READABLE.add(Interest::WRITABLE))?;
    let mut inputs = driver.take_inputs()?;
    driver.counters.loop_input_capacity_bytes = inputs.capacity_bytes();
    // Readback belongs to this retained original socket, never a requested tuple.
    // Diagnostic allocation or getsockopt failure is retained as unavailable.
    if let carrier::IoOwner::Udp(socket) = &socket
        && let Some(metrics) = driver
            .common
            .as_deref_mut()
            .and_then(|runtime| runtime.buffer_metrics.as_mut())
    {
        metrics.observe_udp_socket(socket);
    }
    let ready = sample();
    if ready >= setup_deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "original setup deadline before native readiness",
        ));
    }
    tokio::pin!(shutdown);
    observe(driver, clock(origin, ready)?, true)?;
    let mut observed_transaction = driver.transaction_observation()?;
    let mut native_first = true;
    let result:io::Result<StopReason>=async {
        loop {
            if begin_driver_turn(&mut socket, shutdown.as_mut(), |socket| {
                driver.complete_carrier_io(socket, &mut sample)
            }).await? {
                break Ok(StopReason::Cancelled);
            }
            socket.begin_turn();
            if socket.is_carrier() {
                socket.observe_completions().await;
                driver.complete_carrier_io(&mut socket,&mut sample)?;
            }
            if driver.has_transactions(){
                if !driver.check_expiry(clock(origin,sample())?)? {break Ok(driver.terminal.ok_or_else(||protocol("terminal expiry missing"))?);}
                driver.admit_common(||clock(origin,sample()).map(duration))?;
            }
            let mut instant=sample();let mut now=clock(origin,instant)?;
            driver.performance.counters.loop_turns=driver.performance.counters.loop_turns.saturating_add(1);
            driver.sample_common_buffers(now);
            driver.sample_raw_buffers(&mut socket, instant, false);
            if !driver.check_expiry(now)? {break Ok(driver.terminal.ok_or_else(||protocol("terminal expiry missing"))?);}
            driver.service_common_ingress(now, &mut inputs.native)?;
            driver.collect_native(now)?;
            driver.progress(now)?;
            driver.service_common_rolling(now)?;
            let completed=driver.report_transaction_completion(
                ||clock(origin,sample()),
                |driver,at|observe(driver,at,true),
            )?;
            let actual=driver.transaction_observation()?;
            let mut semantic_observed=false;
            if driver.terminal.is_none() && !completed && (actual!=observed_transaction || driver.observation_dirty()) {
                let reported=clock(origin,sample())?;
                if !driver.check_expiry(reported)? {break Ok(driver.terminal.ok_or_else(||protocol("terminal expiry missing"))?);}
                observe(driver,reported,true)?;
                semantic_observed=true;
            }
            observed_transaction=actual;
            driver.clear_observation_dirty();
            if let Some(reason)=driver.terminal {break Ok(reason);}
            if driver.has_transactions() && (completed || semantic_observed) {
                instant=sample();now=clock(origin,instant)?;
                if !driver.check_expiry(now)? {break Ok(driver.terminal.ok_or_else(||protocol("terminal expiry missing"))?);}
            }
            driver.service_selected_control(now)?;
            driver.submit_control(now)?;
            driver.send_selected_io_sampled(&mut socket,now,instant,&mut sample)?;
            let native_before=driver.performance.counters.native_write_batch_packets;
            let native_spent=driver.flush_native_ready(&mut device,||clock(origin,sample())).await?;
            let native_write_remaining=driver.config.work.native_write_batch.saturating_sub(native_spent);
            if let Some(reason)=driver.terminal {break Ok(reason);}
            if driver.next_report.is_some_and(|at|now>=at) {
                let reported=clock(origin,sample())?;
                observe(driver,reported,true)?;
                driver.next_report=driver.config.report_interval.map(|interval|add(reported,interval)).transpose()?;
            }
            let read_native=driver.can_admit_native()?;
            let write_native=!driver.native.is_empty();
            let interest=if read_native && write_native {Interest::READABLE.add(Interest::WRITABLE)}else if write_native {Interest::WRITABLE}else{Interest::READABLE};
            let mut wake=driver.wake_selected_io(&socket,now)?;
            if native_spent>0 || (driver.native_deliverable()? && driver.native_room()) {wake=wake.min(sample());}
            tokio::select! {
                biased;
                ()=&mut shutdown=>break Ok(StopReason::Cancelled),
                request=next_selected_request(&mut requests),if requests.enabled()=>{
                    driver.performance.counters.request_events=driver.performance.counters.request_events.saturating_add(1);
                    match request {
                        Some(Request::Common(common::Command::Switch(configuration,reply)))=>driver.request_common(clock(origin,sample())?,configuration,reply)?,
                        Some(Request::Common(common::Command::Reuse(request,reply)))=>driver.request_connection_reuse(clock(origin,sample())?,request,reply)?,
                        None=>requests.close(),
                    }
                },
                event=next_io(&mut socket,&mut device,interest,read_native || write_native,driver.ingress.left>0,wake,native_first)=>match event? {
                IoEvent::Udp=>{
                    native_first=true;
                    if socket.is_maintained() {driver.performance.counters.maintained_ready_events=driver.performance.counters.maintained_ready_events.saturating_add(1);}
                    else if !socket.is_raw() {driver.performance.counters.udp_ready_events=driver.performance.counters.udp_ready_events.saturating_add(1);}
                    let maximum=if socket.receive_ready() {driver.config.work.receive_packets.min(driver.ingress.left)}else{0};
                    let mut batch=0u64;
                    for _ in 0..maximum {
                        if !driver.check_expiry(clock(origin,sample())?)? {break;}
                        driver.ingress.left-=1;
                        match socket.try_receive_at_ready(&mut inputs.datagram).await {
                            Ok((length,received,framing))=>{
                                batch+=1;
                                if socket.is_maintained() {
                                    driver.performance.counters.maintained_batch_records=driver.performance.counters.maintained_batch_records.saturating_add(1);
                                    if batch==u64::from(maximum) {driver.performance.counters.maintained_batch_limit_hits=driver.performance.counters.maintained_batch_limit_hits.saturating_add(1);}
                                } else if !socket.is_raw() {
                                    driver.performance.counters.udp_batch_packets=driver.performance.counters.udp_batch_packets.saturating_add(1);
                                    if batch==u64::from(maximum) {driver.performance.counters.udp_batch_limit_hits=driver.performance.counters.udp_batch_limit_hits.saturating_add(1);}
                                }
                                let metadata=socket.final_input_metadata();
                                let at=sample();let time=clock(origin,at)?;
                                if !driver.check_expiry(time)? {
                                    if let Some(metadata)=metadata {socket.commit_final_input(metadata,None)?;}
                                    break;
                                }
                                if length>driver.cover.limits().max_packet_bytes {
                                    driver.counters.received_packets=driver.counters.received_packets.saturating_add(1);
                                    driver.counters.rejected_packets=driver.counters.rejected_packets.saturating_add(1);
                                    if let Some(metadata)=metadata {socket.commit_final_input(metadata,None)?;}
                                }else{
                                    let received_time=received.map(|original|clock(origin,original)).transpose()?.unwrap_or(time);
                                    if let Some(metadata)=metadata {
                                        driver.receive_selected_raw(&mut socket,&inputs.datagram[..length],received_time,time,received.unwrap_or(at),at,metadata)?;
                                    }else if let Some(framing)=framing {
                                        driver.receive_selected_on_carrier(&inputs.datagram[..length],received_time,time,received.unwrap_or(at),at,framing)?;
                                    }else{
                                        driver.receive_selected_with_arrival(&inputs.datagram[..length],received_time,time,received.unwrap_or(at),at)?;
                                    }
                                }
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
                        let written=driver.write_native_batch(&mut ready,native_write_remaining,||clock(origin,sample()));
                        if driver.performance.counters.native_write_batch_packets.saturating_sub(native_before)==driver.config.work.native_write_batch as u64 {driver.performance.counters.native_write_batch_limit_hits=driver.performance.counters.native_write_batch_limit_hits.saturating_add(1);}
                        written?;
                    }
                    if ready.ready().is_readable() && read_native {
                        let mut batch=0u64;
                        for _ in 0..driver.config.work.native_read_batch {
                            let before=driver.performance.counters.native_read_batch_packets;
                            let step=driver.read_native(&mut ready,&mut inputs.native,||clock(origin,sample()));
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
    let metric_stop = sample();
    driver.sample_raw_buffers(&mut socket, metric_stop, true);
    if let Ok(now) = clock(origin, metric_stop) {
        driver.finish_buffer_metrics(now);
    }
    // Retain every already observed Common physical fact before dropping its
    // exact carrier witness, including cancellation before the next work turn.
    // This performs no I/O poll and never replaces an earlier observed error.
    #[cfg(unix)]
    let mut terminal_facts_clear = true;
    let result = if socket.is_carrier() && driver.common.is_some() {
        let facts =
            driver.complete_carrier_io_terminal(&mut socket, result.as_ref().err(), &mut sample);
        #[cfg(unix)]
        {
            terminal_facts_clear = facts.is_ok();
        }
        match result {
            Err(error) => Err(error),
            Ok(reason) => facts.map(|()| reason),
        }
    } else {
        result
    };
    #[cfg(all(unix, debug_assertions))]
    if let Err(error) = &result
        && std::env::var_os("L2TUNNEL_MEASURED_TRACE").is_some()
    {
        driver.trace_proxy_peer_close_refusal(
            terminal_facts_clear,
            socket.retained_peer_close(error),
        );
    }
    // A peer may release its maintained owner after its own earlier drain cap.
    // Only an already proved mutual EOF/ACK/physical/join barrier can stop I/O
    // here. Keep the local original cap and return a typed retirement result;
    // the coordinator must synchronously finish the already joined actor.
    #[cfg(unix)]
    let result = match result {
        Err(error) if terminal_facts_clear && socket.retained_peer_close(&error) => {
            match driver.proved_proxy_peer_close_cap().ok().flatten() {
                Some(cap) => {
                    tokio::select! {
                        biased;
                        () = &mut shutdown => Ok(StopReason::Cancelled),
                        () = sleep_until(cap) => {
                            let retired = driver.common.as_deref()
                                .ok_or_else(|| protocol("proxy retirement owner missing"))
                                .and_then(|runtime| driver.observe_proxy_retirement(runtime));
                            if retired.is_err() {
                                Err(error)
                            } else {
                                Ok(StopReason::ProxyRetired)
                            }
                        }
                    }
                }
                None => Err(error),
            }
        }
        other => other,
    };
    if std::env::var_os("L2TUNNEL_TRACE_FAILURE").is_some()
        && let Err(error) = &result
    {
        use std::io::Write;
        // One terminal diagnostic preserves the original cause before the public
        // status reduces it to a portable category. No packet or key is logged.
        let _ = writeln!(
            io::stderr().lock(),
            "Common runtime failure: role={:?} kind={:?} cause={error:?}",
            driver.role(),
            error.kind(),
        );
        if let Ok(observed) = clock(origin, sample()) {
            let _ = driver
                .control
                .write_failure_snapshot(duration(observed), &mut io::stderr().lock());
        }
        // At most two actual retained shared epochs; no payload or per-packet log.
        if let Ok(state) = driver.common_state() {
            for epoch in driver.common_epochs().into_iter().flatten() {
                if let Ok(engine) = state.engine(epoch)
                    && let Some(snapshot) = engine.compact_retry_failure_snapshot()
                {
                    let _ = writeln!(
                        io::stderr().lock(),
                        "Common CompactARQ retry failure: role={:?} epoch={} snapshot={snapshot:?}",
                        driver.role(),
                        epoch.0,
                    );
                }
            }
        }
    }
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
    if let Some(common) = &mut driver.common {
        if let Some(request) = common.request.take() {
            let _ = request.reply.send(Err(SwitchError::Closed));
        }
        if let Some((reply, _)) = common.completion.take() {
            let _ = reply.send(Err(SwitchError::Closed));
        }
    }
    observe(driver, now, false)?;
    result.map(|reason| LoopCompletion { reason, at: now })
}

enum IoEvent<'a, D: NativeDevice> {
    Udp,
    Native(NativeGuard<'a, D>),
    Timer,
}

// The caller polls shutdown and control first. Alternate ready I/O priorities so
// elapsed receive work cannot renew UDP's quota ahead of every native read.
async fn next_io<'a, D: NativeDevice, R: raw_carrier::RawBacking>(
    socket: &mut carrier::IoOwner<R>,
    device: &'a mut NativeReady<D>,
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
            ready = socket.ready(udp) => ready.map(|()| IoEvent::Udp),
            () = sleep_until(wake) => Ok(IoEvent::Timer),
        }
    } else {
        tokio::select! {
            biased;
            ready = socket.ready(udp) => ready.map(|()| IoEvent::Udp),
            ready = device.ready_mut(interest), if native => ready.map(IoEvent::Native),
            () = sleep_until(wake) => Ok(IoEvent::Timer),
        }
    }
}

// Keep the existing cooperative yield, but settle an already retained whole
// receipt before handing execution to unrelated tasks. This callback performs
// no I/O: normal identity, Research ordering, fresh-time and failure checks stay
// with Driver::complete_carrier_io. Cancellation wins before settlement, and is
// polled again after yielding before the caller can start any new I/O.
async fn begin_driver_turn<R: raw_carrier::RawBacking, S: Future<Output = ()> + ?Sized>(
    socket: &mut carrier::IoOwner<R>,
    mut shutdown: std::pin::Pin<&mut S>,
    settle: impl FnOnce(&mut carrier::IoOwner<R>) -> io::Result<()>,
) -> io::Result<bool> {
    if std::future::poll_fn(|cx| std::task::Poll::Ready(shutdown.as_mut().poll(cx).is_ready()))
        .await
    {
        return Ok(true);
    }
    if socket.is_maintained() {
        if socket.maintained_receipt_ready() {
            settle(socket)?;
        }
        // Bounded maintained turns still allow their driver and writer tasks
        // to run; readiness facts do not authorize another unbounded work turn.
        tokio::task::yield_now().await;
        return Ok(std::future::poll_fn(|cx| {
            std::task::Poll::Ready(shutdown.as_mut().poll(cx).is_ready())
        })
        .await);
    }
    Ok(false)
}

async fn next_selected_request(requests: &mut Requests) -> Option<Request> {
    match requests {
        Requests::Common(Some(requests)) => requests.0.recv().await.map(Request::Common),
        _ => std::future::pending().await,
    }
}

fn try_native_write<D: NativeDevice>(
    ready: &mut NativeGuard<'_, D>,
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
fn try_native_read<D: NativeDevice>(
    ready: &mut NativeGuard<'_, D>,
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
    /// Explicit authenticated independent-stream selection. Current Common
    /// construction requires streams and rejects an absent selection.
    pub streams: Option<control_owner::Settings>,
    /// Immutable nonzero common control scope epoch.
    pub control_epoch: security::Epoch,
    /// Nonzero base common data epoch; logical policy epochs are added to it.
    pub data_epoch: security::Epoch,
    /// Shared complete-wire burst bound.
    pub wire: WireBudget,
    /// Socket/native work bounds.
    pub work: WorkBudget,
    /// Explicit per-directional-scheduler rolling work cap per sole-loop turn.
    /// Two retained generations can service at most four directional schedulers.
    /// None cannot select a rolling record catalog.
    pub rolling_work: Option<l2tunnel_fec::rolling::WorkBudget>,
    /// Optional per-generation authenticated Rolling wire-input custody.
    /// None preserves direct decoder admission and the base resource digest.
    pub rolling_ingress: Option<l2tunnel::rolling_records::IngressLimits>,
    /// Explicit local Benchmark ACK ingress, immutable in the authenticated Common envelope.
    /// None preserves transparent behavior and the base resource digest.
    pub ack_coalescing: Option<l2tunnel_pipeline::ack_coalescing::Policy>,
    /// Explicit deferred authenticated per-connection raw ACK input storage.
    /// None preserves old resource digests and cannot select a raw tag8 catalog.
    pub connection_ingress: Option<ConnectionIngressLimits>,
    /// Complete global selected Rolling fragmentation policy, authenticated at establishment.
    /// None retains unfragmented packet geometry and the base resource digest.
    pub rolling_fragments: Option<l2tunnel::record_engine::FragmentPolicy>,
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
        self.validate_rolling_work()?;
        if self.rolling_fragments.is_some() {
            return Err(invalid(
                "Rolling fragmentation requires explicit Common selection",
            ));
        }
        if self.connection_ingress.is_some() {
            return Err(invalid(
                "connection input custody requires explicit Common selection",
            ));
        }
        if self.rolling_ingress.is_some() {
            return Err(invalid(
                "Rolling input custody requires explicit Common selection",
            ));
        }
        if self.ack_coalescing.is_some() {
            return Err(invalid(
                "ACK coalescing requires an explicit Common Benchmark selection",
            ));
        }
        if self.rolling_work.is_some() {
            return Err(invalid(
                "rolling work is selected only by the common record contract",
            ));
        }
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
    /// The retained Common proxy barrier completed at its original local cap.
    /// The proxy coordinator must still observe its joined actor's final result.
    ProxyRetired,
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
    /// Maintained TLS flush or Quinn DATAGRAM acceptance; never a socket-send claim.
    pub maintained_accepted_records: u64,
    /// Inner record bytes accepted at the selected maintained transport boundary.
    pub maintained_accepted_record_bytes: u64,
    /// Configured admission charge for accepted maintained records, not captured IP bytes.
    pub maintained_accepted_charge_bytes: u64,
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
    /// Actual capacities of the seven owned byte workspaces, excluding other owners.
    pub workspace_capacity_bytes: usize,
    /// Actual capacities of the two sole-loop input buffers.
    pub loop_input_capacity_bytes: usize,
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
#[path = "transport_switch_error.rs"]
mod switch_error;
/// Local policy request failure; teardown cannot imply rollback.
pub use switch_error::SwitchError;
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
    owner: owner::DataOwner,
    common: Option<owner::StateCell<common::Runtime>>,
    source_scope: Scope,
    feedback_scope: Scope,
    target: Option<Scope>,
    transaction_origin: Option<Scope>,
    control: control_owner::Owner,
    control_work: bool,
    buffers: buffers::Buffers,
    inputs: Option<buffers::Inputs>,
    envelope_rx: u64,
    native: common_native::OutputQueue,
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

impl Driver {
    fn take_inputs(&mut self) -> io::Result<buffers::Inputs> {
        match self.inputs.take() {
            Some(inputs) => Ok(inputs),
            None if self.has_transactions() => Err(protocol("generic loop input owner is absent")),
            None => buffers::Inputs::new(
                READ_BUFFER_BYTES,
                self.cover
                    .limits()
                    .max_packet_bytes
                    .checked_add(1)
                    .ok_or_else(exhausted)?,
            ),
        }
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
    // This guard has no delivery, policy-completion or refill side effects.
    // Event branches must check fresh time before removing any original expiry.
    fn check_expiry(&mut self, now: u64) -> io::Result<bool> {
        self.check_expiry_with_native(now, self.native.oldest_since())
    }
    fn check_expiry_with_native(
        &mut self,
        now: u64,
        native_since: Option<u64>,
    ) -> io::Result<bool> {
        self.check_expiry_with_completion(now, native_since, self.native.common_deadline())
    }
    fn check_expiry_with_completion(
        &mut self,
        now: u64,
        native_since: Option<u64>,
        native_deadline: Option<u64>,
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
        if self
            .common
            .as_deref()
            .and_then(|runtime| runtime.pending_ingress)
            .is_some_and(|pending| now >= pending.deadline)
        {
            self.terminal = Some(StopReason::NativeStall);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original native ingress custody deadline",
            ));
        }
        if native_deadline.is_some_and(|deadline| now >= deadline)
            || native_since.is_some_and(|since| {
                add(since, self.config.native.stall_timeout).is_ok_and(|end| now >= end)
            })
        {
            self.terminal = Some(StopReason::NativeStall);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original native output stall deadline",
            ));
        }
        let transaction_cap = match &self.owner {
            owner::DataOwner::Common(state) => state
                .operation_deadline()
                .into_iter()
                .chain(
                    self.common
                        .as_deref()
                        .and_then(|r| r.outcome)
                        .map(common_actions::outcome_deadline),
                )
                .chain(
                    self.common
                        .as_deref()
                        .and_then(|r| r.sealed.as_ref())
                        .map(|pending| duration(pending.deadline)),
                )
                .chain(
                    self.common
                        .as_deref()
                        .and_then(|r| r.unsealed.as_ref())
                        .map(|p| duration(p.deadline)),
                )
                .chain(
                    self.common
                        .as_deref()
                        .and_then(|r| r.raw_control.as_ref())
                        .map(|p| p.deadline.saturating_duration_since(self.origin)),
                )
                .chain(
                    self.common
                        .as_deref()
                        .and_then(|r| r.pending_feedback)
                        .map(|pending| duration(pending.deadline)),
                )
                .min(),
        };
        if transaction_cap.is_some_and(|deadline| duration(now) >= deadline) {
            if std::env::var_os("L2TUNNEL_TRACE_FAILURE").is_some() {
                let owner::DataOwner::Common(state) = &self.owner;
                let runtime = self.common.as_deref();
                eprintln!(
                    "Common custody expiry: now={now} selected={transaction_cap:?} operation={:?} outcome={:?} sealed={:?} unsealed={:?} raw_control={:?} deferred_feedback={:?}",
                    state.operation_deadline(),
                    runtime
                        .and_then(|r| r.outcome)
                        .map(common_actions::outcome_deadline),
                    runtime
                        .and_then(|r| r.sealed.as_ref())
                        .map(|p| duration(p.deadline)),
                    runtime
                        .and_then(|r| r.unsealed.as_ref())
                        .map(|p| duration(p.deadline)),
                    runtime
                        .and_then(|r| r.raw_control.as_ref())
                        .map(|p| p.deadline.saturating_duration_since(self.origin)),
                    runtime
                        .and_then(|r| r.pending_feedback)
                        .map(|p| duration(p.deadline)),
                );
            }
            self.terminal = Some(StopReason::PolicyTimeout);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original generic transaction custody deadline",
            ));
        }
        Ok(true)
    }
    fn progress(&mut self, now: u64) -> io::Result<()> {
        self.progress_common(now)
    }
    fn envelope_limits(&self) -> control::Limits {
        control::Limits {
            max_frame_bytes: self.buffers.control_input.len(),
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
    fn proxy_liveness_quiesced(&self) -> io::Result<bool> {
        #[cfg(unix)]
        if let Some(bridge) = self
            .common
            .as_deref()
            .and_then(|runtime| runtime.proxy_bridge.as_ref())
        {
            return bridge.liveness_quiesced();
        }
        Ok(false)
    }

    fn submit_control(&mut self, now: u64) -> io::Result<()> {
        self.submit_common_native_receipts(now)?;
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
            #[cfg(test)]
            self.trace_liveness("pong-submitted", nonce, now);
            self.pong = None;
            self.pong_deadline = None;
        }
        if self.challenge.is_none() && now >= self.next_ping && !self.proxy_liveness_quiesced()? {
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
            #[cfg(test)]
            self.trace_liveness("ping-submitted", nonce, now);
        }
        Ok(())
    }
    fn service_selected_control(&mut self, now: u64) -> io::Result<()> {
        if self.has_transactions() {
            self.progress(now)?;
        }
        let ready = if self.has_transactions() {
            self.control.ready_nontransaction()?
        } else {
            self.control
                .ready_for_dispatch(self.target.map(envelope_scope))?
        };
        if self.config.streams.is_some() && (self.control_work || ready) {
            self.delivered_selected_control(now)?;
        }
        Ok(())
    }
    fn delivered_selected_control(&mut self, now: u64) -> io::Result<()> {
        self.control_work = false;
        self.configure_common_native_receipts()?;
        // ARQ receive retention bounds this whole loop. All delivered commands are
        // validated/applied before any poll is allowed to encode their receipts.
        for _ in 0..self.config.control.recovery.receive_records {
            if self.config.streams.is_some() {
                self.progress(now)?;
            }
            self.configure_common_native_receipts()?;
            let deferred = self.target.map(envelope_scope);
            let Some(incoming) = self.control.next_with_deferred_scope(
                duration(now),
                &mut self.buffers.control_input,
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
            let envelope = control::Envelope::decode(
                &self.buffers.control_input[..length],
                self.envelope_limits(),
            )
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
            #[allow(clippy::large_enum_variant)] // Bounded stack parsing avoids allocating per control packet.
            enum Command {
                Ping(u64),
                Pong(u64),
                Native(mg::LaneId, u16, u64),
                Reuse(l2tunnel::connection_records::retirement::command::Command),
            }
            let command = match envelope.body {
                control::Body::NativeReceipt {
                    lane,
                    receipt: control::NativeReceipt::Record { channel, record },
                } => Command::Native(lane, channel, record),
                control::Body::Ping { nonce } if scope == self.records.control_scope() => {
                    Command::Ping(nonce)
                }
                control::Body::Pong { nonce } if scope == self.records.control_scope() => {
                    Command::Pong(nonce)
                }
                control::Body::ProfileControl {
                    tag: control::ProfileTag::SlotReuseV1,
                    ..
                } => Command::Reuse(self.admit_connection_reuse(now, envelope)?),
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
                    #[cfg(test)]
                    self.trace_liveness("ping-received", nonce, now);
                    if nonce > self.remote_ping {
                        self.remote_ping = nonce;
                        self.pong = Some(nonce);
                        self.pong_deadline =
                            Some(add(now, self.config.lifetime.pong_timeout)?.min(self.lease));
                    }
                }
                Command::Pong(nonce) => {
                    #[cfg(test)]
                    self.trace_liveness("pong-received", nonce, now);
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
                Command::Native(lane, channel, record) => {
                    self.receive_common_native_delivery(now, scope, lane, channel, record)?
                }
                Command::Reuse(command) => self.receive_connection_reuse(now, command)?,
            }
            self.control.accepted(incoming, duration(now))?;
        }
        self.control_work = self.config.streams.is_some();
        Ok(())
    }
    #[cfg(test)]
    fn trace_liveness(&self, event: &str, nonce: u64, now: u64) {
        if std::env::var_os("L2TUNNEL_MAINTAINED_TRACE").is_some()
            && self
                .common
                .as_deref()
                .is_some_and(|runtime| runtime.contract.maintained_outer().is_some())
        {
            eprintln!(
                "maintained-live session={:?} role={:?} event={event} nonce={nonce} now={now} outstanding={:?} deadline={:?}",
                self.info.binding.session,
                self.info.role,
                self.live.outstanding,
                self.live.deadline_micros
            );
        }
    }
    #[cfg(test)]
    fn receive_selected(&mut self, packet: &[u8], now: u64, instant: Instant) -> io::Result<()> {
        self.receive_selected_at(packet, now, now, instant)
    }
    #[cfg(test)]
    fn receive_selected_at(
        &mut self,
        packet: &[u8],
        received: u64,
        now: u64,
        instant: Instant,
    ) -> io::Result<()> {
        let original = self
            .origin
            .checked_add(duration(received))
            .ok_or_else(exhausted)?;
        // Deterministic fixtures inject coarse time independently from
        // the runtime Instant. Real arrivals use the checked wrapper below.
        self.receive_selected_inner(packet, received, now, original, instant)
    }
    fn receive_selected_with_arrival(
        &mut self,
        packet: &[u8],
        received: u64,
        now: u64,
        original: Instant,
        instant: Instant,
    ) -> io::Result<()> {
        if received > now || original > instant || clock(self.origin, original)? != received {
            return Err(invalid("authenticated input arrived after observation"));
        }
        self.receive_selected_inner(packet, received, now, original, instant)
    }
    fn receive_selected_inner(
        &mut self,
        packet: &[u8],
        received: u64,
        now: u64,
        original: Instant,
        instant: Instant,
    ) -> io::Result<()> {
        self.receive_selected_inner_carrier(
            packet,
            received,
            now,
            original,
            instant,
            None,
            None,
            |_| Ok(()),
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn receive_selected_on_carrier(
        &mut self,
        packet: &[u8],
        received: u64,
        now: u64,
        original: Instant,
        instant: Instant,
        framing: impl Into<carrier::InputFraming>,
    ) -> io::Result<()> {
        if received > now || original > instant || clock(self.origin, original)? != received {
            return Err(invalid("carrier input arrived after observation"));
        }
        self.receive_selected_inner_carrier(
            packet,
            received,
            now,
            original,
            instant,
            None,
            Some(framing.into()),
            |_| Ok(()),
        )
    }
    /// Keep untrusted raw input in its original owner until the sole Records verifier decides.
    #[allow(clippy::too_many_arguments)]
    fn receive_selected_raw<R: raw_carrier::RawBacking>(
        &mut self,
        socket: &mut carrier::IoOwner<R>,
        packet: &[u8],
        received: u64,
        now: u64,
        original: Instant,
        instant: Instant,
        metadata: raw_compact::FinalMetadata,
    ) -> io::Result<()> {
        let mut committed = false;
        let result = match clock(self.origin, original) {
            Err(error) => Err(error),
            Ok(arrived) if received > now || original > instant || arrived != received => {
                Err(invalid("raw input arrived after observation"))
            }
            Ok(_) => self.receive_selected_inner_carrier(
                packet,
                received,
                now,
                original,
                instant,
                Some(metadata),
                None,
                |verdict| {
                    committed = true;
                    socket.commit_final_input(metadata, Some(verdict))
                },
            ),
        };
        if !committed {
            socket.commit_final_input(metadata, None)?;
        }
        result
    }
    #[allow(clippy::too_many_arguments)]
    fn receive_selected_inner_carrier(
        &mut self,
        packet: &[u8],
        received: u64,
        now: u64,
        original: Instant,
        instant: Instant,
        carrier: Option<raw_compact::FinalMetadata>,
        framing: Option<carrier::InputFraming>,
        mut commit: impl FnMut(raw_compact::FinalAcceptance<()>) -> io::Result<()>,
    ) -> io::Result<()> {
        if received > now {
            return Err(invalid("authenticated input arrived after observation"));
        }
        if self.has_transactions() {
            self.progress(now)?;
        }
        self.counters.received_packets = self.counters.received_packets.saturating_add(1);
        let carrier_control = self.records.compact_layout() == record::compact::Layout::Carrier
            && packet.first() == Some(&1);
        if let Some(metadata) = carrier {
            if self.records.compact_layout() != record::compact::Layout::Carrier
                || metadata.payload_bytes() != packet.len()
                || raw_compact::FinalKind::inspect(packet) != Some(metadata.kind())
            {
                self.counters.rejected_packets = self.counters.rejected_packets.saturating_add(1);
                return Ok(());
            }
        } else if carrier_control {
            // Only an actual raw candidate owns the carrier Window/Ping/Pong branch.
            self.counters.rejected_packets = self.counters.rejected_packets.saturating_add(1);
            return Ok(());
        }
        if carrier.is_none() && framing != Some(carrier::InputFraming::Final) {
            // The authenticated selection uses appearance only for setup tails;
            // ordinary established compact records have no cover envelope.
            if let Ok(decoded) = self.cover.decode(packet)
                && (self.bootstrap.receive(decoded, instant).map_err(protocol)?
                    || self.joining.receive(decoded, instant)?)
            {
                return Ok(());
            }
            if framing == Some(carrier::InputFraming::Bootstrap) {
                // Explicit bootstrap framing never falls through to a final record,
                // even when its inner media header overlaps a final route selector.
                self.counters.rejected_packets = self.counters.rejected_packets.saturating_add(1);
                return Ok(());
            }
        }
        let opened = if let Some(metadata) = carrier {
            self.records.open_compact_with_carrier(
                packet,
                &metadata.aad(),
                &mut self.buffers.open,
                &mut self.buffers.plain,
            )
        } else {
            self.records
                .open(packet, &mut self.buffers.open, &mut self.buffers.plain)
        };
        let opened = match opened {
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
        if !self.validate_common_compact_route(opened)? {
            self.counters.rejected_packets = self.counters.rejected_packets.saturating_add(1);
            return Ok(());
        }
        let strong_carrier = carrier
            .is_some_and(|metadata| metadata.kind() != raw_compact::FinalKind::Data)
            && opened.authenticated;
        if carrier_control {
            if !strong_carrier
                || opened.class != Class::Control
                || opened.scope != self.records.control_scope()
            {
                self.counters.rejected_packets = self.counters.rejected_packets.saturating_add(1);
                return Ok(());
            }
            let control =
                match raw_compact::FinalControl::decode(&self.buffers.plain[..opened.bytes]) {
                    Ok(value) => value,
                    Err(_) => {
                        self.counters.rejected_packets =
                            self.counters.rejected_packets.saturating_add(1);
                        return Ok(());
                    }
                };
            commit(raw_compact::FinalAcceptance::control((), control))?;
            self.live.last_verified_micros = Some(now);
            self.restore_common_path();
            return Ok(());
        }
        if carrier.is_some() {
            // Even CCM4 data grants no raw retirement/liveness authority.
            commit(raw_compact::FinalAcceptance::record((), strong_carrier))?;
        }
        if opened.authenticated && (carrier.is_none() || strong_carrier) {
            self.live.last_verified_micros = Some(now);
            // A CRC-selected data check never restores an authenticated path or
            // satisfies liveness; strong Control/Feedback retain those rights.
            self.restore_common_path();
        }
        match opened.class {
            Class::Control => {
                if opened.scope != self.records.control_scope() {
                    return Err(protocol(
                        "authenticated Control scope differs from actual Records",
                    ));
                }
                self.control
                    .receive(
                        mg::Ingress::AuthenticatedManagement {
                            session: mg::SessionId(self.info.binding.session.0),
                            lane: mg::LaneId(LANE),
                            sender: self.remote(),
                        },
                        &self.buffers.plain[..opened.bytes],
                        duration(now),
                    )
                    .map_err(protocol)?;
                self.delivered_selected_control(now)?;
            }
            Class::User => {
                return if self.research_physical_output(opened.scope)? {
                    self.receive_common_user_observed(opened, received, now, original)
                } else {
                    self.receive_common_user_at(opened, received, now)
                };
            }
        }
        Ok(())
    }
    fn native_room(&self) -> bool {
        self.native.can_acquire()
    }
    fn collect_native(&mut self, now: u64) -> io::Result<()> {
        self.collect_common_native(now)
    }
    fn read_native<D: NativeDevice>(
        &mut self,
        ready: &mut NativeGuard<'_, D>,
        output: &mut [u8],
        now: impl FnMut() -> io::Result<u64>,
    ) -> io::Result<bool> {
        self.read_common_native(ready, output, now)
    }
    async fn flush_native_ready<D: NativeDevice>(
        &mut self,
        device: &mut NativeReady<D>,
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
            let spent =
                self.write_native_batch(&mut ready, self.config.work.native_write_batch, &mut now);
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
            Poll::Ready(spent)
        })
        .await
    }
    /// Drain actual native custody within the caller's remaining turn allowance.
    /// An empty-queue channel scan consumes a slot even when it produces no packet;
    /// context progress cannot create an unbounded loop or another write budget.
    fn write_native_batch<D: NativeDevice>(
        &mut self,
        ready: &mut NativeGuard<'_, D>,
        maximum: usize,
        mut now: impl FnMut() -> io::Result<u64>,
    ) -> io::Result<usize> {
        let mut spent = 0;
        for _ in 0..maximum {
            if self.native.is_empty() {
                if !self.native_deliverable()? || !self.native_room() {
                    break;
                }
                spent += 1;
                self.collect_native(now()?)?;
                if self.native.is_empty() {
                    continue;
                }
            } else {
                spent += 1;
            }
            // Only a complete successful write releases the Engine token and
            // permits a later iteration to prepare another native packet.
            if !self.write_native(ready, &mut now)? {
                break;
            }
        }
        Ok(spent)
    }
    fn write_native<D: NativeDevice>(
        &mut self,
        ready: &mut NativeGuard<'_, D>,
        now: impl FnMut() -> io::Result<u64>,
    ) -> io::Result<bool> {
        self.write_common_native(ready, now)
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
        match socket.try_send(&self.buffers.wire[..bytes]) {
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
    fn bootstrap_ip_bytes(&self) -> usize {
        let Some(runtime) = self.common.as_deref() else {
            return self.ip;
        };
        if let Some(raw) = runtime.contract.raw_outer() {
            raw.geometry().ip_tcp_bytes + raw.geometry().record_overhead_bytes
        } else if let Some(outer) = runtime.contract.maintained_outer() {
            outer.requested().geometry.bootstrap_overhead_bytes
        } else {
            self.ip + usize::from(runtime.contract.on_outer_carrier())
        }
    }
    fn tail(&mut self, instant: Instant) -> io::Result<Option<usize>> {
        self.tail_with_cap(instant)
            .map(|value| value.map(|(bytes, _)| bytes))
    }
    fn tail_with_cap(&mut self, instant: Instant) -> io::Result<Option<(usize, Instant)>> {
        if self.outer == u32::MAX {
            return Err(exhausted());
        }
        let bootstrap_max = self.bootstrap.max_packet_bytes();
        let enough = self.bucket.allowance() >= bootstrap_max + self.bootstrap_ip_bytes();
        let result = self.bootstrap.poll(
            instant,
            meta(self.outer, cover::Phase::Handshake),
            if enough {
                &mut self.buffers.wire
            } else {
                &mut []
            },
        );
        match result {
            Ok(Some(bytes)) => return Ok(Some((bytes, self.bootstrap.expiry()))),
            Ok(None) => {}
            Err(establish::Error::OutputTooSmall) if !enough => {}
            Err(error) => return Err(protocol(error)),
        }
        let enough =
            self.bucket.allowance() >= self.joining.max_packet_bytes() + self.bootstrap_ip_bytes();
        let result = self.joining.poll(
            instant,
            meta(self.outer, cover::Phase::Established),
            if enough {
                &mut self.buffers.wire
            } else {
                &mut []
            },
        );
        match result {
            Ok(result) => Ok(result.map(|bytes| (bytes, self.joining.expiry()))),
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
        self.send_sampled(socket, now, instant, Instant::now)
    }
    pub(super) fn send_sampled(
        &mut self,
        socket: &tokio::net::UdpSocket,
        now: u64,
        instant: Instant,
        mut sample: impl FnMut() -> Instant,
    ) -> io::Result<()> {
        self.performance.counters.send_calls =
            self.performance.counters.send_calls.saturating_add(1);
        self.performance.checked(now);
        let mut emitted = 0;
        for _ in 0..self.config.work.send_batch {
            // Whole Common writes advance their actual Engine at completion.
            // The next iteration must use the same injected clock again before
            // touching any owner; the previous batch timestamp is no longer current.
            let instant = if self.common.is_some() {
                sample().max(instant)
            } else {
                instant
            };
            let now = if self.common.is_some() {
                clock(self.origin, instant)?.max(now)
            } else {
                now
            };
            if self.common.is_some() && !self.check_expiry(now)? {
                break;
            }
            if let Some(bytes) = self.tail(instant)? {
                self.handed(socket, bytes, performance::WireKind::Bootstrap)?;
                emitted += 1;
                continue;
            }
            if self.outer == u32::MAX {
                return Err(exhausted());
            }
            if let Some(bytes) = self.prepare_control(now)? {
                self.handed(socket, bytes, performance::WireKind::Control)?;
                emitted += 1;
                continue;
            }
            if self.common.is_some() {
                let origin = self.origin;
                if self.send_common_user_sampled(
                    now,
                    |bytes| socket.try_send(bytes),
                    || clock(origin, sample()).map(|at| at.max(now)),
                )? {
                    emitted += 1;
                    continue;
                }
                break;
            }
            return Err(protocol("UDP send requires the current Common owner"));
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
    fn prepare_control(&mut self, now: u64) -> io::Result<Option<usize>> {
        let Some(emission) = self
            .control
            .poll(
                duration(now),
                self.bucket.allowance(),
                &mut self.buffers.control_wire,
            )
            .map_err(protocol)?
        else {
            return Ok(None);
        };
        let sealed = self
            .records
            .seal(
                Class::Control,
                meta(self.outer, cover::Phase::Established),
                &self.buffers.control_wire[..emission.bytes],
                &mut self.buffers.seal,
                &mut self.buffers.wire,
            )
            .map_err(record_error)?;
        if sealed.bytes + self.ip != emission.wire_bytes {
            return Err(protocol("control service full-wire accounting mismatch"));
        }
        self.counters.control_number = Some(sealed.number);
        self.counters.control_generation = Some(sealed.generation);
        Ok(Some(sealed.bytes))
    }
    fn wake(&self, now: u64) -> io::Result<Instant> {
        self.wake_common(now)
    }
}
