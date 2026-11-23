use l2tunnel::path_bundle::{Receiver, TransmitError, Transmitter};
use l2tunnel_device::{PacketDevice, PacketLayer};
use l2tunnel_fec::FecContext;
use l2tunnel_pipeline::{
    path_ack::{AckBatch, LOGICAL_GROUP},
    path_batch::{BatchId, Decoded, PathConfig, PathId},
    path_request::ShardRequest,
    path_retransmit::{PathRecovery, Reason},
};
use l2tunnel_platform_linux::{READ_BUFFER_BYTES, TunTap};
use l2tunnel_security as sec;
use nix::sys::{
    signal::{SigSet, Signal},
    signalfd::{SfdFlags, SignalFd},
};
use rustix::event::{PollFd, PollFlags, poll};
use serde::Serialize;
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    io,
    net::UdpSocket,
    time::{Duration, Instant},
};

mod ack_apply;
mod feedback;
mod low_load;
mod low_load_io;
mod native;
mod pacing;
use pacing::{Class, Scheduler};
mod readiness;
mod recovery;
mod setup;
mod timer_slack;
mod trace;
use recovery::{Charge, Role};
use trace::{Event, Trace};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const OUTER: usize = 49;
const WINDOW: usize = 8192;
const ROUTE: u8 = 0xb1;
const PATH_WINDOW: usize = 256;
const PATH_RTO: u64 = 90_000;
const ADAPTIVE_RTO_MAX: u64 = 500_000;
const ADAPTIVE_RTO_GRANULARITY: u64 = 1_000;
const PATH_LATER: u8 = 3;
fn rotate(slot: u8, by: u8, n: u8) -> u8 {
    ((u16::from(slot) + u16::from(by)) % u16::from(n)) as u8
}
fn us(t: u64) -> Duration {
    Duration::from_micros(t)
}

#[derive(Default, Serialize)]
struct PathStats {
    slot: u8,
    local: String,
    peer: String,
    paid_ip_bytes: u64,
    paid_packets: u64,
    rx_ip_bytes: u64,
    rx_packets: u64,
    fresh_shard_bytes: u64,
    promoted_first_entries: u64,
    promoted_first_shard_bytes: u64,
    promoted_first_entry_bytes: u64,
    frozen_rescue_entries: u64,
    frozen_rescue_entry_bytes: u64,
    late_first_entries: u64,
    late_first_entry_bytes: u64,
    named_shard_bytes: u64,
    quiet_shard_bytes: u64,
    low_load_round_packets: u64,
    low_load_round_entries: u64,
    low_load_round_ip_bytes: u64,
    low_load_round_shard_bytes: u64,
    data_packets: u64,
    path_ready_async_refusals: u64,
    path_ready_requests_paid: u64,
    path_ready_echoes_paid: u64,
    path_ready_ip_bytes: u64,
    path_ready_ethernet_bytes: u64,
    standalone_ack_packets: u64,
    named_request_packets: u64,
    fresh_entries: u64,
    named_entries: u64,
    named_copy_entries: u64,
    named_copy_shard_bytes: u64,
    named_copy_entry_bytes: u64,
    a3_request_copy_packets: u64,
    a3_request_copy_ip_bytes: u64,
    quiet_entries: u64,
    aggregate_data_packets: u64,
    piggyback_ack_bytes: u64,
    outer_overhead_bytes: u64,
    blocked_sends: u64,
    invalid_packets: u64,
    fresh_only_ip_bytes: u64,
    data_with_repair_ip_bytes: u64,
    standalone_ack_ip_bytes: u64,
    request_ip_bytes: u64,
    path_arq_gap_packets: u64,
    path_arq_timeout_packets: u64,
    path_arq_history_packets: u64,
    path_arq_retry_entries: u64,
    path_arq_retry_shard_bytes: u64,
    path_arq_cancelled_before_staging: u64,
    path_arq_retry_entry_bytes: u64,
    physically_acknowledged_packets: u64,
    logically_cancelled_packets: u64,
    path_arq_peak_flights: usize,
    path_arq_timing: Option<serde_json::Value>,
}
#[derive(Default, Serialize)]
struct Totals {
    native_read_packets: u64,
    native_read_bytes: u64,
    native_delivered_packets: u64,
    native_delivered_bytes: u64,
    max_retained_sender_groups: usize,
    max_retained_rx_groups: usize,
    native_write_blocked: u64,
    native_order_blocked_turns: u64,
    native_ack_bypassed_packets: u64,
    native_ready_to_write_max_us: u64,
    due_lateness_max_us: u64,
    native_window_blocked_turns: u64,
    named_requests_received: u64,
    session_group_releases: u64,
    logical_ack_cleanups: u64,
    logical_ack_duplicate_cleanups_skipped: u64,
    logical_ack_path_scans: u64,
    logical_ack_path_scans_skipped: u64,
    poll_waits: u64,
    authenticated_other_packets_before_path_ready: u64,
}
enum Kind {
    Data(BatchId, Vec<Charge>),
    Ack,
    Request(u8, Option<ShardRequest>),
    PathReady(readiness::Message),
}
impl Kind {
    fn class(&self) -> Class {
        match self {
            Self::Data(..) => Class::Data,
            Self::Ack => Class::Ack,
            Self::Request(..) | Self::PathReady(_) => Class::Request,
        }
    }
}
struct Pending {
    pn: u64,
    bytes: Vec<u8>,
    kind: Kind,
    receipt: Option<feedback::Receipt>,
    due: u64,
}
struct Driver {
    origin: Instant,
    trace: Trace,
    cfg: setup::Config,
    sockets: Vec<UdpSocket>,
    tun: TunTap,
    sig: SignalFd,
    send: sec::compact::Sender,
    decrypt: sec::compact::Receiver,
    digest: sec::ConfigDigest,
    domain: FecContext,
    path: PathConfig,
    tx: Transmitter,
    rx: Receiver,
    ack: feedback::Book,
    gaps: feedback::Gaps,
    path_ready: Option<readiness::State>,
    low_load: Option<low_load::Policy>,
    low_load_wake: Option<u64>,
    recovery: recovery::Recovery,
    physical: Vec<PathRecovery>,
    wire: Vec<Option<Pending>>,
    native: native::Queue,
    ctrl: u8,
    pacing: Option<Scheduler>,
    requests: feedback::RequestCopies,
    stats: Vec<PathStats>,
    totals: Totals,
}

pub fn run() -> Result<()> {
    let cfg = setup::Config::read()?;
    let timer_slack = timer_slack::Setting::apply(cfg.pacing_timer_slack_ns)?;
    let mut mask = SigSet::empty();
    mask.add(Signal::SIGTERM);
    mask.add(Signal::SIGINT);
    mask.thread_block()?;
    let sig = SignalFd::with_flags(&mask, SfdFlags::SFD_NONBLOCK | SfdFlags::SFD_CLOEXEC)?;
    let sockets = cfg.sockets()?;
    let tun = TunTap::attach(&cfg.tun, PacketLayer::Ip)?;
    let (send, decrypt, digest, domain) = cfg.security()?;
    let path = PathConfig {
        mtu: usize::from(cfg.mtu),
        outer_bytes: OUTER,
        max_hold: us(cfg.hold),
        max_entries: 255,
    };
    let n = cfg.n;
    let mut stats: Vec<_> = (0..n).map(|_| PathStats::default()).collect();
    for (i, s) in sockets.iter().enumerate() {
        stats[i].slot = i as u8;
        stats[i].local = s.local_addr()?.to_string();
        stats[i].peer = s.peer_addr()?.to_string();
    }
    let ack = if cfg.paced_recovery {
        feedback::Book::with_selective_repeat(n, 8000)?
    } else {
        feedback::Book::new(n)?
    };
    let pacing = cfg
        .wire_rate_bps
        .map(|rate| {
            Scheduler::new(rate, cfg.mtu, n, cfg.pacing_burst_frames)
                .map(|s| s.with_original_frontiers(cfg.pace_original_frontiers))
        })
        .transpose()?;
    let mut d = Driver {
        origin: Instant::now(),
        physical: if cfg.path_arq {
            (0..n)
                .map(|p| {
                    let ledger = PathRecovery::new(p, PATH_WINDOW, PATH_RTO, PATH_LATER)?;
                    if cfg.paced_recovery {
                        ledger.with_rtt_tracking(
                            PATH_RTO,
                            ADAPTIVE_RTO_MAX,
                            ADAPTIVE_RTO_GRANULARITY,
                        )
                    } else {
                        Ok(ledger)
                    }
                })
                .collect::<std::result::Result<Vec<_>, _>>()?
        } else {
            Vec::new()
        },
        trace: Trace::new(cfg.trace.as_deref(), cfg.trace_scheduler_groups)?,
        tx: Transmitter::new(&vec![path; usize::from(n)], cfg.k, 1500, WINDOW)?,
        rx: Receiver::new(
            domain,
            n,
            cfg.k,
            1500,
            (usize::from(cfg.mtu) - OUTER - 27) as u16,
            WINDOW,
        )?,
        path_ready: None,
        low_load_wake: None,
        low_load: cfg
            .low_load_forward_round
            .then(|| low_load::Policy::new(n))
            .transpose()?,
        recovery: {
            let mut recovery = recovery::Recovery::new(n, cfg.k, cfg.a3_reply_copies)
                .fair_members(cfg.fair_members);
            recovery.use_physical_rank = cfg.physical_rank_suppression;
            recovery.transfer_named_path_debt = cfg.transfer_named_path_debt;
            recovery
        },
        native: native::Queue::new(cfg.native_mode),
        cfg,
        sockets,
        tun,
        sig,
        send,
        decrypt,
        digest,
        domain,
        path,
        ack,
        pacing,
        gaps: feedback::Gaps::new(n, path.mtu - OUTER),
        wire: (0..n).map(|_| None).collect(),
        ctrl: 0,
        requests: feedback::RequestCopies::new(n),
        stats,
        totals: Totals::default(),
    };
    d.path_ready = d.cfg.readiness(d.origin.elapsed().as_micros() as u64)?;
    eprintln!("READY");
    let result = d.drive();
    for (stats, ledger) in d.stats.iter_mut().zip(&d.physical) {
        let timing = ledger.timing();
        stats.path_arq_timing = Some(
            json!({"adaptive":timing.adaptive,"samples":timing.samples,"srtt_us":timing.srtt_us,"rttvar_us":timing.rttvar_us,"rto_us":timing.rto_us}),
        );
    }
    let mut receipt = json!({"role":d.cfg.role,"trace":d.trace.status(),"config":{"paths":d.cfg.n,"threshold":d.cfg.k,"mtu":d.cfg.mtu,"hold_us":d.cfg.hold,
        "netns":d.cfg.netns,"tun":d.cfg.tun,"outer_ipv4_bytes":OUTER,"physical_ack_window":256,"logical_groups":WINDOW,"a3_request_copies":d.cfg.a3_request_copies,"a3_reply_copies":d.cfg.a3_reply_copies,
        "ack_count":16,"ack_us":1000,"logical_ack_count":16,"logical_ack_us":1000,"gap_us":1000,"repeat_us":70000,
        "quiet_us":140000,"duplicate_named_guard_us":35000,"low_load_spare":false,"security":"preprovisioned compact-v3 ChaCha20-Poly1305",
        "path_arq":d.cfg.path_arq,"path_arq_window":PATH_WINDOW,"path_arq_later_packets":PATH_LATER,"path_arq_rto_us":PATH_RTO,
        "adaptive_rto_min_us":d.cfg.paced_recovery.then_some(PATH_RTO),"adaptive_rto_max_us":d.cfg.paced_recovery.then_some(ADAPTIVE_RTO_MAX),
        "adaptive_rto_granularity_us":d.cfg.paced_recovery.then_some(ADAPTIVE_RTO_GRANULARITY),
        "fair_members":d.cfg.fair_members,"paced_recovery":d.cfg.paced_recovery,"wire_rate_bps":d.cfg.wire_rate_bps,
        "ordered_native":d.native.mode() == native::Mode::Ordered,
        "ordered_tcp_data":d.native.mode() == native::Mode::OrderedTcpData,
        "physical_rank_suppression":d.cfg.physical_rank_suppression,
        "pacing_burst_frames":d.pacing.as_ref().map(|_|d.cfg.pacing_burst_frames),
        "pacing_initial_ethernet_bytes":d.pacing.as_ref().map(|_|u64::from(d.cfg.mtu)+pacing::ETHERNET_HEADER),
        "pacing_burst_ethernet_bytes":d.pacing.as_ref().map(Scheduler::burst_bytes),
        "selective_repeat_us":d.pacing.as_ref().map(|_|8000u64)},"pacing":d.pacing.as_ref().map(|s|&s.stats),
        "paths":d.stats,"totals":d.totals,"oldest_unconfirmed":d.tx.oldest_unconfirmed(),"next_generation":d.tx.next_generation(),
        "observed_end":d.rx.observed_end(),"confirmed_prefix":d.rx.confirmed_prefix(),"retained_sender_groups":d.recovery.len(),
        "retained_rx_groups":d.rx.retained_groups(),"native_pending":d.native.len(),"suppressed_named":d.recovery.suppressed,
        "path_arq_outstanding":d.physical.iter().map(PathRecovery::outstanding).collect::<Vec<_>>(),
        "coalesced_names":d.recovery.coalesced_names,"coalesced_path_debts":d.recovery.coalesced_path_debts,"bounded_independent_retries":d.recovery.bounded_independent_retries,
        "rank_suppressed_repairs":d.recovery.rank_suppressed,"member_suppressed_repairs":d.recovery.member_suppressed,
        "native_confirmed_trimmed_repairs":d.recovery.native_trimmed,
        "unpaid_natural_path_redirects":d.stats.iter().map(|p|p.promoted_first_entries).sum::<u64>(),
        "error":result.as_ref().err().map(ToString::to_string)});
    receipt["config"]["pace_original_frontiers"] = d.cfg.pace_original_frontiers.into();
    receipt["timer_slack"] = serde_json::to_value(&timer_slack)?;
    receipt["config"]["authenticated_path_ready"] = d.cfg.authenticated_path_ready.into();
    receipt["config"]["low_load_forward_round"] = d.cfg.low_load_forward_round.into();
    receipt["config"]["transfer_named_path_debt"] = d.cfg.transfer_named_path_debt.into();
    receipt["path_debts_transferred_to_named"] = d.recovery.path_debts_transferred_to_named.into();
    receipt["config"]["low_load_forward_policy"] = d
        .cfg
        .low_load_forward_round
        .then_some("fair-round-v2")
        .into();
    receipt["low_load_forward_round"] =
        serde_json::to_value(d.low_load.as_ref().map(|p| &p.stats))?;
    receipt["authenticated_path_ready"] =
        d.path_ready.as_ref().map(readiness::State::status).into();
    receipt["original_frontier_payments"] =
        serde_json::to_value(d.pacing.as_ref().and_then(|s| s.frontiers.as_ref()))?;
    d.trace.finish()?;
    std::fs::write(&d.cfg.stats, serde_json::to_vec_pretty(&receipt)?)?;
    result
}

fn metadata(hash: sec::ConfigDigest, bound: &[u8]) -> sec::Metadata<'_> {
    sec::Metadata {
        epoch: sec::Epoch(0),
        configuration: hash,
        extra: bound,
    }
}
impl Driver {
    fn seal(&mut self, slot: u8, plain: &[u8]) -> Result<(u64, Vec<u8>)> {
        let mut bytes = vec![0; 1 + self.send.overhead() + plain.len()];
        bytes[0] = ROUTE;
        let sealed = self.send.seal(
            metadata(self.digest, &[ROUTE, slot]),
            plain,
            &mut bytes[1..],
        )?;
        Ok((sealed.number.0, bytes))
    }
    fn path_ready(&self) -> bool {
        self.path_ready.as_ref().is_none_or(readiness::State::ready)
    }
    fn credit(&self) -> bool {
        self.path_ready()
            && self
                .tx
                .oldest_unconfirmed()
                .is_none_or(|id| self.tx.next_generation() - id < WINDOW as u64)
    }
    fn incoming(&mut self, slot: u8, pn: u64, now: u64, plain: &[u8]) -> Result<()> {
        if matches!(plain.first(), Some(&readiness::REQUEST | &readiness::ECHO)) {
            let state = self
                .path_ready
                .as_mut()
                .ok_or("unexpected path readiness message")?;
            let was_ready = state.ready();
            state.receive_authenticated(slot, plain, now)?;
            self.trace.control(
                self.trace.time(),
                if plain[0] == readiness::REQUEST {
                    "path_ready_request_rx"
                } else {
                    "path_ready_echo_rx"
                },
                Event::new(slot, None, pn),
            );
            if !was_ready && state.ready() {
                eprintln!("AUTHENTICATED_PATH_READY");
            }
            return Ok(());
        }
        if !self.path_ready() {
            self.totals.authenticated_other_packets_before_path_ready += 1;
        }
        match plain.first() {
            Some(0xa1) => self.apply_ack(plain, Event::new(slot, None, pn), now)?,
            Some(0xa3) => {
                self.totals.named_requests_received += 1;
                let request = ShardRequest::decode(self.cfg.n, plain)?;
                self.trace.names(
                    self.trace.time(),
                    "a3_rx",
                    Event::new(slot, None, pn),
                    &request,
                );
                if self.cfg.fair_members {
                    self.recovery.named_fair(&self.tx, &request, now)?;
                } else {
                    self.recovery.named(&request, now);
                }
            }
            Some(1 | 2) => {
                let packet = self.path.decode(PathId::new(slot)?, plain)?;
                let link = Event::new(slot, Some(packet.sequence), pn);
                let arrival = self.trace.time();
                if let Some(ack) = packet.ack {
                    self.apply_ack(ack, link, now)?;
                }
                // Receipt of this DATA certifies retention or previous delivery of every
                // member. Any admission or decoding error exits the driver before ACK service.
                self.ack.observe(slot, packet.sequence, now)?;
                for shard in packet.entries() {
                    let prior = self.rx.observed_end();
                    let id = shard.generation;
                    self.trace
                        .shard(arrival, "shard_rx", link, id, shard.ordinal);
                    let ready = self.rx.accept(self.domain, shard)?;
                    self.gaps.expose(prior..self.rx.observed_end(), now);
                    if ready {
                        self.trace
                            .shard(self.trace.time(), "kth", link, id, shard.ordinal);
                        self.native
                            .push(id, self.origin.elapsed().as_micros() as u64, &self.rx)?;
                        self.gaps.remove(id);
                    }
                }
                self.totals.max_retained_rx_groups = self
                    .totals
                    .max_retained_rx_groups
                    .max(self.rx.retained_groups());
            }
            _ => return Err("unknown authenticated payload type".into()),
        }
        Ok(())
    }
    fn receive(&mut self, slot: u8, now: u64, buf: &mut [u8], plain: &mut [u8]) -> Result<bool> {
        let i = usize::from(slot);
        let n = match self.sockets[i].recv(buf) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        self.stats[i].rx_packets += 1;
        self.stats[i].rx_ip_bytes += n as u64 + 28;
        if n < 1 + self.decrypt.overhead() || buf.first() != Some(&ROUTE) || n + 28 > self.path.mtu
        {
            self.stats[i].invalid_packets += 1;
            return Ok(true);
        }
        match self
            .decrypt
            .open(metadata(self.digest, &[ROUTE, slot]), &buf[1..n], plain)
        {
            Ok(m) => self.incoming(slot, m.number.0, now, &plain[..m.bytes])?,
            Err(_) => self.stats[i].invalid_packets += 1,
        }
        Ok(true)
    }
    fn deliver(&mut self, now: u64, limit: usize) -> Result<()> {
        for _ in 0..limit {
            let prefix = self.rx.confirmed_prefix();
            let handoff = self.native.write_after_setup(
                self.path_ready.as_ref(),
                &mut self.rx,
                |gid, packet| {
                    self.tun.transmit(packet)?;
                    self.trace.native("native_write", gid, packet);
                    Ok(())
                },
            )?;
            match handoff {
                native::Handoff::Empty | native::Handoff::WaitingForPathReady => break,
                native::Handoff::WaitingForPrefix => {
                    self.totals.native_order_blocked_turns += 1;
                    break;
                }
                native::Handoff::Written {
                    group,
                    ready_us,
                    len,
                } => {
                    let written_us = self.origin.elapsed().as_micros() as u64;
                    if self.native.mode() == native::Mode::OrderedTcpData && group > prefix {
                        self.totals.native_ack_bypassed_packets += 1;
                    }
                    self.totals.native_ready_to_write_max_us = self
                        .totals
                        .native_ready_to_write_max_us
                        .max(written_us.saturating_sub(ready_us));
                    self.totals.native_delivered_bytes += len as u64;
                    self.totals.native_delivered_packets += 1;
                    if self.pacing.is_some() {
                        self.ack.native(group, written_us);
                        self.pay_at_input_checkpoint(true)?;
                    } else {
                        self.ack.native(group, now);
                    }
                }
                native::Handoff::WouldBlock => {
                    self.totals.native_write_blocked += 1;
                    break;
                }
            }
        }
        Ok(())
    }
    fn send_pending(&mut self, slot: u8) -> Result<bool> {
        let i = usize::from(slot);
        let Some(p) = &self.wire[i] else {
            return Ok(false);
        };
        let offered = self.origin.elapsed().as_micros() as u64;
        if self
            .pacing
            .as_ref()
            .is_some_and(|s| s.ready_at(offered, p.bytes.len() + 28) > offered)
        {
            return Err("unbudgeted physical packet".into());
        }
        let mut attempt = self.sockets[i].send(&p.bytes);
        // A connected UDP socket can surface an ICMP error from an earlier
        // probe sent while its peer was binding. Retry this unpaid handoff
        // once, with the same frozen ciphertext and pacing grant.
        if matches!(p.kind, Kind::PathReady(_))
            && attempt
                .as_ref()
                .is_err_and(|e| e.kind() == io::ErrorKind::ConnectionRefused)
        {
            self.stats[i].path_ready_async_refusals += 1;
            attempt = self.sockets[i].send(&p.bytes);
        }
        let n = match attempt {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.stats[i].blocked_sends += 1;
                if let Some(s) = &mut self.pacing {
                    s.block(slot, self.origin.elapsed().as_micros() as u64);
                }
                self.recovery.socket_blocked(
                    slot,
                    self.origin.elapsed().as_micros() as u64,
                    match &p.kind {
                        Kind::Data(_, entries) => entries,
                        _ => &[],
                    },
                );
                return Ok(false);
            }
            Err(e) => return Err(e.into()),
        };
        if n != p.bytes.len() {
            return Err("partial datagram handoff".into());
        }
        let paid_at = self.trace.time();
        let now = self.origin.elapsed().as_micros() as u64;
        if let Some(s) = &mut self.pacing {
            s.paid(p.kind.class(), slot, n + 28, now);
        }
        let p = self.wire[i].take().ok_or("lost paid packet")?;
        self.recovery.socket_paid(
            slot,
            match &p.kind {
                Kind::Data(_, entries) => entries,
                _ => &[],
            },
        );
        let link = Event::new(
            slot,
            match &p.kind {
                Kind::Data(id, _) => Some(id.sequence()),
                _ => None,
            },
            p.pn,
        );
        if self.trace.active()
            && let Some(r) = &p.receipt
        {
            self.trace.logical(
                paid_at,
                "logical_ack_paid",
                link,
                &AckBatch::decode(&r.bytes)?,
            );
        }
        let stats = &mut self.stats[i];
        let paid = n as u64 + 28;
        self.trace.physical(paid_at, link, paid);
        stats.paid_packets += 1;
        stats.paid_ip_bytes += paid;
        stats.outer_overhead_bytes += OUTER as u64;
        match p.kind {
            Kind::Data(id, mut charges) => {
                self.tx.confirm(id)?;
                self.recovery.price_payments(&mut charges);
                if let Some(policy) = &mut self.low_load {
                    for c in &charges {
                        if c.price.first() {
                            policy.original_paid(c.id, c.ordinal, now)?;
                        } else if c.role == Role::LowLoad {
                            policy.paid(
                                low_load::Member {
                                    group: c.id,
                                    ordinal: c.ordinal,
                                },
                                now,
                            )?;
                        }
                    }
                }
                if let Some(f) = self.pacing.as_mut().and_then(|s| s.frontiers.as_mut()) {
                    f.record_natural_payments(slot, &charges);
                }
                if let Some(ledger) = self.physical.get_mut(i) {
                    ledger.sent(
                        id.sequence(),
                        &self.recovery.live_paid_members(&charges),
                        now,
                    )?;
                    stats.path_arq_peak_flights =
                        stats.path_arq_peak_flights.max(ledger.outstanding());
                }
                self.totals.due_lateness_max_us = self
                    .totals
                    .due_lateness_max_us
                    .max(now.saturating_sub(p.due));
                stats.data_packets += 1;
                stats.aggregate_data_packets += u64::from(charges.len() > 1);
                if charges.iter().any(|c| c.role == Role::LowLoad) {
                    stats.low_load_round_packets += 1;
                    stats.low_load_round_ip_bytes += paid;
                }
                if charges.iter().any(|s| !s.price.first()) {
                    stats.data_with_repair_ip_bytes += paid;
                } else {
                    stats.fresh_only_ip_bytes += paid;
                }
                for c in &charges {
                    if c.role == Role::FrozenRescue {
                        stats.frozen_rescue_entries += 1;
                        stats.frozen_rescue_entry_bytes += c.entry_bytes as u64;
                        self.trace
                            .shard(paid_at, "blocked_rescue_handoff", link, c.id, c.ordinal);
                    }
                    if let Role::Path(previous) = c.role {
                        self.trace.retry(
                            paid_at,
                            "path_retry_paid",
                            link,
                            previous,
                            c.id,
                            c.ordinal,
                        );
                    } else {
                        self.trace.shard(
                            paid_at,
                            match c.price {
                                Role::Fresh | Role::PromotedNamed | Role::PromotedQuiet => {
                                    "fresh_paid"
                                }
                                Role::Named => "named_paid",
                                Role::NamedCopy => "named_copy_paid",
                                Role::Quiet => "quiet_paid",
                                Role::LowLoad => "low_load_paid",
                                Role::Path(_) => "path_retry_paid",
                                Role::FrozenRescue => "named_paid",
                                Role::LateFirst => "late_first_paid",
                            },
                            link,
                            c.id,
                            c.ordinal,
                        );
                    }
                    let b = c.bytes as u64;
                    match c.price {
                        Role::Fresh | Role::PromotedNamed | Role::PromotedQuiet => {
                            stats.fresh_entries += 1;
                            stats.fresh_shard_bytes += b;
                            if c.price != Role::Fresh {
                                stats.promoted_first_entries += 1;
                                stats.promoted_first_shard_bytes += b;
                                stats.promoted_first_entry_bytes += c.entry_bytes as u64;
                                self.trace.shard(
                                    paid_at,
                                    if c.price == Role::PromotedNamed {
                                        "a3_promoted_first"
                                    } else {
                                        "quiet_promoted_first"
                                    },
                                    link,
                                    c.id,
                                    c.ordinal,
                                );
                            }
                        }
                        Role::Named | Role::NamedCopy | Role::FrozenRescue => {
                            if c.role == Role::NamedCopy {
                                stats.named_copy_entries += 1;
                                stats.named_copy_shard_bytes += b;
                                stats.named_copy_entry_bytes += c.entry_bytes as u64;
                            }
                            stats.named_entries += 1;
                            stats.named_shard_bytes += b;
                        }
                        Role::Quiet => {
                            stats.quiet_entries += 1;
                            stats.quiet_shard_bytes += b;
                        }
                        Role::LowLoad => {
                            stats.low_load_round_entries += 1;
                            stats.low_load_round_shard_bytes += b;
                        }
                        Role::LateFirst => {
                            stats.late_first_entries += 1;
                            stats.late_first_entry_bytes += c.entry_bytes as u64;
                        }
                        Role::Path(_) => {
                            stats.path_arq_retry_entries += 1;
                            stats.path_arq_retry_shard_bytes += b;
                            stats.path_arq_retry_entry_bytes += c.entry_bytes as u64;
                        }
                    }
                }
                self.recovery.paid(id, &charges, now);
                if let Some(ref r) = p.receipt {
                    stats.piggyback_ack_bytes += r.bytes.len() as u64;
                }
            }
            Kind::PathReady(message) => {
                self.path_ready
                    .as_mut()
                    .ok_or("missing configured path readiness")?
                    .paid(slot, message, now)?;
                let event = if message.is_echo() {
                    stats.path_ready_echoes_paid += 1;
                    "path_ready_echo_paid"
                } else {
                    stats.path_ready_requests_paid += 1;
                    "path_ready_request_paid"
                };
                stats.path_ready_ip_bytes += paid;
                stats.path_ready_ethernet_bytes += paid + pacing::ETHERNET_HEADER;
                self.trace.control(paid_at, event, link);
            }
            Kind::Ack => {
                stats.standalone_ack_packets += 1;
                stats.standalone_ack_ip_bytes += paid;
            }
            Kind::Request(copy, request) => {
                if copy != 0 {
                    stats.a3_request_copy_packets += 1;
                    stats.a3_request_copy_ip_bytes += paid;
                }
                if let Some(request) = request {
                    self.trace.names(
                        paid_at,
                        if copy == 0 { "a3_paid" } else { "a3_copy_paid" },
                        link,
                        &request,
                    );
                }
                stats.named_request_packets += 1;
                stats.request_ip_bytes += paid;
            }
        }
        if let Some(r) = p.receipt {
            self.ack.paid(r, now)?;
        }
        Ok(true)
    }
    fn send_data(&mut self, slot: u8, now: u64) -> Result<bool> {
        if self.prepare_data(slot, now, pacing::Pass::Regular)? {
            self.send_pending(slot)
        } else {
            Ok(false)
        }
    }

    fn prepare_data(&mut self, slot: u8, now: u64, pass: pacing::Pass) -> Result<bool> {
        let i = usize::from(slot);
        let id = PathId::new(slot)?;
        if self.wire[i].is_some() {
            return Ok(true);
        }
        if let Some(ledger) = self.physical.get_mut(i)
            && (!self.recovery.has_queued_path_repair(slot) || !ledger.can_send())
            && let Some((previous, members, reason)) = ledger.take_due_with_reason(now)
        {
            let stats = &mut self.stats[i];
            let event = match reason {
                Reason::Timeout => {
                    stats.path_arq_timeout_packets += 1;
                    "path_loss_timeout"
                }
                Reason::SelectiveGap => {
                    stats.path_arq_gap_packets += 1;
                    "path_loss_gap"
                }
                Reason::ExpiredHistory => {
                    stats.path_arq_history_packets += 1;
                    "path_loss_floor"
                }
            };
            if self.trace.active() {
                let at = self.trace.time();
                let link = Event::new(slot, Some(previous), u64::MAX);
                for &(gid, ord) in &members {
                    self.trace.retry(at, event, link, previous, gid, ord);
                }
            }
            self.recovery.requeue_path(slot, previous, &members);
        }
        let has_credit = self.physical.get(i).is_none_or(PathRecovery::can_send);
        if self.cfg.fair_members {
            if !has_credit {
                return Ok(false);
            }
            self.stats[i].path_arq_cancelled_before_staging += if self.trace.scheduler_active(now) {
                self.recovery.stage_fair_observed(
                    &mut self.tx,
                    id,
                    us(now),
                    &self.physical,
                    |tx, path| {
                        self.trace.scheduler_staged(
                            tx,
                            path,
                            self.origin.elapsed().as_micros() as u64,
                        )
                    },
                )?
            } else {
                self.recovery
                    .stage_fair(&mut self.tx, id, us(now), &self.physical)?
            };
        } else {
            self.stats[i].path_arq_cancelled_before_staging +=
                self.recovery
                    .stage(&mut self.tx, id, us(now), self.physical.get(i))?;
            if has_credit {
                self.tx.fill_path(id, us(now), 128)?;
            }
        }
        if !has_credit {
            return Ok(false);
        }
        let due = match pass {
            pacing::Pass::Regular => self.tx.next_wake(id)?.is_some_and(|t| t <= us(now)),
            pacing::Pass::Input => self.tx.has_due_head(id, us(now))?,
        };
        if !due {
            return Ok(false);
        }
        if self.cfg.physical_rank_suppression {
            self.recovery.trim_due(&mut self.tx, id, us(now))?;
        }
        let mut ack = self.ack.prepare(&self.rx, now)?;
        let Some(p) = self
            .tx
            .prepare(id, us(now), ack.as_ref().map(|r| r.bytes.as_slice()))?
        else {
            return Ok(false);
        };
        let token = p.id;
        let due = p.deadline.as_micros() as u64;
        self.trace.scheduler_prepared(token, now, due);
        if p.attached_ack.is_none() {
            ack = None;
        }
        let decoded = self.path.decode(id, p.bytes)?;
        let charges = self.recovery.charges(id, decoded)?;
        let mut wire = vec![0; 1 + self.send.overhead() + p.bytes.len()];
        wire[0] = ROUTE;
        let sealed = self.send.seal(
            metadata(self.digest, &[ROUTE, slot]),
            p.bytes,
            &mut wire[1..],
        )?;
        if let Some(held) = &ack {
            self.ack.claim(held);
        }
        self.wire[i] = Some(Pending {
            pn: sealed.number.0,
            bytes: wire,
            kind: Kind::Data(token, charges),
            receipt: ack,
            due,
        });
        Ok(true)
    }
    fn control(&mut self, now: u64) -> Result<bool> {
        let Some(slot) = (0..self.cfg.n)
            .map(|v| rotate(self.ctrl, v, self.cfg.n))
            .find(|s| self.wire[usize::from(*s)].is_none())
        else {
            return Ok(false);
        };
        if self.requests.is_empty()
            && let Some(body) = self.gaps.request(&self.rx, now)?
        {
            self.ctrl = self
                .requests
                .schedule(slot, self.cfg.a3_request_copies, body);
        }
        let mut sent = false;
        while let Some((route, copy, body)) = self
            .requests
            .take_ready(|p| self.wire[usize::from(p)].is_none())
        {
            self.prepare_request(route, copy, &body, now)?;
            sent |= self.send_pending(route)?;
        }
        if sent || self.ack.due(now).is_none_or(|t| t > now) {
            return Ok(sent);
        }
        let Some(route) = (0..self.cfg.n)
            .map(|i| rotate(self.ctrl, i, self.cfg.n))
            .find(|p| self.wire[usize::from(*p)].is_none())
        else {
            return Ok(false);
        };
        self.prepare_ack(route, now)?;
        self.send_pending(route)
    }

    fn prepare_path_ready(&mut self, slot: u8, now: u64) -> Result<bool> {
        let Some(state) = &self.path_ready else {
            return Ok(false);
        };
        let Some(message) = state.due(slot, now)? else {
            return Ok(false);
        };
        let (pn, bytes) = self.seal(slot, &message.encode())?;
        self.wire[usize::from(slot)] = Some(Pending {
            pn,
            bytes,
            kind: Kind::PathReady(message),
            receipt: None,
            due: now,
        });
        Ok(true)
    }

    fn prepare_request(&mut self, route: u8, copy: u8, body: &[u8], now: u64) -> Result<()> {
        let request = if self.trace.active() {
            Some(ShardRequest::decode(self.cfg.n, body)?)
        } else {
            None
        };
        let (pn, bytes) = self.seal(route, body)?;
        self.wire[usize::from(route)] = Some(Pending {
            pn,
            bytes,
            kind: Kind::Request(copy, request),
            receipt: None,
            due: now,
        });
        Ok(())
    }

    fn prepare_ack(&mut self, route: u8, now: u64) -> Result<()> {
        let receipt = self
            .ack
            .prepare(&self.rx, now)?
            .ok_or("lost ACK obligation")?;
        let (pn, bytes) = self.seal(route, &receipt.bytes)?;
        self.ack.claim(&receipt);
        self.ctrl = rotate(route, 1, self.cfg.n);
        self.wire[usize::from(route)] = Some(Pending {
            pn,
            bytes,
            kind: Kind::Ack,
            receipt: Some(receipt),
            due: now,
        });
        Ok(())
    }
    fn protocol_deadline(&self, now: u64) -> Result<Option<u64>> {
        let mut due = self
            .recovery
            .quiet
            .into_iter()
            .chain(self.recovery.deferred_wake())
            .min();
        if self.wire.iter().any(Option::is_none) {
            due = due
                .into_iter()
                .chain(self.ack.due(now))
                .chain(self.gaps.wake().filter(|_| self.requests.is_empty()))
                .min();
        }
        for p in 0..self.cfg.n {
            let i = usize::from(p);
            if self.wire[i].is_some() {
                continue;
            }
            if let Some(state) = &self.path_ready {
                due = due.into_iter().chain(state.path_wake(p, now)?).min();
            }
            if let Some(ledger) = self.physical.get(i) {
                if !self.recovery.has_queued_path_repair(p) || !ledger.can_send() {
                    due = due.into_iter().chain(ledger.next_deadline()).min();
                }
                if !ledger.can_send() {
                    continue;
                }
            }
            if let Some(t) = self.tx.next_wake(PathId::new(p)?)? {
                due = Some(due.map_or(t.as_micros() as u64, |d| d.min(t.as_micros() as u64)));
            }
        }
        Ok(due)
    }

    fn drive(&mut self) -> Result<()> {
        let start = self.origin;
        let elapsed = || start.elapsed().as_micros() as u64;
        let mut native = vec![0; READ_BUFFER_BYTES];
        let (mut buf, mut plain) = ([0; 1600], [0; 1600]);
        // A paid head can exhaust a full frame of shared credit. Bound the
        // ingress work before selecting its successor, including while TUN is hot.
        const PACED_INPUT_QUANTUM: usize = 8;
        let paced = self.pacing.is_some();
        let mut next_rx = 0;
        let mut polled = false;
        let mut udp_readable = vec![true; usize::from(self.cfg.n)];
        let mut tun_readable = true;
        loop {
            if self.sig.read_signal()?.is_some() {
                break;
            }
            if let Some(state) = &self.path_ready {
                state.check(elapsed())?;
            }
            let from_poll = std::mem::take(&mut polled);
            if paced {
                self.pay_at_input_checkpoint(false)?;
            }
            // Bound each pass across live inputs. Keep other paths and feedback serviceable.
            let mut received = 0;
            'rx: for _ in 0..16 {
                let mut any = false;
                for offset in 0..self.cfg.n {
                    let p = rotate(next_rx, offset, self.cfg.n);
                    if from_poll && !udp_readable[usize::from(p)] {
                        continue;
                    }
                    if self.receive(p, elapsed(), &mut buf, &mut plain)? {
                        any = true;
                        if paced {
                            self.pay_at_input_checkpoint(true)?;
                            received += 1;
                            if received == PACED_INPUT_QUANTUM {
                                next_rx = rotate(p, 1, self.cfg.n);
                                break 'rx;
                            }
                        }
                    }
                }
                if !any {
                    break;
                }
            }
            self.deliver(elapsed(), if paced { PACED_INPUT_QUANTUM } else { 64 })?;
            let reads = if !self.path_ready()
                || (from_poll
                    && !tun_readable
                    && !self
                        .low_load
                        .as_ref()
                        .is_some_and(low_load::Policy::has_candidate))
            {
                0
            } else if paced {
                PACED_INPUT_QUANTUM
            } else {
                32
            };
            let mut native_drained = false;
            for _ in 0..reads {
                if !self.credit() {
                    self.totals.native_window_blocked_turns += 1;
                    break;
                }
                let Some(n) = self.tun.receive(&mut native)? else {
                    native_drained = true;
                    break;
                };
                let now = elapsed();
                self.trace
                    .native("native_read", self.tx.next_generation(), &native[..n]);
                let gid = self.tx.admit(us(now), &native[..n])?;
                self.trace.scheduler_admit(gid, now);
                self.recovery.retain(gid, now);
                self.totals.native_read_packets += 1;
                self.totals.native_read_bytes += n as u64;
                if paced {
                    self.pay_at_input_checkpoint(true)?;
                }
            }
            self.totals.max_retained_sender_groups = self
                .totals
                .max_retained_sender_groups
                .max(self.recovery.len());
            let oldest_has_rank = self.cfg.physical_rank_suppression
                && self
                    .tx
                    .oldest_unconfirmed()
                    .is_some_and(|g| self.tx.peer_has_rank(g));
            self.recovery
                .quiet_tick_with_rank(elapsed(), oldest_has_rank);
            self.recovery.wake_due_members(elapsed());
            let mut paced_payments = 0;
            for _ in 0..16 {
                let paid = if self.pacing.is_some() {
                    self.paced_step(elapsed(), pacing::Pass::Regular)?
                } else {
                    let mut any = false;
                    for p in 0..self.cfg.n {
                        any |= self.send_data(p, elapsed())?;
                    }
                    any | self.control(elapsed())?
                };
                if !paid {
                    break;
                }
                if self.pacing.is_some() {
                    paced_payments += 1;
                }
            }
            // A complete quantum can leave unpaid control replicas with no new timer.
            // Revisit inputs before servicing the next quantum.
            if paced_payments == 16 {
                continue;
            }
            // Opportunistic work gets one handoff only after input and all
            // ordinary egress have been serviced, then returns to input.
            if native_drained && received < PACED_INPUT_QUANTUM && self.send_low_load(elapsed())? {
                continue;
            }
            if !native_drained
                && self.path_ready()
                && self.credit()
                && self
                    .low_load
                    .as_ref()
                    .is_some_and(low_load::Policy::has_candidate)
            {
                // A last original can enable a copy after the input scan.
                // Recheck TUN before treating that new opportunity as idle.
                continue;
            }
            let now = elapsed();
            let deadline = self
                .next_deadline(now)?
                .into_iter()
                .chain(self.low_load_wake.take())
                .chain(
                    self.path_ready
                        .as_ref()
                        .and_then(readiness::State::setup_deadline),
                )
                .min()
                .unwrap_or(now + 1_000_000);
            let checked = elapsed();
            if deadline <= checked {
                self.trace.scheduler_due_now(checked, deadline);
                continue;
            }
            let mut native_flags = PollFlags::empty();
            if self.credit() {
                native_flags |= PollFlags::IN;
            }
            if self.path_ready() && self.native.next(self.rx.confirmed_prefix()).is_some() {
                native_flags |= PollFlags::OUT;
            }
            let mut fds = Vec::with_capacity(2 + self.sockets.len());
            fds.push(PollFd::new(&self.sig, PollFlags::IN));
            fds.push(PollFd::new(&self.tun, native_flags));
            let mut observed_out = self.trace.scheduler_active(now).then_some([0u64; 4]);
            for (i, s) in self.sockets.iter().enumerate() {
                let flags = if self.want_writable(i as u8, now) {
                    if let Some(bits) = &mut observed_out {
                        bits[i / 64] |= 1u64 << (i % 64);
                    }
                    PollFlags::IN | PollFlags::OUT
                } else {
                    PollFlags::IN
                };
                fds.push(PollFd::new(s, flags));
            }
            let entered = elapsed();
            let wait = us(deadline.saturating_sub(entered));
            if wait.is_zero() {
                self.trace.scheduler_due_now(entered, deadline);
                continue;
            }
            self.totals.poll_waits += 1;
            let observed = observed_out
                .filter(|_| self.trace.scheduler_active(entered))
                .map(|out| (self.trace.time(), out));
            let reported = poll(&mut fds, Some(&wait.try_into()?))?;
            if let Some(s) = &mut self.pacing {
                let returned = elapsed();
                if let Some((enter_ns, udp_out)) = observed {
                    let return_ns = self.trace.time();
                    self.trace.scheduler_poll(
                        trace::PollSample {
                            id: self.totals.poll_waits,
                            enter_ns,
                            return_ns,
                            entered,
                            returned,
                            deadline,
                            ready_count: reported,
                            tun_interest: native_flags,
                            udp_out,
                        },
                        &fds,
                    );
                }
                if reported == 0 {
                    s.poll_timeout(entered, returned);
                }
                let read_events = PollFlags::IN | PollFlags::ERR | PollFlags::HUP;
                polled = true;
                tun_readable = fds[1].revents().intersects(read_events);
                for (i, fd) in fds.iter().skip(2).enumerate() {
                    udp_readable[i] = fd.revents().intersects(read_events);
                    if fd.revents().contains(PollFlags::OUT) {
                        s.writable(i);
                    }
                }
            }
        }
        Ok(())
    }
}
