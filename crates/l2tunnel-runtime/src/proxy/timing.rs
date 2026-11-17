//! Opt-in bounded proxy custody diagnostics, never scheduling or deadline authority.
//!
//! Physical timestamps retain their existing meaning. Duration populations overlap;
//! their sums and quantiles must not be added. Publication-to-import is deliberately
//! unavailable: watch publication may race with another thread's actor import.
//! Gate samples are repeated gate-by-pending-entry observations, not one sample
//! per packet. Actor stages measure wall time (including wait and cleanup), not
//! backpressure; only a real selected-frame receipt-ring refusal opens a wait.
use super::transport::PhysicalWrite;
mod timeline;
use crate::buffer_metrics::{Class, Extent, Key, Lane, Occupancy, Reason, Site};
use std::io::{self, Write};
use std::sync::atomic::{AtomicU8, Ordering};
pub(crate) use timeline::Event as TimelineEvent;

static UNAVAILABLE: AtomicU8 = AtomicU8::new(0);
/// At most one sanitized notice per reason per process; never print paths or errors.
fn unavailable(bit: u8, reason: &'static str) {
    if UNAVAILABLE.fetch_or(bit, Ordering::Relaxed) & bit == 0 {
        eprintln!("L2TUNNEL_PROXY_TIMING_UNAVAILABLE reason={reason}");
    }
}
#[cfg(test)]
use std::path::PathBuf;
use tokio::time::Instant;

#[derive(Clone, Copy)]
pub(crate) enum Event {
    Timeline(TimelineEvent),
    Whole(PhysicalWrite),
    Imported {
        receipt: PhysicalWrite,
        at: Instant,
        terminal: bool,
    },
    Gate {
        at: Instant,
    },
    GateCandidate {
        ordinal: Option<u64>,
        admitted: Instant,
        physical: Option<PhysicalWrite>,
        at: Instant,
    },
    GateFailed,
    TerminalLedger,
    Callback {
        receipt: PhysicalWrite,
        at: Instant,
    },
    Censored {
        admitted: Instant,
        physical: Option<PhysicalWrite>,
        at: Instant,
    },
    Invalid,
}
#[derive(Clone, Copy)]
#[repr(usize)]
pub(crate) enum Stage {
    Wait,
    Import,
    BeforeCallback,
    Callback,
    UserAndNative,
    Publish,
    Yield,
}
const STAGE_NAMES: [&str; 7] = [
    "wait",
    "import",
    "before_callback",
    "callback",
    "user_and_native",
    "publish",
    "yield",
];
const NAMES: [&str; 10] = [
    "whole_accept_to_common_observe",
    "whole_common_observe_to_live_import",
    "whole_common_observe_to_terminal_import",
    "measured_admission_to_gate",
    "measured_common_observe_to_gate",
    "measured_import_to_gate",
    "measured_accept_to_successful_callback",
    "measured_common_observe_to_successful_callback",
    "censored_admission_age",
    "censored_common_observe_age",
];
#[derive(Clone, Copy, Default, Debug)]
struct Summary {
    samples: u64,
    sum_us: u64,
    max_us: u64,
}
impl Summary {
    fn sample(&mut self, start: Instant, end: Instant) -> bool {
        let Some(us) = end
            .checked_duration_since(start)
            .and_then(|d| u64::try_from(d.as_micros()).ok())
        else {
            return false;
        };
        add(&mut self.samples, 1) & add(&mut self.sum_us, us) & {
            self.max_us = self.max_us.max(us);
            true
        }
    }
}
#[derive(Clone, Copy)]
struct Imported {
    receipt: PhysicalWrite,
    at: Instant,
}
#[derive(Clone)]
pub(crate) struct Snapshot {
    pub(crate) owner_heap_bytes: usize,
    origin: Instant,
    values: [Summary; NAMES.len()],
    stages: [Summary; STAGE_NAMES.len()],
    stage_censored: [u64; STAGE_NAMES.len()],
    active: Option<(Stage, Instant)>,
    imported: [Option<Imported>; 2],
    timeline: timeline::Tail,
    held: u64,
    highwater: u64,
    refusals: u64,
    blocked_since: Option<Instant>,
    cleared: Summary,
    censored_blocked: Summary,
    gates: u64,
    failed_gates: u64,
    last_gate: Option<Instant>,
    gate_pending: u64,
    gate_physical: u64,
    import_unavailable: u64,
    censored_pending: u64,
    censored_physical: u64,
    terminal_ledger_observed: bool,
    invalid: bool,
    finished: bool,
}
struct State {
    core: crate::buffer_metrics::Observer,
    value: Snapshot,
}
/// Three machine words when disabled; the fixed arrays are never in a future.
pub(crate) struct Observer {
    state: Vec<State>,
}
impl Observer {
    pub(crate) fn from_environment() -> Self {
        let origin = Instant::now();
        match crate::buffer_metrics::Observer::from_environment_at("proxy_bridge", origin) {
            Ok(Some(core)) => Self::allocate(core, origin),
            Ok(None) => Self { state: Vec::new() },
            Err(_) => {
                unavailable(1, "observer_setup");
                Self { state: Vec::new() }
            }
        }
    }
    #[inline(never)]
    fn allocate(core: crate::buffer_metrics::Observer, origin: Instant) -> Self {
        let mut state = Vec::new();
        if state.try_reserve_exact(1).is_err() || state.capacity() != 1 {
            unavailable(2, "proxy_state_allocation");
            return Self { state: Vec::new() };
        }
        state.push(State {
            core,
            value: Snapshot {
                owner_heap_bytes: std::mem::size_of::<State>(),
                origin,
                values: [Summary::default(); NAMES.len()],
                stages: [Summary::default(); STAGE_NAMES.len()],
                stage_censored: [0; STAGE_NAMES.len()],
                active: None,
                imported: [None; 2],
                timeline: timeline::Tail::default(),
                held: 0,
                highwater: 0,
                refusals: 0,
                blocked_since: None,
                cleared: Summary::default(),
                censored_blocked: Summary::default(),
                gates: 0,
                failed_gates: 0,
                last_gate: None,
                gate_pending: 0,
                gate_physical: 0,
                import_unavailable: 0,
                censored_pending: 0,
                censored_physical: 0,
                terminal_ledger_observed: false,
                invalid: false,
                finished: false,
            },
        });
        Self { state }
    }
    pub(crate) fn enabled(&self) -> bool {
        !self.state.is_empty()
    }
    pub(crate) fn receipt_refused(&mut self, held: u64, now: Instant) {
        let Some(s) = self.state.first_mut().filter(|s| !s.value.finished) else {
            return;
        };
        let tick = s.core.elapsed_at(now);
        if let Some(tick) = tick {
            let _ = s.core.collector().sample(key(), tick, occupancy(held));
            let _ = s.core.collector().blocked(key(), Reason::ReceiptWait, tick);
        }
        let s = &mut s.value;
        s.held = held;
        s.highwater = s.highwater.max(held);
        s.invalid |= tick.is_none() || held < 2 || !add(&mut s.refusals, 1);
        s.blocked_since.get_or_insert(now);
    }
    pub(crate) fn receipt_cleared(&mut self, held: u64, now: Instant) {
        let Some(s) = self.state.first_mut().filter(|s| !s.value.finished) else {
            return;
        };
        let tick = s.core.elapsed_at(now);
        if let Some(tick) = tick {
            let _ = s.core.collector().sample(key(), tick, occupancy(held));
            if held < 2 {
                let _ = s
                    .core
                    .collector()
                    .progress(key(), Reason::ReceiptWait, tick);
            }
        }
        let s = &mut s.value;
        s.invalid |= tick.is_none();
        s.held = held;
        s.highwater = s.highwater.max(held);
        if held < 2
            && let Some(start) = s.blocked_since.take()
        {
            s.invalid |= !s.cleared.sample(start, now);
        }
    }
    pub(crate) fn enter(&mut self, stage: Stage, now: Instant) {
        let Some(s) = self.state.first_mut().filter(|s| !s.value.finished) else {
            return;
        };
        let s = &mut s.value;
        if let Some((old, start)) = s.active.replace((stage, now)) {
            s.invalid |= !s.stages[old as usize].sample(start, now);
        }
    }
    pub(crate) fn event(&mut self, event: Event) {
        let Some(s) = self.state.first_mut().filter(|s| !s.value.finished) else {
            return;
        };
        let s = &mut s.value;
        match event {
            Event::Timeline(event) => s.timeline.observe(event),
            Event::Whole(r) => {
                s.invalid |= !s.values[0].sample(r.accepted_at, r.observed_at);
                s.timeline.observe(TimelineEvent::Whole(r));
            }
            Event::Imported {
                receipt,
                at,
                terminal,
            } => {
                s.invalid |=
                    !s.values[if terminal { 2 } else { 1 }].sample(receipt.observed_at, at);
                if let Some(ordinal) = receipt.ordinal {
                    let index = ((ordinal.saturating_sub(1)) % 2) as usize;
                    if ordinal == 0 {
                        s.invalid = true;
                    } else {
                        s.imported[index] = Some(Imported { receipt, at });
                    }
                } else {
                    s.invalid = true;
                }
            }
            Event::Gate { at } => {
                s.invalid |= !add(&mut s.gates, 1);
                s.last_gate = Some(at);
                s.gate_pending = 0;
                s.gate_physical = 0;
            }
            Event::GateCandidate {
                ordinal,
                admitted,
                physical,
                at,
            } => {
                s.invalid |= !add(&mut s.gate_pending, 1) | !s.values[3].sample(admitted, at);
                if let Some(ordinal) = ordinal {
                    s.timeline.observe(TimelineEvent::Gate {
                        ordinal,
                        admitted,
                        at,
                    });
                }
                if let Some(r) = physical {
                    s.invalid |=
                        !add(&mut s.gate_physical, 1) | !s.values[4].sample(r.observed_at, at);
                    if let Some(imported) = s.imported.iter().flatten().find(|old| old.receipt == r)
                    {
                        s.invalid |= !s.values[5].sample(imported.at, at);
                    } else {
                        s.invalid |= !add(&mut s.import_unavailable, 1);
                    }
                }
            }
            Event::GateFailed => s.invalid |= !add(&mut s.failed_gates, 1),
            Event::Callback { receipt, at } => {
                s.invalid |= !s.values[6].sample(receipt.accepted_at, at)
                    | !s.values[7].sample(receipt.observed_at, at);
            }
            Event::Censored {
                admitted,
                physical,
                at,
            } => {
                s.invalid |= !add(&mut s.censored_pending, 1) | !s.values[8].sample(admitted, at);
                if let Some(r) = physical {
                    s.invalid |=
                        !add(&mut s.censored_physical, 1) | !s.values[9].sample(r.observed_at, at);
                }
            }
            Event::TerminalLedger => s.terminal_ledger_observed = true,
            Event::Invalid => s.invalid = true,
        }
    }
    pub(crate) fn finish(&mut self, now: Instant) {
        let Some(state) = self.state.first_mut().filter(|s| !s.value.finished) else {
            return;
        };
        let s = &mut state.value;
        if let Some(start) = s.blocked_since.take() {
            s.invalid |= !s.censored_blocked.sample(start, now);
        }
        if let Some((stage, start)) = s.active.take() {
            s.invalid |= !s.stages[stage as usize].sample(start, now)
                | !add(&mut s.stage_censored[stage as usize], 1);
        }
        s.finished = true;
        state.core.retain_proxy(s.clone());
        if let Some(tick) = state.core.elapsed_at(now) {
            state.core.finish_at(tick);
        }
    }
    #[cfg(test)]
    pub(crate) fn for_test(origin: Instant, path: PathBuf) -> io::Result<Self> {
        Ok(Self::allocate(
            crate::buffer_metrics::Observer::for_proxy_test(origin, path)?,
            origin,
        ))
    }
    #[cfg(test)]
    pub(crate) fn test_json(&self) -> io::Result<Vec<u8>> {
        let mut output = Vec::new();
        self.state
            .first()
            .ok_or_else(|| io::Error::other("diagnostic disabled"))?
            .value
            .write(&mut output)?;
        Ok(output)
    }
}
impl Drop for Observer {
    fn drop(&mut self) {
        self.finish(Instant::now());
    }
}
impl Snapshot {
    pub(crate) fn write(&self, out: &mut impl Write) -> io::Result<()> {
        write!(
            out,
            "{{\"schema\":1,\"kind\":\"proxy_timing\",\"pid\":{},\"invalid\":{},\"finished\":{},\"diagnostic_heap_bytes\":{},\"inline_bytes\":{},\"publication_to_import\":null,\"publication_note\":\"not_observed_watch_publication_may_race_with_actor_import\",\"durations\":{{",
            std::process::id(),
            self.invalid,
            self.finished,
            self.owner_heap_bytes,
            std::mem::size_of::<Observer>()
        )?;
        for (index, name) in NAMES.iter().enumerate() {
            if index != 0 {
                write!(out, ",")?;
            }
            write!(out, "\"{name}\":")?;
            summary(out, self.values[index])?;
        }
        write!(
            out,
            "}},\"receipt_ring\":{{\"capacity\":2,\"held\":{},\"sampled_highwater\":{},\"refusals\":{},\"cleared\":",
            self.held, self.highwater, self.refusals
        )?;
        summary(out, self.cleared)?;
        write!(out, ",\"censored\":")?;
        summary(out, self.censored_blocked)?;
        write!(
            out,
            "}},\"gates\":{},\"failed_gates\":{},\"last_gate_pending\":{},\"last_gate_with_physical\":{},\"import_time_unavailable\":{},\"censored_pending\":{},\"censored_with_physical\":{},\"terminal_ledger_observed\":{},\"stages\":{{",
            self.gates,
            self.failed_gates,
            self.gate_pending,
            self.gate_physical,
            self.import_unavailable,
            self.censored_pending,
            self.censored_physical,
            self.terminal_ledger_observed
        )?;
        for (index, name) in STAGE_NAMES.iter().enumerate() {
            if index != 0 {
                write!(out, ",")?;
            }
            write!(out, "\"{name}\":{{\"duration\":")?;
            summary(out, self.stages[index])?;
            write!(out, ",\"censored\":{}}}", self.stage_censored[index])?;
        }
        let elapsed = self
            .last_gate
            .and_then(|at| at.checked_duration_since(self.origin))
            .and_then(|d| u64::try_from(d.as_micros()).ok());
        write!(out, "}},\"last_gate_owner_micros\":")?;
        match elapsed {
            Some(value) => write!(out, "{value}")?,
            None => write!(out, "null")?,
        }
        write!(out, ",\"last_two_user_timelines\":")?;
        self.timeline.write(out, self.origin)?;
        writeln!(out, "}}")
    }
}
fn key() -> Key {
    Key {
        site: Site::ProxyPhysicalReceipt,
        lane: Lane::Shared,
        class: Class::User,
    }
}
fn occupancy(held: u64) -> Occupancy {
    Occupancy {
        items: Some(Extent {
            used: held,
            capacity: Some(2),
        }),
        bytes: None,
    }
}
fn summary(out: &mut impl Write, value: Summary) -> io::Result<()> {
    write!(
        out,
        "{{\"samples\":{},\"sum_us\":{},\"max_us\":{}}}",
        value.samples, value.sum_us, value.max_us
    )
}
fn add(value: &mut u64, increment: u64) -> bool {
    if let Some(next) = value.checked_add(increment) {
        *value = next;
        true
    } else {
        *value = u64::MAX;
        false
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn failed_gate_and_censor_never_become_successful_callbacks() -> io::Result<()> {
        let origin = Instant::now();
        let path = std::env::temp_dir().join(format!(
            "proxy-timing-{}-{}.bmetrics",
            std::process::id(),
            line!()
        ));
        let mut observer = Observer::for_test(origin, path.clone())?;
        let receipt = PhysicalWrite {
            ordinal: Some(1),
            generation: 1,
            identity: l2tunnel_codec::aligned_receiver::RecordIdentity {
                channel: l2tunnel_codec::aligned_receiver::ChannelId(0),
                record: l2tunnel_codec::aligned_receiver::RecordId(1),
            },
            accepted_at: origin + Duration::from_micros(44),
            observed_at: origin + Duration::from_micros(45),
        };
        observer.event(Event::Whole(receipt));
        observer.event(Event::Imported {
            receipt,
            at: origin + Duration::from_micros(46),
            terminal: false,
        });
        observer.event(Event::Gate {
            at: origin + Duration::from_micros(51),
        });
        observer.event(Event::GateCandidate {
            ordinal: Some(1),
            admitted: origin,
            physical: Some(receipt),
            at: origin + Duration::from_micros(51),
        });
        observer.event(Event::GateFailed);
        observer.event(Event::Censored {
            admitted: origin,
            physical: Some(receipt),
            at: origin + Duration::from_micros(52),
        });
        observer.finish(origin + Duration::from_micros(52));
        let value: serde_json::Value = serde_json::from_slice(&observer.test_json()?)?;
        assert_eq!(value["failed_gates"], 1);
        assert_eq!(value["durations"]["measured_import_to_gate"]["sum_us"], 5);
        assert_eq!(
            value["durations"]["measured_accept_to_successful_callback"]["samples"],
            0
        );
        assert_eq!(value["censored_with_physical"], 1);
        assert_eq!(value["terminal_ledger_observed"], false);
        assert!(value["publication_to_import"].is_null());
        assert_eq!(value["invalid"], false);
        drop(observer);
        std::fs::remove_file(path)?;
        Ok(())
    }
    #[test]
    fn repeated_ring_refusals_preserve_one_original_episode() -> io::Result<()> {
        let origin = Instant::now();
        let path = std::env::temp_dir().join(format!(
            "proxy-timing-{}-{}.bmetrics",
            std::process::id(),
            line!()
        ));
        let mut observer = Observer::for_test(origin, path.clone())?;
        observer.receipt_refused(2, origin);
        observer.receipt_refused(2, origin + Duration::from_micros(3));
        observer.receipt_cleared(1, origin + Duration::from_micros(7));
        observer.receipt_refused(2, origin + Duration::from_micros(9));
        observer.finish(origin + Duration::from_micros(11));
        let value: serde_json::Value = serde_json::from_slice(&observer.test_json()?)?;
        assert_eq!(value["receipt_ring"]["cleared"]["samples"], 1);
        assert_eq!(value["receipt_ring"]["cleared"]["sum_us"], 7);
        assert_eq!(value["receipt_ring"]["censored"]["sum_us"], 2);
        assert_eq!(value["receipt_ring"]["refusals"], 3);
        assert_eq!(
            std::mem::size_of::<Observer>(),
            3 * std::mem::size_of::<usize>()
        );
        drop(observer);
        std::fs::remove_file(path)?;
        Ok(())
    }
}
