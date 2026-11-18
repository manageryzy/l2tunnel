//! Optional identity/cause attachments to existing staged-source wait timing.
//! No protocol decisions, payloads, event queue or duplicate duration totals.
use l2tunnel_recovery::{AdmissionFlight, AdmissionSnapshot, PacketView, Retained};
use std::time::Duration;

/// Exact current codec unit and its enclosing originally admitted native record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Unit {
    /// Actual codec channel, not the later waiting Pipeline head's channel.
    pub channel: u16,
    /// Current context/body record identity.
    pub record: u64,
    /// Final native record identity returned by the successful codec admission.
    pub native_record: u64,
    /// Original cursor within this context/body record.
    pub offset: usize,
    /// True while this unit belongs to the context preceding the native body.
    pub context: bool,
}
/// Provenance supplied only by the actual successful native admission caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Native {
    /// Full original local FlowId; outer epoch/configuration scope remains required.
    pub flow: u64,
    /// Original packet arrival timestamp.
    pub received: Duration,
    /// Actual admission into the original Pipeline, not codec admission time.
    pub queued: Duration,
    /// Unchanged external original deadline, if present.
    pub deadline: Option<Duration>,
}
/// Existing operation in which actual send retention was released.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetirementKind {
    /// Valid input handling removed retained sources; parsing alone is insufficient.
    Input,
    /// Correlated physical completion released previously acknowledged custody.
    Physical,
}
/// Last actual release only; it does not claim every source was retired by this event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Retirement {
    /// Monotonic diagnostic event serial, never a wire or protocol number.
    pub serial: u64,
    /// Actual observer/injected operation time.
    pub observed: Duration,
    /// Original physical acceptance when this was a physical completion.
    pub accepted: Option<Duration>,
    /// Actual operation carrying the release.
    pub kind: RetirementKind,
    /// Number of removed retained sources.
    pub records: usize,
    /// Released actual source payload bytes.
    pub bytes: usize,
    /// Whether the full original operation returned success; later failure is preserved.
    pub operation_succeeded: bool,
}
/// Exact oldest retained source and actual physical-token availability at ACK apply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AckOldest {
    /// Original source state, not an inferred ACK or retransmission.
    pub flight: AdmissionFlight,
    /// Actual pending_transmission witness exists for this same source.
    pub physical_pending: bool,
}
pub(crate) type AckBoundary = l2tunnel_recovery::AckRetained;
/// Last successfully applied canonical ACK only; no packet or event history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ack {
    /// Diagnostic serial, independent of all wire packet/source numbers.
    pub serial: u64,
    /// Original authenticated input arrival supplied by the caller.
    pub received: Duration,
    /// Injected actual successful ACK-application time.
    pub observed: Duration,
    /// Validated cumulative prefix and selective bitmap from the original parser.
    pub prefix: u64,
    /// Validated selective bitmap, not a replay/authentication decision.
    pub bitmap: u64,
    /// Actual oldest retained source immediately before ACK application.
    pub before: Option<AckOldest>,
    /// Actual oldest retained source immediately after ACK application.
    pub after: Option<AckOldest>,
    /// Coverage of the exact pre-ACK oldest; None means no retained source existed.
    pub covers_before: Option<bool>,
    /// Actual removal of that same oldest source, distinct from coverage or held retry.
    pub retired_before: Option<bool>,
    /// Actual retained source-count decrease during this successful ACK apply.
    pub released_records: usize,
    /// Actual retained source-byte decrease, which can be zero for empty sources.
    pub released_bytes: usize,
}
/// Identity plus actual gate predicates on the first and latest refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pending {
    /// Exact recovery source awaiting its original first admission.
    pub source: u64,
    /// Exact immutable source payload length.
    pub bytes: usize,
    /// Original first refusal time, matching the existing staged-wait episode.
    pub since: Duration,
    /// Latest actual refusal time.
    pub last_refusal: Duration,
    /// Canonical codec stage; absent for unsupported multi-unit sources.
    pub unit: Option<Unit>,
    /// Earlier staged packet's actual native provenance; never a later refused head.
    pub native: Option<Native>,
    /// Actual gate predicates at the first refusal.
    pub first: AdmissionSnapshot,
    /// Actual gate predicates at the latest refusal.
    pub last: AdmissionSnapshot,
    /// Retirement serial observed when this same-source wait began.
    pub retirement_before: u64,
    /// Latest validated ACK serial already observed when this wait began.
    pub ack_before: u64,
}
/// One completed/censored identity; only last and maxima are retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Resolved {
    /// Full original source and optional codec/native provenance.
    pub pending: Pending,
    /// Actual same-source admission or terminal observation.
    pub at: Duration,
    /// True means unresolved at terminal, never successful admission.
    pub censored: bool,
    /// Latest actual retirement after this wait started, if one was observed.
    pub retirement: Option<Retirement>,
    /// Latest successfully applied ACK during this wait; contextual, not sole cause.
    pub ack: Option<Ack>,
}
/// Fixed optional detailed state, charged through the existing Reliable diagnostic plan.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Snapshot {
    /// Existing exact pending source, never replaced by a later packet.
    pub pending: Option<Pending>,
    /// Last successfully admitted or terminal-censored source.
    pub last_resolved: Option<Resolved>,
    /// Exact longest completed episode; ties retain the earlier identity.
    pub maximum_completed: Option<Resolved>,
    /// Exact longest censored episode; ties retain the earlier identity.
    pub maximum_censored: Option<Resolved>,
    /// Latest actual send-retention release, not an inferred ACK.
    pub last_retirement: Option<Retirement>,
    /// True only for the selected shared SelectiveRepeat feedback boundary.
    pub ack_supported: bool,
    /// Latest successfully applied ACK; None with support means none observed yet.
    pub last_ack: Option<Ack>,
    /// Terminal or snapshot boundary already finalized.
    pub terminal: Option<Duration>,
    /// Counter overflow, changed immutable identity or regressed observed clock.
    pub invalid: bool,
    pub(crate) native_stage: Option<(u16, u64, Native)>,
}
impl Snapshot {
    pub(crate) fn refused(&mut self, at: Duration, gate: AdmissionSnapshot) {
        if self.terminal.is_some() {
            return;
        }
        let pending = self.pending.get_or_insert(Pending {
            source: gate.next_source.0,
            bytes: gate.proposed_bytes,
            since: at,
            last_refusal: at,
            unit: None,
            native: None,
            first: gate,
            last: gate,
            retirement_before: self.last_retirement.map_or(0, |v| v.serial),
            ack_before: self.last_ack.map_or(0, |v| v.serial),
        });
        if pending.source != gate.next_source.0
            || pending.bytes != gate.proposed_bytes
            || at < pending.last_refusal
        {
            self.invalid = true;
            return;
        }
        pending.last_refusal = at;
        pending.last = gate;
    }
    pub(crate) fn unit(&mut self, source: u64, bytes: usize, unit: Unit) {
        if let Some(pending) = &mut self.pending {
            if pending.source != source
                || pending.bytes != bytes
                || pending.unit.is_some_and(|old| old != unit)
            {
                self.invalid = true;
                return;
            }
            pending.unit = Some(unit);
            if let Some((channel, record, native)) = self.native_stage
                && channel == unit.channel
                && record == unit.native_record
            {
                pending.native = Some(native);
            }
        }
    }
    pub(crate) fn native(&mut self, channel: u16, native_record: u64, value: Native) {
        self.native_stage = Some((channel, native_record, value));
        if let Some(pending) = &mut self.pending
            && pending
                .unit
                .is_some_and(|u| u.channel == channel && u.native_record == native_record)
        {
            if pending.native.is_some_and(|old| old != value) {
                self.invalid = true;
                return;
            }
            pending.native = Some(value);
        }
    }
    pub(crate) fn admitted(&mut self, source: u64, bytes: usize, at: Duration) {
        if let Some(pending) = self.pending {
            if pending.source != source || pending.bytes != bytes {
                self.invalid = true;
                return;
            }
            self.resolve(at, false);
        }
    }
    fn resolve(&mut self, at: Duration, censored: bool) {
        let Some(pending) = self.pending else {
            return;
        };
        if at < pending.last_refusal {
            self.invalid = true;
            return;
        }
        let resolved = Resolved {
            pending,
            at,
            censored,
            retirement: self
                .last_retirement
                .filter(|v| v.serial > pending.retirement_before),
            ack: self.last_ack.filter(|v| v.serial > pending.ack_before),
        };
        let maximum = if censored {
            &mut self.maximum_censored
        } else {
            &mut self.maximum_completed
        };
        if maximum.is_none_or(|old| at - pending.since > old.at - old.pending.since) {
            *maximum = Some(resolved);
        }
        self.last_resolved = Some(resolved);
        self.pending = None;
    }
    pub(crate) fn censor(&mut self, at: Duration) {
        if self.terminal.is_none() {
            self.resolve(at, true);
            self.terminal = Some(at);
        }
    }
    pub(crate) fn ack(
        &mut self,
        view: PacketView<'_>,
        before: Option<AckBoundary>,
        after: Option<AckBoundary>,
        received: Duration,
        observed: Duration,
    ) {
        if self.terminal.is_some() {
            return;
        }
        let PacketView::Ack { prefix, bitmap } = view else {
            self.invalid = true;
            return;
        };
        let Some((before, after)) = before.zip(after) else {
            self.invalid = true;
            return;
        };
        let (before_pending, after_pending) = (before.oldest_pending, after.oldest_pending);
        if !self.ack_supported
            || received > observed
            || self.last_ack.is_some_and(|v| observed < v.observed)
            || before.oldest.is_some() != before_pending.is_some()
            || after.oldest.is_some() != after_pending.is_some()
        {
            self.invalid = true;
            return;
        }
        let Some(serial) = self.last_ack.map_or(0, |v| v.serial).checked_add(1) else {
            self.invalid = true;
            return;
        };
        let Some((released_records, released_bytes)) = before
            .records
            .checked_sub(after.records)
            .zip(before.bytes.checked_sub(after.bytes))
        else {
            self.invalid = true;
            return;
        };
        self.last_ack = Some(Ack {
            serial,
            received,
            observed,
            prefix,
            bitmap,
            before: before
                .oldest
                .zip(before_pending)
                .map(|(flight, physical_pending)| AckOldest {
                    flight,
                    physical_pending,
                }),
            after: after
                .oldest
                .zip(after_pending)
                .map(|(flight, physical_pending)| AckOldest {
                    flight,
                    physical_pending,
                }),
            covers_before: before.oldest.and_then(|v| view.acknowledges(v.source)),
            retired_before: before
                .oldest
                .map(|v| after.oldest.is_none_or(|next| next.source != v.source)),
            released_records,
            released_bytes,
        });
    }
    pub(crate) fn retired(
        &mut self,
        before: Retained,
        after: Retained,
        observed: Duration,
        accepted: Option<Duration>,
        kind: RetirementKind,
        operation_succeeded: bool,
    ) {
        if after.send_records >= before.send_records && after.send_bytes >= before.send_bytes {
            return;
        }
        let Some(records) = before.send_records.checked_sub(after.send_records) else {
            self.invalid = true;
            return;
        };
        let Some(bytes) = before.send_bytes.checked_sub(after.send_bytes) else {
            self.invalid = true;
            return;
        };
        let Some(serial) = self.last_retirement.map_or(0, |v| v.serial).checked_add(1) else {
            self.invalid = true;
            return;
        };
        if self.last_retirement.is_some_and(|v| observed < v.observed) {
            self.invalid = true;
        }
        self.last_retirement = Some(Retirement {
            serial,
            observed,
            accepted,
            kind,
            records,
            bytes,
            operation_succeeded,
        });
    }
}
