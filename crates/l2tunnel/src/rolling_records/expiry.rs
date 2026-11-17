//! Failure-time metadata only; current candidates do not establish causality.
use super::*;

/// Actual local check that returned a latched original-custody expiry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalOwner {
    /// Earliest authenticated input retained by the bounded ingress owner.
    Ingress,
    /// Original first-native-admission packing/codec stage.
    CodecStage,
    /// Prepared reconstructed native output awaiting physical acceptance.
    Native,
    /// Newly authenticated input already past its original caller/job cap.
    Incoming,
    /// Authenticated deferred feedback awaiting causal output ordering.
    DeferredFeedback,
}
/// A first actual failed local check, not an inference from a later sample.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalFailure {
    /// Actual owner/check that returned Expired.
    pub owner: LocalOwner,
    /// Original injected check tick.
    pub observed: Tick,
    /// Original deadline compared by that check.
    pub deadline: Tick,
    /// Existing authenticated Records number, if retained by this owner.
    pub records_number: Option<u64>,
    /// Exact reconstructed native record identity, when selected.
    pub native_record: Option<receiver::RecordIdentity>,
}
/// Exact earliest bounded input metadata; no input body is exposed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Input {
    /// Original authenticated arrival.
    pub received: Tick,
    /// Original queue job/caller cap.
    pub deadline: Tick,
    /// Existing full Records number, when supplied by the caller.
    pub records_number: Option<u64>,
}
/// Allocation-free selected Rolling/Research lifetime evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    /// Actual selected send stream; receive scope is held in the nested snapshot.
    pub send_scope: rolling::Scope,
    /// Last complete successful endpoint advance, not the failure occurrence.
    pub last_successful: Tick,
    /// Original endpoint error, if this layer latched it.
    pub terminal: Option<Error>,
    /// Exact failed local check if one was latched.
    pub local_failure: Option<LocalFailure>,
    /// Actual selected sending scheduler and encoder.
    pub send: rolling::expiry::Snapshot,
    /// Actual selected receiving scheduler and decoder.
    pub receive: rolling::expiry::Snapshot,
    /// Current earliest retained authenticated-input candidate.
    pub ingress: Option<Input>,
    /// Current original codec staging candidate.
    pub codec_stage: Option<Tick>,
    /// Current original prepared-native candidate and exact record identity.
    pub native: Option<(Tick, receiver::RecordIdentity)>,
    /// Existing exact source/repair/feedback output, if any, including Records number.
    pub prepared_output: Option<PreparedOutput>,
}
impl<P: RecoveryPolicy> Endpoint<P> {
    pub(super) fn earliest_input_expiry(&self) -> Option<Input> {
        self.ingress
            .as_ref()?
            .queue
            .iter()
            .map(|packet| {
                let input = packet.metadata();
                Input {
                    received: input.received,
                    deadline: input.deadline,
                    records_number: input.number,
                }
            })
            .min_by_key(|input| input.deadline)
    }
    pub(super) fn note_expiry(
        &mut self,
        owner: LocalOwner,
        now: Tick,
        deadline: Tick,
        records_number: Option<u64>,
        native_record: Option<receiver::RecordIdentity>,
    ) {
        self.expiry_failure.get_or_insert(LocalFailure {
            owner,
            observed: now,
            deadline,
            records_number,
            native_record,
        });
    }
    /// Inspect exact selected pure owners; no clock, payload scan or state change.
    /// Ingress observation scans at most the configured finite queue slots.
    /// Nonlatched input-refusal errors remain unavailable rather than fabricated.
    pub fn expiry_snapshot(&self) -> Snapshot {
        Snapshot {
            send_scope: self.send_rolling_scope,
            last_successful: self.now,
            terminal: self.failure,
            local_failure: self.expiry_failure,
            send: P::send_expiry(&self.sender),
            receive: P::receive_expiry(&self.incoming),
            ingress: self.earliest_input_expiry(),
            codec_stage: self.stage_deadline,
            native: self
                .prepared_native
                .map(|native| (native.deadline(), native.identity())),
            prepared_output: self.prepared_output,
        }
    }
}
