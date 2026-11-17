//! Read-only original-owner setup progress, without payloads or key material.
use super::*;

/// Actual packet-transition step; this is not an authentication capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupStage {
    /// Original TCP, TLS/member authentication and lane pairing.
    Pairing,
    /// Prepare request/reply over the original TLS stream.
    PrepareExchange,
    /// Armed exchange after local packet gate installation.
    ArmedExchange,
    /// Seal terminal TLS record exchange.
    SealExchange,
    /// Frozen TLS and maintained TCP drain before unique I/O transfer.
    HandoffDrain,
    /// Raw Hello/Commit/CommitAck exchange after unique I/O transfer.
    PacketConfirmation,
    /// An internal stage value is unavailable; never substitute a successful stage.
    Unavailable,
}

/// Actual inner pairing step, absent after that owner has been transferred.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupPairStage {
    /// The original TCP/TLS/member owner has not completed on every lane.
    Authentication,
    /// Server proposal is being written or read.
    Proposal,
    /// Client response is being written or read.
    Response,
    /// Server confirmation is being written or read.
    Confirmation,
    /// An internal phase value is unavailable.
    Unavailable,
}

/// Local observation boundary, independent of peer knowledge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupOutcome {
    /// The setup still owns its unfinished work at this observation.
    Pending,
    /// The setup returned an error and released original owners.
    Failed,
    /// The setup returned the actual ready carrier.
    Ready,
}

/// Available gate counters; no ciphertext, tuple, key or transcript is included.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetupGateSnapshot {
    /// The original stream observed the installation marker.
    pub installed: bool,
    /// The authenticated transition permits a peer Hello.
    pub hello_allowed: bool,
    /// The packet gate is active.
    pub active: bool,
    /// A first gate fault is retained.
    pub faulted: bool,
    /// Accepted gate receive packets at the existing counter boundary.
    pub received_packets: u64,
    /// Accepted gate receive IP bytes at the existing counter boundary.
    pub received_bytes: u64,
    /// Sent IP packets at the existing counter boundary.
    pub sent_packets: u64,
    /// Sent IP bytes at the existing counter boundary.
    pub sent_bytes: u64,
    /// Existing structural/authentication gate rejections.
    pub rejected_packets: u64,
    /// Retained incoming gate cells.
    pub queued_packets: usize,
}

/// Actual detached-lane transition flags, absent before I/O transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetupTransitionSnapshot {
    /// A complete packet still awaits its physical send boundary.
    pub pending_packet: bool,
    /// The actual PacketIo retains a previously refused packet.
    pub packet_io_pending: bool,
    /// Existing transition copy counter, without resetting its retry policy.
    pub copies: u16,
    /// A Hello has physically completed.
    pub sent_hello: bool,
    /// A Commit has physically completed.
    pub sent_commit: bool,
    /// A CommitAck has physically completed.
    pub sent_ack: bool,
    /// A peer Hello was accepted.
    pub hello: bool,
    /// The peer Hello has been answered.
    pub hello_reply: bool,
    /// A peer Commit was accepted.
    pub commit: bool,
    /// A peer CommitAck was accepted.
    pub ack: bool,
}

/// One real lane. Missing observations remain absent rather than zero-filled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetupLaneSnapshot {
    /// Last published maintained TCP/bridge progress, if still available.
    pub bridge: Option<super::super::super::super::SwitchStatus>,
    /// Exact TLS message progress, if that owner has been created or frozen.
    pub messages: Option<MessageStatus>,
    /// Gate state, absent if its diagnostic lock is unavailable.
    pub gate: Option<SetupGateSnapshot>,
    /// Current TLS control has been staged; absent outside TLS control steps.
    pub control_staged: Option<bool>,
    /// Current TLS control has been received; absent outside TLS control steps.
    pub control_received: Option<bool>,
    /// A frozen TLS owner remains retained locally.
    pub frozen: bool,
    /// Detached packet transition observations, absent before unique transfer.
    pub transition: Option<SetupTransitionSnapshot>,
}

/// Bounded local progress, never a freeze proof or permission to reuse an owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetupSnapshot {
    /// Snapshot time, frozen at the first terminal observation.
    pub observed_at: Instant,
    /// Original immutable setup deadline.
    pub deadline: Instant,
    /// Actual local role.
    pub client: bool,
    /// Current outer setup step.
    pub stage: SetupStage,
    /// Inner pair phase, absent after pairing has transferred.
    pub pair_stage: Option<SetupPairStage>,
    /// Local pending, failed or ready boundary.
    pub outcome: SetupOutcome,
    /// Actual lane count, one for Full and two for Half.
    pub lanes: [Option<SetupLaneSnapshot>; 2],
}

impl<I: PacketIo + Send + 'static> PacketSetup<'_, I> {
    /// Copy actual scalar progress without polling I/O, advancing time, consuming
    /// a message or allocating. Failure retains the first pre-destruction snapshot;
    /// successful completion retains the actual ready boundary. A caller cancelling
    /// this future can sample it before drop to observe the still-pending owner.
    pub fn diagnostic_snapshot(&self) -> SetupSnapshot {
        self.terminal_setup
            .first()
            .copied()
            .unwrap_or_else(|| self.setup_snapshot(SetupOutcome::Pending))
    }

    pub(super) fn retain_setup_snapshot(&mut self, outcome: SetupOutcome) {
        if self.terminal_setup.is_empty() {
            let value = self.setup_snapshot(outcome);
            self.terminal_setup.push(value);
        }
    }

    fn setup_snapshot(&self, outcome: SetupOutcome) -> SetupSnapshot {
        let pair = self
            .setup
            .as_ref()
            .and_then(PairSetup::status)
            .or_else(|| self.paired.as_ref().map(PairedRaw::status));
        let pair_stage = self.setup.as_ref().map(|setup| match setup.phase {
            0 => SetupPairStage::Authentication,
            1 => SetupPairStage::Proposal,
            2 => SetupPairStage::Response,
            3 => SetupPairStage::Confirmation,
            _ => SetupPairStage::Unavailable,
        });
        SetupSnapshot {
            observed_at: Instant::now(),
            deadline: self.deadline,
            client: self.client,
            stage: match self.stage {
                0 => SetupStage::Pairing,
                1 => SetupStage::PrepareExchange,
                2 => SetupStage::ArmedExchange,
                3 => SetupStage::SealExchange,
                4 => SetupStage::HandoffDrain,
                5 => SetupStage::PacketConfirmation,
                _ => SetupStage::Unavailable,
            },
            pair_stage,
            outcome,
            lanes: std::array::from_fn(|index| {
                if index >= self.count {
                    return None;
                }
                let detached = self.detached[index].as_ref().or_else(|| {
                    self.carrier
                        .as_ref()
                        .and_then(|carrier| carrier.lanes[index].as_ref())
                });
                let gate = self.states[index].as_ref().and_then(|state| {
                    state.try_lock().ok().map(|state| SetupGateSnapshot {
                        installed: state.installed,
                        hello_allowed: state.hello_allowed,
                        active: state.active,
                        faulted: state.fault.is_some(),
                        received_packets: state.received_packets,
                        received_bytes: state.received_bytes,
                        sent_packets: state.sent_packets,
                        sent_bytes: state.sent_bytes,
                        rejected_packets: state.rejected_packets,
                        queued_packets: state.incoming.len(),
                    })
                });
                Some(SetupLaneSnapshot {
                    bridge: pair.as_ref().and_then(|pair| pair.bridges[index]),
                    messages: self.frozen[index]
                        .as_ref()
                        .map(FrozenTls::status)
                        .or_else(|| detached.map(|lane| lane._frozen.status()))
                        .or_else(|| pair.as_ref().and_then(|pair| pair.messages[index])),
                    gate,
                    control_staged: (1..=3).contains(&self.stage).then_some(self.staged[index]),
                    control_received: (1..=3)
                        .contains(&self.stage)
                        .then_some(self.received[index]),
                    frozen: self.frozen[index].is_some() || detached.is_some(),
                    transition: detached.map(|lane| SetupTransitionSnapshot {
                        pending_packet: lane.pending.is_some(),
                        packet_io_pending: lane.io.pending(),
                        copies: lane.copies,
                        sent_hello: lane.sent_hello,
                        sent_commit: lane.sent_commit,
                        sent_ack: lane.sent_ack,
                        hello: lane.hello,
                        hello_reply: lane.hello_reply,
                        commit: lane.commit,
                        ack: lane.ack,
                    }),
                })
            }),
        }
    }
}
