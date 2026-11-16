//! One actual fixed cohort behind this Engine's sole Pipeline and carrier slot.
use super::*;
use crate::connection_records as connections;

const MAX_OWNERS: usize = 256;

struct RecoveredPoll<'a> {
    now: Tick,
    number: u64,
    out: &'a mut [u8],
    budget: &'a mut OutboundBudget,
    witnesses: &'a mut [receiver::UnitWitness],
}

#[derive(Clone, Copy)]
enum OutputClass {
    Source,
    Feedback,
    Unreliable,
}
#[derive(Clone, Copy)]
struct OutputMeta {
    owner: connections::OwnerId,
    class: OutputClass,
    emission: Emission,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum OutputWitness {
    Recovered(connections::PreparedOutput),
    Unreliable(connections::UnreliableOutput),
}

enum NativeWitness {
    Recovered(connections::NativeToken),
    Unreliable(connections::UnreliableNativeToken),
}
struct NativeHeld {
    witness: NativeWitness,
    deadline: Duration,
}

pub(super) struct Connections {
    pub(super) collection: connections::Collection,
    next_data: u16,
    raw_data_turn: [bool; MAX_OWNERS],
    raw_native_turn: [bool; MAX_OWNERS],
    output: Option<OutputMeta>,
    native: Option<NativeHeld>,
}

impl Connections {
    pub(super) fn plan(
        send: connections::Direction,
        receive: connections::Direction,
    ) -> Result<connections::storage::Plan, Error> {
        let send_overhead = send
            .compact
            .recovery
            .outer_overhead_bytes()
            .checked_sub(connections::route::HEADER_BYTES)
            .ok_or(Error::Geometry)?;
        let receive_overhead = receive
            .compact
            .recovery
            .outer_overhead_bytes()
            .checked_sub(connections::route::HEADER_BYTES)
            .ok_or(Error::Geometry)?;
        let config =
            connections::Config::from_directions(send, receive, send_overhead, receive_overhead)
                .map_err(Error::Connections)?;
        connections::storage::Plan::for_collection(config).map_err(Error::Connections)
    }

    pub(super) fn new(plan: connections::storage::Plan, context: Context) -> Result<Self, Error> {
        let collection = connections::Collection::new_reserved(
            plan,
            owner::recovery_context(context),
            connections::storage::Limits {
                capacity_bytes: plan.capacity_bytes(),
            },
        )
        .map_err(Error::Connections)?;
        Ok(Self {
            collection,
            next_data: 0,
            raw_data_turn: [true; MAX_OWNERS],
            raw_native_turn: [true; MAX_OWNERS],
            output: None,
            native: None,
        })
    }

    pub(super) fn offer(
        &mut self,
        now: Tick,
        metadata: pipeline::PacketMetadata,
        bytes: &[u8],
    ) -> Result<Option<ProfileIdentity>, Error> {
        let id = self
            .collection
            .owner(metadata.binding.channel)
            .map_err(Error::Connections)?;
        if self
            .collection
            .unreliable_eligible(metadata.classification, bytes)
        {
            let cap = metadata
                .timing
                .original_deadline
                .ok_or(Error::IngressPolicy)?;
            return self
                .collection
                .offer_unreliable(
                    id,
                    metadata.timing.received,
                    duration(now),
                    cap,
                    metadata.classification,
                    bytes,
                )
                .map(|identity| identity.map(ProfileIdentity::UnreliableNative))
                .map_err(Error::Connections);
        }
        self.collection
            .offer_recovered(id, metadata.classification.key, duration(now), bytes)
            .map(|identity| identity.map(ProfileIdentity::Connection))
            .map_err(Error::Connections)
    }

    pub(super) fn has_output(&self) -> bool {
        self.output.is_some()
    }

    pub(super) fn pending_output(&self) -> Result<Option<(Emission, OutputWitness)>, Error> {
        let Some(meta) = self.output else {
            return Ok(None);
        };
        let witness = match meta.class {
            OutputClass::Source => OutputWitness::Recovered(
                self.collection
                    .pending_data_output(meta.owner)
                    .map_err(Error::Connections)?
                    .ok_or(Error::Invariant)?,
            ),
            OutputClass::Feedback => OutputWitness::Recovered(
                self.collection
                    .pending_feedback_output(meta.owner)
                    .map_err(Error::Connections)?
                    .ok_or(Error::Invariant)?,
            ),
            OutputClass::Unreliable => OutputWitness::Unreliable(
                self.collection
                    .pending_unreliable_output(meta.owner)
                    .map_err(Error::Connections)?
                    .ok_or(Error::Invariant)?,
            ),
        };
        Ok(Some((meta.emission, witness)))
    }

    pub(super) fn confirm_output_at(
        &mut self,
        observed: Tick,
        accepted: Tick,
        witness: OutputWitness,
    ) -> Result<(), Error> {
        if self.pending_output()?.as_ref().map(|(_, actual)| actual) != Some(&witness) {
            return Err(Error::Token);
        }
        // The caller observed a whole write. Both wrapper and nested custody are
        // consumed once even if the subsequent timing result is terminal.
        self.output = None;
        match witness {
            OutputWitness::Recovered(token) => {
                self.collection
                    .confirm_output_at(duration(observed), duration(accepted), token)
            }
            OutputWitness::Unreliable(token) => self.collection.confirm_unreliable_output_at(
                duration(observed),
                duration(accepted),
                token,
            ),
        }
        .map_err(Error::Connections)
    }

    pub(super) fn poll(
        &mut self,
        now: Tick,
        number: u64,
        allow_data: bool,
        out: &mut [u8],
        budget: &mut OutboundBudget,
        witnesses: &mut [receiver::UnitWitness],
    ) -> Result<Option<Emission>, Error> {
        if self.output.is_some() {
            return Err(Error::Invariant);
        }
        // Select the exact maintained earliest feedback, not a synthetic fixed
        // feedback size or another owner's source sequence.
        if let Some((id, at, _)) = self
            .collection
            .feedback_opportunity()
            .map_err(Error::Connections)?
            && at <= duration(now)
            && let Some(emission) = self.poll_recovered(
                id,
                true,
                RecoveredPoll {
                    now,
                    number,
                    out: &mut *out,
                    budget: &mut *budget,
                    witnesses: &mut *witnesses,
                },
            )?
        {
            return Ok(Some(emission));
        }
        if !allow_data {
            return Ok(None);
        }
        let width = self.collection.configuration().owners;
        let mut index = self.next_data;
        // Exactly one finite cohort scan. This RR visits actual owners; it never
        // assigns a flow by modulo or creates a second recovery scheduler.
        for _ in 0..width {
            let id = self.collection.owner(index).map_err(Error::Connections)?;
            let next = if index + 1 == width { 0 } else { index + 1 };
            let raw_first = self.raw_data_turn[usize::from(index)];
            let selected = if raw_first {
                match self.poll_raw(id, now, number, out, budget)? {
                    Some(emission) => Some(emission),
                    None => self.poll_recovered(
                        id,
                        false,
                        RecoveredPoll {
                            now,
                            number,
                            out: &mut *out,
                            budget: &mut *budget,
                            witnesses: &mut *witnesses,
                        },
                    )?,
                }
            } else {
                match self.poll_recovered(
                    id,
                    false,
                    RecoveredPoll {
                        now,
                        number,
                        out: &mut *out,
                        budget: &mut *budget,
                        witnesses: &mut *witnesses,
                    },
                )? {
                    Some(emission) => Some(emission),
                    None => self.poll_raw(id, now, number, out, budget)?,
                }
            };
            if let Some(emission) = selected {
                self.next_data = next;
                self.raw_data_turn[usize::from(index)] =
                    emission.kind != EmissionKind::UnreliableNative;
                return Ok(Some(emission));
            }
            index = next;
        }
        Ok(None)
    }

    fn poll_raw(
        &mut self,
        id: connections::OwnerId,
        now: Tick,
        number: u64,
        out: &mut [u8],
        budget: &mut OutboundBudget,
    ) -> Result<Option<Emission>, Error> {
        if self.collection.configuration().send_unreliable.is_none() {
            return Ok(None);
        }
        let Some(token) = self
            .collection
            .poll_unreliable(id, duration(now), out, budget)
            .map_err(Error::Connections)?
        else {
            return Ok(None);
        };
        let emission = Emission {
            bytes: token.bytes(),
            kind: EmissionKind::UnreliableNative,
            wire_bytes: token.wire_bytes(),
            security_number: number,
            witnesses: 0,
        };
        self.output = Some(OutputMeta {
            owner: id,
            class: OutputClass::Unreliable,
            emission,
        });
        Ok(Some(emission))
    }

    fn poll_recovered(
        &mut self,
        id: connections::OwnerId,
        feedback: bool,
        input: RecoveredPoll<'_>,
    ) -> Result<Option<Emission>, Error> {
        let RecoveredPoll {
            now,
            number,
            out,
            budget,
            witnesses,
        } = input;
        let before = *budget;
        let selected = if feedback {
            self.collection
                .poll_feedback(id, duration(now), out, budget)
        } else {
            self.collection.poll_data(id, duration(now), out, budget)
        }
        .map_err(Error::Connections)?;
        let Some(token) = selected else {
            if *budget != before {
                return Err(Error::Invariant);
            }
            return Ok(None);
        };
        if before.packets.checked_sub(budget.packets) != Some(1)
            || before.wire_bytes.checked_sub(budget.wire_bytes) != Some(token.wire_bytes())
        {
            return Err(Error::Invariant);
        }
        let kind = match token.kind() {
            l2tunnel_reliable::RecordKind::Source if !feedback => {
                EmissionKind::Source(SourceForm::DirectArq)
            }
            l2tunnel_reliable::RecordKind::Feedback if feedback => EmissionKind::Feedback,
            _ => return Err(Error::Kind),
        };
        let packet = out.get(..token.bytes()).ok_or(Error::Invariant)?;
        let count = self
            .collection
            .outgoing_units(packet, witnesses)
            .map_err(Error::Connections)?;
        if matches!(kind, EmissionKind::Source(_)) == (count == 0) {
            return Err(Error::Invariant);
        }
        let emission = Emission {
            bytes: token.bytes(),
            kind,
            wire_bytes: token.wire_bytes(),
            security_number: number,
            witnesses: count,
        };
        self.output = Some(OutputMeta {
            owner: id,
            class: if feedback {
                OutputClass::Feedback
            } else {
                OutputClass::Source
            },
            emission,
        });
        Ok(Some(emission))
    }

    pub(super) fn inspect(&self, packet: &[u8]) -> Result<EmissionKind, Error> {
        Ok(
            match self
                .collection
                .inspect_authenticated(packet)
                .map_err(Error::Connections)?
            {
                connections::route::Class::Source => EmissionKind::Source(SourceForm::DirectArq),
                connections::route::Class::Feedback => EmissionKind::Feedback,
                connections::route::Class::UnreliableNative => EmissionKind::UnreliableNative,
            },
        )
    }

    pub(super) fn accept_recovered(
        &mut self,
        received: Tick,
        now: Tick,
        kind: EmissionKind,
        packet: &[u8],
    ) -> Result<(), Error> {
        if self.inspect(packet)? != kind {
            return Err(Error::Kind);
        }
        if kind == EmissionKind::UnreliableNative {
            return Err(Error::IngressPolicy);
        }
        self.collection
            .accept_authenticated_at(duration(received), duration(now), packet)
            .map_err(Error::Connections)
    }

    pub(super) fn accept_raw(
        &mut self,
        received: Tick,
        now: Tick,
        original_cap: Tick,
        packet: &[u8],
        classification: pipeline::Classification,
    ) -> Result<(), Error> {
        if self.inspect(packet)? != EmissionKind::UnreliableNative {
            return Err(Error::Kind);
        }
        self.collection
            .accept_classified_authenticated_at(
                duration(received),
                duration(now),
                duration(original_cap),
                packet,
                classification,
            )
            .map_err(Error::Connections)
    }

    pub(super) fn extract(
        &mut self,
        now: Tick,
        channel: receiver::ChannelId,
        work: usize,
        out: &mut [u8],
    ) -> Result<NativeStep, Error> {
        if self.native.is_some() {
            return Err(Error::Invariant);
        }
        let id = self
            .collection
            .owner(u16::from(channel.0))
            .map_err(Error::Connections)?;
        if self.raw_native_turn[usize::from(channel.0)]
            && let Some(step) = self.extract_raw(id, now, out)?
        {
            self.raw_native_turn[usize::from(channel.0)] = false;
            return Ok(step);
        }
        match self
            .collection
            .prepare_native(id, duration(now), work)
            .map_err(Error::Connections)?
        {
            connections::NativePreparation::Progress => Ok(NativeStep::Progress),
            connections::NativePreparation::Idle => {
                if let Some(step) = self.extract_raw(id, now, out)? {
                    self.raw_native_turn[usize::from(channel.0)] = false;
                    Ok(step)
                } else {
                    Ok(NativeStep::Idle)
                }
            }
            connections::NativePreparation::AlreadyPending(_) => Err(Error::Invariant),
            connections::NativePreparation::Ready(token) => {
                let pending = self
                    .collection
                    .pending_native(id)
                    .map_err(Error::Connections)?
                    .ok_or(Error::Invariant)?;
                let bytes = pending.bytes.len();
                out.get_mut(..bytes)
                    .ok_or(Error::Output { required: bytes })?
                    .copy_from_slice(pending.bytes);
                let step = NativeStep::Ready {
                    identity: ProfileIdentity::Connection(pending.identity),
                    bytes,
                    early: pending.early,
                };
                self.native = Some(NativeHeld {
                    witness: NativeWitness::Recovered(token),
                    deadline: pending.deadline,
                });
                self.raw_native_turn[usize::from(channel.0)] = true;
                Ok(step)
            }
        }
    }

    fn extract_raw(
        &mut self,
        id: connections::OwnerId,
        now: Tick,
        out: &mut [u8],
    ) -> Result<Option<NativeStep>, Error> {
        if self.collection.configuration().receive_unreliable.is_none() {
            return Ok(None);
        }
        let Some(token) = self
            .collection
            .prepare_unreliable_native(id, duration(now))
            .map_err(Error::Connections)?
        else {
            return Ok(None);
        };
        let pending = self
            .collection
            .pending_unreliable_native(id)
            .map_err(Error::Connections)?
            .ok_or(Error::Invariant)?;
        let bytes = pending.bytes.len();
        out.get_mut(..bytes)
            .ok_or(Error::Output { required: bytes })?
            .copy_from_slice(pending.bytes);
        let step = NativeStep::Ready {
            identity: ProfileIdentity::UnreliableNative(pending.identity),
            bytes,
            early: false,
        };
        self.native = Some(NativeHeld {
            witness: NativeWitness::Unreliable(token),
            deadline: pending.deadline,
        });
        Ok(Some(step))
    }

    pub(super) fn commit_native_at(&mut self, observed: Tick, accepted: Tick) -> Result<(), Error> {
        let held = self.native.take().ok_or(Error::Invariant)?;
        match held.witness {
            NativeWitness::Recovered(token) => {
                self.collection.commit_native(duration(observed), token)
            }
            NativeWitness::Unreliable(token) => self.collection.commit_unreliable_native_at(
                duration(observed),
                duration(accepted),
                token,
            ),
        }
        .map_err(Error::Connections)
    }

    pub(super) fn pending_deadline(&self) -> Option<Duration> {
        self.native.as_ref().map(|n| n.deadline)
    }

    pub(super) fn tick(&mut self, now: Tick) -> Result<(), Error> {
        for index in 0..self.collection.configuration().owners {
            let id = self.collection.owner(index).map_err(Error::Connections)?;
            self.collection
                .tick(id, duration(now))
                .map_err(Error::Connections)?;
        }
        Ok(())
    }

    pub(super) fn drained(&self) -> bool {
        self.output.is_none() && self.native.is_none() && self.collection.drained()
    }
}
