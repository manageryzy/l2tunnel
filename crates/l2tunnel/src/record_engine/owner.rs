use super::connections::Connections;
use super::{
    Context, Emission, EmissionKind, Error, NativeStep, ProfileIdentity, SourceForm, Tick, aligned,
    configuration, duration, pipeline, receiver, swift,
};
use crate::rolling_records;
use l2tunnel_recovery::{EndpointRole, RecoveryContext};
use l2tunnel_reliable::{OutboundBudget, RecordKind};
use swift::records;

#[allow(clippy::large_enum_variant)] // Exactly one actual owner; no extra heap indirection or unused engines.
pub(super) enum Owner {
    Swift(swift::storage::Owned),
    Aligned(aligned::Endpoint),
    Packed(aligned::packed::Endpoint),
    Rolling(rolling_records::Endpoint),
    Research(crate::research_records::Endpoint),
    Connections(Connections),
}

impl Owner {
    pub(super) fn enable_carrier_confirmation(
        &mut self,
        configuration: &configuration::Configuration,
    ) -> Result<(), Error> {
        // Compact constructors always enable physical custody before publishing
        // the owner. Legacy constructors require this explicit selection once.
        match configuration.descriptor().profile() {
            configuration::Profile::AlignedCompact { .. } => {
                return if matches!(self, Self::Aligned(_)) {
                    Ok(())
                } else {
                    Err(Error::Invariant)
                };
            }
            configuration::Profile::PackedCompact { .. } => {
                return if matches!(self, Self::Packed(_)) {
                    Ok(())
                } else {
                    Err(Error::Invariant)
                };
            }
            configuration::Profile::PerConnectionCompact { .. } => {
                return if matches!(self, Self::Connections(_)) {
                    Ok(())
                } else {
                    Err(Error::Invariant)
                };
            }
            _ => {}
        }
        match self {
            Self::Aligned(endpoint) => endpoint
                .enable_physical_send_confirmation()
                .map_err(Error::Aligned),
            Self::Packed(endpoint) => endpoint
                .enable_physical_send_confirmation()
                .map_err(Error::Aligned),
            Self::Swift(_) | Self::Rolling(_) | Self::Research(_) | Self::Connections(_) => Ok(()),
        }
    }
    pub(super) fn storage_heap(&self) -> Option<(usize, usize)> {
        match self {
            Self::Swift(owned) => {
                let usage = owned.usage();
                Some((usage.heap_bytes, usage.allocations))
            }
            Self::Aligned(endpoint) => endpoint
                .storage_usage()
                .map(|u| (u.capacity_bytes, u.allocations)),
            Self::Packed(endpoint) => endpoint
                .storage_usage()
                .map(|u| (u.capacity_bytes, u.allocations)),
            Self::Connections(owner) => {
                let usage = owner.collection.storage_usage();
                Some((usage.heap_bytes, usage.allocations))
            }
            Self::Rolling(endpoint) => endpoint
                .storage_usage()
                .map(|u| (u.capacity_bytes, u.allocations)),
            Self::Research(endpoint) => endpoint
                .storage_usage()
                .map(|u| (u.capacity_bytes, u.allocations)),
        }
    }
    pub(super) fn new(
        configuration: &configuration::Configuration,
        context: Context,
    ) -> Result<Self, Error> {
        if let configuration::Profile::Research { config, stream } =
            configuration.descriptor().profile()
        {
            return crate::research_records::Endpoint::new(*config, context, *stream, Tick(0))
                .map(Self::Research)
                .map_err(Error::Rolling);
        }
        if let configuration::Profile::Rolling { config, stream } =
            configuration.descriptor().profile()
        {
            return rolling_records::Endpoint::new(*config, context, *stream, Tick(0))
                .map(Self::Rolling)
                .map_err(Error::Rolling);
        }
        if let configuration::Profile::RollingCopies {
            config,
            stream,
            copies,
        } = configuration.descriptor().profile()
        {
            return rolling_records::Endpoint::new_with_copies(
                *config,
                context,
                *stream,
                Tick(0),
                *copies,
            )
            .map(Self::Rolling)
            .map_err(Error::Rolling);
        }
        if let configuration::Profile::PerConnectionCompact { .. } =
            configuration.descriptor().profile()
        {
            let local = configuration.descriptor().local(context.role);
            let (
                configuration::DirectionProfile::PerConnectionCompact(send),
                configuration::DirectionProfile::PerConnectionCompact(receive),
            ) = (local.send().profile(), local.receive().profile())
            else {
                return Err(Error::Configuration);
            };
            return Connections::new(Connections::plan(*send, *receive)?, context)
                .map(Self::Connections);
        }
        let local = configuration.descriptor().local(context.role);
        let recovery = recovery_context(context);
        match (local.send().profile(), local.receive().profile()) {
            (
                configuration::DirectionProfile::Swift(send),
                configuration::DirectionProfile::Swift(receive),
            ) => {
                let plan =
                    swift::storage::Plan::for_engine(*send, *receive).map_err(Error::Storage)?;
                let capacity_bytes = std::mem::size_of::<swift::storage::Owned>()
                    .checked_add(plan.capacity_bytes())
                    .ok_or(Error::Arithmetic)?;
                swift::storage::Owned::new(plan, swift::storage::Limits { capacity_bytes })
                    .map(Self::Swift)
                    .map_err(Error::Storage)
            }
            (
                configuration::DirectionProfile::Aligned(send),
                configuration::DirectionProfile::Aligned(receive),
            ) => aligned::Endpoint::new_duplex(*send, *receive, recovery)
                .map(Self::Aligned)
                .map_err(Error::Aligned),
            (
                configuration::DirectionProfile::Packed(send),
                configuration::DirectionProfile::Packed(receive),
            ) => aligned::packed::Endpoint::new_duplex(*send, *receive, recovery)
                .map(Self::Packed)
                .map_err(Error::Aligned),
            (
                configuration::DirectionProfile::AlignedCompact(send),
                configuration::DirectionProfile::AlignedCompact(receive),
            ) => {
                let plan = aligned::compact_storage::Plan::for_duplex(*send, *receive)
                    .map_err(Error::AlignedStorage)?;
                aligned::Endpoint::new_compact_duplex_reserved(
                    *send,
                    *receive,
                    recovery,
                    aligned::storage::Limits {
                        capacity_bytes: plan.capacity_bytes(),
                    },
                )
                .map(Self::Aligned)
                .map_err(Error::AlignedStorage)
            }
            (
                configuration::DirectionProfile::PackedCompact(send),
                configuration::DirectionProfile::PackedCompact(receive),
            ) => {
                let plan = aligned::compact_storage::Plan::for_packed_duplex(*send, *receive)
                    .map_err(Error::AlignedStorage)?;
                aligned::packed::Endpoint::new_compact_duplex_reserved(
                    *send,
                    *receive,
                    recovery,
                    aligned::storage::Limits {
                        capacity_bytes: plan.capacity_bytes(),
                    },
                )
                .map(Self::Packed)
                .map_err(Error::AlignedStorage)
            }
            _ => Err(Error::Configuration),
        }
    }

    pub(super) fn offer_queued(
        &mut self,
        now: Tick,
        metadata: pipeline::PacketMetadata,
        bytes: &[u8],
    ) -> Result<Option<ProfileIdentity>, Error> {
        if metadata.classification.kind == l2tunnel_packet::PacketKind::ProxyRecord
            && metadata
                .timing
                .original_deadline
                .is_none_or(|deadline| duration(now) >= deadline)
        {
            return Err(Error::Expired);
        }
        match self {
            Self::Connections(owner) => owner.offer(now, metadata, bytes),
            _ => self.offer(now, metadata.binding.channel, bytes),
        }
    }

    pub(super) fn offer(
        &mut self,
        now: Tick,
        channel: u16,
        bytes: &[u8],
    ) -> Result<Option<ProfileIdentity>, Error> {
        match self {
            Self::Connections(_) => Err(Error::IngressPolicy),
            Self::Swift(owned) => {
                let channel =
                    records::ChannelId::new(usize::from(channel)).ok_or(Error::Configuration)?;
                match owned
                    .entry()
                    .offer_on_channel_identified(now.0, channel, bytes)
                    .map_err(Error::Swift)?
                {
                    records::IdentifiedAdmission::Accepted(identity) => {
                        Ok(Some(ProfileIdentity::Swift(identity)))
                    }
                    records::IdentifiedAdmission::Full => Ok(None),
                    records::IdentifiedAdmission::PacketSize => Err(Error::PacketSize),
                }
            }
            Self::Aligned(endpoint) => {
                let channel =
                    receiver::ChannelId(u8::try_from(channel).map_err(|_| Error::Configuration)?);
                match endpoint.enqueue_identified(channel, bytes, duration(now)) {
                    Ok(identity) => Ok(Some(ProfileIdentity::Aligned(identity))),
                    Err(aligned::Error::Busy) => Ok(None),
                    Err(error) => Err(Error::Aligned(error)),
                }
            }
            Self::Packed(endpoint) => {
                let channel =
                    receiver::ChannelId(u8::try_from(channel).map_err(|_| Error::Configuration)?);
                match endpoint.enqueue_identified(channel, bytes, duration(now)) {
                    Ok(identity) => Ok(Some(ProfileIdentity::Packed(identity))),
                    Err(aligned::Error::Busy) => Ok(None),
                    Err(error) => Err(Error::Aligned(error)),
                }
            }
            Self::Rolling(endpoint) => endpoint
                .enqueue_admitted_identified(now, channel, bytes)
                .map(|identity| identity.map(ProfileIdentity::Rolling))
                .map_err(Error::Rolling),
            Self::Research(endpoint) => endpoint
                .enqueue_admitted_identified(now, channel, bytes)
                .map(|identity| identity.map(ProfileIdentity::Research))
                .map_err(Error::Rolling),
        }
    }

    #[allow(clippy::too_many_arguments)] // Exact parent poll inputs plus the already validated directional overhead.
    pub(super) fn poll(
        &mut self,
        now: Tick,
        number: u64,
        allow_data: bool,
        out: &mut [u8],
        budget: &mut OutboundBudget,
        witnesses: &mut [receiver::UnitWitness],
        overhead: usize,
        feedback_overhead: usize,
    ) -> Result<Option<Emission>, Error> {
        match self {
            Self::Connections(owner) => owner.poll(now, number, allow_data, out, budget, witnesses),
            Self::Swift(owned) => {
                let maximum = owned.engine().send_config().codec.datagram_bytes;
                if out.len() < maximum {
                    return Err(Error::Output { required: maximum });
                }
                let body_limit = budget.wire_bytes.saturating_sub(overhead);
                let feedback_limit = budget.wire_bytes.saturating_sub(feedback_overhead);
                if budget.packets == 0 {
                    return Ok(None);
                }
                let mut entry = owned.entry();
                let Some(emission) = entry
                    .poll_emission_with_limits(
                        now.0,
                        records::RecordNumber(number),
                        allow_data,
                        body_limit,
                        feedback_limit,
                    )
                    .map_err(Error::Swift)?
                else {
                    return Ok(None);
                };
                let bytes = emission.body().len();
                let selected_overhead = if emission.kind() == records::EmissionKind::Feedback {
                    feedback_overhead
                } else {
                    overhead
                };
                if bytes > maximum || bytes > budget.wire_bytes.saturating_sub(selected_overhead) {
                    return Err(Error::Invariant);
                }
                let kind = match emission.kind() {
                    records::EmissionKind::Source => EmissionKind::Source(SourceForm::Swift),
                    records::EmissionKind::Repair => EmissionKind::Repair,
                    records::EmissionKind::Feedback => EmissionKind::Feedback,
                };
                // The actual complete body fit was checked before feedback or
                // sender state committed, using the one shared wire allowance.
                let wire_bytes = bytes
                    .checked_add(selected_overhead)
                    .ok_or(Error::Arithmetic)?;
                out[..bytes].copy_from_slice(emission.body());
                budget.packets -= 1;
                budget.wire_bytes -= wire_bytes;
                Ok(Some(Emission {
                    bytes,
                    kind,
                    wire_bytes,
                    security_number: number,
                    witnesses: 0,
                }))
            }
            Self::Aligned(endpoint) => poll_endpoint(
                endpoint,
                Poll {
                    now,
                    number,
                    allow_data,
                    out,
                    budget,
                    witnesses,
                    overhead,
                    feedback_overhead,
                },
            ),
            Self::Packed(endpoint) => poll_endpoint(
                endpoint,
                Poll {
                    now,
                    number,
                    allow_data,
                    out,
                    budget,
                    witnesses,
                    overhead,
                    feedback_overhead,
                },
            ),
            Self::Rolling(endpoint) => {
                // Only explicit Engine::step budgets perform GF work. This
                // zero-work service pumps already-ready codec/source ownership.
                endpoint
                    .step(now, crate::fec::rolling::WorkBudget::default())
                    .map_err(Error::Rolling)?;
                endpoint
                    .prepare_output(now, number, allow_data, out, budget, witnesses)
                    .map(|prepared| {
                        prepared.map(|p| Emission {
                            bytes: p.bytes,
                            kind: p.kind,
                            wire_bytes: p.wire_bytes,
                            security_number: p.security_number,
                            witnesses: p.witnesses,
                        })
                    })
                    .map_err(Error::Rolling)
            }
            Self::Research(endpoint) => {
                // Only explicit Engine::step budgets perform GF work. This
                // zero-work service pumps already-ready codec/source ownership.
                endpoint
                    .step(now, crate::fec::rolling::WorkBudget::default())
                    .map_err(Error::Rolling)?;
                endpoint
                    .prepare_output(now, number, allow_data, out, budget, witnesses)
                    .map(|prepared| {
                        prepared.map(|p| Emission {
                            bytes: p.bytes,
                            kind: p.kind,
                            wire_bytes: p.wire_bytes,
                            security_number: p.security_number,
                            witnesses: p.witnesses,
                        })
                    })
                    .map_err(Error::Rolling)
            }
        }
    }

    pub(super) fn accept_at(
        &mut self,
        received: Tick,
        now: Tick,
        number: u64,
        kind: EmissionKind,
        body: &mut [u8],
    ) -> Result<(), Error> {
        match self {
            Self::Connections(owner) => owner.accept_recovered(received, now, kind, body),
            Self::Swift(owned) => {
                let observed = match *body.first().ok_or(Error::PacketSize)? & swift::KIND_MASK {
                    swift::KIND_SOURCE => EmissionKind::Source(SourceForm::Swift),
                    swift::KIND_REPAIR => EmissionKind::Repair,
                    swift::KIND_FEEDBACK => EmissionKind::Feedback,
                    _ => return Err(Error::Kind),
                };
                if observed != kind {
                    return Err(Error::Kind);
                }
                owned
                    .entry()
                    .accept(now.0, records::RecordNumber(number), body)
                    .map_err(Error::Swift)
            }
            Self::Aligned(endpoint) => {
                if emission_kind(endpoint.inspect_peer(body).map_err(Error::Aligned)?) != kind {
                    return Err(Error::Kind);
                }
                endpoint
                    .receive_authenticated_at(body, duration(received), duration(now))
                    .map_err(Error::Aligned)
            }
            Self::Packed(endpoint) => {
                if emission_kind(endpoint.inspect_peer(body).map_err(Error::Aligned)?) != kind {
                    return Err(Error::Kind);
                }
                endpoint
                    .receive_authenticated_at(body, duration(received), duration(now))
                    .map_err(Error::Aligned)
            }
            Self::Rolling(endpoint) => endpoint
                .accept_authenticated(now, kind, body)
                .map_err(Error::Rolling),
            Self::Research(endpoint) => endpoint
                .accept_authenticated_at(received, now, kind, body)
                .map_err(Error::Rolling),
        }
    }

    pub(super) fn accept_until(
        &mut self,
        received: Tick,
        now: Tick,
        original_deadline: Tick,
        number: u64,
        kind: EmissionKind,
        body: &mut [u8],
    ) -> Result<(), Error> {
        if let Self::Rolling(endpoint) = self {
            endpoint
                .accept_authenticated_until(
                    received,
                    now,
                    original_deadline,
                    Some(number),
                    kind,
                    body,
                )
                .map_err(Error::Rolling)
        } else if let Self::Research(endpoint) = self {
            endpoint
                .accept_authenticated_until(
                    received,
                    now,
                    original_deadline,
                    Some(number),
                    kind,
                    body,
                )
                .map_err(Error::Rolling)
        } else {
            self.accept_at(received, now, number, kind, body)
        }
    }

    pub(super) fn extract(
        &mut self,
        now: Tick,
        channel: receiver::ChannelId,
        work: usize,
        original_deadline: Tick,
        out: &mut [u8],
    ) -> Result<NativeStep, Error> {
        match self {
            Self::Connections(owner) => owner.extract(now, channel, work, out),
            Self::Swift(owned) => {
                let maximum = owned.engine().receive_config().max_native;
                if out.len() < maximum {
                    return Err(Error::Output { required: maximum });
                }
                let mut entry = owned.entry();
                let Some(packet) = entry.pop_identified().map_err(Error::Swift)? else {
                    return Ok(NativeStep::Idle);
                };
                let bytes = packet.bytes.len();
                let output = out.get_mut(..bytes).ok_or(Error::Invariant)?;
                output.copy_from_slice(packet.bytes);
                Ok(NativeStep::Ready {
                    identity: ProfileIdentity::Swift(packet.identity),
                    bytes,
                    early: false,
                })
            }
            Self::Aligned(endpoint) => {
                let prepared = endpoint
                    .prepare(channel, duration(now), work)
                    .map_err(Error::Aligned)?;
                copy_delivery(prepared, endpoint.pending(), out, ProfileIdentity::Aligned)
            }
            Self::Packed(endpoint) => {
                let prepared = endpoint
                    .prepare(channel, duration(now), work)
                    .map_err(Error::Aligned)?;
                copy_delivery(prepared, endpoint.pending(), out, ProfileIdentity::Packed)
            }
            Self::Rolling(endpoint) => match endpoint
                .prepare_native(now, work, original_deadline, out)
                .map_err(Error::Rolling)?
            {
                rolling_records::NativePreparation::Idle => Ok(NativeStep::Idle),
                rolling_records::NativePreparation::Progress => Ok(NativeStep::Progress),
                rolling_records::NativePreparation::Ready(prepared) => Ok(NativeStep::Ready {
                    identity: ProfileIdentity::Rolling(prepared.identity()),
                    bytes: prepared.bytes(),
                    early: prepared.early(),
                }),
                rolling_records::NativePreparation::AlreadyPending(_) => Err(Error::Invariant),
            },
            Self::Research(endpoint) => match endpoint
                .prepare_native(now, work, original_deadline, out)
                .map_err(Error::Rolling)?
            {
                rolling_records::NativePreparation::Idle => Ok(NativeStep::Idle),
                rolling_records::NativePreparation::Progress => Ok(NativeStep::Progress),
                rolling_records::NativePreparation::Ready(prepared) => Ok(NativeStep::Ready {
                    identity: ProfileIdentity::Research(prepared.identity()),
                    bytes: prepared.bytes(),
                    early: prepared.early(),
                }),
                rolling_records::NativePreparation::AlreadyPending(_) => Err(Error::Invariant),
            },
        }
    }

    pub(super) fn commit(&mut self, now: Tick) -> Result<(), Error> {
        match self {
            Self::Connections(owner) => owner.commit_native_at(now, now),
            Self::Swift(_) => Ok(()),
            Self::Aligned(endpoint) => endpoint
                .commit_delivery(duration(now))
                .map_err(Error::Aligned),
            Self::Packed(endpoint) => endpoint
                .commit_delivery(duration(now))
                .map_err(Error::Aligned),
            Self::Rolling(endpoint) => {
                let token = endpoint.pending_native().ok_or(Error::Invariant)?.token();
                endpoint.commit_native(now, token).map_err(Error::Rolling)
            }
            Self::Research(endpoint) => {
                let token = endpoint.pending_native().ok_or(Error::Invariant)?.token();
                endpoint.commit_native(now, token).map_err(Error::Rolling)
            }
        }
    }

    pub(super) fn pending_deadline(&self) -> Option<std::time::Duration> {
        match self {
            Self::Connections(owner) => owner.pending_deadline(),
            Self::Swift(_) => None,
            Self::Aligned(endpoint) => endpoint.pending_deadline(),
            Self::Packed(endpoint) => endpoint.pending_deadline(),
            Self::Rolling(endpoint) => endpoint
                .pending_native()
                .map(|pending| duration(pending.deadline())),
            Self::Research(endpoint) => endpoint
                .pending_native()
                .map(|pending| duration(pending.deadline())),
        }
    }

    pub(super) fn tick(&mut self, now: Tick) -> Result<(), Error> {
        match self {
            Self::Connections(owner) => owner.tick(now),
            Self::Swift(_) => Ok(()),
            Self::Aligned(endpoint) => endpoint.tick(duration(now)).map_err(Error::Aligned),
            Self::Packed(endpoint) => endpoint.tick(duration(now)).map_err(Error::Aligned),
            Self::Rolling(endpoint) => endpoint.tick(now).map_err(Error::Rolling),
            Self::Research(endpoint) => endpoint.tick(now).map_err(Error::Rolling),
        }
    }

    pub(super) fn feedback_opportunity(&self) -> Result<Option<(Tick, usize)>, Error> {
        let (at, bytes) = match self {
            Self::Connections(owner) => {
                let Some((_, at, bytes)) = owner
                    .collection
                    .feedback_opportunity()
                    .map_err(Error::Connections)?
                else {
                    return Ok(None);
                };
                (Some(at), bytes)
            }
            Self::Swift(owned) => {
                return Ok(owned
                    .engine()
                    .feedback_opportunity()
                    .map(|(at, bytes)| (Tick(at), bytes)));
            }
            Self::Aligned(endpoint) => {
                let Some((at, bytes)) = endpoint.feedback_opportunity().map_err(Error::Aligned)?
                else {
                    return Ok(None);
                };
                (Some(at), bytes)
            }
            Self::Packed(endpoint) => {
                let Some((at, bytes)) = endpoint.feedback_opportunity().map_err(Error::Aligned)?
                else {
                    return Ok(None);
                };
                (Some(at), bytes)
            }
            Self::Rolling(endpoint) => return Ok(endpoint.feedback_opportunity()),
            Self::Research(endpoint) => return Ok(endpoint.feedback_opportunity()),
        };
        at.map(|at| {
            u64::try_from(at.as_micros())
                .map(|at| (Tick(at), bytes))
                .map_err(|_| Error::Arithmetic)
        })
        .transpose()
    }

    pub(super) fn custody_deadline(&self) -> Result<Option<Tick>, Error> {
        let at = match self {
            Self::Connections(owner) => owner.collection.custody_deadline(),
            Self::Swift(_) => return Ok(None),
            Self::Aligned(endpoint) => endpoint.custody_deadline(),
            Self::Packed(endpoint) => endpoint.custody_deadline(),
            // Rolling and Research expire their original coding/debt/output
            // ownership terminally. Their packing and feedback wakes are separate.
            Self::Rolling(endpoint) => return Ok(endpoint.deadline()),
            Self::Research(endpoint) => return Ok(endpoint.deadline()),
        };
        at.map(|at| {
            u64::try_from(at.as_micros())
                .map(Tick)
                .map_err(|_| Error::Arithmetic)
        })
        .transpose()
    }

    pub(super) fn expiry_deadline(&self) -> Result<Option<Tick>, Error> {
        let at = match self {
            Self::Connections(owner) => owner.collection.expiry_deadline(),
            Self::Swift(_) => return Ok(None),
            Self::Aligned(endpoint) => endpoint.expiry_deadline(),
            Self::Packed(endpoint) => endpoint.expiry_deadline(),
            Self::Rolling(endpoint) => return Ok(endpoint.deadline()),
            Self::Research(endpoint) => return Ok(endpoint.deadline()),
        };
        at.map(|at| {
            u64::try_from(at.as_micros())
                .map(Tick)
                .map_err(|_| Error::Arithmetic)
        })
        .transpose()
    }

    pub(super) fn deadline(&self) -> Result<Option<Tick>, Error> {
        match self {
            Self::Connections(owner) => owner
                .collection
                .deadline()
                .map(|at| {
                    u64::try_from(at.as_micros())
                        .map(Tick)
                        .map_err(|_| Error::Arithmetic)
                })
                .transpose(),
            Self::Swift(owned) => {
                let engine = owned.engine();
                Ok(engine
                    .data_deadline()
                    .into_iter()
                    .chain(engine.feedback_deadline())
                    .min()
                    .map(Tick))
            }
            Self::Aligned(endpoint) => endpoint
                .deadline()
                .map(|at| {
                    u64::try_from(at.as_micros())
                        .map(Tick)
                        .map_err(|_| Error::Arithmetic)
                })
                .transpose(),
            Self::Packed(endpoint) => endpoint
                .deadline()
                .map(|at| {
                    u64::try_from(at.as_micros())
                        .map(Tick)
                        .map_err(|_| Error::Arithmetic)
                })
                .transpose(),
            Self::Rolling(endpoint) => Ok(endpoint.deadline()),
            Self::Research(endpoint) => Ok(endpoint.deadline()),
        }
    }

    pub(super) fn drained(&self) -> Result<bool, Error> {
        match self {
            Self::Connections(owner) => Ok(owner.drained()),
            Self::Swift(owned) => {
                let engine = owned.engine();
                Ok(engine.send_drained() && engine.receive_drained())
            }
            Self::Aligned(endpoint) => Ok(endpoint.drained()),
            Self::Packed(endpoint) => Ok(endpoint.drained()),
            Self::Rolling(endpoint) => Ok(endpoint.drained()),
            Self::Research(endpoint) => Ok(endpoint.drained()),
        }
    }
}

pub(super) fn emission_kind(kind: RecordKind) -> EmissionKind {
    match kind {
        RecordKind::Source => EmissionKind::Source(SourceForm::DirectArq),
        RecordKind::Systematic => EmissionKind::Source(SourceForm::SystematicFec),
        RecordKind::Repair => EmissionKind::Repair,
        RecordKind::Feedback => EmissionKind::Feedback,
    }
}

fn copy_delivery(
    prepared: receiver::Prepared,
    delivery: Option<receiver::Delivery<'_>>,
    out: &mut [u8],
    identity: impl FnOnce(receiver::RecordIdentity) -> ProfileIdentity,
) -> Result<NativeStep, Error> {
    match prepared {
        receiver::Prepared::Idle => Ok(NativeStep::Idle),
        receiver::Prepared::Progress => Ok(NativeStep::Progress),
        receiver::Prepared::Ready => {
            let delivery = delivery.ok_or(Error::Invariant)?;
            let bytes = delivery.bytes.len();
            let output = out
                .get_mut(..bytes)
                .ok_or(Error::Output { required: bytes })?;
            output.copy_from_slice(delivery.bytes);
            Ok(NativeStep::Ready {
                identity: identity(receiver::RecordIdentity {
                    channel: delivery.channel,
                    record: delivery.record,
                }),
                bytes,
                early: delivery.early,
            })
        }
    }
}

// Dispatch shares accounting only; every algorithm operation stays with its actual owner.
trait PollEndpoint {
    fn send_max(&self) -> usize;
    fn feedback(
        &mut self,
        now: std::time::Duration,
        out: &mut [u8],
        budget: &mut OutboundBudget,
    ) -> Result<Option<usize>, aligned::Error>;
    fn data(
        &mut self,
        now: std::time::Duration,
        out: &mut [u8],
        budget: &mut OutboundBudget,
    ) -> Result<Option<usize>, aligned::Error>;
    fn inspect(&self, packet: &[u8]) -> Result<RecordKind, aligned::Error>;
    fn units(
        &mut self,
        packet: &[u8],
        witnesses: &mut [receiver::UnitWitness],
    ) -> Result<usize, aligned::Error>;
}

macro_rules! poll_endpoint {
    ($endpoint:ty) => {
        impl PollEndpoint for $endpoint {
            fn send_max(&self) -> usize {
                self.send_max_packet_bytes()
            }
            fn feedback(
                &mut self,
                now: std::time::Duration,
                out: &mut [u8],
                budget: &mut OutboundBudget,
            ) -> Result<Option<usize>, aligned::Error> {
                self.poll_feedback(now, out, budget)
            }
            fn data(
                &mut self,
                now: std::time::Duration,
                out: &mut [u8],
                budget: &mut OutboundBudget,
            ) -> Result<Option<usize>, aligned::Error> {
                self.poll_data(now, out, budget)
            }
            fn inspect(&self, packet: &[u8]) -> Result<RecordKind, aligned::Error> {
                self.inspect_output(packet)
            }
            fn units(
                &mut self,
                packet: &[u8],
                witnesses: &mut [receiver::UnitWitness],
            ) -> Result<usize, aligned::Error> {
                self.outgoing_units(packet, witnesses)
            }
        }
    };
}
poll_endpoint!(aligned::Endpoint);
poll_endpoint!(aligned::packed::Endpoint);

struct Poll<'a> {
    now: Tick,
    number: u64,
    allow_data: bool,
    out: &'a mut [u8],
    budget: &'a mut OutboundBudget,
    witnesses: &'a mut [receiver::UnitWitness],
    overhead: usize,
    feedback_overhead: usize,
}

fn poll_endpoint(
    endpoint: &mut impl PollEndpoint,
    input: Poll<'_>,
) -> Result<Option<Emission>, Error> {
    let Poll {
        now,
        number,
        allow_data,
        out,
        budget,
        witnesses,
        overhead,
        feedback_overhead,
    } = input;
    let maximum = endpoint.send_max();
    if out.len() < maximum {
        return Err(Error::Output { required: maximum });
    }
    maximum.checked_add(overhead).ok_or(Error::Arithmetic)?;
    let before = *budget;
    let feedback = endpoint
        .feedback(duration(now), out, budget)
        .map_err(Error::Aligned)?;
    let output = match feedback {
        Some(bytes) => Some(bytes),
        None if allow_data => endpoint
            .data(duration(now), out, budget)
            .map_err(Error::Aligned)?,
        None => None,
    };
    let Some(bytes) = output else {
        if *budget != before {
            return Err(Error::Invariant);
        }
        return Ok(None);
    };
    let packet = out.get(..bytes).ok_or(Error::Invariant)?;
    let kind = emission_kind(endpoint.inspect(packet).map_err(Error::Aligned)?);
    let selected_overhead = if kind == EmissionKind::Feedback {
        feedback_overhead
    } else {
        overhead
    };
    let wire_bytes = bytes
        .checked_add(selected_overhead)
        .ok_or(Error::Arithmetic)?;
    if before.packets.checked_sub(budget.packets) != Some(1)
        || before.wire_bytes.checked_sub(budget.wire_bytes) != Some(wire_bytes)
    {
        return Err(Error::Invariant);
    }
    let count = endpoint.units(packet, witnesses).map_err(Error::Aligned)?;
    if matches!(kind, EmissionKind::Source(_)) == (count == 0) {
        return Err(Error::Invariant);
    }
    Ok(Some(Emission {
        bytes,
        kind,
        wire_bytes,
        security_number: number,
        witnesses: count,
    }))
}

pub(super) fn recovery_context(context: Context) -> RecoveryContext {
    RecoveryContext {
        session: context.session,
        epoch: context.epoch,
        role: match context.role {
            l2tunnel_management::Role::Client => EndpointRole::Initiator,
            l2tunnel_management::Role::Server => EndpointRole::Responder,
        },
    }
}
