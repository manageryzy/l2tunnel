use super::{
    Context, Emission, EmissionKind, Error, NativeStep, ProfileIdentity, SourceForm, Tick, aligned,
    configuration, duration, receiver, swift,
};
use l2tunnel_recovery::{EndpointRole, RecoveryContext};
use l2tunnel_reliable::{OutboundBudget, RecordKind};
use swift::records;

#[allow(clippy::large_enum_variant)] // Exactly one actual owner; no extra heap indirection or unused engines.
pub(super) enum Owner {
    Swift {
        set: swift::storage::Set,
        id: swift::storage::EngineId,
    },
    Aligned(aligned::Endpoint),
    Packed(aligned::packed::Endpoint),
}

impl Owner {
    pub(super) fn new(
        configuration: &configuration::Configuration,
        context: Context,
    ) -> Result<Self, Error> {
        let local = configuration.descriptor().local(context.role);
        let recovery = RecoveryContext {
            session: context.session,
            epoch: context.epoch,
            role: match context.role {
                l2tunnel_management::Role::Client => EndpointRole::Initiator,
                l2tunnel_management::Role::Server => EndpointRole::Responder,
            },
        };
        match (local.send().profile(), local.receive().profile()) {
            (
                configuration::DirectionProfile::Swift(send),
                configuration::DirectionProfile::Swift(receive),
            ) => {
                let plan =
                    swift::storage::Plan::for_engine(*send, *receive).map_err(Error::Storage)?;
                let capacity_bytes = std::mem::size_of::<swift::storage::Set>()
                    .checked_add(plan.capacity_bytes())
                    .ok_or(Error::Arithmetic)?;
                let mut set =
                    swift::storage::Set::new(swift::storage::Limits { capacity_bytes }, 0)
                        .map_err(Error::Storage)?;
                let id = set.prepare(plan).map_err(Error::Storage)?;
                Ok(Self::Swift { set, id })
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
            _ => Err(Error::Configuration),
        }
    }

    pub(super) fn offer(
        &mut self,
        now: Tick,
        channel: u16,
        bytes: &[u8],
    ) -> Result<Option<ProfileIdentity>, Error> {
        match self {
            Self::Swift { set, id } => {
                let channel =
                    records::ChannelId::new(usize::from(channel)).ok_or(Error::Configuration)?;
                match set
                    .entry(*id)
                    .map_err(Error::Storage)?
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
    ) -> Result<Option<Emission>, Error> {
        match self {
            Self::Swift { set, id } => {
                let maximum = set
                    .engine(*id)
                    .map_err(Error::Storage)?
                    .send_config()
                    .codec
                    .datagram_bytes;
                if out.len() < maximum {
                    return Err(Error::Output { required: maximum });
                }
                let maximum_wire = maximum.checked_add(overhead).ok_or(Error::Arithmetic)?;
                if budget.packets == 0 || budget.wire_bytes < maximum_wire {
                    return Ok(None);
                }
                let mut entry = set.entry(*id).map_err(Error::Storage)?;
                let Some(emission) = entry
                    .poll_emission(now.0, records::RecordNumber(number), allow_data)
                    .map_err(Error::Swift)?
                else {
                    return Ok(None);
                };
                let bytes = emission.body().len();
                if bytes > maximum {
                    return Err(Error::Invariant);
                }
                let kind = match emission.kind() {
                    records::EmissionKind::Source => EmissionKind::Source(SourceForm::Swift),
                    records::EmissionKind::Repair => EmissionKind::Repair,
                    records::EmissionKind::Feedback => EmissionKind::Feedback,
                };
                // The checked worst-case allowance precedes actual engine consumption.
                let wire_bytes = bytes + overhead;
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
                },
            ),
        }
    }

    pub(super) fn accept(
        &mut self,
        now: Tick,
        number: u64,
        kind: EmissionKind,
        body: &mut [u8],
    ) -> Result<(), Error> {
        match self {
            Self::Swift { set, id } => {
                let observed = match *body.first().ok_or(Error::PacketSize)? & swift::KIND_MASK {
                    swift::KIND_SOURCE => EmissionKind::Source(SourceForm::Swift),
                    swift::KIND_REPAIR => EmissionKind::Repair,
                    swift::KIND_FEEDBACK => EmissionKind::Feedback,
                    _ => return Err(Error::Kind),
                };
                if observed != kind {
                    return Err(Error::Kind);
                }
                set.entry(*id)
                    .map_err(Error::Storage)?
                    .accept(now.0, records::RecordNumber(number), body)
                    .map_err(Error::Swift)
            }
            Self::Aligned(endpoint) => {
                if emission_kind(endpoint.inspect_peer(body).map_err(Error::Aligned)?) != kind {
                    return Err(Error::Kind);
                }
                endpoint
                    .receive_authenticated(body, duration(now))
                    .map_err(Error::Aligned)
            }
            Self::Packed(endpoint) => {
                if emission_kind(endpoint.inspect_peer(body).map_err(Error::Aligned)?) != kind {
                    return Err(Error::Kind);
                }
                endpoint
                    .receive_authenticated(body, duration(now))
                    .map_err(Error::Aligned)
            }
        }
    }

    pub(super) fn extract(
        &mut self,
        now: Tick,
        channel: receiver::ChannelId,
        work: usize,
        out: &mut [u8],
    ) -> Result<NativeStep, Error> {
        match self {
            Self::Swift { set, id } => {
                let maximum = set
                    .engine(*id)
                    .map_err(Error::Storage)?
                    .receive_config()
                    .max_native;
                if out.len() < maximum {
                    return Err(Error::Output { required: maximum });
                }
                let mut entry = set.entry(*id).map_err(Error::Storage)?;
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
        }
    }

    pub(super) fn commit(&mut self, now: Tick) -> Result<(), Error> {
        match self {
            Self::Swift { .. } => Ok(()),
            Self::Aligned(endpoint) => endpoint
                .commit_delivery(duration(now))
                .map_err(Error::Aligned),
            Self::Packed(endpoint) => endpoint
                .commit_delivery(duration(now))
                .map_err(Error::Aligned),
        }
    }

    pub(super) fn pending_deadline(&self) -> Option<std::time::Duration> {
        match self {
            Self::Swift { .. } => None,
            Self::Aligned(endpoint) => endpoint.pending_deadline(),
            Self::Packed(endpoint) => endpoint.pending_deadline(),
        }
    }

    pub(super) fn tick(&mut self, now: Tick) -> Result<(), Error> {
        match self {
            Self::Swift { .. } => Ok(()),
            Self::Aligned(endpoint) => endpoint.tick(duration(now)).map_err(Error::Aligned),
            Self::Packed(endpoint) => endpoint.tick(duration(now)).map_err(Error::Aligned),
        }
    }

    pub(super) fn deadline(&self) -> Result<Option<Tick>, Error> {
        match self {
            Self::Swift { set, id } => {
                let engine = set.engine(*id).map_err(Error::Storage)?;
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
        }
    }

    pub(super) fn drained(&self) -> Result<bool, Error> {
        match self {
            Self::Swift { set, id } => {
                let engine = set.engine(*id).map_err(Error::Storage)?;
                Ok(engine.send_drained() && engine.receive_drained())
            }
            Self::Aligned(endpoint) => Ok(endpoint.drained()),
            Self::Packed(endpoint) => Ok(endpoint.drained()),
        }
    }
}

fn emission_kind(kind: RecordKind) -> EmissionKind {
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
    let wire_bytes = bytes.checked_add(overhead).ok_or(Error::Arithmetic)?;
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
