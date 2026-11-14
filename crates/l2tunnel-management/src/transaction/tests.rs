use super::*;
use l2tunnel_core::{Delivery, Mapping, RecordLayout};

fn modes() -> (ModeConfig, ModeConfig) {
    let initial = ModeConfig {
        channels: 2,
        ..ModeConfig::default()
    };
    let next = ModeConfig {
        channels: 3,
        mapping: Mapping::Crc32,
        records: RecordLayout::Packed,
        delivery: Delivery::IndependentShort,
        ..initial.clone()
    };
    (initial, next)
}
fn identity(role: Role, session: u8) -> Identity {
    Identity {
        session: SessionId([session; 16]),
        role,
        local: EndpointId(if role == Role::Client { 1 } else { 2 }),
        remote: EndpointId(if role == Role::Client { 2 } else { 1 }),
        lane: LaneId(7),
    }
}
fn origin(sender: Role) -> Ingress {
    Ingress::AuthenticatedManagement {
        session: SessionId([3; 16]),
        lane: LaneId(7),
        sender,
    }
}
fn pair() -> Result<(Peer, Peer), Error> {
    let (initial, next) = modes();
    let settings = Settings {
        retry_ms: 10,
        phase_timeout_ms: 1_000,
        reconcile_timeout_ms: 2_000,
    };
    let supported = [initial.clone(), next];
    Ok((
        Peer::new(
            identity(Role::Client, 3),
            Epoch(1),
            initial.clone(),
            &supported,
            settings,
            Tick(0),
        )?,
        Peer::new(
            identity(Role::Server, 3),
            Epoch(1),
            initial,
            &supported,
            settings,
            Tick(0),
        )?,
    ))
}
fn wire(effects: Effects) -> Result<Vec<u8>, Error> {
    effects.outbound.ok_or(Error::Unexpected)
}
fn fences(channels: u16) -> Result<(Fence, Fence), Error> {
    Ok((
        Fence::new(&vec![3; usize::from(channels)])?,
        Fence::new(&vec![9; usize::from(channels)])?,
    ))
}
fn begin(
    client: &mut Peer,
    server: &mut Peer,
    next: ModeConfig,
    now: Tick,
) -> Result<(Fence, Fence), Error> {
    let (local, remote) = fences(client.active_config().channels)?;
    assert!(matches!(
        client.propose(next, now)?.event,
        Some(Event::Stage { .. })
    ));
    let prepare = wire(client.staged(local.clone(), now)?)?;
    assert!(matches!(
        server.receive(origin(Role::Client), &prepare, now)?.event,
        Some(Event::Stage { .. })
    ));
    let ready = wire(server.staged(remote.clone(), now)?)?;
    assert!(matches!(
        client.receive(origin(Role::Server), &ready, now)?.event,
        Some(Event::Drain { .. })
    ));
    Ok((local, remote))
}
fn finish(
    client: &mut Peer,
    server: &mut Peer,
    local: &Fence,
    remote: &Fence,
    now: Tick,
) -> Result<(), Error> {
    let old = client.active_epoch();
    let target = Epoch(old.0 + 1);
    let barrier = wire(client.confirm_drained(local, remote, now)?)?;
    assert!(
        server
            .receive(origin(Role::Client), &barrier, now)?
            .outbound
            .is_none()
    );
    assert_eq!(server.phase(), Phase::FollowerDraining);
    let ack = wire(server.confirm_drained(remote, local, now)?)?;
    let commit = wire(client.receive(origin(Role::Server), &ack, now)?)?;
    assert_eq!(
        client.reader(target).ok_or(Error::Unexpected)?.disposition,
        ReadDisposition::Staged
    );
    assert_eq!(
        client.reader(old).ok_or(Error::Unexpected)?.disposition,
        ReadDisposition::DrainOnly
    );
    assert!(server.reader(target).is_none());
    let ack = server.receive(origin(Role::Client), &commit, now)?;
    assert!(matches!(ack.event, Some(Event::Committed(_))));
    assert_eq!(server.active_epoch(), target);
    assert_eq!(client.active_epoch(), old);
    assert_eq!(
        server.reader(old).ok_or(Error::Unexpected)?.disposition,
        ReadDisposition::DrainOnly
    );
    let retire = wire(client.receive(origin(Role::Server), &wire(ack)?, now)?)?;
    assert_eq!(client.active_epoch(), target);
    let ack = wire(server.receive(origin(Role::Client), &retire, now)?)?;
    assert!(server.reader(old).is_none());
    client.receive(origin(Role::Server), &ack, now)?;
    assert!(client.reader(old).is_none());
    assert_eq!(client.active_config(), server.active_config());
    assert_eq!(client.phase(), Phase::Idle);
    assert_eq!(server.phase(), Phase::Idle);
    assert!(client.can_admit_data() && server.can_admit_data());
    Ok(())
}

#[test]
fn canonical_mode_has_exact_fixed_bytes_and_rejects_malformed_values() -> Result<(), Error> {
    let mode = ModeConfig::default();
    let golden = [
        1, 1, 2, 1, 1, 1, 1, 1, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0x40, 0, 0, 0, 0, 0x10, 0,
    ];
    assert_eq!(encode_mode(&mode)?, golden);
    assert_eq!(decode_mode(&golden)?, mode);
    for length in 0..MODE_BYTES {
        assert!(decode_mode(&golden[..length]).is_err());
    }
    for offset in (0..9).chain(10..12) {
        let mut malformed = golden;
        malformed[offset] = 255;
        assert!(decode_mode(&malformed).is_err());
    }
    let mut no_channels = golden;
    no_channels[8..10].fill(0);
    assert!(decode_mode(&no_channels).is_err());
    let mut malformed = golden;
    malformed[12..20].fill(255);
    assert!(decode_mode(&malformed).is_err());
    let next = ModeConfig {
        mapping: Mapping::Crc32,
        ..mode.clone()
    };
    assert_ne!(mode_digest(&mode)?, mode_digest(&next)?);
    assert_eq!(mode_digest(&mode)?, mode_digest(&decode_mode(&golden)?)?);
    Ok(())
}

#[test]
fn two_peers_require_independent_drain_and_never_mix_epoch_configurations() -> Result<(), Error> {
    let (mut client, mut server) = pair()?;
    let (initial, next) = modes();
    assert_eq!(
        server.propose(next.clone(), Tick(0)),
        Err(Error::NotCoordinator)
    );
    let (local, remote) = begin(&mut client, &mut server, next.clone(), Tick(0))?;
    assert_eq!(client.propose(next.clone(), Tick(0)), Err(Error::Busy));
    assert_eq!(
        client.confirm_drained(&remote, &local, Tick(0)),
        Err(Error::IncompleteDrain)
    );
    assert_eq!(client.active_config(), &initial);
    assert_eq!(
        client.reader(Epoch(1)).ok_or(Error::Unexpected)?.config,
        &initial
    );
    assert!(client.reader(Epoch(2)).is_none());
    finish(&mut client, &mut server, &local, &remote, Tick(0))?;
    assert_eq!(
        client.reader(Epoch(2)).ok_or(Error::Unexpected)?.config,
        &next
    );
    assert_eq!(
        server.reader(Epoch(2)).ok_or(Error::Unexpected)?.config,
        &next
    );
    Ok(())
}

#[test]
fn lost_and_reordered_attempts_retry_idempotently_through_uncertain_commit() -> Result<(), Error> {
    let (mut client, mut server) = pair()?;
    let (_, next) = modes();
    let (local, remote) = fences(2)?;
    client.propose(next, Tick(0))?;
    let delayed_prepare = wire(client.staged(local.clone(), Tick(0))?)?;
    let retry_prepare = wire(client.poll(Tick(10))?)?;
    let a = Frame::decode(&delayed_prepare, limits()).map_err(Error::Admission)?;
    let b = Frame::decode(&retry_prepare, limits()).map_err(Error::Admission)?;
    assert_eq!(a.header.request, b.header.request);
    assert_ne!(a.header.packet, b.header.packet);
    assert_eq!(a.body, b.body);
    server.receive(origin(Role::Client), &retry_prepare, Tick(10))?;
    assert_eq!(
        server.receive(origin(Role::Client), &delayed_prepare, Tick(10))?,
        Effects::default()
    );
    let delayed_ready = wire(server.staged(remote.clone(), Tick(10))?)?;
    let retry_ready = wire(server.poll(Tick(20))?)?;
    client.receive(origin(Role::Server), &retry_ready, Tick(20))?;
    assert!(matches!(
        client.receive(origin(Role::Server), &delayed_ready, Tick(20)),
        Err(Error::Admission(crate::Error::RequestRetired))
    ));
    client.confirm_drained(&local, &remote, Tick(20))?; // first BARRIER is lost
    server.confirm_drained(&remote, &local, Tick(20))?;
    let barrier = wire(client.poll(Tick(30))?)?;
    server.receive(origin(Role::Client), &barrier, Tick(30))?; // first BARRIER response is lost
    let barrier_ack = wire(server.poll(Tick(40))?)?;
    client.receive(origin(Role::Server), &barrier_ack, Tick(40))?; // first COMMIT is lost
    let commit = wire(client.poll(Tick(50))?)?;
    let first_ack = server.receive(origin(Role::Client), &commit, Tick(50))?;
    assert!(matches!(first_ack.event, Some(Event::Committed(_)))); // ACK lost
    let uncertain = client.poll(Tick(1_040))?;
    assert!(matches!(uncertain.event, Some(Event::Uncertain(_))));
    assert_eq!(client.phase(), Phase::Uncertain);
    assert_eq!(client.active_epoch(), Epoch(1));
    assert_eq!(server.active_epoch(), Epoch(2));
    let replay_commit = wire(uncertain)?;
    let repeated_ack = server.receive(origin(Role::Client), &replay_commit, Tick(1_040))?;
    assert!(repeated_ack.event.is_none());
    client.receive(origin(Role::Server), &wire(repeated_ack)?, Tick(1_040))?; // RETIRE lost
    let retire = wire(client.poll(Tick(1_050))?)?;
    server.receive(origin(Role::Client), &retire, Tick(1_050))?; // RETIRE response lost
    let retry_retire = wire(client.poll(Tick(1_060))?)?;
    let ack = wire(server.receive(origin(Role::Client), &retry_retire, Tick(1_060))?)?;
    client.receive(origin(Role::Server), &ack, Tick(1_060))?;
    assert_eq!(client.active_config(), server.active_config());
    assert_eq!(client.phase(), Phase::Idle);
    assert_eq!(server.phase(), Phase::Idle);
    assert!(client.reader(Epoch(1)).is_none());
    Ok(())
}

#[test]
fn precommit_abort_handles_missing_prepare_and_rejects_delayed_old_attempt() -> Result<(), Error> {
    let (mut client, mut server) = pair()?;
    let (_, next) = modes();
    let (local, _) = fences(2)?;
    client.propose(next.clone(), Tick(0))?;
    let delayed_prepare = wire(client.staged(local, Tick(0))?)?;
    let abort = wire(client.poll(Tick(1_000))?)?;
    assert_eq!(client.phase(), Phase::Aborting);
    assert!(!client.can_admit_data());
    let ack = wire(server.receive(origin(Role::Client), &abort, Tick(1_000))?)?;
    client.receive(origin(Role::Server), &ack, Tick(1_000))?;
    assert_eq!(client.active_epoch(), Epoch(1));
    assert!(client.can_admit_data() && server.can_admit_data());
    assert!(matches!(
        server.receive(origin(Role::Client), &delayed_prepare, Tick(1_000)),
        Err(Error::Admission(crate::Error::RequestRetired))
    ));
    let (local, remote) = begin(&mut client, &mut server, next, Tick(1_010))?;
    finish(&mut client, &mut server, &local, &remote, Tick(1_010))?;
    Ok(())
}

#[test]
fn follower_timeout_and_exhausted_uncertainty_fail_session_without_rollback() -> Result<(), Error> {
    let (mut client, mut server) = pair()?;
    let (_, next) = modes();
    let (local, remote) = begin(&mut client, &mut server, next.clone(), Tick(0))?;
    let barrier = wire(client.confirm_drained(&local, &remote, Tick(0))?)?;
    server.receive(origin(Role::Client), &barrier, Tick(0))?;
    let ack = wire(server.confirm_drained(&remote, &local, Tick(0))?)?;
    let commit = wire(client.receive(origin(Role::Server), &ack, Tick(0))?)?;
    server.receive(origin(Role::Client), &commit, Tick(0))?;
    client.poll(Tick(1_000))?;
    assert_eq!(client.phase(), Phase::Uncertain);
    assert_eq!(client.poll(Tick(3_000))?.event, Some(Event::Failed));
    assert_eq!(client.phase(), Phase::Failed);
    assert_eq!(client.active_epoch(), Epoch(1));
    assert_eq!(server.active_epoch(), Epoch(2));
    assert!(client.reader(Epoch(1)).is_none());
    assert_eq!(client.propose(next, Tick(3_000)), Err(Error::Busy));
    let (mut client, mut follower) = pair()?;
    let (_, next) = modes();
    begin(&mut client, &mut follower, next, Tick(0))?;
    assert_eq!(follower.poll(Tick(1_000))?.event, Some(Event::Failed));
    assert!(!follower.can_admit_data());
    Ok(())
}

#[test]
fn repeated_transitions_bound_retention_and_permanently_reject_forgotten_ids() -> Result<(), Error>
{
    let (mut client, mut server) = pair()?;
    let (initial, next) = modes();
    let mut first_frame = None;
    for round in 0..100 {
        let now = Tick(round);
        let target = if round % 2 == 0 {
            next.clone()
        } else {
            initial.clone()
        };
        let (local, remote) = fences(client.active_config().channels)?;
        client.propose(target, now)?;
        let prepare = wire(client.staged(local.clone(), now)?)?;
        if first_frame.is_none() {
            first_frame = Some(prepare.clone());
        }
        server.receive(origin(Role::Client), &prepare, now)?;
        let ready = wire(server.staged(remote.clone(), now)?)?;
        client.receive(origin(Role::Server), &ready, now)?;
        finish(&mut client, &mut server, &local, &remote, now)?;
        assert_eq!(client.retained_requests(), 0);
        assert_eq!(server.retained_requests(), 1);
        assert_eq!(server.retained_replies(), 1);
    }
    let saved = first_frame.ok_or(Error::Unexpected)?;
    let frame = Frame::decode(&saved, limits()).map_err(Error::Admission)?;
    let mut fresh_packet = vec![0; saved.len()];
    Frame {
        header: Header {
            packet: PacketNumber(10_000),
            ..frame.header
        },
        body: frame.body,
    }
    .encode(&mut fresh_packet, limits())
    .map_err(Error::Admission)?;
    assert!(matches!(
        server.receive(origin(Role::Client), &fresh_packet, Tick(100)),
        Err(Error::Admission(crate::Error::RequestRetired))
    ));
    assert_eq!(server.active_epoch(), Epoch(101));
    Ok(())
}

#[test]
fn user_origin_stale_session_unsupported_modes_and_backward_time_cannot_switch() -> Result<(), Error>
{
    let (mut client, mut server) = pair()?;
    let (_, next) = modes();
    let unsupported = ModeConfig {
        channels: 17,
        ..next.clone()
    };
    assert_eq!(
        client.propose(unsupported, Tick(0)),
        Err(Error::Unsupported)
    );
    assert_eq!(client.phase(), Phase::Idle);
    client.propose(next.clone(), Tick(1))?;
    let frame = wire(client.staged(fences(2)?.0, Tick(1))?)?;
    assert!(matches!(
        server.receive(Ingress::UserTraffic, &frame, Tick(1)),
        Err(Error::Admission(crate::Error::UntrustedOrigin))
    ));
    assert_eq!(server.phase(), Phase::Idle);
    let (initial, _) = modes();
    let mut restarted = Peer::new(
        identity(Role::Server, 4),
        Epoch(1),
        initial.clone(),
        &[initial, next],
        Settings::default(),
        Tick(0),
    )?;
    assert!(matches!(
        restarted.receive(origin(Role::Client), &frame, Tick(1)),
        Err(Error::Admission(crate::Error::BindingMismatch))
    ));
    assert_eq!(client.poll(Tick(0)), Err(Error::Clock));
    assert_eq!(server.active_epoch(), Epoch(1));
    Ok(())
}

#[test]
fn prepared_abort_discards_delayed_ready_and_requires_ack_before_resuming() -> Result<(), Error> {
    let (mut client, mut server) = pair()?;
    client.propose(modes().1, Tick(0))?;
    let prepare = wire(client.staged(fences(2)?.0, Tick(0))?)?;
    server.receive(origin(Role::Client), &prepare, Tick(0))?;
    let ready = wire(server.staged(fences(2)?.1, Tick(0))?)?;
    let abort = wire(client.poll(Tick(1_000))?)?;
    assert_eq!(client.phase(), Phase::Aborting);
    assert!(!client.can_admit_data());
    assert_eq!(
        client.receive(origin(Role::Server), &ready, Tick(1_000))?,
        Effects::default()
    );
    let ack = server.receive(origin(Role::Client), &abort, Tick(1_000))?;
    assert_eq!(server.phase(), Phase::Idle);
    client.receive(origin(Role::Server), &wire(ack)?, Tick(1_000))?;
    assert_eq!(client.phase(), Phase::Idle);
    assert_eq!(client.active_epoch(), Epoch(1));
    assert!(client.reader(Epoch(2)).is_none());
    Ok(())
}

#[test]
fn authenticated_semantic_corruption_and_counter_exhaustion_fail_closed() -> Result<(), Error> {
    let (mut client, mut server) = pair()?;
    client.propose(modes().1, Tick(0))?;
    let mut prepare = wire(client.staged(fences(2)?.0, Tick(0))?)?;
    prepare[72] ^= 1;
    assert_eq!(
        server.receive(origin(Role::Client), &prepare, Tick(0)),
        Err(Error::Unexpected)
    );
    assert_eq!(server.phase(), Phase::Failed);
    assert_eq!(server.active_epoch(), Epoch(1));
    client.next_packet = u64::MAX;
    assert_eq!(client.poll(Tick(10)), Err(Error::Exhausted));
    assert_eq!(client.phase(), Phase::Failed);
    assert!(!client.can_admit_data());
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WeightedPolicy {
    channels: u16,
    weight: u32,
}
impl Configuration for WeightedPolicy {
    const ENCODED_LEN: usize = 8;
    const DIGEST_DOMAIN: &'static [u8] = b"test/weighted-policy/v1\0";
    fn validate(&self) -> Result<(), Error> {
        if !(1..=256).contains(&self.channels) || !(1..=1024).contains(&self.weight) {
            return Err(Error::Configuration("test policy bounds"));
        }
        Ok(())
    }
    fn encode_into(&self, output: &mut [u8]) -> Result<(), Error> {
        if output.len() != 8 {
            return Err(Error::Malformed);
        }
        output[..2].copy_from_slice(&[1, 0]);
        output[2..4].copy_from_slice(&self.channels.to_be_bytes());
        output[4..].copy_from_slice(&self.weight.to_be_bytes());
        Ok(())
    }
    fn decode(input: &[u8]) -> Result<Self, Error> {
        if input.len() != 8 || input[0] != 1 {
            return Err(Error::Malformed);
        }
        // Deliberately permissive reserved byte here verifies the central
        // canonical re-encoding gate rather than trusting a custom decoder.
        Ok(Self {
            channels: u16::from_be_bytes(input[2..4].try_into().map_err(|_| Error::Malformed)?),
            weight: u32::from_be_bytes(input[4..].try_into().map_err(|_| Error::Malformed)?),
        })
    }
    fn channels(&self) -> u16 {
        self.channels
    }
    fn duplex(&self) -> l2tunnel_core::Duplex {
        l2tunnel_core::Duplex::Half
    }
}

#[test]
fn generic_policy_changes_bind_all_values_and_use_existing_transaction_phases() -> Result<(), Error>
{
    let initial = WeightedPolicy {
        channels: 2,
        weight: 1,
    };
    let next = WeightedPolicy {
        channels: 3,
        weight: 7,
    };
    let supported = [initial.clone(), next.clone()];
    let mut client = Peer::new(
        identity(Role::Client, 3),
        Epoch(1),
        initial.clone(),
        &supported,
        Settings::default(),
        Tick(0),
    )?;
    let mut server = Peer::new(
        identity(Role::Server, 3),
        Epoch(1),
        initial.clone(),
        &supported,
        Settings::default(),
        Tick(0),
    )?;
    let unadvertised = WeightedPolicy {
        weight: 8,
        ..next.clone()
    };
    assert_ne!(
        configuration_digest(&next)?,
        configuration_digest(&unadvertised)?
    );
    assert_eq!(
        client.propose(unadvertised, Tick(0)),
        Err(Error::Unsupported)
    );
    client.propose(next.clone(), Tick(0))?;
    let (a, b) = fences(2)?;
    let prepare = client
        .staged(a.clone(), Tick(0))?
        .outbound
        .ok_or(Error::Unexpected)?;
    let frame = Frame::decode(&prepare, limits()).map_err(Error::Admission)?;
    assert_eq!(
        frame.body.len(),
        8 + WeightedPolicy::ENCODED_LEN + 2 + 2 * 8
    );
    server.receive(origin(Role::Client), &prepare, Tick(0))?;
    let ready = server
        .staged(b.clone(), Tick(0))?
        .outbound
        .ok_or(Error::Unexpected)?;
    client.receive(origin(Role::Server), &ready, Tick(0))?;
    server.confirm_drained(&b, &a, Tick(0))?;
    let mut command = client
        .confirm_drained(&a, &b, Tick(0))?
        .outbound
        .ok_or(Error::Unexpected)?;
    for _ in 0..3 {
        let reply = server
            .receive(origin(Role::Client), &command, Tick(0))?
            .outbound
            .ok_or(Error::Unexpected)?;
        let effect = client.receive(origin(Role::Server), &reply, Tick(0))?;
        if let Some(outbound) = effect.outbound {
            command = outbound;
        }
    }
    assert_eq!(client.phase(), Phase::Idle);
    assert_eq!(server.phase(), Phase::Idle);
    assert_eq!(client.active_config(), &next);
    assert_eq!(server.active_config(), &next);
    assert_eq!(client.active_epoch(), Epoch(2));
    assert!(client.reader(Epoch(1)).is_none());
    Ok(())
}

#[test]
fn generic_codec_enforces_bounds_canonicality_and_legacy_digest_compatibility() -> Result<(), Error>
{
    let policy = WeightedPolicy {
        channels: 256,
        weight: 1024,
    };
    let bytes = config::encode_configuration(&policy)?;
    assert_eq!(
        config::decode_configuration::<WeightedPolicy>(&bytes)?,
        policy
    );
    for len in 0..bytes.len() {
        assert!(config::decode_configuration::<WeightedPolicy>(&bytes[..len]).is_err());
    }
    let mut noncanonical = bytes;
    noncanonical[1] = 1;
    assert_eq!(
        config::decode_configuration::<WeightedPolicy>(&noncanonical),
        Err(Error::Malformed)
    );
    for channels in [0, 257] {
        assert!(
            configuration_digest(&WeightedPolicy {
                channels,
                ..policy.clone()
            })
            .is_err()
        );
    }
    for mode in [modes().0, modes().1] {
        assert_eq!(configuration_digest(&mode)?, mode_digest(&mode)?);
        assert_eq!(config::encode_configuration(&mode)?, encode_mode(&mode)?);
    }
    Ok(())
}

#[derive(Clone, Eq, PartialEq)]
struct OversizedPolicy;
impl Configuration for OversizedPolicy {
    const ENCODED_LEN: usize = usize::MAX;
    const DIGEST_DOMAIN: &'static [u8] = b"test";
    fn validate(&self) -> Result<(), Error> {
        Ok(())
    }
    fn encode_into(&self, _: &mut [u8]) -> Result<(), Error> {
        Err(Error::Unexpected)
    }
    fn decode(_: &[u8]) -> Result<Self, Error> {
        Err(Error::Unexpected)
    }
    fn channels(&self) -> u16 {
        1
    }
    fn duplex(&self) -> l2tunnel_core::Duplex {
        l2tunnel_core::Duplex::Half
    }
}
#[test]
fn generic_type_size_rejected_before_allocation_or_encode() {
    assert!(matches!(
        configuration_digest(&OversizedPolicy),
        Err(Error::Configuration(_))
    ));
    assert!(matches!(
        config::decode_configuration::<OversizedPolicy>(&[]),
        Err(Error::Configuration(_))
    ));
}

pub(super) mod directional;
