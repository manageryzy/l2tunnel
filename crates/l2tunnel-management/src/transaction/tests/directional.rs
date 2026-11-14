//! Global-sender fence regressions through the existing real transaction engine.

use super::*;
use l2tunnel_core::Duplex;

/// The compatibility query is deliberately independent of both encoded widths.
/// Generic invalid widths reach Peer validation; packed widths are C-specific.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::transaction) struct Policy {
    pub(in crate::transaction) legacy: u16,
    pub(in crate::transaction) client: u16,
    pub(in crate::transaction) server: u16,
    pub(in crate::transaction) packed: bool,
}
impl Policy {
    pub(in crate::transaction) fn new(client: u16, server: u16) -> Self {
        Self {
            legacy: 2,
            client,
            server,
            packed: false,
        }
    }
}
impl Configuration for Policy {
    const ENCODED_LEN: usize = 8;
    const DIGEST_DOMAIN: &'static [u8] = b"l2tunnel/test-global-sender/v1\0";

    fn validate(&self) -> Result<(), Error> {
        if !(1..=256).contains(&self.legacy)
            || (self.packed
                && (!(1..=255).contains(&self.client) || !(1..=255).contains(&self.server)))
        {
            return Err(Error::Configuration("test policy channel capability"));
        }
        Ok(())
    }
    fn encode_into(&self, output: &mut [u8]) -> Result<(), Error> {
        if output.len() != Self::ENCODED_LEN {
            return Err(Error::Malformed);
        }
        output[0] = 1;
        output[1] = u8::from(self.packed);
        output[2..4].copy_from_slice(&self.legacy.to_be_bytes());
        output[4..6].copy_from_slice(&self.client.to_be_bytes());
        output[6..8].copy_from_slice(&self.server.to_be_bytes());
        Ok(())
    }
    fn decode(input: &[u8]) -> Result<Self, Error> {
        if input.len() != Self::ENCODED_LEN || input[0] != 1 || input[1] > 1 {
            return Err(Error::Malformed);
        }
        let policy = Self {
            legacy: u16::from_be_bytes([input[2], input[3]]),
            client: u16::from_be_bytes([input[4], input[5]]),
            server: u16::from_be_bytes([input[6], input[7]]),
            packed: input[1] == 1,
        };
        policy.validate()?;
        Ok(policy)
    }
    fn channels(&self) -> u16 {
        self.legacy
    }
    fn sender_channels(&self, sender: Role) -> u16 {
        match sender {
            Role::Client => self.client,
            Role::Server => self.server,
        }
    }
    fn duplex(&self) -> Duplex {
        Duplex::Half
    }
}

fn timing() -> Settings {
    Settings {
        retry_ms: 10,
        phase_timeout_ms: 1_000,
        reconcile_timeout_ms: 2_000,
    }
}
fn endpoints<C: Configuration>(
    initial: C,
    target: C,
    directional: bool,
) -> Result<(Peer<C>, Peer<C>), Error> {
    let catalog = [initial.clone(), target];
    let make = |role| {
        if directional {
            Peer::new_directional(
                identity(role, 3),
                Epoch(1),
                initial.clone(),
                &catalog,
                timing(),
                Tick(0),
            )
        } else {
            Peer::new(
                identity(role, 3),
                Epoch(1),
                initial.clone(),
                &catalog,
                timing(),
                Tick(0),
            )
        }
    };
    Ok((make(Role::Client)?, make(Role::Server)?))
}
fn outgoing<C: Configuration>(effects: Effects<C>) -> Result<Vec<u8>, Error> {
    effects.outbound.ok_or(Error::Unexpected)
}
fn start<C: Configuration + std::fmt::Debug>(
    client: &mut Peer<C>,
    server: &mut Peer<C>,
    target: C,
    local: &Fence,
    remote: &Fence,
) -> Result<[Vec<u8>; 2], Error> {
    assert!(matches!(client.propose(target.clone(), Tick(0))?.event,
        Some(Event::Stage { config, .. }) if config == target));
    let prepare = outgoing(client.staged(local.clone(), Tick(0))?)?;
    let frame = Frame::decode(&prepare, limits()).map_err(Error::Admission)?;
    assert_eq!(frame.header.kind, MessageKind::Prepare);
    assert_eq!(
        &frame.body[8..8 + C::ENCODED_LEN],
        encode_configuration(&target)?.as_slice()
    );
    assert_eq!(&frame.body[8 + C::ENCODED_LEN..], local.encode().as_slice());
    assert!(
        matches!(server.receive(origin(Role::Client), &prepare, Tick(0))?.event,
        Some(Event::Stage { config, .. }) if config == target)
    );
    let ready = server.staged(remote.clone(), Tick(0))?;
    assert_eq!(
        ready.event,
        Some(Event::Drain {
            local: remote.clone(),
            peer: local.clone()
        })
    );
    let ready = outgoing(ready)?;
    let frame = Frame::decode(&ready, limits()).map_err(Error::Admission)?;
    assert_eq!(frame.header.kind, MessageKind::Ready);
    assert_eq!(&frame.body[8..], remote.encode().as_slice());
    assert_eq!(
        client.receive(origin(Role::Server), &ready, Tick(0))?.event,
        Some(Event::Drain {
            local: local.clone(),
            peer: remote.clone()
        })
    );
    Ok([prepare, ready])
}
fn finish_exchange<C: Configuration + std::fmt::Debug>(
    client: &mut Peer<C>,
    server: &mut Peer<C>,
    local: &Fence,
    remote: &Fence,
) -> Result<[Vec<u8>; 6], Error> {
    let old = client.active_epoch();
    let target = Epoch(old.0.checked_add(1).ok_or(Error::Exhausted)?);
    let barrier = outgoing(client.confirm_drained(local, remote, Tick(0))?)?;
    assert!(
        server
            .receive(origin(Role::Client), &barrier, Tick(0))?
            .outbound
            .is_none()
    );
    assert_eq!(server.phase(), Phase::FollowerDraining);
    let barrier_ack = outgoing(server.confirm_drained(remote, local, Tick(0))?)?;
    let commit = outgoing(client.receive(origin(Role::Server), &barrier_ack, Tick(0))?)?;
    assert_eq!(
        client.reader(target).ok_or(Error::Unexpected)?.disposition,
        ReadDisposition::Staged
    );
    assert_eq!(
        client.reader(old).ok_or(Error::Unexpected)?.disposition,
        ReadDisposition::DrainOnly
    );
    let acknowledged = server.receive(origin(Role::Client), &commit, Tick(0))?;
    assert!(matches!(acknowledged.event, Some(Event::Committed(_))));
    assert_eq!(server.active_epoch(), target);
    assert_eq!(client.active_epoch(), old);
    assert_eq!(
        server.reader(old).ok_or(Error::Unexpected)?.disposition,
        ReadDisposition::DrainOnly
    );
    let commit_ack = outgoing(acknowledged)?;
    let retire = outgoing(client.receive(origin(Role::Server), &commit_ack, Tick(0))?)?;
    assert_eq!(client.active_epoch(), target);
    let acknowledged = server.receive(origin(Role::Client), &retire, Tick(0))?;
    assert_eq!(acknowledged.event, Some(Event::Retired(old)));
    let retire_ack = outgoing(acknowledged)?;
    assert_eq!(
        client
            .receive(origin(Role::Server), &retire_ack, Tick(0))?
            .event,
        Some(Event::Retired(old))
    );
    assert_eq!(client.phase(), Phase::Idle);
    assert_eq!(server.phase(), Phase::Idle);
    assert!(client.can_admit_data() && server.can_admit_data());
    assert!(client.reader(old).is_none() && server.reader(old).is_none());
    assert_eq!(client.active_config(), server.active_config());
    Ok([barrier, barrier_ack, commit, commit_ack, retire, retire_ack])
}
fn exchanged<C: Configuration + std::fmt::Debug>(
    client: &mut Peer<C>,
    server: &mut Peer<C>,
    target: C,
    local: &Fence,
    remote: &Fence,
) -> Result<Vec<Vec<u8>>, Error> {
    let mut trace = start(client, server, target, local, remote)?.to_vec();
    trace.extend(finish_exchange(client, server, local, remote)?);
    Ok(trace)
}
fn replace_fields(original: &[u8], offset: usize, fields: &[u8]) -> Result<Vec<u8>, Error> {
    let frame = Frame::decode(original, limits()).map_err(Error::Admission)?;
    let mut body = frame.body.get(..offset).ok_or(Error::Malformed)?.to_vec();
    body.extend_from_slice(fields);
    let mut bytes = vec![0; HEADER_LEN + body.len()];
    Frame {
        header: frame.header,
        body: &body,
    }
    .encode(&mut bytes, limits())
    .map_err(Error::Admission)?;
    Ok(bytes)
}
fn raw_fence(count: u16) -> Vec<u8> {
    let mut fields = count.to_be_bytes().to_vec();
    for _ in 0..count {
        fields.extend_from_slice(&0u64.to_be_bytes());
    }
    fields
}

#[test]
fn two_directional_peers_switch_from_client2_server3_to_client4_server1() -> Result<(), Error> {
    let initial = Policy::new(2, 3);
    let target = Policy::new(4, 1);
    let (mut client, mut server) = endpoints(initial.clone(), target.clone(), true)?;
    for peer in [&client, &server] {
        assert_eq!(peer.sender_channels(Role::Client), 2);
        assert_eq!(peer.sender_channels(Role::Server), 3);
    }
    let local = Fence::new(&[3, 5])?;
    let remote = Fence::new(&[7, 11, 13])?;
    let trace = exchanged(&mut client, &mut server, target.clone(), &local, &remote)?;
    assert_eq!(trace.len(), 8);
    for peer in [&client, &server] {
        assert_eq!(peer.active_config(), &target);
        assert_eq!(peer.active_epoch(), Epoch(2));
        assert_eq!(peer.sender_channels(Role::Client), 4);
        assert_eq!(peer.sender_channels(Role::Server), 1);
    }
    assert_ne!(
        configuration_digest(&initial)?,
        configuration_digest(&target)?
    );
    Ok(())
}

#[test]
fn legacy_constructors_ignore_overridden_even_invalid_sender_widths() -> Result<(), Error> {
    let initial = Policy::new(0, 257);
    let target = Policy::new(257, 0);
    let (mut client, mut server) = endpoints(initial, target.clone(), false)?;
    for peer in [&client, &server] {
        assert_eq!(peer.sender_channels(Role::Client), 2);
        assert_eq!(peer.sender_channels(Role::Server), 2);
    }
    exchanged(
        &mut client,
        &mut server,
        target,
        &Fence::new(&[3, 5])?,
        &Fence::new(&[7, 11])?,
    )?;
    assert_eq!(client.sender_channels(Role::Server), 2);
    assert_eq!(server.sender_channels(Role::Client), 2);
    Ok(())
}

#[test]
fn default_sender_query_keeps_complete_legacy_mode_trace_and_bytes() -> Result<(), Error> {
    let (initial, target) = modes();
    let (mut legacy_client, mut legacy_server) = endpoints(initial.clone(), target.clone(), false)?;
    let (mut explicit_client, mut explicit_server) =
        endpoints(initial.clone(), target.clone(), true)?;
    let local = Fence::new(&[3, 5])?;
    let remote = Fence::new(&[7, 11])?;
    let legacy = exchanged(
        &mut legacy_client,
        &mut legacy_server,
        target.clone(),
        &local,
        &remote,
    )?;
    let explicit = exchanged(
        &mut explicit_client,
        &mut explicit_server,
        target,
        &local,
        &remote,
    )?;
    assert_eq!(explicit, legacy);
    assert_eq!(encode_configuration(&initial)?, encode_mode(&initial)?);
    assert_eq!(configuration_digest(&initial)?, mode_digest(&initial)?);
    Ok(())
}

#[test]
fn local_staging_uses_old_global_sender_and_retains_valid_retry() -> Result<(), Error> {
    let target = Policy::new(4, 1);
    let (mut client, mut server) = endpoints(Policy::new(2, 3), target.clone(), true)?;
    client.propose(target, Tick(0))?;
    for count in [1, 3, 4] {
        assert_eq!(
            client.staged(Fence::new(&vec![0; count])?, Tick(0)),
            Err(Error::IncompleteDrain)
        );
        assert_eq!(client.phase(), Phase::Staging);
    }
    let prepare = outgoing(client.staged(Fence::new(&[3, 5])?, Tick(0))?)?;
    let frame = Frame::decode(&prepare, limits()).map_err(Error::Admission)?;
    assert_eq!(frame.header.request, RequestId(1));
    assert_eq!(frame.header.packet, PacketNumber(1));
    server.receive(origin(Role::Client), &prepare, Tick(0))?;
    for count in [1, 2, 4] {
        assert_eq!(
            server.staged(Fence::new(&vec![0; count])?, Tick(0)),
            Err(Error::IncompleteDrain)
        );
        assert_eq!(server.phase(), Phase::FollowerStaging);
    }
    let ready = outgoing(server.staged(Fence::new(&[7, 11, 13])?, Tick(0))?)?;
    assert!(matches!(
        client.receive(origin(Role::Server), &ready, Tick(0))?.event,
        Some(Event::Drain { .. })
    ));
    Ok(())
}

#[test]
fn first_prepare_rejects_wrong_role_target_and_malformed_fence_widths() -> Result<(), Error> {
    for count in [0, 1, 3, 4, 257] {
        let target = Policy::new(4, 1);
        let (mut client, mut server) = endpoints(Policy::new(2, 3), target.clone(), true)?;
        client.propose(target, Tick(0))?;
        let prepare = outgoing(client.staged(Fence::new(&[3, 5])?, Tick(0))?)?;
        let wrong = replace_fields(&prepare, 8 + Policy::ENCODED_LEN, &raw_fence(count))?;
        assert_eq!(
            server.receive(origin(Role::Client), &wrong, Tick(0)),
            Err(Error::Malformed)
        );
        assert_eq!(server.phase(), Phase::Failed);
    }
    assert_eq!(Fence::new(&[]), Err(Error::Malformed));
    assert_eq!(Fence::new(&[0; 257]), Err(Error::Malformed));
    Ok(())
}

#[test]
fn ready_rejects_old_client_target_server_and_malformed_fence_widths() -> Result<(), Error> {
    for count in [0, 1, 2, 4, 257] {
        let target = Policy::new(4, 1);
        let (mut client, mut server) = endpoints(Policy::new(2, 3), target.clone(), true)?;
        client.propose(target, Tick(0))?;
        let prepare = outgoing(client.staged(Fence::new(&[3, 5])?, Tick(0))?)?;
        server.receive(origin(Role::Client), &prepare, Tick(0))?;
        let ready = outgoing(server.staged(Fence::new(&[7, 11, 13])?, Tick(0))?)?;
        let wrong = replace_fields(&ready, 8, &raw_fence(count))?;
        assert_eq!(
            client.receive(origin(Role::Server), &wrong, Tick(0)),
            Err(Error::Malformed)
        );
        assert_eq!(client.phase(), Phase::Failed);
    }
    Ok(())
}

#[test]
fn drain_equality_preserves_independent_counts_including_zero_and_maximum() -> Result<(), Error> {
    let target = Policy::new(4, 1);
    let (mut client, mut server) = endpoints(Policy::new(2, 3), target.clone(), true)?;
    let local = Fence::new(&[0, u64::MAX])?;
    let remote = Fence::new(&[7, 11, 13])?;
    start(&mut client, &mut server, target, &local, &remote)?;
    let wrong_local = Fence::new(&[0, u64::MAX - 1])?;
    let wrong_remote = Fence::new(&[7, 11, 12])?;
    assert_eq!(
        client.confirm_drained(&remote, &local, Tick(0)),
        Err(Error::IncompleteDrain)
    );
    assert_eq!(
        client.confirm_drained(&wrong_local, &remote, Tick(0)),
        Err(Error::IncompleteDrain)
    );
    assert_eq!(
        client.confirm_drained(&local, &wrong_remote, Tick(0)),
        Err(Error::IncompleteDrain)
    );
    assert_eq!(
        server.confirm_drained(&wrong_remote, &local, Tick(0)),
        Err(Error::IncompleteDrain)
    );
    finish_exchange(&mut client, &mut server, &local, &remote)?;
    Ok(())
}

#[test]
fn directional_initial_and_catalog_widths_validate_both_global_senders() -> Result<(), Error> {
    let valid = Policy::new(2, 3);
    for invalid in [
        Policy::new(0, 3),
        Policy::new(257, 3),
        Policy::new(2, 0),
        Policy::new(2, 257),
    ] {
        // The legacy canonical codec intentionally accepts these test queries.
        configuration_digest(&invalid)?;
        assert!(matches!(
            Peer::new_directional(
                identity(Role::Client, 3),
                Epoch(1),
                invalid.clone(),
                std::slice::from_ref(&invalid),
                timing(),
                Tick(0)
            ),
            Err(Error::Configuration(_))
        ));
        assert!(matches!(
            Peer::new_directional(
                identity(Role::Server, 3),
                Epoch(1),
                valid.clone(),
                &[valid.clone(), invalid],
                timing(),
                Tick(0)
            ),
            Err(Error::Configuration(_))
        ));
    }
    Ok(())
}

#[test]
fn invalid_directional_proposal_does_not_consume_attempt_request_or_packet() -> Result<(), Error> {
    let initial = Policy::new(2, 3);
    let target = Policy::new(4, 1);
    let (mut client, _) = endpoints(initial, target.clone(), true)?;
    for invalid in [
        Policy::new(0, 1),
        Policy::new(257, 1),
        Policy::new(4, 0),
        Policy::new(4, 257),
    ] {
        assert!(matches!(
            client.propose(invalid, Tick(0)),
            Err(Error::Configuration(_))
        ));
        assert_eq!(client.phase(), Phase::Idle);
        assert_eq!(client.retained_requests(), 0);
    }
    let effects = client.propose(target, Tick(0))?;
    let Some(Event::Stage { ticket, .. }) = effects.event else {
        return Err(Error::Unexpected);
    };
    assert_eq!(ticket.attempt, 1);
    let prepare = outgoing(client.staged(Fence::new(&[3, 5])?, Tick(0))?)?;
    let header = Frame::decode(&prepare, limits())
        .map_err(Error::Admission)?
        .header;
    assert_eq!(header.request, RequestId(1));
    assert_eq!(header.packet, PacketNumber(1));
    assert_eq!(header.ticket.attempt, 1);
    Ok(())
}

#[test]
fn both_encoded_sender_widths_change_digest_and_mismatched_target_is_rejected() -> Result<(), Error>
{
    let target = Policy::new(4, 1);
    for changed in [Policy::new(5, 1), Policy::new(4, 2), Policy::new(1, 4)] {
        assert_ne!(
            configuration_digest(&target)?,
            configuration_digest(&changed)?
        );
        assert_eq!(
            decode_configuration::<Policy>(&encode_configuration(&changed)?)?,
            changed
        );
    }
    let (mut client, mut server) = endpoints(Policy::new(2, 3), target.clone(), true)?;
    client.propose(target, Tick(0))?;
    let prepare = outgoing(client.staged(Fence::new(&[3, 5])?, Tick(0))?)?;
    let frame = Frame::decode(&prepare, limits()).map_err(Error::Admission)?;
    let mut fields = encode_configuration(&Policy::new(1, 4))?;
    fields.extend_from_slice(&frame.body[8 + Policy::ENCODED_LEN..]);
    let wrong = replace_fields(&prepare, 8, &fields)?;
    assert_eq!(
        server.receive(origin(Role::Client), &wrong, Tick(0)),
        Err(Error::Unsupported)
    );
    assert_eq!(server.phase(), Phase::Failed);
    Ok(())
}

#[test]
fn generic_256_remains_legal_in_either_direction_through_real_exchanges() -> Result<(), Error> {
    let initial = Policy::new(256, 1);
    let target = Policy::new(1, 256);
    let (mut client, mut server) = endpoints(initial.clone(), target.clone(), true)?;
    let wide = Fence::new(&[u64::MAX; 256])?;
    let narrow = Fence::new(&[0])?;
    exchanged(&mut client, &mut server, target, &wide, &narrow)?;
    assert_eq!(client.sender_channels(Role::Client), 1);
    assert_eq!(server.sender_channels(Role::Server), 256);
    exchanged(&mut client, &mut server, initial, &narrow, &wide)?;
    assert_eq!(client.active_epoch(), Epoch(3));
    assert_eq!(server.sender_channels(Role::Client), 256);
    Ok(())
}

#[test]
fn packed255_is_a_policy_constraint_without_shrinking_generic_or_legacy_maxima() -> Result<(), Error>
{
    let initial = Policy {
        packed: true,
        ..Policy::new(255, 1)
    };
    let target = Policy {
        packed: true,
        ..Policy::new(1, 255)
    };
    let (mut client, mut server) = endpoints(initial, target.clone(), true)?;
    exchanged(
        &mut client,
        &mut server,
        target,
        &Fence::new(&[0; 255])?,
        &Fence::new(&[1])?,
    )?;
    for invalid in [
        Policy {
            packed: true,
            ..Policy::new(256, 1)
        },
        Policy {
            packed: true,
            ..Policy::new(1, 256)
        },
    ] {
        assert!(matches!(
            configuration_digest(&invalid),
            Err(Error::Configuration(_))
        ));
    }
    let old = ModeConfig {
        channels: 256,
        records: RecordLayout::Packed,
        ..ModeConfig::default()
    };
    encode_mode(&old)?;
    Peer::new(
        identity(Role::Client, 3),
        Epoch(1),
        old.clone(),
        std::slice::from_ref(&old),
        timing(),
        Tick(0),
    )?;
    Peer::new_directional(
        identity(Role::Server, 3),
        Epoch(1),
        old.clone(),
        &[old],
        timing(),
        Tick(0),
    )?;
    Ok(())
}
