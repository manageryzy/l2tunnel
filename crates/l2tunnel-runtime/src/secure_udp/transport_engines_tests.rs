//! Real leased Peer intents/operations and actual reserved engines; no physical proof claim.

use super::*;
use l2tunnel::swift_configuration::{Descriptor, EnvelopeDigest};
use l2tunnel_management::{EndpointId, Ingress, LaneId, SessionId};
use l2tunnel_swift::policy;
use std::mem::size_of;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const CAP: tx::Tick = tx::Tick(1_000);
const EXTERNAL: usize = 137;

fn direction(channels: usize) -> policy::Direction {
    policy::Direction {
        records: records::Config {
            codec: l2tunnel_swift::Config {
                datagram_bytes: 256,
                window: 2,
                repair_numerator: 0,
                repair_denominator: 1,
                flow_sources: 6,
                queue_bytes: 2_048,
                max_packet: 129,
                flush_micros: 0,
                feedback_micros: 10,
                tail_micros: 1_000,
                min_rto_micros: 100,
                max_rto_micros: 10_000,
            },
            channels,
            layer: records::Layer::Ip,
            max_native: 128,
        },
        bytes_per_second: 100_000,
    }
}
fn configuration(client: usize, server: usize) -> Result<C> {
    Ok(C::new(
        EnvelopeDigest::new([0x71; 32]),
        Descriptor::new(1500, direction(client), direction(server))?,
    )?)
}
fn values() -> Result<[C; 2]> {
    Ok([configuration(2, 3)?, configuration(4, 1)?])
}
fn identity(role: Role) -> tx::Identity {
    tx::Identity {
        session: SessionId([0x62; 16]),
        role,
        lane: LaneId(7),
        local: EndpointId(if role == Role::Client { 1 } else { 2 }),
        remote: EndpointId(if role == Role::Client { 2 } else { 1 }),
    }
}
fn ingress(role: Role) -> Ingress {
    Ingress::AuthenticatedManagement {
        session: identity(role).session,
        lane: LaneId(7),
        sender: role,
    }
}
fn peer_with(identity: tx::Identity, epoch: Epoch, values: &[C]) -> Result<tx::Peer<C>> {
    Ok(tx::Peer::new_leased_directional(
        identity,
        epoch,
        values[0],
        values,
        tx::Settings {
            retry_ms: 10,
            phase_timeout_ms: 100,
            reconcile_timeout_ms: 200,
        },
        tx::LeaseSettings {
            session_expires: tx::Tick(10_000),
            max_operation_ms: 2_000,
            transaction_epoch: 4,
        },
        tx::Tick(0),
    )?)
}
fn peer(role: Role) -> Result<tx::Peer<C>> {
    peer_with(identity(role), Epoch(10), &values()?)
}
fn budget(role: Role, values: &[C]) -> Result<storage::Limits> {
    let capacity_bytes = values.iter().try_fold(
        size_of::<storage::Set>() + EXTERNAL,
        |total, value| -> Result<usize> {
            let bytes = plan(*value, role)?.capacity_bytes();
            total
                .checked_add(bytes)
                .ok_or_else(|| "fixture capacity overflow".into())
        },
    )?;
    Ok(storage::Limits { capacity_bytes })
}
fn bank(role: Role) -> Result<Bank> {
    let values = values()?;
    Ok(Bank::new(
        identity(role),
        Epoch(10),
        values[0],
        budget(role, &values)?,
        EXTERNAL,
    )?)
}
fn intent(peer: &tx::Peer<C>, target: C) -> Result<tx::Preparation<C>> {
    Ok(peer.preview_propose_until(&target, tx::Tick(1), CAP)?)
}
fn operation(peer: &tx::Peer<C>) -> Result<tx::Operation> {
    peer.operation()
        .ok_or_else(|| "missing actual operation".into())
}
fn flight(effects: tx::Effects<C>) -> Result<Vec<u8>> {
    effects
        .outbound
        .ok_or_else(|| "missing actual Peer flight".into())
}
fn width(engine: &records::Engine, direction: records::Direction) -> usize {
    (0..64)
        .filter_map(records::ChannelId::new)
        .filter(|c| engine.boundary(direction, *c).is_some())
        .count()
}
fn body(bank: &mut Bank, epoch: Epoch, now: u64, number: u64, allow: bool) -> Result<Vec<u8>> {
    Ok(bank
        .entry(epoch)?
        .poll(now, records::RecordNumber(number), allow)?
        .ok_or("missing actual record output")?
        .to_vec())
}
fn transfer(left: &mut Bank, right: &mut Bank, epoch: Epoch) -> Result {
    let native = [0xab; 53];
    let admitted = match left.entry(epoch)?.offer_identified(0, &native)? {
        records::IdentifiedAdmission::Accepted(identity) => identity,
        _ => return Err("native fixture admission refused".into()),
    };
    let mut wire = body(left, epoch, 0, 1 << 42, true)?;
    right
        .entry(epoch)?
        .accept(1, records::RecordNumber(1 << 42), &mut wire)?;
    {
        let mut entry = right.entry(epoch)?;
        let received = entry
            .pop_identified()?
            .ok_or("native fixture not delivered")?;
        assert_eq!(received.identity, admitted);
        assert_eq!(received.bytes, native);
    }
    // The successful pop retains a conservative ready hint. Exhaust the actual
    // extraction API once more so it observes empty stream state without a new ID.
    let delivered = right.engine(epoch)?.stats().receiver.packets;
    let boundary = right
        .engine(epoch)?
        .boundary(records::Direction::Receive, admitted.channel);
    assert!(right.entry(epoch)?.pop_identified()?.is_none());
    assert_eq!(right.engine(epoch)?.stats().receiver.packets, delivered);
    assert_eq!(
        right
            .engine(epoch)?
            .boundary(records::Direction::Receive, admitted.channel),
        boundary
    );
    let mut feedback = body(right, epoch, 100, 1 << 48, false)?;
    left.entry(epoch)?
        .accept(100, records::RecordNumber(1 << 48), &mut feedback)?;
    assert!(left.engine(epoch)?.send_drained());
    assert!(right.engine(epoch)?.receive_drained());
    Ok(())
}

#[test]
fn actual_reservation_hides_virgin_target_and_keeps_old_asymmetric_forwarding_usable() -> Result {
    let values = values()?;
    let mut peer = peer(Role::Client)?;
    let mut left = bank(Role::Client)?;
    let mut right = bank(Role::Server)?;
    assert_eq!(left.current(), &values[0]);
    assert_eq!(left.epoch(), Epoch(10));
    assert_eq!(width(left.engine(Epoch(10))?, records::Direction::Send), 2);
    assert_eq!(
        width(left.engine(Epoch(10))?, records::Direction::Receive),
        3
    );
    assert_eq!(width(right.engine(Epoch(10))?, records::Direction::Send), 3);
    let initial = left.usage();
    let mut guard = left.prepare(intent(&peer, values[1])?)?;
    assert!(guard.matches(&intent(&peer, values[1])?));
    assert_eq!(guard.config(), &values[1]);
    assert_eq!(guard.identity(), identity(Role::Client));
    assert_eq!(guard.ticket().epoch, Epoch(11));
    assert_eq!(guard.origin().epoch, Epoch(10));
    assert_eq!(guard.expires(), CAP);
    assert!(left.engine(Epoch(11)).is_err());
    assert!(left.entry(Epoch(11)).is_err());
    assert!(left.usage().engine_bytes > initial.engine_bytes);
    assert!(peer.operation().is_none());
    transfer(&mut left, &mut right, Epoch(10))?;
    left.cancel(&mut guard)?;
    assert_eq!(left.usage().engine_bytes, initial.engine_bytes);
    assert!(!guard.matches(&intent(&peer, values[1])?));
    assert!(left.cancel(&mut guard).is_err());
    peer.propose_until(values[1], tx::Tick(1), CAP)?;
    assert_eq!(operation(&peer)?.ticket().attempt, 1);
    Ok(())
}

#[test]
fn equal_identity_and_config_banks_reject_each_others_actual_guards() -> Result {
    let values = values()?;
    let mut peer = peer(Role::Client)?;
    let mut left = bank(Role::Client)?;
    let mut other = bank(Role::Client)?;
    let mut guard = left.prepare(intent(&peer, values[1])?)?;
    let mut foreign = other.prepare(intent(&peer, values[1])?)?;
    assert_ne!(left.owner, other.owner);
    let a = left.usage();
    let b = other.usage();
    assert!(left.cancel(&mut foreign).is_err());
    assert!(other.cancel(&mut guard).is_err());
    peer.propose_until(values[1], tx::Tick(1), CAP)?;
    let operation = operation(&peer)?;
    assert!(left.stage(&mut foreign, operation).is_err());
    assert!(other.stage(&mut guard, operation).is_err());
    assert_eq!(left.usage(), a);
    assert_eq!(other.usage(), b);
    left.stage(&mut guard, operation)?;
    other.stage(&mut foreign, operation)?;
    assert!(left.stage(&mut guard, operation).is_err());
    assert!(left.cancel(&mut guard).is_err());
    assert_eq!(left.epoch(), Epoch(10));
    assert!(left.engine(Epoch(11)).is_ok());
    Ok(())
}

#[test]
fn consumed_serial_cannot_free_reused_slot_and_exhaustion_is_atomic() -> Result {
    let values = values()?;
    let peer = peer(Role::Client)?;
    let mut bank = bank(Role::Client)?;
    let mut old = bank.prepare(intent(&peer, values[1])?)?;
    let first_serial = old.serial;
    bank.cancel(&mut old)?;
    let mut fresh = bank.prepare(intent(&peer, values[1])?)?;
    assert!(fresh.serial > first_serial);
    let before = bank.usage();
    assert!(bank.cancel(&mut old).is_err());
    assert_eq!(bank.usage(), before);
    bank.cancel(&mut fresh)?;
    bank.next_serial = u64::MAX;
    let before = bank.usage();
    assert!(bank.prepare(intent(&peer, values[1])?).is_err());
    assert_eq!(bank.usage(), before);
    assert!(bank.reservation.is_none());
    assert_eq!(bank.next_serial, u64::MAX);
    let local = AtomicU64::new(u64::MAX - 1);
    assert_eq!(allocate_owner(&local)?, u64::MAX - 1);
    assert!(allocate_owner(&local).is_err());
    assert_eq!(local.load(Ordering::Relaxed), u64::MAX);
    Ok(())
}

#[test]
fn exact_pair_budget_and_one_short_actual_preparation_preserve_old_generation() -> Result {
    let values = values()?;
    let peer = peer(Role::Client)?;
    let exact = budget(Role::Client, &values)?;
    let mut short = Bank::new(
        identity(Role::Client),
        Epoch(10),
        values[0],
        storage::Limits {
            capacity_bytes: exact.capacity_bytes - 1,
        },
        EXTERNAL,
    )?;
    let before = short.usage();
    assert!(short.prepare(intent(&peer, values[1])?).is_err());
    assert_eq!(short.usage(), before);
    assert!(short.reservation.is_none());
    assert_eq!(short.next_serial, 1);
    assert!(short.engine(Epoch(10))?.send_drained());
    assert!(short.engine(Epoch(11)).is_err());
    let mut exact = bank(Role::Client)?;
    let mut guard = exact.prepare(intent(&peer, values[1])?)?;
    assert_eq!(
        exact.usage().fixed_bytes + exact.usage().external_bytes + exact.usage().engine_bytes,
        exact.usage().limit_bytes
    );
    let before = exact.usage();
    assert_eq!(
        exact
            .prepare(intent(&peer, values[1])?)
            .err()
            .map(|e| e.kind()),
        Some(io::ErrorKind::WouldBlock)
    );
    assert_eq!(exact.usage(), before);
    exact.cancel(&mut guard)?;
    Ok(())
}

#[test]
fn initial_capacity_preflight_matches_actual_role_bank_and_rejects_checked_overflow() -> Result {
    let values = values()?;
    for role in [Role::Client, Role::Server] {
        let required = Bank::required_capacity(values[0], role, EXTERNAL)?;
        let actual = Bank::new(
            identity(role),
            Epoch(10),
            values[0],
            storage::Limits {
                capacity_bytes: required,
            },
            EXTERNAL,
        )?;
        let usage = actual.usage();
        assert_eq!(
            usage.fixed_bytes + usage.external_bytes + usage.engine_bytes,
            required
        );
        assert_eq!(usage.peak_bytes, required);
        assert_eq!(usage.external_bytes, EXTERNAL);
        assert_eq!(actual.current(), &values[0]);
        assert_eq!(
            width(actual.engine(Epoch(10))?, records::Direction::Send),
            if role == Role::Client { 2 } else { 3 }
        );
        assert_eq!(
            width(actual.engine(Epoch(10))?, records::Direction::Receive),
            if role == Role::Client { 3 } else { 2 }
        );
        let error = Bank::new(
            identity(role),
            Epoch(10),
            values[0],
            storage::Limits {
                capacity_bytes: required - 1,
            },
            EXTERNAL,
        )
        .err()
        .ok_or("one-short initial Bank was admitted")?;
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(matches!(
            error
                .get_ref()
                .and_then(|cause| cause.downcast_ref::<storage::Error>()),
            Some(storage::Error::Budget)
        ));
        assert_eq!(
            Bank::required_capacity(values[0], role, usize::MAX)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
        assert_eq!(actual.usage(), usage);
    }
    Ok(())
}

#[test]
fn actual_intents_with_wrong_identity_old_origin_envelope_or_native_format_are_refused() -> Result {
    let values = values()?;
    let mut bank = bank(Role::Client)?;
    let before = bank.usage();
    let base = identity(Role::Client);
    let mut identities = [base; 4];
    identities[0].session = SessionId([0x63; 16]);
    identities[1].lane = LaneId(8);
    identities[2].local = EndpointId(3);
    identities[3].remote = EndpointId(4);
    for identity in identities {
        let peer = peer_with(identity, Epoch(10), &values)?;
        assert!(bank.prepare(intent(&peer, values[1])?).is_err());
        assert_eq!(bank.usage(), before);
    }
    let peer = peer_with(base, Epoch(9), &values)?;
    assert!(bank.prepare(intent(&peer, values[1])?).is_err());
    assert_eq!(bank.usage(), before);
    let wrong_initial = configuration(1, 3)?;
    let peer = peer_with(base, Epoch(10), &[wrong_initial, values[1]])?;
    assert!(bank.prepare(intent(&peer, values[1])?).is_err());
    assert_eq!(bank.usage(), before);
    let envelope = C::new(EnvelopeDigest::new([0x72; 32]), values[1].descriptor())?;
    let mut changed_forward = direction(4);
    let mut changed_reverse = direction(1);
    for direction in [&mut changed_forward, &mut changed_reverse] {
        direction.records.max_native = 64;
        direction.records.codec.max_packet = 65;
    }
    let native = C::new(
        values[0].envelope(),
        Descriptor::new(1500, changed_forward, changed_reverse)?,
    )?;
    for bad in [envelope, native] {
        let peer = peer_with(base, Epoch(10), &[values[0], bad])?;
        assert!(bank.prepare(intent(&peer, bad)?).is_err());
        assert_eq!(bank.usage(), before);
    }
    assert!(bank.reservation.is_none());
    Ok(())
}

#[test]
fn actual_operation_cap_or_full_binding_mismatch_cannot_consume_prepared_engine() -> Result {
    let values = values()?;
    let mut peer = peer(Role::Client)?;
    let mut bank = bank(Role::Client)?;
    let mut guard = bank.prepare(intent(&peer, values[1])?)?;
    let mut wrong = peer_with(identity(Role::Client), Epoch(10), &values)?;
    wrong.propose_until(values[1], tx::Tick(1), tx::Tick(999))?;
    let before = bank.usage();
    assert!(bank.stage(&mut guard, operation(&wrong)?).is_err());
    assert_eq!(bank.usage(), before);
    assert!(!guard.matches(&peer.preview_propose_until(&values[1], tx::Tick(1), tx::Tick(999))?));
    let different_target = configuration(4, 2)?;
    let mut wrong = peer_with(
        identity(Role::Client),
        Epoch(10),
        &[values[0], different_target],
    )?;
    wrong.propose_until(different_target, tx::Tick(1), CAP)?;
    assert!(bank.stage(&mut guard, operation(&wrong)?).is_err());
    assert_eq!(bank.usage(), before);
    let mut different = identity(Role::Client);
    different.lane = LaneId(8);
    let mut wrong = peer_with(different, Epoch(10), &values)?;
    wrong.propose_until(values[1], tx::Tick(1), CAP)?;
    assert!(bank.stage(&mut guard, operation(&wrong)?).is_err());
    assert_eq!(bank.usage(), before);
    assert!(guard.matches(&intent(&peer, values[1])?));
    peer.propose_until(values[1], tx::Tick(1), CAP)?;
    let actual = operation(&peer)?;
    bank.stage(&mut guard, actual)?;
    assert!(bank.commit(operation(&wrong)?).is_err());
    assert!(bank.abort(operation(&wrong)?).is_err());
    assert!(bank.retire(actual).is_err());
    assert_eq!(bank.epoch(), Epoch(10));
    assert!(bank.engine(Epoch(11)).is_ok());
    Ok(())
}

struct Lab {
    client: tx::Peer<C>,
    server: tx::Peer<C>,
    left: Bank,
    right: Bank,
    operations: [tx::Operation; 2],
}
fn staged() -> Result<Lab> {
    let values = values()?;
    let mut client = peer(Role::Client)?;
    let mut server = peer(Role::Server)?;
    let mut left = bank(Role::Client)?;
    let mut right = bank(Role::Server)?;
    let mut local = left.prepare(intent(&client, values[1])?)?;
    client.propose_until(values[1], tx::Tick(1), CAP)?;
    let client_operation = operation(&client)?;
    left.stage(&mut local, client_operation)?;
    let prepare = flight(client.staged(tx::Fence::new(&[0; 2])?, tx::Tick(2))?)?;
    let incoming = server
        .preview_receive_until(ingress(Role::Client), &prepare, tx::Tick(3), CAP)?
        .ok_or("missing remote intent")?;
    let mut remote = right.prepare(incoming)?;
    server.receive_until(ingress(Role::Client), &prepare, tx::Tick(3), CAP)?;
    let server_operation = operation(&server)?;
    right.stage(&mut remote, server_operation)?;
    let ready = flight(server.staged(tx::Fence::new(&[0; 3])?, tx::Tick(4))?)?;
    client.receive_until(ingress(Role::Server), &ready, tx::Tick(5), CAP)?;
    Ok(Lab {
        client,
        server,
        left,
        right,
        operations: [client_operation, server_operation],
    })
}
fn committed(lab: &mut Lab) -> Result<Vec<u8>> {
    let local = tx::Fence::new(&[0; 2])?;
    let remote = tx::Fence::new(&[0; 3])?;
    let barrier = flight(lab.client.confirm_drained(&local, &remote, tx::Tick(6))?)?;
    lab.server
        .receive_until(ingress(Role::Client), &barrier, tx::Tick(7), CAP)?;
    let ack = flight(lab.server.confirm_drained(&remote, &local, tx::Tick(8))?)?;
    let commit =
        flight(
            lab.client
                .receive_until(ingress(Role::Server), &ack, tx::Tick(9), CAP)?,
        )?;
    let ack = lab
        .server
        .receive_until(ingress(Role::Client), &commit, tx::Tick(10), CAP)?;
    assert!(matches!(ack.event, Some(tx::Event::Committed(_))));
    lab.right.commit(lab.operations[1])?;
    let retire =
        lab.client
            .receive_until(ingress(Role::Server), &flight(ack)?, tx::Tick(11), CAP)?;
    assert!(matches!(retire.event, Some(tx::Event::Committed(_))));
    lab.left.commit(lab.operations[0])?;
    flight(retire)
}

#[test]
fn actual_asymmetric_peer_commit_and_retire_promote_once_and_preserve_final_control_custody()
-> Result {
    let values = values()?;
    let mut lab = staged()?;
    assert_eq!(
        width(lab.left.engine(Epoch(11))?, records::Direction::Send),
        4
    );
    assert_eq!(
        width(lab.left.engine(Epoch(11))?, records::Direction::Receive),
        1
    );
    let retire = committed(&mut lab)?;
    assert_eq!(lab.left.current(), &values[1]);
    assert_eq!(lab.right.current(), &values[1]);
    assert_eq!(lab.left.epoch(), Epoch(11));
    assert!(lab.left.engine(Epoch(10)).is_ok());
    assert!(lab.left.abort(lab.operations[0]).is_err());
    assert!(lab.left.commit(lab.operations[0]).is_err());
    let reply = lab
        .server
        .receive_until(ingress(Role::Client), &retire, tx::Tick(12), CAP)?;
    assert!(matches!(reply.event, Some(tx::Event::Retired(Epoch(10)))));
    lab.right.retire(lab.operations[1])?;
    let effects =
        lab.client
            .receive_until(ingress(Role::Server), &flight(reply)?, tx::Tick(13), CAP)?;
    assert!(matches!(effects.event, Some(tx::Event::Retired(Epoch(10)))));
    lab.left.retire(lab.operations[0])?;
    assert!(lab.left.engine(Epoch(10)).is_err());
    assert!(lab.right.entry(Epoch(10)).is_err());
    assert!(lab.left.retire(lab.operations[0]).is_err());
    assert!(lab.client.operation().is_some());
    assert!(lab.server.operation().is_some());
    assert!(!lab.client.can_admit_data()); // Bank retirement is not whole-message proof.
    transfer(&mut lab.left, &mut lab.right, Epoch(11))?;
    Ok(())
}

#[test]
fn precommit_abort_releases_only_a_still_drained_target_and_not_current_engine() -> Result {
    let values = values()?;
    let mut peer = peer(Role::Client)?;
    let mut bank = bank(Role::Client)?;
    let initial = bank.usage();
    let mut guard = bank.prepare(intent(&peer, values[1])?)?;
    peer.propose_until(values[1], tx::Tick(1), CAP)?;
    let operation = operation(&peer)?;
    bank.stage(&mut guard, operation)?;
    let expired_phase = peer.poll(tx::Tick(101))?;
    assert!(matches!(expired_phase.event, Some(tx::Event::Aborted(1))));
    bank.abort(operation)?;
    assert_eq!(bank.current(), &values[0]);
    assert_eq!(bank.epoch(), Epoch(10));
    assert_eq!(bank.usage().engine_bytes, initial.engine_bytes);
    assert!(bank.engine(Epoch(11)).is_err());
    assert!(bank.abort(operation).is_err());
    assert!(bank.cancel(&mut guard).is_err());
    Ok(())
}

#[test]
fn set_drain_refusals_preserve_staged_target_and_old_mapping_before_any_release() -> Result {
    let mut lab = staged()?;
    // Exercise the bank's defensive storage boundary, not permission to transmit early.
    assert_eq!(
        lab.left.entry(Epoch(11))?.offer(0, &[0xaa; 40])?,
        records::Admission::Accepted
    );
    let before = lab.left.usage();
    assert!(lab.left.abort(lab.operations[0]).is_err());
    assert_eq!(lab.left.usage(), before);
    assert!(lab.left.engine(Epoch(11)).is_ok());
    let mut lab = staged()?;
    let _retire = committed(&mut lab)?;
    // An invariant-violating caller can still hold old local debt; retirement must refuse it.
    assert_eq!(
        lab.left.entry(Epoch(10))?.offer(0, &[0xaa; 40])?,
        records::Admission::Accepted
    );
    let before = lab.left.usage();
    assert!(lab.left.retire(lab.operations[0]).is_err());
    assert_eq!(lab.left.usage(), before);
    assert_eq!(lab.left.epoch(), Epoch(11));
    assert!(lab.left.engine(Epoch(10)).is_ok());
    assert!(lab.left.engine(Epoch(11)).is_ok());
    Ok(())
}
