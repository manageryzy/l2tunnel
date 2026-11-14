//! Pure reservation and ownership regressions; no allocator/RSS or native-I/O claim.

use super::*;
use crate::records::{Admission, Direction, IdentifiedAdmission, Layer, RecordNumber};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn config(channels: usize) -> records::Config {
    records::Config {
        codec: crate::Config {
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
        layer: Layer::Ip,
        max_native: 128,
    }
}

fn duplex(send: usize, receive: usize) -> Result<Plan, Error> {
    Plan::for_engine(config(send), config(receive))
}

fn capacity(plans: &[Plan], external: usize) -> Result<usize, Error> {
    plans.iter().try_fold(
        size_of::<Set>()
            .checked_add(external)
            .ok_or(Error::Budget)?,
        |total, plan| {
            total
                .checked_add(plan.capacity_bytes())
                .ok_or(Error::Budget)
        },
    )
}

fn with_plans(plans: &[Plan], external: usize) -> Result<Set, Error> {
    Set::new(
        Limits {
            capacity_bytes: capacity(plans, external)?,
        },
        external,
    )
}

fn legacy(plan: Plan) -> Result<records::Engine, records::Error> {
    let mut engine = records::Engine::new(plan.send_config())?;
    engine.replace_receive(plan.receive_config(), RecordNumber(0))?;
    Ok(engine)
}

fn emitted(
    entry: &mut Entry<'_>,
    now: u64,
    number: u64,
    allow: bool,
) -> Result<Vec<u8>, records::Error> {
    entry
        .poll(now, RecordNumber(number), allow)?
        .map(<[u8]>::to_vec)
        .ok_or(records::Error::Admission)
}

#[test]
fn exact_layout_helpers_reject_invalid_types_and_overflow_before_attempts() -> TestResult {
    assert_eq!(array_bytes::<u8>(0)?, 0);
    assert_eq!(array_bytes::<u64>(3)?, 3 * size_of::<u64>());
    assert_eq!(array_bytes::<()>(0), Err(crate::Error::Storage));
    assert_eq!(array_bytes::<()>(1), Err(crate::Error::Storage));
    assert_eq!(array_bytes::<u64>(usize::MAX), Err(crate::Error::Storage));
    let mut allocation = Allocation::new(16);
    assert!(matches!(
        allocation.vec::<()>(0),
        Err(crate::Error::Storage)
    ));
    assert!(matches!(
        allocation.deque::<u64>(usize::MAX),
        Err(crate::Error::Storage)
    ));
    assert!(matches!(
        allocation.vec::<u8>(17),
        Err(crate::Error::Storage)
    ));
    assert_eq!(allocation.used(), 0);
    assert_eq!(allocation.allocations(), 0);
    assert_eq!(allocation.vec::<u8>(0)?.capacity(), 0);
    assert_eq!(allocation.deque::<u64>(0)?.capacity(), 0);
    assert_eq!(allocation.allocations(), 0);
    Ok(())
}

#[test]
fn exact_vector_and_non_power_of_two_deque_capacities_are_charged() -> TestResult {
    let total = array_bytes::<u32>(3)? + array_bytes::<u64>(5)?;
    let mut allocation = Allocation::new(total);
    let vector = allocation.vec::<u32>(3)?;
    let deque = allocation.deque::<u64>(5)?;
    assert!(vector.is_empty());
    assert!(deque.is_empty());
    assert_eq!(vector.capacity(), 3);
    assert_eq!(deque.capacity(), 5);
    assert_eq!(allocation.used(), total);
    assert_eq!(allocation.allocations(), 2);
    assert!(matches!(
        allocation.vec::<u8>(1),
        Err(crate::Error::Storage)
    ));
    assert_eq!(allocation.used(), total);
    assert_eq!(allocation.allocations(), 2);
    Ok(())
}

#[test]
fn injected_allocation_failure_refunds_only_its_own_precharge() -> TestResult {
    let mut allocation = Allocation::new(128);
    let retained = allocation.vec::<u8>(7)?;
    allocation.fail_at = Some(2);
    assert!(matches!(
        allocation.deque::<u32>(4),
        Err(crate::Error::Allocation)
    ));
    assert_eq!(allocation.used(), 7);
    assert_eq!(allocation.allocations(), 2);
    assert_eq!(retained.capacity(), 7);
    allocation.fail_at = None;
    let next = allocation.deque::<u32>(4)?;
    assert_eq!(next.capacity(), 4);
    assert_eq!(allocation.used(), 7 + 4 * size_of::<u32>());
    assert_eq!(allocation.allocations(), 3);
    Ok(())
}

#[test]
fn plans_preserve_exact_asymmetric_configs_and_reject_invalid_geometry() -> TestResult {
    let mut send = config(2);
    let mut receive = config(3);
    send.codec.queue_bytes = 4_096;
    receive.codec.flow_sources = 7;
    receive.codec.datagram_bytes = 300;
    let plan = Plan::for_engine(send, receive)?;
    assert_eq!(plan.send_config(), send);
    assert_eq!(plan.receive_config(), receive);
    assert!(plan.capacity_bytes() > 0);
    assert_eq!(
        plan.capacity_bytes(),
        records::Engine::reserved_heap_bytes(send, receive)?
    );
    let mut bad = receive;
    bad.channels = 0;
    assert!(matches!(Plan::for_engine(send, bad), Err(Error::Engine(_))));
    bad = receive;
    bad.layer = Layer::Ethernet;
    assert!(matches!(Plan::for_engine(send, bad), Err(Error::Engine(_))));
    bad = receive;
    bad.max_native -= 1;
    assert!(matches!(Plan::for_engine(send, bad), Err(Error::Engine(_))));
    Ok(())
}

#[test]
fn fixed_external_and_exact_engine_budget_are_independent_charges() -> TestResult {
    let plan = duplex(2, 3)?;
    let external = 37;
    let exact = capacity(&[plan], external)?;
    assert!(matches!(
        Set::new(
            Limits {
                capacity_bytes: usize::MAX
            },
            usize::MAX
        ),
        Err(Error::Budget)
    ));
    assert!(matches!(
        Set::new(
            Limits {
                capacity_bytes: size_of::<Set>() - 1
            },
            0
        ),
        Err(Error::Budget)
    ));
    let mut short = Set::new(
        Limits {
            capacity_bytes: exact - 1,
        },
        external,
    )?;
    let before = short.usage();
    assert_eq!(short.prepare(plan), Err(Error::Budget));
    assert_eq!(short.usage(), before);
    assert_eq!(short.last_allocations, 0);
    assert_eq!(short.next_generation, Some(1));
    let mut set = Set::new(
        Limits {
            capacity_bytes: exact,
        },
        external,
    )?;
    let id = set.prepare(plan)?;
    let usage = set.usage();
    assert_eq!(usage.fixed_bytes, size_of::<Set>());
    assert_eq!(usage.external_bytes, external);
    assert_eq!(usage.engine_bytes, plan.capacity_bytes());
    assert_eq!(usage.building_bytes, 0);
    assert_eq!(usage.peak_bytes, exact);
    assert_eq!(set.engine(id)?.send_config(), plan.send_config());
    assert_eq!(set.engine(id)?.receive_config(), plan.receive_config());
    set.retire(id)?;
    let retired = set.usage();
    assert_eq!(retired.engine_bytes, 0);
    assert_eq!(retired.external_bytes, external);
    assert_eq!(retired.peak_bytes, exact);
    Ok(())
}

#[test]
fn third_slot_refusal_and_reuse_never_revive_a_stale_token() -> TestResult {
    let plan = duplex(1, 2)?;
    let mut set = with_plans(&[plan, plan], 0)?;
    let first = set.prepare(plan)?;
    let second = set.prepare(plan)?;
    let before = set.usage();
    let generation = set.next_generation;
    assert_eq!(set.prepare(plan), Err(Error::Slots));
    assert_eq!(set.usage(), before);
    assert_eq!(set.next_generation, generation);
    set.retire(first)?;
    let replacement = set.prepare(plan)?;
    assert_eq!(first.slot, replacement.slot);
    assert_ne!(first.generation, replacement.generation);
    assert!(matches!(set.engine(first), Err(Error::Stale)));
    assert!(matches!(set.entry(first), Err(Error::Stale)));
    assert_eq!(set.retire(first), Err(Error::Stale));
    assert!(set.engine(second).is_ok());
    assert!(set.engine(replacement).is_ok());
    let forged = EngineId {
        slot: usize::MAX,
        generation: replacement.generation,
    };
    assert!(matches!(set.engine(forged), Err(Error::Stale)));
    assert!(matches!(set.entry(forged), Err(Error::Stale)));
    assert_eq!(set.retire(forged), Err(Error::Stale));
    Ok(())
}

#[test]
fn final_generation_is_usable_once_and_failed_preparation_cannot_burn_it() -> TestResult {
    let plan = duplex(1, 1)?;
    let mut set = with_plans(&[plan], 0)?;
    set.next_generation = Some(u64::MAX);
    set.fail_at = Some(1);
    assert_eq!(
        set.prepare(plan),
        Err(Error::Engine(records::Error::Codec(
            crate::Error::Allocation
        )))
    );
    assert_eq!(set.next_generation, Some(u64::MAX));
    assert_eq!(set.usage().engine_bytes, 0);
    set.fail_at = None;
    let final_id = set.prepare(plan)?;
    assert_eq!(final_id.generation, u64::MAX);
    assert_eq!(set.next_generation, None);
    set.retire(final_id)?;
    let before = set.usage();
    assert_eq!(set.prepare(plan), Err(Error::Exhausted));
    assert_eq!(set.usage(), before);
    assert!(matches!(set.engine(final_id), Err(Error::Stale)));
    Ok(())
}

#[test]
fn every_actual_target_allocation_can_fail_without_mutating_the_old_owner() -> TestResult {
    let old_plan = duplex(2, 3)?;
    let target = duplex(4, 1)?;
    let external = 29;
    let mut trial = with_plans(&[old_plan, target], external)?;
    trial.prepare(old_plan)?;
    trial.prepare(target)?;
    let attempts = trial.last_allocations;
    assert!(
        attempts > 4,
        "the actual engine constructor must provision its nested owners"
    );
    let native = [0xab; 53];
    let security_number = 1_u64 << 44;
    for failure in 1..=attempts {
        let mut set = with_plans(&[old_plan, target], external)?;
        let old = set.prepare(old_plan)?;
        let mut expected = legacy(old_plan)?;
        assert_eq!(set.entry(old)?.offer(0, &native)?, Admission::Accepted);
        assert_eq!(expected.offer(0, &native)?, Admission::Accepted);
        let stats = set.engine(old)?.stats();
        let boundary = set.engine(old)?.boundary(
            Direction::Send,
            records::ChannelId::new(0).ok_or(Error::Stale)?,
        );
        let next_generation = set.next_generation;
        set.fail_at = Some(failure);
        assert_eq!(
            set.prepare(target),
            Err(Error::Engine(records::Error::Codec(
                crate::Error::Allocation
            ))),
            "target allocation {failure} must be an actual constructor point"
        );
        assert_eq!(set.last_allocations, failure);
        assert_eq!(set.next_generation, next_generation);
        assert_eq!(set.usage().engine_bytes, old_plan.capacity_bytes());
        assert_eq!(set.usage().building_bytes, 0);
        assert_eq!(
            set.usage().peak_bytes,
            capacity(&[old_plan, target], external)?
        );
        assert!(set.slots[1].is_none());
        assert_eq!(set.engine(old)?.stats(), stats);
        assert_eq!(set.engine(old)?.send_config(), old_plan.send_config());
        assert_eq!(set.engine(old)?.receive_config(), old_plan.receive_config());
        assert_eq!(
            set.engine(old)?.boundary(
                Direction::Send,
                records::ChannelId::new(0).ok_or(Error::Stale)?
            ),
            boundary
        );
        let actual = emitted(&mut set.entry(old)?, 7, security_number, true)?;
        let expected = expected
            .poll(7, RecordNumber(security_number), true)?
            .map(<[u8]>::to_vec)
            .ok_or(records::Error::Admission)?;
        assert_eq!(
            actual, expected,
            "the old engine remains usable after allocation {failure}"
        );
        assert_eq!(set.usage().engine_bytes, old_plan.capacity_bytes());
        set.fail_at = None;
        let next = set.prepare(target)?;
        assert_eq!(Some(next.generation), next_generation);
        assert_eq!(
            set.usage().engine_bytes,
            old_plan.capacity_bytes() + target.capacity_bytes()
        );
    }
    Ok(())
}

#[test]
fn pending_send_and_partial_receive_each_prevent_retirement() -> TestResult {
    let plan = duplex(1, 1)?;
    let mut sending = with_plans(&[plan], 11)?;
    let id = sending.prepare(plan)?;
    assert_eq!(
        sending.entry(id)?.offer(0, &[0xaa; 9])?,
        Admission::Accepted
    );
    let before = sending.usage();
    assert_eq!(sending.retire(id), Err(Error::NotDrained));
    assert_eq!(sending.usage(), before);
    assert!(sending.engine(id).is_ok());

    let mut receiving = with_plans(&[plan], 11)?;
    let id = receiving.prepare(plan)?;
    // One real source carries only the first byte of the two-byte native prefix.
    let mut partial = [crate::KIND_SOURCE, 0, 0, 0, 0, 0];
    receiving
        .entry(id)?
        .accept(0, RecordNumber(9), &mut partial)?;
    assert!(receiving.entry(id)?.pop()?.is_none());
    assert!(receiving.engine(id)?.send_drained());
    assert!(!receiving.engine(id)?.receive_drained());
    let before = receiving.usage();
    assert_eq!(receiving.retire(id), Err(Error::NotDrained));
    assert_eq!(receiving.usage(), before);
    assert_eq!(receiving.engine(id)?.stats().receiver.sources, 1);
    Ok(())
}

#[test]
fn restricted_entries_carry_real_asymmetric_bodies_identities_and_feedback() -> TestResult {
    let forward = duplex(2, 3)?;
    let reverse = duplex(3, 2)?;
    let mut left = with_plans(&[forward], 0)?;
    let mut right = with_plans(&[reverse], 0)?;
    let left_id = left.prepare(forward)?;
    let right_id = right.prepare(reverse)?;
    let native = [0xab; 53];
    let selected = records::ChannelId::new(1).ok_or(records::Error::Configuration)?;
    let accepted = match left
        .entry(left_id)?
        .offer_on_channel_identified(0, selected, &native)?
    {
        IdentifiedAdmission::Accepted(identity) => identity,
        _ => return Err(Box::new(records::Error::Admission)),
    };
    assert_eq!(accepted.channel, selected);
    let left_usage = left.usage();
    let right_usage = right.usage();
    let mut wire = {
        let mut entry = left.entry(left_id)?;
        let emission = entry
            .poll_emission(0, RecordNumber(1 << 42), true)?
            .ok_or(records::Error::Admission)?;
        assert_eq!(emission.kind(), records::EmissionKind::Source);
        emission.body().to_vec()
    };
    right
        .entry(right_id)?
        .accept(1, RecordNumber(1 << 42), &mut wire)?;
    {
        let mut entry = right.entry(right_id)?;
        let received = entry.pop_identified()?.ok_or(records::Error::Admission)?;
        assert_eq!(received.identity, accepted);
        assert_eq!(received.bytes, native);
    }
    assert!(right.entry(right_id)?.pop()?.is_none());
    let mut feedback = {
        let mut entry = right.entry(right_id)?;
        let emission = entry
            .poll_emission(100, RecordNumber(1 << 48), false)?
            .ok_or(records::Error::Admission)?;
        assert_eq!(emission.kind(), records::EmissionKind::Feedback);
        emission.body().to_vec()
    };
    assert_eq!(feedback[0] & crate::KIND_MASK, crate::KIND_FEEDBACK);
    left.entry(left_id)?
        .accept(100, RecordNumber(1 << 48), &mut feedback)?;
    assert!(left.engine(left_id)?.send_drained());
    assert!(right.engine(right_id)?.receive_drained());
    assert_eq!(
        left.usage(),
        left_usage,
        "ACK does not release allocated capacity"
    );
    assert_eq!(
        right.usage(),
        right_usage,
        "native extraction does not release allocated capacity"
    );
    left.retire(left_id)?;
    right.retire(right_id)?;
    assert_eq!(left.usage().engine_bytes, 0);
    assert_eq!(right.usage().engine_bytes, 0);
    Ok(())
}

#[test]
fn set_and_restricted_mutable_borrow_are_send_without_shared_globals() -> TestResult {
    fn assert_send<T: Send>(_: &T) {}
    let plan = duplex(1, 2)?;
    let mut set = with_plans(&[plan], 0)?;
    assert_send(&set);
    let id = set.prepare(plan)?;
    assert_send(&set.entry(id)?);
    Ok(())
}
