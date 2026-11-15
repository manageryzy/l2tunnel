//! Actual wrapper admission, failure cleanup, publication and wire-preserving reuse.

use super::super::wrapper_storage::{self as wrapper, Kind, Slot};
use super::*;

fn message_limits(
    selected: Settings,
    role: mg::Role,
    expires: Duration,
) -> Result<[messages::storage::Limits; 3]> {
    Ok(selected
        .message_storage_plans(binding(role), Duration::ZERO, expires)?
        .map(|plan| messages::storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        }))
}

fn reserved(role: mg::Role, selected: Settings, extra: usize, expires: Duration) -> Result<Owner> {
    let plan = wrapper::Plan::new(selected, base())?;
    Ok(Owner::new_leased_reserved_messages_with_wrapper_plan(
        base(),
        selected,
        binding(role),
        scope(3, 0x31),
        scope(1, 0x71),
        Duration::ZERO,
        expires,
        message_limits(selected, role, expires)?,
        plan,
        wrapper::Limits {
            capacity_bytes: plan.capacity_bytes() + extra,
        },
    )?)
}

fn storage(plan: &wrapper::Plan, capacity_bytes: usize) -> Result<Storage<'_>> {
    Ok(Storage::ReservedMessages {
        messages: message_limits(selected(), mg::Role::Client, Duration::from_secs(5))?,
        wrapper: plan,
        wrapper_limit: wrapper::Limits { capacity_bytes },
    })
}

fn trace() -> wrapper::TraceHandle {
    Rc::new(RefCell::new(wrapper::Trace::default()))
}

fn wrapper_error(error: &io::Error) -> Option<&wrapper::Error> {
    error.get_ref().and_then(|error| error.downcast_ref())
}

fn inventory(owner: &Owner) -> Result<[(usize, usize); 6]> {
    let Backend::Streamed(streamed) = &owner.backend else {
        return Err("missing actual streamed owner".into());
    };
    let value = &**streamed;
    Ok([
        (std::ptr::from_ref(value) as usize, 1),
        (
            value.outgoing[0].as_ptr() as usize,
            value.outgoing[0].capacity(),
        ),
        (
            value.outgoing[1].as_ptr() as usize,
            value.outgoing[1].capacity(),
        ),
        (
            value.outgoing[2].as_ptr() as usize,
            value.outgoing[2].capacity(),
        ),
        (value.envelope.as_ptr() as usize, value.envelope.capacity()),
        (value.raw.as_ptr() as usize, value.raw.capacity()),
    ])
}

#[test]
fn wrapper_layout_overflow_mismatched_plan_and_one_short_refuse_before_provisioning() -> Result {
    let mut outgoing_overflow = selected();
    outgoing_overflow.streams[2].max_outbound_messages = usize::MAX;
    let mut envelope_overflow = selected();
    envelope_overflow.streams[1].max_message_bytes = usize::MAX;
    let mut raw_overflow = base();
    raw_overflow.recovery.max_source_bytes = usize::MAX;
    for (selected, base) in [
        (outgoing_overflow, base()),
        (envelope_overflow, base()),
        (selected(), raw_overflow),
    ] {
        let error = wrapper::Plan::new(selected, base)
            .err()
            .ok_or("overflow plan accepted")?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(wrapper_error(&error), Some(&wrapper::Error::Layout));
    }
    let plan = wrapper::Plan::new(selected(), base())?;
    let events = trace();
    let mut allocation = wrapper::Allocation::traced(None, events.clone());
    let entered = std::cell::Cell::new(false);
    let error = plan
        .provision(
            wrapper::Limits {
                capacity_bytes: plan.capacity_bytes() - 1,
            },
            &mut allocation,
            |_, _, _| {
                entered.set(true);
                Err(io::Error::other("short wrapper entered publication"))
            },
        )
        .err()
        .ok_or("short wrapper published")?;
    assert_eq!(
        wrapper_error(&error),
        Some(&wrapper::Error::Limit {
            required: plan.capacity_bytes(),
            limit: plan.capacity_bytes() - 1,
        })
    );
    assert!(!entered.get());
    assert_eq!(allocation.attempts(), 0);
    assert!(events.borrow().events().next().is_none());

    let mut other = selected();
    other.streams[0].max_outbound_messages += 1;
    let mut other_base = base();
    other_base.interval += Duration::from_millis(1);
    for (plan, limit, expected) in [
        (
            plan,
            plan.capacity_bytes() - 1,
            wrapper::Error::Limit {
                required: plan.capacity_bytes(),
                limit: plan.capacity_bytes() - 1,
            },
        ),
        (
            wrapper::Plan::new(other, base())?,
            usize::MAX,
            wrapper::Error::PlanMismatch,
        ),
        (
            wrapper::Plan::new(selected(), other_base)?,
            usize::MAX,
            wrapper::Error::PlanMismatch,
        ),
    ] {
        let error = Owner::construct_with_wrapper_allocation(
            base(),
            Some(selected()),
            binding(mg::Role::Client),
            scope(3, 0x31),
            scope(1, 0x71),
            Duration::ZERO,
            Duration::from_secs(5),
            storage(&plan, limit)?,
            &mut allocation,
        )
        .err()
        .ok_or("invalid wrapper construction published an Owner")?;
        assert_eq!(wrapper_error(&error), Some(&expected));
        assert_eq!(allocation.attempts(), 0);
        assert!(events.borrow().events().next().is_none());
    }
    Ok(())
}

#[test]
fn exact_and_plus_one_wrapper_limits_construct_actual_asymmetric_backing_once() -> Result {
    let mut selected = selected();
    for (settings, count) in selected.streams.iter_mut().zip([2, 3, 4]) {
        settings.max_outbound_messages = count;
    }
    for role in [mg::Role::Client, mg::Role::Server] {
        for extra in [0, 1] {
            let expires = Duration::from_secs(5);
            let plan = wrapper::Plan::new(selected, base())?;
            let owner = reserved(role, selected, extra, expires)?;
            let usage = owner
                .wrapper_storage_usage()?
                .ok_or("missing actual wrapper Usage")?;
            assert_eq!(usage.limit_bytes, plan.capacity_bytes() + extra);
            assert_eq!(usage.capacity_bytes, plan.capacity_bytes());
            assert_eq!(usage.allocations, 6);
            assert_eq!(owner.wrapper_capacity_bytes()?, usage.capacity_bytes);
            let Backend::Streamed(streamed) = &owner.backend else {
                return Err("missing actual streamed wrapper".into());
            };
            assert!(matches!(streamed, wrapper::StreamedStorage::Reserved(_)));
            assert!(streamed.leased);
            assert_eq!(
                streamed.outgoing.each_ref().map(|values| values.capacity()),
                [2, 3, 4, 0]
            );
            assert!(streamed.outgoing.iter().all(Vec::is_empty));
            assert_eq!(streamed.envelope.len(), 2048);
            assert_eq!(streamed.envelope.capacity(), 2048);
            assert_eq!(
                streamed.raw.len(),
                base().recovery.max_source_bytes + recovery::DATA_HEADER_BYTES
            );
            assert_eq!(streamed.raw.capacity(), streamed.raw.len());
            let measured = std::mem::size_of::<Streamed>()
                + [2, 3, 4].into_iter().sum::<usize>() * std::mem::size_of::<Outgoing>()
                + streamed.envelope.capacity()
                + streamed.raw.capacity();
            assert_eq!(usage.capacity_bytes, measured);
            let plans = selected.message_storage_plans(binding(role), Duration::ZERO, expires)?;
            let full = owner
                .message_storage_usage()
                .ok_or("missing actual message pools")?;
            for (actual, plan) in full.into_iter().zip(plans) {
                assert_eq!(actual.capacity_bytes, plan.capacity_bytes());
                assert_eq!(actual.arq.capacity_bytes, plan.arq_plan().capacity_bytes());
                assert_eq!(
                    actual.reassembly.capacity_bytes,
                    plan.reassembly_plan().capacity_bytes()
                );
            }
        }
    }
    let old = Owner::new_leased(
        base(),
        selected,
        binding(mg::Role::Client),
        scope(3, 0x31),
        scope(1, 0x71),
        Duration::ZERO,
        Duration::from_secs(5),
    )?;
    assert_eq!(old.wrapper_storage_usage()?, None);
    assert_eq!(old.message_storage_usage(), None);
    Ok(())
}

#[test]
fn every_wrapper_reservation_refusal_drops_actual_partial_backing_and_all_complete_owners() -> Result
{
    let plan = wrapper::Plan::new(selected(), base())?;
    let slots = [
        Slot::Cell,
        Slot::Outgoing(0),
        Slot::Outgoing(1),
        Slot::Outgoing(2),
        Slot::Envelope,
        Slot::Raw,
    ];
    let plans = selected().message_storage_plans(
        binding(mg::Role::Client),
        Duration::ZERO,
        Duration::from_secs(5),
    )?;
    for fail_at in 1..=6 {
        let events = trace();
        let owners = Rc::new(RefCell::new(Vec::with_capacity(6)));
        let owner_events = owners.clone();
        let mut allocation = wrapper::Allocation::traced(Some(fail_at), events.clone());
        allocation.owner_observer =
            Some(Box::new(move |event| owner_events.borrow_mut().push(event)));
        let error = Owner::construct_with_wrapper_allocation(
            base(),
            Some(selected()),
            binding(mg::Role::Client),
            scope(3, 0x31),
            scope(1, 0x71),
            Duration::ZERO,
            Duration::from_secs(5),
            storage(&plan, plan.capacity_bytes())?,
            &mut allocation,
        )
        .err()
        .ok_or("failed wrapper construction published an Owner")?;
        assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
        assert_eq!(wrapper_error(&error), Some(&wrapper::Error::Allocation));
        assert_eq!(allocation.attempts(), fail_at);
        let events = events.borrow();
        assert!(!events.overflow);
        let reserved: Vec<_> = events
            .events()
            .filter(|event| event.kind == Kind::Reserved)
            .collect();
        assert_eq!(reserved.len(), fail_at - 1);
        assert_eq!(
            reserved.iter().map(|event| event.slot).collect::<Vec<_>>(),
            slots[..fail_at - 1]
        );
        for actual in reserved {
            assert!(actual.capacity != 0 && actual.element_bytes != 0);
            let drops: Vec<_> = events
                .events()
                .filter(|event| event.slot == actual.slot && event.kind != Kind::Reserved)
                .collect();
            assert_eq!(drops.len(), 2);
            assert_eq!(
                drops[0],
                wrapper::Event {
                    kind: Kind::BeforeDrop,
                    ..actual
                }
            );
            assert_eq!(
                drops[1],
                wrapper::Event {
                    kind: Kind::AfterDrop,
                    ..actual
                }
            );
        }
        assert!(!events.events().any(|event| event.kind == Kind::Published));
        let owners = owners.borrow();
        assert_eq!(owners.len(), 6);
        for ((stream, plan), events) in streams::Stream::ALL
            .into_iter()
            .zip(plans)
            .zip(owners.chunks_exact(2))
        {
            let StreamConstructionDrop::Before(actual_stream, Some(actual)) = events[0] else {
                return Err("missing actual earlier complete owner before drop".into());
            };
            assert_eq!(actual_stream, stream);
            assert_eq!(actual.capacity_bytes, plan.arq_plan().capacity_bytes());
            assert_eq!(actual.limit_bytes, actual.capacity_bytes);
            assert_eq!(actual.allocations, 10);
            assert_eq!(events[1], StreamConstructionDrop::After(stream));
        }
    }
    Ok(())
}

#[test]
fn successful_publication_transfers_actual_pointers_without_retaining_construction_observers()
-> Result {
    let plan = wrapper::Plan::new(selected(), base())?;
    let events = trace();
    let owners = Rc::new(RefCell::new(Vec::with_capacity(6)));
    let owner_events = owners.clone();
    let mut allocation = wrapper::Allocation::traced(None, events.clone());
    allocation.owner_observer = Some(Box::new(move |event| owner_events.borrow_mut().push(event)));
    let owner = Owner::construct_with_wrapper_allocation(
        base(),
        Some(selected()),
        binding(mg::Role::Client),
        scope(3, 0x31),
        scope(1, 0x71),
        Duration::ZERO,
        Duration::from_secs(5),
        storage(&plan, plan.capacity_bytes())?,
        &mut allocation,
    )?;
    let actual = inventory(&owner)?;
    assert_eq!(allocation.attempts(), 6);
    assert!(owners.borrow().is_empty());
    {
        let events = events.borrow();
        assert!(!events.overflow);
        assert_eq!(events.events().count(), 12);
        let reserved: Vec<_> = events
            .events()
            .filter(|event| event.kind == Kind::Reserved)
            .collect();
        let published: Vec<_> = events
            .events()
            .filter(|event| event.kind == Kind::Published)
            .collect();
        for (index, (original, transferred)) in reserved.into_iter().zip(published).enumerate() {
            assert_eq!(
                transferred,
                wrapper::Event {
                    kind: Kind::Published,
                    ..original
                }
            );
            assert_eq!((transferred.pointer, transferred.capacity), actual[index]);
        }
    }
    drop(owner);
    assert_eq!(events.borrow().events().count(), 12);
    assert!(owners.borrow().is_empty());
    Ok(())
}

#[test]
fn reserved_wrapper_reuses_all_actual_backing_and_preserves_legacy_wire_under_loss() -> Result {
    let expires = Duration::from_secs(120);
    let roles = [mg::Role::Client, mg::Role::Server];
    let mut legacy = roles
        .map(|role| {
            Owner::new_leased(
                base(),
                selected(),
                binding(role),
                scope(3, 0x31),
                scope(1, 0x71),
                Duration::ZERO,
                expires,
            )
        })
        .into_iter()
        .collect::<io::Result<Vec<_>>>()?;
    let mut reserved = roles
        .map(|role| reserved(role, selected(), 0, expires))
        .into_iter()
        .collect::<Result<Vec<_>>>()?;
    let initial = [inventory(&reserved[0])?, inventory(&reserved[1])?];
    let usage = [
        reserved[0].wrapper_storage_usage()?,
        reserved[1].wrapper_storage_usage()?,
    ];
    let messages = [
        reserved[0].message_storage_usage(),
        reserved[1].message_storage_usage(),
    ];
    let mut packets = [[0; 512]; 2];
    let mut envelopes = [[0; 2048]; 2];
    for round in 0..80u64 {
        let start = Duration::from_millis(round * 500);
        let deadline = start + Duration::from_millis(400);
        let a = legacy[0]
            .submit(
                scope(3, 0x31),
                sc::Body::Ping { nonce: round },
                start,
                deadline,
                false,
            )?
            .ok_or("legacy Ping admission failed")?;
        let b = reserved[0]
            .submit(
                scope(3, 0x31),
                sc::Body::Ping { nonce: round },
                start,
                deadline,
                false,
            )?
            .ok_or("reserved Ping admission failed")?;
        assert_eq!(a, b);
        let mut accepted = false;
        let mut confirmed = false;
        let mut dropped = round % 17 != 0;
        let mut complete = false;
        for tick in 0..400 {
            let now = start + Duration::from_millis(tick);
            for (side, sender) in roles.into_iter().enumerate() {
                for _ in 0..2 {
                    let a = legacy[side].poll(now, usize::MAX, &mut packets[0])?;
                    let b = reserved[side].poll(now, usize::MAX, &mut packets[1])?;
                    assert_eq!(a, b);
                    assert_eq!(legacy[side].deadline(), reserved[side].deadline());
                    assert_eq!(legacy[side].retained(), reserved[side].retained());
                    let Some(emission) = a else {
                        break;
                    };
                    assert_eq!(packets[0][..emission.bytes], packets[1][..emission.bytes]);
                    if side == 0 && !dropped {
                        dropped = true;
                        continue;
                    }
                    let verified = mg::Ingress::AuthenticatedManagement {
                        session: binding(sender).session,
                        lane: binding(sender).lane,
                        sender,
                    };
                    legacy[1 - side].receive(verified, &packets[0][..emission.bytes], now)?;
                    reserved[1 - side].receive(verified, &packets[1][..emission.bytes], now)?;
                }
            }
            if !accepted {
                let a = legacy[1].next(now, &mut envelopes[0])?;
                let b = reserved[1].next(now, &mut envelopes[1])?;
                assert_eq!(a, b);
                if let Some(incoming) = a {
                    assert_eq!(
                        envelopes[0][..incoming.bytes],
                        envelopes[1][..incoming.bytes]
                    );
                    let decoded = sc::Envelope::decode(
                        &envelopes[1][..incoming.bytes],
                        envelope_limits(2048)?,
                    )?;
                    assert!(matches!(decoded.body, sc::Body::Ping { nonce } if nonce == round));
                    legacy[1].accepted(incoming, now)?;
                    reserved[1].accepted(incoming, now)?;
                    accepted = true;
                }
            }
            if !confirmed {
                let a_confirmed = legacy[0].confirmed(a, now)?;
                let b_confirmed = reserved[0].confirmed(b, now)?;
                assert_eq!(a_confirmed, b_confirmed);
                if a_confirmed {
                    legacy[0].retire(a, now)?;
                    reserved[0].retire(b, now)?;
                    confirmed = true;
                }
            }
            if accepted && confirmed && legacy.iter().chain(&reserved).all(Owner::drained) {
                complete = true;
                break;
            }
        }
        assert!(
            complete,
            "real liveness round {round} did not drain by its original cap"
        );
        for side in 0..2 {
            assert_eq!(inventory(&reserved[side])?, initial[side]);
            assert_eq!(reserved[side].wrapper_storage_usage()?, usage[side]);
            assert_eq!(reserved[side].message_storage_usage(), messages[side]);
        }
    }
    Ok(())
}
