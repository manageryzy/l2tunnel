//! Actual fixed-pool ownership and legacy DRR differentials, without global hooks.
use super::*;
use std::{cell::RefCell, rc::Rc};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn config() -> SchedulerConfig {
    SchedulerConfig {
        base_quantum_bytes: 17,
        max_classes: 4,
        max_flows: 4,
        max_packet_bytes: 512,
        max_queued_bytes: 4096,
        max_queued_packets: 8,
        per_flow_bytes: 2048,
        per_flow_packets: 4,
    }
}
fn classes() -> [ClassConfig; 2] {
    [
        ClassConfig {
            id: ClassId::new(u16::MAX),
            weight: 3,
        },
        ClassConfig {
            id: ClassId::new(0),
            weight: 1,
        },
    ]
}
fn flow(id: u64, weight: u32) -> FlowConfig {
    FlowConfig {
        id: FlowId::new(id),
        class: ClassId::new(if id.is_multiple_of(2) { 0 } else { u16::MAX }),
        weight,
    }
}
fn reserved(config: SchedulerConfig) -> TestResult<Scheduler> {
    let plan = storage::Plan::for_scheduler(config, &classes())?;
    Ok(Scheduler::new_reserved(
        config,
        &classes(),
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?)
}
fn enqueue(scheduler: &mut Scheduler, id: u64, bytes: &[u8]) -> TestResult {
    scheduler
        .enqueue_borrowed(FlowId::new(id), bytes)
        .map_err(|e| format!("borrowed admission: {e:?}"))?;
    Ok(())
}
fn inventory(scheduler: &Scheduler) -> TestResult<Vec<(usize, usize)>> {
    let r = scheduler
        .reserved
        .as_ref()
        .ok_or("reserved backing missing")?;
    Ok(vec![
        (
            r.classes.as_ptr() as usize,
            r.classes.capacity() * std::mem::size_of::<ClassConfig>(),
        ),
        (
            r.slots.as_ptr() as usize,
            r.slots.capacity() * std::mem::size_of::<Option<Registered>>(),
        ),
        (
            r.index.as_ptr() as usize,
            r.index.capacity() * std::mem::size_of::<Index>(),
        ),
        (
            r.free_flows.as_ptr() as usize,
            r.free_flows.capacity() * std::mem::size_of::<usize>(),
        ),
        (
            r.ring.as_ptr() as usize,
            r.ring.capacity() * std::mem::size_of::<FlowId>(),
        ),
        (
            r.packets.as_ptr() as usize,
            r.packets.capacity() * std::mem::size_of::<Packet>(),
        ),
        (
            r.free_packets.as_ptr() as usize,
            r.free_packets.capacity() * std::mem::size_of::<usize>(),
        ),
        (r.slab.as_ptr() as usize, r.slab.capacity()),
    ])
}
fn state(scheduler: &Scheduler) -> Vec<(FlowId, u64, usize)> {
    (0..scheduler.active_flows())
        .filter_map(|i| {
            scheduler.active_id(i).and_then(|id| {
                scheduler
                    .flow(id)
                    .map(|f| (id, f.deficit, f.packet_count()))
            })
        })
        .collect()
}

#[test]
fn complete_plan_refuses_before_reservation_and_drops_each_actual_partial_owner() -> TestResult {
    let config = config();
    let plan = storage::Plan::for_scheduler(config, &classes())?;
    assert_eq!(plan.config(), config);
    assert_eq!(plan.class_count(), 2);
    assert!(
        matches!(Scheduler::new_reserved(config, &classes(), storage::Limits {capacity_bytes: plan.capacity_bytes() - 1}),
        Err(storage::Error::Limit {required, limit}) if required == plan.capacity_bytes() && limit + 1 == required)
    );
    let mut bad = config;
    bad.max_flows = 0;
    assert!(matches!(
        Scheduler::new_reserved(bad, &[], storage::Limits { capacity_bytes: 0 }),
        Err(storage::Error::Configuration(ConfigError::ZeroLimit))
    ));
    let scheduler = reserved(config)?;
    let usage = scheduler.storage_usage().ok_or("usage")?;
    assert_eq!(usage.capacity_bytes, plan.capacity_bytes());
    assert_eq!(usage.limit_bytes, plan.capacity_bytes());
    assert_eq!(
        inventory(&scheduler)?.iter().map(|(_, n)| n).sum::<usize>(),
        usage.capacity_bytes
    );
    assert_eq!(usage.allocations, 8);
    assert!(
        scheduler.classes.is_empty() && scheduler.flows.is_empty() && scheduler.active.is_empty()
    );
    assert_eq!(Scheduler::new(config, &classes())?.storage_usage(), None);
    for fail_at in 1..=usage.allocations {
        let trace = Rc::new(RefCell::new(Vec::new()));
        let mut allocation = storage::Allocation::new(
            plan,
            storage::Limits {
                capacity_bytes: plan.capacity_bytes(),
            },
        )?;
        allocation.fail_at = Some(fail_at);
        allocation.trace = Some(trace.clone());
        assert!(matches!(
            Reserved::new(plan, &classes(), &mut allocation),
            Err(storage::Error::Allocation)
        ));
        let events = trace.borrow();
        if fail_at == 1 {
            assert!(events.is_empty());
        } else {
            assert!(
                matches!(events.as_slice(), [Event::BeforeDrop {bytes}, Event::AfterDrop] if *bytes > 0 && *bytes < plan.capacity_bytes())
            );
        }
    }
    let trace = Rc::new(RefCell::new(Vec::new()));
    let mut allocation = storage::Allocation::new(
        plan,
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?;
    allocation.trace = Some(trace.clone());
    let owner = Reserved::new(plan, &classes(), &mut allocation)?;
    assert_eq!(
        trace.borrow().as_slice(),
        [Event::Transferred {
            bytes: plan.capacity_bytes()
        }]
    );
    drop(owner);
    assert_eq!(trace.borrow().len(), 1);
    Ok(())
}

#[test]
fn full_packet_flow_and_ring_windows_reuse_every_provisioned_buffer() -> TestResult {
    let mut scheduler = reserved(config())?;
    let original = inventory(&scheduler)?;
    let usage = scheduler.storage_usage();
    for cycle in 0..130u64 {
        for id in [3, 1, 2, 0] {
            scheduler.register_flow(flow(id, (id + 1) as u32))?;
        }
        assert_eq!(
            scheduler.register_flow(flow(0, 0)),
            Err(FlowError::Duplicate)
        );
        assert_eq!(
            scheduler.register_flow(flow(9, 0)),
            Err(FlowError::Capacity)
        );
        for sequence in 0..2u8 {
            for id in 0..4u64 {
                let bytes = vec![id as u8 + sequence * 4 + cycle as u8; 512];
                if sequence == 0 {
                    enqueue(&mut scheduler, id, &bytes)?;
                } else {
                    scheduler.enqueue(FlowId::new(id), bytes)?;
                }
            }
        }
        assert_eq!(
            (
                scheduler.registered_flows(),
                scheduler.active_flows(),
                scheduler.queued_packets(),
                scheduler.queued_bytes()
            ),
            (4, 4, 8, 4096)
        );
        scheduler
            .peek_eligible(|_, _| true)?
            .ok_or("full-window selected head")?;
        for _ in 0..2 {
            let mut callbacks = 0;
            assert_eq!(
                scheduler.peek_eligible(|_, _| {
                    callbacks += 1;
                    false
                })?,
                None
            );
            assert_eq!(callbacks, 4);
            assert_eq!(scheduler.selected, None);
            assert!(
                state(&scheduler)
                    .iter()
                    .all(|(_, deficit, _)| *deficit == 0)
            );
            assert_eq!(
                scheduler.offer_selected_borrowed(|_, _| -> Result<Option<()>, &str> {
                    Err("blocked callback")
                }),
                Ok(None)
            );
            assert_eq!(
                (scheduler.queued_packets(), scheduler.queued_bytes()),
                (8, 4096)
            );
        }
        let mut delivered = [0u8; 4];
        while let Some(head) = scheduler.peek_eligible(|_, _| true)? {
            let expected =
                head.flow.value() as u8 + delivered[head.flow.value() as usize] * 4 + cycle as u8;
            let before = state(&scheduler);
            let selected = scheduler.selected;
            for _ in 0..2 {
                assert_eq!(
                    scheduler.offer_selected_borrowed(|actual, bytes| {
                        assert_eq!(actual, head);
                        assert_eq!(bytes, &[expected; 512]);
                        Ok::<Option<()>, &str>(None)
                    }),
                    Ok(None)
                );
                assert_eq!(
                    scheduler.offer_selected_borrowed(|_, _| Err::<Option<()>, _>("full")),
                    Err(OfferError::Downstream("full"))
                );
                assert_eq!(scheduler.selected, selected);
                assert_eq!(state(&scheduler), before);
            }
            let actual = scheduler
                .offer_selected_borrowed(|actual, bytes| {
                    assert_eq!(actual, head);
                    assert_eq!(bytes, &[expected; 512]);
                    Ok::<_, &str>(Some(()))
                })
                .map_err(|_| "service")?
                .ok_or("selected service missing")?;
            assert_eq!(actual, (head, ()));
            delivered[head.flow.value() as usize] += 1;
        }
        assert_eq!(delivered, [2; 4]);
        assert_eq!(
            (
                scheduler.queued_packets(),
                scheduler.queued_bytes(),
                scheduler.active_flows()
            ),
            (0, 0, 0)
        );
        for id in [1, 3, 0, 2] {
            scheduler.remove_flow(FlowId::new(id))?;
        }
        assert_eq!(scheduler.registered_flows(), 0);
        assert_eq!(scheduler.storage_usage(), usage);
        assert_eq!(inventory(&scheduler)?, original);
    }
    Ok(())
}

#[test]
fn reserved_and_allocating_traces_match_with_blocked_heads_weights_and_skipped_rounds() -> TestResult
{
    for count in [1usize, 2, 4, 16, 64] {
        let c = SchedulerConfig {
            base_quantum_bytes: 1,
            max_flows: count + 3,
            max_queued_packets: count * 8,
            max_queued_bytes: count * 8 * 256,
            max_packet_bytes: 256,
            per_flow_bytes: 8 * 256,
            per_flow_packets: 8,
            ..config()
        };
        let mut fixed = reserved(c)?;
        let mut legacy = Scheduler::new(c, &classes())?;
        for scheduler in [&mut fixed, &mut legacy] {
            for id in 0..(count + 3) as u64 {
                scheduler.register_flow(flow(id, id as u32 % 7 + 1))?;
            }
            for sequence in 0..8u8 {
                for id in 0..count as u64 {
                    let length = (id as usize * 13 + usize::from(sequence) * 97) % 256 + 1;
                    enqueue(scheduler, id, &vec![sequence; length])?;
                }
            }
        }
        let pointers = inventory(&fixed)?;
        for step in 0..count * 8 {
            let blocked = step % 3 == 0 && legacy.active_flows() > 1;
            let expected = legacy
                .dequeue_eligible(|id, _| !blocked || id.value() != 0)?
                .ok_or("legacy head")?;
            let active = fixed.active_flows();
            let mut calls = 0;
            let head = fixed
                .peek_eligible(|id, _| {
                    calls += 1;
                    !blocked || id.value() != 0
                })?
                .ok_or("reserved head")?;
            assert_eq!(calls, active);
            assert_eq!(
                (head.flow, head.class, head.packet_bytes),
                (expected.flow, expected.class, expected.payload.len())
            );
            assert_eq!(
                fixed.offer_selected_borrowed(|_, _| Ok::<Option<()>, &str>(None)),
                Ok(None)
            );
            fixed
                .offer_selected_borrowed(|actual, bytes| {
                    assert_eq!(actual, head);
                    assert_eq!(bytes, expected.payload);
                    Ok::<_, &str>(Some(()))
                })
                .map_err(|_| "service")?
                .ok_or("service")?;
            assert_eq!(state(&fixed), state(&legacy));
            assert_eq!(fixed.in_visit, legacy.in_visit);
            assert_eq!(
                (fixed.queued_bytes(), fixed.queued_packets()),
                (legacy.queued_bytes(), legacy.queued_packets())
            );
        }
        assert_eq!(fixed.peek_eligible(|_, _| true)?, None);
        assert_eq!(legacy.dequeue()?, None);
        assert_eq!(inventory(&fixed)?, pointers);
    }
    Ok(())
}

#[test]
fn all_admission_limits_preserve_original_bytes_selection_and_error_precedence() -> TestResult {
    let c = SchedulerConfig {
        max_packet_bytes: 16,
        max_queued_bytes: 32,
        max_queued_packets: 4,
        per_flow_bytes: 24,
        per_flow_packets: 3,
        ..config()
    };
    let mut scheduler = reserved(c)?;
    for id in 0..2 {
        scheduler.register_flow(flow(id, 1))?;
    }
    for (id, bytes, expected) in [
        (9, vec![], AdmissionErrorKind::UnknownFlow),
        (0, vec![], AdmissionErrorKind::EmptyPacket),
        (0, vec![0; 17], AdmissionErrorKind::PacketTooLarge),
    ] {
        assert_eq!(
            scheduler.enqueue_borrowed(FlowId::new(id), &bytes),
            Err(expected)
        );
    }
    enqueue(&mut scheduler, 0, &[7; 16])?;
    scheduler.peek_eligible(|_, _| true)?;
    let selected = scheduler.selected;
    let before = state(&scheduler);
    let pointers = inventory(&scheduler)?;
    for (id, bytes, expected) in [
        (0, vec![1; 9], AdmissionErrorKind::FlowBytes),
        (1, vec![2; 16], AdmissionErrorKind::GlobalBytes),
    ] {
        if id == 1 {
            enqueue(&mut scheduler, 1, &[3])?;
            scheduler.peek_eligible(|_, _| true)?;
        }
        let current = scheduler.selected;
        let counters = (scheduler.queued_bytes(), scheduler.queued_packets());
        assert_eq!(
            scheduler.enqueue_borrowed(FlowId::new(id), &bytes),
            Err(expected)
        );
        let pointer = bytes.as_ptr();
        let error = scheduler
            .enqueue(FlowId::new(id), bytes)
            .err()
            .ok_or("owned refusal")?;
        assert_eq!(error.kind, expected);
        assert_eq!(error.payload.as_ptr(), pointer);
        assert_eq!(scheduler.selected, current);
        assert_eq!(
            (scheduler.queued_bytes(), scheduler.queued_packets()),
            counters
        );
    }
    assert!(selected.is_some());
    assert!(!before.is_empty());
    assert_eq!(inventory(&scheduler)?, pointers);
    let c = SchedulerConfig {
        max_queued_bytes: 1024,
        per_flow_bytes: 512,
        per_flow_packets: 1,
        max_queued_packets: 2,
        ..c
    };
    let mut scheduler = reserved(c)?;
    for id in 0..2 {
        scheduler.register_flow(flow(id, 1))?;
    }
    enqueue(&mut scheduler, 0, &[1])?;
    assert_eq!(
        scheduler.enqueue_borrowed(FlowId::new(0), &[2]),
        Err(AdmissionErrorKind::FlowPackets)
    );
    enqueue(&mut scheduler, 1, &[1])?;
    assert_eq!(
        scheduler.enqueue_borrowed(FlowId::new(0), &[2]),
        Err(AdmissionErrorKind::GlobalPackets)
    );
    Ok(())
}

#[test]
fn owned_and_borrowed_service_share_preflight_without_losing_legacy_allocation() -> TestResult {
    for is_reserved in [false, true] {
        let mut scheduler = if is_reserved {
            reserved(config())?
        } else {
            Scheduler::new(config(), &classes())?
        };
        scheduler.register_flow(flow(0, 1))?;
        let bytes = vec![7; 100];
        let pointer = bytes.as_ptr();
        scheduler.enqueue(FlowId::new(0), bytes)?;
        let head = scheduler.peek_eligible(|_, _| true)?.ok_or("head")?;
        let (packet, token) = scheduler
            .offer_selected(|actual, bytes| {
                assert_eq!(actual, head);
                assert_eq!(bytes, &[7; 100]);
                Ok::<_, &str>(Some(9))
            })
            .map_err(|_| "owned service")?
            .ok_or("owned packet")?;
        if !is_reserved {
            assert_eq!(packet.payload.as_ptr(), pointer);
        }
        assert_eq!(
            (packet.flow, packet.class, packet.payload, token),
            (head.flow, head.class, vec![7; 100], 9)
        );
        enqueue(&mut scheduler, 0, &[8; 100])?;
        scheduler.peek_eligible(|_, _| true)?;
        scheduler
            .offer_selected_borrowed(|_, bytes| {
                assert_eq!(bytes, &[8; 100]);
                Ok::<_, &str>(Some(()))
            })
            .map_err(|_| "borrowed service")?
            .ok_or("borrowed packet")?;
        assert_eq!(
            (scheduler.queued_packets(), scheduler.queued_bytes()),
            (0, 0)
        );
    }
    Ok(())
}

#[test]
fn corrupt_fixed_link_and_accounting_refuse_before_downstream_and_preserve_custody() -> TestResult {
    let mut scheduler = reserved(config())?;
    scheduler.register_flow(flow(0, 1))?;
    enqueue(&mut scheduler, 0, &[7; 100])?;
    let head = scheduler.peek_eligible(|_, _| true)?.ok_or("head")?;
    let pointers = inventory(&scheduler)?;
    let before = state(&scheduler);
    let slot = scheduler
        .reserved
        .as_ref()
        .ok_or("backing")?
        .flow(head.flow)
        .ok_or("flow")?
        .fixed
        .ok_or("fifo")?
        .head
        .ok_or("slot")?;
    scheduler.reserved.as_mut().ok_or("backing")?.packets[slot].next = Some(usize::MAX);
    assert_eq!(
        scheduler.offer_selected_borrowed(|_, _| -> Result<Option<()>, &str> {
            Err("callback entered")
        }),
        Err(OfferError::Schedule(ScheduleError::Invariant))
    );
    scheduler.reserved.as_mut().ok_or("backing")?.packets[slot].next = None;
    scheduler.queued_bytes = 0;
    assert_eq!(
        scheduler.offer_selected_borrowed(|_, _| -> Result<Option<()>, &str> {
            Err("callback entered")
        }),
        Err(OfferError::Schedule(ScheduleError::Arithmetic))
    );
    scheduler.queued_bytes = 100;
    assert_eq!(scheduler.selected, Some(head));
    assert_eq!(state(&scheduler), before);
    assert_eq!(inventory(&scheduler)?, pointers);
    scheduler
        .offer_selected_borrowed(|_, bytes| {
            assert_eq!(bytes, &[7; 100]);
            Ok::<_, &str>(Some(()))
        })
        .map_err(|_| "service")?
        .ok_or("service")?;
    assert_eq!(scheduler.queued_packets(), 0);
    Ok(())
}

#[test]
fn original_large_dimensions_remain_explicit_and_layout_refusal_does_not_prune_them() -> TestResult
{
    let c = SchedulerConfig {
        max_flows: 10_000,
        max_queued_packets: 65_536,
        max_packet_bytes: 16,
        max_queued_bytes: 1_048_576,
        per_flow_bytes: 4096,
        per_flow_packets: 256,
        ..config()
    };
    c.validate(&classes())?;
    let plan = storage::Plan::for_scheduler(c, &classes())?;
    assert_eq!(plan.config(), c);
    assert!(
        matches!(Scheduler::new_reserved(c, &classes(), storage::Limits {capacity_bytes: 0}), Err(storage::Error::Limit {required, limit: 0}) if required == plan.capacity_bytes())
    );
    let bad = SchedulerConfig {
        max_flows: usize::MAX,
        ..c
    };
    bad.validate(&classes())?;
    assert!(matches!(
        storage::Plan::for_scheduler(bad, &classes()),
        Err(storage::Error::Layout)
    ));
    Ok(())
}
