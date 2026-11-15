use super::*;
use crate::backing::{IdEntry, MetadataSlot, StateEntry};
use crate::storage::{Error, Limits, Plan};
use std::alloc::Layout;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn tun() -> Profile {
    Profile::TunDrr(TunQosConfig {
        base_quantum_bytes: 64,
        max_weight: 4,
        per_flow: QueueLimits {
            bytes: 2048,
            packets: 8,
        },
    })
}

fn config(profile: Profile) -> PipelineConfig {
    PipelineConfig {
        profile,
        flows: FlowTableConfig {
            capacity: 8,
            channels: 3,
            mapping: Mapping::ConnectionRoundRobin,
            idle_timeout: Duration::from_secs(5),
        },
        parse: ParseLimits {
            max_packet_bytes: 256,
            ..ParseLimits::default()
        },
        queue: QueueLimits {
            bytes: 2048,
            packets: 8,
        },
    }
}

fn reserved(config: PipelineConfig) -> Result<Pipeline, Error> {
    let plan = Plan::for_pipeline(config)?;
    Pipeline::new_reserved(
        config,
        Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )
}

fn packet(profile: Profile, port: u16, length: usize, seed: u8) -> Vec<u8> {
    let mut bytes = vec![seed; length];
    bytes[..40].fill(0);
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&(length as u16).to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 6;
    bytes[12..16].copy_from_slice(&[10, 0, 0, 1]);
    bytes[16..20].copy_from_slice(&[10, 0, 0, 2]);
    bytes[20..22].copy_from_slice(&port.to_be_bytes());
    bytes[22..24].copy_from_slice(&443u16.to_be_bytes());
    bytes[32] = 0x50;
    bytes[33] = 0x10;
    if matches!(profile, Profile::TapSystem) {
        let mut frame = vec![1; 6];
        frame.extend_from_slice(&[2; 6]);
        frame.extend_from_slice(&[0x08, 0x00]);
        frame.extend(bytes);
        frame
    } else {
        bytes
    }
}

fn take(pipeline: &mut Pipeline) -> Result<Option<(PacketMetadata, Vec<u8>)>, PipelineError> {
    let mut observed = None;
    let result = pipeline.offer_front_borrowed(|metadata, bytes| {
        observed = Some((metadata, bytes.to_vec()));
        Ok::<_, Infallible>(Some(bytes.len()))
    });
    match result {
        Ok(Some(admission)) => {
            let (metadata, bytes) = observed.ok_or(PipelineError::Invariant)?;
            assert_eq!(admission.metadata, metadata);
            assert_eq!(admission.permit, bytes.len());
            Ok(Some((metadata, bytes)))
        }
        Ok(None) => {
            assert!(observed.is_none());
            Ok(None)
        }
        Err(DequeueError::Pipeline(error)) => Err(error),
        Err(DequeueError::Commit(never)) => match never {},
    }
}

fn inventory(pipeline: &Pipeline) -> TestResult {
    let MetadataPool::Reserved {
        slots,
        free,
        available,
    } = &pipeline.metadata_pool
    else {
        return Err("expected actual reserved metadata pool".into());
    };
    let mut seen = vec![false; slots.len()];
    let mut occupied = 0;
    for queue in pipeline
        .states
        .iter()
        .map(|(_, state)| &state.metadata)
        .chain(pipeline.channel_metadata.iter())
    {
        let MetadataQueue::Reserved { head, tail, len } = queue else {
            return Err("legacy queue inside reserved Pipeline".into());
        };
        let mut cursor = *head;
        let mut count = 0;
        let mut last = None;
        while let Some(index) = cursor {
            let slot = slots.get(index).ok_or("metadata index")?;
            let marker = seen.get_mut(index).ok_or("metadata marker")?;
            assert!(!*marker);
            *marker = true;
            assert!(slot.value.is_some());
            last = Some(index);
            cursor = slot.next;
            count += 1;
            assert!(count <= slots.len());
        }
        assert_eq!(count, *len);
        assert_eq!(last, *tail);
        occupied += count;
    }
    assert_eq!(occupied, pipeline.usage.packets);
    let mut cursor = *free;
    let mut free_count = 0;
    while let Some(index) = cursor {
        let slot = slots.get(index).ok_or("free index")?;
        let marker = seen.get_mut(index).ok_or("free marker")?;
        assert!(!*marker);
        *marker = true;
        assert!(slot.value.is_none());
        cursor = slot.next;
        free_count += 1;
        assert!(free_count <= slots.len());
    }
    assert_eq!(free_count, *available);
    assert_eq!(free_count + occupied, slots.len());
    assert!(seen.into_iter().all(|value| value));
    Ok(())
}

fn wrapper_backing(pipeline: &Pipeline) -> Result<[(usize, usize); 4], &'static str> {
    let States::Reserved(states) = &pipeline.states else {
        return Err("states");
    };
    let ById::Reserved(ids) = &pipeline.by_id else {
        return Err("IDs");
    };
    let MetadataPool::Reserved { slots, .. } = &pipeline.metadata_pool else {
        return Err("pool");
    };
    Ok([
        (states.as_ptr() as usize, states.capacity()),
        (ids.as_ptr() as usize, ids.capacity()),
        (slots.as_ptr() as usize, slots.capacity()),
        (
            pipeline.channel_metadata.as_ptr() as usize,
            pipeline.channel_metadata.capacity(),
        ),
    ])
}

#[test]
fn complete_plan_matches_actual_nested_and_wrapper_capacities() -> TestResult {
    for profile in [Profile::TapSystem, tun()] {
        let cfg = config(profile);
        let plan = Plan::for_pipeline(cfg)?;
        assert_eq!(plan.config(), cfg);
        assert_eq!(Pipeline::new(cfg)?.storage_usage(), None);
        let pipeline = reserved(cfg)?;
        let usage = pipeline.storage_usage().ok_or("actual usage")?;
        assert_eq!(usage.limit_bytes, plan.capacity_bytes());
        assert_eq!(usage.capacity_bytes, plan.capacity_bytes());
        let wrapper = Layout::array::<StateEntry>(cfg.flows.capacity)?.size()
            + Layout::array::<IdEntry>(cfg.flows.capacity)?.size()
            + Layout::array::<MetadataSlot>(cfg.queue.packets)?.size()
            + Layout::array::<MetadataQueue>(usize::from(cfg.flows.channels))?.size();
        let flow = pipeline.flows.storage_usage().ok_or("flow usage")?;
        let mux = pipeline.mux.storage_usage().ok_or("MUX usage")?;
        let qos = pipeline.qos.as_ref().and_then(Scheduler::storage_usage);
        assert_eq!(
            usage.capacity_bytes,
            wrapper
                + flow.capacity_bytes
                + mux.capacity_bytes
                + qos.map_or(0, |value| value.capacity_bytes)
        );
        assert_eq!(
            usage.allocations,
            4 + flow.allocations + mux.allocations + qos.map_or(0, |value| value.allocations)
        );
        match profile {
            Profile::TapSystem => assert!(qos.is_none()),
            Profile::TunDrr(_) => {
                assert_eq!(mux.capacity_bytes, 0);
                assert_eq!(mux.allocations, 0);
                assert!(qos.is_some());
            }
        }
        inventory(&pipeline)?;
        let mut allocation = storage::Allocation::default();
        assert!(matches!(Pipeline::new_reserved_with(cfg,
            Limits { capacity_bytes: plan.capacity_bytes() - 1 }, &mut allocation),
            Err(Error::Limit { required, limit }) if required == plan.capacity_bytes() && limit + 1 == required));
    }
    let mut invalid = config(tun());
    invalid.queue.packets = 0;
    assert_eq!(
        Plan::for_pipeline(invalid),
        Err(Error::Pipeline(PipelineError::InvalidConfig))
    );
    let mut overflowing = config(Profile::TapSystem);
    overflowing.queue.packets = usize::MAX;
    assert_eq!(overflowing.validate(), Ok(()));
    assert_eq!(
        Plan::for_pipeline(overflowing),
        Err(Error::Mux(l2tunnel_mux::storage::Error::Layout))
    );
    Ok(())
}

#[test]
fn each_wrapper_reservation_failure_preserves_an_actual_live_owner() -> TestResult {
    for profile in [Profile::TapSystem, tun()] {
        let cfg = config(profile);
        let mut live = reserved(cfg)?;
        let original = packet(profile, 1001, 100, 0x73);
        let metadata = live.enqueue_borrowed(&original, Duration::ZERO)?;
        let usage = live.usage();
        let physical = live.storage_usage();
        let backing = wrapper_backing(&live)?;
        for fail_at in 1..=4 {
            let mut allocation = storage::Allocation::default();
            allocation.fail_at = Some(fail_at);
            assert!(matches!(
                Pipeline::new_reserved_with(
                    cfg,
                    Limits {
                        capacity_bytes: Plan::for_pipeline(cfg)?.capacity_bytes()
                    },
                    &mut allocation
                ),
                Err(Error::Allocation)
            ));
            assert_eq!(live.usage(), usage);
            assert_eq!(live.storage_usage(), physical);
            assert_eq!(wrapper_backing(&live)?, backing);
            assert_eq!(
                live.offer_front_borrowed(|actual, bytes| {
                    assert_eq!(actual, metadata);
                    assert_eq!(bytes, original);
                    Ok::<Option<()>, &str>(None)
                }),
                Ok(None)
            );
            inventory(&live)?;
        }
        assert_eq!(
            take(&mut live)?.ok_or("live original")?,
            (metadata, original)
        );
        drop(reserved(cfg)?);
    }
    Ok(())
}

#[test]
fn borrowed_refusal_retries_actual_bytes_and_reuses_shared_slots_like_legacy() -> TestResult {
    for profile in [Profile::TapSystem, tun()] {
        for mapping in [Mapping::ConnectionRoundRobin, Mapping::Crc32] {
            for channels in [1, 256] {
                let mut cfg = config(profile);
                cfg.flows.channels = channels;
                cfg.flows.mapping = mapping;
                let mut legacy = Pipeline::new(cfg)?;
                let mut fixed = reserved(cfg)?;
                let physical = fixed.storage_usage();
                let backing = wrapper_backing(&fixed)?;
                for round in 0..24 {
                    for (port, length, seed) in [
                        (1001, 100, 1),
                        (1002, 180, 2),
                        (1003, 40, 3),
                        (1001, 120, 4),
                    ] {
                        let bytes = packet(profile, port, length, seed + round);
                        let weight = if matches!(profile, Profile::TapSystem) {
                            1
                        } else {
                            u32::from(port % 3 + 1)
                        };
                        let now = Duration::from_millis(u64::from(round));
                        assert_eq!(
                            fixed.enqueue_borrowed_weighted(&bytes, weight, now)?,
                            legacy.enqueue_weighted(bytes, weight, now)?
                        );
                    }
                    let usage = fixed.usage();
                    let mut retained = None;
                    for _ in 0..3 {
                        assert_eq!(
                            fixed.offer_front_borrowed(|metadata, bytes| {
                                let observed = (metadata, bytes.as_ptr());
                                if let Some(previous) = retained {
                                    assert_eq!(observed, previous);
                                }
                                retained = Some(observed);
                                Ok::<Option<()>, &str>(None)
                            }),
                            Ok(None)
                        );
                        assert_eq!(
                            fixed.offer_front_borrowed(|metadata, bytes| {
                                assert_eq!(Some((metadata, bytes.as_ptr())), retained);
                                Err::<Option<()>, _>("codec full")
                            }),
                            Err(DequeueError::Commit("codec full"))
                        );
                        assert_eq!(fixed.usage(), usage);
                        inventory(&fixed)?;
                    }
                    while let Some(expected) = take(&mut legacy)? {
                        assert_eq!(take(&mut fixed)?, Some(expected));
                        inventory(&fixed)?;
                    }
                    assert_eq!(take(&mut fixed)?, None);
                    assert_eq!(fixed.usage(), QueueUsage::default());
                    assert_eq!(fixed.storage_usage(), physical);
                    assert_eq!(wrapper_backing(&fixed)?, backing);
                }
            }
        }
    }
    Ok(())
}

#[test]
fn policy_budget_parser_time_learning_and_flow_errors_match_existing_owner() -> TestResult {
    for profile in [Profile::TapSystem, tun()] {
        let mut cfg = config(profile);
        cfg.flows.capacity = 2;
        cfg.queue.packets = 2;
        if let Profile::TunDrr(ref mut policy) = cfg.profile {
            policy.per_flow.packets = 2;
        }
        let mut legacy = Pipeline::new(cfg)?;
        let mut fixed = reserved(cfg)?;
        let bytes = packet(profile, 1001, 100, 1);
        let key = fixed.classify(&bytes)?.key;
        assert_eq!(
            fixed.learn(key, 2, 1, Duration::from_secs(1)),
            legacy.learn(key, 2, 1, Duration::from_secs(1))
        );
        assert_eq!(
            fixed.learn(key, 1, 1, Duration::from_secs(1)),
            legacy.learn(key, 1, 1, Duration::from_secs(1))
        );
        for (input, weight, now) in [
            (vec![0; 4], 1, Duration::from_secs(1)),
            (bytes.clone(), 2, Duration::from_secs(1)),
            (bytes.clone(), 0, Duration::from_secs(1)),
            (bytes.clone(), 1, Duration::ZERO),
        ] {
            let expected = legacy
                .enqueue_weighted(input.clone(), weight, now)
                .map_err(|error| error.kind);
            assert!(expected.is_err());
            assert_eq!(
                fixed.enqueue_borrowed_weighted(&input, weight, now),
                expected
            );
            assert_eq!(fixed.usage(), legacy.usage());
            assert_eq!(fixed.flow(&key), legacy.flow(&key));
            inventory(&fixed)?;
        }
        for port in [1001, 1002] {
            let input = packet(profile, port, 100, 7);
            assert_eq!(
                fixed.enqueue_borrowed(&input, Duration::from_secs(2))?,
                legacy.enqueue(input, Duration::from_secs(2))?
            );
        }
        let input = packet(profile, 1003, 100, 9);
        assert_eq!(
            fixed.enqueue_borrowed(&input, Duration::from_secs(100)),
            legacy
                .enqueue(input.clone(), Duration::from_secs(100))
                .map_err(|error| error.kind)
        );
        assert_eq!(fixed.retire_drained(&key), legacy.retire_drained(&key));
        assert_eq!(
            fixed.idle_step(Duration::from_secs(1), None, 0, None),
            legacy.idle_step(Duration::from_secs(1), None, 0, None)
        );
        while let Some(expected) = take(&mut legacy)? {
            assert_eq!(take(&mut fixed)?, Some(expected));
        }
        let third = fixed.classify(&input)?.key;
        assert_eq!(
            fixed.learn(third, 0, 1, Duration::from_secs(2)),
            legacy.learn(third, 0, 1, Duration::from_secs(2))
        );
        assert_eq!(fixed.usage(), legacy.usage());
        inventory(&fixed)?;
    }
    Ok(())
}

#[test]
fn idle_cursor_retirement_churn_and_cross_backing_continuation_preserve_ids() -> TestResult {
    for profile in [Profile::TapSystem, tun()] {
        let cfg = config(profile);
        let mut legacy = Pipeline::new(cfg)?;
        let mut fixed = reserved(cfg)?;
        let backing = wrapper_backing(&fixed)?;
        for port in [1003, 1001, 1002] {
            let key = fixed.classify(&packet(profile, port, 40, 1))?.key;
            assert_eq!(
                fixed.learn(key, port % 3, 1, Duration::ZERO),
                legacy.learn(key, port % 3, 1, Duration::ZERO)
            );
        }
        let now = Duration::from_secs(5);
        assert_eq!(fixed.idle_candidate(now)?, legacy.idle_candidate(now)?);
        let first = fixed.idle_step(now, None, 1, None)?;
        assert_eq!(first, legacy.idle_step(now, None, 1, None)?);
        let (key, binding) = first.candidate.ok_or("first idle")?;
        assert_eq!(
            fixed.idle_step(now, None, 1, Some(key))?,
            legacy.idle_step(now, None, 1, Some(key))?
        );
        assert_eq!(fixed.retire_idle_drained(&key, now)?, binding);
        assert_eq!(legacy.retire_idle_drained(&key, now)?, binding);
        assert_eq!(
            fixed.idle_step(now, Some(key), 1, None)?,
            legacy.idle_step(now, Some(key), 1, None)?
        );
        let remaining: Vec<_> = fixed.states.iter().map(|(key, _)| *key).collect();
        for key in remaining {
            assert_eq!(fixed.retire_drained(&key)?, legacy.retire_drained(&key)?);
        }
        for round in 0..64u16 {
            let bytes = packet(profile, 2000 + round, 100, round as u8);
            let now = Duration::from_secs(6 + u64::from(round));
            let metadata = fixed.enqueue_borrowed(&bytes, now)?;
            assert_eq!(metadata, legacy.enqueue(bytes, now)?);
            assert_eq!(take(&mut fixed)?, take(&mut legacy)?);
            assert_eq!(
                fixed.retire_drained(&metadata.classification.key)?,
                legacy.retire_drained(&metadata.classification.key)?
            );
            inventory(&fixed)?;
            assert_eq!(wrapper_backing(&fixed)?, backing);
        }
        let mut next_fixed = reserved(cfg)?;
        let mut next_legacy = Pipeline::new(cfg)?;
        next_fixed.continue_ids_from(&legacy)?;
        next_legacy.continue_ids_from(&fixed)?;
        let bytes = packet(profile, 9000, 40, 0x7f);
        let next = next_fixed.enqueue_borrowed(&bytes, Duration::from_secs(100))?;
        assert_eq!(next, next_legacy.enqueue(bytes, Duration::from_secs(100))?);
        assert_eq!(next.binding.id.0, 68);
        inventory(&next_fixed)?;
    }
    Ok(())
}

#[test]
fn tun_credit_blocking_and_weighted_service_match_without_metadata_growth() -> TestResult {
    let mut cfg = config(tun());
    cfg.queue = QueueLimits {
        bytes: 32_768,
        packets: 128,
    };
    if let Profile::TunDrr(ref mut policy) = cfg.profile {
        policy.per_flow = cfg.queue;
    }
    let mut legacy = Pipeline::new(cfg)?;
    let mut fixed = reserved(cfg)?;
    let mut blocked = None;
    for _ in 0..40 {
        for (port, length, weight) in [(1001, 100, 1), (1002, 200, 3)] {
            let bytes = packet(cfg.profile, port, length, weight as u8);
            let metadata = fixed.enqueue_borrowed_weighted(&bytes, weight, Duration::ZERO)?;
            assert_eq!(
                metadata,
                legacy.enqueue_weighted(bytes, weight, Duration::ZERO)?
            );
            if port == 1001 {
                blocked = Some(metadata.classification.key);
            }
        }
    }
    for _ in 0..4 {
        for pipeline in [&mut legacy, &mut fixed] {
            let usage = pipeline.usage();
            assert_eq!(
                pipeline.offer_with_borrowed(
                    |_| false,
                    |_, _| -> Result<Option<()>, &str> { Err("blocked callback") }
                ),
                Ok(None)
            );
            assert_eq!(pipeline.usage(), usage);
        }
    }
    for _ in 0..3 {
        let mut observations = Vec::new();
        for pipeline in [&mut legacy, &mut fixed] {
            let mut bytes = None;
            let admission = pipeline
                .offer_with_borrowed(
                    |head| Some(head.key) != blocked,
                    |metadata, packet| {
                        bytes = Some(packet.to_vec());
                        Ok::<_, &str>(Some(metadata.binding.id))
                    },
                )
                .map_err(|_| "credit handoff")?
                .ok_or("eligible other flow")?;
            observations.push((admission, bytes.ok_or("actual selected bytes")?));
        }
        assert_eq!(observations[0], observations[1]);
        inventory(&fixed)?;
    }
    let mut served = [0usize; 2];
    for _ in 0..30 {
        let expected = take(&mut legacy)?.ok_or("legacy queued")?;
        let actual = take(&mut fixed)?.ok_or("reserved queued")?;
        assert_eq!(actual, expected);
        let index = usize::from(Some(actual.0.classification.key) != blocked);
        served[index] += actual.1.len();
    }
    assert!(served[1] > served[0] * 2);
    assert!(served[1] < served[0] * 4);
    while let Some(expected) = take(&mut legacy)? {
        assert_eq!(take(&mut fixed)?, Some(expected));
    }
    inventory(&fixed)?;
    Ok(())
}

#[test]
fn reserved_owned_compatibility_preserves_rejected_capacity_and_original_bytes() -> TestResult {
    for profile in [Profile::TapSystem, tun()] {
        let mut cfg = config(profile);
        cfg.queue.packets = 1;
        if let Profile::TunDrr(ref mut policy) = cfg.profile {
            policy.per_flow.packets = 1;
        }
        let mut pipeline = reserved(cfg)?;
        let bytes = packet(profile, 1001, 100, 0x95);
        let metadata = pipeline.enqueue(bytes.clone(), Duration::ZERO)?;
        let mut rejected = Vec::with_capacity(16_384);
        rejected.extend_from_slice(&packet(profile, 1002, 80, 0x81));
        let pointer = rejected.as_ptr();
        let capacity = rejected.capacity();
        let error = pipeline
            .enqueue(rejected, Duration::from_secs(100))
            .err()
            .ok_or("full queue")?;
        assert_eq!(error.kind, PipelineError::Budget(Budget::Packets));
        assert_eq!(error.payload.as_ptr(), pointer);
        assert_eq!(error.payload.capacity(), capacity);
        let delivered = pipeline.dequeue()?.ok_or("owned compatibility")?;
        assert_eq!(delivered.metadata, metadata);
        assert_eq!(delivered.payload, bytes);
        assert_eq!(delivered.payload.len(), delivered.payload.capacity());
        inventory(&pipeline)?;
    }
    Ok(())
}

#[test]
fn reserved_tap_arp_vlan_opaque_and_tun_ipv6_keep_literal_originals() -> TestResult {
    let mut arp = vec![0; 42];
    arp[..6].fill(0xff);
    arp[6..12].copy_from_slice(&[2, 3, 4, 5, 6, 7]);
    arp[12..22].copy_from_slice(&[8, 6, 0, 1, 8, 0, 6, 4, 0, 1]);
    arp[28..32].copy_from_slice(&[10, 0, 0, 1]);
    arp[38..42].copy_from_slice(&[10, 0, 0, 2]);
    let mut opaque = vec![0x5a; 74];
    opaque[12..14].copy_from_slice(&[0x88, 0xb5]);
    let ip = packet(tun(), 1001, 80, 0x4d);
    let mut vlan = vec![0x2a; 12];
    vlan.extend_from_slice(&[0x81, 0, 0, 7, 8, 0]);
    vlan.extend_from_slice(&ip);
    let mut ipv6 = vec![0; 48];
    ipv6[0] = 0x60;
    ipv6[4..8].copy_from_slice(&[0, 8, 17, 64]);
    ipv6[8..24].copy_from_slice(&[0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    ipv6[24..40].copy_from_slice(&[0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    ipv6[40..48].copy_from_slice(&[4, 210, 1, 187, 0, 8, 0xab, 0xcd]);
    for (profile, originals) in [
        (Profile::TapSystem, vec![arp, vlan, opaque]),
        (tun(), vec![ip, ipv6]),
    ] {
        let mut legacy = Pipeline::new(config(profile))?;
        let mut fixed = reserved(config(profile))?;
        for bytes in &originals {
            assert_eq!(
                fixed.enqueue_borrowed(bytes, Duration::ZERO)?,
                legacy.enqueue(bytes.clone(), Duration::ZERO)?
            );
        }
        while let Some(expected) = take(&mut legacy)? {
            assert!(originals.contains(&expected.1));
            assert_eq!(take(&mut fixed)?, Some(expected));
        }
        inventory(&fixed)?;
    }
    Ok(())
}
