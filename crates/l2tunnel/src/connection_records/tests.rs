//! Actual independent owners; this fixture assumes caller authentication, not I/O.
use super::*;
use crate::codec::{aligned_body, aligned_envelope, aligned_receiver, source_copy};
use l2tunnel_recovery::{
    CompactArqConfig, CompactBounds, CompactRecovery, CompactTiming, EndpointRole,
};
use l2tunnel_reliable::CompactReliableConfig;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}

fn config(owners: u16) -> TestResult<Config> {
    let symbol = 128;
    let source = aligned_envelope::HEADER_BYTES + symbol;
    let policy = aligned::CompactConfig {
        native_policy: aligned::NativePolicy::RawIp,
        receiver: aligned_receiver::Limits {
            body: aligned_body::Config {
                max_frame_bytes: 512,
                symbol_bytes: symbol,
                elide_payload_length: false,
                predictive: false,
                timestamp_pair_dictionary: false,
                independent_short_frame_bytes: 0,
            },
            channels: 1,
            first_record: aligned_receiver::RecordId(0),
            first_source: aligned_receiver::SourceId(0),
            record_window: 16,
            source_window: 16,
            lookahead_records: 8,
            lookahead_bytes: 4096,
            lookahead_fragments: 64,
            max_fragments_per_record: 8,
            lifetime_ticks: 5000,
        },
        recovery: CompactReliableConfig::new(
            CompactArqConfig::new(
                CompactBounds {
                    max_source_bytes: source,
                    send_bytes: source * 8,
                    receive_bytes: source * 8,
                    send_records: 8,
                    receive_records: 8,
                },
                CompactTiming {
                    nominal_rtt: ms(70),
                    feedback_interval: ms(5),
                    feedback_packets: 64,
                },
                128,
                64,
                8,
                CompactRecovery::Guarded,
            )?,
            route::HEADER_BYTES + 28,
        )?,
        max_recovery_packet_bytes: 512,
        copies: source_copy::Policy::ONE,
    };
    Ok(Config {
        owners,
        incarnation: 0x1020_3040_5060_7080,
        send: policy,
        receive: policy,
        send_carrier_overhead_bytes: 28,
        receive_carrier_overhead_bytes: 28,
        send_unreliable: None,
        receive_unreliable: None,
    })
}
fn context(role: EndpointRole) -> RecoveryContext {
    RecoveryContext {
        session: 0x1020,
        epoch: 7,
        role,
    }
}
fn construct(config: Config, role: EndpointRole) -> TestResult<Collection> {
    let plan = storage::Plan::for_collection(config)?;
    Ok(Collection::new_reserved(
        plan,
        context(role),
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?)
}
fn frame(marker: u8) -> Vec<u8> {
    let mut bytes = vec![marker; 100];
    bytes[0] = 0x45;
    bytes[1] = 0;
    bytes[2..4].copy_from_slice(&100u16.to_be_bytes());
    bytes[6..8].fill(0);
    bytes[8] = 64;
    bytes[9] = 17;
    bytes[10..12].fill(0);
    bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
    bytes[16..20].copy_from_slice(&[192, 0, 2, 2]);
    bytes
}

#[test]
fn route_is_strict_and_unreliable_native_is_explicitly_uninstalled() -> TestResult {
    let mut owner = construct(config(1)?, EndpointRole::Initiator)?;
    let id = owner.owner(0)?;
    let header = route::Header {
        owner: id,
        incarnation: config(1)?.incarnation,
        class: route::Class::UnreliableNative,
        unreliable_serial: u64::MAX,
    };
    let mut bytes = vec![0; route::HEADER_BYTES + 3];
    header.encode(&mut bytes[..route::HEADER_BYTES])?;
    bytes[route::HEADER_BYTES..].copy_from_slice(b"ack");
    assert_eq!(route::decode(&bytes)?, (header, &b"ack"[..]));
    let before = owner.storage_usage();
    assert_eq!(
        owner.accept_authenticated_at(ms(0), ms(0), &bytes),
        Err(Error::UnsupportedUnreliable)
    );
    assert!(owner.drained());
    assert_eq!(owner.storage_usage(), before);
    let mut wrong_cohort = bytes.clone();
    wrong_cohort[8..16].copy_from_slice(&(header.incarnation + 1).to_be_bytes());
    assert_eq!(
        owner.accept_authenticated_at(ms(0), ms(0), &wrong_cohort),
        Err(Error::Incarnation)
    );
    let mut absent_owner = bytes.clone();
    absent_owner[6..8].copy_from_slice(&1u16.to_be_bytes());
    assert_eq!(
        owner.accept_authenticated_at(ms(0), ms(0), &absent_owner),
        Err(Error::Owner)
    );
    for offset in [4, 5] {
        let mut bad = bytes.clone();
        bad[offset] = 0;
        assert_eq!(route::decode(&bad), Err(route::Error::Prefix));
    }
    let mut bad = bytes.clone();
    bad[6..8].copy_from_slice(&256u16.to_be_bytes());
    assert_eq!(route::decode(&bad), Err(route::Error::Owner));
    let mut bad = bytes.clone();
    bad[8..16].fill(0);
    assert_eq!(route::decode(&bad), Err(route::Error::Identity));
    let mut bad = bytes.clone();
    bad[16..24].fill(0);
    assert_eq!(route::decode(&bad), Err(route::Error::Identity));
    let mut bad = bytes.clone();
    bad[5] = 1;
    assert_eq!(route::decode(&bad), Err(route::Error::Identity));
    assert_eq!(
        route::decode(&bytes[..route::HEADER_BYTES]),
        Err(route::Error::Length)
    );
    let mut target = [0x55; route::HEADER_BYTES];
    assert_eq!(
        route::Header {
            incarnation: 0,
            ..header
        }
        .encode(&mut target),
        Err(route::Error::Identity)
    );
    assert!(target.iter().all(|b| *b == 0x55));
    Ok(())
}

#[test]
fn sixteen_actual_reserved_owners_require_the_complete_fixed_and_nested_allowance() -> TestResult {
    let plan = storage::Plan::for_collection(config(16)?)?;
    assert!(
        matches!(Collection::new_reserved(plan, context(EndpointRole::Initiator),
        storage::Limits { capacity_bytes: plan.capacity_bytes() - 1 }),
        Err(Error::Limit { required, limit }) if required == plan.capacity_bytes() && limit + 1 == required)
    );
    let collection = construct(plan.config(), EndpointRole::Initiator)?;
    assert_eq!(collection.slots.len(), 16);
    let usage = collection.storage_usage();
    assert_eq!(usage.owners, 16);
    assert_eq!(usage.fixed_bytes + usage.heap_bytes, usage.capacity_bytes);
    assert_eq!(usage.heap_bytes, plan.heap_bytes());
    assert_eq!(usage.capacity_bytes, plan.capacity_bytes());
    let nested = collection.slots.iter().try_fold(0usize, |sum, slot| {
        let actual = slot
            .endpoint
            .storage_usage()
            .ok_or("actual reserved endpoint")?;
        Ok::<_, Box<dyn std::error::Error>>(sum + actual.capacity_bytes)
    })?;
    assert_eq!(
        usage.heap_bytes,
        collection.slots.capacity() * std::mem::size_of::<Slot>() + nested
    );
    assert!(usage.allocations > 16);
    assert_eq!(collection.owner(16), Err(Error::Owner));
    let mut invalid = plan.config();
    invalid.owners = 0;
    assert_eq!(
        storage::Plan::for_collection(invalid),
        Err(Error::Configuration)
    );
    let mut invalid = plan.config();
    invalid.send.receiver.channels = 2;
    assert_eq!(
        storage::Plan::for_collection(invalid),
        Err(Error::Configuration)
    );
    let mut invalid = plan.config();
    invalid.receive.recovery =
        CompactReliableConfig::new(invalid.receive.recovery.arq(), route::HEADER_BYTES - 1)?;
    assert_eq!(
        storage::Plan::for_collection(invalid),
        Err(Error::Configuration)
    );
    Ok(())
}

fn collect(
    collection: &mut Collection,
    id: OwnerId,
    now: Duration,
    output: &mut Vec<Vec<u8>>,
) -> TestResult {
    for _ in 0..8 {
        match collection.prepare_native(id, now, 1)? {
            NativePreparation::Idle => break,
            NativePreparation::Progress => {}
            NativePreparation::Ready(token) | NativePreparation::AlreadyPending(token) => {
                let pending = collection
                    .pending_native(id)?
                    .ok_or("actual pending native")?;
                assert_eq!(pending.identity, token.identity());
                output.push(pending.bytes.to_vec());
                collection.commit_native(now, token)?;
            }
        }
    }
    Ok(())
}

#[test]
fn independent_owner_progress_survives_other_source_loss_and_actual_physical_custody() -> TestResult
{
    let config = config(16)?;
    let plan = storage::Plan::for_collection(config)?;
    let mut a = construct(config, EndpointRole::Initiator)?;
    let mut b = construct(config, EndpointRole::Responder)?;
    let zero = a.owner(0)?;
    let one = a.owner(1)?;
    let frames = [frame(0x31), frame(0x72)];
    let first = a.enqueue(zero, ms(0), &frames[0])?;
    let second = a.enqueue(one, ms(0), &frames[1])?;
    assert_ne!(first.owner, second.owner);
    assert_eq!(first.record, second.record);
    let mut lost = vec![0; plan.send_max_packet_bytes()];
    let mut budget = OutboundBudget {
        packets: 1,
        wire_bytes: 100_000,
    };
    let untouched = budget;
    let mut short = vec![0x5a; plan.send_max_packet_bytes() - 1];
    assert_eq!(
        a.poll_data(zero, ms(0), &mut short, &mut budget),
        Err(Error::Output {
            required: plan.send_max_packet_bytes()
        })
    );
    assert!(short.iter().all(|b| *b == 0x5a));
    assert_eq!(budget, untouched);
    assert!(a.pending_data_output(zero)?.is_none());
    let original = a
        .poll_data(zero, ms(0), &mut lost, &mut budget)?
        .ok_or("actual owner0 source")?;
    assert_eq!(original.wire_bytes(), original.bytes() + 28);
    assert_eq!(budget.packets, 0);
    assert_eq!(budget.wire_bytes, 100_000 - original.wire_bytes());
    let duplicate = a.pending_data_output(zero)?.ok_or("retained original")?;
    let foreign = a.pending_data_output(zero)?.ok_or("foreign view")?;
    assert_eq!(
        b.confirm_output_at(ms(0), ms(0), foreign),
        Err(Error::Token)
    );
    let mut unchanged = vec![0x5a; plan.send_max_packet_bytes()];
    let before = budget;
    assert!(
        a.poll_data(zero, ms(0), &mut unchanged, &mut budget)?
            .is_none()
    );
    assert!(unchanged.iter().all(|b| *b == 0x5a));
    assert_eq!(budget, before);
    assert_eq!(a.pending_data_output(zero)?.as_ref(), Some(&original));
    let mut wrong_class = lost[..original.bytes()].to_vec();
    wrong_class[5] = 2;
    assert_eq!(
        b.accept_authenticated_at(ms(0), ms(0), &wrong_class),
        Err(Error::Class)
    );
    assert_eq!(b.prepare_native(zero, ms(0), 1)?, NativePreparation::Idle);
    let mut bytes = vec![0; plan.send_max_packet_bytes()];
    let mut budget = OutboundBudget {
        packets: 1,
        wire_bytes: 100_000,
    };
    let independent = a
        .poll_data(one, ms(0), &mut bytes, &mut budget)?
        .ok_or("owner1 progresses while0 held")?;
    let length = independent.bytes();
    a.confirm_output_at(ms(0), ms(0), independent)?;
    b.accept_authenticated_at(ms(0), ms(0), &bytes[..length])?;
    let mut delivered = [Vec::new(), Vec::new()];
    let mut ready = false;
    for _ in 0..8 {
        match b.prepare_native(one, ms(0), 1)? {
            NativePreparation::Progress => {}
            NativePreparation::Ready(token) => {
                let pending = b.pending_native(one)?.ok_or("actual independent native")?;
                assert_eq!(pending.bytes, frames[1].as_slice());
                let original_deadline = pending.deadline;
                assert_eq!(a.commit_native(ms(0), token), Err(Error::Token));
                let NativePreparation::AlreadyPending(token) = b.prepare_native(one, ms(0), 1)?
                else {
                    return Err("foreign receipt released actual native custody".into());
                };
                let NativePreparation::AlreadyPending(duplicate) =
                    b.prepare_native(one, ms(0), 1)?
                else {
                    return Err("actual native observation lost".into());
                };
                assert_eq!(token, duplicate);
                let held = b.pending_native(one)?.ok_or("original held native")?;
                assert_eq!(held.deadline, original_deadline);
                delivered[1].push(held.bytes.to_vec());
                b.commit_native(ms(0), token)?;
                assert_eq!(b.commit_native(ms(0), duplicate), Err(Error::Token));
                ready = true;
                break;
            }
            _ => return Err("actual complete owner1 body was not available".into()),
        }
    }
    assert!(ready);
    assert_eq!(delivered[1], vec![frames[1].clone()]);
    assert!(b.pending_native(zero)?.is_none());
    // This is a physical receipt followed by modeled loss, never enqueue-as-success.
    a.confirm_output_at(ms(10), ms(7), original)?;
    assert_eq!(
        a.confirm_output_at(ms(10), ms(7), duplicate),
        Err(Error::Token)
    );
    let mut retried = false;
    let mut feedback_lost = false;
    for step in 1..=200 {
        let now = ms(10 + step * 10);
        for id in [zero, one] {
            let mut bytes = vec![0; plan.send_max_packet_bytes()];
            let mut budget = OutboundBudget {
                packets: 1,
                wire_bytes: 100_000,
            };
            if let Some(token) = a.poll_data(id, now, &mut bytes, &mut budget)? {
                let length = token.bytes();
                if id == zero {
                    retried = true;
                }
                a.confirm_output_at(now, now, token)?;
                b.accept_authenticated_at(now, now, &bytes[..length])?;
            }
            collect(&mut b, id, now, &mut delivered[usize::from(id.index())])?;
            let mut bytes = vec![0; plan.receive_max_packet_bytes()];
            let mut budget = OutboundBudget {
                packets: 1,
                wire_bytes: 100_000,
            };
            if let Some(token) = b.poll_feedback(id, now, &mut bytes, &mut budget)? {
                let length = token.bytes();
                assert_eq!(token.wire_bytes(), length + 28);
                b.confirm_output_at(now, now, token)?;
                if id == zero && !feedback_lost {
                    feedback_lost = true;
                } else {
                    a.accept_authenticated_at(now, now, &bytes[..length])?;
                }
            }
        }
        if a.drained() && b.drained() {
            break;
        }
    }
    assert!(retried && feedback_lost);
    assert_eq!(delivered[0], vec![frames[0].clone()]);
    assert_eq!(delivered[1], vec![frames[1].clone()]);
    assert!(a.drained() && b.drained());
    assert_eq!(a.storage_usage().capacity_bytes, plan.capacity_bytes());
    assert_eq!(b.storage_usage().capacity_bytes, plan.capacity_bytes());
    Ok(())
}

#[test]
fn physical_native_completion_error_cannot_reissue_the_already_written_body() -> TestResult {
    let config = config(1)?;
    let plan = storage::Plan::for_collection(config)?;
    let mut a = construct(config, EndpointRole::Initiator)?;
    let mut b = construct(config, EndpointRole::Responder)?;
    let id = a.owner(0)?;
    a.enqueue(id, ms(0), &frame(0x42))?;
    let mut bytes = vec![0; plan.send_max_packet_bytes()];
    let mut budget = OutboundBudget {
        packets: 1,
        wire_bytes: 100_000,
    };
    let output = a
        .poll_data(id, ms(0), &mut bytes, &mut budget)?
        .ok_or("actual source")?;
    let length = output.bytes();
    a.confirm_output_at(ms(0), ms(0), output)?;
    b.accept_authenticated_at(ms(0), ms(0), &bytes[..length])?;
    let mut completion = None;
    for _ in 0..8 {
        match b.prepare_native(id, ms(10), 1)? {
            NativePreparation::Progress => {}
            NativePreparation::Ready(token) => {
                completion = Some(token);
                break;
            }
            _ => return Err("actual complete native output missing".into()),
        }
    }
    let token = completion.ok_or("bounded native progress")?;
    assert_eq!(
        b.pending_native(id)?.ok_or("actual body")?.bytes,
        frame(0x42)
    );
    // The trusted caller already wrote the whole body, but supplied an invalid
    // observation clock. This fact must never create a second native Ready.
    assert_eq!(
        b.commit_native(ms(9), token),
        Err(Error::Endpoint(aligned::Error::Time))
    );
    assert!(b.slot(id)?.endpoint.pending().is_some());
    assert_eq!(
        b.prepare_native(id, ms(10), 1),
        Err(Error::Endpoint(aligned::Error::Time))
    );
    assert!(matches!(
        b.pending_native(id),
        Err(Error::Endpoint(aligned::Error::Time))
    ));
    assert!(!b.drained());
    Ok(())
}

#[path = "unreliable_tests.rs"]
mod unreliable;
