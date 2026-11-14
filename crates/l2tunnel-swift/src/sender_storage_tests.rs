//! Exact owned layouts and real legacy/reserved Sender protocol comparisons.

use super::*;
use crate::{Receiver, storage::Allocation};
use std::mem::size_of;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn config() -> Config {
    Config {
        datagram_bytes: 128,
        window: 4,
        repair_numerator: 0,
        repair_denominator: 1000,
        flow_sources: 16,
        queue_bytes: 4096,
        max_packet: 128,
        flush_micros: 1000,
        feedback_micros: 2000,
        tail_micros: 10_000,
        min_rto_micros: 20_000,
        max_rto_micros: 200_000,
    }
}

fn reserved(config: Config) -> TestResult<Sender> {
    let bytes = Sender::reserved_bytes(config)?;
    let mut allocation = Allocation::new(bytes);
    let sender = Sender::new_reserved(config, &mut allocation)?;
    assert_eq!(allocation.used(), bytes);
    assert_eq!(allocation.allocations(), config.flow_sources + 4);
    Ok(sender)
}

fn feedback(base: u64, end: u64, requests: &[u16]) -> Vec<u8> {
    let mut bytes = vec![KIND_FEEDBACK];
    bytes.extend_from_slice(&(base as u32).to_be_bytes());
    bytes.extend_from_slice(&(end as u32).to_be_bytes());
    bytes.extend_from_slice(&(requests.len() as u16).to_be_bytes());
    bytes.push(requests.len() as u8);
    for request in requests {
        bytes.extend_from_slice(&request.to_be_bytes());
    }
    bytes
}

fn fill(sender: &mut Sender, count: usize) -> TestResult {
    let mut output = Vec::with_capacity(sender.config.datagram_bytes);
    let packet = vec![0x39; sender.config.symbol_bytes() - FRAME_PREFIX];
    for seed in 0..count {
        assert!(sender.push_packet(0, &packet)?);
        assert!(sender.poll(0, seed as u64, &mut output)?);
        assert_eq!(output[0], KIND_SOURCE);
    }
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
struct Snapshot {
    queue: Vec<u8>,
    queue_since: u64,
    sources: Vec<(Vec<u8>, u64, u64, bool, bool)>,
    acked: u64,
    next: u64,
    credit: u32,
    repairs_due: u32,
    retransmit: Vec<u64>,
    smoothed_rtt: u64,
    sampled_end: u64,
    probe_at: Option<u64>,
    probe_interval: u64,
    probe_burst: u32,
    peer_missing: u32,
    spare: Vec<(usize, usize, usize)>,
    stats: SenderStats,
}

fn snapshot(sender: &Sender) -> Snapshot {
    Snapshot {
        queue: sender.queue.iter().copied().collect(),
        queue_since: sender.queue_since,
        sources: sender
            .sources
            .iter()
            .map(|source| {
                (
                    source.payload.clone(),
                    source.first_sent,
                    source.last_sent,
                    source.retransmitted,
                    source.queued,
                )
            })
            .collect(),
        acked: sender.acked,
        next: sender.next,
        credit: sender.credit,
        repairs_due: sender.repairs_due,
        retransmit: sender.retransmit.iter().copied().collect(),
        smoothed_rtt: sender.smoothed_rtt,
        sampled_end: sender.sampled_end,
        probe_at: sender.probe_at,
        probe_interval: sender.probe_interval,
        probe_burst: sender.probe_burst,
        peer_missing: sender.peer_missing,
        spare: sender
            .spare
            .iter()
            .map(|buffer| (buffer.as_ptr() as usize, buffer.len(), buffer.capacity()))
            .collect(),
        stats: sender.stats,
    }
}

#[derive(Debug)]
struct Inventory {
    queue: usize,
    sources: usize,
    retransmit: usize,
    spare: usize,
    payloads: Vec<(usize, usize)>,
}

fn payloads(sender: &Sender) -> Vec<(usize, usize)> {
    let mut result: Vec<_> = sender
        .spare
        .iter()
        .chain(sender.sources.iter().map(|source| &source.payload))
        .map(|buffer| (buffer.as_ptr() as usize, buffer.capacity()))
        .collect();
    result.sort_unstable();
    result
}

fn inventory(sender: &Sender) -> Inventory {
    Inventory {
        queue: sender.queue.as_slices().0.as_ptr() as usize,
        sources: sender.sources.as_slices().0.as_ptr() as usize,
        retransmit: sender.retransmit.as_slices().0.as_ptr() as usize,
        spare: sender.spare.as_ptr() as usize,
        payloads: payloads(sender),
    }
}

fn inside<T>(queue: &VecDeque<T>, allocation: usize) {
    let end = allocation + queue.capacity() * size_of::<T>();
    for slice in [queue.as_slices().0, queue.as_slices().1] {
        let start = slice.as_ptr() as usize;
        assert!(start >= allocation && start <= end);
        assert!(start + std::mem::size_of_val(slice) <= end);
    }
}

fn unchanged_inventory(sender: &Sender, original: &Inventory) {
    assert_eq!(sender.queue.capacity(), sender.config.queue_bytes);
    assert_eq!(sender.sources.capacity(), sender.config.flow_sources);
    assert_eq!(sender.retransmit.capacity(), sender.config.flow_sources);
    assert_eq!(sender.spare.capacity(), sender.config.flow_sources);
    assert_eq!(
        sender.sources.len() + sender.spare.len(),
        sender.config.flow_sources
    );
    assert!(sender.retransmit.len() <= sender.config.flow_sources);
    assert_eq!(sender.spare.as_ptr() as usize, original.spare);
    inside(&sender.queue, original.queue);
    inside(&sender.sources, original.sources);
    inside(&sender.retransmit, original.retransmit);
    assert_eq!(payloads(sender), original.payloads);
}

#[test]
fn exact_heap_inventory_excludes_inline_sender_and_matches_real_allocations() -> TestResult {
    let config = config();
    let expected = config.queue_bytes
        + config.flow_sources * size_of::<Source>()
        + config.flow_sources * size_of::<u64>()
        + config.flow_sources * size_of::<Vec<u8>>()
        + config.flow_sources * config.symbol_bytes();
    assert_eq!(Sender::reserved_bytes(config)?, expected);
    let sender = reserved(config)?;
    let actual = sender.queue.capacity()
        + sender.sources.capacity() * size_of::<Source>()
        + sender.retransmit.capacity() * size_of::<u64>()
        + sender.spare.capacity() * size_of::<Vec<u8>>()
        + sender.spare.iter().map(Vec::capacity).sum::<usize>();
    assert_eq!(actual, expected);
    assert_eq!(sender.sources.len(), 0);
    assert_eq!(sender.spare.len(), config.flow_sources);
    assert!(
        sender
            .spare
            .iter()
            .all(|payload| payload.is_empty() && payload.capacity() == config.symbol_bytes())
    );
    Ok(())
}

#[test]
fn invalid_geometry_and_each_short_construction_budget_refuse_without_fallback() -> TestResult {
    for invalid in [
        Config {
            datagram_bytes: 0,
            ..config()
        },
        Config {
            flow_sources: usize::MAX,
            ..config()
        },
        Config {
            queue_bytes: usize::MAX,
            ..config()
        },
    ] {
        assert_eq!(Sender::reserved_bytes(invalid), Err(Error::Configuration));
        let mut allocation = Allocation::new(usize::MAX);
        assert!(matches!(
            Sender::new_reserved(invalid, &mut allocation),
            Err(Error::Configuration)
        ));
        assert_eq!(allocation.used(), 0);
    }
    let config = config();
    let mut boundaries = vec![config.queue_bytes];
    boundaries.push(boundaries[0] + config.flow_sources * size_of::<Source>());
    boundaries.push(boundaries[1] + config.flow_sources * size_of::<u64>());
    boundaries.push(boundaries[2] + config.flow_sources * size_of::<Vec<u8>>());
    let before_payloads = boundaries[3];
    for count in 1..=config.flow_sources {
        boundaries.push(before_payloads + count * config.symbol_bytes());
    }
    assert_eq!(
        boundaries.last().copied(),
        Some(Sender::reserved_bytes(config)?)
    );
    for boundary in boundaries {
        let limit = boundary - 1;
        let mut allocation = Allocation::new(limit);
        assert!(matches!(
            Sender::new_reserved(config, &mut allocation),
            Err(Error::Storage)
        ));
        assert!(allocation.used() <= limit);
    }
    Ok(())
}

#[test]
fn more_than_sixty_four_payloads_survive_real_ack_and_reuse_every_pointer() -> TestResult {
    let config = Config {
        flow_sources: 70,
        ..config()
    };
    let mut sender = reserved(config)?;
    let mut legacy = Sender::new(config)?;
    let original = inventory(&sender);
    let mut receiver = Receiver::new(config)?;
    let mut body = Vec::with_capacity(config.datagram_bytes);
    let mut legacy_body = Vec::new();
    let mut native = Vec::new();
    let packet = vec![0xA7; config.symbol_bytes() - FRAME_PREFIX];
    for round in 0..3u64 {
        for index in 0..config.flow_sources {
            let seed = round * config.flow_sources as u64 + index as u64;
            assert!(sender.push_packet(round * 10_000, &packet)?);
            assert!(legacy.push_packet(round * 10_000, &packet)?);
            assert!(sender.poll(round * 10_000, seed, &mut body)?);
            assert!(legacy.poll(round * 10_000, seed, &mut legacy_body)?);
            assert_eq!(body, legacy_body);
            receiver.on_datagram(seed, &body)?;
            assert!(receiver.pop_packet(&mut native)?);
            assert_eq!(native, packet);
        }
        assert_eq!(sender.unconfirmed(), config.flow_sources);
        assert!(sender.spare.is_empty());
        unchanged_inventory(&sender, &original);
        assert!(receiver.feedback((round + 1) * 10_000, &mut body));
        sender.on_feedback((round + 1) * 10_000, &body)?;
        legacy.on_feedback((round + 1) * 10_000, &body)?;
        assert_eq!(sender.unconfirmed(), 0);
        assert_eq!(sender.spare.len(), config.flow_sources);
        assert_eq!(legacy.spare.len(), 64);
        assert_eq!(sender.observation(), legacy.observation());
        assert_eq!(sender.deadline(), legacy.deadline());
        unchanged_inventory(&sender, &original);
    }
    Ok(())
}

#[test]
fn wrapped_queue_full_admission_and_source_flow_bound_keep_all_capacities() -> TestResult {
    let config = Config {
        queue_bytes: 256,
        flow_sources: 4,
        ..config()
    };
    let mut sender = reserved(config)?;
    let original = inventory(&sender);
    let mut body = Vec::with_capacity(config.datagram_bytes);
    assert!(sender.push_packet(0, &[1; 100])?);
    assert!(sender.push_packet(0, &[2; 100])?);
    assert!(sender.poll(0, 0, &mut body)?);
    assert!(sender.push_packet(0, &[3; 100])?);
    assert!(!sender.queue.as_slices().1.is_empty());
    let before = snapshot(&sender);
    assert!(!sender.push_packet(0, &[4; 100])?);
    assert_eq!(snapshot(&sender), before);
    assert!(sender.poll(0, 1, &mut body)?);
    assert!(sender.poll(1000, 2, &mut body)?);
    assert!(sender.push_packet(1000, &[5; 118])?);
    assert!(sender.poll(1000, 3, &mut body)?);
    assert_eq!(sender.unconfirmed(), config.flow_sources);
    assert!(sender.push_packet(1000, &[6; 118])?);
    assert!(!sender.poll(1001, 4, &mut body)?);
    assert_eq!(sender.queued(), config.symbol_bytes());
    unchanged_inventory(&sender, &original);
    Ok(())
}

#[test]
fn insufficient_caller_output_and_missing_pool_refuse_before_state_advance() -> TestResult {
    let config = config();
    let mut sender = reserved(config)?;
    assert!(sender.push_packet(77, &[0x81; 118])?);
    let mut short = Vec::with_capacity(config.datagram_bytes - 1);
    short.extend_from_slice(b"unchanged");
    let before = snapshot(&sender);
    assert_eq!(sender.poll(77, 8, &mut short), Err(Error::Storage));
    assert_eq!(short, b"unchanged");
    assert_eq!(snapshot(&sender), before);
    let _retained_outside_test_pool = sender.spare.pop().ok_or("missing initial spare")?;
    let before = snapshot(&sender);
    let mut body = Vec::with_capacity(config.datagram_bytes);
    assert_eq!(sender.poll(77, 8, &mut body), Err(Error::Storage));
    assert_eq!(snapshot(&sender), before);
    Ok(())
}

#[test]
fn wrong_payload_or_metadata_capacity_never_uses_legacy_growth_path() -> TestResult {
    let config = config();
    let mut sender = reserved(config)?;
    assert!(sender.push_packet(0, &[0x21; 118])?);
    let last = sender.spare.last_mut().ok_or("missing initial spare")?;
    let _retained_original = std::mem::take(last);
    let before = snapshot(&sender);
    let mut body = Vec::with_capacity(config.datagram_bytes);
    assert_eq!(sender.poll(0, 0, &mut body), Err(Error::Storage));
    assert_eq!(snapshot(&sender), before);
    let mut sender = reserved(config)?;
    sender.retransmit = VecDeque::new();
    let before = snapshot(&sender);
    assert_eq!(sender.push_packet(0, &[1]), Err(Error::Storage));
    assert_eq!(snapshot(&sender), before);
    let mut sender = reserved(config)?;
    fill(&mut sender, 1)?;
    let source = sender
        .sources
        .front_mut()
        .ok_or("missing retained source")?;
    let _retained_source = std::mem::take(&mut source.payload);
    let before = snapshot(&sender);
    assert_eq!(
        sender.on_feedback(1000, &feedback(1, 1, &[])),
        Err(Error::Storage)
    );
    assert_eq!(snapshot(&sender), before);
    Ok(())
}

#[test]
fn duplicate_requests_and_acked_stale_entries_stay_within_original_flow_bound() -> TestResult {
    let config = Config {
        flow_sources: MAX_REQUESTS,
        ..config()
    };
    let mut sender = reserved(config)?;
    let original = inventory(&sender);
    fill(&mut sender, config.flow_sources)?;
    let requests: Vec<_> = (0..MAX_REQUESTS as u16).collect();
    sender.on_feedback(1000, &feedback(0, MAX_REQUESTS as u64, &requests))?;
    sender.on_feedback(1000, &feedback(0, MAX_REQUESTS as u64, &requests))?;
    assert_eq!(sender.retransmit.len(), MAX_REQUESTS);
    let duplicates = vec![0; MAX_REQUESTS];
    sender.on_feedback(1001, &feedback(0, MAX_REQUESTS as u64, &duplicates))?;
    assert_eq!(sender.retransmit.len(), MAX_REQUESTS);
    let remaining: Vec<_> = (0..(MAX_REQUESTS / 2) as u16).collect();
    sender.on_feedback(2000, &feedback(32, 64, &remaining))?;
    assert_eq!(sender.retransmit.len(), MAX_REQUESTS);
    assert_eq!(sender.unconfirmed(), 32);
    let mut body = Vec::with_capacity(config.datagram_bytes);
    assert!(sender.poll(2000, 1, &mut body)?);
    assert_eq!(&body[1..5], &32u32.to_be_bytes());
    sender.on_feedback(100_000, &feedback(32, 64, &remaining))?;
    assert_eq!(sender.retransmit.len(), 32);
    let mut unique: Vec<_> = sender.retransmit.iter().copied().collect();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), sender.retransmit.len());
    sender.on_feedback(100_001, &feedback(64, 64, &[]))?;
    assert_eq!(sender.unconfirmed(), 0);
    assert_eq!(sender.retransmit.len(), 32);
    assert!(sender.push_packet(100_001, &[0x67; 118])?);
    assert!(sender.poll(100_001, 2, &mut body)?);
    assert_eq!(&body[1..5], &64u32.to_be_bytes());
    assert!(sender.retransmit.is_empty());
    unchanged_inventory(&sender, &original);
    Ok(())
}

#[test]
fn malformed_final_request_preserves_ack_rtt_probe_and_payload_custody() -> TestResult {
    for selected in [false, true] {
        let mut sender = if selected {
            reserved(config())?
        } else {
            Sender::new(config())?
        };
        fill(&mut sender, 4)?;
        let before = snapshot(&sender);
        // ACK1 and a fresh RTT sample would otherwise be applied before the
        // last offset is discovered to lie beyond end4.
        assert_eq!(
            sender.on_feedback(80_000, &feedback(1, 4, &[0, 1, 3])),
            Err(Error::Malformed)
        );
        assert_eq!(snapshot(&sender), before);
        assert_eq!(
            sender.on_feedback(80_000, &feedback(1, 4, &[0, u16::MAX])),
            Err(Error::Malformed)
        );
        assert_eq!(snapshot(&sender), before);
    }
    Ok(())
}

#[test]
fn source_sequence_and_credit_exhaustion_precede_queue_and_pool_consumption() -> TestResult {
    let config = config();
    let mut sender = reserved(config)?;
    sender.start_at(u64::MAX);
    assert!(sender.push_packet(0, &[0x49; 118])?);
    let before = snapshot(&sender);
    let mut body = Vec::with_capacity(config.datagram_bytes);
    assert_eq!(sender.poll(0, 0, &mut body), Err(Error::Exhausted));
    assert_eq!(snapshot(&sender), before);
    let mut sender = reserved(config)?;
    sender.stats.packets = u64::MAX;
    let before = snapshot(&sender);
    assert_eq!(sender.push_packet(0, &[1]), Err(Error::Exhausted));
    assert_eq!(snapshot(&sender), before);
    let mut sender = reserved(Config {
        repair_numerator: 65_536,
        repair_denominator: 65_536,
        ..config
    })?;
    sender.credit = u32::MAX;
    assert!(sender.push_packet(0, &[0x49; 118])?);
    let before = snapshot(&sender);
    assert_eq!(sender.poll(0, 0, &mut body), Err(Error::Exhausted));
    assert_eq!(snapshot(&sender), before);
    Ok(())
}

#[test]
fn largest_fractional_credit_and_extreme_rtt_remain_checked_and_clamped() -> TestResult {
    let config = Config {
        repair_numerator: 65_536,
        repair_denominator: 65_536,
        ..config()
    };
    let mut sender = reserved(config)?;
    sender.credit = config.repair_denominator - 1;
    assert!(sender.push_packet(0, &[1; 118])?);
    let mut body = Vec::with_capacity(config.datagram_bytes);
    assert!(sender.poll(0, 0, &mut body)?);
    assert_eq!(sender.credit, config.repair_denominator - 1);
    assert_eq!(sender.repairs_due, 1);
    assert!(sender.poll(0, 1, &mut body)?);
    assert_eq!(body[0], KIND_REPAIR);
    assert_eq!(sender.repairs_due, 0);
    for selected in [false, true] {
        let mut sender = if selected {
            reserved(config)?
        } else {
            Sender::new(config)?
        };
        fill(&mut sender, 1)?;
        sender.on_feedback(u64::MAX, &feedback(0, 1, &[]))?;
        assert_eq!(sender.stats.smoothed_rtt_micros, u64::MAX);
        assert_eq!(sender.rto(), config.max_rto_micros);
        assert_eq!(sender.probe_at, Some(u64::MAX));
    }
    Ok(())
}

#[test]
fn valid_huge_tail_interval_saturates_before_existing_probe_clamp() -> TestResult {
    let config = Config {
        tail_micros: u64::MAX,
        ..config()
    };
    config.validate()?;
    let mut outputs = Vec::new();
    for selected in [false, true] {
        let mut sender = if selected {
            reserved(config)?
        } else {
            Sender::new(config)?
        };
        let mut body = Vec::with_capacity(config.datagram_bytes);
        assert!(sender.push_packet(0, &[0x7F; 118])?);
        assert!(sender.poll(0, 0, &mut body)?);
        assert_eq!(sender.deadline(), Some(u64::MAX));
        assert!(sender.poll(u64::MAX, 1, &mut body)?);
        assert_eq!(body[0], KIND_REPAIR);
        assert_eq!(sender.probe_interval, config.max_rto_micros);
        assert_eq!(sender.probe_at, Some(u64::MAX));
        assert_eq!(sender.stats.tail_repairs, 1);
        outputs.push(body);
    }
    assert_eq!(outputs[0], outputs[1]);
    Ok(())
}

fn packet(index: usize) -> Vec<u8> {
    let length = [1, 37, 118, 128, 63][index % 5];
    (0..length)
        .map(|offset| (index.wrapping_mul(31) ^ offset) as u8)
        .collect()
}

fn differential(start: u64, numerator: u32, denominator: u32) -> TestResult {
    let config = Config {
        flow_sources: 64,
        repair_numerator: numerator,
        repair_denominator: denominator,
        ..config()
    };
    let mut legacy = Sender::new(config)?;
    let mut sender = reserved(config)?;
    let original = inventory(&sender);
    let mut receivers = [Receiver::new(config)?, Receiver::new(config)?];
    legacy.start_at(start);
    sender.start_at(start);
    for receiver in &mut receivers {
        receiver.start_at(start);
    }
    let mut left = Vec::with_capacity(config.datagram_bytes);
    let mut right = Vec::with_capacity(config.datagram_bytes);
    let mut feedback_left = Vec::new();
    let mut feedback_right = Vec::new();
    let mut forward = Vec::<(u64, u64, Vec<u8>)>::new();
    let mut reverse = Vec::<(u64, u64, Vec<u8>)>::new();
    let mut offered = 0;
    let mut delivered = 0;
    let mut seed = 0;
    let mut feedback_count = 0_u64;
    for turn in 1..=10_000u64 {
        let now = turn * 1000;
        let mut index = 0;
        while index < reverse.len() {
            if reverse[index].0 <= now {
                let (_, _, body) = reverse.swap_remove(index);
                legacy.on_feedback(now, &body)?;
                sender.on_feedback(now, &body)?;
            } else {
                index += 1;
            }
        }
        for _ in 0..3 {
            assert_eq!(legacy.has_room(), sender.has_room());
            if offered == 200 || !sender.has_room() {
                break;
            }
            let native = packet(offered);
            assert!(legacy.push_packet(now, &native)?);
            assert!(sender.push_packet(now, &native)?);
            offered += 1;
        }
        for _ in 0..3 {
            seed += 1;
            let emitted = legacy.poll(now, seed, &mut left)?;
            assert_eq!(sender.poll(now, seed, &mut right)?, emitted);
            assert_eq!(left, right);
            if !emitted {
                break;
            }
            if !seed.is_multiple_of(7) {
                forward.push((
                    now + 2000 + if seed.is_multiple_of(5) { 4000 } else { 0 },
                    seed,
                    left.clone(),
                ));
            }
        }
        let mut due = Vec::new();
        let mut index = 0;
        while index < forward.len() {
            if forward[index].0 <= now {
                due.push(forward.swap_remove(index));
            } else {
                index += 1;
            }
        }
        due.sort_by_key(|entry| (entry.0, entry.1));
        for (_, number, body) in due {
            receivers[0].on_datagram(number, &body)?;
            receivers[1].on_datagram(number, &body)?;
            loop {
                let mut a = Vec::new();
                let mut b = Vec::new();
                let popped = receivers[0].pop_packet(&mut a)?;
                assert_eq!(receivers[1].pop_packet(&mut b)?, popped);
                assert_eq!(a, b);
                if !popped {
                    break;
                }
                assert_eq!(a, packet(delivered));
                delivered += 1;
            }
        }
        let generated = receivers[0].feedback(now, &mut feedback_left);
        assert_eq!(receivers[1].feedback(now, &mut feedback_right), generated);
        assert_eq!(feedback_left, feedback_right);
        if generated {
            feedback_count += 1;
            if !feedback_count.is_multiple_of(11) {
                reverse.push((
                    now + 2000
                        + if feedback_count.is_multiple_of(4) {
                            4000
                        } else {
                            0
                        },
                    feedback_count,
                    feedback_left.clone(),
                ));
            }
        }
        assert_eq!(legacy.observation(), sender.observation());
        assert_eq!(legacy.deadline(), sender.deadline());
        assert_eq!(legacy.ready(now), sender.ready(now));
        assert_eq!(receivers[0].stats(), receivers[1].stats());
        unchanged_inventory(&sender, &original);
        if offered == 200 && delivered == 200 && sender.unconfirmed() == 0 {
            assert_eq!(sender.queued(), 0);
            assert!(sender.stats.sources > 0);
            if numerator > 0 {
                assert!(sender.stats.repairs > 0);
            } else {
                assert!(sender.stats.retransmits > 0);
            }
            return Ok(());
        }
    }
    Err("finite impaired legacy/reserved comparison did not finish".into())
}

#[test]
fn legacy_reserved_wire_timers_stats_and_recovery_match_with_loss_reorder_and_wrap() -> TestResult {
    for start in [0, (1u64 << 32) - 3] {
        for (numerator, denominator) in [(0, 1), (41, 200), (1, 1)] {
            differential(start, numerator, denominator)?;
        }
    }
    Ok(())
}

#[test]
fn lost_only_source_uses_identical_tail_repair_and_real_receiver_feedback() -> TestResult {
    let config = config();
    let mut legacy = Sender::new(config)?;
    let mut sender = reserved(config)?;
    let original = inventory(&sender);
    let mut receiver = Receiver::new(config)?;
    let mut a = Vec::with_capacity(config.datagram_bytes);
    let mut b = Vec::with_capacity(config.datagram_bytes);
    for source in [&mut legacy, &mut sender] {
        assert!(source.push_packet(0, &[0x29; 80])?);
    }
    assert!(legacy.poll(1000, 0, &mut a)?);
    assert!(sender.poll(1000, 0, &mut b)?);
    assert_eq!(a, b); // Withhold the only original source from the real receiver.
    let tail = 1000 + config.tail_micros;
    assert_eq!(legacy.deadline(), Some(tail));
    assert_eq!(sender.deadline(), Some(tail));
    assert!(legacy.poll(tail, 1, &mut a)?);
    assert!(sender.poll(tail, 1, &mut b)?);
    assert_eq!(a, b);
    assert_eq!(b[0], KIND_REPAIR);
    receiver.on_datagram(1, &b)?;
    let mut native = Vec::new();
    assert!(receiver.pop_packet(&mut native)?);
    assert_eq!(native, [0x29; 80]);
    assert!(receiver.feedback(tail + config.feedback_micros, &mut a));
    legacy.on_feedback(tail + config.feedback_micros, &a)?;
    sender.on_feedback(tail + config.feedback_micros, &a)?;
    assert_eq!(legacy.observation(), sender.observation());
    assert_eq!(sender.unconfirmed(), 0);
    assert_eq!(sender.stats.tail_repairs, 1);
    unchanged_inventory(&sender, &original);
    Ok(())
}
