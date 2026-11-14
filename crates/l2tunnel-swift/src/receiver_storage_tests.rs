//! Reserved receiver pools through real sources, repair algebra and terminal errors.

use super::*;
use crate::{Sender, storage::Allocation};
use std::{collections::BTreeSet, mem::size_of};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn config() -> Config {
    Config {
        datagram_bytes: 64,
        window: 3,
        repair_numerator: 1,
        repair_denominator: 2,
        flow_sources: 24,
        queue_bytes: 1024,
        max_packet: 128,
        flush_micros: 0,
        feedback_micros: 1000,
        tail_micros: 10_000,
        min_rto_micros: 20_000,
        max_rto_micros: 200_000,
    }
}

fn reserved(config: Config) -> Result<Receiver, Error> {
    let mut allocation = Allocation::new(Receiver::reserved_bytes(config)?);
    Receiver::new_reserved(config, &mut allocation)
}

#[derive(Debug, Eq, PartialEq)]
struct Pools {
    metadata: [(usize, usize); 4],
    deques: [usize; 2],
    payloads: Vec<(usize, usize)>,
    terms: Vec<(usize, usize)>,
}

fn pools(receiver: &Receiver) -> Pools {
    let mut payloads = Vec::new();
    let mut terms = vec![(
        receiver.scratch_terms.as_ptr() as usize,
        receiver.scratch_terms.capacity(),
    )];
    for source in receiver.spare.iter().chain(receiver.slots.iter().flatten()) {
        payloads.push((source.as_ptr() as usize, source.capacity()));
    }
    for row in receiver
        .rows
        .iter()
        .chain(&receiver.row_spare)
        .chain(&receiver.repivot)
    {
        payloads.push((row.data.as_ptr() as usize, row.data.capacity()));
        terms.push((row.terms.as_ptr() as usize, row.terms.capacity()));
    }
    payloads.sort_unstable();
    terms.sort_unstable();
    Pools {
        metadata: [
            (receiver.spare.as_ptr() as usize, receiver.spare.capacity()),
            (receiver.rows.as_ptr() as usize, receiver.rows.capacity()),
            (
                receiver.row_spare.as_ptr() as usize,
                receiver.row_spare.capacity(),
            ),
            (
                receiver.repivot.as_ptr() as usize,
                receiver.repivot.capacity(),
            ),
        ],
        // Ring heads move during ordinary history/stream service. Their fixed
        // capacities, not a head slice's moving address, are the invariant.
        deques: [receiver.slots.capacity(), receiver.stream.capacity()],
        payloads,
        terms,
    }
}

#[test]
fn exact_receiver_layout_and_constructor_budget_are_independent() -> TestResult {
    let config = config();
    let (f, w, s, p) = (
        config.flow_sources,
        config.window,
        config.symbol_bytes(),
        config.max_packet,
    );
    let (n, r, t, b) = (f + w, 2 * w, 2 * w + 1, f * s + p + FRAME_PREFIX);
    let expected = n * (size_of::<Option<Vec<u8>>>() + size_of::<Vec<u8>>() + s + 2)
        + (2 * r + t) * size_of::<Row>()
        + t * (f * size_of::<Term>() + s + 2)
        + f * size_of::<Term>()
        + b;
    assert_eq!(Receiver::reserved_bytes(config)?, expected);
    let mut allocation = Allocation::new(expected);
    let receiver = Receiver::new_reserved(config, &mut allocation)?;
    assert_eq!(allocation.used(), expected);
    assert_eq!(allocation.allocations(), n + 2 * t + 7);
    assert_eq!(receiver.slots.capacity(), n);
    assert_eq!(receiver.spare.len(), n);
    assert_eq!(receiver.rows.capacity(), r);
    assert_eq!(receiver.row_spare.len(), t);
    assert_eq!(receiver.row_spare.capacity(), t);
    assert_eq!(receiver.repivot.capacity(), r);
    assert_eq!(receiver.scratch_terms.capacity(), f);
    assert_eq!(receiver.stream.capacity(), b);
    let snapshot = pools(&receiver);
    assert_eq!(snapshot.payloads.len(), n + t);
    assert!(
        snapshot
            .payloads
            .iter()
            .all(|(_, capacity)| *capacity == s + 2)
    );
    assert_eq!(snapshot.terms.len(), t + 1);
    assert!(snapshot.terms.iter().all(|(_, capacity)| *capacity == f));
    let mut short = Allocation::new(expected - 1);
    assert_eq!(
        Receiver::new_reserved(config, &mut short).err(),
        Some(Error::Storage)
    );
    let mut invalid = config;
    invalid.flow_sources = invalid.window - 1;
    let mut untouched = Allocation::new(expected);
    assert_eq!(
        Receiver::new_reserved(invalid, &mut untouched).err(),
        Some(Error::Configuration)
    );
    assert_eq!(untouched.used(), 0);
    assert_eq!(untouched.allocations(), 0);
    Ok(())
}

fn deliver(
    legacy: &mut Receiver,
    receiver: &mut Receiver,
    snapshot: &Pools,
    seed: u64,
    body: &[u8],
) -> TestResult {
    legacy.on_datagram(seed, body)?;
    receiver.on_datagram(seed, body)?;
    assert_eq!(legacy.stats(), receiver.stats());
    assert_eq!(legacy.pending(), receiver.pending());
    assert_eq!(legacy.deadline(), receiver.deadline());
    assert_eq!(&pools(receiver), snapshot);
    Ok(())
}

#[test]
fn actual_sender_loss_reorder_duplicates_match_legacy_and_recycle_over64_sources() -> TestResult {
    let mut config = config();
    config.flow_sources = 80;
    let mut sender = Sender::new(config)?;
    let mut legacy = Receiver::new(config)?;
    let mut receiver = reserved(config)?;
    let snapshot = pools(&receiver);
    let packets: Vec<Vec<u8>> = (0..100usize)
        .map(|index| {
            let length = [1, 20, 53, 100, 128][index % 5];
            (0..length)
                .map(|offset| (index as u8).wrapping_add(offset as u8))
                .collect()
        })
        .collect();
    let (mut offered, mut delivered, mut seed) = (0, 0, 0u64);
    let mut lost = BTreeSet::new();
    let mut pending: Option<(u64, Vec<u8>)> = None;
    let mut body = Vec::with_capacity(config.datagram_bytes);
    let mut old_feedback = Vec::with_capacity(FEEDBACK_HEADER + 2 * MAX_REQUESTS);
    let mut feedback = Vec::with_capacity(FEEDBACK_HEADER + 2 * MAX_REQUESTS);
    let mut old_native = Vec::with_capacity(config.max_packet);
    let mut native = Vec::with_capacity(config.max_packet);
    let mut complete = false;
    for step in 0..5000u64 {
        let now = step * 1000;
        while offered < packets.len() && sender.has_room() {
            assert!(sender.push_packet(now, &packets[offered])?);
            offered += 1;
        }
        if sender.poll(now, seed, &mut body)? {
            let dropped = if body[0] == KIND_SOURCE {
                let sequence = read_u32(&body[1..]).ok_or("missing source sequence")?;
                sequence.is_multiple_of(7) && lost.insert(sequence)
            } else {
                seed.is_multiple_of(11)
            };
            if !dropped {
                if seed.is_multiple_of(5) && pending.is_none() {
                    pending = Some((seed, body.clone()));
                } else {
                    deliver(&mut legacy, &mut receiver, &snapshot, seed, &body)?;
                    if seed.is_multiple_of(13) {
                        deliver(&mut legacy, &mut receiver, &snapshot, seed, &body)?;
                    }
                    if let Some((number, held)) = pending.take() {
                        deliver(&mut legacy, &mut receiver, &snapshot, number, &held)?;
                    }
                }
            }
            seed += 1;
        } else if let Some((number, held)) = pending.take() {
            deliver(&mut legacy, &mut receiver, &snapshot, number, &held)?;
        }
        loop {
            let old = legacy.pop_packet(&mut old_native)?;
            assert_eq!(receiver.pop_packet(&mut native)?, old);
            assert_eq!(native, old_native);
            if !old {
                break;
            }
            assert_eq!(
                native,
                *packets.get(delivered).ok_or("extra native output")?
            );
            delivered += 1;
        }
        let old = legacy.feedback(now, &mut old_feedback);
        assert_eq!(receiver.feedback(now, &mut feedback), old);
        if old {
            assert_eq!(feedback, old_feedback);
            sender.on_feedback(now, &feedback)?;
        }
        assert_eq!(legacy.stats(), receiver.stats());
        assert_eq!(pools(&receiver), snapshot);
        if offered == packets.len()
            && delivered == packets.len()
            && sender.queued() == 0
            && sender.unconfirmed() == 0
        {
            complete = true;
            break;
        }
    }
    assert!(complete, "finite actual source/repair run did not finish");
    assert!(receiver.stats().sources + receiver.stats().recovered > 64);
    assert!(receiver.stats().duplicates > 0);
    assert!(legacy.drained() && receiver.drained());
    assert_eq!(pools(&receiver), snapshot);
    Ok(())
}

#[test]
fn actual_sliding_repairs_fill_beyond_window_evict_and_recycle_every_row() -> TestResult {
    let mut config = config();
    config.repair_numerator = 1;
    config.repair_denominator = 1;
    let mut sender = Sender::new(config)?;
    let mut legacy = Receiver::new(config)?;
    let mut receiver = reserved(config)?;
    let snapshot = pools(&receiver);
    let packets: Vec<_> = (0..15u8)
        .map(|number| vec![number; config.symbol_bytes() - FRAME_PREFIX])
        .collect();
    for packet in &packets {
        assert!(sender.push_packet(0, packet)?);
    }
    let mut sources = Vec::new();
    let mut body = Vec::with_capacity(config.datagram_bytes);
    let mut repairs = 0;
    let mut widened = false;
    for seed in 0..64u64 {
        if !sender.poll(0, seed, &mut body)? {
            break;
        }
        if body[0] == KIND_SOURCE {
            sources.push((seed, body.clone()));
        } else {
            let end = read_u32(&body[1..]).ok_or("missing repair end")?;
            if (3..=15).contains(&end) && !end.is_multiple_of(2) {
                deliver(&mut legacy, &mut receiver, &snapshot, seed, &body)?;
                repairs += 1;
                widened |= receiver
                    .rows
                    .iter()
                    .any(|row| row.terms.len() > config.window);
                assert!(receiver.rows.len() <= 2 * config.window);
            }
        }
    }
    assert_eq!(sources.len(), 15);
    assert_eq!(
        repairs, 7,
        "seven actual equations exceed the six-row retention bound"
    );
    assert!(
        widened,
        "overlapping supports must exercise sparse fill-in beyond W"
    );
    assert_eq!(receiver.rows.len(), 2 * config.window);
    for (seed, source) in &sources {
        deliver(&mut legacy, &mut receiver, &snapshot, *seed, source)?;
    }
    let mut native = Vec::with_capacity(config.max_packet);
    let mut old_native = Vec::with_capacity(config.max_packet);
    for packet in &packets {
        assert!(legacy.pop_packet(&mut old_native)?);
        assert!(receiver.pop_packet(&mut native)?);
        assert_eq!(&native, packet);
        assert_eq!(native, old_native);
    }
    assert!(receiver.rows.is_empty());
    assert_eq!(receiver.row_spare.len(), 2 * config.window + 1);
    assert!(receiver.drained());
    assert_eq!(legacy.stats(), receiver.stats());
    assert_eq!(pools(&receiver), snapshot);
    Ok(())
}

fn source(sequence: u32, bytes: &[u8]) -> Vec<u8> {
    let mut body = vec![KIND_SOURCE];
    body.extend_from_slice(&sequence.to_be_bytes());
    body.extend_from_slice(bytes);
    body
}
fn repair(end: u32, count: u8, bytes: &[u8]) -> Vec<u8> {
    let mut body = vec![KIND_REPAIR];
    body.extend_from_slice(&end.to_be_bytes());
    body.push(count);
    body.extend_from_slice(bytes);
    body
}

#[test]
fn malformed_equation_and_solution_paths_retain_all_pool_buffers() -> TestResult {
    for data in [&[0, 0, 0][..], &[0, 57, 0][..], &[0, 1, 9, 1][..]] {
        let mut receiver = reserved(config())?;
        let snapshot = pools(&receiver);
        let seed = 71;
        let mut encoded = data.to_vec();
        gf::scale(&mut encoded, gf::coefficient(seed, 0));
        assert_eq!(
            receiver.on_datagram(seed, &repair(1, 1, &encoded)),
            Err(Error::Malformed)
        );
        assert_eq!(pools(&receiver), snapshot);
        assert_eq!(receiver.row_spare.len(), 2 * config().window + 1);
    }
    let mut receiver = reserved(config())?;
    let snapshot = pools(&receiver);
    receiver.on_datagram(1, &repair(2, 2, &[0, 0, 0]))?;
    assert_eq!(receiver.rows.len(), 1);
    assert_eq!(
        receiver.on_datagram(1, &repair(2, 2, &[0, 0, 1])),
        Err(Error::Malformed)
    );
    assert_eq!(pools(&receiver), snapshot);
    let mut known = reserved(config())?;
    let snapshot = pools(&known);
    known.on_datagram(0, &source(0, &[0, 4, 11, 12, 13, 14]))?;
    assert_eq!(
        known.on_datagram(3, &repair(2, 2, &[0, 0, 0])),
        Err(Error::Malformed)
    );
    assert_eq!(pools(&known), snapshot);
    Ok(())
}

#[test]
fn internal_early_learn_failure_restores_queued_repivot_metadata_and_buffers() -> TestResult {
    let mut receiver = reserved(config())?;
    let snapshot = pools(&receiver);
    // Deliberately violate reduced-form metadata to exercise error cleanup
    // after one row has already moved to repivot. This is an internal invariant
    // fixture, not an authenticated or honest-sender protocol witness.
    let mut first = receiver.take_row()?;
    first.terms.extend_from_slice(&[(0, 1), (1, 1)]);
    first.data.resize(7, 0);
    let mut contradictory = receiver.take_row()?;
    contradictory.terms.push((0, 1));
    contradictory.data.resize(7, 0);
    receiver.rows.push(first);
    receiver.rows.push(contradictory);
    assert_eq!(
        receiver.on_datagram(0, &source(0, &[0, 3, 11, 12, 13])),
        Err(Error::Malformed)
    );
    assert!(receiver.repivot.is_empty());
    assert!(receiver.rows.is_empty());
    assert_eq!(
        receiver.rows.len() + receiver.row_spare.len(),
        2 * config().window + 1
    );
    assert_eq!(pools(&receiver), snapshot);
    Ok(())
}

#[test]
fn internal_short_solution_failure_recycles_its_owned_row_before_returning() -> TestResult {
    let mut receiver = reserved(config())?;
    let snapshot = pools(&receiver);
    let mut row = receiver.take_row()?;
    row.terms.push((0, 1));
    row.data.push(0);
    receiver.rows.push(row);
    assert_eq!(receiver.solve(), Err(Error::Malformed));
    assert!(receiver.rows.is_empty());
    assert_eq!(pools(&receiver), snapshot);
    Ok(())
}

#[test]
fn reserved_partial_prefix_and_payload_have_no_drain_or_buffer_loss() -> TestResult {
    for prefix in [true, false] {
        let config = config();
        let mut sender = Sender::new(config)?;
        let mut receiver = reserved(config)?;
        let snapshot = pools(&receiver);
        let first = vec![
            0xA5;
            if prefix {
                config.symbol_bytes() - 3
            } else {
                100
            }
        ];
        let second = vec![0x5A; 20];
        assert!(sender.push_packet(0, &first)?);
        if prefix {
            assert!(sender.push_packet(0, &second)?);
        }
        let mut body = Vec::with_capacity(config.datagram_bytes);
        let mut output = Vec::with_capacity(config.max_packet);
        assert!(sender.poll(0, 0, &mut body)?);
        receiver.on_datagram(0, &body)?;
        if prefix {
            assert!(receiver.pop_packet(&mut output)?);
            assert_eq!(output, first);
        }
        assert!(!receiver.pop_packet(&mut output)?);
        assert!(output.is_empty());
        assert_eq!(receiver.pending(), 0);
        assert!(!receiver.drained());
        assert_eq!(pools(&receiver), snapshot);
        assert!(sender.poll(0, 1, &mut body)?);
        assert_eq!(body[0], KIND_SOURCE);
        receiver.on_datagram(1, &body)?;
        assert!(receiver.pop_packet(&mut output)?);
        assert_eq!(output, if prefix { second } else { first });
        assert!(receiver.drained());
        assert_eq!(pools(&receiver), snapshot);
    }
    Ok(())
}

#[test]
fn full_contiguous_stream_append_is_preflighted_before_any_advance_mutation() -> TestResult {
    let mut config = config();
    config.window = 2;
    config.flow_sources = 4;
    config.repair_numerator = 0;
    let bound = config.flow_sources * config.symbol_bytes() + config.max_packet + FRAME_PREFIX;
    assert_eq!(bound, 354);
    let mut sender = Sender::new(config)?;
    let mut receiver = reserved(config)?;
    let snapshot = pools(&receiver);
    for length in [128, 128, 92] {
        assert!(sender.push_packet(0, &vec![3; length])?);
    }
    let mut body = Vec::with_capacity(config.datagram_bytes);
    let mut feedback = Vec::with_capacity(FEEDBACK_HEADER + 2 * MAX_REQUESTS);
    for seed in 0..7u64 {
        assert!(sender.poll(seed * 1000, seed, &mut body)?);
        assert_eq!(body[0], KIND_SOURCE);
        receiver.on_datagram(seed, &body)?;
        assert!(receiver.feedback((seed + 1) * 1000, &mut feedback));
        sender.on_feedback((seed + 1) * 1000, &feedback)?;
    }
    assert_eq!(receiver.stream.len(), bound);
    let before = (
        receiver.base,
        receiver.floor,
        receiver.stream.iter().copied().collect::<Vec<_>>(),
    );
    assert!(sender.push_packet(8000, &[7])?);
    assert!(sender.poll(8000, 7, &mut body)?);
    assert_eq!(receiver.on_datagram(7, &body), Err(Error::Malformed));
    assert_eq!((receiver.base, receiver.floor), (before.0, before.1));
    assert_eq!(
        receiver.stream.iter().copied().collect::<Vec<_>>(),
        before.2
    );
    assert_eq!(pools(&receiver), snapshot);
    Ok(())
}

#[test]
fn reordered_sources_preflight_the_entire_new_contiguous_run_atomically() -> TestResult {
    let mut config = config();
    config.window = 2;
    config.flow_sources = 4;
    config.repair_numerator = 0;
    let mut sender = Sender::new(config)?;
    let mut receiver = reserved(config)?;
    let snapshot = pools(&receiver);
    for length in [128, 128, 36] {
        assert!(sender.push_packet(0, &vec![3; length])?);
    }
    let mut body = Vec::with_capacity(config.datagram_bytes);
    let mut feedback = Vec::with_capacity(FEEDBACK_HEADER + 2 * MAX_REQUESTS);
    for seed in 0..6u64 {
        assert!(sender.poll(seed * 1000, seed, &mut body)?);
        assert_eq!(body[0], KIND_SOURCE);
        receiver.on_datagram(seed, &body)?;
        assert!(receiver.feedback((seed + 1) * 1000, &mut feedback));
        sender.on_feedback((seed + 1) * 1000, &feedback)?;
    }
    assert_eq!(receiver.stream.len(), 298);
    assert!(sender.push_packet(7000, &[7])?);
    assert!(sender.poll(7000, 6, &mut body)?);
    assert_eq!(body.len() - SOURCE_HEADER, 3);
    let missing = body.clone();
    assert!(sender.push_packet(8000, &[9; 54])?);
    assert!(sender.poll(8000, 7, &mut body)?);
    assert_eq!(body.len() - SOURCE_HEADER, 56);
    receiver.on_datagram(7, &body)?;
    let before = (
        receiver.base,
        receiver.floor,
        receiver.stream.iter().copied().collect::<Vec<_>>(),
    );
    // The first three bytes alone fit. A per-source precheck would mutate base
    // and stream before rejecting the following 56-byte now-contiguous source.
    assert_eq!(receiver.on_datagram(6, &missing), Err(Error::Malformed));
    assert_eq!((receiver.base, receiver.floor), (before.0, before.1));
    assert_eq!(
        receiver.stream.iter().copied().collect::<Vec<_>>(),
        before.2
    );
    assert_eq!(pools(&receiver), snapshot);
    Ok(())
}

#[test]
fn reserved_source_window_uses_checked_distance_near_u64_exhaustion() -> TestResult {
    let mut config = config();
    config.repair_numerator = 0;
    let mut sender = Sender::new(config)?;
    let mut receiver = reserved(config)?;
    sender.start_at(u64::MAX - 2);
    receiver.start_at(u64::MAX - 2);
    let snapshot = pools(&receiver);
    let mut body = Vec::with_capacity(config.datagram_bytes);
    let mut output = Vec::with_capacity(config.max_packet);
    for (seed, byte) in [(0, 11), (1, 22)] {
        assert!(sender.push_packet(0, &[byte])?);
        assert!(sender.poll(0, seed, &mut body)?);
        receiver.on_datagram(seed, &body)?;
        assert!(receiver.pop_packet(&mut output)?);
        assert_eq!(output, [byte]);
    }
    assert_eq!(receiver.base, u64::MAX);
    assert!(receiver.drained());
    assert_eq!(
        receiver.on_datagram(2, &source(u32::MAX, &[0, 1, 33])),
        Err(Error::Malformed)
    );
    assert_eq!(pools(&receiver), snapshot);
    Ok(())
}
