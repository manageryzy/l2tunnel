use super::*;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn scope() -> Scope {
    Scope {
        session: [7; 16],
        epoch: l2tunnel_core::Epoch(2),
        direction: Direction::InitiatorToResponder,
    }
}
fn limits() -> Limits {
    Limits {
        body: aligned_body::Config {
            max_frame_bytes: 1600,
            symbol_bytes: 64,
            elide_payload_length: false,
            predictive: false,
            timestamp_pair_dictionary: false,
            independent_short_frame_bytes: 0,
        },
        channels: 2,
        first_record: RecordId(0),
        first_source: SourceId(0),
        record_window: 8,
        source_window: 8,
        lookahead_records: 6,
        lookahead_bytes: 4096,
        lookahead_fragments: 256,
        max_fragments_per_record: 64,
        lifetime_ticks: 100,
    }
}
fn reserved(l: Limits) -> Result<Receiver> {
    let plan = heap::ReceiverPlan::for_limits(l)?;
    Ok(Receiver::new_reserved(
        scope(),
        l,
        heap::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?)
}
fn raw(l: Limits, channel: u8, record: u64, byte: u8) -> Vec<u8> {
    let mut out = vec![0; l.body.symbol_bytes];
    out[0] = channel;
    out[1..3].copy_from_slice(&(record as u16).to_be_bytes());
    out[3] = 2;
    out[4..6].copy_from_slice(&10u16.to_be_bytes());
    out[6..16].fill(byte);
    out
}
fn unit(source: u64, record: u64, bytes: &[u8]) -> AuthenticatedSymbol<'_> {
    AuthenticatedSymbol {
        identity: SymbolIdentity {
            scope: scope(),
            source: SourceId(source),
            record: RecordId(record),
        },
        bytes,
    }
}
fn payloads(receiver: &Receiver) -> Result<Vec<(usize, usize)>> {
    let r = receiver
        .reserved
        .as_ref()
        .ok_or("reserved backing missing")?;
    let mut values = Vec::new();
    let mut record = |bytes: &Vec<u8>, pieces: &Vec<u8>| {
        values.push((bytes.as_ptr() as usize, bytes.capacity()));
        values.push((pieces.as_ptr() as usize, pieces.capacity()));
    };
    for b in &r.records {
        record(&b.bytes, &b.pieces);
    }
    for b in receiver.records.iter().flatten() {
        record(&b.bytes, &b.pieces);
    }
    for j in &r.journals {
        for b in &j.records {
            if let Undo::Value(b) = b {
                record(&b.bytes, &b.pieces);
            }
        }
    }
    for b in &r.proofs {
        values.push((b.as_ptr() as usize, b.capacity()));
    }
    for b in receiver.proofs.iter().flatten() {
        values.push((b.bytes.as_ptr() as usize, b.bytes.capacity()));
    }
    for j in &r.journals {
        for b in &j.proofs {
            if let Undo::Value(b) = b {
                values.push((b.bytes.as_ptr() as usize, b.bytes.capacity()));
            }
        }
    }
    values.sort_unstable();
    Ok(values)
}

#[test]
fn exact_receiver_plan_and_all_constructor_reservations_refuse_without_fallback() -> Result {
    let l = limits();
    let plan = heap::ReceiverPlan::for_limits(l)?;
    assert!(
        matches!(Receiver::new_reserved(scope(), l, heap::Limits {capacity_bytes: plan.capacity_bytes() - 1}),
        Err(heap::Error::Limit {required, limit}) if required == plan.capacity_bytes() && limit + 1 == required)
    );
    let owner = reserved(l)?;
    let usage = owner.storage_usage().ok_or("no actual usage")?;
    assert_eq!(usage.capacity_bytes, plan.capacity_bytes());
    assert_eq!(usage.limit_bytes, plan.capacity_bytes());
    assert!(Receiver::new(scope(), l)?.storage_usage().is_none());
    // Construction-local reservation failpoints exercise the actual constructor;
    // they are not a global/dependency allocator or deallocation observation.
    for fail_at in 1..=usage.allocations {
        let mut allocation = heap::Allocation::new(
            plan.capacity_bytes(),
            heap::Limits {
                capacity_bytes: plan.capacity_bytes(),
            },
        )?;
        allocation.fail_at = Some(fail_at);
        assert!(
            matches!(
                Receiver::new_in(scope(), l, &mut allocation),
                Err(heap::Error::Allocation)
            ),
            "reservation {fail_at}"
        );
    }
    reserved(l)?;
    Ok(())
}

#[test]
fn actual_aligned_and_packed_sender_plans_cover_each_fallible_construction_step() -> Result {
    let l = limits();
    let config = crate::aligned_sender::Config {
        body: l.body,
        channels: l.channels,
        first_record: l.first_record,
    };
    let plan = heap::SenderPlan::for_config(config)?;
    let budget = heap::Limits {
        capacity_bytes: plan.capacity_bytes(),
    };
    let owner = crate::aligned_sender::Sender::new_reserved(scope(), config, budget)?;
    let usage = owner.storage_usage().ok_or("sender usage missing")?;
    assert_eq!(usage.capacity_bytes, plan.capacity_bytes());
    assert!(matches!(
        crate::aligned_sender::Sender::new_reserved(
            scope(),
            config,
            heap::Limits {
                capacity_bytes: plan.capacity_bytes() - 1
            }
        ),
        Err(heap::Error::Limit { .. })
    ));
    for fail_at in 1..=usage.allocations {
        let mut a = heap::Allocation::new(plan.capacity_bytes(), budget)?;
        a.fail_at = Some(fail_at);
        assert!(matches!(
            crate::aligned_sender::Sender::new_in(scope(), config, &mut a),
            Err(heap::Error::Allocation)
        ));
    }
    let packed = crate::packed_sender::Config {
        sender: config,
        packing: crate::packed::Config {
            symbol_bytes: 64,
            hold_micros: 500,
        },
        max_units: 4,
        first_unit: SourceId(0),
        work_limit: 4,
    };
    let plan = heap::PackedSenderPlan::for_config(packed)?;
    let budget = heap::Limits {
        capacity_bytes: plan.capacity_bytes(),
    };
    let owner = crate::packed_sender::Sender::new_reserved(scope(), packed, budget)?;
    let usage = owner.storage_usage().ok_or("packed usage missing")?;
    assert_eq!(usage.capacity_bytes, plan.capacity_bytes());
    assert!(matches!(
        crate::packed_sender::Sender::new_reserved(
            scope(),
            packed,
            heap::Limits {
                capacity_bytes: plan.capacity_bytes() - 1
            }
        ),
        Err(heap::Error::Limit { .. })
    ));
    for fail_at in 1..=usage.allocations {
        let mut a = heap::Allocation::new(plan.capacity_bytes(), budget)?;
        a.fail_at = Some(fail_at);
        assert!(matches!(
            crate::packed_sender::Sender::new_in(scope(), packed, &mut a),
            Err(heap::Error::Allocation)
        ));
    }
    crate::packed_sender::Sender::new_reserved(scope(), packed, budget)?;
    Ok(())
}

#[test]
fn repeated_full_record_and_source_windows_reuse_every_actual_payload_version() -> Result {
    let mut l = limits();
    l.first_record = RecordId(65_534);
    let mut receiver = reserved(l)?;
    let initial = payloads(&receiver)?;
    let usage = receiver.storage_usage();
    assert_eq!(
        initial.len(),
        3 * (usize::from(l.channels) + l.lookahead_records) * 2 + 3 * l.source_window
    );
    for cycle in 0..130u64 {
        let now = Tick(cycle + 1);
        let base = l.first_record.0 + cycle * 4;
        // Hold source zero until every other slot in the actual eight-source
        // window is retained, then fill the last record/head and close the hole.
        for i in (1..8u64).chain([0]) {
            let bytes = raw(l, (i % 2) as u8, base + i / 2, i as u8);
            let u = unit(cycle * 8 + i, base + i / 2, &bytes);
            receiver.admit_authenticated(u.identity, u.bytes, now)?;
            if i == 7 {
                assert_eq!(receiver.status().retained_sources, 7);
            }
        }
        assert_eq!(receiver.status().retained_records, 8);
        assert_eq!(receiver.status().retained_sources, 0);
        for channel in 0..2u8 {
            for i in 0..4u64 {
                assert_eq!(
                    receiver.prepare(ChannelId(channel), now, 1)?,
                    Prepared::Ready
                );
                let pending = receiver.pending().ok_or("native output missing")?;
                assert_eq!(pending.record, RecordId(base + i));
                assert_eq!(pending.bytes, [channel + (2 * i) as u8; 10]);
                let before = pending.bytes.to_vec();
                assert_eq!(receiver.pending().ok_or("lost pending")?.bytes, before);
                receiver.commit_delivery(now)?;
            }
        }
        assert_eq!(receiver.status().retained_records, 0);
        assert_eq!(payloads(&receiver)?, initial);
        assert_eq!(receiver.storage_usage(), usage);
    }
    Ok(())
}

#[test]
fn late_batch_failure_restores_source_hole_pending_bytes_time_and_all_buffers() -> Result {
    let l = limits();
    let mut receiver = reserved(l)?;
    let (a, b, c) = (raw(l, 0, 0, 1), raw(l, 1, 0, 2), raw(l, 0, 1, 3));
    let old = unit(1, 0, &b);
    receiver.admit_authenticated(old.identity, old.bytes, Tick(1))?;
    assert_eq!(receiver.prepare(ChannelId(1), Tick(2), 1)?, Prepared::Ready);
    let status = receiver.status();
    let pointers = payloads(&receiver)?;
    let mut outcomes = [Admission::Duplicate; 2];
    assert_eq!(
        receiver.admit_batch_authenticated_into(
            &[unit(0, 0, &a), unit(2, 7, &c)],
            Tick(9),
            &mut outcomes
        ),
        Err(Error::Malformed)
    );
    assert_eq!(outcomes, [Admission::Duplicate; 2]);
    assert_eq!(receiver.status(), status);
    assert_eq!(receiver.pending().ok_or("pending lost")?.bytes, [2; 10]);
    assert_eq!(payloads(&receiver)?, pointers);
    assert_eq!(
        receiver.admit_authenticated(old.identity, old.bytes, Tick(3))?,
        Admission::Duplicate
    );
    assert_eq!(
        receiver.admit_batch_authenticated_into(
            &[unit(0, 0, &a), unit(2, 1, &c)],
            Tick(3),
            &mut outcomes
        )?,
        2
    );
    assert_eq!(outcomes, [Admission::Accepted; 2]);
    assert_eq!(receiver.pending().ok_or("pending lost")?.bytes, [2; 10]);
    receiver.commit_delivery(Tick(3))?;
    assert_eq!(receiver.prepare(ChannelId(0), Tick(3), 1)?, Prepared::Ready);
    receiver.commit_delivery(Tick(3))?;
    assert_eq!(receiver.prepare(ChannelId(0), Tick(3), 1)?, Prepared::Ready);
    receiver.commit_delivery(Tick(3))?;
    assert_eq!(payloads(&receiver)?, pointers);
    Ok(())
}

fn frame() -> Result<Vec<u8>> {
    let text = include_str!("../../tests/data/aligned-sender-goldens.tsv")
        .lines()
        .find(|l| !l.starts_with('#'))
        .and_then(|l| l.split('\t').nth(6))
        .ok_or("Python frame missing")?;
    text.as_bytes()
        .chunks_exact(2)
        .map(|p| Ok(u8::from_str_radix(std::str::from_utf8(p)?, 16)?))
        .collect()
}
#[test]
fn semantic_journal_restores_real_codec_context_and_native_pending_before_retry() -> Result {
    let mut l = limits();
    l.body.symbol_bytes = 256;
    let config = crate::aligned_sender::Config {
        body: l.body,
        channels: l.channels,
        first_record: l.first_record,
    };
    let plan = heap::SenderPlan::for_config(config)?;
    let mut sender = crate::aligned_sender::Sender::new_reserved(
        scope(),
        config,
        heap::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?;
    let native = frame()?;
    sender.stage(ChannelId(0), &native)?;
    let mut units = Vec::new();
    while sender.is_pending() {
        let pending = sender.pending_unit()?;
        let mut bytes = pending.bytes.to_vec();
        bytes.resize(256, 0);
        units.push((pending.record.0, bytes));
        sender.commit_unit()?;
    }
    assert_eq!(units.len(), 2);
    let mut receiver = reserved(l)?;
    let earlier = raw(l, 1, 0, 9);
    let u = unit(0, 0, &earlier);
    receiver.admit_authenticated(u.identity, u.bytes, Tick(1))?;
    receiver.prepare(ChannelId(1), Tick(1), 1)?;
    let saved = receiver.status();
    let pointers = payloads(&receiver)?;
    let mut bad = vec![0; 256];
    bad[1..3].copy_from_slice(&(units[1].0 as u16).to_be_bytes());
    bad[3] = 6;
    bad[4..10].fill(255);
    let mut outcomes = [Admission::Duplicate; 2];
    assert!(matches!(
        receiver.admit_validated_batch_authenticated_into(
            &[unit(1, units[0].0, &units[0].1), unit(2, units[1].0, &bad)],
            Tick(9),
            &mut outcomes
        ),
        Err(Error::Body(_))
    ));
    assert_eq!(receiver.status(), saved);
    assert_eq!(outcomes, [Admission::Duplicate; 2]);
    assert_eq!(receiver.pending().ok_or("pending lost")?.bytes, [9; 10]);
    assert!(!receiver.channels[0].decoder.has_context());
    assert_eq!(payloads(&receiver)?, pointers);
    receiver.admit_validated_batch_authenticated_into(
        &[
            unit(1, units[0].0, &units[0].1),
            unit(2, units[1].0, &units[1].1),
        ],
        Tick(2),
        &mut outcomes,
    )?;
    assert_eq!(outcomes, [Admission::Accepted; 2]);
    assert!(!receiver.channels[0].decoder.has_context());
    assert_eq!(receiver.pending().ok_or("pending lost")?.bytes, [9; 10]);
    receiver.commit_delivery(Tick(2))?;
    assert_eq!(receiver.prepare(ChannelId(0), Tick(2), 8)?, Prepared::Ready);
    assert_eq!(
        receiver.pending().ok_or("decoded native missing")?.bytes,
        native
    );
    receiver.commit_delivery(Tick(2))?;
    assert_eq!(payloads(&receiver)?, pointers);
    Ok(())
}

fn fragment(record: u64, total: usize, offset: usize, bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![0; 64];
    out[1..3].copy_from_slice(&(record as u16).to_be_bytes());
    out[3] = 4;
    out[4..6].copy_from_slice(&(total as u16).to_be_bytes());
    out[6..8].copy_from_slice(&(offset as u16).to_be_bytes());
    let n = 56.min(total - offset);
    out[8..8 + n].copy_from_slice(&bytes[offset..offset + n]);
    out
}
#[test]
fn final_fragment_refusal_recycles_touched_versions_and_valid_retry_delivers_exact_bytes() -> Result
{
    let l = limits();
    let mut receiver = reserved(l)?;
    let pointers = payloads(&receiver)?;
    assert_eq!(receiver.pending_deadline(), None);
    let mut body = vec![4; 103];
    body[0] = 2;
    body[1..3].copy_from_slice(&100u16.to_be_bytes());
    let first = fragment(0, 103, 0, &body);
    let last = fragment(0, 103, 56, &body);
    body[1..3].copy_from_slice(&99u16.to_be_bytes());
    let bad = fragment(0, 103, 0, &body);
    let saved = receiver.status();
    let mut outcomes = [Admission::Duplicate; 2];
    assert_eq!(
        receiver.admit_batch_authenticated_into(
            &[unit(0, 0, &bad), unit(1, 0, &last)],
            Tick(1),
            &mut outcomes
        ),
        Err(Error::Malformed)
    );
    assert_eq!(receiver.status(), saved);
    assert_eq!(payloads(&receiver)?, pointers);
    receiver.admit_batch_authenticated_into(
        &[unit(0, 0, &first), unit(1, 0, &last)],
        Tick(1),
        &mut outcomes,
    )?;
    assert_eq!(receiver.pending_deadline(), None);
    assert_eq!(receiver.prepare(ChannelId(0), Tick(2), 1)?, Prepared::Ready);
    assert_eq!(receiver.pending_deadline(), Some(Tick(101)));
    receiver.tick(Tick(3))?;
    assert_eq!(receiver.pending_deadline(), Some(Tick(101)));
    assert_eq!(
        receiver.pending().ok_or("assembled native missing")?.bytes,
        [4; 100]
    );
    receiver.commit_delivery(Tick(3))?;
    assert_eq!(receiver.pending_deadline(), None);
    assert_eq!(payloads(&receiver)?, pointers);
    Ok(())
}

#[test]
fn small_batch_never_copies_untouched_partial_history_or_renews_its_deadline() -> Result {
    let l = limits();
    let mut receiver = reserved(l)?;
    let mut body = vec![1; 103];
    body[0] = 2;
    body[1..3].copy_from_slice(&100u16.to_be_bytes());
    let mut partial = fragment(2, 103, 0, &body);
    partial[0] = 1;
    let u = unit(1, 2, &partial);
    receiver.admit_authenticated(u.identity, u.bytes, Tick(1))?;
    let slot = receiver
        .find(ChannelId(1), RecordId(2))
        .ok_or("partial missing")?;
    let old = receiver.records[slot].as_ref().ok_or("partial missing")?;
    let identity = (
        old.bytes.as_ptr(),
        old.pieces.as_ptr(),
        old.deadline,
        old.count,
    );
    let bytes = raw(l, 0, 0, 9);
    receiver.admit_validated_batch_authenticated_into(
        &[unit(0, 0, &bytes)],
        Tick(2),
        &mut [Admission::Duplicate],
    )?;
    let old = receiver.records[slot].as_ref().ok_or("partial lost")?;
    assert_eq!(
        (
            old.bytes.as_ptr(),
            old.pieces.as_ptr(),
            old.deadline,
            old.count
        ),
        identity
    );
    assert_eq!(receiver.deadline(), Some(Tick(101)));
    Ok(())
}

#[test]
fn original_receiver_maxima_are_not_pruned_to_fit_reserved_capacity() -> Result {
    let mut l = limits();
    l.channels = 256;
    l.body.max_frame_bytes = 65_535;
    l.body.symbol_bytes = 9;
    l.record_window = 32_767;
    l.source_window = 65_536;
    l.lookahead_records = 4096;
    l.lookahead_bytes = 128 * 1024 * 1024;
    l.lookahead_fragments = 1_048_576;
    l.max_fragments_per_record = 65_535;
    l.memory_bound_bytes()?;
    let plan = heap::ReceiverPlan::for_limits(l)?;
    assert_eq!(plan.limits(), l);
    assert!(
        matches!(Receiver::new_reserved(scope(), l, heap::Limits {capacity_bytes: 0}), Err(heap::Error::Limit {required, limit: 0}) if required == plan.capacity_bytes())
    );
    Ok(())
}

#[test]
fn empty_reserved_payloads_initialize_dirty_recycled_storage_before_fragment_reads() -> Result {
    let l = limits();
    let mut receiver = reserved(l)?;
    let plan = heap::ReceiverPlan::for_limits(l)?;
    let usage = receiver.storage_usage().ok_or("reserved usage missing")?;
    assert_eq!(usage.capacity_bytes, plan.capacity_bytes());
    let pointers = payloads(&receiver)?;
    for cycle in 0..2u64 {
        // Safe initialized poison models arbitrary previous contents, including
        // buffers returned by the preceding actual delivery. No allocator or
        // spare-capacity reads are needed to prove initialization on acquire.
        let pool = receiver.reserved.as_mut().ok_or("reserved pool missing")?;
        for record in &mut pool.records {
            assert!(record.bytes.is_empty());
            assert!(record.pieces.is_empty());
            assert_eq!(record.bytes.capacity(), 65_535);
            assert_eq!(record.pieces.capacity(), l.max_fragments_per_record);
            record.bytes.resize(record.bytes.capacity(), 0xa5);
            record.bytes.clear();
            record.pieces.resize(record.pieces.capacity(), 0xa5);
            record.pieces.clear();
        }
        for proof in &mut pool.proofs {
            assert!(proof.is_empty());
            assert_eq!(proof.capacity(), l.body.symbol_bytes);
            proof.resize(proof.capacity(), 0xa5);
            proof.clear();
        }
        let mut body = vec![7 + cycle as u8; 103];
        body[0] = 2;
        body[1..3].copy_from_slice(&100u16.to_be_bytes());
        body[95..].fill(0);
        let first = fragment(cycle, body.len(), 0, &body);
        let last = fragment(cycle, body.len(), 56, &body);
        let now = Tick(cycle * 3 + 1);
        let last_identity = unit(cycle * 2 + 1, cycle, &last).identity;
        assert_eq!(
            receiver.admit_authenticated(last_identity, &last, now)?,
            Admission::Accepted
        );
        let slot = receiver
            .find(ChannelId(0), RecordId(cycle))
            .ok_or("partial")?;
        let partial = receiver.records[slot].as_ref().ok_or("partial record")?;
        assert_eq!(&partial.bytes[..56], &[0; 56]);
        assert_eq!(&partial.bytes[56..], &body[56..]);
        assert_eq!(partial.pieces, [0, 1]);
        let proof_slot = ((cycle * 2 + 1) % l.source_window as u64) as usize;
        assert_eq!(
            receiver.proofs[proof_slot].as_ref().ok_or("proof")?.bytes,
            last
        );
        assert_eq!(receiver.prepare(ChannelId(0), now, 1)?, Prepared::Idle);
        let saved = receiver.status();
        let mut malformed = first.clone();
        malformed[9..11].copy_from_slice(&99u16.to_be_bytes());
        assert_eq!(
            receiver.admit_batch_authenticated_into(
                &[unit(cycle * 2, cycle, &malformed)],
                Tick(now.0 + 1),
                &mut [Admission::Duplicate],
            ),
            Err(Error::Malformed)
        );
        assert_eq!(receiver.status(), saved);
        assert_eq!(payloads(&receiver)?, pointers);
        receiver.admit_authenticated(
            unit(cycle * 2, cycle, &first).identity,
            &first,
            Tick(now.0 + 1),
        )?;
        assert_eq!(
            receiver.prepare(ChannelId(0), Tick(now.0 + 1), 1)?,
            Prepared::Ready
        );
        assert_eq!(receiver.pending().ok_or("native")?.bytes, &body[3..]);
        receiver.commit_delivery(Tick(now.0 + 2))?;
        assert_eq!(receiver.status().retained_records, 0);
        assert_eq!(receiver.status().retained_sources, 0);
        assert_eq!(receiver.storage_usage(), Some(usage));
        assert_eq!(payloads(&receiver)?, pointers);
    }
    Ok(())
}
