use super::*;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn limits() -> Limits {
    Limits {
        body: aligned_body::Config {
            max_frame_bytes: 256,
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
        source_window: 8192,
        lookahead_records: 6,
        lookahead_bytes: 4096,
        lookahead_fragments: 256,
        max_fragments_per_record: 64,
        lifetime_ticks: 100,
    }
}
fn scope() -> Scope {
    Scope {
        session: [17; 16],
        epoch: Epoch(8),
        direction: Direction::InitiatorToResponder,
    }
}
fn receiver(l: Limits, reserved: bool) -> Result<Receiver> {
    if reserved {
        let plan = crate::aligned_storage::ReceiverPlan::for_limits(l)?;
        Ok(Receiver::new_reserved(
            scope(),
            l,
            crate::aligned_storage::Limits {
                capacity_bytes: plan.capacity_bytes(),
            },
        )?)
    } else {
        Ok(Receiver::new(scope(), l)?)
    }
}
fn identity(source: u64, record: u64) -> SymbolIdentity {
    SymbolIdentity {
        scope: scope(),
        source: SourceId(source),
        record: RecordId(record),
    }
}
fn raw(channel: u8, record: u64) -> Vec<u8> {
    let mut value = vec![0; 64];
    value[0] = channel;
    value[1..3].copy_from_slice(&(record as u16).to_be_bytes());
    value[3] = 2;
    value[4..6].copy_from_slice(&10_u16.to_be_bytes());
    value[6..16].fill(17);
    value
}
fn fragment(body: &[u8], offset: usize) -> Vec<u8> {
    let mut value = vec![0; 64];
    value[3] = 4;
    value[4..6].copy_from_slice(&(body.len() as u16).to_be_bytes());
    value[6..8].copy_from_slice(&(offset as u16).to_be_bytes());
    let count = (body.len() - offset).min(56);
    value[8..8 + count].copy_from_slice(&body[offset..offset + count]);
    value
}

fn scanned_buffers(r: &Receiver) -> crate::diagnostics::ReceiverBuffers {
    use crate::diagnostics::{ReceiverBuffers, Retention};
    let channels = usize::from(r.limits.channels);
    let mut result = ReceiverBuffers {
        source_proofs: Retention {
            item_capacity: r.limits.source_window,
            byte_capacity: r.limits.source_window * r.limits.body.symbol_bytes,
            ..Retention::default()
        },
        heads: Retention {
            item_capacity: channels,
            byte_capacity: channels * 65_535,
            ..Retention::default()
        },
        lookahead: Retention {
            item_capacity: r.limits.lookahead_records,
            byte_capacity: r.limits.lookahead_bytes,
            ..Retention::default()
        },
        compacted_records: r.retention.compacted,
        compacted_record_capacity: r.compacted_slots,
        head_fragments: 0,
        head_fragment_capacity: channels * r.limits.max_fragments_per_record,
        lookahead_fragments: 0,
        lookahead_fragment_capacity: r.limits.lookahead_fragments,
        pending_native_bytes: r.pending.map(|value| value.written),
        native_capacity_bytes: r.native.len(),
    };
    for proof in r.proofs.iter().flatten() {
        result.source_proofs.items += 1;
        result.source_proofs.bytes += proof.bytes.len();
    }
    for record in r.records.iter().flatten() {
        let head = r.channels[usize::from(record.channel.0)].expected == Some(record.id);
        let retention = if head {
            &mut result.heads
        } else {
            &mut result.lookahead
        };
        retention.items += 1;
        retention.bytes += record.bytes.len();
        if head {
            result.head_fragments += record.pieces.len();
        } else {
            result.lookahead_fragments += record.pieces.len();
        }
    }
    result
}

// Independent pre-cache behavior, exercised against actual live and rollback
// transitions. Full diagnostic scans are independent of the live counters.
pub(super) fn assert_matches(r: &Receiver) {
    assert_eq!(r.buffer_snapshot(), scanned_buffers(r));
    for record in r.records.iter().flatten() {
        assert_eq!(
            record.independent_short,
            record.pieces.is_empty()
                && r.limits.body.independent_short_frame_bytes != 0
                && independent_length(&record.bytes)
                    .is_some_and(|length| length <= r.limits.body.independent_short_frame_bytes)
        );
    }
    for start in 0..r.limits.channels {
        let expected = (0..r.limits.channels)
            .map(|offset| ChannelId(((start + offset) % r.limits.channels) as u8))
            .find(|ch| {
                r.records
                    .iter()
                    .flatten()
                    .any(|record| record.channel == *ch)
            });
        assert_eq!(r.next_retained_channel(ChannelId(start as u8)), expected);
    }
    let mut status = Status {
        source_floor: r.floor,
        retained_sources: r.proofs.iter().flatten().count(),
        retained_records: 0,
        native_records: 0,
        record_bytes: 0,
        fragment_slots: 0,
        early_tombstones: 0,
        compacted_records: 0,
        compacted_record_capacity: r.compacted_slots,
        pending_bytes: r.pending.map(|pending| pending.written),
        failure: r.failure,
    };
    for record in r.records.iter().flatten() {
        status.retained_records += 1;
        status.record_bytes += record.bytes.len();
        status.fragment_slots += record.pieces.len();
        status.early_tombstones += usize::from(record.early_delivered);
        status.compacted_records += usize::from(record.compacted);
        status.native_records += usize::from(
            !record.early_delivered
                && (!matches!(record.bytes.first(), Some(0 | 8))
                    || (!record.pieces.is_empty()
                        && record.pieces.first().copied().unwrap_or(0) == 0)),
        );
    }
    let deadline = if r.failure.is_some() {
        None
    } else {
        r.records
            .iter()
            .flatten()
            .map(|record| record.deadline)
            .chain(r.proofs.iter().flatten().map(|proof| proof.deadline))
            .min()
    };
    let mut ordered: Vec<_> = r
        .records
        .iter()
        .enumerate()
        .filter_map(|(slot, entry)| {
            entry
                .as_ref()
                .map(|record| (record.channel.0, record.id, slot as u16))
        })
        .collect();
    ordered.sort_unstable();
    assert_eq!(
        r.ordered_slots,
        ordered
            .into_iter()
            .map(|(_, _, slot)| slot)
            .collect::<Vec<_>>()
    );
    assert_eq!(r.status(), status);
    assert_eq!(r.deadline(), deadline);
}

#[test]
fn cached_receiver_clean_delivery_reuse_and_original_expiry_match_full_scan() -> Result {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<Receiver>();
    for reserved in [false, true] {
        let mut r = receiver(limits(), reserved)?;
        let storage = r.storage_usage();
        assert_matches(&r);
        r.admit_authenticated(identity(0, 0), &raw(0, 0), Tick(1))?;
        // Consuming the equal-deadline proof leaves the record's minimum known.
        assert!(r.deadlines.checkpoint().flatten().is_some());
        assert_eq!(r.deadline(), Some(Tick(101)));
        assert_eq!(r.status().retained_sources, 0);
        r.admit_authenticated(identity(1, 0), &raw(1, 0), Tick(2))?;
        assert_eq!(r.prepare(ChannelId(1), Tick(3), 1)?, Prepared::Ready);
        r.commit_delivery(Tick(3))?;
        assert!(r.deadlines.checkpoint().flatten().is_some());
        assert_matches(&r);
        assert_eq!(r.deadline(), Some(Tick(101)));
        assert_eq!(r.prepare(ChannelId(0), Tick(4), 1)?, Prepared::Ready);
        r.commit_delivery(Tick(4))?;
        assert!(matches!(r.deadlines.checkpoint(), Some(None)));
        for record in 1..33 {
            let now = Tick(record + 4);
            r.admit_authenticated(identity(record + 1, record), &raw(0, record), now)?;
            assert!(r.deadlines.checkpoint().flatten().is_some());
            assert_matches(&r);
            assert_eq!(r.prepare(ChannelId(0), now, 1)?, Prepared::Ready);
            r.commit_delivery(now)?;
            assert_matches(&r);
            assert!(matches!(r.deadlines.checkpoint(), Some(None)));
        }
        r.admit_authenticated(identity(34, 33), &raw(0, 33), Tick(50))?;
        assert_eq!(r.tick(Tick(49)), Err(Error::Time));
        r.tick(Tick(149))?;
        assert_eq!(r.deadline(), Some(Tick(150)));
        assert_eq!(r.tick(Tick(150)), Err(Error::Expired));
        assert_eq!(r.tick(Tick(49)), Err(Error::Expired));
        assert_matches(&r);
        assert_eq!(r.storage_usage(), storage);
    }
    Ok(())
}

#[test]
fn cached_receiver_early_tombstone_and_source_gap_keep_original_minimum() -> Result {
    for reserved in [false, true] {
        let mut l = limits();
        l.body.independent_short_frame_bytes = 32;
        let mut r = receiver(l, reserved)?;
        r.admit_authenticated(identity(2, 1), &raw(0, 1), Tick(1))?;
        assert_eq!(r.prepare(ChannelId(0), Tick(2), 1)?, Prepared::Ready);
        assert!(r.pending().ok_or("pending early frame")?.early);
        r.commit_delivery(Tick(2))?;
        assert_eq!(r.status().native_records, 0);
        assert_eq!(r.status().early_tombstones, 1);
        assert_matches(&r);
        assert_eq!(
            r.admit_authenticated(identity(2, 1), &raw(0, 1), Tick(3))?,
            Admission::Duplicate
        );
        r.admit_authenticated(identity(0, 0), &raw(0, 0), Tick(4))?;
        assert_eq!(r.prepare(ChannelId(0), Tick(4), 1)?, Prepared::Ready);
        r.commit_delivery(Tick(4))?;
        assert_eq!(r.prepare(ChannelId(0), Tick(5), 1)?, Prepared::Progress);
        assert_eq!(r.status().retained_records, 0);
        assert_eq!(r.status().retained_sources, 1);
        assert_matches(&r);
        assert_eq!(r.deadline(), Some(Tick(101)));
        assert_eq!(
            r.admit_authenticated(identity(1, 0), &raw(0, 0), Tick(100))?,
            Admission::StaleRecord
        );
        assert_matches(&r);
        assert!(matches!(r.deadlines.checkpoint(), Some(None)));
        r.tick(Tick(101))?;
    }
    Ok(())
}

#[test]
fn cached_receiver_fragment_and_nested_validation_rollback_restore_exact_state() -> Result {
    for reserved in [false, true] {
        let mut r = receiver(limits(), reserved)?;
        let mut body = vec![9; 103];
        body[0] = 2;
        body[1..3].copy_from_slice(&100_u16.to_be_bytes());
        let first = fragment(&body, 0);
        let last = fragment(&body, 56);
        r.admit_authenticated(identity(1, 0), &last, Tick(1))?;
        assert_matches(&r);
        let before = r.status();
        let cache = r.deadlines.checkpoint();
        let bad = raw(0, 9);
        let batch = [
            AuthenticatedSymbol {
                identity: identity(0, 0),
                bytes: &first,
            },
            AuthenticatedSymbol {
                identity: identity(2, 1),
                bytes: &bad,
            },
        ];
        assert_eq!(
            r.admit_batch_authenticated(&batch, Tick(2)),
            Err(Error::Malformed)
        );
        assert_eq!(r.status(), before);
        assert_eq!(r.deadlines.checkpoint(), cache);
        assert_matches(&r);
        r.admit_authenticated(identity(0, 0), &first, Tick(3))?;
        assert_matches(&r);
        assert_eq!(r.prepare(ChannelId(0), Tick(3), 1)?, Prepared::Ready);
        assert_eq!(r.pending().ok_or("fragmented frame")?.bytes, &body[3..]);
        r.commit_delivery(Tick(3))?;
        assert_matches(&r);
        let future = raw(0, 2);
        let before = r.status();
        assert_eq!(
            r.admit_validated_batch_authenticated(
                &[AuthenticatedSymbol {
                    identity: identity(2, 2),
                    bytes: &future
                }],
                Tick(4),
            ),
            Err(Error::UnresolvedContext)
        );
        assert_eq!(r.status(), before);
        assert_matches(&r);
        assert!(matches!(r.deadlines.checkpoint(), Some(None)));
    }
    Ok(())
}

#[test]
fn sparse_channels_choose_first_permitted_short_in_record_order() -> Result {
    let mut l = limits();
    l.channels = 256;
    l.lookahead_records = 1024;
    l.body.independent_short_frame_bytes = 32;
    let mut rx = Receiver::new(scope(), l)?;
    // Arrival order and physical slot reuse need not follow either ordering.
    for (source, channel, id) in [(0, 255, 5), (1, 3, 2), (2, 255, 1), (3, 3, 3), (4, 255, 3)] {
        rx.admit_authenticated(identity(source, id), &raw(channel, id), Tick(1))?;
    }
    for channel in [0, 2, 4, 254] {
        assert_eq!(rx.prepare(ChannelId(channel), Tick(2), 1)?, Prepared::Idle);
    }
    let mut visits = 0;
    assert_eq!(
        rx.prepare_with_early_filter(ChannelId(255), Tick(2), 3, |_| {
            visits += 1;
            visits == 2
        })?,
        Prepared::Ready
    );
    assert_eq!(visits, 2);
    assert_eq!(
        rx.pending().ok_or("missing early packet")?.record,
        RecordId(3)
    );
    rx.commit_delivery(Tick(2))?;
    assert_eq!(rx.prepare(ChannelId(3), Tick(2), 1)?, Prepared::Ready);
    assert_eq!(
        rx.pending().ok_or("missing unrelated packet")?.record,
        RecordId(2)
    );
    rx.commit_delivery(Tick(2))?;
    assert_matches(&rx);
    Ok(())
}

#[test]
fn compact_proof_bytes_and_final_channel_frontiers_match_scan() -> Result {
    for reserved in [false, true] {
        let mut l = limits();
        l.first_record = RecordId(u64::MAX - 1);
        l.first_source = SourceId(u64::MAX - 3);
        let mut r = receiver(l, reserved)?;
        r.enable_compact_units()?;
        let future = identity(u64::MAX - 1, u64::MAX);
        let head = identity(u64::MAX - 2, u64::MAX - 1);
        let missing = identity(u64::MAX - 3, u64::MAX - 1);
        let mut long = raw(0, future.record.0);
        long[4..6].copy_from_slice(&17_u16.to_be_bytes());
        long.truncate(23);
        let short = raw(1, head.record.0);
        let short = &short[..16];
        let close = raw(0, missing.record.0);
        let close = &close[..16];
        r.admit_authenticated(future, &long, Tick(1))?;
        r.admit_authenticated(head, short, Tick(2))?;
        assert_eq!(
            r.admit_authenticated(future, &long, Tick(2))?,
            Admission::Duplicate
        );
        let mixed = r.buffer_snapshot();
        assert_eq!(
            (mixed.source_proofs.items, mixed.source_proofs.bytes),
            (2, 39)
        );
        assert_eq!((mixed.heads.items, mixed.lookahead.items), (1, 1));
        assert_eq!(mixed, scanned_buffers(&r));
        let batch = [
            AuthenticatedSymbol {
                identity: missing,
                bytes: close,
            },
            AuthenticatedSymbol {
                identity: identity(u64::MAX, u64::MAX),
                bytes: close,
            },
        ];
        assert_eq!(
            r.admit_batch_authenticated(&batch, Tick(2)),
            Err(Error::Malformed)
        );
        assert_eq!(r.buffer_snapshot(), mixed);
        assert_matches(&r);
        r.admit_authenticated(missing, close, Tick(3))?;
        assert_eq!(r.buffer_snapshot().source_proofs.bytes, 0);
        for channel in [0, 1, 0] {
            assert_eq!(
                r.prepare_ordered(ChannelId(channel), Tick(3), 1)?,
                Prepared::Ready
            );
            assert_matches(&r);
            r.commit_delivery(Tick(3))?;
            assert_matches(&r);
        }
        assert_eq!(r.expected(ChannelId(0))?, None);
    }
    Ok(())
}

#[test]
#[ignore = "release-only timing comparison; run explicitly on one CPU"]
fn measure_buffer_snapshot_against_full_scan() -> Result {
    use std::{hint::black_box, time::Instant};
    let mut l = limits();
    l.channels = 16;
    l.source_window = 16384;
    l.record_window = 1024;
    l.lookahead_records = 1024;
    l.lookahead_bytes = 4 << 20;
    l.lookahead_fragments = 4096;
    l.body.symbol_bytes = 1251;
    l.body.max_frame_bytes = 1500;
    l.max_fragments_per_record = 4;
    let mut r = receiver(l, false)?;
    // Keep the initial source gap. Fourteen heads and 636 future records match
    // the counts of the terminating observer. Payload and fragment mix are synthetic.
    for n in 0..1198 {
        let unit = n % 650;
        let channel = (unit % 16) as u8;
        let record = unit / 16 + u64::from(channel >= 14);
        let mut bytes = raw(channel, record);
        bytes.resize(l.body.symbol_bytes, 0);
        r.admit_authenticated(identity(n + 1, record), &bytes, Tick(1))?;
    }
    let counts = r.buffer_snapshot();
    assert_eq!(counts, scanned_buffers(&r));
    assert_eq!(
        (
            counts.source_proofs.items,
            counts.heads.items,
            counts.lookahead.items
        ),
        (1198, 14, 636)
    );
    const BATCH: usize = 4096;
    for round in 0..8 {
        for indexed in [round % 2 == 0, round % 2 != 0] {
            let query: fn(&Receiver) -> crate::diagnostics::ReceiverBuffers = if indexed {
                Receiver::buffer_snapshot
            } else {
                scanned_buffers
            };
            for _ in 0..64 {
                black_box(query(black_box(&r)));
            }
            let start = Instant::now();
            for _ in 0..BATCH {
                black_box(query(black_box(&r)));
            }
            let ns = start.elapsed().as_nanos();
            println!("round={round} indexed={indexed} samples={BATCH} wall_ns={ns}");
        }
    }
    Ok(())
}
