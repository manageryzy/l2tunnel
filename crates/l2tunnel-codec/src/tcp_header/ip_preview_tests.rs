//! Actual native IP codec bytes, with a lost source before a later reset.
use super::*;

#[test]
fn complete_reset_chain_previews_fragmented_deltas_then_replays_only_ordered_context() -> Result {
    let mut limits = limits();
    limits.body.independent_short_frame_bytes = 0;
    limits.lookahead_records = 32;
    let channel = rx::ChannelId(0);
    let mut sender = tx::Sender::new_ip(
        scope(),
        tx::Config {
            body: limits.body,
            channels: limits.channels,
            first_record: limits.first_record,
        },
    )?;
    let mut frames = Vec::new();
    let mut groups = Vec::new();
    let mut anchor_group = None;
    let mut number = 0;
    for i in 0..16 {
        let frame = packet(
            false,
            &[],
            &options(10 + i, 20),
            &[i as u8; 101],
            100 + i * 101,
            i as u16,
        );
        let (_, parts) =
            sender.stage_selected(channel, &frame, body::Encoding::RefreshedHeaders)?;
        if !frames.is_empty() && parts.context_bytes > 0 && anchor_group.is_none() {
            anchor_group = Some(frames.len());
        }
        let mut units = Vec::new();
        while sender.is_pending() {
            let u = sender.pending_unit()?;
            let mut bytes = u.bytes.to_vec();
            bytes.resize(limits.body.symbol_bytes, 0);
            units.push((
                rx::SymbolIdentity {
                    scope: scope(),
                    source: rx::SourceId(number),
                    record: u.record,
                },
                bytes,
            ));
            number += 1;
            sender.commit_unit()?;
        }
        frames.push(frame);
        groups.push(units);
    }
    let anchor = anchor_group.ok_or("expected periodic reset")?;
    let hole = anchor - 1;
    let last = anchor + 2;
    assert!(
        groups[anchor].len() >= 3,
        "explicit IP context plus fragmented native body"
    );
    let tick = rx::Tick(1);
    for reserved in [false, true] {
        let mut r = if reserved {
            let plan = heap::ReceiverPlan::for_ip_limits_with_early_replay(limits)?;
            rx::Receiver::new_reserved_ip_with_early_replay(
                scope(),
                limits,
                heap::Limits {
                    capacity_bytes: plan.capacity_bytes(),
                },
            )?
        } else {
            rx::Receiver::new_ip_with_early_replay(scope(), limits)?
        };
        let usage = r.storage_usage();
        let admit = |r: &mut rx::Receiver, units: &[(rx::SymbolIdentity, Vec<u8>)]| -> Result {
            for (id, bytes) in units {
                r.admit_authenticated(*id, bytes, tick)?;
            }
            Ok(())
        };
        let prepare = |r: &mut rx::Receiver| {
            r.prepare_with_independent_packets(
                channel,
                tick,
                1,
                |_| false,
                |_, _| rx::EarlyDecision::Allow,
            )
        };
        let take = |r: &mut rx::Receiver, i: usize, early: bool| -> Result {
            for _ in 0..32 {
                if prepare(r)? == rx::Prepared::Ready {
                    break;
                }
            }
            let d = r.pending().ok_or("complete native frame")?;
            assert_eq!(d.bytes, frames[i]);
            assert_eq!(d.early, early);
            assert_eq!(prepare(r)?, rx::Prepared::Ready);
            assert_eq!(r.pending().ok_or("retry")?.bytes, frames[i]);
            r.commit_delivery(tick)?;
            Ok(())
        };
        for (i, units) in groups[..hole].iter().enumerate() {
            admit(&mut r, units)?;
            take(&mut r, i, false)?;
        }
        // A later delta and even the next full delta cannot use a partially
        // reconstructed predecessor between the reset and their record IDs.
        let split = groups[anchor].len() - 1;
        admit(&mut r, &groups[anchor][..split])?;
        admit(&mut r, &groups[anchor + 1])?;
        assert_eq!(prepare(&mut r)?, rx::Prepared::Idle);
        admit(&mut r, &groups[anchor][split..])?;
        take(&mut r, anchor, true)?;
        take(&mut r, anchor + 1, true)?;
        assert_eq!(r.status().early_tombstones, 2);
        admit(&mut r, &groups[anchor + 1])?;
        assert_eq!(prepare(&mut r)?, rx::Prepared::Idle);
        // The original gap remains recoverable. Catch up the real context,
        // including both already-written deltas; the next ordered delta must
        // then reproduce all native header bytes and both checksums.
        admit(&mut r, &groups[hole])?;
        take(&mut r, hole, false)?;
        admit(&mut r, &groups[last])?;
        take(&mut r, last, false)?;
        assert_eq!(r.status().early_tombstones, 0);
        assert_eq!(r.status().retained_records, 0);
        assert_eq!(r.status().retained_sources, 0);
        assert_eq!(r.storage_usage(), usage);
    }
    Ok(())
}

#[test]
fn committed_replay_rows_release_full_slots_preserving_conflicts_deadlines_and_rollback() -> Result
{
    let mut l = limits();
    l.body.independent_short_frame_bytes = 0;
    l.lookahead_records = 2;
    let ordinary = heap::ReceiverPlan::for_ip_limits(l)?;
    assert_eq!(
        ordinary.capacity_bytes(),
        heap::ReceiverPlan::for_limits(l)?.capacity_bytes()
    );
    assert!(
        heap::ReceiverPlan::for_ip_limits_with_early_replay(l)?.capacity_bytes()
            > ordinary.capacity_bytes()
    );
    assert_eq!(
        rx::Receiver::new_ip(scope(), l)?
            .status()
            .compacted_record_capacity,
        0
    );
    let channel = rx::ChannelId(0);
    let symbol = |serial: u8, payload: u8| {
        let mut bytes = vec![0; l.body.symbol_bytes];
        bytes[..7].copy_from_slice(&[0, 0, serial, 2, 0, 1, payload]);
        bytes
    };
    let identity = |source, record| rx::SymbolIdentity {
        scope: scope(),
        source: rx::SourceId(source),
        record: rx::RecordId(record),
    };
    for reserved in [false, true] {
        let plan = heap::ReceiverPlan::for_ip_limits_with_early_replay(l)?;
        let mut r = if reserved {
            rx::Receiver::new_reserved_ip_with_early_replay(
                scope(),
                l,
                heap::Limits {
                    capacity_bytes: plan.capacity_bytes(),
                },
            )?
        } else {
            rx::Receiver::new_ip_with_early_replay(scope(), l)?
        };
        let usage = r.storage_usage();
        let read = |r: &mut rx::Receiver, i: u8, early: bool| -> Result {
            for _ in 0..8 {
                if r.prepare_with_independent_packets(
                    channel,
                    rx::Tick(1),
                    1,
                    |_| false,
                    |_, _| rx::EarlyDecision::Allow,
                )? == rx::Prepared::Ready
                {
                    break;
                }
            }
            let d = r.pending().ok_or("complete frame")?;
            assert_eq!((d.bytes, d.early), (&[i][..], early));
            r.commit_delivery(rx::Tick(1))?;
            Ok(())
        };
        for i in [1, 2] {
            r.admit_authenticated(identity(i, i), &symbol(i as u8, i as u8), rx::Tick(1))?;
        }
        assert_eq!(
            r.admit_authenticated(identity(3, 3), &symbol(3, 3), rx::Tick(1)),
            Err(rx::Error::Capacity)
        );
        read(&mut r, 1, true)?;
        read(&mut r, 2, true)?;
        let snapshot = r.buffer_snapshot();
        assert_eq!(snapshot.lookahead.items, 0);
        assert_eq!(snapshot.lookahead.bytes, 8);
        assert_eq!(
            (
                snapshot.compacted_records,
                snapshot.compacted_record_capacity
            ),
            (2, 2)
        );
        for i in [3, 4] {
            r.admit_authenticated(identity(i, i), &symbol(i as u8, i as u8), rx::Tick(1))?;
            read(&mut r, i as u8, true)?;
        }
        assert_eq!(r.status().early_tombstones, 4);
        assert_eq!(r.status().compacted_records, 2);
        assert_eq!(
            r.admit_authenticated(identity(5, 5), &symbol(5, 5), rx::Tick(1)),
            Err(rx::Error::Capacity)
        );
        let prior = r.status();
        let old = &symbol(1, 1);
        let conflict = &symbol(2, 0x9a);
        let batch = [
            rx::AuthenticatedSymbol {
                identity: identity(6, 1),
                bytes: old,
            },
            rx::AuthenticatedSymbol {
                identity: identity(7, 2),
                bytes: conflict,
            },
        ];
        let mut out = [rx::Admission::Accepted; 2];
        assert_eq!(
            r.admit_batch_authenticated_into(&batch, rx::Tick(1), &mut out),
            Err(rx::Error::Conflict)
        );
        assert_eq!(r.status(), prior);
        assert_eq!(r.deadline(), Some(rx::Tick(1001)));
        r.admit_authenticated(identity(0, 0), &symbol(0, 0), rx::Tick(1))?;
        read(&mut r, 0, false)?;
        assert_eq!(
            r.prepare_ordered(channel, rx::Tick(1), 5)?,
            rx::Prepared::Idle
        );
        assert_eq!(r.status().retained_records, 0);
        assert_eq!(r.status().retained_sources, 0);
        assert_eq!(r.buffer_snapshot().compacted_records, 0);
        assert_eq!(r.storage_usage(), usage);
    }
    Ok(())
}
