use super::*;
use crate::rolling::scheduler::{self, Output, OutputId};

const INPUT: [&[u8]; 8] = [
    &[0, 1, 0, 0],
    &[2, 0],
    &[0, 3, 0, 0],
    &[4, 0],
    &[0, 5, 0, 0],
    &[6, 0],
    &[0, 7, 0, 0],
    &[8, 0],
];
const FIRST: [u8; 8] = [6, 8, 0, 0x41, 0x7c, 0x89, 0, 0];
const SIXTEENTH: [u8; 9] = [6, 0x80, 1, 0, 0x14, 0xd3, 0x24, 0, 0];
fn setup() -> (scheduler::Policy, Scope, WorkBudget) {
    let config = Config {
        window: 256,
        local_window: 128,
        global_every: 16,
        max_payload: 16,
        max_rows: 16,
        repair_history: 16,
        handoff_sources: 256,
        job_ticks: 500_000,
        debt_ticks: 1_000_000,
        handoff_ticks: 500_000,
        memory_bytes: 32 << 20,
    };
    (
        scheduler::Policy {
            recovery: config,
            repair_numerator: 0,
            repair_denominator: 200,
            tail_ticks: 1000,
            feedback_ticks: 1000,
            feedback_packets: 64,
            memory_bytes: 32 << 20,
            source_wire: wire::SourceWire::TargetedNear8,
        },
        Scope {
            session: [8; 16],
            stream: 1,
            epoch: 2,
            direction: 0,
        },
        WorkBudget {
            field: 65536,
            metadata: 65536,
            copies: 65536,
        },
    )
}
fn warm(s: &mut scheduler::Sender) -> Result<(), Error> {
    let mut total = 1_000_000;
    for i in 0..4 {
        s.observe_near8_capacity(Tick(i * 100_000), total, 0, 0)?;
        total += 60_000;
        s.observe_near8_capacity(Tick(i * 100_000 + 90_000), total, 0, 0)?;
        assert!(!s.near8_status().ok_or(Error::Identity)?.spare);
    }
    s.observe_near8_capacity(Tick(400_000), total, 0, 0)?;
    assert!(s.near8_status().ok_or(Error::Identity)?.spare);
    Ok(())
}
#[test]
fn physical_credit_partial_work_and_two_python_golden_rows() -> Result<(), Error> {
    let (p, scope, full) = setup();
    let mut s = scheduler::Sender::new(p, scope, Tick(0))?;
    s.configure_near8(1500, 49, 1_000_000)?;
    warm(&mut s)?;
    let now = Tick(400_000);
    for i in 0..128 {
        let body = INPUT[i % 8];
        let copies = if i == 3 { 3 } else { 1 };
        let id = s.admit_source_with_copies(body, now, copies)?;
        assert_eq!(s.ordinary_backlog_bytes(false), body.len());
        assert_eq!(s.ordinary_backlog_bytes(true), 0);
        for ordinal in 1..=copies {
            let copy = s.pending_source_copy().ok_or(Error::Busy)?;
            assert_eq!((copy.source(), copy.ordinal()), (id, ordinal));
            let credit = s.near8_status().ok_or(Error::Busy)?.credit_eighths;
            s.confirm_source_copy_charged(now, now, copy, 70)?;
            let earned = if ordinal == 1 { 70 } else { 0 };
            assert_eq!(
                s.near8_status().ok_or(Error::Busy)?.credit_eighths,
                (credit + earned).min(12_000)
            );
            assert_eq!(s.ordinary_backlog_bytes(false), 0);
        }
        if i % 8 != 7 {
            continue;
        }
        assert!(s.status().near8_work_pending);
        assert_eq!(s.step(now, WorkBudget::default())?, WorkUsed::default());
        assert!(s.pending_output().is_none());
        let tiny = WorkBudget {
            field: 1,
            copies: 1,
            metadata: 2,
        };
        let mut gf = 0;
        for _ in 0..200 {
            let used = s.step(now, tiny)?;
            assert!(used.field <= 1 && used.copies <= 1 && used.metadata <= 2);
            gf += used.field;
            if s.pending_output().is_some() {
                break;
            }
        }
        let seed = Id((i as u32 + 1) / 8).support()?.seed;
        let expected: usize = (i - 7..=i)
            .filter(|id| crate::field::compact_coefficient(seed, *id as u32) != 0)
            .map(|id| 2 + INPUT[id % 8].len())
            .sum();
        assert_eq!(gf, expected);
        let Some(Output::Near8(row)) = s.pending_output() else {
            return Err(Error::Busy);
        };
        let mut encoded = [0; 32];
        let len = wire::compact::encode_data(Output::Near8(row), &mut encoded)?;
        assert_eq!(wire::compact::data_len(Output::Near8(row))?, len);
        if i == 7 {
            assert_eq!(&encoded[..len], FIRST);
        }
        if i == 127 {
            assert_eq!(&encoded[..len], SIXTEENTH);
        }
        let parsed = inspect(p.recovery, scope, &encoded[..len])?;
        assert_eq!(parsed.id, Id((i as u32 + 1) / 8));
        assert!(wire::compact::inspect(p.recovery, scope, &encoded[..len]).is_err());
        let token = OutputId::Near8(parsed.id);
        assert_eq!(
            s.confirm_output_charged(token, now, 48 + len),
            Err(Error::Identity)
        );
        assert!(matches!(s.pending_output(), Some(Output::Near8(_))));
        let count = s.near8_status().ok_or(Error::Busy)?.sent_rows;
        s.step(now, full)?;
        s.confirm_output_charged(token, now, 49 + len)?;
        assert_eq!(s.near8_status().ok_or(Error::Busy)?.sent_rows, count + 1);
        assert!(s.pending_output().is_none());
    }
    Ok(())
}
#[test]
fn receiver_combines_regular_and_short_same_numeric_id_and_keeps_each_history() -> Result<(), Error>
{
    let (p, scope, w) = setup();
    let mut r = scheduler::Receiver::new(p, scope, Tick(0))?;
    let now = Tick(0);
    for (i, bytes) in INPUT.iter().enumerate() {
        if [2, 4].contains(&i) {
            continue;
        }
        r.receive_view_until(
            wire::View::Source {
                scope,
                id: SourceId(i as u32),
                original: bytes,
            },
            now,
            now,
            Tick(900),
        )?;
        r.step(now, w)?;
    }
    let row = inspect(p.recovery, scope, &FIRST)?;
    r.receive_near8_until(row, now, now, Tick(800))?;
    r.step(now, w)?;
    assert_eq!(
        r.receive_near8_until(row, now, now, Tick(800))?,
        Begin::Duplicate
    );
    let id = RepairId(1);
    let support = p.recovery.support(8, id, false)?;
    let mut body = [0u8; 6];
    for (i, src) in INPUT.iter().enumerate() {
        let factor = crate::field::compact_coefficient(support.seed, i as u32);
        for (dst, b) in body
            .iter_mut()
            .zip((src.len() as u16).to_be_bytes().iter().chain(src.iter()))
        {
            *dst ^= crate::field::multiply(factor, *b);
        }
    }
    let regular = Repair {
        scope,
        id,
        support,
        bytes: &body,
    };
    assert_eq!(
        r.receive_view_until(wire::View::Repair(regular), now, now, Tick(900))?,
        Begin::Staged
    );
    r.step(now, w)?;
    for (i, expected) in INPUT.iter().enumerate() {
        let (id, actual) = r.pending_source().ok_or(Error::Busy)?;
        assert_eq!((id.0, actual), (i as u32, *expected));
        r.confirm_handoff(id, now)?;
    }
    assert_eq!(r.status().decoder.decoded_prefix, 8);
    assert_eq!(
        r.receive_near8_until(row, now, now, Tick(800))?,
        Begin::Duplicate
    );
    assert_eq!(
        r.receive_view_until(wire::View::Repair(regular), now, now, Tick(900))?,
        Begin::Duplicate
    );
    assert_eq!(
        r.receive_near8_until(
            Row {
                bytes: &row.bytes[..5],
                ..row
            },
            now,
            now,
            Tick(800)
        ),
        Err(Error::Conflict)
    );
    Ok(())
}
#[test]
fn committed_profile_gate_parser_and_epoch_storage_are_bounded()
-> Result<(), Box<dyn std::error::Error>> {
    let (p, scope, _) = setup();
    let near = storage::Plan::for_receiver(p)?;
    let old = scheduler::Policy {
        source_wire: wire::SourceWire::TargetedExact,
        ..p
    };
    let base = storage::Plan::for_receiver(old)?;
    assert!(near.capacity_bytes() > base.capacity_bytes());
    let low = storage::Limits {
        capacity_bytes: near.capacity_bytes() - 1,
    };
    assert!(scheduler::Receiver::new_reserved(p, scope, Tick(0), low).is_err());
    let exact = storage::Limits {
        capacity_bytes: near.capacity_bytes(),
    };
    let _owner = scheduler::Receiver::new_reserved(p, scope, Tick(0), exact)?;
    let mut orig = scheduler::Receiver::new(old, scope, Tick(0))?;
    assert_eq!(
        orig.receive_near8_until(
            inspect(p.recovery, scope, &FIRST)?,
            Tick(0),
            Tick(0),
            Tick(10)
        ),
        Err(Error::Configuration)
    );
    assert!(
        scheduler::Receiver::new(
            p,
            Scope {
                direction: 1,
                ..scope
            },
            Tick(0)
        )
        .is_err()
    );
    for invalid in [
        &[6, 0, 1, 2, 3][..],
        &[6, 1, 1, 2, 3],
        &[6, 0x88, 0, 1, 2, 3],
        &[6, 8, 1, 2],
        &[6, 0x80, 0x80, 0x80, 0x80, 0x10, 1, 2, 3],
    ] {
        assert!(inspect(p.recovery, scope, invalid).is_err());
    }
    let mut s = scheduler::Sender::new(p, scope, Tick(0))?;
    s.configure_near8(1500, 49, 1_000_000)?;
    warm(&mut s)?;
    s.observe_near8_capacity(Tick(450_000), 1_340_000, 0, 0)?;
    s.observe_near8_capacity(Tick(500_000), 1_340_000, 0, 0)?;
    assert!(!s.near8_status().ok_or(Error::Busy)?.spare);
    assert_eq!(
        s.observe_near8_capacity(Tick(500_001), 0, 0, 0),
        Err(Error::Identity)
    );
    Ok(())
}

#[test]
fn partial_optional_work_yields_to_fresh_named_and_oldest_with_original_budget() -> Result<(), Error>
{
    let (p, scope, full) = setup();
    let mut s = scheduler::Sender::new(p, scope, Tick(0))?;
    assert_eq!(s.admit_source(INPUT[0], Tick(0)), Err(Error::Configuration));
    s.configure_near8(1500, 49, 1_000_000)?;
    warm(&mut s)?;
    let now = Tick(400_000);
    for bytes in INPUT {
        s.admit_source(bytes, now)?;
        s.confirm_source_copy_charged(now, now, s.pending_source_copy().ok_or(Error::Busy)?, 70)?;
    }
    let small = WorkBudget {
        field: 1,
        copies: 1,
        metadata: 2,
    };
    s.step(now, small)?;
    assert!(s.status().near8_work_pending && s.pending_output().is_none());
    s.admit_source(&[99], now)?;
    assert_eq!(
        s.pending_output().ok_or(Error::Busy)?.id(),
        OutputId::Source(SourceId(8))
    );
    s.confirm_source_copy_charged(now, now, s.pending_source_copy().ok_or(Error::Busy)?, 70)?;
    s.receive_request(
        scheduler::GapRequest {
            scope,
            id: scheduler::FeedbackId(1),
            prefix: 0,
            start: 0,
            mask: 1,
        },
        now,
    )?;
    s.step(now, full)?;
    assert!(s.pending_requested_retry());
    s.confirm_retry_charged(s.pending_retry_token().ok_or(Error::Busy)?, now, now, 70)?;
    s.observe_near8_capacity(Tick(450_000), 1_300_000, 0, 0)?;
    s.observe_near8_capacity(Tick(500_000), 1_300_000, 0, 0)?;
    let due = s.status().tail_due.ok_or(Error::Busy)?;
    s.step(due, full)?;
    assert!(!s.pending_requested_retry());
    let Some(Output::Source { id, original, .. }) = s.pending_output() else {
        return Err(Error::Busy);
    };
    assert_eq!((id, original), (SourceId(0), INPUT[0]));
    s.confirm_retry_charged(s.pending_retry_token().ok_or(Error::Busy)?, due, due, 70)?;
    s.observe_near8_capacity(due, 1_300_140, 12_001, 0)?;
    s.step(due, full)?;
    assert!(s.pending_output().is_none() && !s.status().near8_work_pending);
    let status = s.near8_status().ok_or(Error::Busy)?;
    assert_eq!(
        (status.credit_eighths, status.sent_rows, status.abandoned),
        (9 * 70, 0, 1)
    );
    Ok(())
}

#[test]
fn initial_partial_bucket_missing_sample_and_hysteresis_do_not_invent_spare() -> Result<(), Error> {
    let (p, scope, _) = setup();
    let mut s = scheduler::Sender::new(p, scope, Tick(0))?;
    s.configure_near8(1500, 49, 1_000_000)?;
    let mut total = u64::from(u32::MAX);
    s.observe_near8_capacity(Tick(61_000), total, 0, 0)?;
    for i in 0..5 {
        total += 75_000;
        s.observe_near8_capacity(Tick(i * 100_000 + 96_000), total, 0, 0)?;
        s.observe_near8_capacity(Tick((i + 1) * 100_000), total, 0, 0)?;
        assert_eq!(s.near8_status().ok_or(Error::Busy)?.spare, i == 4);
    }
    total += 80_000;
    s.observe_near8_capacity(Tick(550_000), total, 0, 0)?;
    s.observe_near8_capacity(Tick(600_000), total, 0, 0)?;
    assert!(s.near8_status().ok_or(Error::Busy)?.spare);
    s.observe_near8_capacity(Tick(900_000), total, 0, 0)?;
    assert!(!s.near8_status().ok_or(Error::Busy)?.spare);
    Ok(())
}

#[test]
fn additive_profile_preserves_every_earned_regular_byte_through_a_full_window() -> Result<(), Error>
{
    fn rows(format: wire::SourceWire) -> Result<(Vec<u8>, u32, u64), Error> {
        let (mut p, scope, w) = setup();
        p.source_wire = format;
        p.repair_numerator = 41;
        let mut s = scheduler::Sender::new(p, scope, Tick(0))?;
        s.enable_earned_regular()?;
        if format.is_near8() {
            s.configure_near8(1500, 49, 1_000_000)?;
            warm(&mut s)?;
        }
        let now = Tick(400_000);
        let mut regular = Vec::new();
        let mut count = 0u32;
        for i in 0..320u32 {
            let body = INPUT[i as usize % 8];
            s.admit_source(body, now)?;
            let copy = s.pending_source_copy().ok_or(Error::Busy)?;
            let mut priced = 0;
            s.confirm_source_copy_priced(now, now, copy, 70, |id, support| {
                priced += 1;
                assert_eq!(support.end, i + 1);
                assert_eq!(id.0, u64::from(count + 1));
                // Fixed previously earned named-retry price decision on this source.
                Ok(i % 11 == 0)
            })?;
            assert_eq!(priced, (i + 1) * 41 / 200 - i * 41 / 200);
            while s.status().regular_due != 0
                || s.status().encoder.pending_repair
                || s.status().near8_work_pending
            {
                s.step(now, w)?;
                match s.pending_output() {
                    Some(Output::Repair(r)) => {
                        count += 1;
                        assert_eq!(r.id.0, u64::from(count));
                        let mut encoded = [0; 64];
                        let n = wire::compact::encode_data(Output::Repair(r), &mut encoded)?;
                        regular.extend_from_slice(&(n as u32).to_be_bytes());
                        regular.extend_from_slice(&encoded[..n]);
                        s.confirm_output_charged(OutputId::Repair(r.id), now, n + 49)?;
                    }
                    Some(Output::Near8(row)) => {
                        let n = wire_len(row)?;
                        s.confirm_output_charged(OutputId::Near8(row.id), now, n + 49)?;
                    }
                    Some(Output::Source { .. }) => return Err(Error::Identity),
                    None => {}
                }
            }
            if i >= 64 && i.is_multiple_of(16) {
                let prefix = i - 31;
                s.receive_feedback(
                    scheduler::Feedback {
                        scope,
                        id: scheduler::FeedbackId(u64::from(i)),
                        prefix,
                        observed_end: prefix,
                        deficit: 0,
                    },
                    now,
                )?;
            }
        }
        Ok((
            regular,
            s.status().repair_credit,
            s.near8_status().map_or(0, |n| n.sent_rows),
        ))
    }
    let (base, base_credit, old_near) = rows(wire::SourceWire::TargetedExact)?;
    let (candidate, candidate_credit, new_near) = rows(wire::SourceWire::TargetedNear8)?;
    assert_eq!(base, candidate);
    assert_eq!((base_credit, old_near), (candidate_credit, 0));
    assert!(new_near >= 32);
    Ok(())
}

#[test]
fn earliest_source_cap_cancels_partial_rows_and_expires_retained_output() -> Result<(), Error> {
    let (mut p, scope, full) = setup();
    p.recovery.job_ticks = 24;
    let now = Tick(400_000);
    let earliest = Tick(400_016);
    for exposed in [false, true] {
        let mut sender = scheduler::Sender::new(p, scope, Tick(0))?;
        sender.configure_near8(1500, 49, 1_000_000)?;
        warm(&mut sender)?;
        for (i, source) in INPUT.iter().enumerate() {
            let created = if i == 2 { Tick(now.0 - 8) } else { now };
            sender.admit_source_with_copies_at(source, created, now, 1)?;
            let copy = sender.pending_source_copy().ok_or(Error::Busy)?;
            sender.confirm_source_copy_charged(now, now, copy, 70)?;
        }
        if exposed {
            sender.step(Tick(earliest.0 - 1), full)?;
            let Some(Output::Near8(row)) = sender.pending_output() else {
                return Err(Error::Busy);
            };
            let token = OutputId::Near8(row.id);
            let price = wire_len(row)? + 49;
            assert_eq!(sender.deadline(), Some(earliest));
            assert_eq!(
                sender.confirm_output_charged(token, earliest, price),
                Err(Error::Expired)
            );
            assert_eq!(sender.near8_status().ok_or(Error::Busy)?.sent_ip_bytes, 0);
        } else {
            sender.step(
                now,
                WorkBudget {
                    copies: 1,
                    field: 1,
                    metadata: 2,
                },
            )?;
            assert!(sender.status().near8_work_pending && sender.pending_output().is_none());
            sender.step(earliest, full)?;
            let status = sender.near8_status().ok_or(Error::Busy)?;
            assert_eq!(
                (status.abandoned, status.sent_rows, status.credit_eighths),
                (1, 0, 560)
            );
            for original in INPUT {
                sender.admit_source(original, earliest)?;
                let copy = sender.pending_source_copy().ok_or(Error::Busy)?;
                sender.confirm_source_copy_charged(earliest, earliest, copy, 70)?;
            }
            sender.step(earliest, full)?;
            let Some(Output::Near8(row)) = sender.pending_output() else {
                return Err(Error::Busy);
            };
            assert_eq!(row.id, Id(2));
            let price = wire_len(row)? + 49;
            sender.confirm_output_charged(OutputId::Near8(Id(2)), earliest, price)?;
        }
    }
    Ok(())
}

#[test]
fn unfunded_or_oversized_group_consumes_no_credit_or_output() -> Result<(), Error> {
    let (p, scope, work) = setup();
    for (mtu, first_price, unfunded, oversized) in
        [(1500usize, 53usize, 1u64, 0u64), (56, 70, 0, 1)]
    {
        let mut s = scheduler::Sender::new(p, scope, Tick(0))?;
        s.configure_near8(mtu, 49, 1_000_000)?;
        warm(&mut s)?;
        let now = Tick(400_000);
        for original in INPUT {
            s.admit_source(original, now)?;
            s.confirm_source_copy_charged(
                now,
                now,
                s.pending_source_copy().ok_or(Error::Busy)?,
                first_price,
            )?;
        }
        s.step(now, work)?;
        assert!(s.pending_output().is_none());
        let status = s.near8_status().ok_or(Error::Busy)?;
        assert_eq!(
            (status.unfunded, status.oversized, status.sent_ip_bytes),
            (unfunded, oversized, 0)
        );
        assert_eq!(status.credit_eighths, 8 * first_price.min(mtu) as u64);
    }
    Ok(())
}

#[test]
fn aggregate_ordinary_threshold_matches_at_close_and_group_completion() -> Result<(), Error> {
    let (p, scope, _) = setup();
    let mut s = scheduler::Sender::new(p, scope, Tick(0))?;
    s.configure_near8(1500, 49, 1_000_000)?;
    warm(&mut s)?;
    let t = Tick(401_000);
    s.observe_near8_capacity(t, 1_240_000, 6_000, 6_001)?;
    for body in INPUT {
        s.admit_source(body, t)?;
        s.confirm_source_copy_charged(t, t, s.pending_source_copy().ok_or(Error::Busy)?, 70)?;
    }
    let st = s.near8_status().ok_or(Error::Busy)?;
    assert_eq!(
        (
            st.spare,
            st.gate.open_buckets,
            st.gated,
            st.gate.backlogged_groups,
            st.gate.closed_groups
        ),
        (true, 1, 1, 1, 0)
    );
    s.observe_near8_capacity(Tick(499_000), 1_310_000, 6_000, 6_000)?;
    s.observe_near8_capacity(Tick(500_000), 1_310_000, 6_000, 6_000)?;
    assert!(s.near8_status().ok_or(Error::Busy)?.spare);
    s.observe_near8_capacity(Tick(599_000), 1_380_000, 6_000, 6_000)?;
    s.observe_near8_capacity(Tick(600_000), 1_380_000, 6_000, 6_001)?;
    let st = s.near8_status().ok_or(Error::Busy)?;
    assert!(!st.spare);
    assert_eq!(
        (
            st.gate.light_buckets,
            st.gate.open_buckets,
            st.gate.backlogged_buckets
        ),
        (6, 2, 1)
    );
    s.observe_near8_capacity(Tick(700_000), 1_380_000, 0, 0)?;
    s.observe_near8_capacity(Tick(750_000), 1_470_000, 0, 0)?;
    s.observe_near8_capacity(Tick(800_000), 1_470_000, 0, 0)?;
    let c = s.near8_status().ok_or(Error::Busy)?.gate;
    assert_eq!(
        (c.busy_buckets, c.empty_buckets, c.backlogged_buckets),
        (1, 1, 1)
    );
    Ok(())
}
