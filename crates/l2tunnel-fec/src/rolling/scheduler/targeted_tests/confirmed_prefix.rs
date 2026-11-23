use super::*;

fn feedback(scope: Scope, serial: u64, prefix: u32, end: u32) -> Feedback {
    Feedback {
        scope,
        id: FeedbackId(serial),
        prefix,
        observed_end: end,
        deficit: 0,
    }
}
fn bytes(id: u32) -> Vec<u8> {
    let len = 2 + (id as usize % 6);
    let mut value = vec![id as u8; len];
    value[0] = (id >> 8) as u8;
    value[len - 1] = 0;
    value
}
fn scalar_rhs(support: Support) -> Vec<u8> {
    let mut rhs = vec![0; 10];
    let mut extent = 2;
    for id in support.start..support.end {
        let original = bytes(id);
        extent = extent.max(original.len() + 2);
        let factor = crate::field::compact_coefficient(support.seed, id);
        for (dst, &value) in rhs.iter_mut().zip(
            (original.len() as u16)
                .to_be_bytes()
                .iter()
                .chain(&original),
        ) {
            *dst ^= crate::field::multiply(factor, value);
        }
    }
    rhs.truncate(extent);
    rhs
}

#[test]
fn earned_global_freezes_authenticated_prefix_before_service_and_physical_retry()
-> Result<(), Error> {
    for (wire, expected) in [
        (wire::SourceWire::TargetedNear8, 0),
        (wire::SourceWire::TargetedNear8ConfirmedPrefix, 4),
    ] {
        let (mut p, scope, work) = setup();
        p.source_wire = wire;
        p.recovery.local_window = 2;
        p.recovery.global_every = 2;
        p.repair_numerator = 1;
        p.repair_denominator = 4;
        let mut s = Sender::new(p, scope, Tick(0))?;
        s.configure_near8(1500, 44, 12500000)?;
        s.enable_earned_regular()?;
        let mut priced = Vec::new();
        for i in 0..8 {
            if i == 3 || i == 7 {
                let prefix = if i == 3 { 3 } else { 4 };
                s.receive_feedback(feedback(scope, u64::from(i), prefix, i), Tick(0))?;
            }
            let value = bytes(i);
            s.admit_source(&value, Tick(0))?;
            let copy = s.pending_source_copy().ok_or(Error::Busy)?;
            s.confirm_source_copy_priced(Tick(0), Tick(0), copy, 64, |id, support| {
                priced.push((id, support));
                Ok(false)
            })?;
            if i == 3 {
                s.step(Tick(0), work)?;
                let Some(Output::Repair(r)) = s.pending_output() else {
                    return Err(Error::Busy);
                };
                assert_eq!(r.support.start, 2);
                assert_eq!(r.bytes, scalar_rhs(r.support));
                let id = r.id;
                s.confirm_output_charged(OutputId::Repair(id), Tick(0), 64)?;
            }
        }
        assert_eq!(priced.len(), 2);
        assert_eq!(priced[1].1.start, expected);
        s.receive_feedback(feedback(scope, 8, 5, 8), Tick(1))?;
        s.step(
            Tick(1),
            WorkBudget {
                metadata: 1,
                field: 1,
                copies: 1,
            },
        )?;
        s.receive_feedback(feedback(scope, 9, 6, 8), Tick(2))?;
        for _ in 0..10 {
            s.step(Tick(2), work)?;
            if s.pending_output().is_some() {
                break;
            }
        }
        let Some(Output::Repair(r)) = s.pending_output() else {
            return Err(Error::Busy);
        };
        assert_eq!((r.id, r.support), priced[1]);
        let frozen = r.bytes.to_vec();
        assert_eq!(frozen, scalar_rhs(r.support));
        s.receive_feedback(feedback(scope, 10, 7, 8), Tick(3))?;
        let Some(Output::Repair(r)) = s.pending_output() else {
            return Err(Error::Busy);
        };
        assert_eq!((r.id, r.support), priced[1]);
        assert_eq!(r.bytes, frozen);
        let id = r.id;
        assert_eq!(s.near8_status().ok_or(Error::Busy)?.global_sent_rows, 0);
        s.confirm_output_charged(OutputId::Repair(id), Tick(3), 64)?;
        let status = s.near8_status().ok_or(Error::Busy)?;
        assert_eq!(
            (status.global_sent_rows, status.global_trimmed_rows),
            (1, u64::from(expected > 0))
        );
        assert_eq!(
            (status.global_nominal_columns, status.global_sent_columns),
            (8, u64::from(8 - expected))
        );
        assert!(
            s.confirm_output_charged(OutputId::Repair(id), Tick(3), 64)
                .is_err()
        );
        assert_eq!(s.near8_status(), Some(status));
    }
    Ok(())
}

#[test]
fn global_and_tail_keep_a_hole_outside_local_128_and_verify_only_the_committed_prefix()
-> Result<(), Error> {
    const END: u32 = 1024;
    const ACK: u32 = 880;
    for tail in [false, true] {
        let (mut p, scope, work) = setup();
        p.source_wire = wire::SourceWire::TargetedNear8ConfirmedPrefix;
        p.recovery.window = 8192;
        p.recovery.handoff_sources = 8192;
        // Make serial 1 global in the regular case, and specifically tail in the other.
        p.recovery.global_every = if tail { 16 } else { 1 };
        let mut original = Encoder::new(p.recovery, scope, Tick(0))?;
        let mut trimmed = Encoder::new(p.recovery, scope, Tick(0))?;
        let mut r = Receiver::new(p, scope, Tick(0))?;
        for id in 0..END {
            let v = bytes(id);
            for e in [&mut original, &mut trimmed] {
                e.admit_source(&v, Tick(0))?;
            }
            if id != ACK {
                r.receive_view_until(
                    wire::View::Source {
                        scope,
                        id: SourceId(id),
                        original: &v,
                    },
                    Tick(0),
                    Tick(0),
                    Tick(100),
                )?;
                assert!(matches!(
                    r.step(Tick(0), work)?.decode,
                    DecodeStep::Accepted { .. }
                ));
            }
        }
        assert_eq!(r.status().decoder.decoded_prefix, ACK);
        assert_eq!(r.status().decoder.observed_end, END);
        assert!(ACK < END - p.recovery.local_window as u32);
        for e in [&mut original, &mut trimmed] {
            e.confirm_prefix(ACK, Tick(0))?;
        }
        original.begin_repair(tail, Tick(0))?;
        trimmed.begin_repair_with_prefix(tail, ACK, Tick(0))?;
        let full_work = original.step(Tick(0), work)?;
        let trimmed_work = trimmed.step(Tick(0), work)?;
        let full = original.pending_repair().ok_or(Error::Busy)?;
        let cut = trimmed.pending_repair().ok_or(Error::Busy)?;
        assert_eq!((full.support.start, cut.support.start), (0, ACK));
        assert_eq!((full.id, full.support.seed), (cut.id, cut.support.seed));
        assert_eq!(full.bytes, scalar_rhs(full.support));
        assert_eq!(cut.bytes, scalar_rhs(cut.support));
        let omitted = scalar_rhs(Support {
            end: ACK,
            ..full.support
        });
        let mut normalized = full.bytes.to_vec();
        for (a, b) in normalized.iter_mut().zip(omitted) {
            *a ^= b;
        }
        assert_eq!(cut.bytes, &normalized);
        assert!(trimmed_work.field * 5 < full_work.field);
        let wrong = Repair {
            support: Support {
                start: ACK + 1,
                ..cut.support
            },
            ..cut
        };
        assert_eq!(
            r.receive_view_until(wire::View::Repair(wrong), Tick(0), Tick(0), Tick(100)),
            Err(Error::Identity)
        );
        assert!(!r.status().decoder.pending_job);
        assert_eq!(
            r.receive_view_until(wire::View::Repair(cut), Tick(0), Tick(0), Tick(100))?,
            Begin::Staged
        );
        for _ in 0..128 {
            if !r.status().decoder.pending_job {
                break;
            }
            r.step(Tick(0), work)?;
        }
        assert_eq!(r.status().decoder.decoded_prefix, END);
        assert_eq!(
            r.decoded_source(SourceId(ACK))?,
            Some(bytes(ACK).as_slice())
        );
        assert_eq!(
            r.receive_view_until(wire::View::Repair(cut), Tick(0), Tick(0), Tick(100))?,
            Begin::Duplicate
        );
        let changed = Repair {
            support: Support {
                start: ACK - 1,
                ..cut.support
            },
            ..cut
        };
        assert_eq!(
            r.receive_view_until(wire::View::Repair(changed), Tick(0), Tick(0), Tick(100)),
            Err(Error::Conflict)
        );
    }
    Ok(())
}

#[test]
fn shortened_global_keeps_source_interleaving_without_overwriting_unscanned_terms()
-> Result<(), Error> {
    let (mut p, scope, work) = setup();
    p.source_wire = wire::SourceWire::TargetedNear8ConfirmedPrefix;
    p.recovery.window = 8;
    p.recovery.handoff_sources = 8;
    p.recovery.local_window = 2;
    p.recovery.global_every = 1;
    let mut e = Encoder::new(p.recovery, scope, Tick(0))?;
    for id in 0..8 {
        e.admit_source(&bytes(id), Tick(0))?;
    }
    e.confirm_prefix(6, Tick(0))?;
    e.begin_repair_with_prefix(false, 6, Tick(0))?;
    assert!(e.computing_full_global());
    // Feedback advances while the original two-column equation is still pending.
    e.confirm_prefix(8, Tick(0))?;
    for id in 8..14 {
        let mut grant = work;
        assert_eq!(
            e.admit_queued_source(&bytes(id), Tick(0), Tick(0), true, &mut grant)?,
            Some(SourceId(id))
        );
    }
    let mut grant = work;
    assert_eq!(
        e.admit_queued_source(&bytes(14), Tick(0), Tick(0), true, &mut grant),
        Err(Error::Capacity)
    );
    assert_eq!(grant, work);
    let current = WorkBudget {
        field: bytes(6).len() + 2,
        ..work
    };
    e.step(Tick(0), current)?;
    assert!(e.computing_full_global());
    assert_eq!(
        e.admit_queued_source(&bytes(14), Tick(0), Tick(0), true, &mut grant)?,
        Some(SourceId(14))
    );
    e.step(Tick(0), work)?;
    let r = e.pending_repair().ok_or(Error::Busy)?;
    assert_eq!((r.support.start, r.support.end), (6, 8));
    assert_eq!(r.bytes, scalar_rhs(r.support));
    // A logically global row qualifies for disjoint receiver service even
    // when its physical suffix fits inside the local window.
    for wire in [
        wire::SourceWire::TargetedNear8ConfirmedPrefix,
        wire::SourceWire::TargetedNear8,
    ] {
        let mut receiver = Receiver::new(
            Policy {
                source_wire: wire,
                ..p
            },
            scope,
            Tick(0),
        )?;
        for id in [0, 1, 2, 3, 4, 5, 7] {
            receiver.receive_view_until(
                wire::View::Source {
                    scope,
                    id: SourceId(id),
                    original: &bytes(id),
                },
                Tick(0),
                Tick(0),
                Tick(100),
            )?;
            receiver.step(Tick(0), work)?;
        }
        let result =
            receiver.receive_view_until(wire::View::Repair(r), Tick(0), Tick(0), Tick(100));
        if wire.trims_confirmed_prefix() {
            assert_eq!(result?, Begin::Staged);
            assert_eq!(receiver.independent_source_floor(), Some(8));
            let mut grant = work;
            assert!(receiver.commit_independent_source(
                SourceId(8),
                &bytes(8),
                Tick(0),
                Tick(0),
                Tick(100),
                &mut grant
            )?);
            receiver.step(Tick(0), work)?;
            assert_eq!(
                receiver.decoded_source(SourceId(6))?,
                Some(bytes(6).as_slice())
            );
            assert_eq!(
                receiver.decoded_source(SourceId(8))?,
                Some(bytes(8).as_slice())
            );
        } else {
            assert_eq!(result, Err(Error::Identity));
        }
    }
    Ok(())
}
