//! Actual coalescing transfer retains the first hold time and earliest cap.
use super::*;

#[test]
fn a_lone_ack_is_serviced_at_its_deadline_with_one_slot_of_work() -> TestResult {
    let (mut pipeline, mut ingress) = pair(false, 16)?;
    let first = ack(false, false, 100, 1, 4096, false);
    ingress.ingest(&mut pipeline, &first, ms(0), ms(50))?;
    assert_eq!(take(&mut pipeline)?, first);
    let second = ack(false, false, 101, 2, 4096, false);
    assert_eq!(
        ingress.ingest(&mut pipeline, &second, ms(1), ms(50))?,
        Admission::Held
    );
    assert_eq!(
        ingress.advance(&mut pipeline, ms(3), false, 1)?.forwarded,
        0
    );
    let due = ingress.advance(&mut pipeline, ms(6), false, 1)?;
    assert_eq!(due.forwarded, 1);
    assert_eq!(due.visited, 1);
    assert_eq!(take(&mut pipeline)?, second);
    assert_eq!(ingress.advance(&mut pipeline, ms(7), false, 4)?.visited, 0);
    Ok(())
}

#[test]
fn due_flush_evidence_distinguishes_capacity_from_missing_service() -> TestResult {
    for backpressured in [false, true] {
        let (mut pipeline, mut ingress) = pair(false, 1)?;
        let baseline = ack(false, false, 100, 1, 4096, false);
        ingress.ingest(&mut pipeline, &baseline, ms(0), ms(99))?;
        assert_eq!(take(&mut pipeline)?, baseline);
        for n in 1..=2 {
            ingress.ingest(
                &mut pipeline,
                &ack(false, false, 100 + n, n + 1, 4096, false),
                ms(u64::from(n)),
                ms(99),
            )?;
        }
        ingress.advance(&mut pipeline, ms(5), false, 1)?;
        if backpressured {
            pipeline.enqueue_borrowed(&baseline, ms(5))?;
            for t in [8, 12] {
                assert_eq!(ingress.advance(&mut pipeline, ms(t), false, 1)?.blocked, 1);
            }
        }
        assert_eq!(
            ingress.advance(&mut pipeline, ms(21), false, 1),
            Err(Error::Expired)
        );
        let (pending, observed, last_completed) =
            ingress.earliest_held_service().ok_or("expired candidate")?;
        assert_eq!(
            (
                pending.first_created,
                pending.latest_created,
                pending.deadline,
                pending.expires
            ),
            (ms(1), ms(2), ms(6), ms(21))
        );
        assert_eq!(
            observed.first_due_service,
            Some(ms(if backpressured { 8 } else { 21 }))
        );
        assert_eq!(observed.blocked, if backpressured { 2 } else { 0 });
        assert_eq!(observed.first_blocked, backpressured.then(|| ms(8)));
        assert_eq!(observed.last_blocked, backpressured.then(|| ms(12)));
        assert_eq!(last_completed, Some(ms(if backpressured { 12 } else { 5 })));
        assert_eq!(ingress.statistics().refusals, 0);
    }
    Ok(())
}

#[test]
fn superseded_ack_flush_keeps_original_time_and_cap_in_the_same_pipeline_metadata() -> TestResult {
    for l2 in [false, true] {
        let (mut pipeline, mut ingress) = pair(l2, 16)?;
        let first = ack(false, l2, 100, 1, 4096, false);
        let Admission::Forwarded(first_metadata) =
            ingress.ingest_at(&mut pipeline, &first, ms(0), ms(1), ms(100))?
        else {
            return Err("actual initial ACK admission".into());
        };
        assert_eq!(
            first_metadata.timing,
            crate::PacketTiming {
                received: ms(0),
                admitted: ms(1),
                original_deadline: Some(ms(100)),
            }
        );
        assert_eq!(take(&mut pipeline)?, first);
        let earlier = ack(false, l2, 101, 2, 4096, false);
        let latest = ack(false, l2, 102, 3, 4096, false);
        assert_eq!(
            ingress.ingest_at(&mut pipeline, &earlier, ms(2), ms(3), ms(12))?,
            Admission::Held
        );
        assert_eq!(
            ingress.ingest_at(&mut pipeline, &latest, ms(4), ms(5), ms(10))?,
            Admission::Superseded
        );
        let held = ingress.pending().next().ok_or("actual held candidate")?;
        assert_eq!(held.first_created, ms(2));
        assert_eq!(held.expires, ms(10));
        ingress.advance(&mut pipeline, ms(7), false, 1)?;
        assert!(ingress.is_empty());
        let expected = crate::PacketTiming {
            received: ms(2),
            admitted: ms(7),
            original_deadline: Some(ms(10)),
        };
        for _ in 0..2 {
            assert!(
                pipeline
                    .offer_front_borrowed(|metadata, bytes| {
                        assert_eq!(metadata.timing, expected);
                        assert_eq!(bytes, latest.as_slice());
                        Ok::<Option<()>, Infallible>(None)
                    })?
                    .is_none()
            );
        }
        let handed = pipeline
            .offer_front_borrowed(|metadata, bytes| {
                assert_eq!(metadata.timing, expected);
                assert_eq!(bytes, latest.as_slice());
                Ok::<_, Infallible>(Some(()))
            })?
            .ok_or("actual immutable flush handoff")?;
        assert_eq!(handed.metadata.timing, expected);
        assert_eq!(pipeline.usage().packets, 0);
    }
    Ok(())
}
