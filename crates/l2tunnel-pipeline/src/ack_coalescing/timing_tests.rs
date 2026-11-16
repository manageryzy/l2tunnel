//! Actual coalescing transfer retains the first hold time and earliest cap.
use super::*;

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
