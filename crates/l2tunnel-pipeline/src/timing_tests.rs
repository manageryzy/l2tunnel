//! Original timing stays in the actual metadata pool, through real handoff refusal.
use super::*;

#[test]
fn actual_tap_and_tun_queue_keeps_original_cap_and_refuses_invalid_timing_before_mutation()
-> TestResult {
    for profile in [Profile::TapSystem, tun()] {
        let cfg = config(profile);
        let plan = storage::Plan::for_pipeline(cfg)?;
        let mut pipeline = Pipeline::new_reserved(
            cfg,
            storage::Limits {
                capacity_bytes: plan.capacity_bytes(),
            },
        )?;
        let body = packet(profile, 1001, 60, 7);
        let before = pipeline.usage();
        assert_eq!(
            pipeline.enqueue_borrowed_capped(
                &body,
                Duration::from_millis(3),
                Duration::from_millis(2),
                Duration::from_millis(10)
            ),
            Err(PipelineError::Timing)
        );
        assert_eq!(pipeline.usage(), before);
        let timing = PacketTiming {
            received: Duration::from_millis(1),
            admitted: Duration::from_millis(2),
            original_deadline: Some(Duration::from_millis(10)),
        };
        let original = pipeline.enqueue_borrowed_capped(
            &body,
            timing.received,
            timing.admitted,
            timing.original_deadline.ok_or("explicit cap")?,
        )?;
        assert_eq!(original.timing, timing);
        let queued = pipeline.usage();
        for _ in 0..3 {
            let result = pipeline.offer_front_borrowed(|metadata, bytes| {
                assert_eq!(metadata, original);
                assert_eq!(bytes, body.as_slice());
                Ok::<Option<()>, std::convert::Infallible>(None)
            })?;
            assert_eq!(result, None);
            assert_eq!(pipeline.usage(), queued);
        }
        let handed = pipeline
            .offer_front_borrowed(|metadata, bytes| {
                assert_eq!(metadata.timing, timing);
                assert_eq!(bytes, body.as_slice());
                Ok::<_, std::convert::Infallible>(Some(()))
            })?
            .ok_or("actual original queue handoff")?;
        assert_eq!(handed.metadata, original);
        assert_eq!(pipeline.usage(), before);
        // A later flush cannot replace the packet's original cap with its flush time.
        assert_eq!(
            pipeline.enqueue_borrowed_capped(
                &body,
                Duration::from_millis(1),
                Duration::from_millis(11),
                Duration::from_millis(10)
            ),
            Err(PipelineError::Timing)
        );
        assert_eq!(pipeline.usage(), before);
        // Legacy admission retains its original API and adds no selected cap/timer.
        let legacy = pipeline.enqueue_borrowed(&body, Duration::from_millis(3))?;
        assert_eq!(
            legacy.timing,
            PacketTiming {
                received: Duration::from_millis(3),
                admitted: Duration::from_millis(3),
                original_deadline: None
            }
        );
        assert_eq!(
            pipeline
                .storage_usage()
                .ok_or("actual reserved metadata")?
                .capacity_bytes,
            plan.capacity_bytes()
        );
    }
    Ok(())
}
