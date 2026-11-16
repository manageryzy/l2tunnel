use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn config(cumulative: bool) -> Config {
    Config {
        recovery: rolling::Config {
            window: 4,
            local_window: 2,
            global_every: 4,
            max_payload: 4,
            max_rows: 4,
            repair_history: 8,
            handoff_sources: 4,
            job_ticks: 10_000,
            debt_ticks: 100_000,
            handoff_ticks: 10_000,
            memory_bytes: 1 << 20,
        },
        mode: Mode::Sliding,
        long_window: 2,
        short_window: 1,
        long_every: 2,
        repair_every: 2,
        repairs_per_group: 1,
        interleave_repairs: false,
        feedback_repair: false,
        cumulative_feedback: cumulative,
        feedback_batch: 1,
        fec_wait_ticks: 100,
        repair_spacing_ticks: 0,
        feedback_wait_ticks: 0,
        rto_min_ticks: 100,
        rto_factor_numerator: 2,
        rto_factor_denominator: 1,
        repair_queue: 4,
        max_attempts: 4,
        feedback_payload_budget: 128,
        max_record_bytes: 256,
        memory_bytes: 1 << 20,
    }
}
fn scope() -> Scope {
    Scope {
        session: [0x63; 16],
        epoch: 2,
        stream: 1,
        direction: 0,
    }
}
fn budget() -> WorkBudget {
    WorkBudget {
        field: 64,
        copies: 64,
        metadata: 64,
    }
}
fn payload(id: u32) -> [u8; 3] {
    [id as u8, 0xa5, 0]
}
fn settle(receiver: &mut Receiver, confirm_reverse: bool) -> Result<(), Error> {
    for _ in 0..10_000 {
        let result = receiver.step(Tick(0), budget())?;
        if matches!(result.decode, DecodeStep::Capacity(_)) {
            return Err(Error::Capacity);
        }
        if confirm_reverse && let Some(feedback) = receiver.pending_feedback() {
            receiver.confirm_feedback(feedback.id, Tick(0))?;
        }
        let status = receiver.status();
        if !status.decoder.pending_job
            && !status.scanning
            && (!confirm_reverse || status.pending_receipts == 0 && status.feedback.is_none())
        {
            return Ok(());
        }
    }
    Err(Error::WorkLimit)
}

#[test]
fn legacy_dependent_repair_does_not_reack_known_span_beyond_forward_window() -> TestResult {
    for cumulative in [false, true] {
        let c = config(cumulative);
        let plan = storage::Plan::for_receiver(c)?;
        let mut receiver = Receiver::new_reserved(
            c,
            scope(),
            Tick(0),
            storage::Limits {
                capacity_bytes: plan.capacity_bytes(),
            },
        )?;
        let usage = receiver.storage_usage()?;
        assert!(receiver.is_drained());
        let mut encoder = rolling::Encoder::new_explicit(c.recovery, scope(), Tick(0))?;
        let end = c.recovery.window as u32 + 2;
        for id in 0..end {
            let original = payload(id);
            encoder.admit_source(&original, Tick(0))?;
            encoder.confirm_prefix(id + 1, Tick(0))?;
            let mut bytes = [0; 256];
            let length = wire::encode_source(c, scope(), SourceId(id), &original, &mut bytes)?;
            assert_eq!(
                receiver.receive_wire(&bytes[..length], Tick(0))?,
                Begin::Staged
            );
            // Retire every reverse receipt, but deliberately retain every upper
            // source. Known IDs 0..W+1 now span more than the forward window W.
            settle(&mut receiver, true)?;
        }
        assert_eq!(receiver.status().decoder.handoff_prefix, 0);
        assert_eq!(
            receiver.status().decoder.decoded_prefix,
            c.recovery.window as u32
        );
        assert_eq!(receiver.status().decoder.observed_end, end);
        assert_eq!(receiver.status().receipt_prefix, end);
        assert!(!receiver.is_drained());
        let terms = [
            Term {
                source: SourceId(end - 2),
                coefficient: 7,
            },
            Term {
                source: SourceId(end - 1),
                coefficient: 19,
            },
        ];
        encoder.begin_explicit(&terms, false, Tick(0), Tick(0), Tick(9999))?;
        for _ in 0..10_000 {
            encoder.step(Tick(0), budget())?;
            if encoder.pending_repair().is_some() {
                break;
            }
        }
        let equation = encoder.pending_repair().ok_or(Error::WorkLimit)?;
        let repair = Repair {
            equation,
            terms: &terms,
            feedback_triggered: false,
        };
        let mut bytes = [0; 256];
        let length = wire::encode_repair(c, repair, &mut bytes)?;
        // A new equation identity over already known real bytes is dependent,
        // rather than a history duplicate, and must create no receipt event.
        assert_eq!(
            receiver.receive_wire(&bytes[..length], Tick(0))?,
            Begin::Staged
        );
        settle(&mut receiver, false)?;
        receiver.step(Tick(0), budget())?;
        assert_eq!(receiver.status().pending_receipts, 0);
        assert!(receiver.pending_feedback().is_none());
        assert_eq!(receiver.storage_usage()?, usage);
        for id in 0..end {
            assert_eq!(
                receiver.pending_source(),
                Some((SourceId(id), payload(id).as_slice()))
            );
            receiver.confirm_handoff(SourceId(id), Tick(0))?;
        }
        assert!(receiver.is_drained());
    }
    Ok(())
}
