use super::*;

#[test]
fn decoder_diagnostics_report_exact_capacity_gate_and_preserve_atomic_rejection() -> TestResult {
    let first = encoder(1)?.systematic(SourceId(0))?;
    let second = encoder(2)?.systematic(SourceId(0))?;
    for (config, accept_first, bytes, expected) in [
        (
            DecoderConfig {
                max_generations: 1,
                ..decoder_config()
            },
            true,
            second.bytes.as_slice(),
            DecoderCapacity::GenerationSlots,
        ),
        (
            DecoderConfig {
                max_reserved_bytes: 1,
                ..decoder_config()
            },
            false,
            first.bytes.as_slice(),
            DecoderCapacity::LogicalReservation,
        ),
    ] {
        let mut decoder = Decoder::new(context(), config)?;
        if accept_first {
            decoder.accept(&first.bytes, 0)?;
        }
        let before = snapshot(&decoder, GenerationId(1));
        let buffers = decoder.buffer_snapshot();
        let view = inspect(bytes, context(), config.block)?;
        let mut reason = None;
        assert_eq!(
            decoder.accept_view_observed(view, 1, |value| reason = Some(value)),
            Err(Error::Capacity)
        );
        assert_eq!(reason, Some(expected));
        assert_eq!(snapshot(&decoder, GenerationId(1)), before);
        assert_eq!(decoder.buffer_snapshot(), buffers);
    }
    let config = DecoderConfig {
        block: BlockConfig {
            max_sources: 3,
            ..block_config()
        },
        max_symbols_per_generation: 3,
        ..decoder_config()
    };
    let mut decoder = Decoder::new(context(), config)?;
    let mut encoder = encoder(1)?;
    for factor in 1..=3 {
        decoder.accept(&encoder.repair(&[factor, factor, 0])?.bytes, 0)?;
    }
    let last = encoder.repair(&[4, 4, 0])?;
    let before = snapshot(&decoder, GenerationId(1));
    let mut reason = None;
    assert_eq!(
        decoder.accept_view_observed(inspect(&last.bytes, context(), config.block)?, 1, |value| {
            reason = Some(value)
        }),
        Err(Error::Capacity)
    );
    assert_eq!(reason, Some(DecoderCapacity::SymbolSlots));
    assert_eq!(snapshot(&decoder, GenerationId(1)), before);
    assert_eq!(decoder.buffer_snapshot().basis_rows, 1);
    assert_eq!(decoder.buffer_snapshot().history_symbols, 3);
    Ok(())
}

#[test]
fn decoder_diagnostics_release_live_logical_reservation_without_changing_backing() -> TestResult {
    let config = decoder_config();
    let plan = storage::DecoderPlan::for_decoder(config)?;
    let mut decoder = Decoder::new_reserved(
        context(),
        config,
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?;
    let before = decoder.buffer_snapshot();
    assert_eq!(before.logical_reservation_bytes, 0);
    let mut encoder = encoder(1)?;
    for source in 0..3 {
        encoder.systematic_with(SourceId(source), |view| decoder.accept_view(view, 0))?;
    }
    let ready = decoder.buffer_snapshot();
    assert_eq!(ready.completed_generations, 1);
    assert_eq!(ready.basis_rows, 3);
    assert!(ready.logical_reservation_bytes > 0);
    assert_eq!(
        ready.logical_reservation_capacity,
        config.max_reserved_bytes
    );
    decoder.commit_decoded(GenerationId(1))?;
    assert_eq!(decoder.buffer_snapshot(), before);
    Ok(())
}
