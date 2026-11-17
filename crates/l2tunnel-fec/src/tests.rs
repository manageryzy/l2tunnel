use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn context() -> FecContext {
    FecContext {
        session: SessionId(std::array::from_fn(|index| index as u8)),
        epoch: Epoch(7),
        channel: ChannelId(9),
        direction: Direction::ClientToServer,
    }
}

fn block_config() -> BlockConfig {
    BlockConfig {
        max_sources: 16,
        max_source_bytes: 1200,
        max_packet_bytes: 1500,
        max_work_per_symbol: 100_000,
    }
}

fn decoder_config() -> DecoderConfig {
    DecoderConfig {
        block: block_config(),
        max_generations: 4,
        max_symbols_per_generation: 64,
        max_reserved_bytes: 1_000_000,
        max_lifetime_ticks: 100,
        generation_window: 16,
    }
}

fn source_bytes() -> Vec<Vec<u8>> {
    vec![vec![0, 1, 2], vec![254], vec![5, 4, 3, 2, 1]]
}

fn encoder(generation: u64) -> Result<BlockEncoder, Error> {
    let sources = source_bytes();
    let borrowed: Vec<_> = sources.iter().map(Vec::as_slice).collect();
    BlockEncoder::new(
        context(),
        GenerationId(generation),
        block_config(),
        &borrowed,
    )
}

fn snapshot(
    decoder: &Decoder,
    generation: GenerationId,
) -> (usize, usize, usize, Option<Progress>) {
    (
        decoder.generation_count(),
        decoder.reserved_bytes(),
        decoder.terminal_count(),
        decoder.progress(generation),
    )
}

#[test]
fn all_field_products_and_inverses_match_independent_python() -> TestResult {
    let products = include_bytes!("../tests/fixtures/products.bin");
    for a in 0_u8..=255 {
        for b in 0_u8..=255 {
            assert_eq!(
                field::multiply(a, b),
                products[usize::from(a) * 256 + usize::from(b)]
            );
        }
        if a == 0 {
            assert_eq!(field::inverse(a), None);
        } else {
            assert_eq!(field::multiply(a, field::inverse(a).ok_or("inverse")?), 1);
        }
    }
    Ok(())
}

#[test]
fn compact_and_cauchy_helpers_match_python_and_reject_bounds() -> TestResult {
    let coefficients = include_bytes!("../tests/fixtures/coefficients.bin");
    assert_eq!(cauchy_coefficients(3, 2)?, coefficients[..3]);
    assert_eq!(
        compact_coefficients(0xdead_beef, 100, 16)?,
        coefficients[3..]
    );
    for (count, repair) in [(0, 0), (256, 0), (255, 1), (u16::MAX, 1)] {
        assert_eq!(
            cauchy_coefficients(count, repair),
            Err(Error::InvalidCoefficients)
        );
    }
    assert_eq!(
        compact_coefficients(1, 0, 0),
        Err(Error::InvalidCoefficients)
    );
    assert_eq!(
        compact_coefficients(1, 0, 257),
        Err(Error::InvalidCoefficients)
    );
    assert_eq!(compact_coefficients(1, u32::MAX, 2), Err(Error::Arithmetic));
    assert_eq!(compact_coefficients(0, 0, 1)?, [0]);
    assert_eq!(compact_coefficients(9, u32::MAX, 1)?.len(), 1);
    assert_eq!(cauchy_coefficients(255, 0)?.len(), 255);
    Ok(())
}

#[test]
fn full_wire_vectors_match_independent_python() -> TestResult {
    let mut encoder = encoder(11)?;
    let systematic = encoder.systematic(SourceId(1))?;
    let repair = encoder.repair(&[7, 19, 251])?;
    assert_eq!(
        systematic.bytes,
        include_bytes!("../tests/fixtures/systematic.bin")
    );
    assert_eq!(repair.bytes, include_bytes!("../tests/fixtures/repair.bin"));
    let view = inspect(&repair.bytes, context(), block_config())?;
    assert_eq!(view.generation, GenerationId(11));
    assert_eq!(view.symbol, SymbolId(3));
    assert_eq!(view.coefficients, [7, 19, 251]);
    assert_eq!(view.source_count, 3);
    assert_eq!(view.coded_bytes, 7);
    Ok(())
}

#[test]
fn every_three_of_six_systematic_cauchy_symbols_reconstruct_nonuniform_bytes() -> TestResult {
    let mut encoder = encoder(11)?;
    let mut packets: Vec<_> = (0..3)
        .map(|index| encoder.systematic(SourceId(index)))
        .collect::<Result<_, _>>()?;
    for repair in 0..3 {
        packets.push(encoder.repair(&cauchy_coefficients(3, repair)?)?);
    }
    drop(encoder);
    // Receiver is constructed only after all encoder/source storage is dropped.
    // Every k-of-(k+r) subset includes source loss, repair loss and repair-only recovery.
    for mask in 0_u32..64 {
        if mask.count_ones() != 3 {
            continue;
        }
        let mut decoder = Decoder::new(context(), decoder_config())?;
        for index in (0..6).rev().filter(|index| mask & (1 << index) != 0) {
            decoder.accept(&packets[index].bytes, 0)?;
        }
        let block = decoder.take_decoded(GenerationId(11))?;
        assert_eq!(block.sources, source_bytes());
        assert_eq!(decoder.reserved_bytes(), 0);
        assert_eq!(decoder.generation_count(), 0);
        assert_eq!(decoder.terminal_count(), 1);
        assert_eq!(
            decoder.take_decoded(GenerationId(11)),
            Err(Error::AlreadyCompleted)
        );
        assert_eq!(
            decoder.accept(&packets[0].bytes, 0),
            Err(Error::AlreadyCompleted)
        );
    }
    Ok(())
}

#[test]
fn compact_random_linear_repairs_recover_after_loss_and_reordering_without_systematics()
-> TestResult {
    let sources: Vec<Vec<u8>> = (0..16)
        .map(|index| {
            (0_u8..=255)
                .cycle()
                .skip(index * 17)
                .take(1 + index * 29)
                .collect()
        })
        .collect();
    let borrowed: Vec<_> = sources.iter().map(Vec::as_slice).collect();
    let mut encoder = BlockEncoder::new(context(), GenerationId(1), block_config(), &borrowed)?;
    let packets: Vec<_> = (1..=64)
        .map(|seed| encoder.repair(&compact_coefficients(seed, 70, 16)?))
        .collect::<Result<_, Error>>()?;
    drop(encoder);
    let mut decoder = Decoder::new(context(), decoder_config())?;
    let mut complete = false;
    for (index, packet) in packets.iter().enumerate().rev() {
        if index % 3 == 0 {
            continue;
        }
        if matches!(decoder.accept(&packet.bytes, 1)?, AcceptStatus::Complete(_)) {
            complete = true;
            break;
        }
    }
    assert!(complete);
    assert_eq!(decoder.take_decoded(GenerationId(1))?.sources, sources);
    Ok(())
}

#[test]
fn duplicate_dependent_and_conflicting_symbols_have_distinct_atomic_results() -> TestResult {
    let mut encoder = encoder(1)?;
    let first = encoder.repair(&[1, 1, 0])?;
    let dependent = encoder.repair(&[2, 2, 0])?;
    let inconsistent = encoder.repair(&[1, 1, 0])?;
    let mut decoder = Decoder::new(context(), decoder_config())?;
    assert!(matches!(
        decoder.accept(&first.bytes, 0)?,
        AcceptStatus::Innovative(Progress { rank: 1, .. })
    ));
    assert!(matches!(
        decoder.accept(&first.bytes, 1)?,
        AcceptStatus::Duplicate(Progress {
            received_symbols: 1,
            ..
        })
    ));
    assert!(matches!(
        decoder.accept(&dependent.bytes, 2)?,
        AcceptStatus::Dependent(Progress {
            rank: 1,
            received_symbols: 2,
            ..
        })
    ));
    let before = snapshot(&decoder, GenerationId(1));
    let mut changed_id_bytes = first.bytes.clone();
    *changed_id_bytes.last_mut().ok_or("payload")? ^= 1;
    assert_eq!(decoder.accept(&changed_id_bytes, 3), Err(Error::Conflict));
    assert_eq!(snapshot(&decoder, GenerationId(1)), before);
    let mut changed_equation = inconsistent.bytes;
    *changed_equation.last_mut().ok_or("payload")? ^= 1;
    assert_eq!(decoder.accept(&changed_equation, 3), Err(Error::Conflict));
    assert_eq!(snapshot(&decoder, GenerationId(1)), before);
    assert_eq!(
        decoder.take_decoded(GenerationId(1)),
        Err(Error::InsufficientRank)
    );
    assert_eq!(snapshot(&decoder, GenerationId(1)), before);
    Ok(())
}

#[test]
fn reconstructed_invalid_length_and_padding_reject_before_rank_commit() -> TestResult {
    for corrupt_length in [false, true] {
        let sources: [&[u8]; 2] = [&[1, 2], &[3, 4, 5, 6, 7]];
        let mut encoder = BlockEncoder::new(context(), GenerationId(1), block_config(), &sources)?;
        let mut mixed = encoder.repair(&[1, 1])?;
        let payload = HEADER_BYTES + 2;
        if corrupt_length {
            // Original source0 length 2 XOR 2 becomes zero after reconstruction.
            mixed.bytes[payload + 1] ^= 2;
        } else {
            // Source0's final padded byte must remain zero after reconstruction.
            *mixed.bytes.last_mut().ok_or("payload")? ^= 1;
        }
        let source1 = encoder.systematic(SourceId(1))?;
        let mut decoder = Decoder::new(context(), decoder_config())?;
        decoder.accept(&mixed.bytes, 0)?;
        let before = snapshot(&decoder, GenerationId(1));
        assert_eq!(decoder.accept(&source1.bytes, 1), Err(Error::InvalidSource));
        assert_eq!(snapshot(&decoder, GenerationId(1)), before);
        assert_eq!(
            decoder.take_decoded(GenerationId(1)),
            Err(Error::InsufficientRank)
        );
    }
    Ok(())
}

#[test]
fn parser_rejects_every_truncation_trailing_bytes_and_noncanonical_fields() -> TestResult {
    let encoder = encoder(11)?;
    let packet = encoder.systematic(SourceId(1))?;
    for length in 0..packet.bytes.len() {
        assert!(inspect(&packet.bytes[..length], context(), block_config()).is_err());
    }
    let mut trailing = packet.bytes.clone();
    trailing.push(0);
    assert_eq!(
        inspect(&trailing, context(), block_config()),
        Err(Error::Malformed)
    );
    for offset in [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 23, 24, 31, 32, 35, 44, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56,
        57, 58,
    ] {
        let mut changed = packet.bytes.clone();
        changed[offset] ^= 1;
        assert!(
            inspect(&changed, context(), block_config()).is_err(),
            "offset {offset}"
        );
    }
    for length in [0_u16, 6, u16::MAX] {
        let mut changed = packet.bytes.clone();
        changed[59..61].copy_from_slice(&length.to_be_bytes());
        assert!(inspect(&changed, context(), block_config()).is_err());
    }
    let mut bad_padding = packet.bytes.clone();
    *bad_padding.last_mut().ok_or("padding")? = 1;
    assert_eq!(
        inspect(&bad_padding, context(), block_config()),
        Err(Error::InvalidSource)
    );
    Ok(())
}

#[test]
fn context_descriptor_and_failed_future_time_are_failure_atomic() -> TestResult {
    let packet = encoder(1)?.systematic(SourceId(0))?;
    let mut decoder = Decoder::new(context(), decoder_config())?;
    decoder.accept(&packet.bytes, 5)?;
    let before = snapshot(&decoder, GenerationId(1));
    for offset in [4, 8, 23, 24, 31, 32, 35] {
        let mut altered = packet.bytes.clone();
        altered[offset] ^= 1;
        assert_eq!(decoder.accept(&altered, 1000), Err(Error::ContextMismatch));
        assert_eq!(snapshot(&decoder, GenerationId(1)), before);
    }
    let longer: [&[u8]; 3] = [&[1; 6], &[2], &[3]];
    let other = BlockEncoder::new(context(), GenerationId(1), block_config(), &longer)?
        .systematic(SourceId(0))?;
    assert_eq!(decoder.accept(&other.bytes, 6), Err(Error::Conflict));
    assert_eq!(snapshot(&decoder, GenerationId(1)), before);
    assert!(matches!(
        decoder.accept(&packet.bytes, 6)?,
        AcceptStatus::Duplicate(_)
    ));
    Ok(())
}

#[test]
fn distinct_dependent_symbol_count_is_bounded_and_duplicates_do_not_consume_slots() -> TestResult {
    let mut config = decoder_config();
    config.block.max_sources = 3;
    config.max_symbols_per_generation = 3;
    let mut decoder = Decoder::new(context(), config)?;
    let mut encoder = encoder(1)?;
    let mut packets = Vec::new();
    for factor in 1..=4 {
        packets.push(encoder.repair(&[factor, factor, 0])?);
    }
    for packet in &packets[..3] {
        decoder.accept(&packet.bytes, 0)?;
    }
    let before = snapshot(&decoder, GenerationId(1));
    assert_eq!(decoder.accept(&packets[3].bytes, 0), Err(Error::Capacity));
    assert_eq!(snapshot(&decoder, GenerationId(1)), before);
    assert!(matches!(
        decoder.accept(&packets[0].bytes, 0)?,
        AcceptStatus::Duplicate(_)
    ));
    assert_eq!(snapshot(&decoder, GenerationId(1)), before);
    Ok(())
}

#[test]
fn generation_byte_and_work_limits_reject_before_partial_admission() -> TestResult {
    let first = encoder(1)?.systematic(SourceId(0))?;
    let second = encoder(2)?.systematic(SourceId(0))?;
    let mut config = decoder_config();
    config.block.max_sources = 3;
    config.max_symbols_per_generation = 12;
    let reservation = (3 * 3 + 12) * (3 + 7);
    config.max_reserved_bytes = reservation - 1;
    let mut decoder = Decoder::new(context(), config)?;
    assert_eq!(decoder.accept(&first.bytes, 0), Err(Error::Capacity));
    assert_eq!(snapshot(&decoder, GenerationId(1)), (0, 0, 0, None));
    config.max_reserved_bytes = reservation;
    let mut decoder = Decoder::new(context(), config)?;
    decoder.accept(&first.bytes, 0)?;
    assert_eq!(decoder.reserved_bytes(), reservation);
    let before = snapshot(&decoder, GenerationId(1));
    assert_eq!(decoder.accept(&second.bytes, 0), Err(Error::Capacity));
    assert_eq!(snapshot(&decoder, GenerationId(1)), before);
    config.max_reserved_bytes = 1_000_000;
    config.max_generations = 1;
    let mut decoder = Decoder::new(context(), config)?;
    decoder.accept(&first.bytes, 0)?;
    assert_eq!(decoder.accept(&second.bytes, 0), Err(Error::Capacity));
    config.max_generations = 4;
    config.block.max_work_per_symbol = 85; // Actual bound is (2*3+1)*(3+7)+16 = 86.
    let mut decoder = Decoder::new(context(), config)?;
    assert_eq!(decoder.accept(&first.bytes, 0), Err(Error::WorkLimit));
    assert_eq!(snapshot(&decoder, GenerationId(1)), (0, 0, 0, None));
    config.block.max_work_per_symbol = 86;
    Decoder::new(context(), config)?.accept(&first.bytes, 0)?;
    Ok(())
}

#[test]
fn exact_deadlines_do_not_renew_and_expiry_reports_rank_shortage() -> TestResult {
    let packet = encoder(1)?.systematic(SourceId(0))?;
    let mut decoder = Decoder::new(context(), decoder_config())?;
    decoder.accept(&packet.bytes, 5)?;
    decoder.accept(&packet.bytes, 104)?;
    assert!(decoder.expire(104)?.is_empty());
    let before = snapshot(&decoder, GenerationId(1));
    assert_eq!(decoder.accept(&packet.bytes, 105), Err(Error::Expired));
    assert_eq!(snapshot(&decoder, GenerationId(1)), before);
    assert_eq!(
        decoder.expire(105)?,
        [ExpiredGeneration {
            generation: GenerationId(1),
            rank: 1,
            required_rank: 3
        }]
    );
    assert_eq!(decoder.reserved_bytes(), 0);
    assert_eq!(decoder.accept(&packet.bytes, 105), Err(Error::Expired));
    assert_eq!(decoder.take_decoded(GenerationId(1)), Err(Error::Expired));
    assert_eq!(decoder.expire(104), Err(Error::TimeBackwards));
    assert_eq!(decoder.terminal_count(), 1);
    let mut decoder = Decoder::new(context(), decoder_config())?;
    assert_eq!(
        decoder.accept(&packet.bytes, u64::MAX - 99),
        Err(Error::DeadlineOverflow)
    );
    assert_eq!(decoder.generation_count(), 0);
    decoder.accept(&packet.bytes, 0)?;
    Ok(())
}

#[test]
fn generation_window_never_evicts_live_state_and_terminal_history_is_bounded() -> TestResult {
    let mut config = decoder_config();
    config.generation_window = 4;
    let mut decoder = Decoder::new(context(), config)?;
    let first = encoder(10)?.systematic(SourceId(0))?;
    let distant = encoder(14)?.systematic(SourceId(0))?;
    decoder.accept(&first.bytes, 0)?;
    let before = snapshot(&decoder, GenerationId(10));
    assert_eq!(decoder.accept(&distant.bytes, 1), Err(Error::WindowBlocked));
    assert_eq!(snapshot(&decoder, GenerationId(10)), before);
    decoder.expire(100)?;
    for generation in 14..=20 {
        let packet =
            BlockEncoder::new(context(), GenerationId(generation), block_config(), &[&[1]])?
                .systematic(SourceId(0))?;
        assert!(matches!(
            decoder.accept(&packet.bytes, 100)?,
            AcceptStatus::Complete(_)
        ));
        decoder.take_decoded(GenerationId(generation))?;
        assert!(decoder.terminal_count() <= 4);
    }
    assert_eq!(
        decoder.accept(&first.bytes, 100),
        Err(Error::StaleGeneration)
    );
    assert_eq!(
        decoder.accept(&distant.bytes, 100),
        Err(Error::StaleGeneration)
    );
    let maximum = BlockEncoder::new(context(), GenerationId(u64::MAX), block_config(), &[&[1]])?
        .systematic(SourceId(0))?;
    decoder.accept(&maximum.bytes, 100)?;
    decoder.take_decoded(GenerationId(u64::MAX))?;
    assert_eq!(decoder.terminal_count(), 1);
    Ok(())
}

#[test]
fn full_rank_is_retained_until_taken_and_can_expire_undelivered() -> TestResult {
    let mut encoder = BlockEncoder::new(context(), GenerationId(1), block_config(), &[&[8]])?;
    let source = encoder.systematic(SourceId(0))?;
    let repair = encoder.repair(&[19])?;
    let mut decoder = Decoder::new(context(), decoder_config())?;
    assert!(matches!(
        decoder.accept(&source.bytes, 0)?,
        AcceptStatus::Complete(_)
    ));
    assert!(matches!(
        decoder.accept(&source.bytes, 1)?,
        AcceptStatus::Duplicate(_)
    ));
    assert_eq!(
        decoder.accept(&repair.bytes, 1),
        Err(Error::CompletePending)
    );
    assert_eq!(
        decoder.take_decoded(GenerationId(9)),
        Err(Error::UnknownGeneration)
    );
    let expired = decoder.expire(100)?;
    assert_eq!(expired[0].rank, 1);
    assert_eq!(expired[0].required_rank, 1);
    assert_eq!(decoder.take_decoded(GenerationId(1)), Err(Error::Expired));
    Ok(())
}

#[test]
fn minimum_maximum_source_dimensions_and_exact_mtu() -> TestResult {
    let mut config = block_config();
    config.max_sources = 256;
    config.max_source_bytes = 4096;
    config.max_packet_bytes = 65_507;
    config.max_work_per_symbol = MAX_WORK_PER_SYMBOL;
    let source = vec![0x7a; 4096];
    let mut encoder = BlockEncoder::new(context(), GenerationId(1), config, &[&source])?;
    let repair = encoder.repair(&[255])?;
    assert_eq!(repair.bytes.len(), HEADER_BYTES + 1 + 4098);
    let mut receiver = decoder_config();
    receiver.block = config;
    receiver.max_symbols_per_generation = 256;
    receiver.max_reserved_bytes = 2_000_000;
    let mut decoder = Decoder::new(context(), receiver)?;
    decoder.accept(&repair.bytes, 0)?;
    assert_eq!(decoder.take_decoded(GenerationId(1))?.sources, [source]);
    let tiny: Vec<&[u8]> = vec![&[1]; 256];
    let encoder = BlockEncoder::new(context(), GenerationId(2), config, &tiny)?;
    assert_eq!(encoder.source_count(), 256);
    assert_eq!(
        encoder.systematic(SourceId(255))?.bytes.len(),
        HEADER_BYTES + 256 + 3
    );
    let mut exact = block_config();
    exact.max_packet_bytes = HEADER_BYTES + 3 + 7;
    let sources = source_bytes();
    let borrowed: Vec<_> = sources.iter().map(Vec::as_slice).collect();
    BlockEncoder::new(context(), GenerationId(1), exact, &borrowed)?;
    exact.max_packet_bytes -= 1;
    assert!(matches!(
        BlockEncoder::new(context(), GenerationId(1), exact, &borrowed),
        Err(Error::PacketTooLarge)
    ));
    Ok(())
}

#[test]
fn full_rank_rejects_nonminimal_generation_width_atomically() -> TestResult {
    let mut encoder = BlockEncoder::new(context(), GenerationId(1), block_config(), &[&[1], &[2]])?;
    let mut first = encoder.repair(&[1, 1])?;
    let mut second = encoder.repair(&[1, 2])?;
    for packet in [&mut first, &mut second] {
        packet.bytes[48..50].copy_from_slice(&4_u16.to_be_bytes());
        packet.bytes.push(0);
    }
    let mut decoder = Decoder::new(context(), decoder_config())?;
    decoder.accept(&first.bytes, 0)?;
    let before = snapshot(&decoder, GenerationId(1));
    assert_eq!(decoder.accept(&second.bytes, 1), Err(Error::InvalidSource));
    assert_eq!(snapshot(&decoder, GenerationId(1)), before);
    Ok(())
}

#[test]
fn invalid_configs_sources_coefficients_and_repair_exhaustion_are_explicit() -> TestResult {
    let valid = block_config();
    for invalid in [
        BlockConfig {
            max_sources: 0,
            ..valid
        },
        BlockConfig {
            max_sources: 257,
            ..valid
        },
        BlockConfig {
            max_source_bytes: 0,
            ..valid
        },
        BlockConfig {
            max_source_bytes: 4097,
            ..valid
        },
        BlockConfig {
            max_packet_bytes: 59,
            ..valid
        },
        BlockConfig {
            max_packet_bytes: 65_508,
            ..valid
        },
        BlockConfig {
            max_work_per_symbol: 0,
            ..valid
        },
        BlockConfig {
            max_work_per_symbol: MAX_WORK_PER_SYMBOL + 1,
            ..valid
        },
    ] {
        assert!(matches!(
            BlockEncoder::new(context(), GenerationId(1), invalid, &[&[1]]),
            Err(Error::InvalidConfig)
        ));
    }
    let valid_receiver = decoder_config();
    for invalid in [
        DecoderConfig {
            max_generations: 0,
            ..valid_receiver
        },
        DecoderConfig {
            max_generations: 65,
            ..valid_receiver
        },
        DecoderConfig {
            max_symbols_per_generation: 15,
            ..valid_receiver
        },
        DecoderConfig {
            max_symbols_per_generation: 1025,
            ..valid_receiver
        },
        DecoderConfig {
            max_reserved_bytes: 0,
            ..valid_receiver
        },
        DecoderConfig {
            max_reserved_bytes: 256 * 1024 * 1024 + 1,
            ..valid_receiver
        },
        DecoderConfig {
            max_lifetime_ticks: 0,
            ..valid_receiver
        },
        DecoderConfig {
            generation_window: 0,
            ..valid_receiver
        },
        DecoderConfig {
            generation_window: 4097,
            ..valid_receiver
        },
    ] {
        assert!(matches!(
            Decoder::new(context(), invalid),
            Err(Error::InvalidConfig)
        ));
    }
    assert!(matches!(
        BlockEncoder::new(context(), GenerationId(1), valid, &[]),
        Err(Error::InvalidDimensions)
    ));
    assert!(matches!(
        BlockEncoder::new(context(), GenerationId(1), valid, &[&[]]),
        Err(Error::InvalidDimensions)
    ));
    assert!(matches!(
        BlockEncoder::new(context(), GenerationId(1), valid, &[&[1; 1201]]),
        Err(Error::InvalidDimensions)
    ));
    let mut encoder = encoder(1)?;
    assert_eq!(
        encoder.systematic(SourceId(3)),
        Err(Error::InvalidDimensions)
    );
    assert_eq!(encoder.repair(&[0, 0, 0]), Err(Error::InvalidCoefficients));
    assert_eq!(encoder.repair(&[1, 1]), Err(Error::InvalidCoefficients));
    assert_eq!(encoder.repair(&[1, 1, 1])?.symbol, SymbolId(3));
    encoder.next_repair = Some(SymbolId(u32::MAX));
    assert_eq!(encoder.repair(&[1, 1, 1])?.symbol, SymbolId(u32::MAX));
    assert_eq!(encoder.repair(&[1, 1, 1]), Err(Error::SymbolExhausted));
    Ok(())
}

#[path = "decoder_diagnostics_tests.rs"]
mod decoder_diagnostics;
