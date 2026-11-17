use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn context() -> FecContext {
    FecContext {
        session: SessionId(std::array::from_fn(|i| i as u8)),
        epoch: Epoch(7),
        channel: ChannelId(9),
        direction: Direction::ClientToServer,
    }
}
fn block() -> BlockConfig {
    BlockConfig {
        max_sources: 3,
        max_source_bytes: 8,
        max_packet_bytes: 80,
        max_work_per_symbol: 100_000,
    }
}
fn config() -> DecoderConfig {
    DecoderConfig {
        block: block(),
        max_generations: 2,
        max_symbols_per_generation: 6,
        max_reserved_bytes: 100_000,
        max_lifetime_ticks: 100,
        generation_window: 4,
    }
}
fn reserved(c: DecoderConfig) -> Result<Decoder, storage::Error> {
    let p = storage::DecoderPlan::for_decoder(c)?;
    Decoder::new_reserved(
        context(),
        c,
        storage::Limits {
            capacity_bytes: p.capacity_bytes(),
        },
    )
}
fn snapshot(d: &Decoder, id: GenerationId) -> (usize, usize, usize, Option<Progress>) {
    (
        d.generation_count(),
        d.reserved_bytes(),
        d.terminal_count(),
        d.progress(id),
    )
}

#[test]
fn exact_plans_preflight_invalid_and_one_short_before_construction() -> TestResult {
    let e = storage::EncoderPlan::for_encoder(block())?;
    let d = storage::DecoderPlan::for_decoder(config())?;
    assert_eq!(e.config(), block());
    assert_eq!(d.config(), config());
    assert!(matches!(
        BlockEncoder::new_reserved(
            context(),
            block(),
            storage::Limits {
                capacity_bytes: e.capacity_bytes() - 1
            }
        ),
        Err(storage::Error::Limit { .. })
    ));
    assert!(matches!(
        Decoder::new_reserved(
            context(),
            config(),
            storage::Limits {
                capacity_bytes: d.capacity_bytes() - 1
            }
        ),
        Err(storage::Error::Limit { .. })
    ));
    let mut bad = config();
    bad.block.max_sources = 0;
    assert!(matches!(
        Decoder::new_reserved(context(), bad, storage::Limits { capacity_bytes: 0 }),
        Err(storage::Error::Fec(Error::InvalidConfig))
    ));
    assert_eq!(
        reserved(config())?
            .storage_usage()
            .ok_or("reserved usage")?
            .capacity_bytes,
        d.capacity_bytes()
    );
    assert_eq!(Decoder::new(context(), config())?.storage_usage(), None);
    Ok(())
}

#[test]
fn compact_systematic_extent_restores_only_algebraic_zeros_with_atomic_rejection() -> TestResult {
    let originals = [
        vec![9, 0, 0],
        vec![21, 22, 23, 24, 25, 26, 0, 0],
        vec![4, 0],
    ];
    let sources: Vec<&[u8]> = originals.iter().map(Vec::as_slice).collect();
    let mut encoder = BlockEncoder::new(context(), GenerationId(7), block(), &sources)?;
    let mut decoder = reserved(config())?;
    let backing = decoder.backing_fingerprint();
    let usage = decoder.storage_usage();
    let before = snapshot(&decoder, GenerationId(7));
    encoder.systematic_with(SourceId(0), |full| {
        let extent = full.original_source()?.len() + 2;
        assert!(extent < full.coded_bytes);
        full.validate(block())?;
        assert!(full.validate_compact_extent(block()).is_err());
        let short = SymbolView {
            payload: &full.payload[..extent],
            ..full
        };
        assert!(short.validate(block()).is_err());
        for end in 0..extent {
            let truncated = SymbolView {
                payload: &short.payload[..end],
                ..short
            };
            assert!(
                decoder
                    .accept_compact_view_observed(truncated, 50, |_| {})
                    .is_err()
            );
            assert_eq!(snapshot(&decoder, GenerationId(7)), before);
        }
        assert!(
            decoder
                .accept_compact_view_observed(full, 50, |_| {})
                .is_err()
        );
        assert_eq!(snapshot(&decoder, GenerationId(7)), before);
        // Rejected future-time views did not advance the actual decoder clock.
        assert!(matches!(
            decoder.accept_compact_view_observed(short, 0, |_| {})?,
            AcceptStatus::Innovative(_)
        ));
        assert!(matches!(
            decoder.accept_compact_view_observed(short, 1, |_| {})?,
            AcceptStatus::Duplicate(_)
        ));
        Ok(())
    })?;
    // Neither remaining systematic is delivered: actual Cauchy equations recover
    // both different lengths, including meaningful terminal zero bytes.
    for index in 0..2 {
        encoder.cauchy_repair_with(index, |repair| {
            assert_eq!(repair.payload.len(), repair.coded_bytes);
            let before = snapshot(&decoder, GenerationId(7));
            let truncated = SymbolView {
                payload: &repair.payload[..repair.payload.len() - 1],
                ..repair
            };
            assert!(
                decoder
                    .accept_compact_view_observed(truncated, 50, |_| {})
                    .is_err()
            );
            assert_eq!(snapshot(&decoder, GenerationId(7)), before);
            decoder.accept_compact_view_observed(repair, 2, |_| {})?;
            Ok(())
        })?;
    }
    assert_eq!(decoder.take_decoded(GenerationId(7))?.sources, originals);
    assert_eq!(decoder.storage_usage(), usage);
    assert_eq!(decoder.backing_fingerprint(), backing);
    Ok(())
}

#[test]
fn reusable_encoder_matches_fixed_python_bytes_and_preserves_ids_on_refusal() -> TestResult {
    let plan = storage::EncoderPlan::for_encoder(block())?;
    let mut e = BlockEncoder::new_reserved(
        context(),
        block(),
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?;
    let mut output = [0xa5; 80];
    assert_eq!(
        e.systematic_into(SourceId(0), &mut output),
        Err(Error::Unsealed)
    );
    let sources: [&[u8]; 3] = [&[0, 1, 2], &[254], &[5, 4, 3, 2, 1]];
    e.seal_sources(GenerationId(11), sources.into_iter())?;
    let n = e.systematic_into(SourceId(1), &mut output)?;
    assert_eq!(
        &output[..n],
        include_bytes!("../tests/fixtures/systematic.bin")
    );
    let next = e.next_repair;
    let before = output;
    assert!(matches!(
        e.repair_into(&[7, 19, 251], &mut output[..1]),
        Err(Error::OutputTooSmall { .. })
    ));
    assert_eq!(e.next_repair, next);
    assert_eq!(output, before);
    let n = e.repair_into(&[7, 19, 251], &mut output)?;
    assert_eq!(&output[..n], include_bytes!("../tests/fixtures/repair.bin"));
    assert_eq!(
        e.seal_sources(GenerationId(11), sources.into_iter()),
        Err(Error::StaleGeneration)
    );
    let mut old = BlockEncoder::new(context(), GenerationId(11), block(), &sources)?;
    old.repair(&[7, 19, 251])?;
    let n = e.cauchy_repair_into(2, &mut output)?;
    assert_eq!(&output[..n], old.repair(&cauchy_coefficients(3, 2)?)?.bytes);
    let capacity = e.storage_usage();
    for id in 12..64 {
        e.seal_sources(GenerationId(id), [&[id as u8][..]].into_iter())?;
        e.systematic_into(SourceId(0), &mut output)?;
        e.cauchy_repair_into(0, &mut output)?;
        assert_eq!(e.storage_usage(), capacity);
    }
    Ok(())
}

#[test]
fn every_explicit_encoder_and_decoder_reservation_can_fail_without_publication() -> TestResult {
    let e = storage::EncoderPlan::for_encoder(block())?;
    let count = BlockEncoder::new_reserved(
        context(),
        block(),
        storage::Limits {
            capacity_bytes: e.capacity_bytes(),
        },
    )?
    .storage_usage()
    .ok_or("usage")?
    .allocations;
    for fail in 1..=count {
        let mut a = storage::Allocation::failing(e.capacity_bytes(), fail);
        assert!(matches!(
            BlockEncoder::reserved_with(context(), block(), e, &mut a),
            Err(storage::Error::Allocation)
        ));
    }
    let d = storage::DecoderPlan::for_decoder(config())?;
    let count = reserved(config())?
        .storage_usage()
        .ok_or("usage")?
        .allocations;
    for fail in 1..=count {
        let mut a = storage::Allocation::failing(d.capacity_bytes(), fail);
        assert!(matches!(
            Decoder::reserved_with(context(), config(), d, &mut a),
            Err(storage::Error::Allocation)
        ));
    }
    assert_eq!(reserved(config())?.generation_count(), 0);
    Ok(())
}

#[test]
fn reserved_decoder_recovers_real_reordered_equations_and_reuses_all_generations() -> TestResult {
    let mut old = Decoder::new(context(), config())?;
    let mut new = reserved(config())?;
    let usage = new.storage_usage();
    let backing = new.backing_fingerprint();
    let sources: [&[u8]; 3] = [b"abc", b"z", b"12345"];
    for generation in 0..12 {
        let id = GenerationId(generation);
        let mut e = BlockEncoder::new(context(), id, block(), &sources)?;
        let packets = [
            e.repair(&[1, 1, 0])?.bytes,
            e.repair(&[2, 2, 0])?.bytes,
            e.systematic(SourceId(2))?.bytes,
            e.systematic(SourceId(0))?.bytes,
        ];
        for (i, packet) in packets.iter().enumerate() {
            let now = generation * 2;
            assert_eq!(old.accept(packet, now), new.accept(packet, now));
            assert_eq!(snapshot(&old, id), snapshot(&new, id));
            if i == 0 {
                assert_eq!(old.accept(packet, now), new.accept(packet, now));
            }
        }
        assert_eq!(new.decoded_sources(id)?.collect::<Vec<_>>(), sources);
        assert_eq!(
            old.take_decoded(id)?.sources,
            sources.iter().map(|s| s.to_vec()).collect::<Vec<_>>()
        );
        new.commit_decoded(id)?;
        assert_eq!(
            new.accept(&packets[0], generation * 2),
            Err(Error::AlreadyCompleted)
        );
        assert_eq!(snapshot(&old, id), snapshot(&new, id));
        assert_eq!(new.storage_usage(), usage);
        assert_eq!(new.backing_fingerprint(), backing);
    }
    Ok(())
}

#[test]
fn final_equation_uses_exact_n_plus_one_rows_without_a_basis_snapshot() -> TestResult {
    let mut decoder = reserved(config())?;
    let backing = decoder.backing_fingerprint();
    let sources: [&[u8]; 3] = [b"a", b"bb", b"ccc"];
    let mut e = BlockEncoder::new(context(), GenerationId(1), block(), &sources)?;
    decoder.accept(&e.repair(&[1, 0, 1])?.bytes, 0)?;
    decoder.accept(&e.repair(&[0, 1, 1])?.bytes, 0)?;
    decoder.accept(&e.systematic(SourceId(2))?.bytes, 0)?;
    assert_eq!(decoder.transaction_rows_used(), block().max_sources + 1);
    assert_eq!(
        decoder
            .decoded_sources(GenerationId(1))?
            .collect::<Vec<_>>(),
        sources
    );
    assert_eq!(decoder.backing_fingerprint(), backing);
    Ok(())
}

#[test]
fn changed_row_invalid_original_is_atomic_for_both_backings() -> TestResult {
    for corrupt_length in [false, true] {
        let sources: [&[u8]; 2] = [&[1, 2], &[3, 4, 5, 6, 7]];
        let mut e = BlockEncoder::new(context(), GenerationId(1), block(), &sources)?;
        let mut mixed = e.repair(&[1, 1])?.bytes;
        if corrupt_length {
            mixed[HEADER_BYTES + 3] ^= 2;
        } else {
            *mixed.last_mut().ok_or("payload")? ^= 1;
        }
        let final_packet = e.systematic(SourceId(1))?.bytes;
        for mut decoder in [Decoder::new(context(), config())?, reserved(config())?] {
            decoder.accept(&mixed, 0)?;
            let before = snapshot(&decoder, GenerationId(1));
            assert_eq!(decoder.accept(&final_packet, 50), Err(Error::InvalidSource));
            assert_eq!(snapshot(&decoder, GenerationId(1)), before);
            // Failed future input did not advance time or committed row/history.
            assert!(matches!(
                decoder.accept(&mixed, 1)?,
                AcceptStatus::Duplicate(_)
            ));
        }
    }
    Ok(())
}

#[test]
fn expiry_output_preflight_and_terminal_window_remain_exact() -> TestResult {
    let mut decoder = reserved(config())?;
    let sources: [&[u8]; 2] = [b"a", b"bb"];
    for id in [2, 1] {
        let e = BlockEncoder::new(context(), GenerationId(id), block(), &sources)?;
        decoder.accept(&e.systematic(SourceId(0))?.bytes, 0)?;
    }
    let before = snapshot(&decoder, GenerationId(1));
    assert_eq!(
        decoder.expire_into(100, &mut []),
        Err(Error::OutputTooSmall { required: 2 })
    );
    assert_eq!(snapshot(&decoder, GenerationId(1)), before);
    let mut output = [ExpiredGeneration {
        generation: GenerationId(0),
        rank: 0,
        required_rank: 0,
    }; 2];
    assert_eq!(decoder.expire_into(100, &mut output)?, 2);
    assert_eq!(
        output.map(|e| e.generation),
        [GenerationId(1), GenerationId(2)]
    );
    assert_eq!(decoder.reserved_bytes(), 0);
    assert_eq!(decoder.generation_count(), 0);
    assert_eq!(decoder.terminal_count(), 2);
    let e = BlockEncoder::new(context(), GenerationId(8), block(), &sources)?;
    decoder.accept(&e.systematic(SourceId(0))?.bytes, 100)?;
    assert_eq!(decoder.terminal_count(), 0);
    Ok(())
}
