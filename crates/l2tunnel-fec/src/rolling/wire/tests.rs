use super::*;
use crate::rolling::{Begin, DecodeStep, Decoder, Tick, WorkBudget};

#[path = "extent_tests.rs"]
mod extent;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn config() -> Config {
    Config {
        window: 4,
        local_window: 2,
        global_every: 2,
        max_payload: 8,
        max_rows: 4,
        repair_history: 8,
        handoff_sources: 4,
        job_ticks: 100,
        debt_ticks: 1000,
        handoff_ticks: 500,
        memory_bytes: 1 << 20,
    }
}
fn scope() -> Scope {
    Scope {
        session: std::array::from_fn(|i| i as u8),
        epoch: 0x0102_0304_0506_0708,
        stream: 0x1020_3040,
        direction: 2,
    }
}
fn hex(value: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    value
        .as_bytes()
        .chunks(2)
        .map(|chunk| Ok(u8::from_str_radix(std::str::from_utf8(chunk)?, 16)?))
        .collect()
}

// Header literals derive from independent Python struct.pack, with the version
// explicitly updated for effective repair extents. The repair body is the maintained Python PRODUCT /
// compact coefficient fixture from rolling-equation-design14/oracle-vectors.json.
const SOURCE0: &str = "4c32525703010000000102030405060708090a0b0c0d0e0f010203040506070810203040020000000000000000000000000000000000000100000000000a000000030102000000000000";
const SOURCE1: &str = "4c32525703010000000102030405060708090a0b0c0d0e0f010203040506070810203040020000000000000000000001000000010000000200000000000a000000040000000000000000";
const SOURCE2: &str = "4c32525703010000000102030405060708090a0b0c0d0e0f010203040506070810203040020000000000000000000002000000020000000300000000000a00000001ff00000000000000";
const REPAIR16: &str = "4c32525703020000000102030405060708090a0b0c0d0e0f0102030405060708102030400200000000000000000000100000000000000003e3779b10000a000000456fc1000000000000";
const EQUATION: [u8; 10] = [0, 0x45, 0x6f, 0xc1, 0, 0, 0, 0, 0, 0];

fn equation(id: u64, end: u32, tail: bool) -> Result<Repair<'static>, Error> {
    Ok(Repair {
        scope: scope(),
        id: RepairId(id),
        support: config().support(end, RepairId(id), tail)?,
        bytes: &EQUATION,
    })
}

#[test]
fn literal_source_and_repair_pin_every_header_field_and_full_body() -> TestResult {
    let source = hex(SOURCE0)?;
    assert_eq!(source.len(), 74);
    let View::Source {
        scope: actual_scope,
        id,
        original,
    } = inspect(config(), &source)?
    else {
        return Err("literal original became repair".into());
    };
    assert_eq!(
        (actual_scope, id, original),
        (scope(), SourceId(0), &[1, 2, 0][..])
    );
    let mut output = [0xa5; 80];
    assert_eq!(
        encode_source(config(), scope(), SourceId(0), original, &mut output)?,
        74
    );
    assert_eq!(&output[..74], source);
    assert_eq!(&output[74..], &[0xa5; 6]);

    let repair = hex(REPAIR16)?;
    let View::Repair(view) = inspect(config(), &repair)? else {
        return Err("repair became original".into());
    };
    assert_eq!(view.scope, scope());
    assert_eq!(view.id, RepairId(16));
    assert_eq!(
        view.support,
        Support {
            start: 0,
            end: 3,
            seed: 3_816_266_512,
            tail: false
        }
    );
    assert_eq!(view.bytes, EQUATION);
    output.fill(0xa5);
    assert_eq!(
        encode_repair(config(), equation(16, 3, false)?, &mut output)?,
        74
    );
    assert_eq!(&output[..74], repair);
    assert_eq!(&output[74..], &[0xa5; 6]);
    Ok(())
}

#[test]
fn received_full_wire_recovers_each_missing_original_without_sender_access() -> TestResult {
    let sources = [hex(SOURCE0)?, hex(SOURCE1)?, hex(SOURCE2)?];
    let originals: [&[u8]; 3] = [&[1, 2, 0], &[0; 4], &[255]];
    let repair = hex(REPAIR16)?;
    for missing in 0..3 {
        let mut decoder = Decoder::new(config(), scope(), Tick(0))?;
        for (id, record) in sources.iter().enumerate() {
            if id == missing {
                continue;
            }
            let View::Source {
                scope,
                id,
                original,
            } = inspect(config(), record)?
            else {
                return Err("expected received source".into());
            };
            assert_eq!(
                decoder.begin_source(scope, id, original, Tick(0))?,
                Begin::Staged
            );
            commit(&mut decoder)?;
        }
        let View::Repair(repair) = inspect(config(), &repair)? else {
            return Err("expected received repair".into());
        };
        decoder.begin_repair(repair, Tick(0))?;
        commit(&mut decoder)?;
        assert_eq!(decoder.status().decoded_prefix, 3);
        for (id, original) in originals.iter().enumerate() {
            assert_eq!(
                decoder.pending_source(),
                Some((SourceId(id as u32), *original))
            );
            decoder.confirm_handoff(SourceId(id as u32), Tick(0))?;
        }
        assert_eq!(decoder.pending_source(), None);
    }
    Ok(())
}
fn commit(decoder: &mut Decoder) -> Result<(), Error> {
    for _ in 0..100_000 {
        match decoder.step(
            Tick(0),
            WorkBudget {
                field: 1,
                copies: 3,
                metadata: 7,
            },
        )? {
            DecodeStep::Pending(work) => {
                assert!(work.field <= 1 && work.copies <= 3 && work.metadata <= 7);
            }
            DecodeStep::Accepted { .. } => return Ok(()),
            _ => return Err(Error::Capacity),
        }
    }
    Err(Error::WorkLimit)
}

#[test]
fn source_truncation_and_repair_extent_boundaries_are_rejected() -> TestResult {
    for literal in [SOURCE0, REPAIR16] {
        let record = hex(literal)?;
        let minimum = if literal == REPAIR16 {
            HEADER_BYTES + 3
        } else {
            record.len()
        };
        for length in 0..minimum {
            assert!(matches!(
                inspect(config(), &record[..length]),
                Err(Error::Length)
            ));
        }
        let mut trailing = record.clone();
        trailing.push(0);
        assert!(matches!(inspect(config(), &trailing), Err(Error::Length)));
        for width in [0, 1, 9, 11, u16::MAX] {
            let mut bad = record.clone();
            bad[60..62].copy_from_slice(&width.to_be_bytes());
            assert!(matches!(inspect(config(), &bad), Err(Error::Length)));
        }
        assert!(matches!(
            inspect(
                Config {
                    max_payload: 7,
                    ..config()
                },
                &record
            ),
            Err(Error::Length)
        ));
    }
    Ok(())
}

#[test]
fn version_kind_reserved_and_flag_corpus_is_structurally_rejected() -> TestResult {
    for literal in [SOURCE0, REPAIR16] {
        let record = hex(literal)?;
        for index in [0, 1, 2, 3, 7, 37, 38, 39, 62, 63] {
            let mut bad = record.clone();
            bad[index] ^= 1;
            assert!(
                matches!(inspect(config(), &bad), Err(Error::Format)),
                "byte {index}"
            );
        }
        for (index, values) in [
            (4, &[0, 1, 2, 4, 255][..]),
            (5, &[0, 3, 255][..]),
            (6, &[2, 4, 128, 255][..]),
        ] {
            for value in values {
                let mut bad = record.clone();
                bad[index] = *value;
                assert!(matches!(inspect(config(), &bad), Err(Error::Format)));
            }
        }
    }
    Ok(())
}

#[test]
fn source_identity_canonical_support_and_original_padding_are_checked() -> TestResult {
    let record = hex(SOURCE0)?;
    for index in [40, 48, 52, 56] {
        let mut bad = record.clone();
        bad[index] ^= 1;
        assert!(
            matches!(inspect(config(), &bad), Err(Error::Identity)),
            "byte {index}"
        );
    }
    let mut bad = record.clone();
    bad[6] = 1;
    assert!(matches!(inspect(config(), &bad), Err(Error::Identity)));
    bad = record.clone();
    bad[40..48].copy_from_slice(&u64::from(u32::MAX).to_be_bytes());
    assert!(matches!(inspect(config(), &bad), Err(Error::Identity)));
    for length in [0u16, 9, u16::MAX] {
        bad = record.clone();
        bad[64..66].copy_from_slice(&length.to_be_bytes());
        assert!(matches!(inspect(config(), &bad), Err(Error::Length)));
    }
    for index in 69..74 {
        bad = record.clone();
        bad[index] = 1;
        assert!(matches!(inspect(config(), &bad), Err(Error::Length)));
    }
    Ok(())
}

#[test]
fn repair_full_identity_support_tail_and_seed_are_canonical() -> TestResult {
    let record = hex(REPAIR16)?;
    for index in [48, 52, 56] {
        let mut bad = record.clone();
        bad[index] ^= 1;
        assert!(matches!(inspect(config(), &bad), Err(Error::Identity)));
    }
    for id in [0, u64::MAX] {
        let mut bad = record.clone();
        bad[40..48].copy_from_slice(&id.to_be_bytes());
        assert!(matches!(inspect(config(), &bad), Err(Error::Identity)));
    }
    let mut bad = record.clone();
    bad[52..56].fill(0);
    assert!(matches!(inspect(config(), &bad), Err(Error::Identity)));
    for (id, tail) in [
        (1, false),
        (2, false),
        (32_768, false),
        (32_769, false),
        (32_769, true),
        (u64::MAX - 1, true),
    ] {
        let repair = equation(id, 9, tail)?;
        let mut output = [0; 74];
        encode_repair(config(), repair, &mut output)?;
        let View::Repair(parsed) = inspect(config(), &output)? else {
            return Err("repair became source".into());
        };
        assert_eq!(parsed.id, RepairId(id));
        assert_eq!(parsed.support, repair.support);
        assert_eq!(parsed.bytes, EQUATION);
    }
    // A repeated 15-bit serial retains its full independent replay identity.
    bad = record.clone();
    bad[40..48].copy_from_slice(&32_784u64.to_be_bytes());
    let View::Repair(parsed) = inspect(config(), &bad)? else {
        return Err("repair became source".into());
    };
    assert_eq!(parsed.id, RepairId(32_784));
    assert_eq!(parsed.support, config().support(3, RepairId(16), false)?);
    Ok(())
}

#[test]
fn source_maximum_identity_and_length_preserve_all_zero_original() -> TestResult {
    let mut output = [0; 74];
    encode_source(
        config(),
        scope(),
        SourceId(u32::MAX - 1),
        &[0; 8],
        &mut output,
    )?;
    let View::Source { id, original, .. } = inspect(config(), &output)? else {
        return Err("source became repair".into());
    };
    assert_eq!(id, SourceId(u32::MAX - 1));
    assert_eq!(original, &[0; 8]);
    assert_eq!(u32::from_be_bytes(output[52..56].try_into()?), u32::MAX);
    let c = Config {
        max_payload: MAX_PAYLOAD,
        ..config()
    };
    let payload = vec![0; MAX_PAYLOAD];
    let mut largest = vec![0; MAX_RECORD_BYTES];
    assert_eq!(
        encode_source(c, scope(), SourceId(0), &payload, &mut largest)?,
        MAX_RECORD_BYTES
    );
    let View::Source { original, .. } = inspect(c, &largest)? else {
        return Err("source became repair".into());
    };
    assert_eq!(original, payload);
    Ok(())
}

#[test]
fn rejected_source_and_repair_encodes_leave_all_caller_bytes_unchanged() -> TestResult {
    let mut output = [0xa5; 80];
    for (id, original) in [
        (SourceId(0), &[][..]),
        (SourceId(0), &[0; 9][..]),
        (SourceId(u32::MAX), &[1][..]),
    ] {
        assert!(encode_source(config(), scope(), id, original, &mut output).is_err());
        assert_eq!(output, [0xa5; 80]);
    }
    assert_eq!(
        encode_source(config(), scope(), SourceId(0), &[1], &mut output[..73]),
        Err(Error::OutputTooSmall)
    );
    assert_eq!(output, [0xa5; 80]);
    assert_eq!(
        encode_source(
            Config {
                window: 0,
                ..config()
            },
            scope(),
            SourceId(0),
            &[1],
            &mut output
        ),
        Err(Error::Configuration)
    );
    assert_eq!(output, [0xa5; 80]);
    let valid = equation(16, 3, false)?;
    let mut invalid = valid;
    invalid.support.seed ^= 1;
    let mut wrong_start = valid;
    wrong_start.support.start += 1;
    for repair in [
        Repair {
            bytes: &EQUATION[..2],
            ..valid
        },
        Repair {
            id: RepairId(0),
            ..valid
        },
        Repair {
            id: RepairId(u64::MAX),
            ..valid
        },
        invalid,
        wrong_start,
    ] {
        assert!(encode_repair(config(), repair, &mut output).is_err());
        assert_eq!(output, [0xa5; 80]);
    }
    assert_eq!(
        encode_repair(config(), valid, &mut output[..73]),
        Err(Error::OutputTooSmall)
    );
    assert_eq!(output, [0xa5; 80]);
    assert_eq!(
        encode_repair(
            Config {
                window: 0,
                ..config()
            },
            valid,
            &mut output
        ),
        Err(Error::Configuration)
    );
    assert_eq!(output, [0xa5; 80]);
    Ok(())
}

#[test]
fn structural_scope_is_complete_and_does_not_grant_owner_authority() -> TestResult {
    let record = hex(SOURCE0)?;
    for index in [8, 23, 24, 31, 32, 35, 36] {
        let mut foreign = record.clone();
        foreign[index] ^= 0x80;
        let View::Source {
            scope: received,
            id,
            original,
        } = inspect(config(), &foreign)?
        else {
            return Err("source became repair".into());
        };
        assert_ne!(received, scope());
        let mut decoder = Decoder::new(config(), scope(), Tick(0))?;
        assert_eq!(
            decoder.begin_source(received, id, original, Tick(0)),
            Err(Error::Scope)
        );
        assert_eq!(decoder.status().observed_end, 0);
    }
    Ok(())
}

// Independent Python struct.pack literals for the exact-source format. The
// source ends after its three original bytes, including the real trailing zero.
const EXACT0: &str = "4c32525704010000000102030405060708090a0b0c0d0e0f010203040506070810203040020000000000000000000000000000000000000100000000000a00000003010200";
const EXACT_REPAIR16: &str = "4c32525704020000000102030405060708090a0b0c0d0e0f0102030405060708102030400200000000000000000000100000000000000003e3779b10000a000000456fc1000000000000";

#[test]
fn exact_source_literal_and_explicit_full_extent_equation_remain_exact() -> TestResult {
    let source = hex(EXACT0)?;
    assert_eq!(source.len(), HEADER_BYTES + 2 + 3);
    assert_eq!(source_len(config(), SourceWire::Exact, 3)?, 69);
    assert_eq!(source_len(config(), SourceWire::Padded, 3)?, 74);
    let View::Source {
        scope: actual_scope,
        id,
        original,
    } = inspect_with(config(), SourceWire::Exact, &source)?
    else {
        return Err("exact original became repair".into());
    };
    assert_eq!(
        (actual_scope, id, original),
        (scope(), SourceId(0), &[1, 2, 0][..])
    );
    let mut output = [0xa5; 80];
    assert_eq!(
        encode_source_with(
            config(),
            SourceWire::Exact,
            scope(),
            SourceId(0),
            &[1, 2, 0],
            &mut output
        )?,
        69
    );
    assert_eq!(&output[..69], source);
    assert_eq!(&output[69..], &[0xa5; 11], "bytes after the record changed");

    let repair = hex(EXACT_REPAIR16)?;
    assert_eq!(repair.len(), 74);
    let View::Repair(view) = inspect_with(config(), SourceWire::Exact, &repair)? else {
        return Err("exact repair became original".into());
    };
    assert_eq!((view.id, view.bytes), (RepairId(16), &EQUATION[..]));
    output.fill(0xa5);
    assert_eq!(
        encode_repair_with(
            config(),
            SourceWire::Exact,
            equation(16, 3, false)?,
            &mut output
        )?,
        74
    );
    assert_eq!(&output[..74], repair);
    // Source padding remains distinct from a repair's selected extent.
    output.fill(0xa5);
    encode_source(config(), scope(), SourceId(0), &[1, 2, 0], &mut output)?;
    assert_eq!(&output[..74], hex(SOURCE0)?);
    Ok(())
}

#[test]
fn exact_and_padded_formats_never_accept_each_other() -> TestResult {
    let padded = [hex(SOURCE0)?, hex(REPAIR16)?];
    let exact = [hex(EXACT0)?, hex(EXACT_REPAIR16)?];
    for record in &padded {
        assert!(inspect_with(config(), SourceWire::Exact, record).is_err());
        assert!(inspect(config(), record).is_ok());
    }
    for record in &exact {
        assert!(inspect(config(), record).is_err());
        assert!(inspect_with(config(), SourceWire::Padded, record).is_err());
    }
    // A padded-length source relabelled as the exact-source version is not canonical either:
    // the exact format rejects every byte after the declared original.
    let mut relabelled = hex(SOURCE0)?;
    relabelled[4] = EXACT_SOURCE_VERSION;
    assert_eq!(
        inspect_with(config(), SourceWire::Exact, &relabelled).err(),
        Some(Error::Length)
    );
    Ok(())
}

#[test]
fn exact_source_rejects_truncation_trailing_bytes_and_length_limits() -> TestResult {
    let source = hex(EXACT0)?;
    for cut in 0..source.len() {
        assert!(
            inspect_with(config(), SourceWire::Exact, &source[..cut]).is_err(),
            "truncated at {cut}"
        );
    }
    let mut trailing = source.clone();
    trailing.push(0);
    assert_eq!(
        inspect_with(config(), SourceWire::Exact, &trailing).err(),
        Some(Error::Length)
    );
    let mut zero = source.clone();
    zero[HEADER_BYTES..HEADER_BYTES + 2].copy_from_slice(&0_u16.to_be_bytes());
    assert!(inspect_with(config(), SourceWire::Exact, &zero[..HEADER_BYTES + 2]).is_err());
    assert!(inspect_with(config(), SourceWire::Exact, &zero).is_err());
    let mut reserved = source.clone();
    reserved[7] = 1;
    assert_eq!(
        inspect_with(config(), SourceWire::Exact, &reserved).err(),
        Some(Error::Format)
    );

    // Largest original fills the vector exactly; one more byte is rejected
    // without touching the caller output.
    let full = [0_u8; 8];
    let mut output = [0xa5; 80];
    let length = encode_source_with(
        config(),
        SourceWire::Exact,
        scope(),
        SourceId(7),
        &full,
        &mut output,
    )?;
    assert_eq!(length, HEADER_BYTES + config().width()?);
    let View::Source { original, .. } =
        inspect_with(config(), SourceWire::Exact, &output[..length])?
    else {
        return Err("full exact original became repair".into());
    };
    assert_eq!(original, &full, "an all-zero original is real data");
    output.fill(0xa5);
    for (bad, expected) in [(&[][..], Error::Length), (&[0_u8; 9][..], Error::Length)] {
        assert_eq!(
            encode_source_with(
                config(),
                SourceWire::Exact,
                scope(),
                SourceId(7),
                bad,
                &mut output
            )
            .err(),
            Some(expected)
        );
        assert_eq!(output, [0xa5; 80]);
    }
    assert_eq!(
        encode_source_with(
            config(),
            SourceWire::Exact,
            scope(),
            SourceId(7),
            &[9],
            &mut output[..HEADER_BYTES + 2]
        )
        .err(),
        Some(Error::OutputTooSmall)
    );
    assert_eq!(output, [0xa5; 80]);
    Ok(())
}

#[test]
fn selected_compact_union_full_identity_support_and_strict_feedback_shape() -> TestResult {
    use crate::rolling::scheduler::{Feedback, FeedbackId, Output};
    for source in [0, 127, 128, u32::MAX - 1] {
        let value = Output::Source {
            scope: scope(),
            id: SourceId(source),
            original: &[1, 0, 0],
        };
        let length = compact::data_len(value)?;
        let mut output = [0xa5; 64];
        assert_eq!(
            compact::encode_data(value, &mut output[..length - 1]),
            Err(Error::OutputTooSmall)
        );
        assert_eq!(output, [0xa5; 64]);
        compact::encode_data(value, &mut output)?;
        let compact::View::Data(View::Source { id, original, .. }) =
            compact::inspect(config(), scope(), &output[..length])?
        else {
            return Err("source kind".into());
        };
        assert_eq!(id, SourceId(source));
        assert_eq!(original, [1, 0, 0]);
    }
    for tail in [false, true] {
        let repair = equation(16, 3, tail)?;
        let mut output = [0; 64];
        let length = compact::encode_data(Output::Repair(repair), &mut output)?;
        let compact::View::Data(View::Repair(decoded)) =
            compact::inspect(config(), scope(), &output[..length])?
        else {
            return Err("repair kind".into());
        };
        assert_eq!(decoded.support, repair.support);
        assert_eq!(decoded.bytes, repair.bytes);
        // A bounded shorter equation prefix is valid; enclosing integrity
        // protects its exact transmitted extent against network truncation.
        assert!(compact::inspect(config(), scope(), &output[..length - 1]).is_ok());
    }
    let feedback = Feedback {
        scope: scope(),
        id: FeedbackId(u64::MAX - 1),
        prefix: u32::MAX - 4,
        observed_end: u32::MAX,
        deficit: 2,
    };
    let mut output = [0; 64];
    let length = compact::encode_feedback(feedback, &mut output)?;
    assert!(
        matches!(compact::inspect(config(), scope(), &output[..length])?, compact::View::Feedback(actual) if actual == feedback)
    );
    assert!(compact::inspect(config(), scope(), &output[..length + 1]).is_err());
    assert!(compact::inspect(config(), scope(), &[1, 0x80, 0, 1]).is_err());
    assert!(compact::inspect(config(), scope(), &hex(SOURCE0)?).is_err());
    Ok(())
}

#[test]
fn previous_full_width_wire_versions_are_refused() -> TestResult {
    for (format, literals) in [
        (SourceWire::Padded, [SOURCE0, REPAIR16]),
        (SourceWire::Exact, [EXACT0, EXACT_REPAIR16]),
    ] {
        for literal in literals {
            let mut bytes = hex(literal)?;
            for old in [1, 2] {
                bytes[4] = old;
                assert!(matches!(
                    inspect_with(config(), format, &bytes),
                    Err(Error::Format)
                ));
            }
        }
    }
    Ok(())
}
