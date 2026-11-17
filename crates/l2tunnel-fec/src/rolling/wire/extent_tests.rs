//! Real coded-byte recovery from effective repair prefixes, not sender ledgers.
use super::*;
use crate::rolling::{Encoder, scheduler};

fn limits() -> Config {
    Config {
        max_payload: 1024,
        ..config()
    }
}

fn ready(encoder: &mut Encoder) -> Result<(), Error> {
    for _ in 0..10_000 {
        let used = encoder.step(
            Tick(0),
            WorkBudget {
                field: 17,
                copies: 13,
                metadata: 31,
            },
        )?;
        assert!(used.field <= 17 && used.copies <= 13 && used.metadata <= 31);
        if encoder.pending_repair().is_some() {
            return Ok(());
        }
    }
    Err(Error::WorkLimit)
}

#[test]
fn effective_repair_extent_recovers_each_lost_source_and_meaningful_zero_tail() -> TestResult {
    let originals: [&[u8]; 3] = [&[0x91, 0x37, 0], &[0; 17], &[0xfa, 0, 0, 0, 0]];
    let mut encoder = Encoder::new(limits(), scope(), Tick(0))?;
    for original in originals {
        encoder.admit_source(original, Tick(0))?;
    }
    encoder.begin_repair(true, Tick(0))?;
    ready(&mut encoder)?;
    let repair = encoder.pending_repair().ok_or(Error::Busy)?;
    assert_eq!(repair.bytes.len(), 2 + 17);
    // These bytes belong to the longest original, not dispensable source padding.
    assert_eq!(&repair.bytes[7..], &[0; 12]);
    let expected = 1 + 1 + 1 + 19;
    assert_eq!(
        compact::data_len(scheduler::Output::Repair(repair))?,
        expected
    );
    let mut wire = [0xa5; 1100];
    let length = compact::encode_data(scheduler::Output::Repair(repair), &mut wire)?;
    assert_eq!(length, expected);
    assert!(wire[length..].iter().all(|byte| *byte == 0xa5));
    let compact::View::Data(View::Repair(received)) =
        compact::inspect(limits(), scope(), &wire[..length])?
    else {
        return Err("actual short repair became another kind".into());
    };
    assert_eq!(received.bytes, repair.bytes);

    for missing in 0..originals.len() {
        let mut decoder = Decoder::new(limits(), scope(), Tick(0))?;
        for (index, original) in originals.iter().enumerate() {
            if index != missing {
                decoder.begin_source(scope(), SourceId(index as u32), original, Tick(0))?;
                commit(&mut decoder)?;
            }
        }
        decoder.begin_repair(received, Tick(0))?;
        commit(&mut decoder)?;
        for (index, original) in originals.iter().enumerate() {
            assert_eq!(
                decoder.pending_source(),
                Some((SourceId(index as u32), *original))
            );
            decoder.confirm_handoff(SourceId(index as u32), Tick(0))?;
        }
        assert_eq!(decoder.begin_repair(received, Tick(0))?, Begin::Duplicate);
        let mut expanded = vec![0; limits().width()?];
        expanded[..received.bytes.len()].copy_from_slice(received.bytes);
        assert_eq!(
            decoder.begin_repair(
                Repair {
                    bytes: &expanded,
                    ..received
                },
                Tick(0)
            )?,
            Begin::Duplicate
        );
        expanded[1000] = 1;
        assert_eq!(
            decoder.begin_repair(
                Repair {
                    bytes: &expanded,
                    ..received
                },
                Tick(0)
            ),
            Err(Error::Conflict)
        );
    }
    Ok(())
}

#[test]
fn effective_repair_extent_uses_complete_selected_support_and_exact_output_charge() -> TestResult {
    let mut encoder = Encoder::new(limits(), scope(), Tick(0))?;
    for original in [&[7; 64][..], &[1, 0][..], &[0; 9][..]] {
        encoder.admit_source(original, Tick(0))?;
    }
    encoder.begin_repair(false, Tick(0))?;
    ready(&mut encoder)?;
    let local = encoder.pending_repair().ok_or(Error::Busy)?;
    assert_eq!(local.support.start, 1);
    assert_eq!(local.bytes.len(), 11);
    let mut wire = [0xa5; 1100];
    let length = encode_repair(limits(), local, &mut wire)?;
    assert_eq!(length, HEADER_BYTES + 11);
    let View::Repair(decoded) = inspect(limits(), &wire[..length])? else {
        return Err("local repair kind".into());
    };
    assert_eq!(decoded.bytes, local.bytes);
    encoder.confirm_repair(local.id, Tick(0))?;
    encoder.begin_repair(true, Tick(0))?;
    ready(&mut encoder)?;
    let global = encoder.pending_repair().ok_or(Error::Busy)?;
    assert_eq!(global.support.start, 0);
    assert_eq!(global.bytes.len(), 66);
    Ok(())
}

#[test]
fn effective_repair_extent_rejects_too_short_or_oversized_without_decoder_mutation() -> TestResult {
    let config = limits();
    let mut decoder = Decoder::new(config, scope(), Tick(0))?;
    let before = decoder.status();
    for size in [0, 1, 2, config.width()? + 1] {
        let bytes = vec![0; size];
        let repair = Repair {
            scope: scope(),
            id: RepairId(1),
            support: config.support(1, RepairId(1), true)?,
            bytes: &bytes,
        };
        assert_eq!(decoder.begin_repair(repair, Tick(0)), Err(Error::Length));
        let mut packet = vec![4, 1, 1];
        packet.extend_from_slice(&bytes);
        assert!(matches!(
            compact::inspect(config, scope(), &packet),
            Err(Error::Length)
        ));
        assert_eq!(decoder.status(), before);
    }
    Ok(())
}
