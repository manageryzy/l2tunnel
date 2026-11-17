//! Two owners exchange received records only, across repeated fixed windows.
use l2tunnel_fec::rolling::{
    Begin, Config, DecodeStep, Decoder, Encoder, Error, Repair, Scope, SourceId, Tick, WorkBudget,
};

type Result = std::result::Result<(), Box<dyn std::error::Error>>;

fn config(handoff_sources: usize) -> Config {
    Config {
        window: 8,
        local_window: 3,
        global_every: 4,
        max_payload: 64,
        max_rows: 8,
        repair_history: 31,
        handoff_sources,
        job_ticks: 100,
        debt_ticks: 1000,
        handoff_ticks: 500,
        memory_bytes: 1 << 20,
    }
}

fn scope() -> Scope {
    Scope {
        session: [91; 16],
        epoch: 1,
        stream: 7,
        direction: 0,
    }
}

fn budget(units: usize) -> WorkBudget {
    WorkBudget {
        field: units,
        copies: units,
        metadata: units,
    }
}

fn finish(decoder: &mut Decoder, now: Tick, units: usize) -> Result {
    for _ in 0..100_000 {
        match decoder.step(now, budget(units))? {
            DecodeStep::Pending(_) => (),
            DecodeStep::Accepted { .. } => return Ok(()),
            other => return Err(format!("unexpected decode result: {other:?}").into()),
        }
    }
    Err("decoder service bound exhausted".into())
}

fn original(id: u32) -> Vec<u8> {
    let length = id as usize % 64 + 1;
    (0..length)
        .map(|offset| (id.wrapping_mul(73) as u8) ^ offset as u8)
        .collect()
}

fn drain(decoder: &mut Decoder, received: &mut u32, now: Tick) -> Result {
    while let Some((id, bytes)) = decoder.pending_source() {
        assert_eq!(id.0, *received);
        assert_eq!(bytes, original(id.0));
        decoder.confirm_handoff(id, now)?;
        *received += 1;
    }
    Ok(())
}

#[test]
fn two_independent_endpoints_cross_sixteen_windows_with_loss_and_reorder() -> Result {
    for handoff in [1, 3, 8] {
        let config = config(handoff);
        let mut sender = Encoder::new(config, scope(), Tick(0))?;
        let mut receiver = Decoder::new(config, scope(), Tick(0))?;
        let mut received = 0;
        for batch in 0..16_u32 {
            let now = Tick(u64::from(batch));
            let first = batch * 8;
            for id in first..first + 8 {
                assert_eq!(sender.admit_source(&original(id), now)?, SourceId(id));
            }
            // Odd windows lose every systematic record. Even windows deliver
            // only selected records in reverse order, including future columns.
            if batch % 2 == 0 {
                for id in (first..first + 8).rev().filter(|id| id % 3 == 0) {
                    assert_eq!(
                        receiver.begin_source(scope(), SourceId(id), &original(id), now)?,
                        Begin::Staged
                    );
                    finish(&mut receiver, now, 17)?;
                    drain(&mut receiver, &mut received, now)?;
                }
            }
            for attempt in 0..64 {
                if received == first + 8 {
                    break;
                }
                sender.begin_repair(attempt % 3 == 0, now)?;
                for _ in 0..100_000 {
                    sender.step(now, budget(19))?;
                    if sender.pending_repair().is_some() {
                        break;
                    }
                }
                let mut wire = vec![0; config.width()?];
                let (id, support, length) = sender.take_repair(&mut wire, now)?;
                let extent = (support.start..support.end)
                    .map(|source| 2 + original(source).len())
                    .max()
                    .ok_or("empty repair support")?;
                assert_eq!(length, extent);
                wire.truncate(length);
                let packet = Repair {
                    scope: scope(),
                    id,
                    support,
                    bytes: &wire,
                };
                let begin = receiver.begin_repair(packet, now)?;
                if begin == Begin::Staged {
                    finish(&mut receiver, now, 23)?;
                }
                drain(&mut receiver, &mut received, now)?;
                sender.confirm_prefix(receiver.status().decoded_prefix, now)?;
            }
            assert_eq!(
                received,
                first + 8,
                "finite repair bound, handoff={handoff}, batch={batch}"
            );
            sender.confirm_prefix(receiver.status().decoded_prefix, now)?;
            assert_eq!(sender.deadline(), None);
            assert_eq!(receiver.deadline(), None);
            assert!(receiver.status().known_sources <= 2 * config.window);
        }
        assert_eq!(received, 128);
    }
    // The rolling owner did not widen the unrelated sealed-generation contract.
    assert_eq!(l2tunnel_fec::MAX_SOURCES, 256);
    Ok(())
}

#[test]
fn runtime_deadline_overflow_is_terminal_before_new_input_is_owned() -> Result {
    let start = Tick(u64::MAX - 1001);
    let late = Tick(u64::MAX - 50);
    let mut sender = Encoder::new(config(8), scope(), start)?;
    sender.admit_source(b"unconfirmed", start)?;
    assert_eq!(sender.begin_repair(true, late), Err(Error::Exhausted));
    assert_eq!(sender.status().terminal, Some(Error::Exhausted));
    assert!(!sender.status().pending_repair);
    assert_eq!(sender.step(late, budget(1)), Err(Error::Terminal));

    let mut receiver = Decoder::new(config(8), scope(), start)?;
    receiver.begin_source(scope(), SourceId(1), b"future", start)?;
    finish(&mut receiver, start, 65_536)?;
    let before = receiver.status();
    assert_eq!(
        receiver.begin_source(scope(), SourceId(0), b"gap", late),
        Err(Error::Exhausted)
    );
    assert_eq!(receiver.status().terminal, Some(Error::Exhausted));
    assert!(!receiver.status().pending_job);
    assert_eq!(receiver.status().known_sources, before.known_sources);
    assert_eq!(receiver.status().decoded_prefix, before.decoded_prefix);
    Ok(())
}

#[test]
fn exact_owner_reservations_reject_one_byte_short() -> Result {
    let c = config(8);
    let encoder_bytes = Encoder::memory_bound(c)?;
    let decoder_bytes = Decoder::memory_bound(c)?;
    let sender = Config {
        memory_bytes: encoder_bytes,
        ..c
    };
    let receiver = Config {
        memory_bytes: decoder_bytes,
        ..c
    };
    assert!(Encoder::new(sender, scope(), Tick(0)).is_ok());
    assert!(Decoder::new(receiver, scope(), Tick(0)).is_ok());
    assert!(matches!(
        Encoder::new(
            Config {
                memory_bytes: encoder_bytes - 1,
                ..c
            },
            scope(),
            Tick(0)
        ),
        Err(Error::Capacity)
    ));
    assert!(matches!(
        Decoder::new(
            Config {
                memory_bytes: decoder_bytes - 1,
                ..c
            },
            scope(),
            Tick(0)
        ),
        Err(Error::Capacity)
    ));
    Ok(())
}
