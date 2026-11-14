//! Native identity regressions; physical device completion is not exercised.
//!
//! Normal packets, packing, source loss and feedback use public engine APIs.
//! The only private state setup seeds counters that cannot be reached in a
//! finite test; no source, ready bit, header context or stream is fabricated.

use super::*;

const FIRST_SOURCE: u64 = 1 << 40;
const FIRST_FEEDBACK: u64 = 1 << 48;
const NEW_FLOOR: RecordNumber = RecordNumber(1 << 52);

fn channel(index: usize) -> Result<ChannelId, Error> {
    ChannelId::new(index).ok_or(Error::Configuration)
}

fn identity(index: usize, record: u64) -> Result<NativeIdentity, Error> {
    Ok(NativeIdentity {
        channel: channel(index)?,
        record: NativeRecordId(record),
    })
}

fn count(engine: &Engine, direction: Direction, index: usize) -> Result<u64, Error> {
    let id = channel(index)?;
    let boundary = engine.boundary(direction, id).ok_or(Error::Admission)?;
    assert_eq!(boundary.direction, direction);
    assert_eq!(boundary.channel, id);
    Ok(boundary.count.0)
}

fn accepted(engine: &mut Engine, now: u64, bytes: &[u8]) -> Result<NativeIdentity, Error> {
    match engine.offer_identified(now, bytes)? {
        IdentifiedAdmission::Accepted(id) => Ok(id),
        _ => Err(Error::Admission),
    }
}

fn popped(engine: &mut Engine) -> Result<Option<(NativeIdentity, Vec<u8>)>, Error> {
    Ok(engine
        .pop_identified()?
        .map(|packet| (packet.identity, packet.bytes.to_vec())))
}

fn ports(channels: usize) -> Result<Vec<u16>, Error> {
    let mut result = vec![None; channels];
    for port in 0..=u16::MAX {
        let index = crate::flow::classify_ip(&packet(port, 0, 8), channels);
        if result[index].is_none() {
            result[index] = Some(port);
        }
        if result.iter().all(Option::is_some) {
            break;
        }
    }
    result
        .into_iter()
        .map(|port| port.ok_or(Error::Admission))
        .collect()
}

fn sources(engine: &mut Engine, now: u64, next: &mut u64) -> Result<Vec<(u64, Vec<u8>)>, Error> {
    let mut result = Vec::new();
    for _ in 0..128 {
        let Some(bytes) = engine.poll(now, RecordNumber(*next), true)? else {
            return Ok(result);
        };
        assert_eq!(bytes[0] & crate::KIND_MASK, crate::KIND_SOURCE);
        result.push((*next, bytes.to_vec()));
        *next += 1;
    }
    Err(Error::Admission)
}

fn deliver(receiver: &mut Engine, now: u64, wire: &[(u64, Vec<u8>)]) -> Result<(), Error> {
    for (number, bytes) in wire {
        receiver.accept(now, RecordNumber(*number), &mut bytes.clone())?;
    }
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct Snapshot {
    send: Config,
    receive: Config,
    stats: Stats,
    channels: Vec<Option<ChannelStats>>,
    admitted: Vec<Option<ChannelBoundary>>,
    extracted: Vec<Option<ChannelBoundary>>,
    source_floor: RecordNumber,
    feedback_floor: RecordNumber,
    body_limit: usize,
    data_deadline: Option<u64>,
    feedback_deadline: Option<u64>,
    deliverable: bool,
}

pub(super) fn snapshot(engine: &Engine) -> Result<Snapshot, Error> {
    let mut admitted = Vec::new();
    let mut extracted = Vec::new();
    for index in 0..crate::MAX_CHANNELS {
        let id = channel(index)?;
        admitted.push(engine.boundary(Direction::Send, id));
        extracted.push(engine.boundary(Direction::Receive, id));
    }
    Ok(Snapshot {
        send: engine.send_config(),
        receive: engine.receive_config(),
        stats: engine.stats(),
        channels: (0..crate::MAX_CHANNELS)
            .map(|index| engine.channel_stats(index))
            .collect(),
        admitted,
        extracted,
        source_floor: engine.source_floor(),
        feedback_floor: engine.feedback_floor(),
        body_limit: engine.body_limit(),
        data_deadline: engine.data_deadline(),
        feedback_deadline: engine.feedback_deadline(),
        deliverable: engine.deliverable(),
    })
}

#[test]
fn checked_channels_and_local_direction_boundaries_are_explicit() -> Result<(), Error> {
    assert_eq!(ChannelId::new(0).ok_or(Error::Admission)?.index(), 0);
    assert_eq!(ChannelId::new(63).ok_or(Error::Admission)?.index(), 63);
    assert!(ChannelId::new(64).is_none());
    assert!(ChannelId::new(usize::MAX).is_none());
    let mut engine = Engine::new(config(4))?;
    engine.replace_receive(config(2), RecordNumber(0))?;
    for index in 0..4 {
        assert_eq!(count(&engine, Direction::Send, index)?, 0);
        if index < 2 {
            assert_eq!(count(&engine, Direction::Receive, index)?, 0);
        } else {
            assert!(
                engine
                    .boundary(Direction::Receive, channel(index)?)
                    .is_none()
            );
        }
    }
    assert!(engine.boundary(Direction::Send, channel(4)?).is_none());
    Ok(())
}

#[test]
fn packed_compressed_records_keep_per_channel_fifo_through_rotation() -> Result<(), Error> {
    let c = config(4);
    let mut sender = Engine::new(c)?;
    let mut receiver = Engine::new(c)?;
    let ports = ports(c.channels)?;
    let mut expected = vec![Vec::new(); c.channels];
    for ordinal in 0..3 {
        for (index, port) in ports.iter().copied().enumerate() {
            let native = packet(port, ordinal, 8);
            assert_eq!(
                accepted(&mut sender, 0, &native)?,
                identity(index, u64::from(ordinal))?
            );
            expected[index].push(native);
        }
    }
    assert!(sender.stats().header_bytes_saved > 0);
    let mut next = FIRST_SOURCE;
    let mut wire = sources(&mut sender, 0, &mut next)?;
    assert_eq!(
        wire.len(),
        c.channels,
        "three native records fit one source per channel"
    );
    assert_eq!(sender.stats().sender.sources, 4);
    assert_eq!(sender.stats().sender.packets, 12);
    // Reverse physical arrival does not change the channel cursor or FIFO IDs.
    wire.reverse();
    deliver(&mut receiver, 0, &wire)?;
    for index in 0..c.channels {
        assert_eq!(count(&receiver, Direction::Receive, index)?, 0);
    }
    for (ordinal, _) in expected[0].iter().enumerate() {
        for (index, packets) in expected.iter().enumerate() {
            let (id, bytes) = popped(&mut receiver)?.ok_or(Error::Admission)?;
            assert_eq!(id, identity(index, ordinal as u64)?);
            assert_eq!(bytes, packets[ordinal]);
            assert!(id.record.0 < FIRST_SOURCE);
        }
    }
    assert!(popped(&mut receiver)?.is_none());
    assert!(receiver.receive_drained());
    for index in 0..c.channels {
        assert_eq!(count(&sender, Direction::Send, index)?, 3);
        assert_eq!(count(&receiver, Direction::Receive, index)?, 3);
    }
    Ok(())
}

#[test]
fn actual_source_loss_retransmission_and_duplicates_allocate_no_extra_native_ids()
-> Result<(), Error> {
    let c = config(2);
    let ports = ports(2)?;
    let mut sender = Engine::new(c)?;
    let mut receiver = Engine::new(c)?;
    let mut expected = vec![Vec::new(); 2];
    for ordinal in 0..3 {
        for index in 0..2 {
            let native = packet(ports[index], ordinal, 360);
            assert_eq!(
                accepted(&mut sender, 0, &native)?,
                identity(index, u64::from(ordinal))?
            );
            expected[index].push(native);
        }
    }
    let mut next_source = FIRST_SOURCE;
    let mut next_feedback = FIRST_FEEDBACK;
    let initial = sources(&mut sender, 0, &mut next_source)?;
    let mut dropped = 0;
    let mut duplicate_body = None;
    for (number, mut bytes) in initial {
        let index = usize::from(bytes[0] >> 2);
        let sequence = u32::from_be_bytes(bytes[1..5].try_into().map_err(|_| Error::Admission)?);
        if index == 0 && sequence == 0 {
            dropped += 1;
            continue;
        }
        if duplicate_body.is_none() {
            duplicate_body = Some(bytes.clone());
        }
        receiver.accept(0, RecordNumber(number), &mut bytes)?;
    }
    assert_eq!(dropped, 1);
    let mut duplicate = duplicate_body.ok_or(Error::Admission)?;
    receiver.accept(0, RecordNumber(next_source), &mut duplicate)?;
    next_source += 1;
    let mut extracted = [0_usize; 2];
    let mut finished = false;
    for tick in 1..20_000_u64 {
        let now = tick * 100;
        for _ in 0..16 {
            let Some((id, bytes)) = popped(&mut receiver)? else {
                break;
            };
            let index = id.channel.index();
            assert_eq!(id.record.0, extracted[index] as u64);
            assert_eq!(bytes, expected[index][extracted[index]]);
            extracted[index] += 1;
        }
        if let Some(feedback) = receiver.poll(now, RecordNumber(next_feedback), false)? {
            let mut feedback = feedback.to_vec();
            sender.accept(now, RecordNumber(next_feedback), &mut feedback)?;
            next_feedback += 1;
        }
        for _ in 0..16 {
            let Some(bytes) = sender.poll(now, RecordNumber(next_source), true)? else {
                break;
            };
            let mut bytes = bytes.to_vec();
            receiver.accept(now, RecordNumber(next_source), &mut bytes)?;
            next_source += 1;
        }
        if extracted == [3, 3] && sender.send_drained() {
            finished = true;
            break;
        }
    }
    assert!(
        finished,
        "bounded public feedback/retransmission must finish"
    );
    assert!(sender.stats().sender.retransmits > 0);
    assert!(receiver.stats().receiver.duplicates > 0);
    assert!(sender.stats().header_bytes_saved > 0);
    assert_eq!(receiver.stats().receiver.packets, 6);
    for index in 0..2 {
        assert_eq!(count(&sender, Direction::Send, index)?, 3);
        assert_eq!(count(&receiver, Direction::Receive, index)?, 3);
    }
    Ok(())
}

#[test]
fn legacy_and_identified_calls_share_wire_bytes_and_one_native_id_space() -> Result<(), Error> {
    let c = config(2);
    let ports = ports(2)?;
    let mut left = Engine::new(c)?;
    let mut right = Engine::new(c)?;
    for ordinal in 0..4 {
        for (index, port) in ports.iter().copied().enumerate() {
            let native = packet(port, ordinal, 16);
            if ordinal % 2 == 0 {
                assert_eq!(left.offer(0, &native)?, Admission::Accepted);
                assert_eq!(
                    accepted(&mut right, 0, &native)?,
                    identity(index, u64::from(ordinal))?
                );
            } else {
                assert_eq!(
                    accepted(&mut left, 0, &native)?,
                    identity(index, u64::from(ordinal))?
                );
                assert_eq!(right.offer(0, &native)?, Admission::Accepted);
            }
        }
    }
    let mut left_receiver = Engine::new(c)?;
    let mut right_receiver = Engine::new(c)?;
    for number in FIRST_SOURCE..FIRST_SOURCE + 16 {
        let a = left
            .poll(0, RecordNumber(number), true)?
            .map(<[u8]>::to_vec);
        let b = right
            .poll(0, RecordNumber(number), true)?
            .map(<[u8]>::to_vec);
        assert_eq!(a, b);
        if let Some(bytes) = a {
            left_receiver.accept(0, RecordNumber(number), &mut bytes.clone())?;
            right_receiver.accept(0, RecordNumber(number), &mut bytes.clone())?;
        } else {
            break;
        }
    }
    for ordinal in 0..4 {
        for (index, port) in ports.iter().copied().enumerate() {
            let expected = packet(port, ordinal, 16);
            if ordinal % 2 == 0 {
                assert_eq!(left_receiver.pop()?, Some(expected.as_slice()));
                assert_eq!(
                    popped(&mut right_receiver)?,
                    Some((identity(index, u64::from(ordinal))?, expected))
                );
            } else {
                assert_eq!(right_receiver.pop()?, Some(expected.as_slice()));
                assert_eq!(
                    popped(&mut left_receiver)?,
                    Some((identity(index, u64::from(ordinal))?, expected))
                );
            }
        }
    }
    assert!(left_receiver.pop()?.is_none());
    assert!(right_receiver.pop_identified()?.is_none());
    for index in 0..2 {
        assert_eq!(count(&left, Direction::Send, index)?, 4);
        assert_eq!(count(&right, Direction::Send, index)?, 4);
        assert_eq!(count(&left_receiver, Direction::Receive, index)?, 4);
        assert_eq!(count(&right_receiver, Direction::Receive, index)?, 4);
    }
    assert_eq!(left.stats(), right.stats());
    assert_eq!(left_receiver.stats(), right_receiver.stats());
    for (step, now) in [100, 200, 300].into_iter().enumerate() {
        assert_eq!(
            left_receiver.poll(now, RecordNumber(FIRST_FEEDBACK + step as u64), false)?,
            right_receiver.poll(now, RecordNumber(FIRST_FEEDBACK + step as u64), false)?
        );
    }
    Ok(())
}

#[test]
fn receive_identity_uses_accepted_source_channel_not_reclassified_native_bytes() -> Result<(), Error>
{
    let ports = ports(2)?;
    let native = packet(ports[1], 0, 16);
    assert_eq!(crate::flow::classify_ip(&native, 2), 1);
    // Authenticated body grammar permits a peer to place a literal in channel0.
    // The pure engine is not the global policy/configuration authentication gate.
    let mut sender = Engine::new(config(1))?;
    let mut receiver = Engine::new(config(2))?;
    assert_eq!(accepted(&mut sender, 0, &native)?, identity(0, 0)?);
    let mut source = body(&mut sender, 0, FIRST_SOURCE, true)?;
    assert_eq!(source[0] >> 2, 0);
    receiver.accept(0, RecordNumber(FIRST_SOURCE), &mut source)?;
    assert_eq!(popped(&mut receiver)?, Some((identity(0, 0)?, native)));
    assert_eq!(count(&receiver, Direction::Receive, 0)?, 1);
    assert_eq!(count(&receiver, Direction::Receive, 1)?, 0);
    Ok(())
}

#[test]
fn refused_size_and_queue_admission_burn_no_identity_or_header_context() -> Result<(), Error> {
    let mut c = config(1);
    c.max_native = 96;
    c.codec.max_packet = 97;
    c.codec.queue_bytes = 99;
    let mut observed = Engine::new(c)?;
    let mut reference = Engine::new(c)?;
    let first = packet(40_000, 0, 56);
    let next = packet(40_000, 1, 56);
    assert_eq!(accepted(&mut observed, 0, &first)?, identity(0, 0)?);
    assert_eq!(accepted(&mut reference, 0, &first)?, identity(0, 0)?);
    assert_eq!(
        observed.offer_identified(0, &packet(40_000, 99, 56))?,
        IdentifiedAdmission::Full
    );
    assert_eq!(
        observed.offer_identified(0, &[])?,
        IdentifiedAdmission::PacketSize
    );
    assert_eq!(
        observed.offer_identified(0, &[0; 97])?,
        IdentifiedAdmission::PacketSize
    );
    assert_eq!(count(&observed, Direction::Send, 0)?, 1);
    assert_eq!(observed.stats().native_dropped, 3);
    assert_eq!(
        body(&mut observed, 0, FIRST_SOURCE, true)?,
        body(&mut reference, 0, FIRST_SOURCE, true)?
    );
    assert_eq!(accepted(&mut observed, 0, &next)?, identity(0, 1)?);
    assert_eq!(accepted(&mut reference, 0, &next)?, identity(0, 1)?);
    assert_eq!(
        body(&mut observed, 0, FIRST_SOURCE + 1, true)?,
        body(&mut reference, 0, FIRST_SOURCE + 1, true)?
    );
    assert_eq!(
        observed.stats().header_bytes_saved,
        reference.stats().header_bytes_saved
    );
    Ok(())
}

#[test]
fn last_admissible_native_id_then_exhaustion_preserves_context_and_stats() -> Result<(), Error> {
    let mut observed = Engine::new(config(1))?;
    let mut reference = Engine::new(config(1))?;
    // Saturation seam only: every retained byte still enters through offer.
    observed.admitted[0] = u64::MAX - 1;
    let first = packet(40_000, 0, 16);
    assert_eq!(
        accepted(&mut observed, 0, &first)?,
        identity(0, u64::MAX - 1)?
    );
    accepted(&mut reference, 0, &first)?;
    assert_eq!(count(&observed, Direction::Send, 0)?, u64::MAX);
    let before = snapshot(&observed)?;
    assert_eq!(
        observed.offer_identified(0, &packet(40_000, 1, 16)),
        Err(Error::CounterExhausted)
    );
    assert_eq!(snapshot(&observed)?, before);
    assert_eq!(
        observed.offer(0, &packet(40_000, 1, 16)),
        Err(Error::CounterExhausted)
    );
    assert_eq!(snapshot(&observed)?, before);
    observed.admitted[0] = 1;
    assert_eq!(
        accepted(&mut observed, 0, &packet(40_000, 1, 16))?,
        identity(0, 1)?
    );
    accepted(&mut reference, 0, &packet(40_000, 1, 16))?;
    assert_eq!(
        body(&mut observed, 0, FIRST_SOURCE, true)?,
        body(&mut reference, 0, FIRST_SOURCE, true)?
    );
    assert_eq!(observed.stats(), reference.stats());
    Ok(())
}

#[test]
fn aggregate_native_admission_and_refusal_counter_exhaustion_are_atomic() -> Result<(), Error> {
    let mut observed = Engine::new(config(1))?;
    let mut reference = Engine::new(config(1))?;
    observed.base.native_read = u64::MAX;
    let before = snapshot(&observed)?;
    assert_eq!(
        observed.offer_identified(0, &packet(40_000, 99, 16)),
        Err(Error::CounterExhausted)
    );
    assert_eq!(snapshot(&observed)?, before);
    observed.base.native_read = 0;
    observed.base.native_dropped = u64::MAX;
    let before = snapshot(&observed)?;
    assert_eq!(
        observed.offer_identified(0, &[]),
        Err(Error::CounterExhausted)
    );
    assert_eq!(observed.offer(0, &[0; 701]), Err(Error::CounterExhausted));
    assert_eq!(snapshot(&observed)?, before);
    observed.base.native_dropped = 0;
    let native = packet(40_000, 0, 16);
    assert_eq!(accepted(&mut observed, 0, &native)?, identity(0, 0)?);
    assert_eq!(accepted(&mut reference, 0, &native)?, identity(0, 0)?);
    assert_eq!(
        body(&mut observed, 0, FIRST_SOURCE, true)?,
        body(&mut reference, 0, FIRST_SOURCE, true)?
    );
    assert_eq!(observed.stats(), reference.stats());

    let mut c = config(1);
    c.max_native = 96;
    c.codec.max_packet = 97;
    c.codec.queue_bytes = 99;
    let mut full = Engine::new(c)?;
    accepted(&mut full, 0, &packet(40_000, 0, 56))?;
    full.base.native_dropped = u64::MAX;
    let before = snapshot(&full)?;
    assert_eq!(
        full.offer_identified(0, &packet(40_000, 1, 56)),
        Err(Error::CounterExhausted)
    );
    assert_eq!(snapshot(&full)?, before);
    Ok(())
}

#[test]
fn complete_receive_exhaustion_preserves_packet_context_and_channel_cursor() -> Result<(), Error> {
    let c = config(2);
    let ports = ports(2)?;
    let mut sender = Engine::new(c)?;
    let mut receiver = Engine::new(c)?;
    let mut reference = Engine::new(c)?;
    for ordinal in 0..2 {
        for port in ports.iter().copied() {
            accepted(&mut sender, 0, &packet(port, ordinal, 16))?;
        }
    }
    let mut number = FIRST_SOURCE;
    let wire = sources(&mut sender, 0, &mut number)?;
    deliver(&mut receiver, 0, &wire)?;
    deliver(&mut reference, 0, &wire)?;
    receiver.extracted[0] = u64::MAX;
    let before = snapshot(&receiver)?;
    assert_eq!(popped(&mut receiver), Err(Error::CounterExhausted));
    assert_eq!(snapshot(&receiver)?, before);
    assert_eq!(receiver.pop(), Err(Error::CounterExhausted));
    assert_eq!(snapshot(&receiver)?, before);
    receiver.extracted[0] = 0;
    for ordinal in 0..2 {
        for (index, port) in ports.iter().take(2).enumerate() {
            let expected = Some((identity(index, ordinal)?, packet(*port, ordinal as u32, 16)));
            assert_eq!(popped(&mut receiver)?, expected);
            assert_eq!(popped(&mut reference)?, expected);
        }
    }
    assert!(popped(&mut receiver)?.is_none());
    assert!(popped(&mut reference)?.is_none());
    assert_eq!(snapshot(&receiver)?, snapshot(&reference)?);
    Ok(())
}

#[test]
fn last_extracted_id_does_not_make_empty_receive_an_exhaustion_error() -> Result<(), Error> {
    let mut sender = Engine::new(config(1))?;
    let mut receiver = Engine::new(config(1))?;
    let native = packet(40_000, 0, 16);
    accepted(&mut sender, 0, &native)?;
    let mut bytes = body(&mut sender, 0, FIRST_SOURCE, true)?;
    receiver.accept(0, RecordNumber(FIRST_SOURCE), &mut bytes)?;
    receiver.extracted[0] = u64::MAX - 1;
    assert_eq!(
        popped(&mut receiver)?,
        Some((identity(0, u64::MAX - 1)?, native))
    );
    assert_eq!(count(&receiver, Direction::Receive, 0)?, u64::MAX);
    assert!(popped(&mut receiver)?.is_none());
    assert!(receiver.receive_drained());
    Ok(())
}

fn incomplete_at_exhaustion(prefix: bool) -> Result<(), Error> {
    let c = config(1);
    let mut sender = Engine::new(c)?;
    let mut receiver = Engine::new(c)?;
    let mut already_extracted = 0;
    if prefix {
        accepted(&mut sender, 0, &packet(40_000, 0, 204))?;
    }
    let ordinal = u32::from(prefix);
    let native = packet(40_000, ordinal, 360);
    accepted(&mut sender, 0, &native)?;
    let mut first = body(&mut sender, 0, FIRST_SOURCE, true)?;
    assert_eq!(first.len(), crate::SOURCE_HEADER + c.codec.symbol_bytes());
    receiver.accept(0, RecordNumber(FIRST_SOURCE), &mut first)?;
    if prefix {
        assert_eq!(
            popped(&mut receiver)?,
            Some((identity(0, 0)?, packet(40_000, 0, 204)))
        );
        already_extracted = 1;
    }
    // The hint is still set by actual ingress: do not clear it with an earlier
    // empty pop, which would fail to distinguish peek-before-counter behavior.
    assert!(receiver.deliverable());
    receiver.extracted[0] = u64::MAX;
    let stats = receiver.stats();
    assert!(popped(&mut receiver)?.is_none());
    assert_eq!(receiver.stats(), stats);
    assert_eq!(count(&receiver, Direction::Receive, 0)?, u64::MAX);
    assert!(!receiver.deliverable());
    assert!(!receiver.receive_drained());
    assert_eq!(
        receiver.replace_receive(config(2), NEW_FLOOR),
        Err(Error::NotDrained)
    );
    let mut next = FIRST_SOURCE + 1;
    let suffix = sources(&mut sender, 0, &mut next)?;
    assert!((1..=2).contains(&suffix.len()));
    deliver(&mut receiver, 0, &suffix)?;
    let before = snapshot(&receiver)?;
    assert_eq!(popped(&mut receiver), Err(Error::CounterExhausted));
    assert_eq!(snapshot(&receiver)?, before);
    receiver.extracted[0] = already_extracted;
    assert_eq!(
        popped(&mut receiver)?,
        Some((identity(0, already_extracted)?, native))
    );
    assert!(popped(&mut receiver)?.is_none());
    assert!(receiver.receive_drained());
    assert_eq!(
        count(&receiver, Direction::Receive, 0)?,
        already_extracted + 1
    );
    // Following deltas prove the rejected complete pop retained decompression
    // state and that no identity was minted for the incomplete prefix/payload.
    let following = packet(40_000, ordinal + 1, 16);
    accepted(&mut sender, 0, &following)?;
    let mut source = body(&mut sender, 0, next, true)?;
    receiver.accept(0, RecordNumber(next), &mut source)?;
    assert_eq!(
        popped(&mut receiver)?,
        Some((identity(0, already_extracted + 1)?, following))
    );
    Ok(())
}

#[test]
fn partial_prefix_mints_no_identity_even_at_extracted_counter_limit() -> Result<(), Error> {
    incomplete_at_exhaustion(true)
}

#[test]
fn partial_payload_mints_no_identity_even_at_extracted_counter_limit() -> Result<(), Error> {
    incomplete_at_exhaustion(false)
}

#[test]
fn asymmetric_direction_replacement_resets_only_its_drained_native_boundaries() -> Result<(), Error>
{
    let mut engine = Engine::new(config(4))?;
    engine.replace_receive(config(2), RecordNumber(0))?;
    let outgoing_ports = ports(4)?;
    let incoming_ports = ports(2)?;
    let outgoing = packet(outgoing_ports[3], 0, 16);
    assert_eq!(accepted(&mut engine, 0, &outgoing)?, identity(3, 0)?);
    let mut peer = Engine::new(config(2))?;
    let incoming = packet(incoming_ports[1], 0, 16);
    accepted(&mut peer, 0, &incoming)?;
    let mut wire = body(&mut peer, 0, FIRST_SOURCE, true)?;
    engine.accept(0, RecordNumber(FIRST_SOURCE), &mut wire)?;
    let before = snapshot(&engine)?;
    assert_eq!(
        engine.replace_send(config(1), NEW_FLOOR),
        Err(Error::NotDrained)
    );
    assert_eq!(
        engine.replace_receive(config(4), NEW_FLOOR),
        Err(Error::NotDrained)
    );
    assert_eq!(snapshot(&engine)?, before);
    assert_eq!(popped(&mut engine)?, Some((identity(1, 0)?, incoming)));
    assert!(popped(&mut engine)?.is_none());
    assert_eq!(count(&engine, Direction::Receive, 1)?, 1);
    // Receive reset preserves the queued opposite direction and its identity.
    engine.replace_receive(config(4), NEW_FLOOR)?;
    assert_eq!(count(&engine, Direction::Receive, 1)?, 0);
    assert_eq!(count(&engine, Direction::Send, 3)?, 1);
    assert!(!engine.send_drained());
    assert_eq!(engine.feedback_floor(), RecordNumber(0));
    let mut outgoing_receiver = Engine::new(config(4))?;
    let mut next = FIRST_SOURCE + 10;
    let outgoing_wire = sources(&mut engine, 0, &mut next)?;
    deliver(&mut outgoing_receiver, 0, &outgoing_wire)?;
    assert_eq!(
        popped(&mut outgoing_receiver)?,
        Some((identity(3, 0)?, outgoing))
    );
    assert!(popped(&mut outgoing_receiver)?.is_none());
    let mut feedback = body(&mut outgoing_receiver, 100, FIRST_FEEDBACK, false)?;
    engine.accept(100, RecordNumber(FIRST_FEEDBACK), &mut feedback)?;
    assert!(engine.send_drained());
    // Install new receive data before resetting send, so its nonzero opposite
    // count is demonstrably retained rather than merely remaining zero.
    let mut fresh_peer = Engine::new(config(4))?;
    let fresh_native = packet(outgoing_ports[2], 0, 16);
    accepted(&mut fresh_peer, 100, &fresh_native)?;
    let mut fresh = body(&mut fresh_peer, 100, NEW_FLOOR.0, true)?;
    engine.accept(100, NEW_FLOOR, &mut fresh)?;
    assert_eq!(popped(&mut engine)?, Some((identity(2, 0)?, fresh_native)));
    assert!(popped(&mut engine)?.is_none());
    engine.replace_send(config(1), NEW_FLOOR)?;
    assert_eq!(count(&engine, Direction::Send, 0)?, 0);
    assert!(engine.boundary(Direction::Send, channel(3)?).is_none());
    assert_eq!(count(&engine, Direction::Receive, 2)?, 1);
    assert_eq!(engine.source_floor(), NEW_FLOOR);
    assert_eq!(engine.feedback_floor(), NEW_FLOOR);
    assert_eq!(
        engine.stats().native_read,
        1,
        "cumulative admission totals do not reset"
    );
    assert_eq!(
        accepted(&mut engine, 100, &packet(40_000, 0, 16))?,
        identity(0, 0)?
    );
    assert_eq!(count(&engine, Direction::Receive, 2)?, 1);
    Ok(())
}

#[test]
fn drained_send_reset_preserves_opposite_receive_rotation_context_and_ids() -> Result<(), Error> {
    let c = config(4);
    let ports = ports(4)?;
    let mut sender = Engine::new(c)?;
    let mut receiver = Engine::new(c)?;
    let low = packet(ports[1], 0, 16);
    let high = packet(ports[3], 0, 16);
    accepted(&mut sender, 0, &low)?;
    accepted(&mut sender, 0, &high)?;
    let mut next = FIRST_SOURCE;
    deliver(&mut receiver, 0, &sources(&mut sender, 0, &mut next)?)?;
    assert_eq!(popped(&mut receiver)?, Some((identity(1, 0)?, low)));
    assert!(receiver.send_drained());
    assert!(!receiver.receive_drained());
    receiver.replace_send(config(1), NEW_FLOOR)?;
    assert_eq!(count(&receiver, Direction::Receive, 1)?, 1);
    assert_eq!(count(&receiver, Direction::Receive, 3)?, 0);
    let following = packet(ports[1], 1, 16);
    accepted(&mut sender, 0, &following)?;
    let mut wire = body(&mut sender, 0, next, true)?;
    receiver.accept(0, RecordNumber(next), &mut wire)?;
    assert_eq!(popped(&mut receiver)?, Some((identity(3, 0)?, high)));
    assert_eq!(popped(&mut receiver)?, Some((identity(1, 1)?, following)));
    assert!(popped(&mut receiver)?.is_none());
    assert!(receiver.receive_drained());
    assert_eq!(count(&receiver, Direction::Receive, 1)?, 2);
    assert_eq!(count(&receiver, Direction::Receive, 3)?, 1);
    assert_eq!(count(&receiver, Direction::Send, 0)?, 0);
    assert!(receiver.boundary(Direction::Send, channel(3)?).is_none());
    Ok(())
}

#[test]
fn malformed_compressed_record_does_not_allocate_an_extracted_identity() -> Result<(), Error> {
    let c = config(1);
    let mut sender = crate::Sender::new(c.codec)?;
    assert!(sender.push_packet(0, &[255])?);
    let mut bytes = Vec::new();
    assert!(sender.poll(0, FIRST_SOURCE, &mut bytes)?);
    let mut receiver = Engine::new(c)?;
    receiver.accept(0, RecordNumber(FIRST_SOURCE), &mut bytes)?;
    assert_eq!(
        popped(&mut receiver),
        Err(Error::Codec(crate::Error::Malformed))
    );
    assert_eq!(count(&receiver, Direction::Receive, 0)?, 0);
    // Authenticated malformed compression is terminal; no rollback or continued
    // session use is inferred from observing the unchanged identity boundary.
    Ok(())
}
