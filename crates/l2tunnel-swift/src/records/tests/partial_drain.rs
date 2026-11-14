//! Public-API regressions for native bytes retained after source advancement.

use super::*;

const FIRST_NUMBER: u64 = 1 << 40;
const DUPLICATE_NUMBER: RecordNumber = RecordNumber(1 << 44);
const REPLACEMENT_FLOOR: RecordNumber = RecordNumber(1 << 50);
const PORT: u16 = 40_000;

#[derive(Clone, Copy, Debug)]
enum Cut {
    Prefix,
    Payload,
}

#[derive(Debug, Eq, PartialEq)]
struct Observation {
    send: Config,
    receive: Config,
    source_floor: RecordNumber,
    feedback_floor: RecordNumber,
    body_limit: usize,
    stats: Stats,
    channel: Option<ChannelStats>,
    feedback_deadline: Option<u64>,
    data_deadline: Option<u64>,
}

fn observe(engine: &Engine) -> Observation {
    Observation {
        send: engine.send_config(),
        receive: engine.receive_config(),
        source_floor: engine.source_floor(),
        feedback_floor: engine.feedback_floor(),
        body_limit: engine.body_limit(),
        stats: engine.stats(),
        channel: engine.channel_stats(0),
        feedback_deadline: engine.feedback_deadline(),
        data_deadline: engine.data_deadline(),
    }
}

struct Partial {
    sender: Engine,
    receiver: Engine,
    native: Vec<u8>,
    first_source: Vec<u8>,
    next_number: u64,
    delivered_before_suffix: u64,
    next_counter: u32,
}

fn partial(cut: Cut) -> Result<Partial, Error> {
    let c = config(1);
    assert_eq!(c.codec.symbol_bytes(), 248);
    let mut sender = Engine::new(c)?;
    let mut receiver = Engine::new(c)?;
    let first = packet(PORT, 0, 204);
    let (counter, delivered_before_suffix) = if matches!(cut, Cut::Prefix) {
        // The initial literal-store record consumes 244 native bytes, one tag
        // and two length bytes. Only one byte of the next prefix fits source0.
        assert_eq!(first.len() + 1 + crate::FRAME_PREFIX, 247);
        assert_eq!(sender.offer(0, &first)?, Admission::Accepted);
        (1, 1)
    } else {
        (0, 0)
    };
    let native = packet(PORT, counter, 360);
    assert_eq!(native.len(), 400);
    assert_eq!(sender.offer(0, &native)?, Admission::Accepted);
    if matches!(cut, Cut::Prefix) {
        // This later record really depends on the preceding TCP context.
        assert!(sender.stats().header_bytes_saved > 0);
    }
    let first_source = body(&mut sender, 0, FIRST_NUMBER, true)?;
    assert_eq!(first_source[0], crate::KIND_SOURCE);
    assert_eq!(
        first_source.len(),
        crate::SOURCE_HEADER + c.codec.symbol_bytes()
    );
    receiver.accept(0, RecordNumber(FIRST_NUMBER), &mut first_source.clone())?;
    if matches!(cut, Cut::Prefix) {
        assert_eq!(receiver.pop()?, Some(first.as_slice()));
    }
    assert!(receiver.pop()?.is_none());
    assert!(!receiver.deliverable());
    let channel = receiver.channel_stats(0).ok_or(Error::Admission)?;
    assert_eq!(channel.receive_pending, 0);
    assert_eq!(channel.receive.ok_or(Error::Admission)?.sources, 1);
    assert_eq!(receiver.stats().receiver.packets, delivered_before_suffix);
    assert!(!sender.send_drained());
    Ok(Partial {
        sender,
        receiver,
        native,
        first_source,
        next_number: FIRST_NUMBER + 1,
        delivered_before_suffix,
        next_counter: counter + 1,
    })
}

fn suffix(partial: &mut Partial, now: u64) -> Result<(), Error> {
    let mut emitted = 0;
    for _ in 0..8 {
        let Some(source) = partial
            .sender
            .poll(now, RecordNumber(partial.next_number), true)?
        else {
            break;
        };
        let mut source = source.to_vec();
        assert_eq!(source[0], crate::KIND_SOURCE);
        partial
            .receiver
            .accept(now, RecordNumber(partial.next_number), &mut source)?;
        partial.next_number += 1;
        emitted += 1;
    }
    assert!((1..=2).contains(&emitted));
    assert_eq!(partial.receiver.pop()?, Some(partial.native.as_slice()));
    assert!(partial.receiver.pop()?.is_none());
    assert!(!partial.receiver.deliverable());
    assert!(partial.receiver.receive_drained());
    assert_eq!(
        partial.receiver.stats().receiver.packets,
        partial.delivered_before_suffix + 1
    );
    Ok(())
}

fn query_retains(cut: Cut) -> Result<(), Error> {
    let mut p = partial(cut)?;
    let before = observe(&p.receiver);
    assert!(
        !p.receiver.receive_drained(),
        "advanced source retains native cut {cut:?}"
    );
    assert!(!p.receiver.receive_drained());
    assert_eq!(observe(&p.receiver), before);
    suffix(&mut p, 0)
}

fn refuse_replacement(cut: Cut) -> Result<(), Error> {
    let mut p = partial(cut)?;
    let before = observe(&p.receiver);
    let mut replacement = config(2);
    replacement.codec.datagram_bytes = 512;
    assert_eq!(
        p.receiver.replace_receive(replacement, REPLACEMENT_FLOOR),
        Err(Error::NotDrained),
        "replacement must retain native cut {cut:?}"
    );
    assert_eq!(observe(&p.receiver), before);
    suffix(&mut p, 0)?;
    let delivered = p.receiver.stats();
    p.receiver.replace_receive(replacement, REPLACEMENT_FLOOR)?;
    assert_eq!(p.receiver.receive_config(), replacement);
    assert_eq!(p.receiver.send_config(), config(1));
    assert_eq!(p.receiver.source_floor(), REPLACEMENT_FLOOR);
    assert_eq!(p.receiver.feedback_floor(), before.feedback_floor);
    assert_eq!(p.receiver.stats(), delivered);

    // A newly installed floor rejects old source history before it can enter
    // the new channel/header state; current cumulative counters still persist.
    let duplicates = p.receiver.stats().receiver.duplicates;
    p.receiver
        .accept(0, DUPLICATE_NUMBER, &mut p.first_source.clone())?;
    assert!(p.receiver.pop()?.is_none());
    assert_eq!(p.receiver.stats().receiver.duplicates, duplicates + 1);
    assert!(p.receiver.receive_drained());
    let mut fresh_sender = Engine::new(replacement)?;
    let fresh_native = packet(PORT + 1, 0, 16);
    assert_eq!(fresh_sender.offer(0, &fresh_native)?, Admission::Accepted);
    let mut fresh = body(&mut fresh_sender, 0, REPLACEMENT_FLOOR.0, true)?;
    p.receiver.accept(0, REPLACEMENT_FLOOR, &mut fresh)?;
    assert_eq!(p.receiver.pop()?, Some(fresh_native.as_slice()));
    assert!(p.receiver.pop()?.is_none());
    assert!(p.receiver.receive_drained());
    assert_eq!(
        p.receiver.stats().receiver.packets,
        delivered.receiver.packets + 1
    );
    Ok(())
}

#[test]
fn advanced_source_with_partial_native_prefix_is_not_drained() -> Result<(), Error> {
    query_retains(Cut::Prefix)
}

#[test]
fn advanced_source_with_partial_native_payload_is_not_drained() -> Result<(), Error> {
    query_retains(Cut::Payload)
}

#[test]
fn partial_native_prefix_refuses_receive_replacement() -> Result<(), Error> {
    refuse_replacement(Cut::Prefix)
}

#[test]
fn partial_native_payload_refuses_receive_replacement() -> Result<(), Error> {
    refuse_replacement(Cut::Payload)
}

#[test]
fn refused_prefix_replacement_preserves_header_context_and_opposite_direction() -> Result<(), Error>
{
    let mut p = partial(Cut::Prefix)?;
    let local_native = packet(PORT + 2, 0, 32);
    assert_eq!(p.receiver.offer(0, &local_native)?, Admission::Accepted);
    let before = observe(&p.receiver);
    assert_eq!(
        p.receiver.replace_receive(config(2), REPLACEMENT_FLOOR),
        Err(Error::NotDrained)
    );
    assert_eq!(observe(&p.receiver), before);
    suffix(&mut p, 0)?;

    let next = packet(PORT, p.next_counter, 360);
    let saved = p.sender.stats().header_bytes_saved;
    assert_eq!(p.sender.offer(0, &next)?, Admission::Accepted);
    assert!(p.sender.stats().header_bytes_saved > saved);
    for _ in 0..4 {
        let Some(wire) = p.sender.poll(0, RecordNumber(p.next_number), true)? else {
            break;
        };
        let mut wire = wire.to_vec();
        p.receiver
            .accept(0, RecordNumber(p.next_number), &mut wire)?;
        p.next_number += 1;
    }
    assert_eq!(p.receiver.pop()?, Some(next.as_slice()));
    assert!(p.receiver.pop()?.is_none());
    assert!(p.receiver.receive_drained());
    assert_eq!(p.receiver.send_config(), before.send);
    assert_eq!(p.receiver.feedback_floor(), before.feedback_floor);
    assert_eq!(p.receiver.stats().sender, before.stats.sender);
    assert_eq!(p.receiver.stats().native_read, before.stats.native_read);
    assert_eq!(
        p.receiver.channel_stats(0).ok_or(Error::Admission)?.send,
        before.channel.ok_or(Error::Admission)?.send
    );
    Ok(())
}

#[test]
fn source_acknowledgement_does_not_complete_retained_native_bytes() -> Result<(), Error> {
    for cut in [Cut::Prefix, Cut::Payload] {
        let mut p = partial(cut)?;
        let mut feedback = body(&mut p.receiver, 100, 1 << 48, false)?;
        assert_eq!(feedback[0], crate::KIND_FEEDBACK);
        p.sender.accept(100, RecordNumber(1 << 48), &mut feedback)?;
        assert_eq!(p.sender.unconfirmed(), 0);
        assert!(!p.sender.send_drained());
        assert_eq!(
            p.receiver
                .channel_stats(0)
                .ok_or(Error::Admission)?
                .receive_pending,
            0
        );
        assert!(!p.receiver.receive_drained());
        suffix(&mut p, 100)?;
    }
    Ok(())
}

#[test]
fn duplicate_source_cannot_discard_partial_prefix_or_payload() -> Result<(), Error> {
    for cut in [Cut::Prefix, Cut::Payload] {
        let mut p = partial(cut)?;
        let before = p.receiver.stats();
        // A retransmitted source has a fresh outer number but the same inner
        // source sequence. Authentication/replay remain the caller's work.
        p.receiver
            .accept(0, DUPLICATE_NUMBER, &mut p.first_source.clone())?;
        assert!(p.receiver.pop()?.is_none());
        assert!(!p.receiver.deliverable());
        assert!(!p.receiver.receive_drained());
        assert_eq!(p.receiver.stats().receiver.packets, before.receiver.packets);
        assert_eq!(
            p.receiver.stats().receiver.duplicates,
            before.receiver.duplicates + 1
        );
        assert_eq!(
            p.receiver
                .channel_stats(0)
                .ok_or(Error::Admission)?
                .receive_pending,
            0
        );
        suffix(&mut p, 0)?;
    }
    Ok(())
}

#[test]
fn missing_source_blocks_replacement_until_exact_gap_recovery() -> Result<(), Error> {
    let c = config(1);
    let mut sender = Engine::new(c)?;
    let mut receiver = Engine::new(c)?;
    let native = packet(PORT, 0, 360);
    assert_eq!(sender.offer(0, &native)?, Admission::Accepted);
    let mut first = body(&mut sender, 0, FIRST_NUMBER, true)?;
    let mut second = body(&mut sender, 0, FIRST_NUMBER + 1, true)?;
    receiver.accept(0, RecordNumber(FIRST_NUMBER + 1), &mut second)?;
    assert!(receiver.pop()?.is_none());
    assert!(!receiver.deliverable());
    assert_eq!(
        receiver
            .channel_stats(0)
            .ok_or(Error::Admission)?
            .receive_pending,
        2
    );
    let before = observe(&receiver);
    assert!(!receiver.receive_drained());
    assert_eq!(
        receiver.replace_receive(c, REPLACEMENT_FLOOR),
        Err(Error::NotDrained)
    );
    assert_eq!(observe(&receiver), before);
    receiver.accept(0, RecordNumber(FIRST_NUMBER), &mut first)?;
    assert_eq!(receiver.pop()?, Some(native.as_slice()));
    assert!(receiver.pop()?.is_none());
    assert!(receiver.receive_drained());
    assert_eq!(receiver.stats().receiver.sources, 2);
    assert_eq!(receiver.stats().receiver.packets, 1);
    Ok(())
}

#[test]
fn delivered_history_and_repeated_feedback_do_not_obstruct_drain() -> Result<(), Error> {
    let c = config(1);
    let mut sender = Engine::new(c)?;
    let mut receiver = Engine::new(c)?;
    let native = packet(PORT, 0, 204);
    assert_eq!(sender.offer(0, &native)?, Admission::Accepted);
    let source = body(&mut sender, 0, FIRST_NUMBER, true)?;
    receiver.accept(0, RecordNumber(FIRST_NUMBER), &mut source.clone())?;
    assert_eq!(
        receiver
            .channel_stats(0)
            .ok_or(Error::Admission)?
            .receive_pending,
        0
    );
    assert!(!receiver.receive_drained());
    assert_eq!(receiver.pop()?, Some(native.as_slice()));
    assert!(receiver.pop()?.is_none());
    assert!(receiver.receive_drained());
    for (index, now) in [100, 200, 300].into_iter().enumerate() {
        assert!(receiver.feedback_deadline().is_some());
        let mut feedback = body(&mut receiver, now, (1 << 48) + index as u64, false)?;
        assert_eq!(feedback[0], crate::KIND_FEEDBACK);
        sender.accept(now, RecordNumber((1 << 48) + index as u64), &mut feedback)?;
        assert!(sender.send_drained());
        assert!(receiver.receive_drained());
    }
    assert_eq!(receiver.feedback_deadline(), None);
    let duplicates = receiver.stats().receiver.duplicates;
    receiver.accept(301, DUPLICATE_NUMBER, &mut source.clone())?;
    assert!(receiver.pop()?.is_none());
    assert_eq!(receiver.stats().receiver.duplicates, duplicates + 1);
    assert_eq!(receiver.stats().receiver.packets, 1);
    assert!(receiver.feedback_deadline().is_some());
    assert!(receiver.receive_drained());
    let before = receiver.stats();
    receiver.replace_receive(config(2), REPLACEMENT_FLOOR)?;
    assert_eq!(receiver.stats(), before);
    assert_eq!(receiver.receive_config().channels, 2);
    Ok(())
}

#[test]
fn complete_native_packet_still_requires_consumption_before_replacement() -> Result<(), Error> {
    let c = config(1);
    let mut sender = Engine::new(c)?;
    let mut receiver = Engine::new(c)?;
    let native = packet(PORT, 0, 16);
    assert_eq!(sender.offer(0, &native)?, Admission::Accepted);
    let mut source = body(&mut sender, 0, FIRST_NUMBER, true)?;
    receiver.accept(0, RecordNumber(FIRST_NUMBER), &mut source)?;
    assert_eq!(
        receiver
            .channel_stats(0)
            .ok_or(Error::Admission)?
            .receive_pending,
        0
    );
    assert!(receiver.deliverable());
    assert!(!receiver.receive_drained());
    let before = observe(&receiver);
    assert_eq!(
        receiver.replace_receive(c, REPLACEMENT_FLOOR),
        Err(Error::NotDrained)
    );
    assert_eq!(observe(&receiver), before);
    assert_eq!(receiver.pop()?, Some(native.as_slice()));
    assert!(receiver.pop()?.is_none());
    assert!(receiver.receive_drained());
    receiver.replace_receive(c, REPLACEMENT_FLOOR)?;
    Ok(())
}
