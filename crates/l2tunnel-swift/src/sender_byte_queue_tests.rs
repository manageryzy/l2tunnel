//! Packing regressions for `sender`; only local packing storage is rearranged.

use super::*;
use crate::{Receiver, SOURCE_HEADER};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn config() -> Config {
    Config {
        datagram_bytes: 64,
        window: 4,
        repair_numerator: 0,
        repair_denominator: 1000,
        flow_sources: 16,
        queue_bytes: 1024,
        max_packet: 128,
        flush_micros: 1000,
        feedback_micros: 2000,
        tail_micros: 10_000,
        min_rto_micros: 20_000,
        max_rto_micros: 1_000_000,
    }
}

fn wrap_existing_queue(sender: &mut Sender, first: usize) {
    let bytes: Vec<_> = sender.queue.iter().copied().collect();
    assert!(first > 0 && first < bytes.len());
    let mut queue = VecDeque::with_capacity(bytes.len() + 8);
    let capacity = queue.capacity();
    queue.resize(capacity - first, 0xEE);
    queue.extend(&bytes[..first]);
    drop(queue.drain(..capacity - first));
    queue.extend(&bytes[first..]);
    assert_eq!(queue.as_slices().0.len(), first);
    assert!(!queue.as_slices().1.is_empty());
    assert_eq!(queue.iter().copied().collect::<Vec<_>>(), bytes);
    // Trusted local storage geometry only: every byte was admitted through
    // push_packet, and all sequence, source, timing and counter state is intact.
    sender.queue = queue;
}

#[test]
fn wrapped_packing_keeps_exact_symbols_partial_flush_and_retained_retransmission() -> TestResult {
    let config = config();
    let mut sender = Sender::new(config)?;
    let mut receiver = Receiver::new(config)?;
    let first = vec![0xA3; config.symbol_bytes() - 3];
    let second: Vec<_> = (0..80).map(|index| index as u8).collect();
    assert!(sender.push_packet(100, &first)?);
    assert!(sender.push_packet(100, &second)?);
    let packed: Vec<_> = sender.queue.iter().copied().collect();
    wrap_existing_queue(&mut sender, 17);
    let mut body = Vec::new();
    assert!(sender.poll(100, 0, &mut body)?);
    let original = body.clone();
    assert_eq!(body[0], KIND_SOURCE);
    assert_eq!(&body[1..SOURCE_HEADER], &0u32.to_be_bytes());
    assert_eq!(&body[SOURCE_HEADER..], &packed[..config.symbol_bytes()]);
    assert_eq!(
        sender.queue.iter().copied().collect::<Vec<_>>(),
        &packed[config.symbol_bytes()..]
    );
    assert_eq!(
        sender
            .sources
            .front()
            .ok_or("missing retained source")?
            .payload,
        packed[..config.symbol_bytes()]
    );

    assert!(sender.poll(100, 1, &mut body)?);
    assert_eq!(
        &body[SOURCE_HEADER..],
        &packed[config.symbol_bytes()..2 * config.symbol_bytes()]
    );
    // Deliver the real second source, withholding only the first source.
    receiver.on_datagram(1, &body)?;
    assert!(!sender.poll(1099, 2, &mut body)?);
    assert_eq!(sender.deadline(), Some(1100));
    let remainder = packed.len() - 2 * config.symbol_bytes();
    assert_eq!(sender.queued(), remainder);
    assert_eq!(
        sender.stats().packed_bytes,
        (2 * config.symbol_bytes()) as u64
    );

    // With no new source between feedback rounds, the real receiver requests
    // the missing first source. No sequence or recovery state is fabricated.
    assert!(receiver.feedback(2000, &mut body));
    sender.on_feedback(2000, &body)?;
    assert!(receiver.feedback(4000, &mut body));
    sender.on_feedback(4000, &body)?;
    assert!(sender.urgent());
    assert!(sender.poll(4000, 2, &mut body)?);
    assert_eq!(body, original);
    assert_eq!(sender.queued(), remainder);
    assert_eq!(sender.stats().sources, 2);
    assert_eq!(sender.stats().retransmits, 1);
    assert_eq!(
        sender.stats().packed_bytes,
        (2 * config.symbol_bytes()) as u64
    );
    assert_eq!(
        sender
            .sources
            .front()
            .ok_or("source lost after retransmission")?
            .payload,
        &original[SOURCE_HEADER..]
    );
    assert_eq!(sender.deadline(), Some(1100));
    // The remainder is still the exact queued suffix and becomes a third source
    // without clearing or reusing either retained earlier source payload.
    assert!(sender.poll(4000, 3, &mut body)?);
    assert_eq!(&body[1..SOURCE_HEADER], &2u32.to_be_bytes());
    assert_eq!(&body[SOURCE_HEADER..], &packed[2 * config.symbol_bytes()..]);
    assert_eq!(sender.queued(), 0);
    assert_eq!(
        sender
            .sources
            .front()
            .ok_or("source retention changed")?
            .payload,
        &original[SOURCE_HEADER..]
    );
    Ok(())
}
