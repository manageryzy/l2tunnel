//! Unpacking regressions for `receiver`; all sequence state uses real datagrams.

use super::*;
use crate::Sender;

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
        flush_micros: 0,
        feedback_micros: 2000,
        tail_micros: 10_000,
        min_rto_micros: 20_000,
        max_rto_micros: 1_000_000,
    }
}

fn wrap_existing_stream(receiver: &mut Receiver, first: usize) {
    let bytes: Vec<_> = receiver.stream.iter().copied().collect();
    assert!(first > 0 && first < bytes.len());
    let mut stream = VecDeque::with_capacity(bytes.len() + 8);
    let capacity = stream.capacity();
    stream.resize(capacity - first, 0xEE);
    stream.extend(&bytes[..first]);
    drop(stream.drain(..capacity - first));
    stream.extend(&bytes[first..]);
    assert_eq!(stream.as_slices().0.len(), first);
    assert!(!stream.as_slices().1.is_empty());
    assert_eq!(stream.iter().copied().collect::<Vec<_>>(), bytes);
    // Only physical storage changes. Ordered bytes, source history, decoder,
    // sequence state, counters and deadlines came from on_datagram unchanged.
    receiver.stream = stream;
}

#[test]
fn source_boundary_inside_length_prefix_never_consumes_the_partial_prefix() -> TestResult {
    let config = config();
    let mut sender = Sender::new(config)?;
    let mut receiver = Receiver::new(config)?;
    let first = vec![0xA5; config.symbol_bytes() - 3];
    let second = vec![0x5A; 20];
    assert!(sender.push_packet(0, &first)?);
    assert!(sender.push_packet(0, &second)?);
    let mut body = Vec::new();
    assert!(sender.poll(0, 0, &mut body)?);
    assert_eq!(body.len(), SOURCE_HEADER + config.symbol_bytes());
    let retained = body[SOURCE_HEADER..].to_vec();
    receiver.on_datagram(0, &body)?;
    wrap_existing_stream(&mut receiver, 1);
    let mut output = vec![0xEE; 16];
    assert!(receiver.pop_packet(&mut output)?);
    assert_eq!(output, first);
    assert_eq!(receiver.stream.len(), 1);
    assert_eq!(receiver.stream.front().copied(), Some(0));
    let before = receiver.stream.clone();
    output.extend_from_slice(&[9, 8, 7]);
    assert!(!receiver.pop_packet(&mut output)?);
    assert!(output.is_empty());
    assert_eq!(receiver.stream, before);
    assert_eq!(
        receiver.slot(0).ok_or("source history disappeared")?,
        &retained
    );
    assert_eq!(receiver.stats().packets, 1);
    assert!(sender.poll(0, 1, &mut body)?);
    receiver.on_datagram(1, &body)?;
    assert!(receiver.pop_packet(&mut output)?);
    assert_eq!(output, second);
    assert!(!receiver.pop_packet(&mut output)?);
    assert!(output.is_empty());
    assert_eq!(receiver.stats().packets, 2);
    Ok(())
}

#[test]
fn real_received_packet_unpacks_with_wrapped_prefix_or_wrapped_body() -> TestResult {
    for first_segment in [1, 7] {
        let config = config();
        let mut sender = Sender::new(config)?;
        let mut receiver = Receiver::new(config)?;
        let packet: Vec<_> = (0..100).map(|index| index as u8).collect();
        assert!(sender.push_packet(0, &packet)?);
        let mut body = Vec::new();
        for seed in 0..2 {
            assert!(sender.poll(0, seed, &mut body)?);
            receiver.on_datagram(seed, &body)?;
        }
        let slots = receiver.slots.clone();
        let deadline = receiver.deadline();
        wrap_existing_stream(&mut receiver, first_segment);
        let mut output = Vec::with_capacity(128);
        output.extend_from_slice(&[0xEE; 9]);
        assert!(receiver.pop_packet(&mut output)?);
        assert_eq!(output, packet);
        assert!(receiver.stream.is_empty());
        assert_eq!(receiver.slots, slots);
        assert_eq!(receiver.deadline(), deadline);
        assert_eq!(receiver.stats().packets, 1);
        assert!(!receiver.pop_packet(&mut output)?);
        assert!(output.is_empty());
    }
    Ok(())
}

#[test]
fn incomplete_and_malformed_wrapped_packets_preserve_every_stream_byte() -> TestResult {
    for packed in [
        &[0, 4, 11, 12][..],
        &[0, 0, 11, 12][..],
        &[0, 129, 11, 12][..],
    ] {
        let config = config();
        let mut receiver = Receiver::new(config)?;
        let mut source = vec![KIND_SOURCE];
        source.extend_from_slice(&0u32.to_be_bytes());
        source.extend_from_slice(packed);
        receiver.on_datagram(0, &source)?;
        wrap_existing_stream(&mut receiver, 1);
        let before = receiver.stream.clone();
        let slots = receiver.slots.clone();
        let deadline = receiver.deadline();
        let stats = receiver.stats();
        let mut output = vec![0xEE; 12];
        if packed[1] == 4 {
            assert!(!receiver.pop_packet(&mut output)?);
        } else {
            assert_eq!(
                receiver.pop_packet(&mut output).err(),
                Some(Error::Malformed)
            );
        }
        assert!(output.is_empty());
        assert_eq!(receiver.stream, before);
        assert_eq!(receiver.slots, slots);
        assert_eq!(receiver.deadline(), deadline);
        assert_eq!(receiver.stats(), stats);
    }
    Ok(())
}
