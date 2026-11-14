//! Deterministic public-API coverage of bounded cross-channel native service.

use super::*;

fn channel_ports(channels: usize) -> Result<Vec<u16>, Error> {
    let mut ports = vec![None; channels];
    for port in 0..=u16::MAX {
        let channel = crate::flow::classify_ip(&packet(port, 0, 8), channels);
        if ports[channel].is_none() {
            ports[channel] = Some(port);
        }
        if ports.iter().all(Option::is_some) {
            return ports
                .into_iter()
                .map(|port| port.ok_or(Error::Admission))
                .collect();
        }
    }
    Err(Error::Admission)
}

struct Pair {
    sender: Engine,
    receiver: Engine,
    ports: Vec<u16>,
    number: u64,
}

impl Pair {
    fn new(channels: usize) -> Result<Self, Error> {
        Ok(Self {
            sender: Engine::new(config(channels))?,
            receiver: Engine::new(config(channels))?,
            ports: channel_ports(channels)?,
            number: 1 << 40,
        })
    }

    fn native(&self, channel: usize, counter: u32) -> Vec<u8> {
        packet(self.ports[channel], counter, 8)
    }

    fn enqueue(&mut self, channel: usize, counter: u32) -> Result<(), Error> {
        let native = self.native(channel, counter);
        assert_eq!(self.sender.offer(0, &native)?, Admission::Accepted);
        let mut wire = body(&mut self.sender, 0, self.number, true)?;
        assert_eq!(usize::from(wire[0] >> 2), channel);
        assert_eq!(wire[0] & crate::KIND_MASK, crate::KIND_SOURCE);
        self.receiver
            .accept(0, RecordNumber(self.number), &mut wire)?;
        self.number += 1;
        Ok(())
    }

    fn pop(&mut self) -> Result<Vec<u8>, Error> {
        self.receiver
            .pop()?
            .map(<[u8]>::to_vec)
            .ok_or(Error::Admission)
    }
}

#[test]
fn continuously_replenished_low_channel_cannot_starve_high_channel() -> Result<(), Error> {
    let mut pair = Pair::new(2)?;
    pair.enqueue(0, 0)?;
    pair.enqueue(1, 0)?;
    assert_eq!(pair.pop()?, pair.native(0, 0));

    // Every later call has a complete low-channel packet. The high channel
    // must still receive one of the two successful returns in each cycle.
    for counter in 0..8 {
        pair.enqueue(0, counter + 1)?;
        assert_eq!(pair.pop()?, pair.native(1, counter));
        if counter != 7 {
            pair.enqueue(1, counter + 1)?;
            assert_eq!(pair.pop()?, pair.native(0, counter + 1));
        }
    }
    assert_eq!(pair.pop()?, pair.native(0, 8));
    assert!(pair.receiver.pop()?.is_none());
    assert!(pair.receiver.receive_drained());
    assert_eq!(pair.receiver.stats().receiver.packets, 17);
    Ok(())
}

#[test]
fn replenished_all_sixty_four_channels_complete_one_bounded_cycle() -> Result<(), Error> {
    let mut pair = Pair::new(crate::MAX_CHANNELS)?;
    for channel in 0..crate::MAX_CHANNELS {
        pair.enqueue(channel, 0)?;
    }
    for channel in 0..crate::MAX_CHANNELS {
        assert_eq!(pair.pop()?, pair.native(channel, 0));
        pair.enqueue(channel, 1)?;
    }
    for channel in 0..crate::MAX_CHANNELS {
        assert_eq!(pair.pop()?, pair.native(channel, 1));
    }
    assert!(pair.receiver.pop()?.is_none());
    assert!(pair.receiver.receive_drained());
    assert_eq!(pair.receiver.stats().receiver.packets, 128);
    Ok(())
}

#[test]
fn sparse_ready_channels_wrap_past_replenished_low_channel() -> Result<(), Error> {
    let mut pair = Pair::new(crate::MAX_CHANNELS)?;
    for channel in [1, 31, 63] {
        pair.enqueue(channel, 0)?;
    }
    assert_eq!(pair.pop()?, pair.native(1, 0));
    pair.enqueue(1, 1)?;
    assert_eq!(pair.pop()?, pair.native(31, 0));
    assert_eq!(pair.pop()?, pair.native(63, 0));
    assert_eq!(pair.pop()?, pair.native(1, 1));
    assert!(pair.receiver.pop()?.is_none());
    assert!(pair.receiver.receive_drained());
    Ok(())
}

#[test]
fn incomplete_low_record_does_not_block_complete_high_record() -> Result<(), Error> {
    let mut pair = Pair::new(2)?;
    let large = packet(pair.ports[0], 0, 400);
    let high = pair.native(1, 0);
    assert_eq!(pair.sender.offer(0, &large)?, Admission::Accepted);
    let mut prefix = body(&mut pair.sender, 0, pair.number, true)?;
    assert_eq!(prefix[0] >> 2, 0);
    assert_eq!(
        prefix.len(),
        crate::SOURCE_HEADER + config(2).codec.symbol_bytes()
    );
    pair.receiver
        .accept(0, RecordNumber(pair.number), &mut prefix)?;
    pair.number += 1;

    // The first source has a genuine length prefix and only part of its native
    // record. A ready hint alone must not monopolize another channel's packet.
    assert!(pair.receiver.deliverable());
    assert_eq!(pair.sender.offer(0, &high)?, Admission::Accepted);
    let mut high_source = body(&mut pair.sender, 0, pair.number, true)?;
    assert_eq!(high_source[0] >> 2, 1);
    pair.receiver
        .accept(0, RecordNumber(pair.number), &mut high_source)?;
    pair.number += 1;
    assert_eq!(pair.pop()?, high);
    assert!(pair.receiver.pop()?.is_none());
    assert!(!pair.receiver.deliverable());
    assert_eq!(pair.receiver.stats().receiver.packets, 1);

    let mut suffix = body(&mut pair.sender, 0, pair.number, true)?;
    assert_eq!(suffix[0] >> 2, 0);
    pair.receiver
        .accept(0, RecordNumber(pair.number), &mut suffix)?;
    assert_eq!(pair.pop()?, large);
    assert!(pair.receiver.pop()?.is_none());
    assert!(pair.receiver.receive_drained());
    assert_eq!(pair.receiver.stats().receiver.packets, 2);
    Ok(())
}

#[test]
fn reordered_sources_preserve_exact_compressed_order_within_each_channel() -> Result<(), Error> {
    let mut pair = Pair::new(3)?;
    for counter in 0..4 {
        for channel in 0..3 {
            let native = packet(pair.ports[channel], counter, 180);
            assert_eq!(pair.sender.offer(0, &native)?, Admission::Accepted);
        }
    }
    let mut sources = Vec::new();
    while let Some(bytes) = pair.sender.poll(0, RecordNumber(pair.number), true)? {
        assert_eq!(bytes[0] & crate::KIND_MASK, crate::KIND_SOURCE);
        sources.push((RecordNumber(pair.number), bytes.to_vec()));
        pair.number += 1;
    }
    assert!(sources.len() > 3);
    assert!(pair.sender.stats().header_bytes_saved > 0);
    for (number, mut source) in sources.into_iter().rev() {
        pair.receiver.accept(0, number, &mut source)?;
    }

    let mut expected = [0_u32; 3];
    for _ in 0..12 {
        let native = pair.pop()?;
        let channel = crate::flow::classify_ip(&native, 3);
        assert_eq!(native, packet(pair.ports[channel], expected[channel], 180));
        expected[channel] += 1;
    }
    assert_eq!(expected, [4; 3]);
    assert!(pair.receiver.pop()?.is_none());
    assert!(pair.receiver.receive_drained());
    assert_eq!(pair.receiver.stats().receiver.packets, 12);
    Ok(())
}

#[test]
fn replacing_drained_send_direction_does_not_reset_receive_service() -> Result<(), Error> {
    let mut pair = Pair::new(crate::MAX_CHANNELS)?;
    pair.enqueue(9, 0)?;
    pair.enqueue(55, 0)?;
    assert_eq!(pair.pop()?, pair.native(9, 0));
    assert!(pair.receiver.send_drained());
    pair.receiver
        .replace_send(config(1), RecordNumber(1 << 48))?;
    assert_eq!(pair.receiver.send_config().channels, 1);
    assert_eq!(pair.receiver.receive_config().channels, crate::MAX_CHANNELS);
    assert_eq!(pair.receiver.feedback_floor(), RecordNumber(1 << 48));
    let last = pair.receiver.channel_stats(63).ok_or(Error::Admission)?;
    assert!(last.send.is_none());
    assert!(last.receive.is_some());

    pair.enqueue(9, 1)?;
    assert_eq!(pair.pop()?, pair.native(55, 0));
    assert_eq!(pair.pop()?, pair.native(9, 1));
    assert!(pair.receiver.pop()?.is_none());
    assert!(pair.receiver.receive_drained());
    Ok(())
}

#[test]
fn refused_receive_reset_keeps_pending_bytes_and_service_position() -> Result<(), Error> {
    let mut pair = Pair::new(2)?;
    pair.enqueue(0, 0)?;
    pair.enqueue(1, 0)?;
    assert_eq!(pair.pop()?, pair.native(0, 0));
    let before = pair.receiver.stats();
    assert_eq!(
        pair.receiver
            .replace_receive(config(1), RecordNumber(1 << 48)),
        Err(Error::NotDrained)
    );
    assert_eq!(pair.receiver.receive_config(), config(2));
    assert_eq!(pair.receiver.source_floor(), RecordNumber(0));
    assert_eq!(pair.receiver.stats(), before);

    pair.enqueue(0, 1)?;
    assert_eq!(pair.pop()?, pair.native(1, 0));
    assert_eq!(pair.pop()?, pair.native(0, 1));
    assert!(pair.receiver.pop()?.is_none());
    assert!(pair.receiver.receive_drained());
    Ok(())
}

#[test]
fn drained_receive_replacement_resets_cursor_and_preserves_asymmetric_state() -> Result<(), Error> {
    let mut pair = Pair::new(crate::MAX_CHANNELS)?;
    pair.receiver
        .replace_send(config(1), RecordNumber(1 << 48))?;
    pair.enqueue(0, 0)?;
    assert_eq!(pair.pop()?, pair.native(0, 0));
    assert!(pair.receiver.pop()?.is_none());
    assert!(pair.receiver.receive_drained());
    let mut feedback = body(&mut pair.receiver, 100, pair.number, false)?;
    pair.sender
        .accept(100, RecordNumber(pair.number), &mut feedback)?;
    assert!(pair.sender.send_drained());

    let floor = RecordNumber(1 << 50);
    let before = pair.receiver.stats();
    pair.sender.replace_send(config(4), floor)?;
    pair.receiver.replace_receive(config(4), floor)?;
    assert_eq!(pair.receiver.stats(), before);
    assert_eq!(pair.receiver.source_floor(), floor);
    assert_eq!(pair.receiver.feedback_floor(), RecordNumber(1 << 48));
    assert_eq!(pair.receiver.send_config().channels, 1);
    assert_eq!(pair.receiver.receive_config().channels, 4);
    pair.ports = channel_ports(4)?;
    pair.number = floor.0;
    pair.enqueue(0, 1)?;
    pair.enqueue(3, 1)?;
    // The preceding successful old receive left its cursor after channel0.
    // A drained receive replacement starts at channel0 in the new direction.
    assert_eq!(pair.pop()?, pair.native(0, 1));
    assert_eq!(pair.pop()?, pair.native(3, 1));
    assert!(pair.receiver.pop()?.is_none());
    assert!(pair.receiver.receive_drained());
    assert_eq!(pair.receiver.stats().receiver.packets, 3);
    let last = pair.receiver.channel_stats(3).ok_or(Error::Admission)?;
    assert!(last.send.is_none());
    assert!(last.receive.is_some());
    assert!(pair.receiver.channel_stats(4).is_none());
    Ok(())
}
