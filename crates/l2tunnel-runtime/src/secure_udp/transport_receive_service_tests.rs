//! Real protected-UDP receive service through a one-packet native output owner.

use super::*;

fn frame(port: u16, number: u8) -> Vec<u8> {
    let mut frame = vec![0; 46];
    frame[..12].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    let ip = &mut frame[14..];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&32_u16.to_be_bytes());
    ip[4..6].copy_from_slice(&u16::from(number).to_be_bytes());
    ip[6] = 0x40;
    ip[8] = 64;
    ip[9] = 17;
    ip[12..20].copy_from_slice(&[198, 18, 0, 1, 198, 18, 0, 2]);
    let sum: u32 = ip[..20]
        .chunks_exact(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], pair[1]])))
        .sum();
    let sum = (sum & 0xffff) + (sum >> 16);
    let sum = (sum & 0xffff) + (sum >> 16);
    ip[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    ip[20..22].copy_from_slice(&port.to_be_bytes());
    ip[22..24].copy_from_slice(&24_500_u16.to_be_bytes());
    ip[24..26].copy_from_slice(&12_u16.to_be_bytes());
    ip[28..32].fill(number);
    frame
}

fn port(channel: usize) -> Result<u16> {
    (40_000..40_256_u16)
        .find(|value| swift::flow::classify_ethernet(&frame(*value, 0), 2) == channel)
        .ok_or_else(|| "no classified receive-service fixture port".into())
}

fn drain_setup(socket: &tokio::net::UdpSocket) -> Result {
    let mut wire = [0; 1501];
    for _ in 0..128 {
        match socket.try_recv(&mut wire) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error.into()),
        }
    }
    Err("receive-service fixture setup drain exceeded its bound".into())
}

fn sealed_source(driver: &mut Driver, now: u64) -> Result<Vec<u8>> {
    let seed = driver.records.next_number(Class::User);
    let body = driver
        .swift
        .poll(now, records::RecordNumber(seed.0), true)?
        .ok_or_else(|| protocol("receive-service fixture source not emitted"))?;
    assert_eq!(body[0] & swift::KIND_MASK, swift::KIND_SOURCE);
    let mut wire = vec![0; driver.cover.limits().max_packet_bytes];
    let sealed = driver.records.seal_user_in(
        driver.source_scope,
        meta(driver.outer, cover::Phase::Established),
        body,
        &mut driver.seal,
        &mut wire,
    )?;
    driver.outer = driver.outer.checked_add(1).ok_or_else(exhausted)?;
    wire.truncate(sealed.bytes);
    Ok(wire)
}

async fn write_one(driver: &mut Driver, device: &mut AsyncFd<Device>) -> Result<bool> {
    let mut ready =
        tokio::time::timeout(Duration::from_secs(1), device.ready_mut(Interest::WRITABLE))
            .await??;
    assert!(ready.ready().is_writable());
    Ok(driver.write_native(&mut ready, || Ok(10))?)
}

async fn case(kind: cover::Appearance, blocked: bool) -> Result {
    let mut config = config(kind);
    config.send.records.codec.repair_numerator = 0;
    config.receive = config.send;
    config.native.pending_packets = 1;
    config.native.pending_bytes = 512;
    config.work.native_write_batch = 1;
    let (local, other) = parts_pair(kind).await?;
    drain_setup(&local.socket)?;
    drain_setup(&other.socket)?;
    let origin = Instant::now();
    let (socket, mut local) = Driver::new(local, security::ConfigDigest([3; 32]), config, origin)?;
    let (remote_socket, mut remote) =
        Driver::new(other, security::ConfigDigest([3; 32]), config, origin)?;
    let low = port(0)?;
    let high = port(1)?;
    for number in 0..8 {
        assert_eq!(
            remote.swift.offer(1, &frame(low, number))?,
            records::Admission::Accepted
        );
    }
    let high_packet = frame(high, 200);
    assert_eq!(
        remote.swift.offer(1, &high_packet)?,
        records::Admission::Accepted
    );
    let mut input = [0; 1501];
    // Queue both independent channel streams before the native drain, as a
    // bounded UDP receive batch does. Every byte crosses the original socket
    // and the actual common authentication/replay/dispatch owner.
    for expected_channel in 0..2 {
        let wire = sealed_source(&mut remote, 1)?;
        assert_eq!(remote_socket.send(&wire).await?, wire.len());
        let length =
            tokio::time::timeout(Duration::from_secs(1), socket.recv(&mut input)).await??;
        local.receive(&input[..length], 1, origin + duration(1), &resolve(config))?;
        assert!(
            local
                .swift
                .channel_stats(expected_channel)
                .and_then(|c| c.receive)
                .is_some_and(|c| c.sources == 1)
        );
    }
    let (native, host) = UnixDatagram::pair()?;
    native.set_nonblocking(true)?;
    host.set_nonblocking(true)?;
    let mut device = AsyncFd::with_interest(
        Device {
            socket: native,
            blocked,
            wouldblock: None,
        },
        Interest::WRITABLE,
    )?;
    local.collect_native(1)?;
    assert_eq!(local.native.len(), 1);
    assert_eq!(local.native.bytes(), frame(low, 0).len());
    assert_eq!(
        local.native.front().map(|packet| packet.bytes()),
        Some(frame(low, 0).as_slice())
    );
    if blocked {
        assert!(!write_one(&mut local, &mut device).await?);
        assert_eq!(local.counters.native_written, 0);
        let before = local.swift.stats();
        local.collect_native(2)?;
        assert_eq!(local.swift.stats(), before);
        assert_eq!(local.native.len(), 1);
        assert_eq!(local.native.front().map(|packet| packet.since()), Some(1));
        assert_eq!(local.performance.counters.native_write_would_block, 1);
        assert_eq!(
            host.recv(&mut input).err().map(|e| e.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        // Simulated WouldBlock cleared cached reactor readiness, although the
        // underlying socket stayed writable. Re-register the same owned device
        // so recovery does not depend on an absent kernel readiness edge.
        let mut unblocked = device.into_inner();
        unblocked.blocked = false;
        device = AsyncFd::with_interest(unblocked, Interest::WRITABLE)?;
    }
    assert!(write_one(&mut local, &mut device).await?);
    let length = host.recv(&mut input)?;
    assert_eq!(&input[..length], frame(low, 0));
    // The next available output slot must serve the complete upper channel,
    // even though seven lower-channel packets remain immediately deliverable.
    local.collect_native(3)?;
    assert_eq!(local.native.len(), 1);
    assert!(write_one(&mut local, &mut device).await?);
    let length = host.recv(&mut input)?;
    assert_eq!(
        &input[..length],
        high_packet,
        "low-channel backlog monopolized the second physical native handoff"
    );
    assert_eq!(local.counters.native_written, 2);
    for number in 1..8 {
        local.collect_native(4)?;
        assert_eq!(local.native.len(), 1);
        assert!(write_one(&mut local, &mut device).await?);
        let length = host.recv(&mut input)?;
        assert_eq!(&input[..length], frame(low, number));
    }
    local.collect_native(5)?;
    assert!(local.native.is_empty());
    assert_eq!(local.native.bytes(), 0);
    assert!(local.swift.receive_drained());
    assert_eq!(local.counters.native_written, 9);
    assert_eq!(local.performance.counters.native_write_batch_packets, 9);
    assert_eq!(local.performance.counters.native_pending_packets_high, 1);
    assert_eq!(local.counters.native_backpressure_drops, 0);
    assert_eq!(local.counters.rejected_packets, 0);
    assert_eq!(local.counters.replay_rejections, 0);
    assert!(local.terminal.is_none());
    Ok(())
}

#[tokio::test]
async fn protected_receive_channels_share_one_packet_native_output() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        for blocked in [false, true] {
            case(kind, blocked).await?;
        }
    }
    Ok(())
}
