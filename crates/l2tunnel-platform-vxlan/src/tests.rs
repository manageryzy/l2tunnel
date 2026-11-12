use super::*;
use std::thread;
use std::time::{Duration, Instant};

type TestResult = io::Result<()>;

fn vni(value: u32) -> io::Result<Vni> {
    Vni::new(value).map_err(|_| invalid("test VNI"))
}

fn configuration(peer: SocketAddr, maximum: usize, budget: usize) -> io::Result<VxlanConfig> {
    Ok(VxlanConfig {
        peer,
        vni: vni(0x12_3456)?,
        max_frame_bytes: maximum,
        receive_budget: budget,
    })
}

fn pair(maximum: usize, budget: usize) -> io::Result<(VxlanDevice, VxlanDevice)> {
    let a = UdpSocket::bind("127.0.0.1:0")?;
    let b = UdpSocket::bind("127.0.0.1:0")?;
    let a_addr = a.local_addr()?;
    let b_addr = b.local_addr()?;
    Ok((
        VxlanDevice::from_socket(a, configuration(b_addr, maximum, budget)?)?,
        VxlanDevice::from_socket(b, configuration(a_addr, maximum, budget)?)?,
    ))
}

fn wait_receive(device: &mut VxlanDevice, buffer: &mut [u8]) -> io::Result<usize> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(length) = device.receive(buffer)? {
            return Ok(length);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "loopback VXLAN receive",
            ));
        }
        thread::sleep(Duration::from_millis(1));
    }
}

fn encoded(vni: Vni, frame: &[u8]) -> io::Result<Vec<u8>> {
    let mut output = vec![0; HEADER_LEN + frame.len()];
    let length = l2tunnel_vxlan::encode(vni, frame, &mut output)
        .map_err(|_| invalid("test frame encode"))?;
    output.truncate(length);
    Ok(output)
}

#[test]
fn bidirectional_loopback_preserves_opaque_vlan_and_management_looking_frames() -> TestResult {
    let (mut a, mut b) = pair(1600, 32)?;
    assert_eq!(a.layer(), PacketLayer::Ethernet);
    assert_eq!(a.peer_addr(), b.local_addr()?);
    assert_eq!(a.max_frame_bytes(), 1600);
    let mut vlan = vec![0x5a; 128];
    vlan[12..18].copy_from_slice(&[0x81, 0, 0, 7, 0x86, 0xdd]);
    let mut output = [0xa5; 1608];
    assert_eq!(b.receive(&mut output)?, None);
    assert_eq!(output, [0xa5; 1608]);
    a.transmit(&vlan)?;
    let length = wait_receive(&mut b, &mut output)?;
    assert_eq!(&output[..length], vlan);
    assert!(output[length..].iter().all(|value| *value == 0xa5));
    let mut management_looking = vec![0xee; 96];
    management_looking[12..14].copy_from_slice(&[0x88, 0xb5]);
    b.transmit(&management_looking)?;
    let length = wait_receive(&mut a, &mut output)?;
    assert_eq!(&output[..length], management_looking);
    assert_eq!(a.stats().transmitted_frames, 1);
    assert_eq!(a.stats().transmitted_frame_bytes, 128);
    assert_eq!(a.stats().received_frames, 1);
    assert_eq!(a.stats().received_frame_bytes, 96);
    assert_eq!(b.stats().received_frames, 1);
    Ok(())
}

#[test]
fn same_peer_ip_with_a_different_udp_source_port_is_accepted() -> TestResult {
    let configured = UdpSocket::bind("127.0.0.1:0")?;
    let source = UdpSocket::bind("127.0.0.1:0")?;
    assert_ne!(configured.local_addr()?.port(), source.local_addr()?.port());
    let mut device = VxlanDevice::bind(
        "127.0.0.1:0".parse().map_err(|_| invalid("test address"))?,
        configuration(configured.local_addr()?, 1600, 32)?,
    )?;
    let frame = [7; 64];
    source.send_to(&encoded(vni(0x12_3456)?, &frame)?, device.local_addr()?)?;
    let mut output = [0; 1600];
    let length = wait_receive(&mut device, &mut output)?;
    assert_eq!(&output[..length], frame);
    assert_eq!(device.stats().dropped_foreign_source, 0);
    Ok(())
}

#[test]
fn invalid_vni_and_headers_are_dropped_before_a_following_valid_frame() -> TestResult {
    let source = UdpSocket::bind("127.0.0.1:0")?;
    let mut device = VxlanDevice::bind(
        "127.0.0.1:0".parse().map_err(|_| invalid("test address"))?,
        configuration(source.local_addr()?, 1600, 32)?,
    )?;
    let destination = device.local_addr()?;
    source.send_to(&encoded(vni(9)?, &[1; 64])?, destination)?;
    source.send_to(&[0; 7], destination)?;
    let mut bad_flags = encoded(vni(0x12_3456)?, &[1; 64])?;
    bad_flags[0] = 0xff;
    source.send_to(&bad_flags, destination)?;
    source.send_to(&encoded(vni(0x12_3456)?, &[2; 64])?, destination)?;
    let mut output = [0xa5; 1600];
    let length = wait_receive(&mut device, &mut output)?;
    assert_eq!(&output[..length], [2; 64]);
    let stats = device.stats();
    assert_eq!(stats.received_datagrams, 4);
    assert_eq!(stats.dropped_wrong_vni, 1);
    assert_eq!(stats.dropped_malformed, 2);
    assert_eq!(stats.received_frames, 1);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn foreign_loopback_ip_is_dropped_even_with_valid_vni() -> TestResult {
    let authorized = UdpSocket::bind("127.0.0.1:0")?;
    let foreign = UdpSocket::bind("127.0.0.2:0")?;
    let mut device = VxlanDevice::bind(
        "127.0.0.1:0".parse().map_err(|_| invalid("test address"))?,
        configuration(authorized.local_addr()?, 1600, 32)?,
    )?;
    let packet = encoded(vni(0x12_3456)?, &[3; 64])?;
    foreign.send_to(&packet, device.local_addr()?)?;
    authorized.send_to(&packet, device.local_addr()?)?;
    let mut output = [0; 1600];
    assert_eq!(wait_receive(&mut device, &mut output)?, 64);
    assert_eq!(device.stats().dropped_foreign_source, 1);
    assert_eq!(device.stats().received_frames, 1);
    Ok(())
}

// Linux returns the truncated prefix; other platforms may surface a socket error.
#[cfg(target_os = "linux")]
#[test]
fn configured_size_and_truncation_sentinel_never_deliver_a_partial_frame() -> TestResult {
    let source = UdpSocket::bind("127.0.0.1:0")?;
    let mut device = VxlanDevice::bind(
        "127.0.0.1:0".parse().map_err(|_| invalid("test address"))?,
        configuration(source.local_addr()?, 64, 32)?,
    )?;
    let destination = device.local_addr()?;
    source.send_to(&encoded(vni(0x12_3456)?, &[1; 65])?, destination)?;
    source.send_to(&encoded(vni(0x12_3456)?, &[1; 2000])?, destination)?;
    source.send_to(&encoded(vni(0x12_3456)?, &[2; 64])?, destination)?;
    let mut output = [0xa5; 80];
    let length = wait_receive(&mut device, &mut output)?;
    assert_eq!(length, 64);
    assert_eq!(&output[..64], [2; 64]);
    assert_eq!(&output[64..], [0xa5; 16]);
    assert_eq!(device.stats().dropped_oversized, 2);
    Ok(())
}

#[test]
fn receive_work_budget_is_finite_and_caller_capacity_error_is_explicit() -> TestResult {
    let source = UdpSocket::bind("127.0.0.1:0")?;
    let mut device = VxlanDevice::bind(
        "127.0.0.1:0".parse().map_err(|_| invalid("test address"))?,
        configuration(source.local_addr()?, 1600, 1)?,
    )?;
    source.send_to(&[0; 7], device.local_addr()?)?;
    source.send_to(&encoded(vni(0x12_3456)?, &[1; 64])?, device.local_addr()?)?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut output = [0xa5; 63];
    while device.stats().received_datagrams == 0 {
        assert_eq!(device.receive(&mut output)?, None);
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "work-budget packet",
            ));
        }
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(device.stats().received_datagrams, 1);
    assert_eq!(device.stats().receive_budget_exhaustions, 1);
    loop {
        match device.receive(&mut output) {
            Err(error) => {
                assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
                break;
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(1)),
            _ => return Err(io::Error::other("expected caller capacity failure")),
        }
    }
    assert_eq!(output, [0xa5; 63]);
    assert_eq!(device.stats().dropped_output_too_small, 1);
    assert_eq!(device.stats().received_frames, 0);
    let mut enough = [0; 1600];
    assert_eq!(device.receive(&mut enough)?, None);
    Ok(())
}

#[test]
fn exact_maximum_udp_payload_and_minimum_ethernet_bounds() -> TestResult {
    let (mut a, mut b) = pair(MAX_FRAME_BYTES, 32)?;
    assert_eq!(a.receive_buffer.len(), MAX_UDP_PAYLOAD_BYTES + 1);
    assert_eq!(a.transmit_buffer.len(), MAX_UDP_PAYLOAD_BYTES);
    for length in [14, MAX_FRAME_BYTES] {
        let frame = vec![0x71; length];
        a.transmit(&frame)?;
        let mut output = vec![0; MAX_FRAME_BYTES];
        let received = wait_receive(&mut b, &mut output)?;
        assert_eq!(received, length);
        assert_eq!(&output[..received], frame);
    }
    assert_eq!(
        a.transmit(&[0; 13]).err().map(|error| error.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
    assert_eq!(
        a.transmit(&vec![0; MAX_FRAME_BYTES + 1])
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
    assert_eq!(a.stats().transmitted_frames, 2);
    assert_eq!(a.stats().transmit_errors, 2);
    Ok(())
}

#[test]
fn invalid_configuration_and_connected_sockets_are_rejected() -> TestResult {
    let peer = UdpSocket::bind("127.0.0.1:0")?;
    let local: SocketAddr = "127.0.0.1:0".parse().map_err(|_| invalid("test address"))?;
    let good = configuration(peer.local_addr()?, 1600, 32)?;
    let mut cases = vec![good; 10];
    cases[0].max_frame_bytes = 13;
    cases[1].max_frame_bytes = MAX_FRAME_BYTES + 1;
    cases[2].receive_budget = 0;
    cases[3].receive_budget = MAX_RECEIVE_BUDGET + 1;
    cases[4].peer.set_port(0);
    for (index, address) in [
        "0.0.0.0:4789",
        "224.0.0.1:4789",
        "255.255.255.255:4789",
        "[::1]:4789",
        "[::]:4789",
    ]
    .iter()
    .enumerate()
    {
        cases[index + 5].peer = address.parse().map_err(|_| invalid("test address"))?;
    }
    for config in cases {
        assert_eq!(
            VxlanDevice::bind(local, config)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
    }
    let socket = UdpSocket::bind(local)?;
    socket.connect(peer.local_addr()?)?;
    assert_eq!(
        VxlanDevice::from_socket(socket, good)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
    Ok(())
}
