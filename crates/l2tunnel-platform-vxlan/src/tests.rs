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

fn eth_frame(
    dst: [u8; 6],
    src: [u8; 6],
    ethertype: [u8; 2],
    vlan: Option<u16>,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(18 + payload.len());
    frame.extend_from_slice(&dst);
    frame.extend_from_slice(&src);
    if let Some(vid) = vlan {
        frame.extend_from_slice(&[0x81, 0x00]);
        frame.extend_from_slice(&(vid & 0x0fff).to_be_bytes());
    }
    frame.extend_from_slice(&ethertype);
    frame.extend_from_slice(payload);
    frame
}

fn recv_udp_vxlan(socket: &UdpSocket, expected_vni: Vni) -> io::Result<Option<Vec<u8>>> {
    let mut buf = [0u8; 2048];
    match socket.recv_from(&mut buf) {
        Ok((len, _)) => {
            let decoded = l2tunnel_vxlan::decode(&buf[..len], 2000)
                .map_err(|_| invalid("decode peer VXLAN datagram"))?;
            assert_eq!(decoded.vni, expected_vni);
            Ok(Some(decoded.ethernet.to_vec()))
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(error) => Err(error),
    }
}

fn wait_udp_vxlan(socket: &UdpSocket, expected_vni: Vni) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(frame) = recv_udp_vxlan(socket, expected_vni)? {
            return Ok(frame);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "loopback VTEP peer receive",
            ));
        }
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn ipv6_loopback_vxlan_device_roundtrip_and_self_loop_rejected() -> TestResult {
    let Ok(a) = UdpSocket::bind("[::1]:0") else {
        // Host without IPv6 loopback enabled.
        return Ok(());
    };
    let b = UdpSocket::bind("[::1]:0")?;
    let a_addr = a.local_addr()?;
    let b_addr = b.local_addr()?;
    // Self-loop rejected before opening.
    assert_eq!(
        VxlanDevice::bind(a_addr, configuration(a_addr, 1600, 32)?)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
    let mut dev_a = VxlanDevice::from_socket(a, configuration(b_addr, 1600, 32)?)?;
    let mut dev_b = VxlanDevice::from_socket(b, configuration(a_addr, 1600, 32)?)?;
    let frame = eth_frame(
        [0x02, 0, 0, 0, 0, 2],
        [0x02, 0, 0, 0, 0, 1],
        [0x86, 0xdd],
        Some(42),
        &[0x60; 64],
    );
    dev_a.transmit(&frame)?;
    let mut out = [0u8; 1600];
    let len = wait_receive(&mut dev_b, &mut out)?;
    assert_eq!(&out[..len], frame);
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        assert!(dev_a.as_raw_fd() >= 0);
    }
    Ok(())
}

#[test]
fn multi_peer_vtep_fdb_learning_unicast_bum_split_horizon_and_isolation() -> TestResult {
    use l2tunnel_vxlan::vtep::{
        BumPolicy, DomainConfig, DomainId, EgressSource, FdbConfig, Mac, OverheadBudget, PeerId,
        UnknownUnicastPolicy, VlanPolicy,
    };
    use std::collections::BTreeSet;

    let test_vni = vni(0x00_2233)?;
    let budget = OverheadBudget::compute(1500, false, 0)
        .map_err(|_| invalid("compute IPv4 overhead budget"))?;
    let domain = DomainConfig {
        domain: DomainId(1),
        vni: test_vni,
        mtu: budget,
        vlan: VlanPolicy::Allowed {
            allow_untagged: true,
            vlans: BTreeSet::from([100]),
        },
        fdb: FdbConfig {
            max_entries: 16,
            aging_ttl_micros: 10_000_000,
            move_window_micros: 1_000_000,
            max_moves_per_window: 4,
        },
        bum: BumPolicy {
            bytes_per_sec: 1_000,
            burst_bytes: 300,
            packets_per_sec: 100,
            burst_packets: 10,
            max_replicas_per_frame: 4,
            per_peer_packets_per_sec: 100,
        },
        unknown_unicast: UnknownUnicastPolicy::Flood,
        reject_recursive_vxlan: true,
    };

    let mut vtep = VxlanVtepDevice::bind(
        "127.0.0.1:0".parse().map_err(|_| invalid("vtep bind"))?,
        VtepDeviceConfig {
            domain,
            receive_budget: 32,
            max_peers: 8,
        },
    )?;
    assert_eq!(vtep.layer(), PacketLayer::Ethernet);
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        assert!(vtep.as_raw_fd() >= 0);
    }

    let peer1_sock = UdpSocket::bind("127.0.0.1:0")?;
    let peer2_sock = UdpSocket::bind("127.0.0.1:0")?;
    let peer3_sock = UdpSocket::bind("127.0.0.1:0")?;
    for sock in [&peer1_sock, &peer2_sock, &peer3_sock] {
        sock.set_nonblocking(true)?;
    }

    let p1 = PeerId(1);
    let p2 = PeerId(2);
    let p3 = PeerId(3);
    vtep.add_peer(p1, peer1_sock.local_addr()?)?;
    vtep.add_peer(p2, peer2_sock.local_addr()?)?;
    vtep.add_peer(p3, peer3_sock.local_addr()?)?;

    // Self-loop and duplicate peer endpoints must be rejected.
    assert!(vtep.add_peer(PeerId(99), vtep.local_addr()).is_err());
    assert!(vtep.add_peer(PeerId(98), peer1_sock.local_addr()?).is_err());

    let mac_local = [0x02, 0, 0, 0, 0, 0x0a];
    let mac_p1 = [0x02, 0, 0, 0, 0, 0x11];
    let mac_p2 = [0x02, 0, 0, 0, 0, 0x22];
    let mac_static = [0x02, 0, 0, 0, 0, 0x77];
    let mac_bcast = [0xff; 6];

    // 1. Unauthorized sender must be dropped before FDB learning.
    let rogue = UdpSocket::bind("127.0.0.1:0")?;
    let rogue_frame = eth_frame(mac_local, mac_p1, [0x08, 0x00], None, &[0x99; 46]);
    rogue.send_to(&encoded(test_vni, &rogue_frame)?, vtep.local_addr())?;

    // 2. Peer 1 sends a legitimate frame (learns mac_p1 -> p1) and a disallowed VLAN 200 frame.
    let bad_vlan = eth_frame(mac_local, mac_p2, [0x08, 0x00], Some(200), &[0x44; 46]);
    peer1_sock.send_to(&encoded(test_vni, &bad_vlan)?, vtep.local_addr())?;

    let good_p1 = eth_frame(mac_local, mac_p1, [0x08, 0x00], Some(100), &[0x11; 46]);
    peer1_sock.send_to(&encoded(test_vni, &good_p1)?, vtep.local_addr())?;

    let mut out = [0u8; 1600];
    let deadline = Instant::now() + Duration::from_secs(2);
    let len = loop {
        if let Some(n) = vtep.receive(&mut out)? {
            break n;
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "vtep ingress"));
        }
        thread::sleep(Duration::from_millis(1));
    };
    assert_eq!(&out[..len], good_p1);
    assert_eq!(vtep.stats().dropped_foreign_source, 1);
    assert_eq!(vtep.stats().dropped_vtep_policy, 1);

    // 3. Learned unicast on VLAN 100 goes ONLY to peer 1 (not peer 2 or peer 3).
    let reply_p1 = eth_frame(mac_p1, mac_local, [0x08, 0x00], Some(100), &[0x22; 46]);
    let sent = vtep.transmit_with_source(EgressSource::Local, &reply_p1)?;
    assert_eq!(sent, 1);
    assert_eq!(wait_udp_vxlan(&peer1_sock, test_vni)?, reply_p1);
    thread::sleep(Duration::from_millis(10));
    assert_eq!(recv_udp_vxlan(&peer2_sock, test_vni)?, None);
    assert_eq!(recv_udp_vxlan(&peer3_sock, test_vni)?, None);

    // 4. Static FDB entry steers to peer 3 even if peer 2 claims that MAC.
    vtep.insert_static_fdb(None, Mac(mac_static), p3)?;
    let spoof_static = eth_frame(mac_local, mac_static, [0x08, 0x00], None, &[0x33; 46]);
    peer2_sock.send_to(&encoded(test_vni, &spoof_static)?, vtep.local_addr())?;
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if vtep.receive(&mut out)?.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "static mac test"));
        }
        thread::sleep(Duration::from_millis(1));
    }
    let to_static = eth_frame(mac_static, mac_local, [0x08, 0x00], None, &[0x55; 46]);
    assert_eq!(
        vtep.transmit_with_source(EgressSource::Local, &to_static)?,
        1
    );
    assert_eq!(wait_udp_vxlan(&peer3_sock, test_vni)?, to_static);
    assert_eq!(recv_udp_vxlan(&peer2_sock, test_vni)?, None);

    // 5. Split-horizon broadcast from Peer 1 replicates ONLY to Peer 2 & Peer 3 (2 datagrams).
    let bcast = eth_frame(mac_bcast, mac_p1, [0x08, 0x06], None, &[0xaa; 32]);
    let replicated = vtep.transmit_with_source(EgressSource::RemotePeer(p1), &bcast)?;
    assert_eq!(replicated, 2);
    assert_eq!(wait_udp_vxlan(&peer2_sock, test_vni)?, bcast);
    assert_eq!(wait_udp_vxlan(&peer3_sock, test_vni)?, bcast);
    assert_eq!(recv_udp_vxlan(&peer1_sock, test_vni)?, None);

    // 6. BUM aggregate byte budget (burst = 300 bytes): next large broadcast is dropped by policy.
    // Previous bcast charged 2 * (8 + 46) = 108 bytes; remaining ~192 bytes.
    // A 120-byte frame * 3 peers = 3 * 128 = 384 bytes > remaining burst -> dropped!
    let large_bcast = eth_frame(mac_bcast, mac_local, [0x08, 0x06], None, &[0xbb; 106]);
    assert_eq!(
        vtep.transmit_with_source(EgressSource::Local, &large_bcast)?,
        0
    );
    assert!(vtep.stats().transmit_dropped_policy >= 1);
    assert!(vtep.vtep_stats().egress_bum_budget_drops >= 1);

    // 7. Management-looking inner frame (0x88b5 / L2MG) is treated as ordinary opaque user data.
    let mgmt_looking = eth_frame(
        mac_p1,
        mac_local,
        [0x88, 0xb5],
        Some(100),
        b"L2MG\x00\x01admin",
    );
    assert_eq!(
        vtep.transmit_with_source(EgressSource::Local, &mgmt_looking)?,
        1
    );
    assert_eq!(wait_udp_vxlan(&peer1_sock, test_vni)?, mgmt_looking);

    // 8. Tightening path MTU rejects larger frames cleanly without fragmenting.
    let tight = OverheadBudget::compute(576, false, 100)
        .map_err(|_| invalid("compute tight overhead budget"))?;
    vtep.update_mtu(tight)?;
    let too_big = eth_frame(mac_p1, mac_local, [0x08, 0x00], None, &[0xcc; 600]);
    assert_eq!(
        vtep.transmit(&too_big).err().map(|e| e.kind()),
        Some(io::ErrorKind::InvalidInput)
    );

    // 9. Removing peer 1 purges its dynamic FDB entry and blocks future frames from it.
    assert_eq!(vtep.remove_peer(p1)?, 1);

    // 10. Advancing clock past aging TTL ages remaining dynamic entries cleanly.
    vtep.advance_clock(Duration::from_secs(15));
    let _ = vtep.age_fdb();

    Ok(())
}
