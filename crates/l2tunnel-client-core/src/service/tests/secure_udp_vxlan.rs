//! End-to-end Common authenticated tunnel tests for VXLAN pass-through (`VX-02`,
//! `VX-06`, `VX-07`) and live VTEP/VXLAN device attachments (`MOD-VX-06`, `VX-04..VX-07`).

use super::*;
use l2tunnel_vxlan::{HEADER_LEN, Vni};
use std::collections::BTreeSet;
use std::net::UdpSocket;

fn build_plans_for_layer(
    layer: PacketLayer,
    max_packet: usize,
    attachments: [Attachment; 2],
) -> Result<TransactionPlans> {
    let held = [
        crate::test_ports::reserve(false)?,
        crate::test_ports::reserve(false)?,
    ];
    let addresses = [held[0].local_addr()?, held[1].local_addr()?];
    let encoded = Zeroizing::new(l2tunnel_auth::MemberKey::generate_pkcs8()?);
    let member = identity::IdentityKey::from_pkcs8(&encoded)?;
    let peers = l2tunnel_runtime::secure_udp::establish::Peers {
        initiator: hs::LocalSecret::new(Zeroizing::new([11; 32])).public_key(),
        responder: hs::LocalSecret::new(Zeroizing::new([22; 32])).public_key(),
    };
    let selection = Selection {
        appearance: l2tunnel_cover::Appearance::QuicLike,
        role: Role::Initiator,
        local: addresses[0],
        peer: addresses[1],
        policy: l2tunnel_swift::control::Policy {
            path_mtu: 1500,
            forward_kbit: 10_000,
            reverse_kbit: 5_000,
            channels: 4,
            window: 32,
            repair_permille: 0,
        },
        maximum_mtu: 2000,
        profile: hs::Profile::Ik,
        report: None,
    };
    let connection = ConnectionConfig {
        layer,
        duplex: Duplex::Full,
        max_packet,
        compression: crate::Compression::None,
        handshake_timeout: Duration::from_secs(3),
    };
    let legacy = selection.build(connection, peers, member.public_key())?;
    let mut settings = legacy.settings();
    settings.application = l2tunnel_core::ConfigDigest([31; 32]);
    let mut initiator = streamed(legacy.runtime(Role::Initiator));
    let mut responder = streamed(legacy.runtime(Role::Responder));
    let mut forward = initiator.send;
    let mut reverse = initiator.receive;
    forward.records.codec.flow_sources = 64;
    reverse.records.codec.flow_sources = 64;
    forward.records.codec.queue_bytes = 65_536;
    reverse.records.codec.queue_bytes = 65_536;
    forward.records.channels = 2;
    reverse.records.channels = 2;
    forward.records.codec.window = 8;
    reverse.records.codec.window = 8;
    forward.records.codec.repair_numerator = 0;
    forward.records.codec.repair_denominator = 1;
    reverse.records.codec.repair_numerator = 0;
    reverse.records.codec.repair_denominator = 1;
    let direction_for =
        |channels: u16, rate: u64| -> Result<l2tunnel::record_configuration::CommonDirection> {
            use l2tunnel::{pipeline as l2tunnel_pipeline, record_configuration as common};
            use l2tunnel_core::traffic;
            if layer == PacketLayer::Ip {
                return common_service::common_direction(channels, connection.max_packet, rate);
            }
            let queue = l2tunnel_pipeline::QueueLimits {
                bytes: 65_536,
                packets: 8,
            };
            Ok(common::CommonDirection::new(
                traffic::TrafficPolicy {
                    layer: traffic::NetworkLayer::Tap,
                    tcp: traffic::TcpControl::System,
                    qos: traffic::Qos::System,
                },
                l2tunnel_pipeline::PipelineConfig {
                    profile: l2tunnel_pipeline::Profile::TapSystem,
                    flows: l2tunnel_pipeline::FlowTableConfig {
                        capacity: 8,
                        channels,
                        mapping: l2tunnel_pipeline::Mapping::Crc32,
                        idle_timeout: Duration::from_secs(5),
                    },
                    parse: l2tunnel_pipeline::ParseLimits {
                        max_packet_bytes: connection.max_packet,
                        ..l2tunnel_pipeline::ParseLimits::default()
                    },
                    queue,
                },
                rate,
                65_536,
                common::NativeWindow::Disabled,
            )?)
        };
    let descriptor = Descriptor::new(
        1500,
        Duplex::Full,
        direction_for(forward.records.channels as u16, forward.bytes_per_second)?,
        direction_for(reverse.records.channels as u16, reverse.bytes_per_second)?,
        l2tunnel::record_configuration::Profile::Swift {
            forward: forward.records,
            reverse: reverse.records,
        },
    )?;
    initiator.send = forward;
    initiator.receive = reverse;
    responder.send = reverse;
    responder.receive = forward;
    let profile = transaction_profile::Profile::new(
        connection,
        settings,
        peers,
        initiator,
        responder,
        Catalog::new(descriptor, &[descriptor])?,
        transport::TransactionSettings {
            protocol: transaction::Settings {
                retry_ms: 10,
                phase_timeout_ms: 500,
                reconcile_timeout_ms: 1000,
            },
            max_operation_ms: 1500,
            retained_bytes: 16 * 1024 * 1024,
        },
    )?;
    let initial = profile.initial();
    let client_noise = credentials::NoiseIdentity::new(
        Zeroizing::new([11; 32]),
        peers.responder,
        hs::Profile::Ik,
        None,
    )?;
    let server_noise = credentials::NoiseIdentity::new(
        Zeroizing::new([22; 32]),
        peers.initiator,
        hs::Profile::Ik,
        None,
    )?;
    let [client_attachment, server_attachment] = attachments;
    let client = Prepared::secure_udp_common_client(
        profile.clone(),
        credentials::Client::new(
            client_noise,
            member,
            credentials::Secret32::new(Zeroizing::new([44; 32]))?,
        )?,
        client_attachment,
    )?;
    let server = Prepared::secure_udp_common_server(
        profile.clone(),
        credentials::Server::new(
            server_noise,
            credentials::Secret32::new(Zeroizing::new([44; 32]))?,
            credentials::Secret32::new(Zeroizing::new([55; 32]))?,
        )?,
        server_attachment,
    )?;
    drop(held);
    Ok(TransactionPlans {
        plans: [client, server],
        addresses,
        profile,
        initial,
        target: initial,
        outside: initial,
    })
}

fn eth_frame(
    dst: [u8; 6],
    src: [u8; 6],
    vlan: Option<u16>,
    ethertype: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(18 + payload.len());
    out.extend_from_slice(&dst);
    out.extend_from_slice(&src);
    if let Some(vid) = vlan {
        out.extend_from_slice(&0x8100u16.to_be_bytes());
        out.extend_from_slice(&(vid & 0x0fff).to_be_bytes());
    }
    out.extend_from_slice(&ethertype.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn ipv4_udp_packet(dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = (8 + payload.len()) as u16;
    let total_len = (20 + usize::from(udp_len)) as u16;
    let mut out = Vec::with_capacity(usize::from(total_len));
    out.extend_from_slice(&[
        0x45,
        0x00,
        (total_len >> 8) as u8,
        total_len as u8,
        0x00,
        0x01,
        0x40,
        0x00,
        64,
        17,
        0,
        0,
        10,
        20,
        0,
        1,
        10,
        20,
        0,
        2,
    ]);
    out.extend_from_slice(&50000u16.to_be_bytes());
    out.extend_from_slice(&dst_port.to_be_bytes());
    out.extend_from_slice(&udp_len.to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(payload);
    out
}

fn ipv6_udp_packet(dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = (8 + payload.len()) as u16;
    let mut out = Vec::with_capacity(40 + usize::from(udp_len));
    out.extend_from_slice(&[0x60, 0, 0, 0]);
    out.extend_from_slice(&udp_len.to_be_bytes());
    out.push(17); // UDP
    out.push(64);
    out.extend_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    out.extend_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    out.extend_from_slice(&50001u16.to_be_bytes());
    out.extend_from_slice(&dst_port.to_be_bytes());
    out.extend_from_slice(&udp_len.to_be_bytes());
    out.extend_from_slice(&[0xab, 0xcd]);
    out.extend_from_slice(payload);
    out
}

fn encode_vxlan(vni: u32, inner_eth: &[u8]) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; HEADER_LEN + inner_eth.len()];
    let n = l2tunnel_vxlan::encode(
        Vni::new(vni).map_err(|e| format!("{e:?}"))?,
        inner_eth,
        &mut buf,
    )
    .map_err(|e| format!("{e:?}"))?;
    buf.truncate(n);
    Ok(buf)
}

async fn exchange_exact(pair: &mut support::Pair, side: usize, bytes: &[u8]) -> Result {
    pair.hosts[side].send(bytes)?;
    pair.until(|pair| {
        let mut output = vec![0u8; bytes.len() + 64];
        let application = pair.hosts[1 - side]
            .application
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match application
            .as_ref()
            .ok_or("packet device not opened")?
            .recv(&mut output)
        {
            Ok(length) => {
                assert_eq!(&output[..length], bytes);
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(error) => Err(error.into()),
        }
    })
    .await
}

#[tokio::test]
async fn nested_vxlan_passthrough_roundtrips_through_common_tun_and_tap_with_vlan_ipv6_fallback_and_mgmt_isolation()
-> Result {
    let mac_a = [0x02, 0x00, 0x00, 0x00, 0x00, 0x11];
    let mac_b = [0x02, 0x00, 0x00, 0x00, 0x00, 0x22];

    // Inner Ethernet frames carried inside nested VXLAN payloads:
    let inner_untagged = eth_frame(mac_b, mac_a, None, 0x0800, &[0x45; 64]);
    let inner_vlan_ipv6 = eth_frame(mac_b, mac_a, Some(100), 0x86dd, &[0x60; 64]);
    let inner_mgmt_looking = eth_frame(mac_b, mac_a, Some(100), 0x88b5, b"L2MG\x00\x01L2SCcontrol");

    let vxlan_ipv4 = ipv4_udp_packet(4789, &encode_vxlan(0x11_2233, &inner_untagged)?);
    let vxlan_ipv6_vlan = ipv6_udp_packet(4789, &encode_vxlan(0x44_5566, &inner_vlan_ipv6)?);
    let vxlan_mgmt = ipv4_udp_packet(4789, &encode_vxlan(0x11_2233, &inner_mgmt_looking)?);

    // Unsupported header-codec fallback: non-base VXLAN-GPE flags (0x0c, next_proto=1)
    // and non-standard bytes must still pass through transparently as opaque user bytes.
    let mut vxlan_gpe = encode_vxlan(0x77_8899, &inner_untagged)?;
    vxlan_gpe[0] = 0x0c;
    vxlan_gpe[3] = 0x01;
    let fallback_gpe = ipv4_udp_packet(4789, &vxlan_gpe);

    for layer in [PacketLayer::Ip, PacketLayer::Ethernet] {
        let hosts = support::hosts();
        let fixture = build_plans_for_layer(
            layer,
            1600,
            [
                hosts[0].attachment_for(layer),
                hosts[1].attachment_for(layer),
            ],
        )?;
        let initial = fixture.initial;
        let mut pair = support::Pair::new(fixture, hosts)?;
        pair.ready().await?;

        let wrap = |ip_pkt: &[u8], ethertype: u16| -> Vec<u8> {
            match layer {
                PacketLayer::Ip => ip_pkt.to_vec(),
                PacketLayer::Ethernet => eth_frame(mac_b, mac_a, None, ethertype, ip_pkt),
            }
        };

        let cases = [
            wrap(&vxlan_ipv4, 0x0800),
            wrap(&vxlan_ipv6_vlan, 0x86dd),
            wrap(&fallback_gpe, 0x0800),
            wrap(&vxlan_mgmt, 0x0800),
        ];
        for (idx, payload) in cases.iter().enumerate() {
            let side = idx % 2;
            exchange_exact(&mut pair, side, payload).await?;
        }
        // On TAP, also test a direct (non-nested) management-looking Ethernet frame
        // plus an unknown EtherType fallback frame.
        if layer == PacketLayer::Ethernet {
            exchange_exact(&mut pair, 0, &inner_mgmt_looking).await?;
            let unknown_et = eth_frame(mac_b, mac_a, Some(200), 0x88cc, b"opaque-lldp-fallback");
            exchange_exact(&mut pair, 1, &unknown_et).await?;
        }

        // Oversized input (> max_packet = 1600) must not crash or tear down the tunnel.
        let oversized = vec![0x45; 1700];
        let _ = pair.hosts[0].send(&oversized);
        // Subsequent valid nested VXLAN packet must still round-trip cleanly.
        let sentinel = wrap(&vxlan_ipv4, 0x0800);
        exchange_exact(&mut pair, 0, &sentinel).await?;

        // VX-06: verify session state, epoch=1, idle phase and active configuration remained completely untouched.
        for side in 0..2 {
            let st = status(&pair.handles[side])?;
            assert_current(&st, initial, 1)?;
            assert_eq!(
                pair.handles[side].snapshot().generation,
                Some(pair.accepted[side].operation)
            );
        }

        pair.close()?;
    }
    Ok(())
}

#[tokio::test]
async fn live_vxlan_vtep_and_device_attachments_bridge_ethernet_across_authenticated_common_session()
-> Result {
    use l2tunnel_platform_vxlan::{VtepDeviceConfig, VxlanConfig, VxlanDevice, VxlanVtepDevice};
    use l2tunnel_vxlan::vtep::{
        BumPolicy, DomainConfig, DomainId, FdbConfig, OverheadBudget, PeerId, UnknownUnicastPolicy,
        VlanPolicy,
    };

    let test_vni = Vni::new(0x00_4455).map_err(|e| format!("{e:?}"))?;

    // External VXLAN UDP peers connected to the two sides of the authenticated Common tunnel:
    // Side 0 (Client): multi-peer VxlanVtepDevice talking to ext_p1 and ext_p2.
    // Side 1 (Server): point-to-point VxlanDevice talking to ext_b.
    let ext_p1 = UdpSocket::bind("127.0.0.1:0")?;
    let ext_p2 = UdpSocket::bind("127.0.0.1:0")?;
    let ext_b = UdpSocket::bind("127.0.0.1:0")?;
    for sock in [&ext_p1, &ext_p2, &ext_b] {
        sock.set_nonblocking(true)?;
    }
    let ext_p1_addr = ext_p1.local_addr()?;
    let ext_p2_addr = ext_p2.local_addr()?;
    let ext_b_addr = ext_b.local_addr()?;

    let vtep_sock = UdpSocket::bind("127.0.0.1:0")?;
    let vtep_addr = vtep_sock.local_addr()?;
    let server_vxlan_sock = UdpSocket::bind("127.0.0.1:0")?;
    let server_vxlan_addr = server_vxlan_sock.local_addr()?;

    let vtep_socket_slot = Arc::new(Mutex::new(Some(vtep_sock)));
    let server_socket_slot = Arc::new(Mutex::new(Some(server_vxlan_sock)));

    let client_attachment = Attachment::readable(PacketLayer::Ethernet, move || {
        let sock = vtep_socket_slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .ok_or_else(|| io::Error::other("vtep socket already taken"))?;
        let budget = OverheadBudget::compute(1500, false, 0)
            .map_err(|e| io::Error::other(format!("{e:?}")))?;
        let mut device = VxlanVtepDevice::from_socket(
            sock,
            VtepDeviceConfig {
                domain: DomainConfig {
                    domain: DomainId(1),
                    vni: test_vni,
                    mtu: budget,
                    vlan: VlanPolicy::Allowed {
                        allow_untagged: true,
                        vlans: BTreeSet::from([100]),
                    },
                    fdb: FdbConfig {
                        max_entries: 32,
                        aging_ttl_micros: 60_000_000,
                        move_window_micros: 1_000_000,
                        max_moves_per_window: 4,
                    },
                    bum: BumPolicy {
                        bytes_per_sec: 100_000,
                        burst_bytes: 16_384,
                        packets_per_sec: 500,
                        burst_packets: 32,
                        max_replicas_per_frame: 8,
                        per_peer_packets_per_sec: 500,
                    },
                    unknown_unicast: UnknownUnicastPolicy::Flood,
                    reject_recursive_vxlan: true,
                },
                receive_budget: 32,
                max_peers: 8,
            },
        )?;
        device.add_peer(PeerId(1), ext_p1_addr)?;
        device.add_peer(PeerId(2), ext_p2_addr)?;
        Ok(crate::native::Native::new(device))
    });

    let server_attachment = Attachment::readable(PacketLayer::Ethernet, move || {
        let sock = server_socket_slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .ok_or_else(|| io::Error::other("server vxlan socket already taken"))?;
        let device = VxlanDevice::from_socket(
            sock,
            VxlanConfig {
                peer: ext_b_addr,
                vni: test_vni,
                max_frame_bytes: 1500,
                receive_budget: 32,
            },
        )?;
        Ok(crate::native::Native::new(device))
    });

    let hosts = support::hosts();
    let fixture = build_plans_for_layer(
        PacketLayer::Ethernet,
        1500,
        [client_attachment, server_attachment],
    )?;
    let initial = fixture.initial;
    let mut pair = support::Pair::new(fixture, hosts)?;
    pair.ready().await?;

    let mac_p1 = [0x02, 0xaa, 0x00, 0x00, 0x00, 0x01];
    let mac_b = [0x02, 0xbb, 0x00, 0x00, 0x00, 0x02];
    let mac_bcast = [0xff; 6];

    // Helper to wait for a VXLAN datagram on an external UDP socket while driving the tunnel pair.
    async fn wait_external(
        pair: &mut support::Pair,
        socket: &UdpSocket,
        expected_vni: Vni,
        step: &'static str,
    ) -> Result<Vec<u8>> {
        let mut captured = None;
        pair.until(|_| {
            let mut buf = [0u8; 2048];
            match socket.recv_from(&mut buf) {
                Ok((len, _)) => {
                    let pkt = l2tunnel_vxlan::decode(&buf[..len], 2000)
                        .map_err(|e| format!("{step} external decode: {e:?}"))?;
                    assert_eq!(pkt.vni, expected_vni);
                    captured = Some(pkt.ethernet.to_vec());
                    Ok(true)
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
                Err(error) => Err(error.into()),
            }
        })
        .await
        .map_err(|e| format!("{step}: {e}"))?;
        captured.ok_or_else(|| format!("{step}: missing external VXLAN frame").into())
    }

    // 1. Rogue peer and disallowed VLAN 200 must be dropped at VTEP ingress before reaching B.
    let rogue = UdpSocket::bind("127.0.0.1:0")?;
    let rogue_frame = eth_frame(
        mac_b,
        mac_p1,
        None,
        0x0800,
        &ipv4_udp_packet(9000, b"rogue"),
    );
    rogue.send_to(&encode_vxlan(0x00_4455, &rogue_frame)?, vtep_addr)?;
    let bad_vlan = eth_frame(
        mac_b,
        mac_p1,
        Some(200),
        0x0800,
        &ipv4_udp_packet(9000, b"disallowed-vlan-200"),
    );
    ext_p1.send_to(&encode_vxlan(0x00_4455, &bad_vlan)?, vtep_addr)?;

    // 2. Authorized peer P1 sends VLAN-100 IPv6 frame -> learns mac_p1 on VLAN 100 -> crosses Common -> arrives at B.
    let vlan100_frame = eth_frame(
        mac_b,
        mac_p1,
        Some(100),
        0x86dd,
        &ipv6_udp_packet(9001, b"vlan100-ipv6-payload"),
    );
    ext_p1.send_to(&encode_vxlan(0x00_4455, &vlan100_frame)?, vtep_addr)?;
    let received_at_b = wait_external(&mut pair, &ext_b, test_vni, "step2-vlan100-to-b").await?;
    assert_eq!(received_at_b, vlan100_frame);

    // 3. Management-looking inner frame (0x88b5 / L2MG) from P1 crosses VTEP + Common as opaque user bytes.
    let mgmt_frame = eth_frame(
        mac_b,
        mac_p1,
        Some(100),
        0x88b5,
        b"L2MG\x00\x01spoofed-mgmt",
    );
    ext_p1.send_to(&encode_vxlan(0x00_4455, &mgmt_frame)?, vtep_addr)?;
    assert_eq!(
        wait_external(&mut pair, &ext_b, test_vni, "step3-mgmt-to-b").await?,
        mgmt_frame
    );

    // 4. B replies unicast to mac_p1 on VLAN 100 -> VTEP steers ONLY to P1 (NOT P2!).
    let reply_unicast = eth_frame(
        mac_p1,
        mac_b,
        Some(100),
        0x86dd,
        &ipv6_udp_packet(9002, b"unicast-reply-to-p1"),
    );
    ext_b.send_to(&encode_vxlan(0x00_4455, &reply_unicast)?, server_vxlan_addr)?;
    assert_eq!(
        wait_external(&mut pair, &ext_p1, test_vni, "step4-unicast-to-p1").await?,
        reply_unicast
    );
    // Drive briefly and assert P2 never received the learned unicast frame.
    for _ in 0..10 {
        pair.drive().await?;
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let mut probe = [0u8; 2048];
    assert_eq!(
        ext_p2.recv_from(&mut probe).err().map(|e| e.kind()),
        Some(io::ErrorKind::WouldBlock)
    );

    // 5. B sends a valid broadcast ARP request -> VTEP replicates BUM to BOTH P1 and P2.
    let mut arp_body = [0u8; 28];
    arp_body[0..2].copy_from_slice(&1u16.to_be_bytes()); // Ethernet
    arp_body[2..4].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4
    arp_body[4] = 6; // MAC len
    arp_body[5] = 4; // IPv4 len
    arp_body[6..8].copy_from_slice(&1u16.to_be_bytes()); // Request
    arp_body[8..14].copy_from_slice(&mac_b);
    arp_body[14..18].copy_from_slice(&[10, 0, 0, 2]);
    arp_body[24..28].copy_from_slice(&[10, 0, 0, 1]);
    let broadcast = eth_frame(mac_bcast, mac_b, None, 0x0806, &arp_body);
    ext_b.send_to(&encode_vxlan(0x00_4455, &broadcast)?, server_vxlan_addr)?;
    assert_eq!(
        wait_external(&mut pair, &ext_p1, test_vni, "step5-bcast-to-p1").await?,
        broadcast
    );
    assert_eq!(
        wait_external(&mut pair, &ext_p2, test_vni, "step5-bcast-to-p2").await?,
        broadcast
    );

    // 6. Both authenticated Common endpoints remain connected at epoch=1 with unmodified configuration.
    for side in 0..2 {
        let st = status(&pair.handles[side])?;
        assert_current(&st, initial, 1)?;
    }

    pair.close()?;
    Ok(())
}
