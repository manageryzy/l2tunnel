//! Actual initial-only OpenVPN carrier in the public sole Common Driver loop.
use super::*;
use crate::secure_udp::member::carrier::tests as factory_fixture;
use l2tunnel::record_configuration::{Catalog, EnvelopeDigest};

fn selected(
    outer: &establish::carrier::AuthenticatedOuter,
    client: bool,
) -> Result<(establish::Config, CommonTransactionContract)> {
    selected_kind(outer, client, cover::Appearance::QuicLike)
}
fn selected_kind(
    outer: &establish::carrier::AuthenticatedOuter,
    client: bool,
    kind: cover::Appearance,
) -> Result<(establish::Config, CommonTransactionContract)> {
    let mut resources = config(kind);
    resources.control.wire_overhead = 28 + record::compact::AUTHENTICATED_OVERHEAD;
    let selected = mg::messages::Settings {
        delivery: delivery::Settings {
            wire_overhead: resources.control.wire_overhead + streams::HEADER_BYTES,
            ..resources.control
        },
        path_mtu: resources.path_mtu,
        max_message_bytes: 4096,
        max_outbound_messages: 4,
        max_outbound_bytes: 131072,
        max_fragments: 32,
        max_reassembly_bytes: 16384,
        max_incomplete_messages: 2,
        message_lifetime: Duration::from_secs(4),
        work_per_call: 8,
    };
    resources.streams = Some(control_owner::Settings {
        streams: [selected; 3],
    });
    let (local, peer) = if client { (1, 2) } else { (2, 1) };
    let cover = cover::Config::new(
        kind,
        cover::ConnectionIds {
            local: cover::ConnectionId([local; 8]),
            peer: cover::ConnectionId([peer; 8]),
        },
        cover::MediaConfig {
            local_ssrc: cover::Ssrc(u32::from(local)),
            peer_ssrc: cover::Ssrc(u32::from(peer)),
            payload_type: 96,
        },
        cover::Limits {
            max_packet_bytes: 1471,
            max_protected_bytes: 1400,
        },
    )?;
    let value = super::super::common_engines::tests::values()
        .map_err(|error| io::Error::other(error.to_string()))?[0];
    let catalog = Catalog::new(*value.descriptor(), &[*value.descriptor()])?;
    let contract = CommonTransactionContract::new_on_carrier_paired_compact(
        security::ConfigDigest([3; 32]),
        if client {
            security::Role::Initiator
        } else {
            security::Role::Responder
        },
        [resources; 2],
        cover,
        false,
        EnvelopeDigest::new([0x39; 32]),
        catalog,
        TransactionSettings {
            protocol: transaction::Settings {
                retry_ms: 10,
                phase_timeout_ms: 1000,
                reconcile_timeout_ms: 2000,
            },
            max_operation_ms: 3000,
            retained_bytes: 256 << 20,
        },
        *outer,
        common_selected::default_record_selection(),
    )?;
    assert_eq!(
        contract.compact_wire(),
        common_selected::default_record_selection()
    );
    let mut setup = factory_fixture::effective(outer, client)?;
    setup.gate.path_mtu = resources.path_mtu;
    setup.cover = cover;
    setup.gate.outer_overhead = 28
        + 1
        + 1
        + match kind {
            cover::Appearance::QuicLike => 30,
            cover::Appearance::MediaLike => cover::MEDIA_OVERHEAD,
        };
    setup.binding.configuration = contract.expected_configuration().0;
    Ok((setup, contract))
}

fn device() -> Result<(Device, tokio::net::UnixDatagram)> {
    let (native, host) = UnixDatagram::pair()?;
    native.set_nonblocking(true)?;
    host.set_nonblocking(true)?;
    Ok((
        Device {
            socket: native,
            blocked: false,
            wouldblock: None,
        },
        tokio::net::UnixDatagram::from_std(host)?,
    ))
}

#[tokio::test]
async fn actual_initial_only_openvpn_common_loop_delivers_both_directions_and_liveness() -> Result {
    run_initial_case(None).await
}

#[tokio::test]
async fn selected_compact_openvpn_common_loop_delivers_both_suites_on_original_socket() -> Result {
    for protection in [
        security::compact::Protection::Aes128Ccm4,
        security::compact::Protection::ChaCha20Crc32c,
    ] {
        run_initial_case(Some(record::compact::Selection {
            protection,
            limits: security::compact::Selection {
                max_forward_packets: 8192,
                max_failed_checks: 64,
            },
        }))
        .await?;
    }
    Ok(())
}

fn selected_wire(
    proof: &establish::carrier::AuthenticatedOuter,
    client: bool,
    selection: Option<record::compact::Selection>,
) -> Result<(establish::Config, CommonTransactionContract)> {
    selected_wire_kind(proof, client, selection, cover::Appearance::QuicLike)
}
fn selected_wire_kind(
    proof: &establish::carrier::AuthenticatedOuter,
    client: bool,
    selection: Option<record::compact::Selection>,
    kind: cover::Appearance,
) -> Result<(establish::Config, CommonTransactionContract)> {
    let (mut setup, old) = selected_kind(proof, client, kind)?;
    let Some(selection) = selection else {
        return Ok((setup, old));
    };
    let mut resources = old.resources();
    resources.control.wire_overhead = 28 + record::compact::AUTHENTICATED_OVERHEAD;
    for stream in &mut resources.streams.as_mut().ok_or("actual streams")?.streams {
        stream.delivery.wire_overhead = resources.control.wire_overhead + streams::HEADER_BYTES;
    }
    let contract = CommonTransactionContract::new_on_carrier_paired_compact(
        security::ConfigDigest([3; 32]),
        old.role(),
        [resources; 2],
        old.cover(),
        false,
        EnvelopeDigest::new([0x39; 32]),
        old.catalog().clone(),
        old.settings(),
        *proof,
        selection,
    )?;
    setup.binding.configuration = contract.expected_configuration().0;
    Ok((setup, contract))
}

#[tokio::test]
async fn selected_compact_openvpn_member_proof_refuses_a_different_data_suite() -> Result {
    let mut outer = factory_fixture::outer_config();
    outer.base.layer = PacketLayer::Ethernet;
    outer.path_mtu = 1500;
    outer.max_record_bytes = 1471;
    let selection = record::compact::Selection {
        protection: security::compact::Protection::Aes128Ccm4,
        limits: security::compact::Selection {
            max_forward_packets: 8192,
            max_failed_checks: 64,
        },
    };
    let [(a, original), _peer] = factory_fixture::initial::initial_parts(outer, |proof, client| {
        selected_wire(proof, client, Some(selection))
    })
    .await?;
    let mut changed = selection;
    changed.protection = security::compact::Protection::ChaCha20Crc32c;
    let (_, contract) = selected_wire(&a.outer(), true, Some(changed))?;
    assert_ne!(
        contract.expected_configuration(),
        original.expected_configuration()
    );
    assert!(!a.datagram.final_records());
    let (native, _host) = device()?;
    let error = run_common_on_carrier(native, a, contract, None, async {}, |_| {})
        .await
        .err()
        .ok_or("different suite installed")?;
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    Ok(())
}

#[tokio::test]
async fn selected_compact_openvpn_explicit_final_route_never_enters_media_joining_tail() -> Result {
    use l2tunnel_openvpn::wire_carrier::common::ReceiveFraming;
    let mut outer = factory_fixture::outer_config();
    outer.base.layer = PacketLayer::Ethernet;
    outer.path_mtu = 1500;
    outer.max_record_bytes = 1471;
    let selection = record::compact::Selection {
        protection: security::compact::Protection::ChaCha20Crc32c,
        limits: security::compact::Selection {
            max_forward_packets: 8192,
            max_failed_checks: 64,
        },
    };
    let [(a, contract), (_b, peer)] =
        factory_fixture::initial::initial_parts(outer, |proof, client| {
            selected_wire_kind(proof, client, Some(selection), cover::Appearance::MediaLike)
        })
        .await?;
    let (_socket, mut driver) = Driver::new_common_on_carrier(a, contract)?;
    let mut collision = [0; 128];
    let bytes = peer
        .cover()
        .encode(meta(0, cover::Phase::Established), &[3], &mut collision)?;
    assert_eq!(collision[0], 0x80);
    assert_eq!(driver.cover.decode(&collision[..bytes])?.protected, &[3]);
    let at = Instant::now();
    let now = clock(driver.origin, at)?;
    let rejected = driver.counters.rejected_packets;
    let verified = driver.live.last_verified_micros;
    driver.receive_selected_on_carrier(
        &collision[..bytes],
        now,
        now,
        at,
        at,
        ReceiveFraming::DataV1,
    )?;
    assert_eq!(driver.counters.rejected_packets, rejected);
    driver.receive_selected_on_carrier(
        &collision[..bytes],
        now,
        now,
        at,
        at,
        ReceiveFraming::Final,
    )?;
    assert_eq!(driver.counters.rejected_packets, rejected + 1);
    assert_eq!(driver.live.last_verified_micros, verified);
    Ok(())
}

async fn run_initial_case(selection: Option<record::compact::Selection>) -> Result {
    let mut outer = factory_fixture::outer_config();
    outer.base.layer = PacketLayer::Ethernet;
    outer.path_mtu = 1500;
    outer.max_record_bytes = 1471;
    let [(a, a_contract), (b, b_contract)] =
        factory_fixture::initial::initial_parts(outer, |proof, client| {
            selected_wire(proof, client, selection)
        })
        .await?;
    let endpoints = a.outer().endpoints();
    let cap = a.deadline.min(b.deadline);
    assert_eq!(a.datagram.addresses(), endpoints);
    assert_eq!(b.datagram.addresses(), (endpoints.1, endpoints.0));
    assert_eq!(
        a_contract.expected_configuration(),
        b_contract.expected_configuration()
    );
    let (a_device, a_host) = device()?;
    let (b_device, b_host) = device()?;
    let (a_stop, a_shutdown) = oneshot::channel::<()>();
    let (b_stop, b_shutdown) = oneshot::channel::<()>();
    let verified = Arc::new(AtomicUsize::new(0));
    let a_verified = verified.clone();
    let b_verified = verified.clone();
    let a_run = run_common_on_carrier(
        a_device,
        a,
        a_contract,
        None,
        async move {
            let _ = a_shutdown.await;
        },
        move |snapshot| {
            if snapshot.liveness.last_pong_micros.is_some() {
                a_verified.fetch_or(1, Ordering::Relaxed);
            }
        },
    );
    let b_run = run_common_on_carrier(
        b_device,
        b,
        b_contract,
        None,
        async move {
            let _ = b_shutdown.await;
        },
        move |snapshot| {
            if snapshot.liveness.last_pong_micros.is_some() {
                b_verified.fetch_or(2, Ordering::Relaxed);
            }
        },
    );
    let exercise = async move {
        let result = tokio::time::timeout_at(cap, async {
            let forward = ethernet(31);
            let reverse = ethernet(42);
            assert_eq!(a_host.send(&forward).await?, forward.len());
            assert_eq!(b_host.send(&reverse).await?, reverse.len());
            let mut a_packet = [0; 2048];
            let mut b_packet = [0; 2048];
            let (a_bytes, b_bytes) =
                tokio::try_join!(a_host.recv(&mut a_packet), b_host.recv(&mut b_packet))?;
            assert_eq!(&a_packet[..a_bytes], reverse);
            assert_eq!(&b_packet[..b_bytes], forward);
            loop {
                if verified.load(Ordering::Relaxed) == 3 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            Ok::<_, io::Error>(())
        })
        .await;
        let _ = a_stop.send(());
        let _ = b_stop.send(());
        result??;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    };
    let (a, b, exercise) = tokio::join!(a_run, b_run, exercise);
    exercise?;
    for (side, stopped) in [a?, b?].into_iter().enumerate() {
        assert_eq!(stopped.reason, StopReason::Cancelled);
        assert_eq!(
            stopped.snapshot.compact_wire,
            Some(selection.unwrap_or_else(common_selected::default_record_selection))
        );
        let expected = if side == 0 {
            endpoints
        } else {
            (endpoints.1, endpoints.0)
        };
        assert_eq!(
            (
                stopped.snapshot.info.local_addr,
                stopped.snapshot.info.peer_addr
            ),
            expected
        );
        assert!(stopped.snapshot.counters.native_written > 0);
        assert!(stopped.snapshot.counters.socket_accepted_packets > 0);
        assert!(stopped.snapshot.counters.user_number.is_some());
        assert!(stopped.snapshot.counters.control_number.is_some());
        assert!(stopped.snapshot.liveness.last_pong_micros.is_some());
        assert_eq!(stopped.snapshot.counters.socket_drops, 0);
        assert!(!stopped.snapshot.running);
    }
    Ok(())
}

#[path = "transport_common_carrier_research_tests.rs"]
mod research;
