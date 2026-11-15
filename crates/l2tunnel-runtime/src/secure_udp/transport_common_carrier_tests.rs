//! Actual initial-only OpenVPN carrier in the public sole Common Driver loop.
use super::*;
use crate::secure_udp::member::carrier::tests as factory_fixture;
use l2tunnel::record_configuration::{Catalog, EnvelopeDigest};

fn selected(
    outer: &establish::carrier::AuthenticatedOuter,
    client: bool,
) -> Result<(establish::Config, CommonTransactionContract)> {
    let kind = cover::Appearance::QuicLike;
    let mut resources = config(kind);
    resources.control.wire_overhead += 1;
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
    let contract = CommonTransactionContract::new_on_carrier(
        security::ConfigDigest([3; 32]),
        if client {
            security::Role::Initiator
        } else {
            security::Role::Responder
        },
        resources,
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
    )?;
    assert!(contract.refresh_selection().is_none());
    let mut setup = factory_fixture::effective(outer, client)?;
    setup.gate.path_mtu = resources.path_mtu;
    setup.cover = cover;
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
    let mut outer = factory_fixture::outer_config();
    outer.base.layer = PacketLayer::Ethernet;
    outer.path_mtu = 1500;
    outer.max_record_bytes = 1471;
    let [(a, a_contract), (b, b_contract)] =
        factory_fixture::initial::initial_parts(outer, selected).await?;
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
