//! Selected raw regressions using genuine original TLS/Noise/member ownership.
use super::*;
use crate::secure_udp::raw_carrier_io::{RawAdapter, RawBacking};

type RawIo = carrier::IoOwner<RawAdapter<PacketLink>>;

#[tokio::test(start_paused = true)]
async fn raw_setup_write_leaves_concurrent_bootstrap_input_for_final_handoff() -> Result {
    let selection = record::compact::Selection {
        protection: security::compact::Protection::Aes128Ccm4,
        limits: security::compact::Selection {
            max_forward_packets: 8192,
            max_failed_checks: 128,
        },
    };
    let OriginalPair {
        mut client,
        mut server,
        server_contract,
        ..
    } = establish_original_pair(true, selection).await?;
    let deadline = client.deadline().min(server.deadline());
    // These are distinguishable old-format control records sent on the real
    // authenticated packet owners. The fixture checks custody, not membership.
    let covered = |config: cover::Config, number, marker| -> Result<Vec<u8>> {
        let mut bytes = vec![0; config.limits().max_packet_bytes];
        let used = config.encode(
            cover::PacketMeta {
                phase: cover::Phase::Established,
                packet_number: cover::PacketNumber(number),
                media_timestamp: cover::MediaTimestamp(0),
            },
            &[member::ROUTE, marker],
            &mut bytes,
        )?;
        bytes.truncate(used);
        Ok(bytes)
    };
    let incoming = covered(client.cover, client.next_outer, 1)?;
    let end_marker = covered(client.cover, client.next_outer + 1, 3)?;
    let outgoing = covered(server.cover, server.next_outer, 2)?;
    tokio::time::timeout_at(deadline, async {
        poll_fn(|cx| client.io.poll_setup_send(cx, &incoming, deadline)).await?;
        poll_fn(|cx| client.io.poll_setup_send(cx, &end_marker, deadline)).await?;
        poll_fn(|cx| {
            server.io.begin_turn();
            if let std::task::Poll::Ready(Err(error)) = server.io.poll_ready(cx, false) {
                return std::task::Poll::Ready(Err(error));
            }
            match server.io.earliest_input_for_ordering_at() {
                Ok(Some(_)) => std::task::Poll::Ready(Ok(())),
                Ok(None) => std::task::Poll::Pending,
                Err(error) => std::task::Poll::Ready(Err(error)),
            }
        })
        .await?;
        assert!(!server.io.receive_ready());
        poll_fn(|cx| server.io.poll_setup_send(cx, &outgoing, deadline)).await?;
        assert!(!server.io.control_pending());
        server
            .io
            .enable_final_records(server_contract.expected_configuration().0, server.cover)?;
        let mut scratch = [0; 1500];
        let mut received_marker = false;
        // Both markers use one FIFO PacketLink. Genuine bootstrap retries from
        // establishing the fixture can precede our marker in the same queue.
        loop {
            poll_fn(|cx| {
                server.io.begin_turn();
                server.io.poll_ready(cx, true)
            })
            .await?;
            let (n, _) = server.io.try_receive(&mut scratch)?;
            let packet = &scratch[..n];
            assert!(server.io.final_input_metadata().is_none());
            if packet == end_marker {
                assert!(received_marker);
                break;
            }
            if packet == incoming {
                assert!(!received_marker);
                received_marker = true;
            } else {
                let decoded = server.cover.decode(packet).map_err(invalid)?;
                assert!(
                    server
                        .bootstrap
                        .receive(decoded, Instant::now())
                        .map_err(invalid)?
                );
            }
        }
        assert!(matches!(server.io.try_receive(&mut scratch), Err(error)
            if error.kind() == io::ErrorKind::WouldBlock));
        Ok::<(), io::Error>(())
    })
    .await??;
    Ok(())
}

struct SelectedRuntimePair {
    a: RawIo,
    b: RawIo,
    ad: owner::StateCell<Driver>,
    bd: owner::StateCell<Driver>,
    probes: Vec<Arc<Probe>>,
}

#[inline(never)]
async fn selected_runtime_pair(
    half: bool,
    protection: security::compact::Protection,
) -> Result<SelectedRuntimePair> {
    let selection = record::compact::Selection {
        protection,
        limits: security::compact::Selection {
            max_forward_packets: 8192,
            max_failed_checks: 128,
        },
    };
    let pair = establish_original_pair(half, selection).await?;
    let (a, ad) = Driver::new_common_on_raw(pair.client, pair.client_contract)?;
    let (b, bd) = Driver::new_common_on_raw(pair.server, pair.server_contract)?;
    assert_eq!(
        ad.records.compact_layout(),
        record::compact::Layout::Carrier
    );
    assert_eq!(
        bd.records.compact_layout(),
        record::compact::Layout::Carrier
    );
    assert_eq!(a.ip_wire_bytes()?, 40);
    assert_eq!(b.ip_wire_bytes()?, 40);
    Ok(SelectedRuntimePair {
        a,
        b,
        ad,
        bd,
        probes: pair.probes,
    })
}

async fn progress_owner(socket: &mut RawIo, driver: &mut Driver) -> Result {
    socket.begin_turn();
    poll_fn(|cx| {
        let mut ready = std::pin::pin!(socket.ready(true));
        match ready.as_mut().poll(cx) {
            std::task::Poll::Ready(Err(error)) => std::task::Poll::Ready(Err(error)),
            _ => std::task::Poll::Ready(Ok(())),
        }
    })
    .await?;
    let mut bytes = [0; 1500];
    while let Ok((length, Some(arrived), _)) = socket.try_receive_at(&mut bytes) {
        let now = Instant::now();
        let received = clock(driver.origin, arrived)?;
        let observed = clock(driver.origin, now)?;
        if let Some(metadata) = socket.final_input_metadata() {
            driver.receive_selected_raw(
                socket,
                &bytes[..length],
                received,
                observed,
                arrived,
                now,
                metadata,
            )?;
        } else {
            driver.receive_selected_with_arrival(
                &bytes[..length],
                received,
                observed,
                arrived,
                now,
            )?;
        }
    }
    driver.complete_carrier_io(socket, Instant::now)?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn selected_compact_raw_services_alternate_management_and_both_half_lanes() -> Result {
    let mut pair = Box::pin(selected_runtime_pair(
        true,
        security::compact::Protection::Aes128Ccm4,
    ))
    .await?;
    for _ in 0..4 {
        progress_owner(&mut pair.a, &mut pair.ad).await?;
        progress_owner(&mut pair.b, &mut pair.bd).await?;
    }
    tokio::time::advance(Duration::from_secs(5)).await;
    let now = clock(pair.ad.origin, Instant::now())?;
    pair.ad.bucket.refill(now)?;
    // Both original lane Pings remain due when a reservation is cancelled.
    // A fresh prepare must rotate even though the first lane remains ready.
    let raw = pair.a.final_raw_mut().ok_or("selected raw owner")?;
    for lane in [0, 1] {
        let (metadata, _) = raw
            .prepare_final_control()?
            .ok_or("original lane Ping due")?;
        assert_eq!(metadata.aad()[32], lane);
        raw.cancel_final()?;
    }
    pair.ad
        .common
        .as_mut()
        .ok_or("selected common owner")?
        .raw_control_turn = true;
    let scope = pair.ad.records.control_scope();
    assert!(
        pair.ad
            .control
            .submit(
                envelope_scope(scope),
                control::Body::Ping { nonce: 42 },
                duration(now),
                duration(now + 1_000_000),
                true
            )?
            .is_some()
    );
    assert!(pair.ad.send_raw_services(&mut pair.a, now)?);
    progress_owner(&mut pair.a, &mut pair.ad).await?;
    assert_eq!(pair.probes[0].final_carrier.load(Ordering::Relaxed), 1);
    assert_eq!(pair.probes[2].final_carrier.load(Ordering::Relaxed), 0);
    // Upper management wins the next turn even while the other raw lane's
    // genuine original Ping remains due. All writes use the original adapters.
    assert!(pair.ad.send_raw_services(&mut pair.a, now)?);
    progress_owner(&mut pair.a, &mut pair.ad).await?;
    assert_eq!(pair.probes[2].final_management.load(Ordering::Relaxed), 1);
    assert_eq!(pair.probes[2].final_carrier.load(Ordering::Relaxed), 0);
    assert!(pair.ad.send_raw_services(&mut pair.a, now)?);
    progress_owner(&mut pair.a, &mut pair.ad).await?;
    assert_eq!(pair.probes[2].final_carrier.load(Ordering::Relaxed), 1);
    assert_eq!(pair.ad.records.next_number(Class::Control).0, 3);
    Ok(())
}

#[path = "transport_common_raw_pending_tests.rs"]
mod pending;

#[path = "transport_common_raw_receive_tests.rs"]
mod receive_fairness;
