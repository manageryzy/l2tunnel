//! Selected raw regressions using genuine original TLS/Noise/member ownership.
use super::*;
use crate::secure_udp::raw_carrier_io::{RawAdapter, RawBacking};

type RawIo = carrier::IoOwner<RawAdapter<PacketLink>>;
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
            max_forward_packets: 4096,
            max_failed_checks: 128,
        },
    };
    let pair = establish_original_pair(half, Some(selection)).await?;
    let (a, ad) = Driver::new_common_on_raw(pair.client, pair.client_contract)?;
    let (b, bd) = Driver::new_common_on_raw(pair.server, pair.server_contract)?;
    assert_eq!(
        ad.records.compact_layout(),
        Some(record::compact::Layout::Carrier)
    );
    assert_eq!(
        bd.records.compact_layout(),
        Some(record::compact::Layout::Carrier)
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
                None,
                metadata,
            )?;
        } else {
            driver.receive_selected_with_arrival(
                &bytes[..length],
                received,
                observed,
                arrived,
                now,
                None,
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
