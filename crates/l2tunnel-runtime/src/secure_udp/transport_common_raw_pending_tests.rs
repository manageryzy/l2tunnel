//! Original raw custody under unavailable output: no extra nonce/debit or renewed cap.
use super::*;

fn hold_management(pair: &mut SelectedRuntimePair, now: u64) -> Result {
    for probe in &pair.probes {
        probe.blocked.store(true, Ordering::Relaxed);
    }
    let scope = pair.ad.records.control_scope();
    assert!(
        pair.ad
            .submit(
                now,
                scope,
                control::Body::Pong { nonce: 1 },
                now + 1_000_000,
                true
            )?
            .is_some()
    );
    let (bytes, cap) = pair
        .ad
        .prepare_raw_management(&mut pair.a, now)?
        .ok_or("initial management emission")?;
    pair.ad
        .stage_carrier_control(&mut pair.a, bytes, cap, performance::WireKind::Control)?;
    assert!(pair.a.control_pending());
    Ok(())
}

#[tokio::test]
async fn compact_raw_pending_management_keeps_original_cap_and_exact_body_while_lane_busy() -> Result
{
    let mut pair = Box::pin(selected_runtime_pair(
        false,
        security::compact::Protection::ChaCha20Crc32c,
    ))
    .await?;
    let now = clock(pair.ad.origin, Instant::now())? + 1;
    hold_management(&mut pair, now)?;
    let scope = pair.ad.records.control_scope();
    let cap = now + 50_000;
    assert!(
        pair.ad
            .submit(now + 1, scope, control::Body::Pong { nonce: 2 }, cap, true)?
            .is_some()
    );
    let number = pair.ad.records.next_number(Class::Control);
    let tokens = pair.ad.bucket.tokens;
    assert!(
        pair.ad
            .prepare_raw_management(&mut pair.a, now + 1)?
            .is_none()
    );
    let pending = pair
        .ad
        .common
        .as_ref()
        .and_then(|runtime| runtime.raw_control.as_ref())
        .ok_or("retained management")?;
    let deadline = pending.deadline;
    let bytes = pending.bytes;
    let body = pair.ad.buffers.control_wire[..bytes].to_vec();
    assert_eq!(deadline, pair.ad.origin + duration(cap));
    assert!(deadline < pair.ad.origin + duration(pair.ad.lease));
    for at in [now + 2, now + 10_000, cap - 1] {
        assert!(pair.ad.prepare_raw_management(&mut pair.a, at)?.is_none());
        let pending = pair
            .ad
            .common
            .as_ref()
            .and_then(|runtime| runtime.raw_control.as_ref())
            .ok_or("retained management")?;
        assert_eq!((pending.deadline, pending.bytes), (deadline, bytes));
        assert_eq!(&pair.ad.buffers.control_wire[..bytes], body);
        assert_eq!(pair.ad.records.next_number(Class::Control), number);
        assert_eq!(pair.ad.bucket.tokens, tokens);
    }
    let error = pair
        .ad
        .prepare_raw_management(&mut pair.a, cap)
        .err()
        .ok_or("original management cap was renewed")?;
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(pair.ad.records.next_number(Class::Control), number);
    assert_eq!(pair.ad.bucket.tokens, tokens);
    Ok(())
}

#[tokio::test]
async fn compact_raw_pending_plaintext_keeps_native_body_without_nonce_or_repeated_debit_or_renewal()
-> Result {
    let mut pair = Box::pin(selected_runtime_pair(
        false,
        security::compact::Protection::Aes128Ccm4,
    ))
    .await?;
    let mut now = clock(pair.ad.origin, Instant::now())? + 1;
    hold_management(&mut pair, now)?;
    let (native, host) = device()?;
    let mut native = AsyncFd::with_interest(native, Interest::READABLE.add(Interest::WRITABLE))?;
    let packet = ethernet(77);
    host.send(&packet).await?;
    let mut ready =
        tokio::time::timeout(Duration::from_secs(1), native.ready_mut(Interest::READABLE))
            .await??;
    let mut input = [0; READ_BUFFER_BYTES];
    assert!(pair.ad.read_native(&mut ready, &mut input, || Ok(now))?);
    drop(ready);
    let number = pair.ad.records.next_number(Class::User);
    let accepted = pair.ad.counters.socket_accepted_packets;
    let before_tokens = pair.ad.bucket.tokens;
    for _ in 0..64 {
        now += 1000;
        let instant = pair.ad.origin + duration(now);
        assert!(!pair.ad.send_common_carrier(&mut pair.a, now, || instant)?);
        if pair
            .ad
            .common
            .as_ref()
            .is_some_and(|runtime| runtime.unsealed.is_some())
        {
            break;
        }
    }
    let runtime = pair.ad.common.as_ref().ok_or("Common runtime")?;
    let pending = runtime
        .unsealed
        .as_ref()
        .ok_or("actual native emission did not wait for raw lane")?;
    let identity = (
        pending.scope,
        pending.number,
        pending.bytes,
        pending.cost,
        pending.deadline,
    );
    let body = runtime.wire[..pending.bytes].to_vec();
    assert!(runtime.sealed.is_none());
    assert_eq!(pending.number, number);
    assert_eq!(pair.ad.records.next_number(Class::User), number);
    let tokens = pair.ad.bucket.tokens;
    assert_eq!(before_tokens - tokens, pending.cost as u128 * SCALE);
    let retry_cap = clock(
        pair.ad.origin,
        pair.a.deadline().ok_or("held raw control cap")?,
    )?
    .min(pending.deadline);
    for at in [now + 1, retry_cap - 1] {
        let instant = pair.ad.origin + duration(at);
        assert!(!pair.ad.send_common_carrier(&mut pair.a, at, || instant)?);
        let runtime = pair.ad.common.as_ref().ok_or("Common runtime")?;
        let pending = runtime.unsealed.as_ref().ok_or("retained native body")?;
        assert_eq!(
            (
                pending.scope,
                pending.number,
                pending.bytes,
                pending.cost,
                pending.deadline
            ),
            identity
        );
        assert_eq!(&runtime.wire[..pending.bytes], body);
        assert!(runtime.sealed.is_none());
        assert_eq!(pair.ad.records.next_number(Class::User), number);
        assert_eq!(pair.ad.bucket.tokens, tokens);
    }
    let at = identity.4;
    let instant = pair.ad.origin + duration(at);
    let error = pair
        .ad
        .send_common_carrier(&mut pair.a, at, || instant)
        .err()
        .ok_or("original native body cap was renewed")?;
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(error.to_string(), "original Common body cap");
    assert_eq!(pair.ad.records.next_number(Class::User), number);
    assert_eq!(pair.ad.counters.socket_accepted_packets, accepted);
    assert_eq!(pair.ad.bucket.tokens, tokens);
    Ok(())
}
