//! Actual protected UDP/whole-write receipts with deliberately delayed observation.
//! The imported real session fixture is not a new catalog-bound Noise/TLS proof.
use super::*;
use l2tunnel::record_engine as engine;

async fn read_one(socket: &tokio::net::UdpSocket, driver: &mut Driver) -> Result<u64> {
    let mut packet = [0; 1501];
    let cap = (driver.origin + duration(driver.lease)).min(Instant::now() + Duration::from_secs(1));
    let length = tokio::time::timeout_at(cap, socket.recv(&mut packet)).await??;
    let at = Instant::now();
    let now = clock(driver.origin, at)?;
    driver.receive_selected(&packet[..length], now, at, None)?;
    Ok(now)
}

#[tokio::test]
async fn actual_early_compact_feedback_keeps_original_input_until_delayed_whole_write_observation()
-> Result {
    let kind = cover::Appearance::QuicLike;
    let (contracts, _) = super::compact::selected_compact(kind)?;
    let fixture = Fixture::from_contracts_with_tail(kind, contracts, false).await?;
    let [mut a, mut b] = fixture.endpoints;
    // No simulated fixture turns have run: use the sole real clock origin for
    // both preparation and the actual carrier acceptance timestamp below.
    let now = clock(a.driver.origin, Instant::now())?;
    let epoch = a.driver.common_state()?.epoch();
    a.driver
        .common_state_mut()?
        .entry(epoch)?
        .enqueue_borrowed(engine::Tick(now), &frame(28_801, 91))?;
    let active = a.driver.common_state()?.current();
    let local = active
        .descriptor()
        .local(common_contract::mg_role(a.driver.info.role));
    let needed = common_contract::maximum_body(local.send(), local.receive())?
        .checked_add(a.driver.config.control.wire_overhead)
        .and_then(|n| n.checked_add(a.driver.reserve))
        .ok_or("actual wire requirement overflow")?;
    let ready = a.driver.bucket.ready_at(needed)?;
    tokio::time::sleep_until(a.driver.origin + duration(ready)).await;
    let now = clock(a.driver.origin, Instant::now())?;
    a.driver.progress_common(now)?;
    assert!(
        !a.driver
            .send_common_user_with(now, |_| { Err(io::Error::from(io::ErrorKind::WouldBlock)) })?
    );
    let (identity, original_wire, original_token, original_cap) = {
        let runtime = a.driver.common.as_ref().ok_or("Common owner")?;
        let pending = runtime.sealed.as_ref().ok_or("real sealed source")?;
        let token = pending.carrier.as_ref().ok_or("real source token")?;
        assert_eq!(
            token.emission().kind,
            engine::EmissionKind::Source(engine::SourceForm::DirectArq)
        );
        (
            carrier::UserIdentity {
                scope: pending.scope,
                number: pending.sealed.number,
                bytes: pending.sealed.bytes,
                deadline: a.driver.origin + duration(pending.deadline),
            },
            runtime.wire[..pending.sealed.bytes].to_vec(),
            token.emission(),
            pending.deadline,
        )
    };
    let original_usage = a.driver.common_state()?.usage();
    let original_charges = (a.driver.counters.wire_packets, a.driver.counters.wire_bytes);
    let next_user = a.driver.records.next_number(Class::User);
    let mut socket_owner: carrier::IoOwner = carrier::IoOwner::Udp(a.socket);
    let receipt = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let carrier::IoOwner::Udp(socket) = &socket_owner else {
                return Err(io::Error::other("real UDP owner changed"));
            };
            socket.writable().await?;
            match socket_owner.try_user(identity, &original_wire) {
                Ok(carrier::SendProgress::Whole { receipt, late }) => {
                    assert!(!late);
                    return Ok(receipt);
                }
                Ok(carrier::SendProgress::Pending) => {
                    return Err(io::Error::other("UDP admission was not whole write"));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
    })
    .await??;
    // Hold this real successful receipt, not a fabricated physical completion.
    read_one(&b.socket, &mut b.driver).await?;
    let feedback_at = b
        .driver
        .common_state()?
        .engine(epoch)?
        .feedback_opportunity()?
        .ok_or("actual receiver feedback opportunity")?
        .0
        .0;
    tokio::time::sleep_until(b.driver.origin + duration(feedback_at)).await;
    let now = clock(b.driver.origin, Instant::now())?;
    b.driver.progress_common(now)?;
    assert!(b.driver.send_common_user(&b.socket, now)?);
    let carrier::IoOwner::Udp(socket) = &socket_owner else {
        return Err("UDP owner changed".into());
    };
    let received = read_one(socket, &mut a.driver).await?;
    let (saved, exact_input, input_pointer) = {
        let runtime = a.driver.common.as_ref().ok_or("Common runtime")?;
        let pending = runtime
            .pending_feedback
            .ok_or("actual authenticated feedback was dropped")?;
        assert_eq!(pending.received, received);
        assert_eq!(pending.deadline, original_cap);
        assert_eq!(pending.scope, identity.scope);
        assert_eq!(&runtime.wire[..identity.bytes], original_wire);
        assert_eq!(
            runtime
                .sealed
                .as_ref()
                .and_then(|p| p.carrier.as_ref())
                .map(|t| t.emission()),
            Some(original_token)
        );
        (
            pending,
            runtime.feedback_input[..pending.bytes].to_vec(),
            runtime.feedback_input.as_ptr(),
        )
    };
    let now = clock(a.driver.origin, Instant::now())?;
    assert!(!a.driver.retry_common_feedback(now)?);
    assert_eq!(
        a.driver.common.as_ref().and_then(|r| r.pending_feedback),
        Some(saved)
    );
    assert!(!a.driver.common_state()?.engine(epoch)?.drained()?);
    // A genuine independent management Ping is accepted while User input waits.
    let nonce = 91;
    let now = clock(b.driver.origin, Instant::now())?;
    let deadline = add(now, b.driver.config.lifetime.pong_timeout)?.min(b.driver.lease);
    let control_scope = envelope_scope(b.driver.records.control_scope());
    assert!(
        b.driver
            .control
            .submit(
                control_scope,
                control::Body::Ping { nonce },
                duration(now),
                duration(deadline),
                true
            )?
            .is_some()
    );
    let before = b.driver.counters.socket_accepted_packets;
    let instant = Instant::now();
    b.driver.send_sampled(
        &b.socket,
        clock(b.driver.origin, instant)?,
        instant,
        Instant::now,
    )?;
    let emitted = b.driver.counters.socket_accepted_packets - before;
    assert!(emitted > 0);
    for _ in 0..emitted {
        let carrier::IoOwner::Udp(socket) = &socket_owner else {
            return Err("UDP owner changed".into());
        };
        read_one(socket, &mut a.driver).await?;
    }
    assert_eq!(a.driver.remote_ping, nonce);
    assert_eq!(
        a.driver.common.as_ref().and_then(|r| r.pending_feedback),
        Some(saved)
    );
    assert_eq!(a.driver.records.next_number(Class::User), next_user);
    assert_eq!(
        (a.driver.counters.wire_packets, a.driver.counters.wire_bytes),
        original_charges
    );
    let before = a.driver.counters;
    assert!(
        a.driver
            .complete_common_carrier(identity, receipt, false, Instant::now)?
    );
    let runtime = a.driver.common.as_ref().ok_or("retained Common runtime")?;
    assert!(runtime.pending_feedback.is_none());
    assert!(runtime.sealed.is_none());
    assert_eq!(runtime.feedback_input.as_ptr(), input_pointer);
    assert_eq!(&runtime.feedback_input[..saved.bytes], exact_input);
    assert_eq!(a.driver.common_state()?.usage(), original_usage);
    // This receipt releases its actual source/feedback dependency. Remaining
    // native-context records are not falsely treated as a drained generation.
    assert!(
        a.driver
            .common_state_mut()?
            .entry(epoch)?
            .pending_carrier_output()
            .is_none()
    );
    assert_eq!(a.driver.records.next_number(Class::User), next_user);
    assert_eq!(
        (a.driver.counters.wire_packets, a.driver.counters.wire_bytes),
        original_charges
    );
    assert_eq!(
        a.driver.counters.socket_accepted_packets,
        before.socket_accepted_packets + 1
    );
    assert_eq!(
        a.driver.counters.replay_rejections,
        before.replay_rejections
    );
    assert_eq!(a.driver.counters.rejected_packets, before.rejected_packets);
    assert!(clock(a.driver.origin, Instant::now())? > saved.received);
    assert_eq!(socket_owner.addresses()?, a.original);
    Ok(())
}
