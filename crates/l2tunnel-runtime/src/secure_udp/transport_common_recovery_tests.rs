//! Same real UDP/native owners survive explicitly refused pre-accept writes.
use super::*;

async fn protected_control(fixture: &mut Fixture, side: usize) -> Result<Vec<u8>> {
    // Reach the actual unchanged Ping wake, not a manufactured Control body.
    fixture.now = fixture.now.max(fixture.endpoints[side].driver.next_ping);
    let now = fixture.now;
    let endpoint = &mut fixture.endpoints[side];
    endpoint.driver.bucket.refill(now)?;
    endpoint.driver.submit_control(now)?;
    let bytes = endpoint
        .driver
        .prepare_control(now)?
        .ok_or("actual fixed Control output missing")?;
    let packet = endpoint.driver.buffers.wire[..bytes].to_vec();
    endpoint
        .driver
        .handed(&endpoint.socket, bytes, performance::WireKind::Control)?;
    let target = &mut fixture.endpoints[1 - side];
    let mut input = [0; 1501];
    let length =
        tokio::time::timeout(Duration::from_secs(1), target.socket.recv(&mut input)).await??;
    assert_eq!(&input[..length], packet);
    target
        .driver
        .receive_selected(&input[..length], now, target.driver.origin + duration(now))?;
    Ok(packet)
}

#[test]
fn same_flow_retry_retains_actual_packed_token_native_debt_and_leased_operation() -> Result {
    // Avoid an extra by-value copy of this large fixture future in block_on.
    // The test retains the default thread stack and all original owner checks.
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(Box::pin(async {
            for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
                let mut fixture = Fixture::new(kind)?.await?;
                let contract = fixture.endpoints[0]
                    .driver
                    .common
                    .as_ref()
                    .ok_or("common absent")?
                    .contract
                    .clone();
                let packed = contract
                    .catalog()
                    .configurations(contract.envelope())?
                    .into_iter()
                    .find(|value| {
                        matches!(
                            value.descriptor().profile(),
                            l2tunnel::record_configuration::Profile::Packed { .. }
                        )
                    })
                    .ok_or("actual Packed member absent")?;
                fixture.switch(packed).await?;
                let old = frame(40_000, 41);
                let next_packet = frame(40_000, 42);
                fixture.admit(0, &old).await?;
                let mut held = None;
                for _ in 0..100 {
                    fixture.turn_with_held_native(Some(1)).await?;
                    if let Some(front) = fixture.endpoints[1].driver.native.common()?.front() {
                        held = Some((*front.metadata(), front.since(), front.bytes().to_vec()));
                        break;
                    }
                }
                let (native, since, native_bytes) = held.ok_or("actual native debt absent")?;
                let replay = protected_control(&mut fixture, 1).await?;
                fixture.admit(0, &next_packet).await?;
                let (reply, mut result) = oneshot::channel();
                fixture.endpoints[0].driver.request_common(
                    fixture.now,
                    contract.initial(),
                    reply,
                )?;
                fixture.endpoints[0]
                    .driver
                    .admit_common(|| Ok(duration(fixture.now)))?;
                let operation = fixture.endpoints[0]
                    .driver
                    .common_state()?
                    .peer()
                    .operation()
                    .ok_or("real operation absent")?;
                let session = fixture.endpoints[0].driver.info.binding;
                let bank = std::ptr::from_ref(fixture.endpoints[0].driver.common_state()?) as usize;
                let mut refused = false;
                for _ in 0..16 {
                    fixture.now += 1000;
                    let driver = &mut fixture.endpoints[0].driver;
                    driver.progress_common(fixture.now)?;
                    driver.send_common_user_with(fixture.now, |_| {
                        Err(io::ErrorKind::ConnectionRefused.into())
                    })?;
                    if driver
                        .common
                        .as_ref()
                        .ok_or("common absent")?
                        .path
                        .unavailable
                    {
                        refused = true;
                        break;
                    }
                }
                assert!(refused, "actual retained source was not ready");
                let now = fixture.now;
                let endpoint = &mut fixture.endpoints[0];
                let driver = &mut endpoint.driver;
                let runtime = driver.common.as_ref().ok_or("common absent")?;
                let pending = runtime.sealed.as_ref().ok_or("real ciphertext absent")?;
                let token = pending
                    .carrier
                    .as_ref()
                    .ok_or("real Packed physical output token absent")?;
                let token_identity = (token.generation(), token.context(), token.emission());
                let identity = (
                    pending.scope,
                    pending.sealed,
                    pending.cost,
                    pending.deadline,
                );
                let wire = runtime.wire[..pending.sealed.bytes].to_vec();
                let debit = driver.bucket.tokens;
                let packets = driver.counters.wire_packets;
                let next_number = driver.records.next_number(Class::User);
                let written = driver.counters.socket_accepted_packets;
                assert!(!driver.can_admit_native()?);
                let retry_at = runtime.path.retry_at_micros.ok_or("retry time absent")?;
                assert!(retry_at > now);
                let mut early_socket_call = false;
                assert!(!driver.flush_common_wire_with(retry_at - 1, |_| {
                    early_socket_call = true;
                    Err(io::ErrorKind::WouldBlock.into())
                })?);
                assert!(!early_socket_call, "early retry reached socket");
                assert!(!driver.flush_common_wire_with(retry_at, |_| Err(
                    io::ErrorKind::NetworkDown.into()
                ))?);
                let runtime = driver.common.as_ref().ok_or("common absent")?;
                let pending = runtime.sealed.as_ref().ok_or("retained ciphertext lost")?;
                let token = pending.carrier.as_ref().ok_or("physical token lost")?;
                assert_eq!(
                    (token.generation(), token.context(), token.emission()),
                    token_identity
                );
                assert_eq!(
                    (
                        pending.scope,
                        pending.sealed,
                        pending.cost,
                        pending.deadline
                    ),
                    identity
                );
                assert_eq!(&runtime.wire[..pending.sealed.bytes], wire);
                assert_eq!(
                    (runtime.path.send_failures, runtime.path.retry_attempts),
                    (2, 1)
                );
                assert_eq!(
                    (driver.bucket.tokens, driver.counters.wire_packets),
                    (debit, packets)
                );
                assert_eq!(driver.records.next_number(Class::User), next_number);
                assert_eq!(driver.counters.socket_accepted_packets, written);
                assert_eq!(driver.common_state()?.peer().operation(), Some(operation));
                assert_eq!(std::ptr::from_ref(driver.common_state()?) as usize, bank);
                let rejected_before = driver.counters.replay_rejections;
                driver.receive_selected(&replay, retry_at, driver.origin + duration(retry_at))?;
                assert_eq!(driver.counters.replay_rejections, rejected_before + 1);
                assert!(
                    driver
                        .common
                        .as_ref()
                        .ok_or("common absent")?
                        .path
                        .unavailable
                );
                let (reply, mut refused_request) = oneshot::channel();
                driver.request_common(retry_at, packed, reply)?;
                assert_eq!(refused_request.try_recv()?, Err(SwitchError::Busy));
                let retry_at = driver
                    .common
                    .as_ref()
                    .ok_or("common absent")?
                    .path
                    .retry_at_micros
                    .ok_or("retry time absent")?;
                let resumed_debit = driver.bucket.tokens;
                assert!(
                    driver.flush_common_wire_with(retry_at, |bytes| endpoint
                        .socket
                        .try_send(bytes))?
                );
                assert_eq!(driver.bucket.tokens, resumed_debit);
                assert_eq!(driver.records.next_number(Class::User), next_number);
                assert_eq!(driver.counters.socket_accepted_packets, written + 1);
                assert_eq!(
                    driver
                        .common
                        .as_ref()
                        .ok_or("common absent")?
                        .path
                        .retry_attempts,
                    2
                );
                assert!(
                    driver
                        .common
                        .as_ref()
                        .ok_or("common absent")?
                        .path
                        .unavailable,
                    "local physical send is not authenticated peer recovery"
                );
                fixture.now = retry_at;
                let target = &mut fixture.endpoints[1];
                let mut input = [0; 1501];
                let length =
                    tokio::time::timeout(Duration::from_secs(1), target.socket.recv(&mut input))
                        .await??;
                assert_eq!(&input[..length], wire);
                target.driver.receive_selected(
                    &input[..length],
                    retry_at,
                    target.driver.origin + duration(retry_at),
                )?;
                let front = target
                    .driver
                    .native
                    .common()?
                    .front()
                    .ok_or("old native tuple lost")?;
                assert_eq!(
                    (
                        front.metadata().token,
                        front.metadata().origin,
                        front.since()
                    ),
                    (native.token, native.origin, since)
                );
                assert_eq!(front.bytes(), native_bytes);
                for _ in 0..100 {
                    fixture.turn_with_held_native(Some(1)).await?;
                    if !fixture.endpoints[0]
                        .driver
                        .common
                        .as_ref()
                        .ok_or("common absent")?
                        .path
                        .unavailable
                    {
                        break;
                    }
                }
                let driver = &fixture.endpoints[0].driver;
                assert_eq!(driver.info.binding, session);
                assert_eq!(std::ptr::from_ref(driver.common_state()?) as usize, bank);
                assert_eq!(driver.common_state()?.peer().operation(), Some(operation));
                let recovery = driver.snapshot_common(fixture.now, true)?.path_recovery;
                assert!(!recovery.unavailable);
                assert_eq!((recovery.send_failures, recovery.resumptions), (2, 1));
                assert!(recovery.retry_attempts >= 2);
                assert_eq!(recovery.retry_at_micros, None);
                assert!(matches!(
                    result.try_recv(),
                    Err(oneshot::error::TryRecvError::Empty)
                ));
                let mut completed = false;
                for _ in 0..1000 {
                    fixture.turn().await?;
                    if let Ok(answer) = result.try_recv() {
                        assert!(answer.is_ok());
                        completed = true;
                        break;
                    }
                }
                assert!(completed, "same retained transaction did not settle");
                let target = &fixture.endpoints[1];
                let mut actual = Vec::new();
                let mut output = [0; 1024];
                for _ in 0..4 {
                    match target.host.recv(&mut output) {
                        Ok(length) => actual.push(output[..length].to_vec()),
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) => return Err(error.into()),
                    }
                }
                assert_eq!(actual, vec![old, next_packet]);
                assert_eq!(target.driver.counters.native_written, 2);
                for endpoint in &fixture.endpoints {
                    assert_eq!(
                        (endpoint.socket.local_addr()?, endpoint.socket.peer_addr()?),
                        endpoint.original
                    );
                    assert_eq!(endpoint.driver.terminal, None);
                }
            }
            Ok(())
        }))
}

#[test]
fn same_flow_retry_keeps_original_cap_and_permanent_error_is_terminal() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            for error in [
                io::ErrorKind::HostUnreachable,
                io::ErrorKind::NetworkUnreachable,
            ] {
                let mut fixture = Fixture::new(cover::Appearance::QuicLike)?.await?;
                fixture.admit(0, &frame(40_000, 83)).await?;
                let now = fixture.now;
                let driver = &mut fixture.endpoints[0].driver;
                let contract = driver
                    .common
                    .as_ref()
                    .ok_or("common absent")?
                    .contract
                    .clone();
                let target = contract
                    .catalog()
                    .configurations(contract.envelope())?
                    .into_iter()
                    .find(|value| *value != contract.initial())
                    .ok_or("target absent")?;
                let (reply, mut queued) = oneshot::channel();
                driver.request_common(now, target, reply)?;
                let cap = driver
                    .common
                    .as_ref()
                    .ok_or("common absent")?
                    .request
                    .as_ref()
                    .ok_or("queued request absent")?
                    .cap;
                driver.bucket.refill(now)?;
                assert!(!driver.send_common_user_with(now, |_| Err(error.into()))?);
                let pending = driver
                    .common
                    .as_ref()
                    .ok_or("common absent")?
                    .sealed
                    .as_ref()
                    .ok_or("real seal absent")?;
                let identity = (pending.scope, pending.sealed, pending.deadline);
                let debit = driver.bucket.tokens;
                let next_number = driver.records.next_number(Class::User);
                driver.admit_common(|| Ok(Duration::from_millis(cap.0)))?;
                assert_eq!(queued.try_recv()?, Err(SwitchError::Rejected));
                assert!(
                    driver
                        .common
                        .as_ref()
                        .ok_or("common absent")?
                        .request
                        .is_none()
                );
                assert!(driver.common_state()?.peer().operation().is_none());
                assert_eq!(*driver.common_state()?.current(), contract.initial());
                let at = driver
                    .common
                    .as_ref()
                    .ok_or("common absent")?
                    .path
                    .retry_at_micros
                    .ok_or("retry absent")?
                    .max(u64::try_from(Duration::from_millis(cap.0).as_micros())?);
                assert_eq!(
                    driver
                        .flush_common_wire_with(at, |_| Err(io::ErrorKind::PermissionDenied.into()))
                        .err()
                        .ok_or("permanent send error was not returned")?
                        .kind(),
                    io::ErrorKind::PermissionDenied
                );
                assert_eq!(identity.2, driver.lease);
                let mut expired_socket_call = false;
                assert!(!driver.flush_common_wire_with(identity.2, |_| {
                    expired_socket_call = true;
                    Err(io::ErrorKind::WouldBlock.into())
                })?);
                assert!(!expired_socket_call, "expired retry reached socket");
                assert_eq!(driver.terminal, Some(StopReason::LeaseExpired));
                let pending = driver
                    .common
                    .as_ref()
                    .ok_or("common absent")?
                    .sealed
                    .as_ref()
                    .ok_or("original seal lost")?;
                assert_eq!((pending.scope, pending.sealed, pending.deadline), identity);
                assert_eq!(driver.bucket.tokens, debit);
                assert_eq!(driver.records.next_number(Class::User), next_number);
                assert_eq!(driver.counters.socket_accepted_packets, 0);
            }
            Ok(())
        })
}
