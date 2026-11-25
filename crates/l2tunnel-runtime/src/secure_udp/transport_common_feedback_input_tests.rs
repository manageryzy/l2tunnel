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
    driver.receive_selected(&packet[..length], now, at)?;
    Ok(now)
}

#[tokio::test]
async fn actual_udp_metrics_require_receipt_identity_and_preserve_late_acceptance() -> Result {
    for wrong_identity in [true, false] {
        let kind = cover::Appearance::QuicLike;
        let (contracts, _) = super::compact::selected_compact(kind)?;
        let fixture = Fixture::from_contracts_with_tail(kind, contracts, false).await?;
        let [mut a, b] = fixture.endpoints;
        let path = std::env::temp_dir().join(format!(
            "l2tunnel-receipt-metrics-{}-{wrong_identity}.json",
            std::process::id()
        ));
        a.driver
            .common
            .as_deref_mut()
            .ok_or("Common owner")?
            .wire_metrics = Some(common::wire_metrics::Observer::for_test(
            path.clone(),
            1500,
        )?);
        let buffer_path = path.with_extension("bmetrics");
        a.driver
            .common
            .as_deref_mut()
            .ok_or("Common owner")?
            .buffer_metrics = Some(crate::buffer_metrics::Observer::for_test(
            a.driver.origin,
            buffer_path.clone(),
        )?);
        let now = clock(a.driver.origin, Instant::now())?;
        let epoch = a.driver.common_state()?.epoch();
        a.driver
            .common_state_mut()?
            .entry(epoch)?
            .enqueue_borrowed(engine::Tick(now), &frame(28_802, 92))?;
        let active = a.driver.common_state()?.current();
        let local = active
            .descriptor()
            .local(common_contract::mg_role(a.driver.info.role));
        let needed = common_contract::maximum_body(local.send(), local.receive())?
            .checked_add(a.driver.config.control.wire_overhead)
            .and_then(|bytes| bytes.checked_add(a.driver.reserve))
            .ok_or("actual wire requirement overflow")?;
        let ready = a.driver.bucket.ready_at(needed)?;
        tokio::time::sleep_until(a.driver.origin + duration(ready)).await;
        let now = clock(a.driver.origin, Instant::now())?;
        a.driver.progress_common(now)?;
        assert!(
            !a.driver
                .send_common_user_with(now, |_| Err(io::ErrorKind::WouldBlock.into()))?
        );
        assert!(
            !a.driver
                .send_common_user_with(now + 1, |_| Err(io::ErrorKind::WouldBlock.into()))?
        );
        let (identity, wire) = {
            let runtime = a.driver.common.as_deref().ok_or("Common owner")?;
            let pending = runtime
                .sealed
                .as_ref()
                .ok_or("actual retained ciphertext")?;
            assert!(runtime.wire_sample.is_some());
            assert_eq!(
                runtime
                    .wire_metrics
                    .as_ref()
                    .ok_or("metrics observer")?
                    .accepted_record_totals_for_test(),
                (0, 0),
                "WouldBlock cannot count as acceptance"
            );
            (
                carrier::UserIdentity {
                    scope: pending.scope,
                    number: pending.sealed.number,
                    bytes: pending.sealed.bytes,
                    deadline: a.driver.origin + duration(pending.deadline),
                },
                runtime.wire[..pending.sealed.bytes].to_vec(),
            )
        };
        let mut socket_owner: carrier::IoOwner = carrier::IoOwner::from(a.socket);
        let receipt = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let carrier::IoOwner::Udp(socket) = &socket_owner else {
                    return Err(io::Error::other("real UDP owner changed"));
                };
                socket.writable().await?;
                match socket_owner.try_user(identity, &wire) {
                    Ok(carrier::SendProgress::Whole { receipt, late }) => {
                        assert!(!late);
                        return Ok(receipt);
                    }
                    Ok(carrier::SendProgress::Pending) => {
                        return Err(io::Error::other("UDP admission was not a whole write"));
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error),
                }
            }
        })
        .await??;
        let mut received = [0; 1501];
        let bytes =
            tokio::time::timeout(Duration::from_secs(1), b.socket.recv(&mut received)).await??;
        assert_eq!(&received[..bytes], wire);
        assert!(receipt.accepted_at < identity.deadline);
        let before = a.driver.counters;
        let mut supplied = identity;
        if wrong_identity {
            supplied.number = security::PacketNumber(
                supplied
                    .number
                    .0
                    .checked_add(1)
                    .ok_or("packet number exhausted")?,
            );
        }
        // Use the unchanged original deadline as the delayed observation clock.
        // The actual whole-send receipt and its acceptance time stay untouched.
        let error = a
            .driver
            .complete_common_carrier(supplied, receipt, false, || identity.deadline)
            .err()
            .ok_or("wrong identity or original-cap observation must fail")?;
        assert_eq!(
            error.kind(),
            if wrong_identity {
                io::ErrorKind::InvalidData
            } else {
                io::ErrorKind::TimedOut
            }
        );
        let runtime = a.driver.common.as_deref_mut().ok_or("Common owner")?;
        let metrics = runtime.wire_metrics.take().ok_or("metrics observer")?;
        assert_eq!(
            metrics.accepted_record_totals_for_test(),
            if wrong_identity {
                (0, 0)
            } else {
                (1, identity.bytes as u128)
            }
        );
        assert!(runtime.sealed.is_none());
        assert_eq!(
            a.driver.counters.socket_accepted_packets,
            before.socket_accepted_packets + 1,
            "the real whole write remains an irreversible physical fact"
        );
        assert_eq!(
            a.driver.counters.socket_accepted_ip_bytes,
            before.socket_accepted_ip_bytes
                + u64::try_from(receipt.socket_ip_bytes.ok_or("actual UDP IP bytes")?)?
        );
        assert_eq!(socket_owner.addresses()?, a.original);
        let terminal_at = clock(a.driver.origin, identity.deadline)?;
        let buffer = a
            .driver
            .common
            .as_deref_mut()
            .ok_or("Common owner")?
            .buffer_metrics
            .as_mut()
            .ok_or("buffer observer")?;
        let key = crate::buffer_metrics::Key {
            site: crate::buffer_metrics::Site::CommonUserSlot,
            lane: crate::buffer_metrics::Lane::Shared,
            class: crate::buffer_metrics::Class::Shared,
        };
        let waiting = buffer
            .collector()
            .reason(key, crate::buffer_metrics::Reason::SocketWrite, terminal_at)
            .map_err(|_| "metric clock")?;
        assert_eq!(waiting.refusals, 2);
        assert_eq!(waiting.blocked.episodes, 1);
        assert_eq!(
            waiting.blocked.completed_episodes,
            u64::from(!wrong_identity)
        );
        assert_eq!(waiting.blocked.open_us.is_some(), wrong_identity);
        buffer.finish_at(terminal_at);
        let frozen = buffer
            .collector()
            .reason(key, crate::buffer_metrics::Reason::SocketWrite, terminal_at)
            .map_err(|_| "metric clock")?;
        assert_eq!(frozen.blocked.censored_episodes, u64::from(wrong_identity));
        drop(
            a.driver
                .common
                .as_deref_mut()
                .ok_or("Common owner")?
                .buffer_metrics
                .take(),
        );
        drop(metrics);
        std::fs::remove_file(path)?;
        std::fs::remove_file(buffer_path)?;
    }
    Ok(())
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
    let mut socket_owner: carrier::IoOwner = carrier::IoOwner::from(a.socket);
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

#[tokio::test]
async fn actual_common_protocol_buffers_sample_real_engine_before_terminal_freeze() -> Result {
    let kind = cover::Appearance::QuicLike;
    let (contracts, _) = super::compact::selected_compact(kind)?;
    let fixture = Fixture::from_contracts_with_tail(kind, contracts, false).await?;
    let [mut a, _b] = fixture.endpoints;
    let path = std::env::temp_dir().join(format!(
        "l2tunnel-protocol-buffer-terminal-{}.bmetrics",
        std::process::id()
    ));
    let mut observer = crate::buffer_metrics::Observer::for_test(a.driver.origin, path.clone())?;
    let role = common_contract::mg_role(a.driver.info.role);
    let current = a.driver.common_state()?.current();
    let expected_digest = current.digest()?;
    observer.configure_protocol_buffers(1, role)?;
    let local = current.descriptor().local(role);
    let needed = common_contract::maximum_body(local.send(), local.receive())?
        .checked_add(a.driver.config.control.wire_overhead)
        .and_then(|bytes| bytes.checked_add(a.driver.reserve))
        .ok_or("actual wire requirement overflow")?;
    a.driver
        .common
        .as_deref_mut()
        .ok_or("Common owner")?
        .buffer_metrics = Some(observer);
    let now = clock(a.driver.origin, Instant::now())?.max(a.driver.bucket.ready_at(needed)?);
    a.driver.sample_common_buffers(now);
    let epoch = a.driver.common_state()?.epoch();
    a.driver
        .common_state_mut()?
        .entry(epoch)?
        .enqueue_borrowed(engine::Tick(now + 1), &frame(28_880, 71))?;
    // Enqueue retains a MUX item. The production send path must actually admit
    // that item into the codec and poll its first recovery output before sampling.
    a.driver.bucket.refill(now + 2)?;
    assert!(
        !a.driver
            .send_common_user_with(now + 2, |_| Err(io::ErrorKind::WouldBlock.into()))?
    );
    let first = a
        .driver
        .common_state_mut()?
        .entry(epoch)?
        .pending_carrier_output()
        .ok_or("actual first recovery emission")?;
    assert_eq!(
        first.emission().kind,
        engine::EmissionKind::Source(engine::SourceForm::DirectArq)
    );
    a.driver.sample_common_buffers(now + 50_000); // The periodic cadence must skip this observation.
    a.driver.finish_buffer_metrics(now + 50_000); // Forced sample precedes the terminal freeze.
    let metrics = a
        .driver
        .common
        .as_deref_mut()
        .ok_or("Common owner")?
        .buffer_metrics
        .as_mut()
        .ok_or("observer")?;
    assert!(metrics.is_finished());
    assert!(metrics.protocol_buffers().is_none());
    drop(
        a.driver
            .common
            .as_deref_mut()
            .ok_or("Common owner")?
            .buffer_metrics
            .take(),
    );
    let json: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    std::fs::remove_file(path)?;
    assert_eq!(json["finished_at_us"], now + 50_000);
    assert_eq!(json["source_terminal_sample"]["boundary"], "loop_stop");
    assert_eq!(
        json["source_terminal_sample"]["source_unavailable_events"],
        0
    );
    let provider = &json["protocol_buffers"];
    assert_eq!(provider["identity_errors"], 0);
    assert_eq!(provider["staged_terminal_unavailable"], 0);
    let observed = &provider["epochs"][0];
    assert_eq!(observed["epoch"], epoch.0);
    let digest: String = expected_digest
        .0
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(observed["configuration_digest_hex"], digest);
    assert_eq!(observed["samples"], 2);
    assert_eq!(observed["last_sample_us"], now + 50_000);
    let row = &observed["owners"][0];
    assert_eq!(row["scope"], "endpoint-shared");
    assert_eq!(row["samples"], 2);
    let retention = row["gauges"]
        .as_array()
        .ok_or("actual gauges")?
        .iter()
        .find(|value| value["name"] == "arq_send_records")
        .ok_or("actual ARQ retention")?;
    assert!(retention["used"].as_u64().is_some_and(|used| used > 0));
    assert_eq!(retention["high_water"], retention["used"]);
    let wait = &row["staged_admission"];
    assert_eq!(wait["terminal_stage"], "pre_settlement_metric_stop");
    assert_eq!(wait["terminal_at_us"], now + 50_000);
    assert_eq!(wait["union"]["completed_episodes"], 0);
    assert_eq!(wait["union"]["censored_episodes"], 0);
    assert!(
        wait["pending"].is_null(),
        "nonempty retention alone must not open a wait"
    );
    Ok(())
}

#[tokio::test]
async fn dropped_common_future_samples_live_protocol_and_management_before_owner_release() -> Result
{
    use std::{future::Future, task::Poll};
    let kind = cover::Appearance::QuicLike;
    let (contracts, _) = super::compact::selected_compact(kind)?;
    let fixture = Fixture::from_contracts_with_tail(kind, contracts, false).await?;
    let [mut a, _b] = fixture.endpoints;
    tokio::time::pause();
    let path = std::env::temp_dir().join(format!(
        "l2tunnel-protocol-buffer-dropped-future-{}.bmetrics",
        std::process::id()
    ));
    let role = common_contract::mg_role(a.driver.info.role);
    let current = a.driver.common_state()?.current();
    let local = current.descriptor().local(role);
    let needed = common_contract::maximum_body(local.send(), local.receive())?
        .checked_add(a.driver.config.control.wire_overhead)
        .and_then(|bytes| bytes.checked_add(a.driver.reserve))
        .ok_or("actual wire requirement overflow")?;
    let ready = a.driver.origin + duration(a.driver.bucket.ready_at(needed)?);
    tokio::time::sleep_until(ready).await;
    let now = clock(a.driver.origin, Instant::now())?;
    let mut observer = crate::buffer_metrics::Observer::for_test(a.driver.origin, path.clone())?;
    observer.configure_protocol_buffers(1, role)?;
    observer.configure_management_buffers()?;
    a.driver.control.enable_buffer_metrics();
    a.driver
        .common
        .as_deref_mut()
        .ok_or("Common owner")?
        .buffer_metrics = Some(observer);
    a.driver.sample_common_buffers(now);
    let epoch = a.driver.common_state()?.epoch();
    a.driver
        .common_state_mut()?
        .entry(epoch)?
        .enqueue_borrowed(engine::Tick(now), &frame(28_881, 72))?;
    a.driver.progress_common(now)?;
    assert!(
        !a.driver
            .send_common_user_with(now, |_| Err(io::ErrorKind::WouldBlock.into()))?
    );
    assert!(
        a.driver
            .common_state_mut()?
            .entry(epoch)?
            .pending_carrier_output()
            .is_some()
    );
    let deadline = add(now, a.driver.config.lifetime.pong_timeout)?.min(a.driver.lease);
    let control_scope = envelope_scope(a.driver.records.control_scope());
    assert!(
        a.driver
            .control
            .submit(
                control_scope,
                control::Body::Ping { nonce: 92 },
                duration(now),
                duration(deadline),
                true
            )?
            .is_some()
    );
    let origin = a.driver.origin;
    let timing = crate::initialization_timing::Timing::try_new(
        crate::initialization_timing::Owner::CommonExecution,
        origin,
    )?;
    // This polled future owns the actual authenticated Driver and the same
    // production stack guard. Cancellation skips the operation continuation;
    // the guard freezes its entered interval before Driver source sampling.
    let mut running = Box::pin(async move {
        let mut execution = DriverExecution {
            driver: &mut a.driver,
            timing,
            initialization_failed: false,
            transferred: false,
        };
        let _never = execution
            .timing
            .measure_selection(
                origin + duration(now + 10_000),
                std::future::pending::<io::Result<()>>(),
                |_| crate::initialization_timing::SelectionWinner::IoError,
            )
            .await;
        drop(execution);
        drop(a);
    });
    std::future::poll_fn(|cx| {
        assert!(running.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    tokio::time::advance(Duration::from_micros(50_000)).await;
    let stopped = clock(origin, Instant::now())?;
    assert_eq!(stopped, now + 50_000);
    drop(running);
    let json: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    std::fs::remove_file(path)?;
    assert_eq!(json["finished_at_us"], stopped);
    let execution = &json["common_execution"];
    assert_eq!(execution["availability"], "observed");
    assert_eq!(execution["boundary"], "driver_future_drop");
    assert_eq!(execution["timing"]["checkpoint"], "driver_future_drop");
    assert_eq!(execution["timing"]["elapsed_us"], stopped);
    assert_eq!(execution["timing"]["invalid"], false);
    let stage = execution["timing"]["stages"]
        .as_array()
        .ok_or("execution stages")?
        .iter()
        .find(|stage| stage["stage"] == "CommonSelectPending")
        .ok_or("entered selected suspension")?;
    assert_eq!(stage["samples"], 1);
    assert_eq!(stage["censored"], 1);
    assert_eq!(stage["failed"], 0);
    assert_eq!(stage["sum_us"], 50_000);
    assert_eq!(stage["maximum_start_us"], now);
    assert_eq!(stage["maximum_end_us"], stopped);
    let selection = &execution["timing"]["selection"];
    assert_eq!(selection["completed"], 0);
    assert!(selection["maximum_lateness"].is_null());
    assert!(selection["pending_planned_wake_us"].is_null());
    assert_eq!(selection["interrupted"]["planned_wake_us"], now + 10_000);
    assert_eq!(selection["interrupted"]["observed_at_us"], stopped);
    assert!(
        execution["timing"]["diagnostic_heap_bytes"]
            .as_u64()
            .is_some_and(|bytes| bytes > 0)
    );
    assert_eq!(json["source_terminal_sample"]["boundary"], "driver_drop");
    assert_eq!(json["source_terminal_sample"]["attempted_at_us"], stopped);
    assert_eq!(
        json["source_terminal_sample"]["source_unavailable_events"],
        0
    );
    let protocol = &json["protocol_buffers"];
    assert_eq!(protocol["identity_errors"], 0);
    assert_eq!(protocol["staged_terminal_unavailable"], 0);
    let observed = &protocol["epochs"][0];
    assert_eq!(observed["epoch"], epoch.0);
    assert_eq!(observed["samples"], 2);
    assert_eq!(observed["last_sample_us"], stopped);
    let row = &observed["owners"][0];
    let retention = row["gauges"]
        .as_array()
        .ok_or("actual gauges")?
        .iter()
        .find(|value| value["name"] == "arq_send_records")
        .ok_or("actual ARQ retention")?;
    assert!(retention["used"].as_u64().is_some_and(|used| used > 0));
    assert_eq!(row["staged_admission"]["terminal_at_us"], stopped);
    assert_eq!(
        row["staged_admission"]["union"]["censored_episodes"], 0,
        "retained data without actual refusal cannot become a wait"
    );
    let management = &json["management_streams"];
    assert_eq!(management["samples"], 2);
    assert_eq!(management["last_sample_us"], stopped);
    assert_eq!(management["unavailable_samples"], 0);
    assert_eq!(
        management["frozen_submission_wait"]["terminal_at_us"],
        stopped
    );
    assert_eq!(
        management["frozen_submission_wait"]["terminal_kind"],
        "MetricStop"
    );
    assert_eq!(management["frozen_submission_wait"]["censored_episodes"], 0);
    assert!(
        json["invalid"]
            .as_object()
            .ok_or("invalid flags")?
            .values()
            .all(|value| value == false)
    );
    Ok(())
}

#[tokio::test]
async fn actual_common_swift_buffers_preserve_channels_and_terminal_sampling() -> Result {
    let kind = cover::Appearance::QuicLike;
    let fixture = Fixture::from_contracts_with_tail(kind, contracts(kind)?, false).await?;
    let [mut a, _b] = fixture.endpoints;
    let current = a.driver.common_state()?.current();
    let role = common_contract::mg_role(a.driver.info.role);
    let local = current.descriptor().local(role);
    let l2tunnel::record_configuration::DirectionProfile::Swift(send) = local.send().profile()
    else {
        return Err("fixture did not install actual Swift".into());
    };
    let l2tunnel::record_configuration::DirectionProfile::Swift(receive) =
        local.receive().profile()
    else {
        return Err("fixture did not install actual Swift peer".into());
    };
    let (send_channels, receive_channels) = (send.channels, receive.channels);
    assert!(
        send_channels > receive_channels,
        "fixture must exercise absent receive direction"
    );
    let expected_digest = current.digest()?;
    let needed = common_contract::maximum_body(local.send(), local.receive())?
        .checked_add(a.driver.config.control.wire_overhead)
        .and_then(|bytes| bytes.checked_add(a.driver.reserve))
        .ok_or("actual wire requirement overflow")?;
    let path = std::env::temp_dir().join(format!(
        "l2tunnel-swift-channel-buffers-{}.bmetrics",
        std::process::id()
    ));
    let mut observer = crate::buffer_metrics::Observer::for_test(a.driver.origin, path.clone())?;
    observer.configure_protocol_buffers(send_channels.max(receive_channels) + 1, role)?;
    a.driver
        .common
        .as_deref_mut()
        .ok_or("Common owner")?
        .buffer_metrics = Some(observer);
    let now = clock(a.driver.origin, Instant::now())?.max(a.driver.bucket.ready_at(needed)?);
    a.driver.sample_common_buffers(now);
    let epoch = a.driver.common_state()?.epoch();
    a.driver
        .common_state_mut()?
        .entry(epoch)?
        .enqueue_borrowed(engine::Tick(now + 1), &frame(28_881, 73))?;
    a.driver.bucket.refill(now + 2)?;
    let mut send_attempts = 0;
    assert!(!a.driver.send_common_user_with(now + 2, |_| {
        send_attempts += 1;
        Err(io::ErrorKind::WouldBlock.into())
    })?);
    assert_eq!(
        send_attempts, 1,
        "actual Swift ciphertext reached the carrier"
    );
    // Swift keeps its original source and exact prepared-output witness while
    // the runtime retains the authenticated ciphertext until carrier acceptance.
    let pending = a
        .driver
        .common
        .as_deref()
        .and_then(|runtime| runtime.sealed.as_ref())
        .ok_or("WouldBlock did not retain actual Swift ciphertext")?;
    assert!(pending.sealed.bytes > 0);
    assert!(!pending.feedback);
    a.driver.sample_common_buffers(now + 50_000);
    a.driver.finish_buffer_metrics(now + 50_000);
    drop(
        a.driver
            .common
            .as_deref_mut()
            .ok_or("Common owner")?
            .buffer_metrics
            .take(),
    );
    let json: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    std::fs::remove_file(path)?;
    assert_eq!(json["source_terminal_sample"]["boundary"], "loop_stop");
    let provider = &json["protocol_buffers"];
    assert_eq!(provider["unsupported_codec_samples"], 0);
    assert_eq!(provider["identity_errors"], 0);
    let observed = &provider["epochs"][0];
    assert_eq!(observed["epoch"], epoch.0);
    let digest: String = expected_digest
        .0
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(observed["configuration_digest_hex"], digest);
    assert_eq!(
        observed["samples"], 2,
        "periodic sampling was gated before the forced terminal sample"
    );
    assert_eq!(observed["last_sample_us"], now + 50_000);
    let rows = observed["owners"].as_array().ok_or("Swift rows")?;
    assert_eq!(rows.len(), send_channels.max(receive_channels) + 1);
    assert_eq!(rows[0]["scope"], "swift-shared-packing");
    let mut retained_sources = 0;
    for (channel, row) in rows.iter().skip(1).enumerate() {
        assert_eq!(row["scope"], "swift-channel");
        assert_eq!(row["channel"], channel);
        assert_eq!(row["send_present"], channel < send_channels);
        assert_eq!(row["receive_present"], channel < receive_channels);
        assert!(row["staged_admission"].is_null(), "occupancy is not a wait");
        let gauges = row["gauges"].as_array().ok_or("channel gauges")?;
        for gauge in gauges {
            if gauge["name"] == "swift_sender_source_records" {
                retained_sources += gauge["used"].as_u64().ok_or("source count")?;
            }
            if gauge["name"] == "swift_sender_repairs_due" {
                assert!(
                    gauge["capacity"].is_null(),
                    "repair work is not payload capacity"
                );
            }
            if channel >= receive_channels {
                assert!(
                    !gauge["name"]
                        .as_str()
                        .ok_or("gauge name")?
                        .starts_with("swift_receiver_")
                );
            }
        }
    }
    assert!(
        retained_sources > 0,
        "must sample actual admitted source custody"
    );
    Ok(())
}

#[path = "transport_common_swift_acceptance_tests.rs"]
mod swift_acceptance;

#[tokio::test]
async fn observed_actual_selection_preserves_shutdown_request_and_alternating_io_priority() -> Result
{
    use crate::initialization_timing::{Owner, Timing};
    let kind = cover::Appearance::QuicLike;
    let (contracts, _) = super::compact::selected_compact(kind)?;
    let fixture = Fixture::from_contracts_with_tail(kind, contracts, false).await?;
    let [mut a, b] = fixture.endpoints;
    let current = a.driver.common_state()?.current();
    let mut socket: carrier::IoOwner = carrier::IoOwner::from(a.socket);
    b.socket.send(b"readiness fixture").await?;
    let carrier::IoOwner::Udp(udp) = &socket else {
        return Err("UDP fixture".into());
    };
    tokio::time::timeout(Duration::from_secs(1), udp.readable()).await??;
    a.host.send(b"native readiness fixture")?;
    drop(tokio::time::timeout(Duration::from_secs(1), a.device.readable_mut()).await??);
    let origin = Instant::now();
    let mut timing = Timing::try_new(Owner::CommonExecution, origin)?;
    let (handle, requests) = common_channel();
    let mut requests = Requests::Common(Some(requests));
    let (reply, _receive) = oneshot::channel();
    handle
        .0
        .try_send(common::Command::Switch(*current, reply))
        .map_err(|_| "fixture request admission")?;
    let shutdown = std::future::ready(());
    tokio::pin!(shutdown);
    let selected = timing
        .measure_selection(
            origin,
            next_selected(
                &mut socket,
                &mut a.device,
                shutdown.as_mut(),
                &mut requests,
                Interest::READABLE,
                true,
                ReceiveInterest::Poll,
                SelectedWake {
                    at: origin,
                    work_ready: true,
                }
                .wait(None),
                true,
            ),
            Selected::winner,
        )
        .await;
    assert!(matches!(selected, Selected::Shutdown));
    drop(selected);
    let shutdown = std::future::pending::<()>();
    tokio::pin!(shutdown);
    let selected = timing
        .measure_selection(
            origin,
            next_selected(
                &mut socket,
                &mut a.device,
                shutdown.as_mut(),
                &mut requests,
                Interest::READABLE,
                true,
                ReceiveInterest::Poll,
                SelectedWake {
                    at: origin,
                    work_ready: true,
                }
                .wait(None),
                true,
            ),
            Selected::winner,
        )
        .await;
    assert!(matches!(
        selected,
        Selected::Request(Some(Request::Common(common::Command::Switch(..))))
    ));
    drop(selected);
    for native_first in [true, false] {
        let selected = timing
            .measure_selection(
                origin,
                next_selected(
                    &mut socket,
                    &mut a.device,
                    shutdown.as_mut(),
                    &mut requests,
                    Interest::READABLE,
                    true,
                    ReceiveInterest::Poll,
                    SelectedWake {
                        at: origin,
                        work_ready: true,
                    }
                    .wait(None),
                    native_first,
                ),
                Selected::winner,
            )
            .await;
        if native_first {
            assert!(matches!(selected, Selected::Io(Ok(IoEvent::Native(_)))));
        } else {
            assert!(matches!(selected, Selected::Io(Ok(IoEvent::Udp))));
        }
        drop(selected);
    }
    let selected = timing
        .measure_selection(
            origin,
            next_selected(
                &mut socket,
                &mut a.device,
                shutdown.as_mut(),
                &mut requests,
                Interest::READABLE,
                false,
                ReceiveInterest::Disabled,
                SelectedWake::timer(origin).wait(None),
                false,
            ),
            Selected::winner,
        )
        .await;
    assert!(matches!(selected, Selected::Io(Ok(IoEvent::Timer))));
    drop(selected);
    // With both I/O branches disabled, local work wins after its cooperative
    // yield and remains a distinct observation from an elapsed timer.
    let selected = timing
        .measure_selection(
            origin,
            next_selected(
                &mut socket,
                &mut a.device,
                shutdown.as_mut(),
                &mut requests,
                Interest::READABLE,
                false,
                ReceiveInterest::Disabled,
                SelectedWake {
                    at: origin,
                    work_ready: true,
                }
                .wait(None),
                false,
            ),
            Selected::winner,
        )
        .await;
    assert!(matches!(selected, Selected::Io(Ok(IoEvent::Work))));
    drop(selected);
    let mut bytes = Vec::new();
    timing.write_snapshot_at(Instant::now(), &mut bytes)?;
    let json: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(json["selection"]["completed"], 6);
    for winner in ["Shutdown", "Request", "Native", "Carrier", "Timer", "Work"] {
        let row = json["selection"]["winners"]
            .as_array()
            .ok_or("winner array")?
            .iter()
            .find(|row| row["winner"] == winner)
            .ok_or("actual winner")?;
        assert_eq!(row["count"], 1);
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn work_wake_yields_without_timer_advance_and_idle_wake_stays_pending() -> Result {
    let now = Instant::now();
    let work = SelectedWake {
        at: now,
        work_ready: true,
    };
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    let mut work_wait = std::pin::pin!(work.wait(None));
    assert!(std::future::Future::poll(work_wait.as_mut(), &mut cx).is_pending());
    assert!(std::future::Future::poll(work_wait.as_mut(), &mut cx).is_ready());
    assert_eq!(Instant::now(), now);
    let idle = SelectedWake::timer(now + duration(100));
    let mut idle_wait = std::pin::pin!(idle.wait(None));
    assert!(std::future::Future::poll(idle_wait.as_mut(), &mut cx).is_pending());
    assert!(std::future::Future::poll(idle_wait.as_mut(), &mut cx).is_pending());
    assert_eq!(Instant::now(), now);
    Ok(())
}
