//! Actual-loop evidence that synchronous observation cannot extend operation custody.
//!
//! These local socket/device cases inject protocol time; they do not measure
//! physical WAN delivery or qualify native, platform or complete fault matrices.

use super::*;
use std::{future::poll_fn, task::Poll};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Effects {
    wire_packets: u64,
    wire_bytes: u64,
    socket_packets: u64,
    socket_ip_bytes: u64,
    native_read: u64,
    native_written: u64,
    outer: u32,
    control_number: u64,
    user_number: u64,
}

impl Effects {
    fn actual(driver: &Driver) -> Self {
        Self {
            wire_packets: driver.counters.wire_packets,
            wire_bytes: driver.counters.wire_bytes,
            socket_packets: driver.counters.socket_accepted_packets,
            socket_ip_bytes: driver.counters.socket_accepted_ip_bytes,
            native_read: driver.counters.native_read,
            native_written: driver.counters.native_written,
            outer: driver.outer,
            control_number: driver.records.next_number(Class::Control).0,
            user_number: driver.records.next_number(Class::User).0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Crossing {
    operation: transaction::Operation,
    cap_micros: u64,
    effects: Effects,
}

#[derive(Clone, Copy, Debug)]
struct FinalObservation {
    at: u64,
    terminal: Option<StopReason>,
    operation: Option<transaction::Operation>,
    effects: Effects,
}

async fn callback_crosses_actual_cap(kind: cover::Appearance) -> Result {
    let (parts, peer) = parts_pair(kind).await?;
    // Establish actual send readiness before the synchronous callback. Otherwise
    // lack of socket readiness could hide the old post-callback stale send path.
    parts.socket.writable().await?;
    let [contract, _] = contracts(kind)?;
    let target = contract
        .catalog()
        .configurations(contract.envelope())
        .into_iter()
        .find(|value| *value != contract.initial())
        .ok_or("deadline fixture lacks a distinct actual catalog value")?;
    let target_digest = transaction::configuration_digest(&target)?;
    let (handle, requests) = transaction_channel();
    let switch = handle.switch(target);
    tokio::pin!(switch);
    // Poll the genuine API once: its bounded channel receives the real request,
    // while its public completion future remains pending for the actual loop.
    poll_fn(|context| {
        assert!(switch.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
    let (native, host) = UnixDatagram::pair()?;
    native.set_nonblocking(true)?;
    host.set_nonblocking(true)?;
    let device = Device {
        socket: native,
        blocked: false,
        wouldblock: None,
    };
    let base = Instant::now();
    assert!(base < parts.deadline);
    let offset = Arc::new(AtomicU64::new(0));
    let sampled = Arc::clone(&offset);
    let mut crossing: Option<Crossing> = None;
    let mut final_observation = None;
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        Box::pin(run_selected_clock(
            device,
            parts,
            Start::Transaction(contract),
            Requests::Transaction(Some(requests)),
            None,
            std::future::pending::<()>(),
            |driver, at, running| {
                let owner::DataOwner::Generic(state) = &driver.owner else {
                    return Err(protocol("deadline fixture selected legacy owner"));
                };
                let operation = state.peer().operation();
                if running {
                    if let Some(crossing) = crossing {
                        assert!(
                            at < crossing.cap_micros,
                            "an expired semantic report published running=true"
                        );
                    } else if let Some(operation) = operation
                        && driver.control.retained().send_records > 0
                    {
                        assert_eq!(operation.ticket().digest, target_digest);
                        let request = driver
                            .generic
                            .as_ref()
                            .and_then(|runtime| runtime.request.as_ref())
                            .ok_or_else(|| protocol("actual operation lost its genuine request"))?;
                        assert_eq!(request.configuration, target);
                        assert_eq!(request.cap, operation.expires());
                        let cap_micros = operation
                            .expires()
                            .0
                            .checked_mul(1000)
                            .ok_or_else(exhausted)?;
                        assert!(at < cap_micros);
                        crossing = Some(Crossing {
                            operation,
                            cap_micros,
                            effects: Effects::actual(driver),
                        });
                        // The callback owns no Peer mutation or invented expiry:
                        // only subsequent injected samples reach its actual cap.
                        offset.store(cap_micros, Ordering::SeqCst);
                    }
                } else {
                    assert!(final_observation.is_none());
                    final_observation = Some(FinalObservation {
                        at,
                        terminal: driver.terminal,
                        operation,
                        effects: Effects::actual(driver),
                    });
                }
                Ok(())
            },
            move || base + Duration::from_micros(sampled.load(Ordering::SeqCst)),
        )),
    )
    .await?;
    let error = match result {
        Err(error) => error,
        Ok(_) => return Err("crossing the real operation cap did not fail the loop".into()),
    };
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    let crossing = crossing.ok_or("no semantic callback retained actual pending Control output")?;
    let final_observation = final_observation.ok_or("missing actual terminal observation")?;
    assert_eq!(final_observation.at, crossing.cap_micros);
    assert_eq!(final_observation.terminal, Some(StopReason::PolicyTimeout));
    assert_eq!(final_observation.operation, Some(crossing.operation));
    assert_eq!(
        final_observation.effects, crossing.effects,
        "a synchronous observer authorized another wire attempt, socket handoff, native action or security number after the original cap"
    );
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), switch).await?,
        Err(SwitchError::Closed)
    ));
    // Keep both real peer and host endpoints alive through loop termination;
    // their closure must not be the reason for this observed PolicyTimeout.
    drop((peer, host));
    Ok(())
}

#[test]
fn actual_semantic_observer_crossing_original_cap_stops_before_further_effects() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(Box::pin(async {
            for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
                callback_crosses_actual_cap(kind).await?;
            }
            Ok(())
        }))
}
