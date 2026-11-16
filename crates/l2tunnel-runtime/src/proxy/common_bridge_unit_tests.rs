//! Existing Bridge and maintained Aligned unit grammar; physical facts injected.
//! No authentication, kernel raw path or peer-delivery claim is made here.
use super::*;
use l2tunnel_codec::{
    aligned_body, aligned_envelope, aligned_receiver as receiver, aligned_sender,
};
use l2tunnel_core::Epoch;
use std::future::Future;
use tokio::io::AsyncWriteExt;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}
fn actual_units(bytes: &[u8]) -> Result<Vec<UnitWitness>> {
    let body = aligned_body::Config {
        max_frame_bytes: 256,
        symbol_bytes: 32,
        elide_payload_length: false,
        predictive: false,
        timestamp_pair_dictionary: false,
        independent_short_frame_bytes: 0,
    };
    let scope = receiver::Scope {
        session: [7; 16],
        epoch: Epoch(9),
        direction: receiver::Direction::InitiatorToResponder,
    };
    let limits = receiver::Limits {
        body,
        channels: 1,
        first_record: receiver::RecordId(7),
        first_source: receiver::SourceId(0),
        record_window: 16,
        source_window: 16,
        lookahead_records: 2,
        lookahead_bytes: 1024,
        lookahead_fragments: 32,
        max_fragments_per_record: 16,
        lifetime_ticks: 1000,
    };
    let mut owner = aligned_sender::Sender::new(
        scope,
        aligned_sender::Config {
            body,
            channels: 1,
            first_record: limits.first_record,
        },
    )?;
    let identity = owner.stage_raw_identified(receiver::ChannelId(0), bytes)?;
    let mut units = Vec::new();
    while owner.is_pending() {
        let mut wire = [0; 80];
        let n = owner.write_pending(receiver::SourceId(units.len() as u64), &mut wire)?;
        let view = aligned_envelope::decode(scope, 32, 1, &wire[..n])?;
        let unit = receiver::unit_witness(view.identity, view.symbol, limits)?;
        assert_eq!(unit.identity, identity);
        units.push(unit);
        owner.commit_unit()?;
    }
    assert!(units.len() > 1);
    assert!(units.iter().all(|u| u.count == units.len()));
    Ok(units)
}
async fn sent(port: &mut RecordPort, stream: &mut Stream, bytes: &[u8]) -> Result {
    stream.write_all(bytes).await?;
    let mut flush = Box::pin(stream.flush());
    let mut output = [0; 257];
    for _ in 0..64 {
        assert!(once(flush.as_mut()).is_pending());
        if let Some(n) = port.receive(&mut output)? {
            assert_eq!(&output[..n], bytes);
            return Ok(());
        }
        tokio::task::yield_now().await;
    }
    Err("actual Bridge record did not reach port".into())
}
#[tokio::test(start_paused = true)]
async fn physical_units_release_one_record_only_after_all_unique_actual_units() -> Result {
    let bytes = [0, 0, 0, 61].into_iter().chain([7; 61]).collect::<Vec<_>>();
    let units = actual_units(&bytes)?;
    let (mut port, mut stream, bridge) = pair_retained(256, Duration::from_millis(20))?;
    bridge.enable_physical_receipts()?;
    bridge.prepare_user_receipt(1).await?;
    sent(&mut port, &mut stream, &bytes).await?;
    bridge.admitted(units[0].identity)?;
    let first = bridge.timing()?.0;
    let cap = bridge.timing()?.1;
    assert_eq!(
        super::super::Config::new(
            crate::RuntimeConfig {
                layer: PacketLayer::Ip,
                max_packet: 1600,
                compression: crate::Compression::None,
                queue_packets: 4,
                poll_interval: Duration::from_millis(1)
            },
            l2tunnel_core::Duplex::Full,
            super::super::RoutePolicy::new(Vec::new())?
        )?
        .validate()?
        .common_bridge_metadata_bytes,
        Bridge::metadata_bytes()
    );
    for (offset, unit) in units.iter().rev().enumerate() {
        // Receipts intentionally arrive opposite physical acceptance order.
        let accepted = first + Duration::from_micros((unit.index + 1) as u64);
        tokio::time::advance(Duration::from_millis(1)).await;
        let observed = Instant::now();
        let result = bridge.complete_unit(*unit, accepted, observed)?;
        assert_eq!(
            result,
            if offset + 1 == units.len() {
                UnitCompletion::Complete
            } else {
                UnitCompletion::Pending
            }
        );
        if offset + 1 != units.len() {
            assert!(bridge.pending_physical_receipt()?.is_none());
            assert_eq!(bridge.retained_user_receipts()?.0, 0);
            assert!(matches!(
                Pin::new(&mut stream).poll_flush(&mut Context::from_waker(Waker::noop())),
                Poll::Pending
            ));
            assert_eq!(
                bridge.complete_unit(*unit, accepted, observed + Duration::from_micros(1))?,
                UnitCompletion::Duplicate
            );
            assert_eq!(bridge.timing()?.1, cap);
        }
    }
    let physical = bridge
        .pending_physical_receipt()?
        .ok_or("whole physical receipt")?;
    assert_eq!(
        physical.accepted_at,
        first + Duration::from_micros(units.len() as u64)
    );
    assert_eq!(
        physical.observed_at,
        first + Duration::from_millis(units.len() as u64)
    );
    assert_eq!(
        bridge.retained_user_receipts()?,
        (1, [Some(physical), None])
    );
    assert!(matches!(
        Pin::new(&mut stream).poll_flush(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(bridge.take_physical_receipt()?, physical);
    Ok(())
}
#[tokio::test(start_paused = true)]
async fn physical_unit_conflicts_and_late_last_fact_never_release_original_write() -> Result {
    let bytes = [0, 0, 0, 61].into_iter().chain([7; 61]).collect::<Vec<_>>();
    let units = actual_units(&bytes)?;
    // Every invalid witness fails before any receipt bit or count changes.
    for bad in [
        UnitWitness {
            index: usize::MAX,
            ..units[0]
        },
        UnitWitness {
            count: 0,
            ..units[0]
        },
        UnitWitness {
            count: MAX_UNITS + 1,
            ..units[0]
        },
        UnitWitness {
            identity: RecordIdentity {
                record: receiver::RecordId(8),
                ..units[0].identity
            },
            ..units[0]
        },
        UnitWitness {
            count: units.len() + 1,
            ..units[0]
        },
    ] {
        let (mut port, mut stream, bridge) = pair_retained(256, Duration::from_millis(10))?;
        sent(&mut port, &mut stream, &bytes).await?;
        bridge.admitted(units[0].identity)?;
        let first = bridge.timing()?.0;
        assert_eq!(
            bridge.complete_unit(units[0], first, first)?,
            UnitCompletion::Pending
        );
        assert!(bridge.complete_unit(bad, first, first).is_err());
        let state = bridge.lock()?;
        let pending = state.pending.as_ref().ok_or("pending physical owner")?;
        assert_eq!(pending.units.received, 1);
        assert!(!pending.completed && pending.physical.is_none());
    }
    // An earlier Common cap or saved semantic failure wins even while this
    // Bridge's own original stall cap is still healthy. The runtime latches
    // that actual kind before retaining its final physical unit fact.
    for kind in [io::ErrorKind::TimedOut, io::ErrorKind::InvalidData] {
        let (mut port, mut stream, bridge) = pair_retained(256, Duration::from_millis(10))?;
        bridge.enable_physical_receipts()?;
        bridge.prepare_user_receipt(1).await?;
        sent(&mut port, &mut stream, &bytes).await?;
        bridge.admitted(units[0].identity)?;
        let first = bridge.timing()?.0;
        for unit in &units[..units.len() - 1] {
            assert_eq!(
                bridge.complete_unit(*unit, first, first)?,
                UnitCompletion::Pending
            );
        }
        let cap = bridge.timing()?.1;
        let observed = first + Duration::from_millis(1);
        assert!(observed < cap);
        bridge.reject_completion(kind)?;
        let last = *units.last().ok_or("actual last unit")?;
        let error = bridge
            .complete_unit(last, first, observed)
            .err()
            .ok_or("rejected final unit must fail")?;
        assert_eq!(error.kind(), kind);
        let physical = bridge
            .pending_physical_receipt()?
            .ok_or("rejected whole physical fact")?;
        assert_eq!(physical.observed_at, observed);
        assert_eq!(
            bridge.retained_user_receipts()?,
            (1, [Some(physical), None])
        );
        assert_eq!(
            bridge
                .lock()?
                .pending
                .as_ref()
                .ok_or("pending owner")?
                .deadline,
            cap
        );
        assert!(
            !bridge
                .lock()?
                .pending
                .as_ref()
                .ok_or("pending owner")?
                .completed
        );
        assert!(
            matches!(Pin::new(&mut stream).poll_flush(&mut Context::from_waker(Waker::noop())),Poll::Ready(Err(error)) if error.kind()==kind)
        );
        assert!(bridge.take_physical_receipt().is_err());
    }
    let (mut port, mut stream, bridge) = pair_retained(256, Duration::from_millis(10))?;
    bridge.enable_physical_receipts()?;
    bridge.prepare_user_receipt(1).await?;
    sent(&mut port, &mut stream, &bytes).await?;
    bridge.admitted(units[0].identity)?;
    let first = bridge.timing()?.0;
    let cap = bridge.timing()?.1;
    for unit in &units[..units.len() - 1] {
        assert_eq!(
            bridge.complete_unit(*unit, first, first)?,
            UnitCompletion::Pending
        );
    }
    tokio::time::advance(Duration::from_millis(10)).await;
    let observed = Instant::now();
    let original = match Pin::new(&mut stream).poll_flush(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(Err(error)) => error,
        _ => return Err("original write must expire".into()),
    };
    assert_eq!(original.kind(), io::ErrorKind::TimedOut);
    let last = *units.last().ok_or("actual final unit")?;
    let error = bridge
        .complete_unit(last, first + Duration::from_millis(1), observed)
        .err()
        .ok_or("late completion failure")?;
    assert_eq!(error.to_string(), original.to_string());
    let physical = bridge
        .pending_physical_receipt()?
        .ok_or("late complete physical fact retained")?;
    assert_eq!(physical.accepted_at, first + Duration::from_millis(1));
    assert_eq!(physical.observed_at, observed);
    assert_eq!(
        bridge.retained_user_receipts()?,
        (1, [Some(physical), None])
    );
    assert_eq!(
        bridge
            .lock()?
            .pending
            .as_ref()
            .ok_or("pending owner")?
            .deadline,
        cap
    );
    assert!(bridge.take_physical_receipt().is_err());
    assert!(
        bridge
            .complete_unit(last, first + Duration::from_millis(2), observed)
            .is_err()
    );
    assert_eq!(bridge.pending_physical_receipt()?, Some(physical));
    Ok(())
}
