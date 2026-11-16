//! The accepted service cap precedes another real paired PacketIo setup poll.
use super::*;

#[tokio::test(start_paused = true)]
async fn delayed_raw_half_setup_stops_before_io_at_original_accepted_cap() -> Result {
    let hosts = support::hosts();
    let (
        CarrierPlans {
            plans: [client, server],
            ..
        },
        probes,
    ) = raw_plans(&hosts)?;
    let (handle, run) = channel();
    let accepted = handle
        .connect(client, handle.next_key().map_err(submit)?)
        .map_err(submit)?;
    let deadline = accepted
        .deadline
        .ok_or("actual accepted setup cap absent")?;
    let mut run = Box::pin(run);
    // Delay real factory construction; its duration-based internal cap would
    // otherwise finish later than the already accepted service operation.
    tokio::time::advance(Duration::from_secs(1)).await;
    drive_once(&mut run).await;
    for index in [0, 2] {
        assert_eq!(probes[index].opened.load(Ordering::SeqCst), 1);
        assert!(probes[index].io_polls.load(Ordering::SeqCst) > 0);
        assert_eq!(probes[index].dropped.load(Ordering::SeqCst), 0);
    }
    assert!(support::completed(&handle, accepted.operation).is_none());
    let before_cap = deadline
        .checked_sub(Duration::from_micros(1))
        .ok_or("original cap subtraction")?;
    tokio::time::advance(before_cap.duration_since(tokio::time::Instant::now())).await;
    drive_once(&mut run).await;
    assert!(support::completed(&handle, accepted.operation).is_none());
    let before: [usize; 4] = std::array::from_fn(|i| probes[i].io_polls.load(Ordering::SeqCst));
    tokio::time::advance(Duration::from_micros(1)).await;
    assert_eq!(tokio::time::Instant::now(), deadline);
    drive_once(&mut run).await;
    assert_eq!(
        support::completed(&handle, accepted.operation),
        Some(Completed::Failed(Failure {
            kind: io::ErrorKind::TimedOut,
        }))
    );
    for (index, probe) in probes.iter().enumerate() {
        assert_eq!(
            probe.io_polls.load(Ordering::SeqCst),
            before[index],
            "original cap must precede another actual I/O poll"
        );
        assert_eq!(
            probe.dropped.load(Ordering::SeqCst),
            usize::from(index == 0 || index == 2)
        );
    }
    let snapshot = handle.snapshot();
    assert_eq!(snapshot.phase, Phase::Failed);
    assert!(snapshot.runtime.is_none() && snapshot.generation.is_none());
    support::assert_unopened(&hosts);
    // The unused peer's unopened originals are still its actual factory owners,
    // not part of the failed client. Dropping that plan releases them once too.
    drop(server);
    assert!(
        probes
            .iter()
            .all(|probe| probe.dropped.load(Ordering::SeqCst) == 1)
    );
    assert_eq!(
        support::observation(&handle, accepted.operation)?.original_timeout_micros,
        3_000_000
    );
    Ok(())
}
