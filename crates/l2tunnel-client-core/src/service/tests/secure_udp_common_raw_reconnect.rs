//! Explicit lower-layer replacement acquires fresh originals and authenticates again.
//! This is not retained old-session recovery or native kernel qualification.
use super::*;

#[tokio::test]
async fn raw_common_explicit_reconnect_releases_then_reauthenticates_fresh_originals() -> Result {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let hosts = support::hosts();
    let setup_hosts = hosts.clone();
    // Keep finite nested profile construction off the lifecycle poll frame,
    // without increasing either thread stack or the original test deadline.
    let prepared =
        tokio::task::spawn_blocking(move || raw_plans_with_rounds(&setup_hosts, 2).map(Box::new))
            .await??;
    tokio::time::timeout_at(deadline, Box::pin(exercise_raw_reconnect(hosts, prepared))).await?
}

async fn exercise_raw_reconnect(
    hosts: [Arc<Host>; 2],
    prepared: Box<(CarrierPlans, Vec<Arc<Probe>>)>,
) -> Result {
    let (
        CarrierPlans {
            plans: [left, right],
            addresses,
            requested,
        },
        probes,
    ) = *prepared;
    assert_eq!(probes.len(), 8);
    let retained = [left.clone(), right.clone()];
    let (client, run) = channel();
    let (server, peer) = channel();
    let task = tokio::spawn(run);
    let peer_task = tokio::spawn(peer);
    let handles = [client, server];
    let first_keys = [
        handles[0].next_key().map_err(submit)?,
        handles[1].next_key().map_err(submit)?,
    ];
    let first_accepted = [
        handles[0].connect(left, first_keys[0]).map_err(submit)?,
        handles[1].connect(right, first_keys[1]).map_err(submit)?,
    ];
    let (a, b) = tokio::try_join!(
        connected(&handles[0], first_accepted[0]),
        connected(&handles[1], first_accepted[1])
    )?;
    let first_generations = [a, b];
    let first = [common_frame(&handles[0])?, common_frame(&handles[1])?];
    let first_profile = &first[0].requested;
    let first_epoch = first[0]
        .runtime
        .as_ref()
        .ok_or("first actual raw runtime absent")?
        .epoch
        .0;
    exchange_stage(&hosts, &handles, first_profile.initial(), first_epoch, 6).await?;
    for probe in &probes[..4] {
        assert_eq!(probe.opened.load(Ordering::SeqCst), 1);
        assert_eq!(probe.dropped.load(Ordering::SeqCst), 0);
        assert!(probe.sent.load(Ordering::SeqCst) > 0);
    }
    assert!(
        probes[4..]
            .iter()
            .all(|probe| probe.opened.load(Ordering::SeqCst) == 0)
    );
    let stopped = [
        handles[0]
            .disconnect(handles[0].next_key().map_err(submit)?)
            .map_err(submit)?,
        handles[1]
            .disconnect(handles[1].next_key().map_err(submit)?)
            .map_err(submit)?,
    ];
    for side in 0..2 {
        assert_eq!(
            handles[side]
                .wait(stopped[side].operation)
                .await
                .map_err(submit)?,
            Completed::Aborted
        );
        assert_eq!(
            handles[side]
                .wait_stopped(first_generations[side])
                .await
                .map_err(submit)?,
            Terminal::Aborted
        );
        assert_eq!(hosts[side].live.load(Ordering::SeqCst), 0);
        assert_eq!(hosts[side].opened.load(Ordering::SeqCst), 1);
    }
    assert!(
        probes[..4]
            .iter()
            .all(|probe| probe.dropped.load(Ordering::SeqCst) == 1)
    );
    assert!(
        probes[4..]
            .iter()
            .all(|probe| probe.opened.load(Ordering::SeqCst) == 0)
    );

    // Reuse the actual unbound request/credentials, never the consumed original
    // PacketIo or first generation's bound E1/Noise/Records owners.
    let keys = [
        handles[0].next_key().map_err(submit)?,
        handles[1].next_key().map_err(submit)?,
    ];
    let accepted = [
        handles[0]
            .reconnect(retained[0].clone(), keys[0])
            .map_err(submit)?,
        handles[1]
            .reconnect(retained[1].clone(), keys[1])
            .map_err(submit)?,
    ];
    let (a, b) = tokio::try_join!(
        connected(&handles[0], accepted[0]),
        connected(&handles[1], accepted[1])
    )?;
    let generations = [a, b];
    let second = [common_frame(&handles[0])?, common_frame(&handles[1])?];
    let effective = &second[0].requested;
    let epoch = second[0]
        .runtime
        .as_ref()
        .ok_or("replacement actual raw runtime absent")?
        .epoch
        .0;
    for side in 0..2 {
        assert_ne!(generations[side], first_generations[side]);
        let before = first[side]
            .requested
            .raw_binding()
            .ok_or("first genuine raw proof absent")?;
        let after = second[side]
            .requested
            .raw_binding()
            .ok_or("replacement genuine raw proof absent")?;
        assert_ne!(after.binding(), before.binding());
        assert_ne!(after.info().session_id, before.info().session_id);
        assert_ne!(
            second[side].info.binding.session,
            first[side].info.binding.session
        );
        assert_eq!(after.lane_endpoints(), before.lane_endpoints());
        assert_eq!(after.policy(), before.policy());
        assert_eq!(
            second[side].requested.requested_configuration()?,
            requested.configuration()?
        );
        assert_eq!(
            second[side].requested.requested_envelope(),
            requested.envelope()
        );
        assert_eq!(
            second[side].requested.requested_catalog().root(),
            requested.catalog().root()
        );
        assert_ne!(
            second[side].requested.configuration()?,
            first[side].requested.configuration()?
        );
        assert_eq!(second[side].info.local_addr, addresses[side]);
        assert_eq!(second[side].info.peer_addr, addresses[1 - side]);
        assert_eq!(hosts[side].opened.load(Ordering::SeqCst), 2);
        assert_eq!(hosts[side].live.load(Ordering::SeqCst), 1);
        assert_eq!(
            support::observation(&handles[side], generations[side])?.original_timeout_micros,
            3_000_000
        );
        assert_common(
            &second[side],
            effective.initial(),
            epoch,
            &second[side],
            generations[side],
        )?;
        let status = second[side].status()?;
        assert_eq!(
            status
                .raw_carrier
                .as_ref()
                .ok_or("replacement raw status absent")?
                .binding,
            after.binding()
        );
        assert!(status.original_carrier.is_none());
        // Retained request replay is an old result, never another setup or SYN.
        let replay = handles[side]
            .connect(retained[side].clone(), first_keys[side])
            .map_err(submit)?;
        assert_eq!(replay.operation, first_accepted[side].operation);
        assert_eq!(
            handles[side].wait(replay.operation).await.map_err(submit)?,
            Completed::Connected {
                generation: first_generations[side]
            }
        );
    }
    exchange_stage(&hosts, &handles, effective.initial(), epoch, 7).await?;
    let target = effective
        .catalog()
        .configurations(effective.envelope())?
        .into_iter()
        .find(|value| matches!(value.descriptor().profile(), common::Profile::Packed { .. }))
        .ok_or("replacement Packed catalog member absent")?;
    let applied = handles[0]
        .apply_common(target, handles[0].next_key().map_err(submit)?)
        .map_err(submit)?;
    assert_eq!(
        timeout(Duration::from_secs(4), handles[0].wait(applied.operation))
            .await?
            .map_err(submit)?,
        Completed::Common {
            configuration: target,
            outcome: Ok(l2tunnel_core::Epoch(epoch + 1))
        }
    );
    await_common(&handles[1], target, epoch + 1, 0, None).await?;
    exchange_stage(&hosts, &handles, target, epoch + 1, 8).await?;
    for side in 0..2 {
        assert_common(
            &common_frame(&handles[side])?,
            target,
            epoch + 1,
            &second[side],
            generations[side],
        )?;
        assert_no_native_replay(&hosts[side])?;
    }
    let stopped = [
        handles[0]
            .disconnect(handles[0].next_key().map_err(submit)?)
            .map_err(submit)?,
        handles[1]
            .disconnect(handles[1].next_key().map_err(submit)?)
            .map_err(submit)?,
    ];
    for side in 0..2 {
        assert_eq!(
            handles[side]
                .wait(stopped[side].operation)
                .await
                .map_err(submit)?,
            Completed::Aborted
        );
        assert_eq!(
            handles[side]
                .wait_stopped(generations[side])
                .await
                .map_err(submit)?,
            Terminal::Aborted
        );
        assert_eq!(hosts[side].live.load(Ordering::SeqCst), 0);
        assert_eq!(hosts[side].opened.load(Ordering::SeqCst), 2);
    }
    for probe in &probes {
        assert_eq!(probe.opened.load(Ordering::SeqCst), 1);
        assert_eq!(probe.dropped.load(Ordering::SeqCst), 1);
        assert!(probe.syns.load(Ordering::SeqCst) > 0);
    }
    task.abort();
    peer_task.abort();
    let _ = task.await;
    let _ = peer_task.await;
    Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
}
