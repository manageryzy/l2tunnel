//! Migration witnesses for the retired Swift-only service entry. The carrier is
//! actual maintained TLS and every data/control record uses the Common owner.
use super::*;

fn swift_plans(
    hosts: &[Arc<Host>; 2],
) -> Result<([Prepared; 2], common_transaction_profile::Profile)> {
    let TransactionPlans { profile, .. } =
        transaction_plans(l2tunnel_cover::Appearance::QuicLike, hosts)?;
    let (plans, profile, _) = maintained_plans(profile, false, hosts)?;
    Ok((plans, profile))
}

#[test]
fn common_swift_plan_retains_deferred_attachment_and_original_setup_bound() -> Result {
    for wrong_layer in [false, true] {
        let hosts = support::hosts();
        let ([_, server], profile) = swift_plans(&hosts)?;
        assert_eq!(
            server.setup_timeout(),
            profile.connection().handshake_timeout
        );
        assert!(
            hosts
                .iter()
                .all(|host| host.opened.load(Ordering::SeqCst) == 0)
        );
        let data = Arc::try_unwrap(server.data).map_err(|_| "fixture plan unexpectedly shared")?;
        let prepared::Endpoint::CommonMaintainedServer(server) = data.endpoint else {
            return Err("fixture did not select actual maintained credentials".into());
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let observe = calls.clone();
        let attachment = if wrong_layer {
            Attachment::readable(PacketLayer::Ethernet, move || {
                observe.fetch_add(1, Ordering::SeqCst);
                Err(io::Error::other("invalid attachment opened"))
            })
        } else {
            Attachment::new(PacketLayer::Ip, move || {
                observe.fetch_add(1, Ordering::SeqCst);
                Err(io::Error::other("unreadable attachment opened"))
            })
        };
        let result = Prepared::secure_udp_common_maintained_server(
            profile,
            server.outer,
            server.inner,
            attachment,
        );
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[tokio::test]
async fn current_swift_tls_service_preserves_switch_refusal_noop_release_and_reconnect() -> Result {
    let hosts = support::hosts();
    let ([a, b], requested) = swift_plans(&hosts)?;
    let (client, run) = channel();
    let (server, peer) = channel();
    let tasks = [tokio::spawn(run), tokio::spawn(peer)];
    let initial = requested.initial();
    let next = |handle: &Handle| handle.next_key().map_err(submit);
    let first_server = server.connect(b.clone(), next(&server)?).map_err(submit)?;
    timeout(Duration::from_secs(5), async {
        while server.snapshot().listening.is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let first_client = client.connect(a.clone(), next(&client)?).map_err(submit)?;
    let generations = tokio::try_join!(
        connected(&client, first_client),
        connected(&server, first_server)
    )
    .map_err(|error| -> Error {
        format!(
            "initial TLS connection failed: {error}; client_setup={:?}; server_setup={:?}",
            client.setup_observation(first_client.operation),
            server.setup_observation(first_server.operation),
        )
        .into()
    })?;
    let original = common_frame(&client)?;
    let session = original.info.binding.session;
    let epoch = original
        .runtime
        .as_ref()
        .ok_or("missing running snapshot")?
        .epoch;
    let effective = original.requested.clone();
    assert_eq!(effective.initial().descriptor(), initial.descriptor());
    assert!(
        hosts
            .iter()
            .all(|host| host.opened.load(Ordering::SeqCst) == 1)
    );
    for side in 0..2 {
        let bytes = packet(10 + side as u8, 512);
        hosts[side].send(&bytes)?;
        hosts[1 - side].expect(&bytes).await?;
    }
    let target = effective
        .catalog()
        .configurations(effective.envelope())?
        .into_iter()
        .find(|value| *value != effective.initial())
        .ok_or("missing complete Swift target")?;
    let operation = client
        .apply_common(target, next(&client)?)
        .map_err(submit)?;
    assert_eq!(
        timeout(Duration::from_secs(5), client.wait(operation.operation))
            .await?
            .map_err(submit)?,
        Completed::Common {
            configuration: target,
            outcome: Ok(l2tunnel_core::Epoch(epoch.0 + 1))
        }
    );
    await_common(&server, target, epoch.0 + 1, 0, None).await?;
    for side in 0..2 {
        let bytes = packet(20 + side as u8, 512);
        hosts[side].send(&bytes)?;
        hosts[1 - side].expect(&bytes).await?;
    }
    let follower = server
        .apply_common(effective.initial(), next(&server)?)
        .map_err(submit)?;
    assert_eq!(
        timeout(Duration::from_secs(5), server.wait(follower.operation))
            .await?
            .map_err(submit)?,
        Completed::Common {
            configuration: effective.initial(),
            outcome: Err(transport::SwitchError::NotCoordinator)
        }
    );
    let foreign = common::Configuration::new(
        common::EnvelopeDigest::new([0xfe; 32]),
        *target.descriptor(),
    )?;
    assert_eq!(
        client.apply_common(foreign, next(&client)?),
        Err(SubmitError::InvalidConfiguration)
    );
    let noop = client
        .apply_common(target, next(&client)?)
        .map_err(submit)?;
    assert_eq!(
        timeout(Duration::from_secs(5), client.wait(noop.operation))
            .await?
            .map_err(submit)?,
        Completed::Common {
            configuration: target,
            outcome: Ok(l2tunnel_core::Epoch(epoch.0 + 1))
        }
    );
    let stop = client.disconnect(next(&client)?).map_err(submit)?;
    assert_eq!(
        client.wait(stop.operation).await.map_err(submit)?,
        Completed::Aborted
    );
    assert_eq!(
        client.wait_stopped(generations.0).await.map_err(submit)?,
        Terminal::Aborted
    );
    assert_eq!(hosts[0].live.load(Ordering::SeqCst), 0);
    let terminal = timeout(Duration::from_secs(5), server.wait_stopped(generations.1))
        .await?
        .map_err(submit)?;
    assert!(
        matches!(terminal, Terminal::Failed(_)),
        "peer must observe real TLS owner closure: {terminal:?}"
    );
    assert_eq!(hosts[1].live.load(Ordering::SeqCst), 0);
    let second_server = server.reconnect(b, next(&server)?).map_err(submit)?;
    timeout(Duration::from_secs(5), async {
        while server.snapshot().listening.is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let second_client = client.reconnect(a, next(&client)?).map_err(submit)?;
    tokio::try_join!(
        connected(&client, second_client),
        connected(&server, second_server)
    )
    .map_err(|error| -> Error {
        format!(
            "same-port TLS reconnect failed: {error}; client_setup={:?}; server_setup={:?}",
            client.setup_observation(second_client.operation),
            server.setup_observation(second_server.operation),
        )
        .into()
    })?;
    let fresh = common_frame(&client)?;
    assert_ne!(fresh.info.binding.session, session);
    assert!(fresh.generation > generations.0.value());
    assert_eq!(
        fresh
            .runtime
            .as_ref()
            .ok_or("fresh runtime absent")?
            .current,
        fresh.requested.initial()
    );
    assert_eq!(
        fresh.runtime.as_ref().ok_or("fresh runtime absent")?.epoch,
        epoch
    );
    for side in 0..2 {
        assert_eq!(hosts[side].opened.load(Ordering::SeqCst), 2);
        let bytes = packet(30 + side as u8, 512);
        hosts[side].send(&bytes)?;
        hosts[1 - side].expect(&bytes).await?;
    }
    // Submit both local stops on this executor before yielding. Otherwise the
    // first owner's TLS close can terminate its peer before the second request.
    let stops = [
        client.disconnect(next(&client)?).map_err(submit)?,
        server.disconnect(next(&server)?).map_err(submit)?,
    ];
    for (handle, stop) in [&client, &server].into_iter().zip(stops) {
        assert_eq!(
            handle.wait(stop.operation).await.map_err(submit)?,
            Completed::Aborted
        );
    }
    for task in tasks {
        task.abort();
        let _ = task.await;
    }
    assert!(
        hosts
            .iter()
            .all(|host| host.live.load(Ordering::SeqCst) == 0)
    );
    Ok(())
}
