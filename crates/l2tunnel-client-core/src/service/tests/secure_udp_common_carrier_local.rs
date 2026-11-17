//! Real APIv4 IPC for actual original-carrier TLS/Noise/member/Common owners.
use super::*;
use crate::secure_udp::common_status::{CanonicalConfiguration, Status};

fn arq_only_descriptor(value: common::Descriptor) -> Result<common::Descriptor> {
    let mut profile = *value.profile();
    match &mut profile {
        common::Profile::Aligned { forward, reverse } => {
            forward.recovery.repair_symbols = 0;
            reverse.recovery.repair_symbols = 0;
        }
        common::Profile::Packed { forward, reverse } => {
            forward.base.recovery.repair_symbols = 0;
            reverse.base.recovery.repair_symbols = 0;
        }
        common::Profile::Swift { .. }
        | common::Profile::AlignedCompact { .. }
        | common::Profile::PackedCompact { .. }
        | common::Profile::PerConnectionCompact { .. }
        | common::Profile::Research { .. }
        | common::Profile::Rolling { .. }
        | common::Profile::RollingCopies { .. } => return Ok(value),
    }
    Ok(common::Descriptor::new(
        value.path_mtu(),
        value.duplex(),
        *value.direction(DataRole::Client).common(),
        *value.direction(DataRole::Server).common(),
        profile,
    )?)
}
#[inline(never)]
fn arq_only_carrier_plans(
    appearance: l2tunnel_cover::Appearance,
    hosts: &[Arc<Host>; 2],
) -> Result<CarrierPlans> {
    let original = carrier_plans(appearance, hosts, false)?;
    arq_only_from_carrier(original, hosts)
}
#[inline(never)]
fn arq_only_from_carrier(original: CarrierPlans, hosts: &[Arc<Host>; 2]) -> Result<CarrierPlans> {
    let CarrierPlans {
        plans: [left, right],
        addresses,
        requested: original,
    } = original;
    let descriptors = original
        .catalog()
        .descriptors()
        .iter()
        .copied()
        .map(arq_only_descriptor)
        .collect::<Result<Vec<_>>>()?;
    let requested = common_transaction_profile::Profile::new(
        original.connection(),
        original.settings(),
        original.peers(),
        original.runtime_contract(Role::Initiator)?.resources(),
        original.runtime_contract(Role::Responder)?.resources(),
        common::Catalog::new(
            arq_only_descriptor(*original.initial().descriptor())?,
            &descriptors,
        )?,
        original.parameters(),
    )?;
    let reprepare = |plan: Prepared| -> Result<Prepared> {
        let data = Arc::try_unwrap(plan.data)
            .map_err(|_| "unused carrier credentials unexpectedly shared")?;
        let prepared::Data {
            endpoint,
            attachment,
            transport,
            ..
        } = data;
        let prepared::Transport::SecureUdpCommonCarrier { outer, .. } = transport else {
            return Err("unexpected carrier transport".into());
        };
        let mut outer = *outer;
        // Only the new canonical catalog changes the derived requested setup digest.
        // Transfer the original unstarted TLS/Noise/member and device owners.
        outer.base.digest = l2tunnel_core::ConfigDigest(requested.requested_configuration()?.0);
        match endpoint {
            prepared::Endpoint::CommonCarrierClient { outer: tls, inner } => {
                Ok(Prepared::secure_udp_common_carrier_client(
                    requested.clone(),
                    outer,
                    tls,
                    inner,
                    attachment,
                )?)
            }
            prepared::Endpoint::CommonCarrierServer(server) => {
                let prepared::CommonCarrierServer {
                    outer: tls,
                    inner,
                    admission,
                } = *server;
                assert!(admission.into_inner().is_none());
                Ok(Prepared::secure_udp_common_carrier_server(
                    requested.clone(),
                    outer,
                    tls,
                    inner,
                    attachment,
                )?)
            }
            _ => Err("unexpected carrier credential owner".into()),
        }
    };
    let plans = [reprepare(left)?, reprepare(right)?];
    assert!(
        hosts
            .iter()
            .all(|host| host.opened.load(Ordering::SeqCst) == 0)
    );
    Ok(CarrierPlans {
        plans,
        addresses,
        requested,
    })
}
fn assert_arq_only(value: common::Configuration) {
    match value.descriptor().profile() {
        common::Profile::Aligned { forward, reverse } => {
            assert_eq!(forward.recovery.repair_symbols, 0);
            assert_eq!(reverse.recovery.repair_symbols, 0);
        }
        common::Profile::Packed { forward, reverse } => {
            assert_eq!(forward.base.recovery.repair_symbols, 0);
            assert_eq!(reverse.base.recovery.repair_symbols, 0);
        }
        common::Profile::Swift { .. }
        | common::Profile::AlignedCompact { .. }
        | common::Profile::PackedCompact { .. }
        | common::Profile::PerConnectionCompact { .. }
        | common::Profile::Research { .. }
        | common::Profile::Rolling { .. }
        | common::Profile::RollingCopies { .. } => {}
    }
}

fn request(action: local::Action) -> local::Request {
    local::Request {
        version: local::COMMON_VERSION,
        action,
    }
}
fn observed(response: &local::Response) -> Result<&Status> {
    assert_eq!(response.version, local::COMMON_VERSION);
    let state = response
        .state
        .as_ref()
        .ok_or("missing actual service state")?;
    state
        .common
        .as_ref()
        .ok_or_else(|| "missing actual carrier Common status".into())
}
fn assert_current(status: &Status, configuration: common::Configuration, epoch: u64) -> Result {
    assert!(status.running && status.terminal.is_none() && status.service_terminal.is_none());
    assert_eq!(
        status
            .current
            .as_ref()
            .ok_or("missing actual current")?
            .configuration()?,
        configuration
    );
    assert_eq!(status.epoch, Some(epoch));
    assert_eq!(
        status.phase,
        Some(crate::secure_udp::common_status::Phase::Idle)
    );
    assert!(status.operation.is_none() && status.requested.is_none());
    let physical = status
        .physical_scope
        .as_ref()
        .ok_or("missing physical scope")?;
    assert_eq!(physical.epoch, epoch);
    assert_eq!(physical.configuration, configuration.digest()?.0);
    Ok(())
}

#[tokio::test]
async fn v4_carrier_socket_keeps_full_effective_catalog_keyed_switches_and_release() -> Result {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    for appearance in support::appearances() {
        let hosts = support::hosts();
        let setup_hosts = hosts.clone();
        // The finite factory completes outside the large lifecycle poll frame.
        // Join it before applying the unchanged absolute cap; no setup is detached.
        let plans = tokio::task::spawn_blocking(move || {
            arq_only_carrier_plans(appearance, &setup_hosts).map(Box::new)
        })
        .await??;
        tokio::time::timeout_at(deadline, Box::pin(exercise_carrier_local(hosts, plans))).await??;
    }
    Ok(())
}

async fn exercise_carrier_local(hosts: [Arc<Host>; 2], plans: Box<CarrierPlans>) -> Result {
    let CarrierPlans {
        plans: [left, right],
        addresses,
        requested,
    } = *plans;
    let (client, client_run) = channel();
    let (server, server_run) = channel();
    let client_task = tokio::spawn(client_run);
    let server_task = tokio::spawn(server_run);
    let accepted = [
        client
            .connect(left, client.next_key().map_err(submit)?)
            .map_err(submit)?,
        server
            .connect(right, server.next_key().map_err(submit)?)
            .map_err(submit)?,
    ];
    let (a, b) = tokio::try_join!(
        connected(&client, accepted[0]),
        connected(&server, accepted[1])
    )?;
    let handles = [client, server];
    let generations = [a, b];
    let originals = [common_frame(&handles[0])?, common_frame(&handles[1])?];
    let effective = originals[0].requested.clone();
    let supported = effective.catalog().configurations(effective.envelope())?;
    assert_eq!(supported.len(), 4);
    let configurations = [
        effective.initial(),
        *supported
            .iter()
            .find(|value| {
                matches!(
                    value.descriptor().profile(),
                    common::Profile::Aligned { .. }
                )
            })
            .ok_or("effective Aligned absent")?,
        *supported
            .iter()
            .find(|value| matches!(value.descriptor().profile(), common::Profile::Packed { .. }))
            .ok_or("effective Packed absent")?,
        *supported
            .iter()
            .find(|value| {
                matches!(
                    value.descriptor().profile(),
                    common::Profile::Rolling { .. }
                )
            })
            .ok_or("effective Rolling absent")?,
    ];
    let epoch = originals[0]
        .runtime
        .as_ref()
        .ok_or("missing initial epoch")?
        .epoch
        .0;
    let directory = ApiDirectory::new()?;
    let paths = [directory.0.join("ca.sock"), directory.0.join("cb.sock")];
    let mut api_tasks = Vec::new();
    for side in 0..2 {
        let api = local::Server::bind(&paths[side])?;
        let handle = handles[side].clone();
        api_tasks.push(tokio::spawn(async move {
            api.serve(move |request| {
                let handle = handle.clone();
                async move { handle.lifecycle_request(request).await }
            })
            .await
        }));
    }
    for side in 0..2 {
        let response = local::request(&paths[side], &request(local::Action::Status {})).await?;
        assert!(response.ok);
        let status = observed(&response)?;
        assert_eq!(status.generation, generations[side].value());
        assert_eq!(status.carrier, "openvpn-like");
        assert_eq!(status.local, addresses[side].to_string());
        assert_eq!(status.peer, addresses[1 - side].to_string());
        assert_current(status, configurations[0], epoch)?;
        let carrier = status
            .original_carrier
            .as_ref()
            .ok_or("missing actual outer status")?;
        let proof = originals[side]
            .requested
            .carrier_binding()
            .ok_or("missing genuine proof")?;
        assert_eq!(
            carrier.requested_configuration,
            requested.configuration()?.0
        );
        assert_eq!(carrier.requested_envelope, *requested.envelope().as_bytes());
        assert_eq!(
            carrier.requested_catalog,
            *requested.catalog().root().as_bytes()
        );
        assert_eq!(
            carrier.effective_configuration,
            effective.configuration()?.0
        );
        assert_eq!(carrier.effective_envelope, *effective.envelope().as_bytes());
        assert_eq!(
            carrier.effective_catalog,
            *effective.catalog().root().as_bytes()
        );
        assert_ne!(
            carrier.requested_configuration,
            carrier.effective_configuration
        );
        assert_ne!(carrier.requested_envelope, carrier.effective_envelope);
        assert_eq!(carrier.binding, proof.binding());
        assert_eq!(carrier.session, proof.info().session_id);
        assert_eq!(carrier.configuration, proof.info().config.digest.0);
    }
    let key = handles[0].next_key().map_err(submit)?;
    let mut collected = Vec::new();
    for offset in [0, 2] {
        let response = local::request(
            &paths[0],
            &request(local::Action::CommonCatalog {
                generation: a.value(),
                catalog: *effective.catalog().root().as_bytes(),
                offset,
                limit: 2,
            }),
        )
        .await?;
        assert!(response.ok);
        let page = observed(&response)?
            .catalog_page
            .as_ref()
            .ok_or("missing actual catalog page")?;
        assert_eq!(page.total, 4);
        assert_eq!(page.next, if offset == 0 { Some(2) } else { None });
        assert_eq!(page.configurations.len(), 2);
        for configuration in &page.configurations {
            let actual = configuration.configuration()?;
            assert_arq_only(actual);
            collected.push(actual);
        }
    }
    assert_eq!(collected, supported);
    // Current compact carrier binding changes the envelope/session proof, not
    // the canonical algorithm catalog. Use an actually foreign root for refusal.
    assert_eq!(requested.catalog().root(), effective.catalog().root());
    let mut foreign_catalog = *effective.catalog().root().as_bytes();
    foreign_catalog[0] ^= 1;
    for (generation, catalog) in [
        (a.value() + 1, *effective.catalog().root().as_bytes()),
        (a.value(), foreign_catalog),
    ] {
        let stale = local::request(
            &paths[0],
            &request(local::Action::CommonCatalog {
                generation,
                catalog,
                offset: 0,
                limit: 2,
            }),
        )
        .await?;
        assert!(!stale.ok);
        assert_eq!(stale.code, "stale_catalog");
        assert_eq!(handles[0].next_key().map_err(submit)?, key);
    }
    let wrong_base = local::request(
        &paths[0],
        &request(local::Action::SwitchCommonConfiguration {
            configuration: CanonicalConfiguration::from_configuration(requested.initial())?,
            request_key: key.value(),
        }),
    )
    .await?;
    assert!(!wrong_base.ok);
    assert_eq!(wrong_base.code, "invalid_configuration");
    assert_eq!(handles[0].next_key().map_err(submit)?, key);
    exchange_stage(&hosts, &handles, configurations[0], epoch, 0).await?;
    for (stage, target) in [
        configurations[1],
        configurations[2],
        configurations[3],
        configurations[0],
    ]
    .into_iter()
    .enumerate()
    {
        let request_key = handles[0].next_key().map_err(submit)?;
        let change = request(local::Action::SwitchCommonConfiguration {
            configuration: CanonicalConfiguration::from_configuration(target)?,
            request_key: request_key.value(),
        });
        let changed = local::request(&paths[0], &change).await?;
        assert!(changed.ok, "{changed:?}");
        assert_eq!(
            changed
                .state
                .as_ref()
                .ok_or("missing completed state")?
                .phase,
            "forwarding"
        );
        let status = observed(&changed)?;
        let current_epoch = epoch + stage as u64 + 1;
        assert_current(status, target, current_epoch)?;
        let result = status
            .result
            .as_ref()
            .ok_or("missing actual actor completion")?;
        assert_eq!(result.configuration.configuration()?, target);
        assert_eq!(result.epoch, Some(current_epoch));
        assert_eq!(result.request_key, request_key.value());
        assert_eq!(result.outcome, "ok");
        let next = handles[0].next_key().map_err(submit)?;
        let replay = local::request(&paths[0], &change).await?;
        assert!(replay.ok);
        assert_eq!(observed(&replay)?.result, status.result);
        assert_eq!(handles[0].next_key().map_err(submit)?, next);
        await_common(&handles[1], target, current_epoch, 0, None).await?;
        exchange_stage(&hosts, &handles, target, current_epoch, stage as u8 + 1).await?;
        for side in 0..2 {
            let response = local::request(&paths[side], &request(local::Action::Status {})).await?;
            assert!(response.ok);
            assert_current(observed(&response)?, target, current_epoch)?;
            assert_arq_only(
                observed(&response)?
                    .current
                    .as_ref()
                    .ok_or("missing current ARQ-only profile")?
                    .configuration()?,
            );
            assert_common(
                &common_frame(&handles[side])?,
                target,
                current_epoch,
                &originals[side],
                generations[side],
            )?;
            assert_no_native_replay(&hosts[side])?;
        }
    }
    let disconnect = request(local::Action::Disconnect {});
    let (left, right) = tokio::try_join!(
        local::request(&paths[0], &disconnect),
        local::request(&paths[1], &disconnect)
    )?;
    assert!(left.ok && right.ok);
    for side in 0..2 {
        assert_eq!(
            handles[side]
                .wait_stopped(generations[side])
                .await
                .map_err(submit)?,
            Terminal::Aborted
        );
        assert_eq!(hosts[side].live.load(Ordering::SeqCst), 0);
        let stopped = local::request(&paths[side], &request(local::Action::Status {})).await?;
        assert!(stopped.ok);
        assert_eq!(
            stopped
                .state
                .as_ref()
                .ok_or("missing released state")?
                .phase,
            "disconnected"
        );
        let status = observed(&stopped)?;
        assert!(!status.running);
        assert_eq!(status.service_terminal.as_deref(), Some("Aborted"));
        assert_eq!(
            status
                .original_carrier
                .as_ref()
                .ok_or("missing retained carrier")?
                .effective_envelope,
            *effective.envelope().as_bytes()
        );
    }
    timeout(Duration::from_secs(1), async {
        loop {
            if support::assert_ports_free(addresses).is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await?;
    for task in api_tasks {
        task.abort();
        let _ = task.await;
    }
    client_task.abort();
    server_task.abort();
    let _ = client_task.await;
    let _ = server_task.await;
    assert!(paths.iter().all(|path| !path.exists()));
    Ok::<(), Error>(())
}

#[path = "secure_udp_common_carrier_compact.rs"]
mod compact;
