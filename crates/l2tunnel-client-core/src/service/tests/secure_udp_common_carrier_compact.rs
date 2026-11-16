//! Actual shared-service Compact selection through completed TLS/Noise/member owners.
//! Unprivileged Unix packet devices do not qualify native TUN or Python topology.
use super::*;
use l2tunnel_recovery::{CompactArqConfig, CompactBounds, CompactRecovery, CompactTiming};
use l2tunnel_reliable::CompactReliableConfig;

fn compact_direction(old: aligned::Config, reverse: bool) -> Result<aligned::CompactConfig> {
    let arq = old.recovery.arq;
    Ok(aligned::CompactConfig {
        native_policy: old.native_policy,
        receiver: old.receiver,
        recovery: CompactReliableConfig::new(
            CompactArqConfig::new(
                CompactBounds {
                    max_source_bytes: arq.max_source_bytes,
                    send_bytes: arq.send_bytes,
                    receive_bytes: arq.receive_bytes,
                    send_records: arq.send_records,
                    receive_records: arq.receive_records,
                },
                CompactTiming {
                    nominal_rtt: Duration::from_millis(if reverse { 90 } else { 70 }),
                    feedback_interval: Duration::from_millis(if reverse { 3 } else { 5 }),
                    feedback_packets: if reverse { 3 } else { 2 },
                },
                if reverse { 400 } else { 200 },
                32,
                8,
                if reverse {
                    CompactRecovery::FirstFlight
                } else {
                    CompactRecovery::Guarded
                },
            )?,
            old.recovery.outer_overhead_bytes,
        )?,
        max_recovery_packet_bytes: old.max_recovery_packet_bytes,
        copies: l2tunnel_codec::source_copy::Policy::ONE,
    })
}

fn compact_carrier_plans(hosts: &[Arc<Host>; 2]) -> Result<CarrierPlans> {
    let CarrierPlans {
        plans: [left, right],
        addresses,
        requested: original,
    } = carrier_plans(l2tunnel_cover::Appearance::QuicLike, hosts, false)?;
    let mut selected = Vec::new();
    for value in original.catalog().descriptors() {
        let profile = match *value.profile() {
            common::Profile::Aligned { forward, reverse } => common::Profile::AlignedCompact {
                forward: compact_direction(forward, false)?,
                reverse: compact_direction(reverse, true)?,
            },
            common::Profile::Packed { forward, reverse } => common::Profile::PackedCompact {
                forward: aligned::packed::CompactConfig {
                    base: compact_direction(forward.base, false)?,
                    hold_micros: forward.hold_micros,
                    max_units: forward.max_units,
                    work_limit: forward.work_limit,
                },
                reverse: aligned::packed::CompactConfig {
                    base: compact_direction(reverse.base, true)?,
                    hold_micros: reverse.hold_micros,
                    max_units: reverse.max_units,
                    work_limit: reverse.work_limit,
                },
            },
            _ => continue,
        };
        selected.push(common::Descriptor::new(
            value.path_mtu(),
            value.duplex(),
            *value.direction(DataRole::Client).common(),
            *value.direction(DataRole::Server).common(),
            profile,
        )?);
    }
    assert_eq!(selected.len(), 2);
    let initial = *selected
        .iter()
        .find(|value| matches!(value.profile(), common::Profile::AlignedCompact { .. }))
        .ok_or("explicit initial Compact policy absent")?;
    let requested = common_transaction_profile::Profile::new(
        original.connection(),
        original.settings(),
        original.peers(),
        original.runtime_contract(Role::Initiator)?.resources(),
        original.runtime_contract(Role::Responder)?.resources(),
        common::Catalog::new(initial, &selected)?,
        original.parameters(),
    )?;
    let reprepare = |plan: Prepared| -> Result<Prepared> {
        let data = Arc::try_unwrap(plan.data)
            .map_err(|_| "unstarted actual credentials unexpectedly shared")?;
        let prepared::Data {
            endpoint,
            attachment,
            transport,
            ..
        } = data;
        let prepared::Transport::SecureUdpCommonCarrier { mut outer, .. } = transport else {
            return Err("actual original-carrier transport absent".into());
        };
        // Transfer genuine unstarted credentials; only the explicit catalog and
        // its requested setup digest change before the actual factory executes.
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
            _ => Err("actual carrier credential owner absent".into()),
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

#[tokio::test]
async fn actual_carrier_v4_service_binds_compact_catalog_and_switches_exact_native_bytes() -> Result
{
    timeout(Duration::from_secs(30), async {
        let hosts = support::hosts();
        let CarrierPlans {
            plans: [left, right],
            addresses,
            requested,
        } = compact_carrier_plans(&hosts)?;
        let (client, run) = channel();
        let (server, peer) = channel();
        let client_task = tokio::spawn(run);
        let server_task = tokio::spawn(peer);
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
        assert!(matches!(
            effective.initial().descriptor().profile(),
            common::Profile::AlignedCompact { .. }
        ));
        let supported = effective.catalog().configurations(effective.envelope())?;
        assert_eq!(supported.len(), 2);
        let target = *supported
            .iter()
            .find(|value| {
                matches!(
                    value.descriptor().profile(),
                    common::Profile::PackedCompact { .. }
                )
            })
            .ok_or("bound effective PackedCompact absent")?;
        let epoch = originals[0]
            .runtime
            .as_ref()
            .ok_or("actual initial runtime absent")?
            .epoch
            .0;
        let directory = ApiDirectory::new()?;
        let paths = [
            directory.0.join("compact-a.sock"),
            directory.0.join("compact-b.sock"),
        ];
        let mut api_tasks = Vec::new();
        for side in 0..2 {
            let frame = &originals[side];
            assert_eq!(frame.info.local_addr, addresses[side]);
            assert_eq!(frame.info.peer_addr, addresses[1 - side]);
            assert_eq!(frame.requested.configuration()?, effective.configuration()?);
            assert_eq!(
                frame.requested.requested_configuration()?,
                requested.configuration()?
            );
            assert_eq!(frame.requested.requested_envelope(), requested.envelope());
            assert_ne!(frame.requested.configuration()?, requested.configuration()?);
            assert_ne!(frame.requested.envelope(), requested.envelope());
            let proof = frame
                .requested
                .carrier_binding()
                .ok_or("genuine completed outer proof absent")?;
            assert_eq!(proof.endpoints(), (addresses[0], addresses[1]));
            assert_eq!(
                proof
                    .expected_binding(
                        frame.requested.establish_config(frame.info.role)?,
                        frame.info.peers,
                        frame.info.binding.session
                    )?
                    .outer,
                frame.info.authenticated.outer
            );
            assert_common(frame, effective.initial(), epoch, frame, generations[side])?;
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
        assert_eq!(originals[0].info.binding, originals[1].info.binding);
        exchange_stage(&hosts, &handles, effective.initial(), epoch, 0).await?;
        let key = handles[0].next_key().map_err(submit)?;
        assert_eq!(
            handles[0].apply_common(requested.initial(), key),
            Err(SubmitError::InvalidConfiguration)
        );
        assert_eq!(handles[0].next_key().map_err(submit)?, key);
        let change = request(local::Action::SwitchCommonConfiguration {
            configuration: CanonicalConfiguration::from_configuration(target)?,
            request_key: key.value(),
        });
        let changed = local::request(&paths[0], &change).await?;
        assert!(changed.ok, "{changed:?}");
        assert_current(observed(&changed)?, target, epoch + 1)?;
        let completion = observed(&changed)?
            .result
            .as_ref()
            .ok_or("actual completion absent")?;
        assert_eq!(completion.configuration.configuration()?, target);
        assert_eq!(completion.epoch, Some(epoch + 1));
        assert_eq!(completion.request_key, key.value());
        assert_eq!(completion.outcome, "ok");
        await_common(&handles[1], target, epoch + 1, 0, None).await?;
        exchange_stage(&hosts, &handles, target, epoch + 1, 1).await?;
        for side in 0..2 {
            let response = local::request(&paths[side], &request(local::Action::Status {})).await?;
            assert!(response.ok);
            let status = observed(&response)?;
            assert_current(status, target, epoch + 1)?;
            let carrier = status
                .original_carrier
                .as_ref()
                .ok_or("actual carrier status absent")?;
            assert_eq!(
                carrier.requested_configuration,
                requested.configuration()?.0
            );
            assert_eq!(
                carrier.effective_configuration,
                effective.configuration()?.0
            );
            assert_eq!(
                carrier.requested_catalog,
                *requested.catalog().root().as_bytes()
            );
            assert_eq!(
                carrier.effective_catalog,
                *effective.catalog().root().as_bytes()
            );
            assert_common(
                &common_frame(&handles[side])?,
                target,
                epoch + 1,
                &originals[side],
                generations[side],
            )?;
            assert_eq!(hosts[side].opened.load(Ordering::SeqCst), 1);
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
    })
    .await?
}
