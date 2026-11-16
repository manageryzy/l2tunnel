//! Genuine paired raw Half TLS/member -> Noise/member -> shared Common actor.
//! PacketIo and native devices are the existing injected owners; no kernel/raw
//! firewall, platform TLS, Python topology or throughput qualification is claimed.
use super::*;
use l2tunnel::{
    codec,
    fec::{research, rolling},
    record_engine, research_records,
};

#[inline(never)]
fn research_plans(hosts: &[Arc<Host>; 2]) -> Result<(CarrierPlans, Vec<Arc<Probe>>)> {
    let (
        CarrierPlans {
            plans,
            addresses,
            requested: original,
        },
        probes,
    ) = raw_plans(hosts)?;
    let mut resources = [
        original.requested_resources(Role::Initiator),
        original.requested_resources(Role::Responder),
    ];
    for resource in &mut resources {
        resource.rolling_work = Some(rolling::WorkBudget {
            field: 4096,
            copies: 4096,
            metadata: 4096,
        });
        resource.rolling_ingress = Some(l2tunnel::rolling_records::IngressLimits {
            slots: 16,
            capacity_bytes: 1 << 20,
        });
    }
    let native = original.connection().max_packet;
    let direction = |policy, overhead| {
        let original = aligned_direction(native, 1, overhead, true);
        let mut receiver = original.receiver;
        receiver.lifetime_ticks = 5_000_000;
        research_records::DirectionConfig {
            native_policy: original.native_policy,
            receiver,
            packing: codec::packed_sender::Config {
                sender: codec::aligned_sender::Config {
                    body: receiver.body,
                    channels: receiver.channels,
                    first_record: receiver.first_record,
                },
                packing: codec::packed::Config {
                    symbol_bytes: receiver.body.symbol_bytes,
                    hold_micros: 503,
                },
                max_units: 3,
                first_unit: receiver.first_source,
                work_limit: 3,
            },
            codec_stage_micros: 1_000_000,
            scheduler: research::Config {
                recovery: rolling::Config {
                    window: 16,
                    local_window: 4,
                    global_every: 2,
                    max_payload: 1024,
                    max_rows: 16,
                    repair_history: 64,
                    handoff_sources: 2,
                    job_ticks: 1_000_000,
                    debt_ticks: 10_000_000,
                    handoff_ticks: 2_000_000,
                    memory_bytes: 16 << 20,
                },
                profile: policy,
                feedback_ticks: 1,
                memory_bytes: 16 << 20,
            },
        }
    };
    let policies = [
        research::Profile::Recursive {
            taps: 1,
            width: 1,
            reset: 1,
            fresh_interval: 0,
        },
        research::Profile::Recursive {
            taps: 1,
            width: 1,
            reset: 1,
            fresh_interval: 2,
        },
        research::Profile::Accumulator {
            lanes: 3,
            window: 16,
        },
    ];
    let initial = *original.initial().descriptor();
    let mut descriptors = vec![initial];
    for policy in policies {
        descriptors.push(common::Descriptor::new(
            initial.path_mtu(),
            initial.duplex(),
            common_direction(
                1,
                native,
                initial
                    .direction(DataRole::Client)
                    .common()
                    .bytes_per_second(),
            )?,
            common_direction(
                1,
                native,
                initial
                    .direction(DataRole::Server)
                    .common()
                    .bytes_per_second(),
            )?,
            common::Profile::Research {
                config: research_records::Config {
                    forward: direction(policy, resources[0].control.wire_overhead),
                    reverse: direction(policy, resources[1].control.wire_overhead),
                    geometry: record_engine::Geometry {
                        forward_overhead_bytes: resources[0].control.wire_overhead,
                        reverse_overhead_bytes: resources[1].control.wire_overhead,
                    },
                    native_stall_micros: u64::try_from(
                        resources[0].native.stall_timeout.as_micros(),
                    )?,
                },
                stream: 23,
            },
        )?);
    }
    let requested = common_transaction_profile::Profile::new_raw(
        original.connection(),
        original.settings(),
        original.peers(),
        resources[0],
        resources[1],
        common::Catalog::new(initial, &descriptors)?,
        original.parameters(),
        original.raw_policy().ok_or("actual requested raw policy")?,
    )?;
    let convert = |plan: Prepared| -> Result<Prepared> {
        let data = Arc::try_unwrap(plan.data).map_err(|_| "unstarted actual credentials shared")?;
        let prepared::Data {
            endpoint,
            attachment,
            transport,
            ..
        } = data;
        let prepared::Transport::SecureUdpCommonRaw { raw, opener, .. } = transport else {
            return Err("actual raw transport absent".into());
        };
        match endpoint {
            prepared::Endpoint::CommonRawClient { outer, inner } => {
                Ok(Prepared::secure_udp_common_raw_client(
                    requested.clone(),
                    raw.as_ref().clone(),
                    outer,
                    inner,
                    opener,
                    attachment,
                )?)
            }
            prepared::Endpoint::CommonRawServer(server) => {
                let prepared::CommonRawServer {
                    outer,
                    inner,
                    admission,
                } = *server;
                assert!(admission.into_inner().is_none());
                Ok(Prepared::secure_udp_common_raw_server(
                    requested.clone(),
                    raw.as_ref().clone(),
                    outer,
                    inner,
                    opener,
                    attachment,
                )?)
            }
            _ => Err("unexpected actual raw credential owner".into()),
        }
    };
    let [a, b] = plans;
    let plans = [convert(a)?, convert(b)?];
    assert!(probes.iter().all(|p| p.opened.load(Ordering::SeqCst) == 0));
    support::assert_unopened(hosts);
    Ok((
        CarrierPlans {
            plans,
            addresses,
            requested,
        },
        probes,
    ))
}

async fn held_first_raw_lane(
    hosts: &[Arc<Host>; 2],
    handles: &[Handle; 2],
    probes: &[Arc<Probe>],
    expected: common::Configuration,
    epoch: u64,
) -> Result {
    // The existing Half fixture indexes client First, server First, client
    // Second, server Second. Actual RawAdapter sends client User on First;
    // client management remains on its distinct Second original.
    let probe = probes.first().ok_or("actual client First original")?;
    let before = [common_frame(&handles[0])?, common_frame(&handles[1])?];
    let mut bytes = packet(120, 513);
    let udp_bytes = u16::try_from(bytes.len() - 20)?;
    bytes[24..26].copy_from_slice(&udp_bytes.to_be_bytes());
    probe.blocked.store(true, Ordering::SeqCst);
    hosts[0].send(&bytes)?;
    let held = timeout(Duration::from_millis(100), async {
        while probe.blocked_attempts.load(Ordering::SeqCst) < 2 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let wire = probe
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or("actual blocked raw packet")?;
        assert!(!wire.is_empty());
        assert_no_native_replay(&hosts[1])?;
        for side in 0..2 {
            let current = common_frame(&handles[side])?;
            assert_eq!(current.info, before[side].info);
            let actual = current.runtime.as_ref().ok_or("held runtime observation")?;
            assert!(actual.running && actual.terminal.is_none());
            assert_eq!((actual.current, actual.epoch.0), (expected, epoch));
        }
        Ok::<_, Error>(())
    })
    .await;
    probe.blocked.store(false, Ordering::SeqCst);
    held??;
    hosts[1].expect(&bytes).await?;
    let old = [
        before[0]
            .runtime
            .as_ref()
            .ok_or("original client observation")?,
        before[1]
            .runtime
            .as_ref()
            .ok_or("original server observation")?,
    ];
    tokio::try_join!(
        await_common(
            &handles[0],
            expected,
            epoch,
            old[0].counters.native_written,
            old[0].liveness.last_pong_micros
        ),
        await_common(
            &handles[1],
            expected,
            epoch,
            old[1].counters.native_written + 1,
            old[1].liveness.last_pong_micros
        )
    )?;
    assert!(
        probe
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_none()
    );
    assert_no_native_replay(&hosts[1])?;
    Ok(())
}

#[tokio::test]
async fn actual_raw_half_shared_service_switches_three_research_policies_with_physical_custody()
-> Result {
    timeout(
        Duration::from_secs(30),
        Box::pin(async {
            let hosts = support::hosts();
            let (
                CarrierPlans {
                    plans: [a, b],
                    addresses,
                    requested,
                },
                probes,
            ) = research_plans(&hosts)?;
            let (client, run) = channel();
            let (server, peer) = channel();
            let tasks = [tokio::spawn(run), tokio::spawn(peer)];
            let accepted = [
                client
                    .connect(a, client.next_key().map_err(submit)?)
                    .map_err(submit)?,
                server
                    .connect(b, server.next_key().map_err(submit)?)
                    .map_err(submit)?,
            ];
            let (a, b) = tokio::try_join!(
                connected(&client, accepted[0]),
                connected(&server, accepted[1])
            )?;
            let handles = [client, server];
            let generations = [a, b];
            let originals = [common_frame(&handles[0])?, common_frame(&handles[1])?];
            let effective = &originals[0].requested;
            let supported = effective.catalog().configurations(effective.envelope())?;
            assert_eq!(supported.len(), 4);
            assert_eq!(originals[0].info.binding, originals[1].info.binding);
            let syns: Vec<_> = probes
                .iter()
                .map(|p| p.syns.load(Ordering::SeqCst))
                .collect();
            let first_epoch = originals[0]
                .runtime
                .as_ref()
                .ok_or("actual raw runtime")?
                .epoch
                .0;
            for side in 0..2 {
                let frame = &originals[side];
                let raw = frame.status()?.raw_carrier.ok_or("genuine raw status")?;
                let proof = frame.requested.raw_binding().ok_or("genuine raw proof")?;
                assert_eq!(raw.duplex, "half");
                assert!(raw.lanes.iter().all(Option::is_some));
                assert_eq!(raw.binding, proof.binding());
                assert_eq!(raw.policy_digest, proof.policy_digest());
                assert_eq!(raw.requested_configuration, requested.configuration()?.0);
                assert_eq!(raw.effective_configuration, effective.configuration()?.0);
                assert_ne!(raw.requested_configuration, raw.effective_configuration);
                assert_eq!(
                    raw.effective_catalog,
                    *effective.catalog().root().as_bytes()
                );
                assert_eq!(
                    frame.info.authenticated.configuration,
                    effective.configuration()?.0
                );
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
                assert_eq!(
                    support::observation(&handles[side], generations[side])?
                        .original_timeout_micros,
                    3_000_000
                );
                assert_common(
                    frame,
                    effective.initial(),
                    first_epoch,
                    frame,
                    generations[side],
                )?;
            }
            exchange_stage(&hosts, &handles, effective.initial(), first_epoch, 0).await?;
            let mut targets: Vec<_> = supported
                .iter()
                .copied()
                .filter(|c| matches!(c.descriptor().profile(), common::Profile::Research { .. }))
                .collect();
            assert_eq!(targets.len(), 3);
            targets.push(effective.initial());
            for (step, target) in targets.into_iter().enumerate() {
                let key = handles[0].next_key().map_err(submit)?;
                let accepted = handles[0].apply_common(target, key).map_err(submit)?;
                assert_eq!(
                    handles[0].apply_common(target, key).map_err(submit)?,
                    accepted
                );
                let epoch = first_epoch + step as u64 + 1;
                assert_eq!(
                    timeout(Duration::from_secs(4), handles[0].wait(accepted.operation))
                        .await?
                        .map_err(submit)?,
                    Completed::Common {
                        configuration: target,
                        outcome: Ok(l2tunnel_core::Epoch(epoch))
                    }
                );
                tokio::try_join!(
                    await_common(&handles[0], target, epoch, 0, None),
                    await_common(&handles[1], target, epoch, 0, None)
                )?;
                if step == 0 {
                    held_first_raw_lane(&hosts, &handles, &probes, target, epoch).await?;
                }
                exchange_stage(&hosts, &handles, target, epoch, step as u8 + 1).await?;
                for side in 0..2 {
                    let frame = common_frame(&handles[side])?;
                    assert_common(&frame, target, epoch, &originals[side], generations[side])?;
                    assert_eq!(frame.info.local_addr, addresses[side]);
                    assert_eq!(frame.info.peer_addr, addresses[1 - side]);
                    assert_eq!(
                        frame
                            .status()?
                            .raw_carrier
                            .ok_or("raw proof/status lost")?
                            .binding,
                        originals[side]
                            .requested
                            .raw_binding()
                            .ok_or("original raw proof")?
                            .binding()
                    );
                    assert!(frame.status()?.original_carrier.is_none());
                    assert_no_native_replay(&hosts[side])?;
                }
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
                assert_eq!(hosts[side].opened.load(Ordering::SeqCst), 1);
                assert_eq!(hosts[side].live.load(Ordering::SeqCst), 0);
            }
            for (index, probe) in probes.iter().enumerate() {
                assert_eq!(probe.opened.load(Ordering::SeqCst), 1);
                assert_eq!(probe.dropped.load(Ordering::SeqCst), 1);
                assert_eq!(probe.syns.load(Ordering::SeqCst), syns[index]);
            }
            for task in tasks {
                task.abort();
                let _ = task.await;
            }
            Ok::<_, Error>(())
        }),
    )
    .await?
}
