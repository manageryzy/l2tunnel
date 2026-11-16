//! Actual catalog-bound Noise/member and shared service on the original UDP pair.
//! Unprivileged packet devices do not qualify native platforms or Python rates.
use super::*;
use l2tunnel::{
    codec,
    fec::{research, rolling},
    record_engine, research_records,
};

struct Selected {
    plans: [Prepared; 2],
    addresses: [std::net::SocketAddr; 2],
    profile: Arc<common_transaction_profile::Profile>,
    configurations: [common::Configuration; 4],
}
#[inline(never)]
fn selected(hosts: &[Arc<Host>; 2]) -> Result<Selected> {
    let CommonPlans {
        plans,
        addresses,
        profile: original,
        ..
    } = common_plans(l2tunnel_cover::Appearance::QuicLike, hosts)?;
    let mut resources = [
        original.runtime_contract(Role::Initiator)?.resources(),
        original.runtime_contract(Role::Responder)?.resources(),
    ];
    let work = rolling::WorkBudget {
        field: 4096,
        copies: 4096,
        metadata: 4096,
    };
    for resource in &mut resources {
        resource.rolling_work = Some(work);
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
                // Explicit finite fixture policy. This is not a product default
                // or the Python study's separately specified five-ms policy.
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
    let profile = Arc::new(common_transaction_profile::Profile::new(
        original.connection(),
        original.settings(),
        original.peers(),
        resources[0],
        resources[1],
        common::Catalog::new(initial, &descriptors)?,
        original.parameters(),
    )?);
    let configurations = [
        profile.initial(),
        common::Configuration::new(profile.envelope(), descriptors[1])?,
        common::Configuration::new(profile.envelope(), descriptors[2])?,
        common::Configuration::new(profile.envelope(), descriptors[3])?,
    ];
    let convert = |plan: Prepared| -> Result<Prepared> {
        let data = Arc::try_unwrap(plan.data).map_err(|_| "unstarted credentials shared")?;
        let prepared::Data {
            endpoint,
            attachment,
            ..
        } = data;
        match endpoint {
            prepared::Endpoint::SecureClient(credentials) => Ok(
                Prepared::secure_udp_common_client((*profile).clone(), credentials, attachment)?,
            ),
            prepared::Endpoint::SecureServer(server) => {
                let prepared::SecureServer {
                    credentials,
                    admission,
                } = *server;
                assert!(admission.into_inner().is_none());
                Ok(Prepared::secure_udp_common_server(
                    (*profile).clone(),
                    credentials,
                    attachment,
                )?)
            }
            _ => Err("unexpected unstarted endpoint".into()),
        }
    };
    let [a, b] = plans;
    let plans = [convert(a)?, convert(b)?];
    assert!(hosts.iter().all(|v| v.opened.load(Ordering::SeqCst) == 0));
    Ok(Selected {
        plans,
        addresses,
        profile,
        configurations,
    })
}

#[tokio::test]
async fn actual_catalog_bound_udp_service_switches_three_research_policies_and_preserves_authority()
-> Result {
    timeout(
        Duration::from_secs(30),
        Box::pin(async {
            let hosts = support::hosts();
            let Selected {
                plans: [client_plan, server_plan],
                addresses,
                profile,
                configurations,
            } = selected(&hosts)?;
            let (client, client_run) = channel();
            let (server, server_run) = channel();
            let tasks = [tokio::spawn(client_run), tokio::spawn(server_run)];
            let accepted = [
                client
                    .connect(client_plan, client.next_key().map_err(submit)?)
                    .map_err(submit)?,
                server
                    .connect(server_plan, server.next_key().map_err(submit)?)
                    .map_err(submit)?,
            ];
            let (a, b) = tokio::try_join!(
                connected(&client, accepted[0]),
                connected(&server, accepted[1])
            )?;
            let handles = [client, server];
            let generations = [a, b];
            let originals = [common_frame(&handles[0])?, common_frame(&handles[1])?];
            assert_eq!(originals[0].info.binding, originals[1].info.binding);
            assert_eq!(
                originals[0].info.authenticated.configuration,
                profile.configuration()?.0
            );
            let epoch = originals[0]
                .runtime
                .as_ref()
                .ok_or("initial runtime")?
                .epoch
                .0;
            exchange_stage(&hosts, &handles, configurations[0], epoch, 0).await?;
            for (step, target) in [
                configurations[1],
                configurations[2],
                configurations[3],
                configurations[0],
            ]
            .into_iter()
            .enumerate()
            {
                let key = handles[0].next_key().map_err(submit)?;
                let accepted = handles[0].apply_common(target, key).map_err(submit)?;
                assert_eq!(
                    handles[0].apply_common(target, key).map_err(submit)?,
                    accepted
                );
                let completed =
                    timeout(Duration::from_secs(4), handles[0].wait(accepted.operation))
                        .await?
                        .map_err(submit)?;
                let next = epoch + step as u64 + 1;
                assert_eq!(
                    completed,
                    Completed::Common {
                        configuration: target,
                        outcome: Ok(l2tunnel_core::Epoch(next))
                    }
                );
                tokio::try_join!(
                    await_common(&handles[0], target, next, 0, None),
                    await_common(&handles[1], target, next, 0, None)
                )?;
                exchange_stage(&hosts, &handles, target, next, step as u8 + 1).await?;
                for side in 0..2 {
                    let frame = common_frame(&handles[side])?;
                    assert_common(&frame, target, next, &originals[side], generations[side])?;
                    assert_eq!(frame.info.local_addr, addresses[side]);
                    assert_eq!(frame.info.peer_addr, addresses[1 - side]);
                    assert_eq!(
                        frame.info.authenticated.configuration,
                        profile.configuration()?.0
                    );
                    assert_eq!(
                        frame.requested.catalog().descriptors(),
                        profile.catalog().descriptors()
                    );
                    assert_eq!(hosts[side].opened.load(Ordering::SeqCst), 1);
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
            let (a, b) = tokio::join!(
                handles[0].wait(stopped[0].operation),
                handles[1].wait(stopped[1].operation)
            );
            assert_eq!(a.map_err(submit)?, Completed::Aborted);
            assert_eq!(b.map_err(submit)?, Completed::Aborted);
            for side in 0..2 {
                assert_eq!(
                    handles[side]
                        .wait_stopped(generations[side])
                        .await
                        .map_err(submit)?,
                    Terminal::Aborted
                );
                assert_eq!(hosts[side].live.load(Ordering::SeqCst), 0);
            }
            support::assert_ports_free(addresses)?;
            for task in tasks {
                task.abort();
                let _ = task.await;
            }
            Ok::<(), Error>(())
        }),
    )
    .await?
}
