//! Actual shared Common service with explicit v3 data and strong control/feedback.
use super::*;
use crate::secure_udp::common_status::{CompactDataProtection, CompactWireSelection};

fn compact_direction(old: aligned::Config, reverse: bool) -> Result<aligned::CompactConfig> {
    use l2tunnel_recovery::{CompactArqConfig, CompactBounds, CompactRecovery, CompactTiming};
    let arq = old.recovery.arq;
    Ok(aligned::CompactConfig {
        native_policy: old.native_policy,
        receiver: old.receiver,
        recovery: l2tunnel_reliable::CompactReliableConfig::new(
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

type CompactPlans = (
    [Prepared; 2],
    common_transaction_profile::Profile,
    [std::net::SocketAddr; 2],
    Vec<common::Configuration>,
);

fn compact_plans(
    appearance: l2tunnel_cover::Appearance,
    hosts: &[Arc<Host>; 2],
    selection: l2tunnel::secure_record::compact::Selection,
) -> Result<CompactPlans> {
    let CommonPlans {
        plans,
        profile: old,
        addresses,
        ..
    } = common_plans(appearance, hosts)?;
    let mut resources = [
        old.runtime_contract(Role::Initiator)?.resources(),
        old.runtime_contract(Role::Responder)?.resources(),
    ];
    let physical = if addresses[0].is_ipv6() { 48 } else { 28 };
    for value in &mut resources {
        value.control.wire_overhead =
            physical + l2tunnel::secure_record::compact::AUTHENTICATED_OVERHEAD;
        for stream in &mut value
            .streams
            .as_mut()
            .ok_or("actual explicit streams")?
            .streams
        {
            stream.delivery.wire_overhead =
                value.control.wire_overhead + l2tunnel_management::control_streams::HEADER_BYTES;
        }
    }
    let make = |catalog| {
        common_transaction_profile::Profile::new_compact(
            old.connection(),
            old.settings(),
            old.peers(),
            resources[0],
            resources[1],
            catalog,
            old.parameters(),
            selection,
        )
    };
    // Every advertised member remains in the selected authenticated catalog.
    let data_overhead = physical + l2tunnel::secure_record::compact::DATA_OVERHEAD;
    let mut descriptors = Vec::new();
    for original in old.catalog().descriptors() {
        let profile = match *original.profile() {
            common::Profile::Swift { forward, reverse } => {
                common::Profile::Swift { forward, reverse }
            }
            common::Profile::Aligned {
                mut forward,
                mut reverse,
            } => {
                forward.recovery.outer_overhead_bytes = data_overhead;
                reverse.recovery.outer_overhead_bytes = data_overhead;
                common::Profile::Aligned { forward, reverse }
            }
            common::Profile::Packed {
                mut forward,
                mut reverse,
            } => {
                forward.base.recovery.outer_overhead_bytes = data_overhead;
                reverse.base.recovery.outer_overhead_bytes = data_overhead;
                common::Profile::Packed { forward, reverse }
            }
            _ => return Err("unexpected original Common fixture".into()),
        };
        let descriptor = |profile| {
            common::Descriptor::new(
                original.path_mtu(),
                original.duplex(),
                *original.direction(DataRole::Client).common(),
                *original.direction(DataRole::Server).common(),
                profile,
            )
        };
        descriptors.push(descriptor(profile)?);
        match profile {
            common::Profile::Aligned { forward, reverse } => {
                descriptors.push(descriptor(common::Profile::AlignedCompact {
                    forward: compact_direction(forward, false)?,
                    reverse: compact_direction(reverse, true)?,
                })?)
            }
            common::Profile::Packed { forward, reverse } => {
                descriptors.push(descriptor(common::Profile::PackedCompact {
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
                })?)
            }
            _ => {}
        }
    }
    let native = old.connection().max_packet;
    let direction = |reverse| -> Result<l2tunnel::connection_records::Direction> {
        let mut base = aligned_direction(native, 1, data_overhead, false);
        base.receiver.record_window = 4;
        base.receiver.source_window = 16;
        base.receiver.lookahead_bytes = 8192;
        base.receiver.lookahead_fragments = 64;
        let mut compact = compact_direction(base, reverse)?;
        compact.recovery = l2tunnel_reliable::CompactReliableConfig::new(
            compact.recovery.arq(),
            data_overhead + l2tunnel::connection_records::route::HEADER_BYTES,
        )?;
        Ok(l2tunnel::connection_records::Direction {
            compact,
            owners: 16,
            incarnation: 29,
            unreliable: None,
        })
    };
    let policy = || -> Result<common::CommonDirection> {
        let original = common_direction(16, native, 1_000_000)?;
        let mut pipeline = original.pipeline();
        pipeline.flows.capacity = 32;
        pipeline.flows.mapping = l2tunnel_pipeline::Mapping::ConnectionRoundRobinLearned;
        Ok(common::CommonDirection::new(
            original.traffic(),
            pipeline,
            original.bytes_per_second(),
            original.burst_bytes(),
            original.native_window(),
        )?)
    };
    descriptors.push(common::Descriptor::new(
        1500,
        Duplex::Full,
        policy()?,
        policy()?,
        common::Profile::PerConnectionCompact {
            forward: direction(false)?,
            reverse: direction(true)?,
        },
    )?);
    let catalog = common::Catalog::new(descriptors[0], &descriptors)?;
    let profile = make(catalog)?;
    let configurations = profile.catalog().configurations(profile.envelope())?;
    assert_ne!(profile.configuration()?, old.configuration()?);
    let convert = |plan: Prepared| -> Result<Prepared> {
        let data =
            Arc::try_unwrap(plan.data).map_err(|_| "unstarted credentials unexpectedly shared")?;
        let prepared::Data {
            endpoint,
            attachment,
            ..
        } = data;
        match endpoint {
            prepared::Endpoint::SecureClient(credentials) => Ok(
                Prepared::secure_udp_common_client(profile.clone(), credentials, attachment)?,
            ),
            prepared::Endpoint::SecureServer(server) => {
                let prepared::SecureServer {
                    credentials,
                    admission,
                } = *server;
                assert!(
                    admission.into_inner().is_none(),
                    "actual authentication must not have begun"
                );
                Ok(Prepared::secure_udp_common_server(
                    profile.clone(),
                    credentials,
                    attachment,
                )?)
            }
            _ => Err("unexpected unstarted Common credentials".into()),
        }
    };
    let [left, right] = plans;
    Ok((
        [convert(left)?, convert(right)?],
        profile,
        addresses,
        configurations,
    ))
}

async fn exchange_selected_stage(
    hosts: &[Arc<Host>; 2],
    handles: &[Handle; 2],
    expected: common::Configuration,
    epoch: u64,
    stage: u8,
) -> Result {
    if !matches!(
        expected.descriptor().profile(),
        common::Profile::PerConnectionCompact { .. }
    ) {
        return exchange_stage(hosts, handles, expected, epoch, stage).await;
    }
    // This profile deliberately admits learned TCP owners rather than generic UDP.
    let before = [common_frame(&handles[0])?, common_frame(&handles[1])?];
    let packets = [
        independent_connections::tcp(false, true)?,
        independent_connections::tcp(true, true)?,
    ];
    hosts[0].send(&packets[0])?;
    hosts[1].send(&packets[1])?;
    tokio::try_join!(hosts[1].expect(&packets[0]), hosts[0].expect(&packets[1]))?;
    for side in 0..2 {
        let previous = before[side]
            .runtime
            .as_ref()
            .ok_or("actual independent runtime")?;
        let frame = await_common(
            &handles[side],
            expected,
            epoch,
            previous.counters.native_written + 1,
            previous.liveness.last_pong_micros,
        )
        .await?;
        assert!(
            frame
                .runtime
                .as_ref()
                .and_then(|runtime| runtime.connections)
                .is_some()
        );
    }
    Ok(())
}

#[tokio::test]
async fn actual_common_compact_wire_service_authenticates_selected_h0_status_and_native() -> Result
{
    timeout(
        Duration::from_secs(30),
        Box::pin(async {
            for appearance in support::appearances() {
                for data_protection in [
                    CompactDataProtection::AesCcm4,
                    CompactDataProtection::ChaCha20Crc32c,
                ] {
                    let requested = CompactWireSelection {
                        version: 3,
                        data_protection,
                        max_forward_packets: 8192,
                        max_failed_checks: 64,
                    };
                    let selection = requested.build()?;
                    let hosts = support::hosts();
                    let ([left, right], profile, addresses, configurations) =
                        compact_plans(appearance, &hosts, selection)?;
                    let (client, client_run) = channel();
                    let (server, server_run) = channel();
                    let tasks = [tokio::spawn(client_run), tokio::spawn(server_run)];
                    let accepts = [
                        client
                            .connect(left, client.next_key().map_err(submit)?)
                            .map_err(submit)?,
                        server
                            .connect(right, server.next_key().map_err(submit)?)
                            .map_err(submit)?,
                    ];
                    let (left, right) = tokio::try_join!(
                        connected(&client, accepts[0]),
                        connected(&server, accepts[1])
                    )?;
                    let generations = [left, right];
                    let handles = [client, server];
                    let initial = profile.initial();
                    let first = common_frame(&handles[0])?;
                    let epoch = first
                        .runtime
                        .as_ref()
                        .ok_or("actual compact runtime")?
                        .epoch
                        .0;
                    assert_eq!(
                        first.info.authenticated.configuration,
                        profile.configuration()?.0
                    );
                    assert_eq!(first.info.binding, common_frame(&handles[1])?.info.binding);
                    exchange_stage(&hosts, &handles, initial, epoch, 0).await?;
                    for (stage, target) in configurations
                        .iter()
                        .copied()
                        .skip(1)
                        .chain([initial])
                        .enumerate()
                    {
                        let accepted = handles[0]
                            .apply_common(target, handles[0].next_key().map_err(submit)?)
                            .map_err(submit)?;
                        let completed =
                            handles[0].wait(accepted.operation).await.map_err(submit)?;
                        let next_epoch = epoch + stage as u64 + 1;
                        assert_eq!(
                            completed,
                            Completed::Common {
                                configuration: target,
                                outcome: Ok(l2tunnel_core::Epoch(next_epoch)),
                            }
                        );
                        await_common(&handles[1], target, next_epoch, 0, None).await?;
                        exchange_selected_stage(
                            &hosts,
                            &handles,
                            target,
                            next_epoch,
                            stage as u8 + 1,
                        )
                        .await
                        .map_err(|error| {
                            format!(
                                "selected service exchange stage {} {:?}: {error}",
                                stage + 1,
                                target.descriptor().profile()
                            )
                        })?;
                    }
                    for side in 0..2 {
                        let frame = common_frame(&handles[side])?;
                        let actual = frame.runtime.as_ref().ok_or("actual compact sample")?;
                        assert_eq!(actual.compact_wire, Some(selection));
                        assert_eq!(
                            actual
                                .compact_check_status
                                .ok_or("actual check counters")?
                                .limit,
                            64
                        );
                        assert_eq!(
                            frame.info.authenticated.configuration,
                            profile.configuration()?.0
                        );
                        assert_eq!(frame.info.local_addr, addresses[side]);
                        assert_eq!(frame.info.peer_addr, addresses[1 - side]);
                        assert!(actual.liveness.last_pong_micros.is_some());
                        assert_eq!(hosts[side].opened.load(Ordering::SeqCst), 1);
                        let response = handles[side]
                            .lifecycle_request(local::Request {
                                version: local::COMMON_VERSION,
                                action: local::Action::Status {},
                            })
                            .await;
                        assert!(response.ok, "{response:?}");
                        let status = response
                            .state
                            .as_ref()
                            .and_then(|state| state.common.as_ref())
                            .ok_or("actual API4 Common status")?;
                        let compact = status
                            .compact_wire
                            .as_ref()
                            .ok_or("actual portable compact status")?;
                        assert_eq!(compact.requested, requested);
                        assert_eq!(compact.effective, Some(requested));
                        assert_eq!(
                            compact
                                .checks
                                .ok_or("actual portable check counters")?
                                .limit,
                            64
                        );
                        assert_eq!(status.protection, data_protection.name());
                        assert!(status.cross_profile_switching);
                        let encoded = serde_json::to_value(status)?;
                        assert_eq!(encoded["compact_wire"]["effective"]["version"], 3);
                        assert_eq!(
                            encoded["configuration"],
                            serde_json::json!(profile.configuration()?.0)
                        );
                    }
                    let stopped = [
                        handles[0]
                            .disconnect(handles[0].next_key().map_err(submit)?)
                            .map_err(submit)?,
                        handles[1]
                            .disconnect(handles[1].next_key().map_err(submit)?)
                            .map_err(submit)?,
                    ];
                    let (a, b) = tokio::try_join!(
                        handles[0].wait(stopped[0].operation),
                        handles[1].wait(stopped[1].operation)
                    )
                    .map_err(submit)?;
                    assert_eq!(a, Completed::Aborted);
                    assert_eq!(b, Completed::Aborted);
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
                }
            }
            Ok::<(), Error>(())
        }),
    )
    .await?
}
