//! Genuine catalog-bound Noise/member setup and shared tag8 service, without privileges.
use super::*;
use l2tunnel::{connection_records as connections, reliable::CompactReliableConfig};
use l2tunnel_recovery::{CompactArqConfig, CompactBounds, CompactRecovery, CompactTiming};
use l2tunnel_runtime::secure_udp::transport;

struct Selected {
    plans: [Prepared; 2],
    addresses: [std::net::SocketAddr; 2],
    profile: Arc<common_transaction_profile::Profile>,
}
#[inline(never)]
fn selected(hosts: &[Arc<Host>; 2]) -> Result<Selected> {
    selected_reuse(hosts, false)
}
#[inline(never)]
fn selected_reuse(hosts: &[Arc<Host>; 2], reuse: bool) -> Result<Selected> {
    selected_wire(hosts, reuse, None)
}
fn selected_wire(
    hosts: &[Arc<Host>; 2],
    reuse: bool,
    wire: Option<l2tunnel::secure_record::compact::Selection>,
) -> Result<Selected> {
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
    for (side, resource) in resources.iter_mut().enumerate() {
        resource.connection_ingress = Some(transport::ConnectionIngressLimits {
            slots: side + 2,
            capacity_bytes: 1 << 20,
        });
    }
    let native = original.connection().max_packet;
    let direction = |overhead| -> Result<connections::Direction> {
        let old = aligned_direction(native, 1, overhead, false);
        let bounds = old.recovery.arq;
        let mut receiver = old.receiver;
        receiver.record_window = 4;
        receiver.source_window = 16;
        receiver.lookahead_bytes = 8192;
        receiver.lookahead_fragments = 64;
        let recovery = CompactReliableConfig::new(
            CompactArqConfig::new(
                CompactBounds {
                    max_source_bytes: bounds.max_source_bytes,
                    send_bytes: bounds.send_bytes,
                    receive_bytes: bounds.receive_bytes,
                    send_records: bounds.send_records,
                    receive_records: bounds.receive_records,
                },
                CompactTiming {
                    nominal_rtt: Duration::from_millis(20),
                    feedback_interval: Duration::from_millis(1),
                    feedback_packets: 1,
                },
                200,
                64,
                8,
                CompactRecovery::Guarded,
            )?,
            overhead + connections::route::HEADER_BYTES,
        )?;
        Ok(connections::Direction {
            owners: 16,
            incarnation: 29,
            compact: aligned::CompactConfig {
                native_delivery: aligned::NativeDelivery::ProfileDefault,
                native_policy: aligned::NativePolicy::IpHeaders,
                receiver,
                recovery,
                max_recovery_packet_bytes: 1024,
                copies: l2tunnel_codec::source_copy::Policy::ONE,
            },
            unreliable: Some(connections::UnreliableConfig {
                max_bytes: 128,
                hold_micros: 1_000_000,
            }),
        })
    };
    let policy = || -> Result<common::CommonDirection> {
        let old = common_direction(16, native, 1_000_000)?;
        let mut pipeline = old.pipeline();
        pipeline.flows.capacity = 32;
        pipeline.flows.mapping = l2tunnel_pipeline::Mapping::ConnectionRoundRobinLearned;
        Ok(common::CommonDirection::new(
            old.traffic(),
            pipeline,
            old.bytes_per_second(),
            old.burst_bytes(),
            old.native_window(),
        )?)
    };
    let descriptor = common::Descriptor::new(
        1500,
        Duplex::Full,
        policy()?,
        policy()?,
        common::Profile::PerConnectionCompact {
            forward: direction(resources[0].control.wire_overhead)?,
            reverse: direction(resources[1].control.wire_overhead)?,
        },
    )?;
    let catalog = common::Catalog::new(descriptor, &[descriptor])?;
    let construct = if reuse {
        common_transaction_profile::Profile::new_with_connection_reuse
    } else {
        common_transaction_profile::Profile::new
    };
    let profile = construct(
        original.connection(),
        original.settings(),
        original.peers(),
        resources[0],
        resources[1],
        catalog,
        original.parameters(),
    )?;
    let profile = Arc::new(match wire {
        Some(selection) => profile.with_compact_wire(selection)?,
        None => profile,
    });
    let convert = |plan: Prepared| -> Result<Prepared> {
        let data = Arc::try_unwrap(plan.data)
            .map_err(|_| "unstarted Common credentials unexpectedly shared")?;
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
                assert!(
                    admission.into_inner().is_none(),
                    "tag8 setup must use the original unstarted credentials"
                );
                Ok(Prepared::secure_udp_common_server(
                    (*profile).clone(),
                    credentials,
                    attachment,
                )?)
            }
            _ => Err("unexpected original Common endpoint".into()),
        }
    };
    let [client, server] = plans;
    let plans = [convert(client)?, convert(server)?];
    assert!(
        hosts
            .iter()
            .all(|host| host.opened.load(Ordering::SeqCst) == 0)
    );
    Ok(Selected {
        plans,
        addresses,
        profile,
    })
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([
            pair[0],
            pair.get(1).copied().unwrap_or(0),
        ]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
pub(super) fn tcp(reverse: bool, payload: bool) -> Result<Vec<u8>> {
    let mut packet = vec![0; if payload { 100 } else { 40 }];
    packet[0] = 0x45;
    let length = u16::try_from(packet.len())?;
    packet[2..4].copy_from_slice(&length.to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..20].copy_from_slice(if reverse {
        &[198, 18, 0, 2, 198, 18, 0, 1]
    } else {
        &[198, 18, 0, 1, 198, 18, 0, 2]
    });
    let (source, destination): (u16, u16) = if reverse { (443, 41000) } else { (41000, 443) };
    packet[20..22].copy_from_slice(&source.to_be_bytes());
    packet[22..24].copy_from_slice(&destination.to_be_bytes());
    packet[31] = 7;
    packet[32] = 0x50;
    packet[33] = if payload { 0x18 } else { 0x10 };
    packet[34..36].copy_from_slice(&4096u16.to_be_bytes());
    if payload {
        packet[40..].fill(0x61);
    }
    let value = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&value.to_be_bytes());
    let mut pseudo = packet[12..20].to_vec();
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&(length - 20).to_be_bytes());
    pseudo.extend_from_slice(&packet[20..]);
    let value = checksum(&pseudo);
    packet[36..38].copy_from_slice(&value.to_be_bytes());
    Ok(packet)
}

async fn reported(handle: &Handle, sender: bool) -> Result<SecureUdpCommonFrame> {
    let mut changed = handle.subscribe();
    timeout(Duration::from_secs(4), async {
        loop {
            let frame = common_frame(handle)?;
            if frame.runtime.as_ref().is_some_and(|actual| {
                actual.running
                    && actual.liveness.last_pong_micros.is_some()
                    && actual.connections.is_some_and(|cohort| {
                        if sender {
                            cohort.unreliable.physical_accepted == 1
                        } else {
                            cohort.unreliable.native_written == 1
                        }
                    })
            }) {
                return Ok::<_, Error>(frame);
            }
            changed.changed().await?;
        }
    })
    .await?
}

#[tokio::test]
async fn actual_tag8_prepared_service_authenticates_catalog_delivers_tcp_and_reports_raw_ack_custody()
-> Result {
    timeout(Duration::from_secs(20), async {
        let hosts = support::hosts();
        let Selected {
            plans: [client_plan, server_plan],
            addresses,
            profile,
        } = selected(&hosts)?;
        let initial = profile.initial();
        let mut canonical = [0; common::CONFIGURATION_BYTES];
        initial.encode_into(&mut canonical)?;
        assert_eq!(canonical[5], 8);
        let (client, client_run) = channel();
        let (server, server_run) = channel();
        let client_task = tokio::spawn(client_run);
        let server_task = tokio::spawn(server_run);
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
        for frame in &originals {
            assert_eq!(
                frame.info.authenticated.configuration,
                profile.configuration()?.0
            );
            assert_eq!(frame.requested.initial(), initial);
        }
        let epoch = originals[0]
            .runtime
            .as_ref()
            .ok_or("actual initial tag8 runtime")?
            .epoch
            .0;
        let data = tcp(false, true)?;
        hosts[0].send(&data)?;
        hosts[1].expect(&data).await?;
        await_common(&handles[1], initial, epoch, 1, None).await?;
        let ack = tcp(true, false)?;
        hosts[1].send(&ack)?;
        hosts[0].expect(&ack).await?;
        let (left, right) =
            tokio::try_join!(reported(&handles[0], false), reported(&handles[1], true))?;
        for (side, frame) in [left, right].iter().enumerate() {
            let actual = frame
                .runtime
                .as_ref()
                .ok_or("actual tag8 service observation")?;
            assert_eq!(actual.current, initial);
            assert_eq!(actual.info.local_addr, addresses[side]);
            assert_eq!(actual.info.peer_addr, addresses[1 - side]);
            let cohort = actual
                .connections
                .ok_or("actual reserved independent cohort")?;
            assert_eq!(cohort.owners, 16);
            assert!(!cohort.flow_reuse);
            let queue = actual
                .connection_input
                .ok_or("actual independent raw input queue")?;
            assert_eq!(
                queue.limits,
                profile.connection_ingress()[side].ok_or("requested paired queue")?
            );
            assert!(
                queue.capacity_bytes > 0 && queue.capacity_bytes <= queue.limits.capacity_bytes
            );
            assert_eq!(
                (
                    queue.packets,
                    queue.bytes,
                    queue.dropped_full,
                    queue.expired
                ),
                (0, 0, 0, 0)
            );
            if side == 0 {
                assert_eq!(
                    (cohort.unreliable.received, cohort.unreliable.native_written),
                    (1, 1)
                );
            } else {
                assert_eq!(
                    (
                        cohort.unreliable.admitted,
                        cohort.unreliable.physical_accepted
                    ),
                    (1, 1)
                );
            }
            let status = frame.status()?;
            let encoded = serde_json::to_vec(&status)?;
            let decoded: crate::secure_udp::common_status::Status =
                serde_json::from_slice(&encoded)?;
            assert_eq!(
                decoded
                    .current
                    .as_ref()
                    .ok_or("actual canonical status")?
                    .configuration()?,
                initial
            );
            let observed = decoded.connections.ok_or("serialized actual cohort")?;
            assert_eq!(observed.owners, 16);
            assert!(!observed.flow_reuse);
            let ingress = decoded
                .connection_ingress
                .ok_or("serialized paired queue status")?;
            assert_eq!(ingress.requested.build()?, profile.connection_ingress());
            assert_eq!(
                ingress.effective.ok_or("effective local queue")?.build()?,
                queue.limits
            );
            assert!(
                !ingress.policy_switching
                    && !decoded.resource_preallocation_complete
                    && !decoded.fresh_rekey
            );
            assert!(actual.liveness.last_pong_micros.is_some());
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
        let (left, right) = timeout(Duration::from_secs(4), async {
            tokio::join!(
                handles[0].wait(stopped[0].operation),
                handles[1].wait(stopped[1].operation)
            )
        })
        .await?;
        assert_eq!(left.map_err(submit)?, Completed::Aborted);
        assert_eq!(right.map_err(submit)?, Completed::Aborted);
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
        client_task.abort();
        server_task.abort();
        let _ = client_task.await;
        let _ = server_task.await;
        Ok::<(), Error>(())
    })
    .await?
}

#[path = "secure_udp_common_reuse.rs"]
mod reuse;

#[test]
fn maintained_requested_reuse_is_explicit_and_commits_before_outer_authentication() -> Result {
    let hosts = support::hosts();
    let selected = selected_reuse(&hosts, false)?;
    let original = selected.profile;
    let mut settings = original.settings();
    settings.cover.max_packet_bytes = 1250;
    settings.cover.max_protected_bytes = 1220;
    settings.gate.arq.max_source_bytes = 1000;
    settings.gate.arq.send_bytes = 1000 * settings.gate.arq.send_records;
    settings.gate.arq.receive_bytes = 1000 * settings.gate.arq.receive_records;
    let mut resources = [
        original.runtime_contract(Role::Initiator)?.resources(),
        original.runtime_contract(Role::Responder)?.resources(),
    ];
    for resource in &mut resources {
        resource.security.max_body_bytes = 1200;
        resource.control.wire_overhead = 91;
        for stream in &mut resource.streams.as_mut().ok_or("missing streams")?.streams {
            stream.delivery.wire_overhead = 91 + l2tunnel_management::control_streams::HEADER_BYTES;
        }
    }
    let old = original.catalog().initial();
    let mut record = *old.profile();
    let common::Profile::PerConnectionCompact { forward, reverse } = &mut record else {
        return Err("missing connection profile".into());
    };
    for direction in [forward, reverse] {
        direction.compact.recovery = CompactReliableConfig::new(
            direction.compact.recovery.arq(),
            79 + connections::route::HEADER_BYTES,
        )?;
    }
    let descriptor = common::Descriptor::new(
        1500,
        Duplex::Full,
        *old.direction(DataRole::Client).common(),
        *old.direction(DataRole::Server).common(),
        record,
    )?;
    let maintained = crate::secure_udp::maintained::Settings {
        first: settings.gate.path,
        second: None,
        transport: crate::secure_udp::maintained::Transport::Tls(
            l2tunnel_runtime::retained_tls::Limits {
                max_record_bytes: 1430,
                record_timeout: Duration::from_secs(2),
            },
        ),
        geometry: l2tunnel_runtime::secure_udp::maintained::Geometry {
            path_mtu: 1500,
            max_record_bytes: 1430,
            max_bootstrap_bytes: 1430,
            charged_overhead_bytes: 70,
            bootstrap_overhead_bytes: 70,
            framing_bytes: 5,
        },
    };
    let wire = l2tunnel::secure_record::compact::Selection {
        protection: l2tunnel_security::compact::Protection::Aes128Ccm4,
        limits: l2tunnel_security::compact::Selection {
            max_forward_packets: 32_768,
            max_failed_checks: 64,
        },
    };
    let construct = |reuse| {
        let make = if reuse {
            common_transaction_profile::Profile::new_maintained_compact_with_connection_reuse
        } else {
            common_transaction_profile::Profile::new_maintained_compact
        };
        make(
            original.connection(),
            settings,
            original.peers(),
            resources[0],
            resources[1],
            common::Catalog::new(descriptor, &[descriptor]).map_err(io::Error::other)?,
            original.parameters(),
            maintained,
            wire,
        )
    };
    let fixed = construct(false)?;
    let reuse = construct(true)?;
    assert!(!fixed.connection_reuse() && reuse.connection_reuse());
    assert_ne!(
        fixed.requested_configuration()?,
        reuse.requested_configuration()?
    );
    assert_ne!(fixed.maintained_session()?, reuse.maintained_session()?);
    assert_eq!(fixed.catalog().descriptors(), reuse.catalog().descriptors());
    assert!(reuse.maintained_binding().is_none());
    assert!(reuse.runtime_contract(Role::Initiator).is_err());
    Ok(())
}
