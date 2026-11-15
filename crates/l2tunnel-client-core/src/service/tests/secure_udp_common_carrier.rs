//! Actual TLS/Noise/member/Driver owners through the sole shared service actor.
use super::*;
use l2tunnel::{codec, fec::rolling, record_engine, rolling_records};
use l2tunnel_openvpn::{WireBudget, wire_carrier::common as opaque};

struct CarrierPlans {
    plans: [Prepared; 2],
    addresses: [std::net::SocketAddr; 2],
    requested: common_transaction_profile::Profile,
}

fn rolling_direction(packed: aligned::packed::Config) -> rolling_records::DirectionConfig {
    let mut receiver = packed.base.receiver;
    receiver.lifetime_ticks = 5_000_000;
    rolling_records::DirectionConfig {
        native_policy: packed.base.native_policy,
        receiver,
        packing: codec::packed_sender::Config {
            sender: codec::aligned_sender::Config {
                body: receiver.body,
                channels: receiver.channels,
                first_record: receiver.first_record,
            },
            packing: codec::packed::Config {
                symbol_bytes: receiver.body.symbol_bytes,
                hold_micros: packed.hold_micros,
            },
            max_units: packed.max_units,
            first_unit: receiver.first_source,
            work_limit: packed.work_limit,
        },
        codec_stage_micros: 1_000_000,
        scheduler: rolling::scheduler::Policy {
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
            repair_numerator: 1,
            repair_denominator: 2,
            tail_ticks: 1000,
            feedback_ticks: 100,
            feedback_packets: 2,
            memory_bytes: 16 << 20,
            source_wire: rolling::wire::SourceWire::Exact,
        },
    }
}

fn carrier_plans(
    appearance: l2tunnel_cover::Appearance,
    hosts: &[Arc<Host>; 2],
    wrong_outer_member: bool,
) -> Result<CarrierPlans> {
    let CommonPlans { profile: old, .. } = common_plans(appearance, hosts)?;
    let mut settings = old.settings();
    let addresses = [settings.gate.path.client, settings.gate.path.server];
    let encoded = Zeroizing::new(MemberKey::generate_pkcs8()?);
    let member = identity::IdentityKey::from_pkcs8(&encoded)?;
    settings.member = member.public_key();
    // Explicit finite requested geometry reserves room for the extra opcode.
    // Binding never clamps an existing source, native maximum or path MTU.
    settings.cover.max_packet_bytes = 1471;
    settings.cover.max_protected_bytes = 1441;
    let mut resources = [
        old.runtime_contract(Role::Initiator)?.resources(),
        old.runtime_contract(Role::Responder)?.resources(),
    ];
    for resource in &mut resources {
        resource.security.max_body_bytes = 1300;
        resource.rolling_work = Some(rolling::WorkBudget {
            field: 4096,
            copies: 4096,
            metadata: 4096,
        });
    }
    resources[0].work.send_batch = 4;
    resources[1].work.send_batch = 5;
    let descriptor = *old.initial().descriptor();
    let aligned_descriptor = *old
        .catalog()
        .descriptors()
        .iter()
        .find(|value| matches!(value.profile(), common::Profile::Aligned { .. }))
        .ok_or("aligned fixture absent")?;
    let packed_descriptor = *old
        .catalog()
        .descriptors()
        .iter()
        .find(|value| matches!(value.profile(), common::Profile::Packed { .. }))
        .ok_or("packed fixture absent")?;
    let common::Profile::Swift {
        mut forward,
        mut reverse,
    } = *descriptor.profile()
    else {
        return Err("initial Swift fixture absent".into());
    };
    forward.codec.datagram_bytes = 1024;
    reverse.codec.datagram_bytes = 1024;
    let initial = common::Descriptor::new(
        descriptor.path_mtu(),
        descriptor.duplex(),
        *descriptor.direction(DataRole::Client).common(),
        *descriptor.direction(DataRole::Server).common(),
        common::Profile::Swift { forward, reverse },
    )?;
    let common::Profile::Packed { forward, reverse } = *packed_descriptor.profile() else {
        return Err("packed fixture absent".into());
    };
    let overhead = resources[0].control.wire_overhead;
    let fourth = common::Descriptor::new(
        descriptor.path_mtu(),
        descriptor.duplex(),
        *packed_descriptor.direction(DataRole::Client).common(),
        *packed_descriptor.direction(DataRole::Server).common(),
        common::Profile::Rolling {
            config: rolling_records::Config {
                forward: rolling_direction(forward),
                reverse: rolling_direction(reverse),
                geometry: record_engine::Geometry {
                    forward_overhead_bytes: overhead,
                    reverse_overhead_bytes: overhead,
                },
                native_stall_micros: 10_000_000,
            },
            stream: 17,
        },
    )?;
    let requested = common_transaction_profile::Profile::new(
        old.connection(),
        settings,
        old.peers(),
        resources[0],
        resources[1],
        common::Catalog::new(
            initial,
            &[initial, aligned_descriptor, packed_descriptor, fourth],
        )?,
        old.parameters(),
    )?;
    let certificate = rcgen::generate_simple_self_signed(vec!["service-carrier.test".into()])?;
    let chain = vec![certificate.cert.der().to_vec()];
    let outer_member = if wrong_outer_member {
        Arc::new(MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?)
    } else {
        Arc::new(MemberKey::from_pkcs8(&encoded)?)
    };
    let mut base = requested.connection().session()?;
    base.digest = l2tunnel_core::ConfigDigest(requested.requested_configuration()?.0);
    let outer = opaque::Config {
        base,
        path_mtu: 1500,
        outer_overhead_bytes: 29,
        max_record_bytes: 1471,
        control_arq: l2tunnel_recovery::ArqConfig {
            max_source_bytes: 512,
            send_bytes: 4096,
            receive_bytes: 4096,
            send_records: 8,
            receive_records: 8,
            initial_rto: Duration::from_millis(10),
            maximum_rto: Duration::from_millis(100),
            ack_delay: Duration::from_millis(1),
            max_retries: 16,
        },
        handshake_timeout: requested.connection().handshake_timeout,
        lifetime: Duration::from_secs(30),
        packet_slots: 8,
        stream_bytes: 16_384,
        poll_interval: Duration::from_millis(1),
        work_limit: 16,
        wire_budget: WireBudget {
            interval: Duration::from_millis(10),
            packets: 64,
            ip_bytes: 96_000,
            reserved_control_packets: 8,
            reserved_control_bytes: 12_000,
            maximum_control_packets: 32,
        },
    };
    let client = Prepared::secure_udp_common_carrier_client(
        requested.clone(),
        outer,
        Client {
            remote: addresses[1],
            tls: ClientTls::from_der_roots(&chain)?,
            server_name: "service-carrier.test".into(),
            member: outer_member,
        },
        credentials::Client::new(
            credentials::NoiseIdentity::new(
                Zeroizing::new([11; 32]),
                requested.peers().responder,
                hs::Profile::Ik,
                None,
            )?,
            member,
            credentials::Secret32::new(Zeroizing::new([44; 32]))?,
        )?,
        hosts[0].attachment(),
    )?;
    let server = Prepared::secure_udp_common_carrier_server(
        requested.clone(),
        outer,
        Server {
            listen: addresses[1],
            tls: ServerTls::from_der(&chain, &certificate.signing_key.serialize_der())?,
            members: MemberAllowlist::new(&[l2tunnel_auth::MemberPublicKey(settings.member.0)])?,
        },
        credentials::Server::new(
            credentials::NoiseIdentity::new(
                Zeroizing::new([22; 32]),
                requested.peers().initiator,
                hs::Profile::Ik,
                None,
            )?,
            credentials::Secret32::new(Zeroizing::new([44; 32]))?,
            credentials::Secret32::new(Zeroizing::new([55; 32]))?,
        )?,
        hosts[1].attachment(),
    )?;
    Ok(CarrierPlans {
        plans: [client, server],
        addresses,
        requested,
    })
}

#[tokio::test]
async fn actual_openvpn_common_service_uses_bound_catalog_for_all_four_families() -> Result {
    timeout(Duration::from_secs(30), async {
        for appearance in support::appearances() {
            let hosts = support::hosts();
            let CarrierPlans {
                plans: [a, b],
                addresses,
                requested,
            } = carrier_plans(appearance, &hosts, false)?;
            let (client, run) = channel();
            let (server, peer) = channel();
            let task = tokio::spawn(run);
            let peer_task = tokio::spawn(peer);
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
            let originals = [common_frame(&handles[0])?, common_frame(&handles[1])?];
            let effective = &originals[0].requested;
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
                    .ok_or("effective aligned absent")?,
                *supported
                    .iter()
                    .find(|value| {
                        matches!(value.descriptor().profile(), common::Profile::Packed { .. })
                    })
                    .ok_or("effective packed absent")?,
                *supported
                    .iter()
                    .find(|value| {
                        matches!(
                            value.descriptor().profile(),
                            common::Profile::Rolling { .. }
                        )
                    })
                    .ok_or("effective rolling absent")?,
            ];
            assert_eq!(originals[0].info.binding, originals[1].info.binding);
            let epoch = originals[0]
                .runtime
                .as_ref()
                .ok_or("missing runtime")?
                .epoch
                .0;
            for (side, generation) in [a, b].into_iter().enumerate() {
                let frame = &originals[side];
                assert_eq!(frame.info.local_addr, addresses[side]);
                assert_eq!(frame.info.peer_addr, addresses[1 - side]);
                assert_eq!(frame.requested.configuration()?, effective.configuration()?);
                assert_eq!(frame.requested.envelope(), effective.envelope());
                assert_eq!(
                    frame.requested.requested_configuration()?,
                    requested.configuration()?
                );
                assert_eq!(frame.requested.requested_envelope(), requested.envelope());
                assert_ne!(frame.requested.configuration()?, requested.configuration()?);
                assert_ne!(frame.requested.envelope(), requested.envelope());
                let status = frame.status()?;
                let carrier = status
                    .original_carrier
                    .as_ref()
                    .ok_or("missing actual carrier")?;
                let proof = frame
                    .requested
                    .carrier_binding()
                    .ok_or("missing genuine outer proof")?;
                assert_eq!(status.carrier, "openvpn-like");
                assert_eq!(
                    carrier.requested_configuration,
                    requested.configuration()?.0
                );
                assert_eq!(carrier.requested_envelope, *requested.envelope().as_bytes());
                assert_eq!(
                    carrier.effective_configuration,
                    effective.configuration()?.0
                );
                assert_eq!(carrier.effective_envelope, *effective.envelope().as_bytes());
                assert_eq!(
                    carrier.requested_catalog,
                    *requested.catalog().root().as_bytes()
                );
                assert_eq!(
                    carrier.effective_catalog,
                    *effective.catalog().root().as_bytes()
                );
                assert_eq!(carrier.session, proof.info().session_id);
                assert_eq!(carrier.configuration, proof.info().config.digest.0);
                assert_eq!(carrier.binding, proof.binding());
                assert_eq!(
                    proof
                        .expected_binding(
                            frame.requested.establish_config(frame.info.role)?,
                            frame.info.peers,
                            frame.info.binding.session,
                        )?
                        .outer,
                    frame.info.authenticated.outer,
                );
                assert_eq!(proof.endpoints(), (addresses[0], addresses[1]));
                assert_eq!(
                    support::observation(&handles[side], generation)?.original_timeout_micros,
                    3_000_000
                );
                assert_common(frame, configurations[0], epoch, frame, generation)?;
            }
            exchange_stage(&hosts, &handles, configurations[0], epoch, 0).await?;
            // A requested E0 configuration cannot acquire an effective E1 operation.
            assert_eq!(
                handles[0]
                    .apply_common(requested.initial(), handles[0].next_key().map_err(submit)?),
                Err(SubmitError::InvalidConfiguration),
            );
            for (stage, target) in [
                configurations[1],
                configurations[2],
                configurations[3],
                configurations[0],
            ]
            .into_iter()
            .enumerate()
            {
                let operation = handles[0]
                    .apply_common(target, handles[0].next_key().map_err(submit)?)
                    .map_err(submit)?;
                assert_eq!(
                    timeout(Duration::from_secs(4), handles[0].wait(operation.operation))
                        .await?
                        .map_err(submit)?,
                    Completed::Common {
                        configuration: target,
                        outcome: Ok(l2tunnel_core::Epoch(epoch + stage as u64 + 1))
                    },
                );
                await_common(&handles[1], target, epoch + stage as u64 + 1, 0, None).await?;
                exchange_stage(
                    &hosts,
                    &handles,
                    target,
                    epoch + stage as u64 + 1,
                    stage as u8 + 1,
                )
                .await?;
                for (side, generation) in [a, b].into_iter().enumerate() {
                    assert_common(
                        &common_frame(&handles[side])?,
                        target,
                        epoch + stage as u64 + 1,
                        &originals[side],
                        generation,
                    )?;
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
            for (side, generation) in [a, b].into_iter().enumerate() {
                assert_eq!(
                    handles[side]
                        .wait(stopped[side].operation)
                        .await
                        .map_err(submit)?,
                    Completed::Aborted
                );
                assert_eq!(
                    handles[side]
                        .wait_stopped(generation)
                        .await
                        .map_err(submit)?,
                    Terminal::Aborted
                );
                assert_eq!(hosts[side].live.load(Ordering::SeqCst), 0);
            }
            // The sole actor abort is asynchronous on drop; wait only for owned ports.
            timeout(Duration::from_secs(1), async {
                loop {
                    if support::assert_ports_free(addresses).is_ok() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await?;
            task.abort();
            peer_task.abort();
            let _ = task.await;
            let _ = peer_task.await;
        }
        Ok::<(), Error>(())
    })
    .await?
}

#[tokio::test(start_paused = true)]
async fn common_carrier_prepared_rejects_split_member_and_setup_expires_before_io() -> Result {
    let hosts = support::hosts();
    let failure = match carrier_plans(l2tunnel_cover::Appearance::QuicLike, &hosts, true) {
        Ok(_) => return Err("split outer/inner member was accepted".into()),
        Err(error) => error,
    };
    assert_eq!(
        failure.downcast_ref::<io::Error>().map(io::Error::kind),
        Some(io::ErrorKind::PermissionDenied)
    );
    assert!(
        hosts
            .iter()
            .all(|host| host.opened.load(Ordering::SeqCst) == 0)
    );
    let CarrierPlans {
        plans: [client, server],
        addresses,
        ..
    } = carrier_plans(l2tunnel_cover::Appearance::QuicLike, &hosts, false)?;
    let data = Arc::try_unwrap(server.data).map_err(|_| "unstarted carrier credentials shared")?;
    let prepared::Endpoint::CommonCarrierServer(server) = data.endpoint else {
        return Err("unexpected carrier credentials".into());
    };
    let prepared::Transport::SecureUdpCommonCarrier { profile, outer } = data.transport else {
        return Err("unexpected carrier transport".into());
    };
    let prepared::CommonCarrierServer {
        outer: mut tls,
        inner,
        admission,
    } = *server;
    assert!(admission.into_inner().is_none());
    let wrong = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    tls.members = MemberAllowlist::new(&[wrong.public_key()])?;
    let refusal = Prepared::secure_udp_common_carrier_server(
        (*profile).clone(),
        outer,
        tls,
        inner,
        data.attachment,
    );
    assert_eq!(
        refusal.err().map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    let (handle, run) = channel();
    let accepted = handle
        .connect(client, handle.next_key().map_err(submit)?)
        .map_err(submit)?;
    let mut run = Box::pin(run);
    // Expire the retained accepted cap before polling the selected setup future.
    tokio::time::advance(Duration::from_secs(3)).await;
    drive_once(&mut run).await;
    assert_eq!(
        handle.wait(accepted.operation).await.map_err(submit)?,
        Completed::Failed(Failure {
            kind: io::ErrorKind::TimedOut
        })
    );
    assert!(
        hosts
            .iter()
            .all(|host| host.opened.load(Ordering::SeqCst) == 0)
    );
    support::assert_ports_free(addresses)?;
    Ok(())
}
