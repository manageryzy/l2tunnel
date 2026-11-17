//! Actual shared service with genuine TLS Full and genuine Quinn Half owners.
use super::*;
use crate::secure_udp::maintained::{self, Settings, Transport};
use l2tunnel_runtime::{retained_tls, secure_udp::maintained::Geometry};

#[inline(never)]
fn plans(
    half: bool,
    hosts: &[Arc<Host>; 2],
) -> Result<(
    [Prepared; 2],
    common_transaction_profile::Profile,
    Vec<std::net::SocketAddr>,
)> {
    let CommonPlans { profile, .. } = common_plans(l2tunnel_cover::Appearance::QuicLike, hosts)?;
    maintained_plans(profile, half, hosts)
}
#[inline(never)]
pub(super) fn maintained_plans(
    old: common_transaction_profile::Profile,
    half: bool,
    hosts: &[Arc<Host>; 2],
) -> Result<(
    [Prepared; 2],
    common_transaction_profile::Profile,
    Vec<std::net::SocketAddr>,
)> {
    let mut connection = old.connection();
    connection.duplex = if half { Duplex::Half } else { Duplex::Full };
    let held = (0..if half { 4 } else { 2 })
        .map(|_| crate::test_ports::reserve(false))
        .collect::<io::Result<Vec<_>>>()?;
    let addresses = held
        .iter()
        .map(|socket| socket.local_addr())
        .collect::<io::Result<Vec<_>>>()?;
    let physical = if half { 156 } else { 70 };
    let geometry = Geometry {
        path_mtu: 1500,
        max_record_bytes: 1500 - physical,
        max_bootstrap_bytes: if half { 1296 } else { 1430 },
        charged_overhead_bytes: physical,
        bootstrap_overhead_bytes: if half { 204 } else { 70 },
        framing_bytes: if half { 0 } else { 5 },
    };
    let first = l2tunnel_udp_control::Path {
        client: addresses[0],
        server: addresses[1],
    };
    let second = half.then(|| l2tunnel_udp_control::Path {
        client: addresses[2],
        server: addresses[3],
    });
    let transport = if half {
        let first = l2tunnel_quic::Profile {
            application_id: [7; 16],
            traffic: l2tunnel_quic::Traffic::HalfDuplex {
                sender: l2tunnel_auth::Direction::ClientToServer,
            },
            lane: 0,
            datagram_format: l2tunnel_quic::DatagramFormat::CommonCompact,
            max_datagram_bytes: 1344,
            queued_datagrams: 8,
            control_window_bytes: 16384,
            udp_payload_ceiling: 1472,
            idle_timeout: Duration::from_secs(30),
            io_timeout: Duration::from_secs(2),
        };
        Transport::Quic([
            Some(first),
            Some(l2tunnel_quic::Profile {
                traffic: l2tunnel_quic::Traffic::HalfDuplex {
                    sender: l2tunnel_auth::Direction::ServerToClient,
                },
                lane: 1,
                ..first
            }),
        ])
    } else {
        Transport::Tls(retained_tls::Limits {
            max_record_bytes: 1430,
            record_timeout: Duration::from_secs(2),
        })
    };
    let selected = Settings {
        first,
        second,
        transport,
        geometry,
    };
    let encoded = Zeroizing::new(MemberKey::generate_pkcs8()?);
    let member = identity::IdentityKey::from_pkcs8(&encoded)?;
    let mut settings = old.settings();
    settings.gate.path = first;
    settings.member = member.public_key();
    settings.cover.max_packet_bytes = 1250;
    settings.cover.max_protected_bytes = 1220;
    settings.gate.arq.max_source_bytes = 1000;
    settings.gate.arq.send_bytes = 1000 * settings.gate.arq.send_records;
    settings.gate.arq.receive_bytes = 1000 * settings.gate.arq.receive_records;
    let mut resources = [
        old.runtime_contract(Role::Initiator)?.resources(),
        old.runtime_contract(Role::Responder)?.resources(),
    ];
    for value in &mut resources {
        value.path_mtu = geometry.path_mtu;
        value.security.max_body_bytes = 1200;
        value.control.wire_overhead =
            physical + l2tunnel::secure_record::compact::AUTHENTICATED_OVERHEAD;
        for stream in &mut value.streams.as_mut().ok_or("missing streams")?.streams {
            stream.path_mtu = geometry.path_mtu;
            stream.delivery.wire_overhead =
                value.control.wire_overhead + l2tunnel_management::control_streams::HEADER_BYTES;
        }
    }
    let data = physical + l2tunnel::secure_record::compact::DATA_OVERHEAD;
    let mut descriptors = Vec::new();
    for original in old.catalog().descriptors() {
        let mut profile = *original.profile();
        match &mut profile {
            common::Profile::Swift { forward, reverse } => {
                forward.codec.datagram_bytes = 1024;
                reverse.codec.datagram_bytes = 1024;
            }
            common::Profile::Aligned { forward, reverse } => {
                forward.recovery.outer_overhead_bytes = data;
                reverse.recovery.outer_overhead_bytes = data;
                if old.proxy_config().is_some() {
                    for value in [forward, reverse] {
                        value.receiver.body.symbol_bytes = 1024;
                        let original = 48 + value.receiver.body.symbol_bytes;
                        let wrapped = 44 + original;
                        value.recovery.arq.max_source_bytes = original;
                        value.recovery.arq.send_bytes = 8 * original;
                        value.recovery.arq.receive_bytes = 8 * original;
                        value.recovery.fec.block.max_source_bytes = wrapped;
                        value.recovery.fec.block.max_packet_bytes = 56 + 2 + 2 + wrapped;
                        value.recovery.max_restored_bytes =
                            value.recovery.max_restored_packets * wrapped;
                        value.max_recovery_packet_bytes = value.recovery.maximum_packet_bytes()?;
                    }
                }
            }
            common::Profile::Packed { forward, reverse } => {
                forward.base.recovery.outer_overhead_bytes = data;
                reverse.base.recovery.outer_overhead_bytes = data;
            }
            _ => return Err("unexpected fixture catalog".into()),
        }
        descriptors.push(common::Descriptor::new(
            geometry.path_mtu,
            connection.duplex,
            *original.direction(DataRole::Client).common(),
            *original.direction(DataRole::Server).common(),
            profile,
        )?);
    }
    let selection = l2tunnel::secure_record::compact::Selection {
        protection: l2tunnel_security::compact::Protection::Aes128Ccm4,
        limits: l2tunnel_security::compact::Selection {
            max_forward_packets: 8192,
            max_failed_checks: 64,
        },
    };
    let requested = if let Some(proxy) = old.proxy_config() {
        let mut proxy = proxy.clone();
        proxy.duplex = connection.duplex;
        let measured = old.proxy_measured_config().map(|value| {
            let mut value = value.clone();
            value.fixed = proxy.clone();
            value
        });
        common_transaction_profile::Profile::new_proxy_maintained(
            connection,
            settings,
            old.peers(),
            resources[0],
            resources[1],
            common::Catalog::new(descriptors[0], &descriptors)?,
            old.parameters(),
            proxy,
            old.proxy_retirement(),
            measured,
            Some(old.compact_wire()),
            selected,
        )?
    } else {
        common_transaction_profile::Profile::new_maintained_compact(
            connection,
            settings,
            old.peers(),
            resources[0],
            resources[1],
            common::Catalog::new(descriptors[0], &descriptors)?,
            old.parameters(),
            selected,
            selection,
        )?
    };
    let offline = crate::secure_udp::common_status::MaintainedCarrier::observe(&requested, None)?
        .ok_or("requested maintained status absent")?;
    assert!(
        offline.effective.is_none()
            && offline.binding.is_none()
            && offline.lanes.iter().all(Option::is_none)
    );
    let certificate = rcgen::generate_simple_self_signed(vec!["maintained-service.test".into()])?;
    let chain = vec![certificate.cert.der().to_vec()];
    let key = certificate.signing_key.serialize_der();
    let outer_member = Arc::new(MemberKey::from_pkcs8(&encoded)?);
    let members = MemberAllowlist::new(&[outer_member.public_key()])?;
    let outer_client = if half {
        maintained::Client::Quic {
            roots: chain.clone(),
            server_name: "maintained-service.test".into(),
            member: outer_member,
        }
    } else {
        maintained::Client::Tls(Client {
            remote: first.server,
            tls: ClientTls::from_der_roots_with_sni(
                &chain,
                l2tunnel_auth::ClientSni::named("public-cover.test")?,
            )?,
            server_name: "maintained-service.test".into(),
            member: outer_member,
        })
    };
    let outer_server = if half {
        maintained::Server::Quic {
            certs: chain,
            key: Zeroizing::new(key),
            members,
        }
    } else {
        maintained::Server::Tls(Server {
            listen: first.server,
            tls: ServerTls::from_der(&chain, &key)?,
            members,
        })
    };
    let a = (if requested.proxy_config().is_some() {
        Prepared::proxy_common_maintained_client
    } else {
        Prepared::secure_udp_common_maintained_client
    })(
        requested.clone(),
        outer_client,
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
    let b = (if requested.proxy_config().is_some() {
        Prepared::proxy_common_maintained_server
    } else {
        Prepared::secure_udp_common_maintained_server
    })(
        requested.clone(),
        outer_server,
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
    drop(held);
    Ok(([a, b], requested, addresses))
}
#[tokio::test]
async fn actual_maintained_common_tls_full_service_has_observed_owner_switch_and_release() -> Result
{
    exercise(false).await
}
#[tokio::test]
async fn actual_maintained_common_quic_half_service_has_observed_owner_switch_and_release() -> Result
{
    exercise(true).await
}
#[inline(never)]
fn exercise(half: bool) -> Pin<Box<dyn std::future::Future<Output = Result> + Send>> {
    Box::pin(async move {
        timeout(Duration::from_secs(15), async {
            let hosts = support::hosts();
            let ([a, b], requested, addresses) = plans(half, &hosts)?;
            let (client, run) = channel();
            let (server, peer) = channel();
            let task = tokio::spawn(run);
            let peer_task = tokio::spawn(peer);
            let accepted_server = server
                .connect(b, server.next_key().map_err(submit)?)
                .map_err(submit)?;
            timeout(Duration::from_secs(2), async {
                while server.snapshot().listening.is_none() {
                    tokio::task::yield_now().await;
                }
            })
            .await?;
            let accepted_client = client
                .connect(a, client.next_key().map_err(submit)?)
                .map_err(submit)?;
            let (a, b) = tokio::try_join!(
                connected(&client, accepted_client),
                connected(&server, accepted_server)
            )
            .map_err(|error| {
                io::Error::other(format!(
                    "maintained setup: {error}; client={:?}; server={:?}",
                    client.setup_observation(accepted_client.operation),
                    server.setup_observation(accepted_server.operation)
                ))
            })?;
            eprintln!("maintained service {half}: both actual owners ready");
            let handles = [client, server];
            let originals = [common_frame(&handles[0])?, common_frame(&handles[1])?];
            let effective = &originals[0].requested;
            let initial = effective.initial();
            let epoch = originals[0]
                .runtime
                .as_ref()
                .ok_or("runtime absent")?
                .epoch
                .0;
            assert_eq!(originals[0].info.binding, originals[1].info.binding);
            assert_eq!(effective.catalog().root(), requested.catalog().root());
            assert_ne!(effective.configuration()?, requested.configuration()?);
            for (side, generation) in [a, b].into_iter().enumerate() {
                let frame = &originals[side];
                let status = frame.status()?;
                let maintained = status
                    .maintained_carrier
                    .as_ref()
                    .ok_or("maintained status absent")?;
                assert_eq!(status.carrier, if half { "quic" } else { "tcp" });
                assert_eq!(maintained.effective, Some(maintained.requested.clone()));
                let outer = frame
                    .runtime
                    .as_ref()
                    .and_then(|value| value.maintained)
                    .ok_or("actual maintained proof absent")?;
                if half {
                    let queues = maintained
                        .effective
                        .as_ref()
                        .and_then(|value| value.quic_queues)
                        .ok_or("actual QUIC queue geometry absent")?;
                    for (observed, lane) in queues.into_iter().zip(outer.lanes()) {
                        let observed = observed.ok_or("missing Half queue")?;
                        let actual = lane
                            .and_then(|lane| lane.quic_queues)
                            .ok_or("missing actual Half queue")?;
                        assert_eq!(
                            observed.maintained_queue_bytes,
                            actual.maintained_queue_bytes as u64
                        );
                        assert_eq!(
                            observed.maintained_send_queue_bytes,
                            actual.maintained_send_queue_bytes as u64
                        );
                        assert!(
                            observed.maintained_send_queue_bytes < observed.maintained_queue_bytes
                        );
                    }
                } else {
                    assert!(maintained.requested.quic_queues.is_none());
                    assert!(
                        outer
                            .lanes()
                            .into_iter()
                            .flatten()
                            .all(|lane| lane.quic_queues.is_none())
                    );
                }
                // The proxy-style projection has the actual proof but no Settings.
                // Its effective queues remain known; requested queues stay unknown.
                let without_settings =
                    crate::secure_udp::common_status::MaintainedCarrier::from_observation(
                        outer.requested(),
                        Some(outer),
                    )?;
                assert!(without_settings.requested.quic_queues.is_none());
                assert_eq!(without_settings.effective, maintained.effective);
                assert!(maintained.binding.is_some());
                assert!(!maintained.physical_wire_bytes_observed);
                assert_eq!(
                    maintained.lanes.iter().flatten().count(),
                    if half { 2 } else { 1 }
                );
                assert_eq!(maintained.independent_sni_supported, !half);
                assert_eq!(
                    maintained.send_boundary.as_deref(),
                    Some(if half {
                        "QuicDatagramAccepted"
                    } else {
                        "TlsStreamFlushed"
                    })
                );
                let first = maintained.lanes[0].as_ref().ok_or("lane absent")?;
                assert_eq!(first.local, addresses[side].to_string());
                assert_eq!(first.peer, addresses[1 - side].to_string());
                assert_common(frame, initial, epoch, frame, generation)?;
            }
            eprintln!("maintained service {half}: initial native exchange");
            exchange_stage(&hosts, &handles, initial, epoch, 0).await?;
            eprintln!("maintained service {half}: initial exchange and liveness passed");
            let target = effective
                .catalog()
                .configurations(effective.envelope())?
                .into_iter()
                .find(|value| {
                    matches!(
                        value.descriptor().profile(),
                        common::Profile::Aligned { .. }
                    )
                })
                .ok_or("aligned target absent")?;
            let operation = handles[0]
                .apply_common(target, handles[0].next_key().map_err(submit)?)
                .map_err(submit)?;
            assert_eq!(
                handles[0].wait(operation.operation).await.map_err(submit)?,
                Completed::Common {
                    configuration: target,
                    outcome: Ok(l2tunnel_core::Epoch(epoch + 1))
                }
            );
            eprintln!("maintained service {half}: local switch completed");
            await_common(&handles[1], target, epoch + 1, 0, None).await?;
            eprintln!("maintained service {half}: peer switch observed");
            exchange_stage(&hosts, &handles, target, epoch + 1, 1).await?;
            eprintln!("maintained service {half}: post-switch exchange passed");
            let stops = handles
                .iter()
                .map(|handle| {
                    handle
                        .disconnect(handle.next_key().map_err(submit)?)
                        .map_err(submit)
                })
                .collect::<io::Result<Vec<_>>>()?;
            for (handle, stop) in handles.iter().zip(stops) {
                assert_eq!(
                    handle.wait(stop.operation).await.map_err(submit)?,
                    Completed::Aborted
                );
            }
            assert!(
                hosts
                    .iter()
                    .all(|host| host.live.load(Ordering::SeqCst) == 0)
            );
            eprintln!("maintained service {half}: both owners disconnected");
            if half {
                timeout(Duration::from_secs(5), async {
                    loop {
                        let held = addresses
                            .iter()
                            .map(std::net::UdpSocket::bind)
                            .collect::<io::Result<Vec<_>>>();
                        if held.is_ok() {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await?;
            }
            // Disconnect releases active transport/native ownership; the reusable
            // service supervisor intentionally stays alive after Handle drop.
            drop(handles);
            task.abort();
            peer_task.abort();
            assert!(task.await.is_err_and(|error| error.is_cancelled()));
            assert!(peer_task.await.is_err_and(|error| error.is_cancelled()));
            eprintln!("maintained service {half}: both service tasks released");
            Ok::<_, Error>(())
        })
        .await?
    })
}

#[path = "secure_udp_common_swift_lifecycle.rs"]
mod swift_lifecycle;
