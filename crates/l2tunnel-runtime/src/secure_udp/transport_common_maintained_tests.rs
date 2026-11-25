//! Real original TLS/QUIC authentication, Noise/member and Common runtime matrix.
//! Finite loopback and Unix-device evidence; transport charges are configured allowances.
use super::*;
use crate::{
    retained_tls,
    secure_udp::{maintained, maintained_io},
};
use l2tunnel_auth::{ClientTls, MemberAllowlist, MemberKey, ServerTls, SessionConfig};
use l2tunnel_quic::{self as quic_transport, common as quic_common};
use std::{future::Future, pin::Pin};
use zeroize::Zeroizing;

fn requested(
    duplex: core::Duplex,
    geometry: maintained::Geometry,
) -> Result<(
    [Config; 2],
    [cover::Config; 2],
    Catalog,
    TransactionSettings,
)> {
    let kind = cover::Appearance::QuicLike;
    let mut resources = config(kind);
    resources.security.max_body_bytes = 1200;
    resources.control.wire_overhead =
        geometry.charged_overhead_bytes + record::compact::AUTHENTICATED_OVERHEAD;
    let data_overhead = geometry.charged_overhead_bytes + record::compact::DATA_OVERHEAD;
    // Keep the base rollover interval within its inherited per-key byte cap.
    resources.lifetime.lease = Duration::from_secs(30);
    resources.native.stall_timeout = Duration::from_secs(5);
    resources.rolling_work = Some(work());
    let message = mg::messages::Settings {
        delivery: delivery::Settings {
            wire_overhead: resources.control.wire_overhead + streams::HEADER_BYTES,
            ..resources.control
        },
        path_mtu: 1500,
        max_message_bytes: 4096,
        max_outbound_messages: 4,
        max_outbound_bytes: 131072,
        max_fragments: 32,
        max_reassembly_bytes: 16384,
        max_incomplete_messages: 2,
        message_lifetime: Duration::from_secs(5),
        work_per_call: 8,
    };
    resources.streams = Some(control_owner::Settings {
        streams: [message; 3],
    });
    let cover_for = |local: u8, peer: u8| {
        cover::Config::new(
            kind,
            cover::ConnectionIds {
                local: cover::ConnectionId([local; 8]),
                peer: cover::ConnectionId([peer; 8]),
            },
            cover::MediaConfig {
                local_ssrc: cover::Ssrc(u32::from(local)),
                peer_ssrc: cover::Ssrc(u32::from(peer)),
                payload_type: 96,
            },
            cover::Limits {
                max_packet_bytes: geometry.max_bootstrap_bytes,
                max_protected_bytes: 1200,
            },
        )
    };
    let covers = [cover_for(1, 2)?, cover_for(2, 1)?];
    let original = values(kind, rolling::wire::SourceWire::Exact)?;
    let mut descriptors = original.map(|c| *c.descriptor());
    for descriptor in &mut descriptors {
        let profile = match *descriptor.profile() {
            c::Profile::Swift { forward, reverse } => c::Profile::Swift { forward, reverse },
            c::Profile::Aligned {
                mut forward,
                mut reverse,
            } => {
                forward.recovery.outer_overhead_bytes = data_overhead;
                reverse.recovery.outer_overhead_bytes = data_overhead;
                c::Profile::Aligned { forward, reverse }
            }
            c::Profile::Packed {
                mut forward,
                mut reverse,
            } => {
                forward.base.recovery.outer_overhead_bytes = data_overhead;
                reverse.base.recovery.outer_overhead_bytes = data_overhead;
                c::Profile::Packed { forward, reverse }
            }
            c::Profile::Rolling { mut config, stream } => {
                config.native_stall_micros =
                    u64::try_from(resources.native.stall_timeout.as_micros())?;
                config.geometry = engine::Geometry {
                    forward_overhead_bytes: data_overhead,
                    reverse_overhead_bytes: data_overhead,
                };
                c::Profile::Rolling { config, stream }
            }
            _ => return Err("four-family actual fixture unexpectedly changed profile".into()),
        };
        *descriptor = c::Descriptor::new(
            descriptor.path_mtu(),
            duplex,
            *descriptor.direction(mg::Role::Client).common(),
            *descriptor.direction(mg::Role::Server).common(),
            profile,
        )?;
    }
    let catalog = Catalog::new(descriptors[0], &descriptors)?;
    Ok((
        [resources; 2],
        covers,
        catalog,
        TransactionSettings {
            protocol: transaction::Settings {
                retry_ms: 10,
                phase_timeout_ms: 1000,
                reconcile_timeout_ms: 2000,
            },
            max_operation_ms: 3000,
            retained_bytes: 256 << 20,
        },
    ))
}
fn setup(
    outer: maintained::Authenticated,
    contract: &CommonTransactionContract,
) -> Result<establish::Config> {
    let (client, server) = outer.endpoints()?;
    let mut gate = l2tunnel_udp_control::Config::new(
        l2tunnel_udp_control::Path { client, server },
        [30; 32],
        1,
    )?;
    gate.path_mtu = outer.requested().geometry.path_mtu;
    gate.outer_overhead = outer.requested().geometry.bootstrap_overhead_bytes + 1 + 30;
    gate.arq.max_source_bytes = 100;
    gate.arq.send_bytes = 3200;
    gate.arq.receive_bytes = 3200;
    gate.arq.initial_rto = Duration::from_millis(10);
    gate.arq.maximum_rto = Duration::from_millis(100);
    gate.arq.ack_delay = Duration::from_millis(1);
    gate.arq.max_retries = 32;
    gate.cookie_ttl = Duration::from_millis(500);
    gate.handshake_timeout = Duration::from_secs(1);
    gate.initial_rto = Duration::from_millis(10);
    gate.maximum_rto = Duration::from_millis(100);
    gate.gate_attempts = 32;
    Ok(establish::Config {
        gate,
        cover: contract.cover(),
        profile: hs::Profile::Ik,
        binding: establish::Binding {
            configuration: contract.expected_configuration().0,
            carrier: [4; 32],
            outer: outer.binding(),
            member: [6; 32],
        },
        receive_packets_per_interval: 64,
    })
}
fn membership(e: &establish::maintained::InitialEstablished) -> member::Settings {
    member::Settings {
        context: l2tunnel_identity::Context {
            session: e.binding().session,
            transcript: e.binding().transcript,
            configuration: e.authenticated().configuration,
            carrier: e.authenticated().carrier,
            outer: e.authenticated().outer,
            initiator_noise: l2tunnel_identity::NoisePublicKey(e.peers().initiator.0),
            responder_noise: l2tunnel_identity::NoisePublicKey(e.peers().responder.0),
        },
        retry_interval: Duration::from_millis(10),
        max_attempts: 32,
        receive_interval: Duration::from_millis(1),
        receive_packets_per_interval: 64,
    }
}
fn device() -> Result<(Device, tokio::net::UnixDatagram)> {
    let (native, host) = UnixDatagram::pair()?;
    native.set_nonblocking(true)?;
    host.set_nonblocking(true)?;
    Ok((
        Device {
            socket: native,
            blocked: false,
            wouldblock: None,
        },
        tokio::net::UnixDatagram::from_std(host)?,
    ))
}

fn selection(protection: security::compact::Protection) -> record::compact::Selection {
    record::compact::Selection {
        protection,
        limits: security::compact::Selection {
            max_forward_packets: 8192,
            max_failed_checks: 128,
        },
    }
}
fn profiles(duplex: core::Duplex) -> Vec<quic_transport::Profile> {
    let mut first = quic_transport::Profile::new(*b"common-maintain1");
    first.datagram_format = quic_transport::DatagramFormat::CommonCompact;
    first.udp_payload_ceiling = 1472;
    first.max_datagram_bytes = 1344;
    first.io_timeout = Duration::from_secs(4);
    if duplex == core::Duplex::Full {
        vec![first]
    } else {
        first.traffic = quic_transport::Traffic::HalfDuplex {
            sender: l2tunnel_auth::Direction::ClientToServer,
        };
        let mut reverse = first;
        reverse.lane = 1;
        reverse.traffic = quic_transport::Traffic::HalfDuplex {
            sender: l2tunnel_auth::Direction::ServerToClient,
        };
        vec![first, reverse]
    }
}
fn tls_limits() -> retained_tls::Limits {
    retained_tls::Limits {
        max_record_bytes: 1431,
        record_timeout: Duration::from_secs(4),
    }
}
fn request(kind: maintained::Kind, duplex: core::Duplex) -> Result<maintained::Request> {
    Ok(match kind {
        maintained::Kind::TlsStream => maintained::Request {
            kind,
            duplex,
            geometry: maintained::Geometry {
                path_mtu: 1500,
                max_record_bytes: 1431,
                max_bootstrap_bytes: 1431,
                charged_overhead_bytes: 69,
                bootstrap_overhead_bytes: 69,
                framing_bytes: retained_tls::FRAMING_BYTES,
            },
            policy: retained_tls::policy_digest(duplex, tls_limits())?,
        },
        maintained::Kind::QuicDatagram => maintained::Request {
            kind,
            duplex,
            geometry: maintained::Geometry {
                path_mtu: 1500,
                max_record_bytes: 1344,
                max_bootstrap_bytes: 1296,
                charged_overhead_bytes: 156,
                bootstrap_overhead_bytes: 204,
                framing_bytes: 0,
            },
            policy: quic_common::policy_digest(&profiles(duplex))?,
        },
    })
}

async fn real_carriers(
    request: maintained::Request,
    base: SessionConfig,
    certificate: &rcgen::CertifiedKey<rcgen::KeyPair>,
    member: &MemberKey,
    allowed: &MemberAllowlist,
    deadline: Instant,
) -> Result<(maintained_io::Carrier, maintained_io::Carrier)> {
    let chain = vec![certificate.cert.der().to_vec()];
    let private = certificate.signing_key.serialize_der();
    let maximum = 256 << 20;
    match request.kind {
        maintained::Kind::TlsStream => {
            let client_tls = ClientTls::from_der_roots(&chain)?;
            let server_tls = ServerTls::from_der(&chain, &private)?;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let mut pairs = Vec::new();
            for _ in 0..if request.duplex == core::Duplex::Half {
                2
            } else {
                1
            } {
                let client = tokio::net::TcpStream::connect(listener.local_addr()?).await?;
                let (server, _) = listener.accept().await?;
                client.set_nodelay(true)?;
                server.set_nodelay(true)?;
                pairs.push(tokio::try_join!(
                    l2tunnel_auth::client_connect(
                        client,
                        &client_tls,
                        "maintained-common.test",
                        member,
                        base,
                        Duration::from_secs(4)
                    ),
                    l2tunnel_auth::server_accept(
                        server,
                        &server_tls,
                        allowed,
                        base,
                        Duration::from_secs(4)
                    ),
                )?);
            }
            let mut pairs = pairs.into_iter();
            let (a, b) = pairs.next().ok_or("actual first TLS pair")?;
            let (a, b) = if request.duplex == core::Duplex::Half {
                let (c, d) = pairs.next().ok_or("actual reverse TLS pair")?;
                tokio::try_join!(
                    retained_tls::client_pair(a, c, deadline, tls_limits()),
                    retained_tls::server_pair(b, d, deadline, tls_limits())
                )?
            } else {
                (
                    retained_tls::Link::full(a, deadline, tls_limits())?,
                    retained_tls::Link::full(b, deadline, tls_limits())?,
                )
            };
            Ok((
                maintained_io::Carrier::tls(a, tls_limits(), request, base, maximum)?,
                maintained_io::Carrier::tls(b, tls_limits(), request, base, maximum)?,
            ))
        }
        maintained::Kind::QuicDatagram => {
            let profiles = profiles(request.duplex);
            let mut pairs = Vec::new();
            for &profile in &profiles {
                let limits = quic_transport::EndpointLimits::default();
                let client = quic_transport::ClientEndpoint::bind(
                    "127.0.0.1:0".parse()?,
                    &quic_transport::ClientConfig::from_der_roots(&chain, profile, limits)?,
                )?;
                let server = quic_transport::ServerEndpoint::bind(
                    "127.0.0.1:0".parse()?,
                    &quic_transport::ServerConfig::from_der(&chain, &private, profile, limits)?,
                )?;
                pairs.push(tokio::try_join!(
                    client.connect(server.local_addr()?, "maintained-common.test", member, base),
                    server.accept(allowed, base),
                )?);
            }
            let mut pairs = pairs.into_iter();
            let (a, b) = pairs.next().ok_or("actual first QUIC pair")?;
            let (a, b) = if request.duplex == core::Duplex::Half {
                let (c, d) = pairs.next().ok_or("actual reverse QUIC pair")?;
                let policy = [profiles[0], profiles[1]];
                let (a, b) = tokio::try_join!(
                    quic_common::client_pair(a, c, policy, base, deadline),
                    quic_common::server_pair(b, d, policy, base, deadline),
                )?;
                (Vec::from(a), Vec::from(b))
            } else {
                (
                    vec![quic_common::Carrier::new(a, profiles[0], base, deadline)?],
                    vec![quic_common::Carrier::new(b, profiles[0], base, deadline)?],
                )
            };
            Ok((
                maintained_io::Carrier::quic(a, request, base, maximum)?,
                maintained_io::Carrier::quic(b, request, base, maximum)?,
            ))
        }
    }
}
struct OriginalPair {
    client: member::maintained::InitialParts,
    server: member::maintained::InitialParts,
    client_contract: CommonTransactionContract,
    server_contract: CommonTransactionContract,
    catalog: Catalog,
    endpoints: (std::net::SocketAddr, std::net::SocketAddr),
}
#[inline(never)]
fn establish_original_pair(
    kind: maintained::Kind,
    duplex: core::Duplex,
    protection: security::compact::Protection,
) -> Pin<Box<dyn Future<Output = Result<OriginalPair>>>> {
    Box::pin(establish_original_pair_inner(kind, duplex, protection))
}
async fn establish_original_pair_inner(
    kind: maintained::Kind,
    duplex: core::Duplex,
    protection: security::compact::Protection,
) -> Result<OriginalPair> {
    let selection = selection(protection);
    let request = request(kind, duplex)?;
    let (resources, covers, catalog, settings) = requested(duplex, request.geometry)?;
    let base = security::ConfigDigest([3; 32]);
    let envelope = c::EnvelopeDigest::new([0x39; 32]);
    let requested = CommonTransactionContract::maintained_requested_configuration_compact(
        base, envelope, &catalog, resources, covers, settings, request, selection,
    )?;
    let certificate =
        rcgen::generate_simple_self_signed(vec!["maintained-common.test".to_owned()])?;
    let key_bytes = MemberKey::generate_pkcs8()?;
    let outer_member = MemberKey::from_pkcs8(&key_bytes)?;
    let inner_member = l2tunnel_identity::IdentityKey::from_pkcs8(&key_bytes)?;
    let allowed = MemberAllowlist::new(&[outer_member.public_key()])?;
    let inner_allowed = l2tunnel_identity::Allowlist::new(&[inner_member.public_key()])?;
    let cap = Instant::now() + Duration::from_secs(10);
    let (a, b) = Box::pin(real_carriers(
        request,
        SessionConfig {
            layer: PacketLayer::Ethernet,
            digest: requested,
        },
        &certificate,
        &outer_member,
        &allowed,
        cap,
    ))
    .await
    .map_err(|error| {
        format!("maintained {kind:?} {duplex:?} stage=outer-authentication: {error:?}")
    })?;
    assert_eq!(a.authenticated().binding(), b.authenticated().binding());
    assert_eq!(a.authenticated().requested(), request);
    let lanes = if duplex == core::Duplex::Half { 2 } else { 1 };
    assert_eq!(a.authenticated().lanes().iter().flatten().count(), lanes);
    assert_eq!(b.authenticated().lanes().iter().flatten().count(), lanes);
    for (a, b) in a
        .authenticated()
        .lanes()
        .into_iter()
        .zip(b.authenticated().lanes())
    {
        if let (Some(a), Some(b)) = (a, b) {
            assert_eq!(a.info.session_id, b.info.session_id);
            assert_eq!((a.local, a.peer), (b.peer, b.local));
        }
    }
    let endpoints = a.authenticated().endpoints()?;
    let a = establish::maintained::Outer::from_carrier(a)?;
    let b = establish::maintained::Outer::from_carrier(b)?;
    let bind = |role, resources, outer| {
        CommonTransactionContract::new_on_maintained_paired_compact(
            base,
            role,
            resources,
            covers,
            envelope,
            catalog.clone(),
            settings,
            outer,
            selection,
        )
    };
    let a_contract = bind(security::Role::Initiator, resources, a.authenticated())?;
    let b_contract = bind(security::Role::Responder, resources, b.authenticated())?;
    assert_eq!(
        a_contract.expected_configuration(),
        b_contract.expected_configuration()
    );
    assert_ne!(a_contract.envelope(), envelope);
    assert_eq!(a_contract.compact_wire(), selection);
    let mut wrong = resources;
    wrong[1].work.send_batch += 1;
    assert!(bind(security::Role::Initiator, wrong, a.authenticated()).is_err());
    let a_config = setup(a.authenticated(), &a_contract)?;
    let b_config = setup(b.authenticated(), &b_contract)?;
    let local = hs::LocalSecret::new(Zeroizing::new([11; 32]));
    let remote = hs::LocalSecret::new(Zeroizing::new([22; 32]));
    let peers = establish::Peers {
        initiator: local.public_key(),
        responder: remote.public_key(),
    };
    let mut admission = establish::maintained::InitialServerAdmission::new(
        &b,
        b_config,
        peers,
        l2tunnel_udp_control::Secret::new([7; 32]),
        l2tunnel_udp_control::Secret::new([8; 32]),
        Instant::now(),
    )?;
    let mut a_entropy = Entropy(40);
    let mut b_entropy = Entropy(60);
    let mut a_noop = |_| {};
    let mut b_noop = |_| {};
    let (a, b) = tokio::try_join!(
        a.connect_initial(
            a_config,
            establish::Identity {
                local,
                peer: peers.responder,
                psk: None
            },
            l2tunnel_udp_control::Secret::new([7; 32]),
            &mut a_entropy,
            &mut a_noop,
            establish::Tuning::Off
        ),
        b.accept_initial(
            establish::Identity {
                local: remote,
                peer: peers.initiator,
                psk: None
            },
            &mut admission,
            &mut b_entropy,
            &mut b_noop,
            establish::Tuning::Off
        ),
    )
    .map_err(|error| format!("maintained {kind:?} {duplex:?} stage=inner-noise: {error:?}"))?;
    assert_eq!(
        a.authenticated().configuration,
        a_contract.expected_configuration().0
    );
    for statistics in [a.statistics(), b.statistics()] {
        assert!(statistics.maintained_accepted_records > 0);
        assert!(statistics.maintained_accepted_record_bytes > 0);
        assert_eq!(statistics.socket_sent_datagrams, 0);
        assert_eq!(statistics.socket_sent_udp_bytes, 0);
    }
    let a_settings = membership(&a);
    let b_settings = membership(&b);
    let (a, b) = tokio::try_join!(
        member::maintained::connect_initial(a, &inner_member, a_settings, &mut a_noop),
        member::maintained::accept_initial(b, inner_allowed, b_settings, &mut b_noop),
    )
    .map_err(|error| format!("maintained {kind:?} {duplex:?} stage=inner-membership: {error:?}"))?;
    let a = a.into_parts();
    let b = b.into_parts();
    assert_eq!(a.info.member, inner_member.public_key());
    assert_eq!(b.info.member, inner_member.public_key());
    Ok(OriginalPair {
        client: a,
        server: b,
        client_contract: a_contract,
        server_contract: b_contract,
        catalog,
        endpoints,
    })
}

async fn exercise_established(
    kind: maintained::Kind,
    duplex: core::Duplex,
    pair: OriginalPair,
) -> Result {
    let OriginalPair {
        client: a,
        server: b,
        client_contract: a_contract,
        server_contract: b_contract,
        catalog,
        endpoints,
    } = pair;
    let cap = a.deadline.min(b.deadline);
    let session = a.info.binding;
    let targets = catalog
        .descriptors()
        .iter()
        .map(|d| C::new(a_contract.envelope(), *d))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let initial = a_contract.initial();
    let find = |tag| {
        targets
            .iter()
            .copied()
            .find(|c| match c.descriptor().profile() {
                c::Profile::Swift { .. } => tag == 0,
                c::Profile::Aligned { .. } => tag == 1,
                c::Profile::Packed { .. } => tag == 2,
                c::Profile::Rolling { .. } => tag == 3,
                _ => false,
            })
            .ok_or("actual four-family member")
    };
    let order = [initial, find(1)?, find(2)?, find(3)?, initial];
    let (a_device, a_host) = device()?;
    let (b_device, b_host) = device()?;
    let (a_control, a_requests) = common_channel();
    let (_b_control, b_requests) = common_channel();
    let (a_stop, a_shutdown) = oneshot::channel::<()>();
    let (b_stop, b_shutdown) = oneshot::channel::<()>();
    let (a_seen, a_snapshots) = tokio::sync::watch::channel(None::<CommonSnapshot>);
    let (b_seen, b_snapshots) = tokio::sync::watch::channel(None::<CommonSnapshot>);
    let a_run = run_common_on_maintained(
        a_device,
        a,
        a_contract,
        Some(a_requests),
        async {
            let _ = a_shutdown.await;
        },
        move |s| {
            a_seen.send_replace(Some(s.clone()));
        },
    );
    let b_run = run_common_on_maintained(
        b_device,
        b,
        b_contract,
        Some(b_requests),
        async {
            let _ = b_shutdown.await;
        },
        move |s| {
            b_seen.send_replace(Some(s.clone()));
        },
    );
    let exercise = async {
        let result = tokio::time::timeout_at(cap, async {
            for (index, target) in order.into_iter().enumerate() {
                if index > 0 {
                    a_control
                        .switch(target)
                        .await
                        .map_err(|error| io::Error::other(format!("{error:?}")))?;
                }
                loop {
                    let matched = [a_snapshots.borrow().clone(), b_snapshots.borrow().clone()]
                        .into_iter()
                        .all(|s| {
                            s.is_some_and(|s| {
                                s.running && s.current == target && s.info.binding == session
                            })
                        });
                    if matched {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                let forward = frame(4100 + index as u16, 31 + index as u8);
                let reverse = frame(4200 + index as u16, 71 + index as u8);
                assert_eq!(a_host.send(&forward).await?, forward.len());
                assert_eq!(b_host.send(&reverse).await?, reverse.len());
                let (mut ap, mut bp) = ([0; 2048], [0; 2048]);
                let (an, bn) = tokio::try_join!(a_host.recv(&mut ap), b_host.recv(&mut bp))?;
                assert_eq!(&ap[..an], reverse);
                assert_eq!(&bp[..bn], forward);
            }
            loop {
                let live = [a_snapshots.borrow().clone(), b_snapshots.borrow().clone()]
                    .into_iter()
                    .all(|s| s.is_some_and(|s| s.liveness.last_pong_micros.is_some()));
                if live {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        })
        .await;
        let _ = a_stop.send(());
        let _ = b_stop.send(());
        result??;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    };
    let (a, b, result) = tokio::join!(a_run, b_run, exercise);
    if std::env::var_os("L2TUNNEL_MAINTAINED_TRACE").is_some() {
        for (role, snapshot) in [
            ("client", a_snapshots.borrow().clone()),
            ("server", b_snapshots.borrow().clone()),
        ] {
            if let Some(snapshot) = snapshot {
                eprintln!(
                    "MAINTAINED_LOOP_FINAL role={role} elapsed={} turns={} events={} records={} batch_limits={} timers={} sends={} control={} feedback={}",
                    snapshot.elapsed_micros,
                    snapshot.performance.loop_turns,
                    snapshot.performance.maintained_ready_events,
                    snapshot.performance.maintained_batch_records,
                    snapshot.performance.maintained_batch_limit_hits,
                    snapshot.performance.timer_events,
                    snapshot.performance.send_calls,
                    snapshot.performance.control_packets,
                    snapshot.performance.feedback_packets
                );
            }
        }
    }
    let stopped = |result: &io::Result<CommonStopped>| match result {
        Ok(value) => format!(
            "stop={:?}, elapsed={}, epoch={}, phase={:?}",
            value.reason,
            value.snapshot.elapsed_micros,
            value.snapshot.epoch.0,
            value.snapshot.phase
        ),
        Err(error) => format!("entry={error:?}"),
    };
    let observed = |snapshot: Option<&CommonSnapshot>| match snapshot {
        Some(snapshot) => format!(
            "elapsed={}, epoch={}, physical_epoch={}, phase={:?}, engine={:?}, control={:?}, counters={:?}, liveness={:?}",
            snapshot.elapsed_micros,
            snapshot.epoch.0,
            snapshot.physical_scope.epoch.0,
            snapshot.phase,
            snapshot.engine,
            snapshot.control,
            snapshot.counters,
            snapshot.liveness,
        ),
        None => "no native readiness observation".to_owned(),
    };
    if let Err(error) = result {
        return Err(format!(
            "maintained {kind:?} {duplex:?} exercise={error}; client {} [{}]; server {} [{}]",
            stopped(&a),
            observed(a_snapshots.borrow().as_ref()),
            stopped(&b),
            observed(b_snapshots.borrow().as_ref()),
        )
        .into());
    }
    if a.is_err() || b.is_err() {
        return Err(format!(
            "maintained {kind:?} {duplex:?} stage=runtime-terminal exercise=passed; client {} [{}]; server {} [{}]",
            stopped(&a),
            observed(a_snapshots.borrow().as_ref()),
            stopped(&b),
            observed(b_snapshots.borrow().as_ref()),
        )
        .into());
    }
    for (index, stopped) in [a?, b?].into_iter().enumerate() {
        assert_eq!(stopped.reason, StopReason::Cancelled);
        assert_eq!(stopped.snapshot.current, initial);
        assert_eq!(stopped.snapshot.info.binding, session);
        assert_eq!(stopped.snapshot.counters.native_written, 5);
        let expected = if index == 0 {
            endpoints
        } else {
            (endpoints.1, endpoints.0)
        };
        assert_eq!(
            (
                stopped.snapshot.info.local_addr,
                stopped.snapshot.info.peer_addr
            ),
            expected
        );
        assert_eq!(stopped.snapshot.counters.socket_accepted_packets, 0);
        assert_eq!(stopped.snapshot.counters.socket_accepted_ip_bytes, 0);
        assert!(stopped.snapshot.counters.maintained_accepted_records > 0);
        assert!(stopped.snapshot.counters.maintained_accepted_record_bytes > 0);
        assert!(
            stopped.snapshot.counters.maintained_accepted_charge_bytes
                > stopped.snapshot.counters.maintained_accepted_record_bytes
        );
        assert_eq!(stopped.snapshot.counters.socket_drops, 0);
        assert!(!stopped.snapshot.resource_preallocation_complete);
    }
    Ok(())
}

// Separate setup and runtime poll frames while retaining every actual owner.
#[inline(never)]
fn exercise(
    kind: maintained::Kind,
    duplex: core::Duplex,
    protection: security::compact::Protection,
) -> Pin<Box<dyn Future<Output = Result>>> {
    Box::pin(async move {
        let pair = establish_original_pair(kind, duplex, protection)
            .await
            .map_err(|error| {
                format!(
                    "maintained {kind:?} {duplex:?} {protection:?} stage=establishment: {error}"
                )
            })?;
        Box::pin(exercise_established(kind, duplex, pair)).await
    })
}
macro_rules! actual_case {
    ($name:ident, $kind:ident, $duplex:ident, $suite:ident) => {
        #[tokio::test]
        async fn $name() -> Result {
            exercise(
                maintained::Kind::$kind,
                core::Duplex::$duplex,
                security::compact::Protection::$suite,
            )
            .await
        }
    };
}
actual_case!(
    actual_tls_full_ccm_common_four_family_switching,
    TlsStream,
    Full,
    Aes128Ccm4
);
actual_case!(
    actual_tls_full_crc_common_four_family_switching,
    TlsStream,
    Full,
    ChaCha20Crc32c
);
actual_case!(
    actual_tls_half_ccm_common_four_family_switching,
    TlsStream,
    Half,
    Aes128Ccm4
);
actual_case!(
    actual_tls_half_crc_common_four_family_switching,
    TlsStream,
    Half,
    ChaCha20Crc32c
);
actual_case!(
    actual_quic_full_ccm_common_four_family_switching,
    QuicDatagram,
    Full,
    Aes128Ccm4
);
actual_case!(
    actual_quic_full_crc_common_four_family_switching,
    QuicDatagram,
    Full,
    ChaCha20Crc32c
);
actual_case!(
    actual_quic_half_ccm_common_four_family_switching,
    QuicDatagram,
    Half,
    Aes128Ccm4
);
actual_case!(
    actual_quic_half_crc_common_four_family_switching,
    QuicDatagram,
    Half,
    ChaCha20Crc32c
);

#[tokio::test]
async fn maintained_tls_half_cancellation_at_readiness_precedes_closed_peer_io() -> Result {
    let pair = establish_original_pair(
        maintained::Kind::TlsStream,
        core::Duplex::Half,
        security::compact::Protection::ChaCha20Crc32c,
    )
    .await?;
    let OriginalPair {
        client,
        server,
        client_contract,
        ..
    } = pair;
    let (native, _host) = device()?;
    let (cancel, cancelled) = oneshot::channel();
    let mut cancel = Some(cancel);
    let mut peer = Some(server);
    let stopped = run_common_on_maintained(
        native,
        client,
        client_contract,
        None,
        async {
            let _ = cancelled.await;
        },
        move |snapshot| {
            if snapshot.running {
                // Make peer closure and local cancellation ready at the same
                // boundary, before the first maintained work turn can poll I/O.
                drop(peer.take());
                if let Some(cancel) = cancel.take() {
                    let _ = cancel.send(());
                }
            }
        },
    )
    .await?;
    assert_eq!(stopped.reason, StopReason::Cancelled);
    assert_eq!(stopped.snapshot.counters.maintained_accepted_records, 0);
    assert_eq!(stopped.snapshot.counters.native_read, 0);
    assert_eq!(stopped.snapshot.counters.native_written, 0);
    Ok(())
}

async fn quic_terminal_close(already_observed: bool, cancel: bool) -> Result {
    let OriginalPair {
        client,
        server,
        client_contract,
        ..
    } = establish_original_pair(
        maintained::Kind::QuicDatagram,
        core::Duplex::Full,
        security::compact::Protection::ChaCha20Crc32c,
    )
    .await?;
    let deadline = client.deadline;
    let (mut socket, mut driver) = Driver::new_common_on_maintained(client, client_contract)?;
    let (native, _host) = device()?;
    let (stop, shutdown) = oneshot::channel();
    let mut stop = Some(stop);
    // Fix the causal order without a sleep: in the unobserved case local
    // cancellation is ready before the peer's background close arrives.
    if cancel && !already_observed {
        stop.take()
            .ok_or("QUIC cancellation sender lost")?
            .send(())
            .map_err(|_| "QUIC cancellation receiver lost")?;
    }
    drop(server);
    tokio::time::timeout_at(deadline, async {
        while socket.check_physical_failure().is_ok() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let original = if already_observed {
        // This is a real maintained poll, so its first error must survive both
        // a later cancellation and terminal re-observation of the same cause.
        socket.observe_completions().await;
        Some(
            socket
                .check_physical_failure()
                .err()
                .ok_or("QUIC close was not retained by its actual poll")?,
        )
    } else {
        None
    };
    if cancel && already_observed {
        stop.take()
            .ok_or("QUIC cancellation sender lost")?
            .send(())
            .map_err(|_| "QUIC cancellation receiver lost")?;
    }
    let result = run_driver_clock(
        native,
        socket,
        &mut driver,
        deadline,
        Requests::Common(None),
        async {
            let _ = shutdown.await;
        },
        |_, _, _| Ok(()),
        Instant::now,
    )
    .await;
    drop(stop);
    match original {
        None => assert_eq!(result?.reason, StopReason::Cancelled),
        Some(original) => {
            let error = result.err().ok_or("observed QUIC failure was suppressed")?;
            assert_eq!(error.kind(), original.kind());
            let cause = original
                .get_ref()
                .and_then(|value| value.downcast_ref::<crate::retained_tls::failure::Failure>())
                .ok_or("actual QUIC first-cause identity was not retained")?;
            assert!(cause.is_peer_close(&error));
        }
    }
    assert_eq!(driver.counters.maintained_accepted_records, 0);
    assert_eq!(driver.counters.native_read, 0);
    assert_eq!(driver.counters.native_written, 0);
    Ok(())
}

#[tokio::test]
async fn maintained_quic_cancellation_does_not_sample_later_background_close() -> Result {
    quic_terminal_close(false, true).await
}

#[tokio::test]
async fn maintained_quic_cancellation_preserves_already_observed_close() -> Result {
    quic_terminal_close(true, true).await
}

#[tokio::test]
async fn maintained_quic_terminal_settlement_preserves_original_error_identity() -> Result {
    quic_terminal_close(true, false).await
}
