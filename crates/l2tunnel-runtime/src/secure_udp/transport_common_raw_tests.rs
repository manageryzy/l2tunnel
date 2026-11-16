//! Real original raw TLS/member -> Noise/member -> sole Common Driver fixture.
//! PacketIo and Unix devices are finite caller-owned transports, not kernel/firewall evidence.
use super::*;
use l2tunnel_auth::{ClientTls, MemberAllowlist, MemberKey, ServerTls, SessionConfig};
use l2tunnel_raw_io::{
    PacketIo,
    handoff::{
        MessageLimits, SwitchLimits,
        pairing::{
            PairConfig, RawInput, RawInputs,
            packet::{self as packet, PacketCarrier, PacketPhaseConfig, PacketPolicy},
        },
    },
};
use std::{
    future::poll_fn,
    net::{Ipv4Addr, SocketAddrV4},
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use zeroize::Zeroizing;

#[derive(Default)]
struct Probe {
    sent: AtomicUsize,
    syns: AtomicUsize,
    dropped: AtomicUsize,
    blocked: AtomicBool,
}
struct PacketLink {
    incoming: mpsc::Receiver<Vec<u8>>,
    outgoing: mpsc::Sender<Vec<u8>>,
    probe: Arc<Probe>,
}
impl PacketIo for PacketLink {
    fn receive(&mut self, output: &mut [u8]) -> io::Result<Option<usize>> {
        match self.incoming.try_recv() {
            Ok(bytes) => {
                let target = output
                    .get_mut(..bytes.len())
                    .ok_or_else(|| invalid("actual raw fixture receive capacity"))?;
                target.copy_from_slice(&bytes);
                Ok(Some(bytes.len()))
            }
            Err(_) => Ok(None),
        }
    }
    fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.probe.blocked.load(Ordering::Relaxed) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.outgoing
            .try_send(bytes.to_vec())
            .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
        self.probe.sent.fetch_add(1, Ordering::Relaxed);
        if bytes.get(33).is_some_and(|flags| flags & 2 != 0) {
            self.probe.syns.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }
}
impl Drop for PacketLink {
    fn drop(&mut self) {
        self.probe.dropped.fetch_add(1, Ordering::Relaxed);
    }
}
fn originals(
    half: bool,
) -> (
    RawInputs<PacketLink>,
    RawInputs<PacketLink>,
    Vec<Arc<Probe>>,
) {
    let mut probes = Vec::new();
    let mut lane = |index: u16| {
        let client = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 11), 45001 + index * 2);
        let server = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 12), 45002 + index * 2);
        let (a_out, b_in) = mpsc::channel(256);
        let (b_out, a_in) = mpsc::channel(256);
        let a = Arc::new(Probe::default());
        let b = Arc::new(Probe::default());
        probes.extend([a.clone(), b.clone()]);
        let cfg = |local, peer, random_seed| l2tunnel_raw_tcp::Config {
            local,
            peer,
            mtu: 1500,
            send_bytes: 32768,
            receive_bytes: 32768,
            packet_slots: 16,
            random_seed,
            ack_delay_millis: 1,
            keepalive_millis: 1000,
            idle_timeout_millis: 30000,
        };
        (
            RawInput {
                config: cfg(client, server, 0x3131 + u64::from(index)),
                io: PacketLink {
                    incoming: a_in,
                    outgoing: a_out,
                    probe: a,
                },
            },
            RawInput {
                config: cfg(server, client, 0x4242 + u64::from(index)),
                io: PacketLink {
                    incoming: b_in,
                    outgoing: b_out,
                    probe: b,
                },
            },
        )
    };
    let (a, b) = lane(0);
    if half {
        let (c, d) = lane(1);
        (
            RawInputs::Half {
                forward: a,
                reverse: c,
            },
            RawInputs::Half {
                forward: b,
                reverse: d,
            },
            probes,
        )
    } else {
        (RawInputs::Full(a), RawInputs::Full(b), probes)
    }
}
fn requested(
    duplex: core::Duplex,
) -> Result<(
    [Config; 2],
    [cover::Config; 2],
    Catalog,
    TransactionSettings,
)> {
    let kind = cover::Appearance::QuicLike;
    let physical = PacketPolicy::new(1500).record_geometry()?.ip_bytes(1)? - 1;
    let mut resources = config(kind);
    resources.security.max_body_bytes = 1200;
    resources.control.wire_overhead = physical
        + record::ROUTE_BYTES
        + security::Protection::ChaCha20Poly1305.overhead_bytes()
        + 13;
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
                max_packet_bytes: 1348,
                max_protected_bytes: 1300,
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
                forward.recovery.outer_overhead_bytes = resources.control.wire_overhead;
                reverse.recovery.outer_overhead_bytes = resources.control.wire_overhead;
                c::Profile::Aligned { forward, reverse }
            }
            c::Profile::Packed {
                mut forward,
                mut reverse,
            } => {
                forward.base.recovery.outer_overhead_bytes = resources.control.wire_overhead;
                reverse.base.recovery.outer_overhead_bytes = resources.control.wire_overhead;
                c::Profile::Packed { forward, reverse }
            }
            c::Profile::Rolling { mut config, stream } => {
                config.native_stall_micros =
                    u64::try_from(resources.native.stall_timeout.as_micros())?;
                config.geometry = engine::Geometry {
                    forward_overhead_bytes: resources.control.wire_overhead,
                    reverse_overhead_bytes: resources.control.wire_overhead,
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
    outer: establish::raw_carrier::AuthenticatedRaw,
    contract: &CommonTransactionContract,
) -> Result<establish::Config> {
    let (client, server) = outer.lane_endpoints()[0].ok_or("actual first original tuple")?;
    let mut gate = l2tunnel_udp_control::Config::new(
        l2tunnel_udp_control::Path { client, server },
        [30; 32],
        1,
    )?;
    gate.path_mtu = outer.geometry().path_mtu;
    gate.outer_overhead = contract.physical_overhead_bytes()? + 1 + 30;
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
fn membership<I: PacketIo + Send + 'static>(
    e: &establish::raw_carrier::RawInitialEstablished<I>,
) -> member::Settings {
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

#[tokio::test]
async fn genuine_original_raw_common_loop_keeps_authentication_native_and_four_family_switching()
-> Result {
    exercise_original_raw(false).await
}

#[tokio::test]
async fn genuine_paired_half_raw_common_keeps_both_original_lanes_and_four_family_switching()
-> Result {
    exercise_original_raw(true).await
}

struct OriginalPair {
    client: member::raw_carrier::RawInitialParts<PacketLink>,
    server: member::raw_carrier::RawInitialParts<PacketLink>,
    client_contract: CommonTransactionContract,
    server_contract: CommonTransactionContract,
    catalog: Catalog,
    probes: Vec<Arc<Probe>>,
    endpoints: (std::net::SocketAddr, std::net::SocketAddr),
}

// Complete both real setup state machines before constructing either Driver.
// Keeping their poll temporaries in a separate future reflects the actual
// setup-to-runtime handoff and leaves the test's default thread stack unchanged.
async fn establish_original_pair(half: bool) -> Result<OriginalPair> {
    let duplex = if half {
        core::Duplex::Half
    } else {
        core::Duplex::Full
    };
    let (resources, covers, catalog, settings) = requested(duplex)?;
    let base = security::ConfigDigest([3; 32]);
    let envelope = c::EnvelopeDigest::new([0x39; 32]);
    let requested = CommonTransactionContract::raw_requested_configuration(
        base, envelope, &catalog, resources, covers, settings,
    )?;
    let certificate = rcgen::generate_simple_self_signed(vec!["raw-common.test".to_owned()])?;
    let roots = vec![certificate.cert.der().to_vec()];
    let tls_client = ClientTls::from_der_roots(&roots)?;
    let tls_server = ServerTls::from_der(&roots, &certificate.signing_key.serialize_der())?;
    let key_bytes = MemberKey::generate_pkcs8()?;
    let outer_member = MemberKey::from_pkcs8(&key_bytes)?;
    let inner_member = l2tunnel_identity::IdentityKey::from_pkcs8(&key_bytes)?;
    let allowed = MemberAllowlist::new(&[outer_member.public_key()])?;
    let inner_allowed = l2tunnel_identity::Allowlist::new(&[inner_member.public_key()])?;
    let phase = PacketPhaseConfig {
        pair: PairConfig {
            session: SessionConfig {
                layer: PacketLayer::Ethernet,
                digest: requested,
            },
            messages: MessageLimits::default(),
            driver: SwitchLimits::default(),
            timeout: Duration::from_secs(10),
        },
        packet: PacketPolicy::new(1500),
    };
    let (a, b, probes) = originals(half);
    let mut a =
        packet::begin_packet_client(a, &tls_client, "raw-common.test", &outer_member, phase)?;
    let mut b = packet::begin_packet_server(b, &tls_server, &allowed, phase)?;
    let (mut ar, mut br) = (None, None);
    poll_fn(|cx| {
        for (setup, owner) in [(&mut a, &mut ar), (&mut b, &mut br)] {
            if let Some(carrier) = owner {
                if let std::task::Poll::Ready(Err(error)) =
                    PacketCarrier::poll_progress(carrier, cx)
                {
                    return std::task::Poll::Ready(Err(error));
                }
            } else if let std::task::Poll::Ready(result) = Pin::new(setup).poll(cx) {
                *owner = Some(result?);
            }
        }
        if ar.is_some() && br.is_some() {
            std::task::Poll::Ready(Ok(()))
        } else {
            std::task::Poll::Pending
        }
    })
    .await?;
    let a = establish::raw_carrier::RawOuter::from_packet(ar.ok_or("actual client raw owner")?)?;
    let b = establish::raw_carrier::RawOuter::from_packet(br.ok_or("actual server raw owner")?)?;
    assert_eq!(a.authenticated().binding(), b.authenticated().binding());
    assert_eq!(a.authenticated().duplex(), duplex);
    assert_eq!(b.authenticated().duplex(), duplex);
    let lanes = if half { 2 } else { 1 };
    assert_eq!(
        a.authenticated().lane_infos().iter().flatten().count(),
        lanes
    );
    assert_eq!(
        b.authenticated().lane_infos().iter().flatten().count(),
        lanes
    );
    let original_endpoints = a.authenticated().lane_endpoints();
    assert_eq!(original_endpoints, b.authenticated().lane_endpoints());
    if half {
        assert_ne!(original_endpoints[0], original_endpoints[1]);
    }
    let endpoints = a.authenticated().lane_endpoints()[0].ok_or("original tuple")?;
    let a_contract = CommonTransactionContract::new_on_raw_paired(
        base,
        security::Role::Initiator,
        resources,
        covers,
        envelope,
        catalog.clone(),
        settings,
        a.authenticated(),
    )?;
    let b_contract = CommonTransactionContract::new_on_raw_paired(
        base,
        security::Role::Responder,
        resources,
        covers,
        envelope,
        catalog.clone(),
        settings,
        b.authenticated(),
    )?;
    assert_eq!(
        a_contract.expected_configuration(),
        b_contract.expected_configuration()
    );
    assert_ne!(a_contract.envelope(), envelope);
    assert!(a_contract.refresh_selection().is_none());
    let mut wrong = resources;
    wrong[1].work.send_batch += 1;
    assert!(
        CommonTransactionContract::new_on_raw_paired(
            base,
            security::Role::Initiator,
            wrong,
            covers,
            envelope,
            catalog.clone(),
            settings,
            a.authenticated()
        )
        .is_err()
    );
    let a_config = setup(a.authenticated(), &a_contract)?;
    let b_config = setup(b.authenticated(), &b_contract)?;
    let local = hs::LocalSecret::new(Zeroizing::new([11; 32]));
    let remote = hs::LocalSecret::new(Zeroizing::new([22; 32]));
    let peers = establish::Peers {
        initiator: local.public_key(),
        responder: remote.public_key(),
    };
    let mut admission = establish::raw_carrier::RawInitialServerAdmission::new(
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
            &mut a_noop
        ),
        b.accept_initial(
            establish::Identity {
                local: remote,
                peer: peers.initiator,
                psk: None
            },
            &mut admission,
            &mut b_entropy,
            &mut b_noop
        )
    )?;
    assert_eq!(
        a.authenticated().configuration,
        a_contract.expected_configuration().0
    );
    let a_settings = membership(&a);
    let b_settings = membership(&b);
    let (a, b) = tokio::try_join!(
        member::raw_carrier::connect_initial(a, &inner_member, a_settings, &mut a_noop),
        member::raw_carrier::accept_initial(b, inner_allowed, b_settings, &mut b_noop)
    )?;
    let a = a.into_parts();
    let b = b.into_parts();
    assert_eq!(a.info().member, inner_member.public_key());
    assert_eq!(b.info().member, inner_member.public_key());
    Ok(OriginalPair {
        client: a,
        server: b,
        client_contract: a_contract,
        server_contract: b_contract,
        catalog,
        probes,
        endpoints,
    })
}

async fn exercise_original_raw(half: bool) -> Result {
    let OriginalPair {
        client: a,
        server: b,
        client_contract: a_contract,
        server_contract: b_contract,
        catalog,
        probes,
        endpoints,
    } = Box::pin(establish_original_pair(half)).await?;
    let cap = a.deadline().min(b.deadline());
    let session = a.info().binding;
    let original_syns: Vec<_> = probes
        .iter()
        .map(|p| p.syns.load(Ordering::Relaxed))
        .collect();
    let original_sent: Vec<_> = probes
        .iter()
        .map(|p| p.sent.load(Ordering::Relaxed))
        .collect();
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
    let a_run = run_common_on_raw(
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
    let b_run = run_common_on_raw(
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
    if let Err(error) = result {
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
        return Err(format!(
            "raw half={half} exercise={error}; client {} [{}]; server {} [{}]",
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
        assert!(stopped.snapshot.counters.socket_accepted_packets > 0);
        assert_eq!(stopped.snapshot.counters.socket_drops, 0);
        assert!(!stopped.snapshot.resource_preallocation_complete);
    }
    for (index, probe) in probes.iter().enumerate() {
        assert_eq!(probe.syns.load(Ordering::Relaxed), original_syns[index]);
        assert!(probe.sent.load(Ordering::Relaxed) > original_sent[index]);
        assert_eq!(probe.dropped.load(Ordering::Relaxed), 1);
    }
    Ok(())
}
