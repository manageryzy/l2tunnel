//! Genuine injected paired original raw Half service ownership, not kernel evidence.
use super::*;
use crate::raw_packet::common::{PacketOpener, Settings as RawSettings};
use l2tunnel_raw_io::{PacketIo, handoff::pairing::packet::PacketPolicy};
use std::sync::atomic::AtomicUsize;
use tokio::sync::mpsc;

#[derive(Default)]
struct Probe {
    opened: AtomicUsize,
    sent: AtomicUsize,
    syns: AtomicUsize,
    dropped: AtomicUsize,
    io_polls: AtomicUsize,
    blocked: std::sync::atomic::AtomicBool,
    blocked_attempts: AtomicUsize,
    held: std::sync::Mutex<Option<Vec<u8>>>,
}
struct Link {
    incoming: mpsc::Receiver<Vec<u8>>,
    outgoing: mpsc::Sender<Vec<u8>>,
    probe: Arc<Probe>,
}
impl PacketIo for Link {
    fn receive(&mut self, output: &mut [u8]) -> io::Result<Option<usize>> {
        self.probe.io_polls.fetch_add(1, Ordering::SeqCst);
        match self.incoming.try_recv() {
            Ok(bytes) => {
                output
                    .get_mut(..bytes.len())
                    .ok_or_else(|| io::Error::other("raw fixture input capacity"))?
                    .copy_from_slice(&bytes);
                Ok(Some(bytes.len()))
            }
            Err(_) => Ok(None),
        }
    }
    fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.probe.io_polls.fetch_add(1, Ordering::SeqCst);
        let mut held = self
            .probe
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(original) = held.as_ref() {
            assert_eq!(original.as_slice(), bytes);
        }
        if self.probe.blocked.load(Ordering::SeqCst) {
            if held.is_none() {
                *held = Some(bytes.to_vec());
            }
            self.probe.blocked_attempts.fetch_add(1, Ordering::SeqCst);
            return Err(io::ErrorKind::WouldBlock.into());
        }
        held.take();
        drop(held);
        self.outgoing
            .try_send(bytes.to_vec())
            .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
        self.probe.sent.fetch_add(1, Ordering::SeqCst);
        if bytes.get(33).is_some_and(|flags| flags & 2 != 0) {
            self.probe.syns.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }
}
impl Drop for Link {
    fn drop(&mut self) {
        self.probe.dropped.fetch_add(1, Ordering::SeqCst);
    }
}
fn next(address: std::net::SocketAddrV4) -> std::net::SocketAddrV4 {
    std::net::SocketAddrV4::new(
        *address.ip(),
        if address.port() == u16::MAX {
            address.port() - 1
        } else {
            address.port() + 1
        },
    )
}
fn carrier_settings(
    local: [std::net::SocketAddrV4; 2],
    peer: [std::net::SocketAddrV4; 2],
    policy: PacketPolicy,
) -> Result<RawSettings> {
    let packet = serde_json::json!({"mtu":policy.mtu,"protection":"aead","queue_packets":policy.queue_packets,
        "horizon_bytes":policy.horizon_bytes,"minimum_transfer_bytes":policy.minimum_transfer_bytes,
        "bytes_per_second":policy.bytes_per_second,"packets_per_second":policy.packets_per_second,
        "burst_bytes":policy.burst_bytes,"burst_packets":policy.burst_packets,
        "max_key_packets":policy.max_key_packets,"max_key_bytes":policy.max_key_bytes});
    Ok(RawSettings::from_json(&serde_json::to_vec(
        &serde_json::json!({"version":1,"profile":"raw-common-carrier-v1",
        "forward":{"local":local[0],"peer":peer[0]},"reverse":{"local":local[1],"peer":peer[1]},"packet":packet}),
    )?)?)
}
type RawOriginals = ([RawSettings; 2], [PacketOpener; 2], Vec<Arc<Probe>>);

fn raw_originals(
    addresses: [std::net::SocketAddr; 2],
    policy: PacketPolicy,
    rounds: usize,
) -> Result<RawOriginals> {
    let [std::net::SocketAddr::V4(a), std::net::SocketAddr::V4(b)] = addresses else {
        return Err("raw fixture IPv4 originals required".into());
    };
    let a = [a, next(a)];
    let b = [b, next(b)];
    let settings = [
        carrier_settings(a, b, policy)?,
        carrier_settings(b, a, policy)?,
    ];
    let mut left = Vec::new();
    let mut right = Vec::new();
    let mut probes = Vec::new();
    for _ in 0..rounds {
        for index in 0..2 {
            let (at, br) = mpsc::channel(256);
            let (bt, ar) = mpsc::channel(256);
            let ap = Arc::new(Probe::default());
            let bp = Arc::new(Probe::default());
            left.push((
                a[index],
                b[index],
                Some(Link {
                    incoming: ar,
                    outgoing: at,
                    probe: ap.clone(),
                }),
            ));
            right.push((
                b[index],
                a[index],
                Some(Link {
                    incoming: br,
                    outgoing: bt,
                    probe: bp.clone(),
                }),
            ));
            probes.extend([ap, bp]);
        }
    }
    type Originals = Vec<(std::net::SocketAddrV4, std::net::SocketAddrV4, Option<Link>)>;
    let opener = |lanes: Originals| {
        let lanes = std::sync::Mutex::new(lanes);
        PacketOpener::new(move |config: l2tunnel_raw_tcp::Config, _role| {
            let mut lanes = lanes
                .lock()
                .map_err(|_| io::Error::other("raw fixture lock"))?;
            let (_, _, slot) = lanes
                .iter_mut()
                .find(|(local, peer, slot)| {
                    *local == config.local && *peer == config.peer && slot.is_some()
                })
                .ok_or_else(|| io::Error::other("opener requested another original tuple"))?;
            let io = slot
                .take()
                .ok_or_else(|| io::Error::other("actual original reopened"))?;
            io.probe.opened.fetch_add(1, Ordering::SeqCst);
            Ok(io)
        })
    };
    Ok((settings, [opener(left), opener(right)], probes))
}
fn raw_descriptor(descriptor: common::Descriptor, delta: usize) -> Result<common::Descriptor> {
    let mut profile = *descriptor.profile();
    match &mut profile {
        common::Profile::Swift { .. } => {}
        common::Profile::Aligned { forward, reverse } => {
            forward.recovery.outer_overhead_bytes += delta;
            reverse.recovery.outer_overhead_bytes += delta;
        }
        common::Profile::Packed { forward, reverse } => {
            forward.base.recovery.outer_overhead_bytes += delta;
            reverse.base.recovery.outer_overhead_bytes += delta;
        }
        common::Profile::Rolling { config, .. } => {
            config.geometry.forward_overhead_bytes += delta;
            config.geometry.reverse_overhead_bytes += delta;
        }
        _ => return Err("raw four-family fixture unexpectedly changed profile".into()),
    }
    Ok(common::Descriptor::new(
        descriptor.path_mtu(),
        l2tunnel_core::Duplex::Half,
        *descriptor.direction(DataRole::Client).common(),
        *descriptor.direction(DataRole::Server).common(),
        profile,
    )?)
}
fn raw_plans(hosts: &[Arc<Host>; 2]) -> Result<(CarrierPlans, Vec<Arc<Probe>>)> {
    raw_plans_with_rounds(hosts, 1)
}
fn raw_plans_with_rounds(
    hosts: &[Arc<Host>; 2],
    rounds: usize,
) -> Result<(CarrierPlans, Vec<Arc<Probe>>)> {
    raw_plans_wire(hosts, rounds, None)
}
#[inline(never)]
fn raw_plans_wire(
    hosts: &[Arc<Host>; 2],
    rounds: usize,
    wire: Option<l2tunnel::secure_record::compact::Selection>,
) -> Result<(CarrierPlans, Vec<Arc<Probe>>)> {
    let original = carrier_plans(l2tunnel_cover::Appearance::QuicLike, hosts, false)?;
    raw_plans_from_carrier(original, hosts, rounds, wire)
}

// The original Common and OpenVPN fixtures have completed before this frame
// preflights raw geometry; all raw callers share this bounded constructor chain.
#[inline(never)]
fn raw_plans_from_carrier(
    original: CarrierPlans,
    hosts: &[Arc<Host>; 2],
    rounds: usize,
    wire: Option<l2tunnel::secure_record::compact::Selection>,
) -> Result<(CarrierPlans, Vec<Arc<Probe>>)> {
    // Transfer real unused outer TLS/inner credentials from the maintained helper.
    // No socket, authenticated metadata or root is fabricated/adopted here.
    let CarrierPlans {
        plans: [left, right],
        addresses,
        requested: original,
    } = original;
    let mut policy = PacketPolicy::new(1500);
    if wire.is_some() {
        // Exercise the requested native-matrix horizon through real bootstrap
        // and handoff, including the negotiated scaled advertisements.
        policy.horizon_bytes = 1_048_576;
    }
    let geometry = policy.record_geometry()?;
    let delta = geometry.ip_tcp_bytes + geometry.record_overhead_bytes - 28;
    let mut connection = original.connection();
    connection.duplex = l2tunnel_core::Duplex::Half;
    let mut settings = original.settings();
    settings.cover.max_packet_bytes = geometry.max_record_bytes;
    settings.cover.max_protected_bytes = 1300;
    // Explicit raw bootstrap geometry, as in the actual raw CLI derivation.
    // Its control envelope must fit the newly selected covered capacity too.
    settings.gate.arq.max_source_bytes = settings
        .cover
        .max_protected_bytes
        .checked_sub(
            l2tunnel_udp_control::CONTROL_OVERHEAD + l2tunnel_recovery::DATA_HEADER_BYTES + 1,
        )
        .ok_or("raw fixture bootstrap framing cannot fit")?
        .min(settings.gate.arq.max_source_bytes);
    let mut resources = [
        original.runtime_contract(Role::Initiator)?.resources(),
        original.runtime_contract(Role::Responder)?.resources(),
    ];
    for resource in &mut resources {
        // Explicit new raw fixture capacity; no production/canonical policy clamp.
        resource.security.max_body_bytes = 1200;
        resource.control.wire_overhead += delta;
        for stream in &mut resource
            .streams
            .as_mut()
            .ok_or("missing actual stream resources")?
            .streams
        {
            stream.delivery.wire_overhead += delta;
        }
    }
    let descriptors = original
        .catalog()
        .descriptors()
        .iter()
        .copied()
        .map(|d| raw_descriptor(d, delta))
        .collect::<Result<Vec<_>>>()?;
    let requested = common_transaction_profile::Profile::new_raw(
        connection,
        settings,
        original.peers(),
        resources[0],
        resources[1],
        common::Catalog::new(
            raw_descriptor(*original.initial().descriptor(), delta)?,
            &descriptors,
        )?,
        original.parameters(),
        policy,
    )?;
    let requested = match wire {
        Some(selection) => requested.with_compact_wire(selection)?,
        None => requested,
    };
    assert!(requested.raw_binding().is_none() && requested.carrier_binding().is_none());
    let ([a_settings, b_settings], [a_open, b_open], probes) =
        raw_originals(addresses, policy, rounds)?;
    let convert = |plan: Prepared, raw, opener| -> Result<Prepared> {
        let data = Arc::try_unwrap(plan.data).map_err(|_| "unused TLS credential owner shared")?;
        match data.endpoint {
            prepared::Endpoint::CommonCarrierClient { outer, inner } => {
                Ok(Prepared::secure_udp_common_raw_client(
                    requested.clone(),
                    raw,
                    outer,
                    inner,
                    opener,
                    data.attachment,
                )?)
            }
            prepared::Endpoint::CommonCarrierServer(server) => {
                let prepared::CommonCarrierServer {
                    outer,
                    inner,
                    admission,
                } = *server;
                assert!(admission.into_inner().is_none());
                Ok(Prepared::secure_udp_common_raw_server(
                    requested.clone(),
                    raw,
                    outer,
                    inner,
                    opener,
                    data.attachment,
                )?)
            }
            _ => Err("unexpected original carrier credential owner".into()),
        }
    };
    let plans = [
        convert(left, a_settings, a_open)?,
        convert(right, b_settings, b_open)?,
    ];
    assert!(probes.iter().all(|p| p.opened.load(Ordering::SeqCst) == 0));
    assert!(hosts.iter().all(|h| h.opened.load(Ordering::SeqCst) == 0));
    Ok((
        CarrierPlans {
            plans,
            addresses,
            requested,
        },
        probes,
    ))
}

#[tokio::test]
async fn actual_paired_raw_common_service_keeps_authenticated_catalog_native_switches_and_release()
-> Result {
    exercise_raw_wire(None).await
}

#[tokio::test]
async fn actual_compact_wire_paired_raw_service_preserves_switches_and_both_suites() -> Result {
    use l2tunnel::secure_record::compact::Selection;
    use l2tunnel_security::compact::Protection;
    for protection in [Protection::Aes128Ccm4, Protection::ChaCha20Crc32c] {
        exercise_raw_wire(Some(Selection {
            protection,
            limits: l2tunnel_security::compact::Selection {
                max_forward_packets: 8192,
                max_failed_checks: 64,
            },
        }))
        .await?;
    }
    Ok(())
}

// Keep the parameterized suite's large retained status fixture off its parent
// test future's stack. Runtime owners and default thread stacks stay unchanged.
#[inline(never)]
fn exercise_raw_wire(
    wire: Option<l2tunnel::secure_record::compact::Selection>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result>>> {
    Box::pin(async move {
        timeout(Duration::from_secs(30), async {
            let hosts = support::hosts();
            let (
                CarrierPlans {
                    plans: [a, b],
                    addresses,
                    requested,
                },
                probes,
            ) = raw_plans_wire(&hosts, 1, wire)?;
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
            )
            .map_err(|error| -> Error {
                format!(
                    "raw service connection failed: {error}; wire={wire:?}; client_setup={:?}; server_setup={:?}",
                    client.setup_observation(accepted[0].operation),
                    server.setup_observation(accepted[1].operation),
                )
                .into()
            })?;
            let handles = [client, server];
            let originals = [common_frame(&handles[0])?, common_frame(&handles[1])?];
            let effective = &originals[0].requested;
            let supported = effective.catalog().configurations(effective.envelope())?;
            assert_eq!(originals[0].info.binding, originals[1].info.binding);
            let syns: Vec<_> = probes
                .iter()
                .map(|p| p.syns.load(Ordering::SeqCst))
                .collect();
            let first_epoch = originals[0]
                .runtime
                .as_ref()
                .ok_or("actual raw runtime absent")?
                .epoch
                .0;
            for (side, generation) in [a, b].into_iter().enumerate() {
                let frame = &originals[side];
                let status = frame.status()?;
                let raw = status
                    .raw_carrier
                    .as_ref()
                    .ok_or("genuine raw status absent")?;
                let proof = frame
                    .requested
                    .raw_binding()
                    .ok_or("genuine raw binding absent")?;
                assert_eq!(status.carrier, "raw-packet");
                match status.compact_wire.as_ref() {
                    Some(actual) => {
                        assert_eq!(
                            actual.requested,
                            crate::secure_udp::common_status::CompactWireSelection::from_selection(
                                requested.compact_wire()
                            )?
                        );
                        assert_eq!(actual.effective.as_ref(), Some(&actual.requested));
                        let expected_data = requested.compact_wire().data_overhead() as u64;
                        assert_eq!(actual.effective_data_overhead_bytes, Some(expected_data));
                        let framing = raw
                            .final_framing
                            .as_ref()
                            .ok_or("actual activated raw framing absent")?;
                        assert_eq!(framing.ip_tcp_bytes, 40);
                        assert_eq!(framing.data_overhead_bytes, 40 + expected_data);
                        assert_eq!(framing.control_feedback_overhead_bytes, 61);
                        assert_eq!(framing.protection_layers, 1);
                        assert_eq!(frame.requested.catalog().root(), requested.catalog().root());
                        assert_eq!(
                            frame
                                .requested
                                .requested_resources(frame.info.role)
                                .control
                                .wire_overhead,
                            61
                        );
                    }
                    _ => return Err("raw compact requested/effective status absent".into()),
                }
                assert!(status.original_carrier.is_none());
                assert_eq!(raw.duplex, "half");
                let encoded = serde_json::to_value(&status)?;
                assert!(encoded["raw_carrier"].is_object());
                assert!(encoded.get("original_carrier").is_none());
                assert!(raw.lanes.iter().all(Option::is_some));
                assert_eq!(raw.requested_policy, raw.effective_policy);
                for (lane, limits) in raw.lanes.iter().zip(proof.lane_limits()) {
                    let lane = lane.as_ref().ok_or("actual raw lane")?;
                    let limits = limits.ok_or("actual raw lane limits")?;
                    assert_eq!(
                        lane.limits,
                        crate::secure_udp::common_status::RawLaneLimits::from(limits)
                    );
                    assert_eq!(lane.limits.data_reserve_bytes, 11_680);
                    assert_eq!(
                        lane.limits.send_data_capacity_bytes,
                        lane.limits.peer_horizon_bytes
                            .checked_sub(lane.limits.data_reserve_bytes)
                            .ok_or("peer horizon below Data reserve")?
                    );
                    assert_eq!(
                        lane.limits.receive_data_capacity_bytes,
                        lane.limits.local_horizon_bytes
                            .checked_sub(lane.limits.data_reserve_bytes)
                            .ok_or("local horizon below Data reserve")?
                    );
                    assert!(
                        lane.limits.peer_horizon_bytes
                            <= u64::from(raw.effective_policy.horizon_bytes)
                    );
                    assert!(
                        lane.limits.local_horizon_bytes
                            <= u64::from(raw.effective_policy.horizon_bytes)
                    );
                    if wire.is_some() {
                        // A genuine horizon larger than the unscaled wire field
                        // proves scaling survived the authenticated handoff.
                        // The last advertisement need not equal the policy cap.
                        assert!(lane.limits.local_horizon_bytes > u64::from(u16::MAX));
                        assert!(lane.limits.peer_horizon_bytes > u64::from(u16::MAX));
                    }
                }
                assert_eq!(
                    encoded["raw_carrier"]["lanes"][0]["limits"]["send_data_capacity_bytes"],
                    raw.lanes[0]
                        .as_ref()
                        .ok_or("first raw lane")?
                        .limits
                        .send_data_capacity_bytes
                );
                assert_eq!(raw.binding, proof.binding());
                assert_eq!(raw.policy_digest, proof.policy_digest());
                assert_eq!(raw.requested_configuration, requested.configuration()?.0);
                assert_eq!(raw.requested_envelope, *requested.envelope().as_bytes());
                assert_eq!(
                    raw.requested_catalog,
                    *requested.catalog().root().as_bytes()
                );
                assert_eq!(raw.effective_configuration, effective.configuration()?.0);
                assert_eq!(raw.effective_envelope, *effective.envelope().as_bytes());
                assert_eq!(
                    raw.effective_catalog,
                    *effective.catalog().root().as_bytes()
                );
                assert_ne!(raw.requested_configuration, raw.effective_configuration);
                assert_ne!(raw.requested_envelope, raw.effective_envelope);
                assert_eq!(frame.info.local_addr, addresses[side]);
                assert_eq!(frame.info.peer_addr, addresses[1 - side]);
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
                    support::observation(&handles[side], generation)?.original_timeout_micros,
                    3_000_000
                );
                assert_common(frame, effective.initial(), first_epoch, frame, generation)?;
            }
            exchange_stage(&hosts, &handles, effective.initial(), first_epoch, 0).await?;
            assert_eq!(
                handles[0]
                    .apply_common(requested.initial(), handles[0].next_key().map_err(submit)?),
                Err(SubmitError::InvalidConfiguration)
            );
            let family = |tag| {
                supported
                    .iter()
                    .copied()
                    .find(|value| match value.descriptor().profile() {
                        common::Profile::Aligned { .. } => tag == 1,
                        common::Profile::Packed { .. } => tag == 2,
                        common::Profile::Rolling { .. } => tag == 3,
                        _ => false,
                    })
                    .ok_or("actual raw supported family absent")
            };
            let order = [family(1)?, family(2)?, family(3)?, effective.initial()];
            for (index, target) in order.into_iter().enumerate() {
                let operation = handles[0]
                    .apply_common(target, handles[0].next_key().map_err(submit)?)
                    .map_err(submit)?;
                let epoch = first_epoch + index as u64 + 1;
                assert_eq!(
                    timeout(Duration::from_secs(4), handles[0].wait(operation.operation))
                        .await?
                        .map_err(submit)?,
                    Completed::Common {
                        configuration: target,
                        outcome: Ok(l2tunnel_core::Epoch(epoch))
                    }
                );
                await_common(&handles[1], target, epoch, 0, None).await?;
                exchange_stage(&hosts, &handles, target, epoch, index as u8 + 1).await?;
                for (side, generation) in [a, b].into_iter().enumerate() {
                    let frame = common_frame(&handles[side])?;
                    assert_common(&frame, target, epoch, &originals[side], generation)?;
                    let status = frame.status()?;
                    assert_eq!(
                        status
                            .raw_carrier
                            .as_ref()
                            .ok_or("raw status lost")?
                            .binding,
                        originals[side]
                            .requested
                            .raw_binding()
                            .ok_or("proof lost")?
                            .binding()
                    );
                    assert!(status.original_carrier.is_none());
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
                assert_eq!(hosts[side].opened.load(Ordering::SeqCst), 1);
            }
            for (index, probe) in probes.iter().enumerate() {
                assert_eq!(probe.opened.load(Ordering::SeqCst), 1);
                assert_eq!(probe.dropped.load(Ordering::SeqCst), 1);
                assert_eq!(probe.syns.load(Ordering::SeqCst), syns[index]);
                assert!(probe.sent.load(Ordering::SeqCst) > 0);
            }
            task.abort();
            peer_task.abort();
            let _ = task.await;
            let _ = peer_task.await;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        })
        .await?
    })
}

#[path = "secure_udp_common_raw_reconnect.rs"]
mod reconnect;

#[path = "secure_udp_common_raw_setup_cap.rs"]
mod setup_cap;

#[path = "secure_udp_common_raw_research.rs"]
mod research;

#[path = "proxy_common_raw.rs"]
mod proxy_common;
