//! Actual shared service, original authenticated UDP and three real record owners.
//! UnixDatagram packet devices are unprivileged functional witnesses, not TAP or
//! native-platform/performance qualification. Full SW-11/fault/resource gates stay open.

use super::*;
#[path = "proxy_common.rs"]
mod proxy_common;
use crate::secure_udp::common_transaction_profile;
use l2tunnel::{
    aligned, codec::aligned_body, pipeline as l2tunnel_pipeline, record_configuration as common,
};
use l2tunnel_core::traffic;
use l2tunnel_management::Role as DataRole;

pub(in super::super) fn common_direction(
    channels: u16,
    native: usize,
    rate: u64,
) -> Result<common::CommonDirection> {
    let queue = l2tunnel_pipeline::QueueLimits {
        bytes: 65_536,
        packets: 8,
    };
    Ok(common::CommonDirection::new(
        traffic::TrafficPolicy {
            layer: traffic::NetworkLayer::Tun,
            tcp: traffic::TcpControl::System,
            qos: traffic::Qos::WeightedDeficit,
        },
        l2tunnel_pipeline::PipelineConfig {
            profile: l2tunnel_pipeline::Profile::TunDrr(l2tunnel_pipeline::TunQosConfig {
                base_quantum_bytes: native as u32,
                max_weight: 1,
                per_flow: queue,
            }),
            flows: l2tunnel_pipeline::FlowTableConfig {
                capacity: 8,
                channels,
                mapping: l2tunnel_pipeline::Mapping::Crc32,
                idle_timeout: Duration::from_secs(5),
            },
            parse: l2tunnel_pipeline::ParseLimits {
                max_packet_bytes: native,
                ..l2tunnel_pipeline::ParseLimits::default()
            },
            queue,
        },
        rate,
        65_536,
        common::NativeWindow::Disabled,
    )?)
}
fn aligned_direction(
    native: usize,
    channels: u16,
    overhead: usize,
    packed: bool,
) -> aligned::Config {
    let symbol = if packed { 320 } else { 256 };
    let original = if packed {
        56 + 8 * 3 + symbol
    } else {
        48 + symbol
    };
    let wrapped = 44 + original;
    let fec_packet = 56 + 2 + 2 + wrapped;
    aligned::Config {
        native_policy: aligned::NativePolicy::RawIp,
        receiver: l2tunnel_codec::aligned_receiver::Limits {
            body: aligned_body::Config {
                max_frame_bytes: native,
                symbol_bytes: symbol,
                elide_payload_length: false,
                predictive: false,
                timestamp_pair_dictionary: false,
                independent_short_frame_bytes: 0,
            },
            channels,
            first_record: l2tunnel_codec::aligned_receiver::RecordId(0),
            first_source: l2tunnel_codec::aligned_receiver::SourceId(0),
            record_window: 32,
            source_window: 32,
            lookahead_records: 4,
            lookahead_bytes: 4 * 65_535,
            lookahead_fragments: 64,
            max_fragments_per_record: 16,
            lifetime_ticks: 5000,
        },
        recovery: l2tunnel_reliable::ReliableConfig {
            arq: l2tunnel_recovery::ArqConfig {
                max_source_bytes: original,
                send_bytes: 8 * original,
                receive_bytes: 8 * original,
                send_records: 8,
                receive_records: 8,
                initial_rto: Duration::from_millis(10),
                maximum_rto: Duration::from_millis(100),
                ack_delay: Duration::from_millis(1),
                max_retries: 2,
            },
            fec: l2tunnel_fec::DecoderConfig {
                block: l2tunnel_fec::BlockConfig {
                    max_sources: 2,
                    max_source_bytes: wrapped,
                    max_packet_bytes: fec_packet,
                    max_work_per_symbol: 1_000_000,
                },
                max_generations: 4,
                max_symbols_per_generation: 3,
                max_reserved_bytes: 1_000_000,
                max_lifetime_ticks: 50,
                generation_window: 32,
            },
            repair_symbols: 1,
            flush_after: Duration::from_millis(1),
            max_restored_packets: 16,
            max_restored_bytes: 16 * wrapped,
            outer_overhead_bytes: overhead,
        },
        max_recovery_packet_bytes: 8 + fec_packet,
    }
}
struct CommonPlans {
    plans: [Prepared; 2],
    addresses: [std::net::SocketAddr; 2],
    profile: common_transaction_profile::Profile,
    configurations: [common::Configuration; 3],
    outside: common::Configuration,
}
fn common_plans(
    appearance: l2tunnel_cover::Appearance,
    hosts: &[Arc<Host>; 2],
) -> Result<CommonPlans> {
    let TransactionPlans {
        plans,
        addresses,
        profile: old,
        initial: swift,
        ..
    } = transaction_plans(appearance, hosts)?;
    let mut initiator = old.runtime_contract(Role::Initiator)?.resources();
    let mut responder = old.runtime_contract(Role::Responder)?.resources();
    // Fixed immutable shared-resource templates; Common C below supplies actual data policy.
    initiator.report_interval = Some(Duration::from_millis(1));
    responder.report_interval = initiator.report_interval;
    let common::Profile::Swift { forward, reverse } = swift.descriptor().profile() else {
        return Err("fixture initial profile is not Swift".into());
    };
    let rates = [
        swift
            .descriptor()
            .direction(DataRole::Client)
            .common()
            .bytes_per_second(),
        swift
            .descriptor()
            .direction(DataRole::Server)
            .common()
            .bytes_per_second(),
    ];
    let native = old.connection().max_packet;
    let descriptor = |profile, widths: [u16; 2]| -> Result<common::Descriptor> {
        Ok(common::Descriptor::new(
            1500,
            Duplex::Full,
            common_direction(widths[0], native, rates[0])?,
            common_direction(widths[1], native, rates[1])?,
            profile,
        )?)
    };
    let initial = descriptor(
        common::Profile::Swift {
            forward: *forward,
            reverse: *reverse,
        },
        [forward.channels as u16, reverse.channels as u16],
    )?;
    let aligned = descriptor(
        common::Profile::Aligned {
            forward: aligned_direction(native, 3, initiator.control.wire_overhead, false),
            reverse: aligned_direction(native, 2, responder.control.wire_overhead, false),
        },
        [3, 2],
    )?;
    let packed = descriptor(
        common::Profile::Packed {
            forward: aligned::packed::Config {
                base: aligned_direction(native, 4, initiator.control.wire_overhead, true),
                hold_micros: 503,
                max_units: 3,
                work_limit: 3,
            },
            reverse: aligned::packed::Config {
                base: aligned_direction(native, 1, responder.control.wire_overhead, true),
                hold_micros: 701,
                max_units: 3,
                work_limit: 3,
            },
        },
        [4, 1],
    )?;
    let mut parameters = old.parameters();
    parameters.retained_bytes = 64 * 1024 * 1024;
    let profile = common_transaction_profile::Profile::new(
        old.connection(),
        old.settings(),
        old.peers(),
        initiator,
        responder,
        common::Catalog::new(initial, &[initial, aligned, packed])?,
        parameters,
    )?;
    let configurations = [
        profile.initial(),
        common::Configuration::new(
            profile.envelope(),
            *profile
                .catalog()
                .descriptors()
                .iter()
                .find(|descriptor| matches!(descriptor.profile(), common::Profile::Aligned { .. }))
                .ok_or("missing rebased Aligned descriptor")?,
        )?,
        common::Configuration::new(
            profile.envelope(),
            *profile
                .catalog()
                .descriptors()
                .iter()
                .find(|descriptor| matches!(descriptor.profile(), common::Profile::Packed { .. }))
                .ok_or("missing rebased Packed descriptor")?,
        )?,
    ];
    let unlisted = common::Descriptor::new(
        1500,
        Duplex::Full,
        common_direction(forward.channels as u16, native, rates[0] + 1)?,
        common_direction(reverse.channels as u16, native, rates[1])?,
        *initial.profile(),
    )?;
    let outside = common::Configuration::new(profile.envelope(), unlisted)?;
    let [client, server] = plans;
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
                    "authentication must not have begun"
                );
                Ok(Prepared::secure_udp_common_server(
                    profile.clone(),
                    credentials,
                    attachment,
                )?)
            }
            _ => Err("unexpected unstarted credential type".into()),
        }
    };
    let plans = [convert(client)?, convert(server)?];
    assert!(
        hosts
            .iter()
            .all(|host| host.opened.load(Ordering::SeqCst) == 0)
    );
    Ok(CommonPlans {
        plans,
        addresses,
        profile,
        configurations,
        outside,
    })
}

#[tokio::test]
async fn rejected_socket_protection_precedes_connect_authentication_and_native_open() -> Result {
    let hosts = support::hosts();
    let CommonPlans {
        plans: [take, _],
        addresses,
        ..
    } = common_plans(support::appearances()[0], &hosts)?;
    let peer = std::net::UdpSocket::bind(addresses[1])?;
    peer.set_nonblocking(true)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let plan = take.with_udp_socket_protector(move |socket| {
        assert_eq!(socket.local_addr().ok(), Some(addresses[0]));
        assert!(socket.peer_addr().is_err());
        observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::future::ready(Err(io::ErrorKind::PermissionDenied.into()))
    })?;
    let (handle, owner) = channel();
    let task = tokio::spawn(owner);
    let accepted = handle
        .connect(plan, handle.next_key().map_err(submit)?)
        .map_err(submit)?;
    let completed = timeout(Duration::from_secs(3), handle.wait(accepted.operation))
        .await?
        .map_err(submit)?;
    assert_eq!(
        completed,
        Completed::Failed(Failure {
            kind: io::ErrorKind::PermissionDenied
        })
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        peer.recv_from(&mut [0]).err().map(|err| err.kind()),
        Some(io::ErrorKind::WouldBlock)
    );
    support::assert_unopened(&hosts);
    task.abort();
    Ok(())
}
fn common_frame(handle: &Handle) -> Result<SecureUdpCommonFrame> {
    handle
        .snapshot()
        .runtime
        .as_ref()
        .and_then(Observation::secure_udp_common)
        .cloned()
        .ok_or_else(|| "missing actual Common service frame".into())
}
fn assert_common(
    frame: &SecureUdpCommonFrame,
    expected: common::Configuration,
    epoch: u64,
    original: &SecureUdpCommonFrame,
    generation: OperationId,
) -> Result {
    let actual = frame
        .runtime
        .as_ref()
        .ok_or("missing actual Common runtime observation")?;
    assert_eq!(frame.generation, generation.value());
    assert_eq!(frame.info, original.info);
    assert_eq!(actual.info, original.info);
    assert_eq!(frame.service_terminal, None);
    assert!(actual.running && actual.terminal.is_none());
    assert_eq!(actual.current, expected);
    assert_eq!(actual.epoch.0, epoch);
    assert_eq!(actual.physical_scope.epoch.0, epoch);
    assert_eq!(actual.physical_scope.configuration.0, expected.digest()?.0);
    assert_eq!(actual.phase, transaction::Phase::Idle);
    assert!(actual.operation.is_none() && actual.requested.is_none());
    assert_eq!(
        actual.configuration,
        original
            .runtime
            .as_ref()
            .ok_or("missing original Common runtime")?
            .configuration
    );
    let role = if frame.info.role == Role::Initiator {
        DataRole::Client
    } else {
        DataRole::Server
    };
    let local = expected.descriptor().local(role);
    assert_eq!(actual.send_channels, local.send().channels());
    assert_eq!(actual.receive_channels, local.receive().channels());
    assert!(!actual.resource_preallocation_complete);
    Ok(())
}
async fn await_common(
    handle: &Handle,
    expected: common::Configuration,
    epoch: u64,
    minimum_native: u64,
    after_pong: Option<u64>,
) -> Result<SecureUdpCommonFrame> {
    let mut changed = handle.subscribe();
    timeout(Duration::from_secs(4), async {
        loop {
            let frame = common_frame(handle)?;
            if frame.runtime.as_ref().is_some_and(|actual| {
                actual.running
                    && actual.current == expected
                    && actual.epoch.0 == epoch
                    && actual.phase == transaction::Phase::Idle
                    && actual.operation.is_none()
                    && actual.counters.native_written >= minimum_native
                    && actual
                        .liveness
                        .last_pong_micros
                        .is_some_and(|pong| after_pong.is_none_or(|before| pong > before))
            }) {
                return Ok::<_, Error>(frame);
            }
            changed.changed().await?;
        }
    })
    .await?
}
async fn exchange_stage(
    hosts: &[Arc<Host>; 2],
    handles: &[Handle; 2],
    expected: common::Configuration,
    epoch: u64,
    stage: u8,
) -> Result {
    let before = [
        common_frame(&handles[0])?
            .runtime
            .ok_or("missing client runtime")?
            .counters
            .native_written,
        common_frame(&handles[1])?
            .runtime
            .ok_or("missing server runtime")?
            .counters
            .native_written,
    ];
    let pongs = [
        common_frame(&handles[0])?
            .runtime
            .ok_or("missing client liveness")?
            .liveness
            .last_pong_micros,
        common_frame(&handles[1])?
            .runtime
            .ok_or("missing server liveness")?
            .liveness
            .last_pong_micros,
    ];
    let mut forward = packet(31 + stage * 8, 512 + usize::from(stage) * 17);
    let mut reverse = packet(35 + stage * 8, 389 + usize::from(stage) * 23);
    // Reuse the original opaque fixture while supplying valid UDP lengths to
    // the actual common Pipeline's stricter structural classifier.
    let forward_udp = u16::try_from(forward.len() - 20)?;
    let reverse_udp = u16::try_from(reverse.len() - 20)?;
    forward[24..26].copy_from_slice(&forward_udp.to_be_bytes());
    reverse[24..26].copy_from_slice(&reverse_udp.to_be_bytes());
    if expected
        .descriptor()
        .direction(DataRole::Client)
        .common()
        .traffic()
        .layer
        == traffic::NetworkLayer::Tap
    {
        let wrap = |packet: Vec<u8>| {
            let mut frame = vec![2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 8, 0];
            frame.extend_from_slice(&packet);
            frame
        };
        forward = wrap(forward);
        reverse = wrap(reverse);
    }
    assert!(forward.iter().any(|byte| *byte != 0) && reverse.iter().any(|byte| *byte != 0));
    hosts[0].send(&forward)?;
    hosts[1].send(&reverse)?;
    tokio::try_join!(hosts[1].expect(&forward), hosts[0].expect(&reverse))?;
    tokio::try_join!(
        await_common(&handles[0], expected, epoch, before[0] + 1, pongs[0]),
        await_common(&handles[1], expected, epoch, before[1] + 1, pongs[1])
    )?;
    Ok(())
}

#[tokio::test]
async fn actual_common_service_switches_swift_aligned_packed_swift_on_original_authenticated_udp()
-> Result {
    timeout(Duration::from_secs(30), Box::pin(async {
    for appearance in support::appearances() {
        let hosts = support::hosts();
        let CommonPlans { plans: [client_plan, server_plan], addresses, profile, configurations, outside } = common_plans(appearance, &hosts)?;
        let (client, client_run) = channel(); let (server, server_run) = channel();
        let client_task = tokio::spawn(client_run); let server_task = tokio::spawn(server_run);
        let accepted = [client.connect(client_plan, client.next_key().map_err(submit)?).map_err(submit)?,
            server.connect(server_plan, server.next_key().map_err(submit)?).map_err(submit)?];
        let (a, b) = tokio::try_join!(connected(&client, accepted[0]), connected(&server, accepted[1]))?;
        let generations = [a, b]; let handles = [client, server];
        let originals = [common_frame(&handles[0])?, common_frame(&handles[1])?];
        let first_epoch = originals[0].runtime.as_ref().ok_or("missing initial Common epoch")?.epoch.0;
        let setup = [support::observation(&handles[0], a)?, support::observation(&handles[1], b)?];
        assert_eq!(originals[0].info.binding, originals[1].info.binding);
        assert_eq!(originals[0].info.authenticated.configuration, profile.configuration()?.0);
        assert_eq!(originals[0].requested.initial(), configurations[0]);
        for side in 0..2 {
            assert_eq!(originals[side].info.local_addr, addresses[side]);
            assert_eq!(originals[side].info.peer_addr, addresses[1 - side]);
            assert_eq!(setup[side].original_timeout_micros, 3_000_000);
            assert_common(&originals[side], configurations[0], first_epoch, &originals[side], generations[side])?;
        }
        exchange_stage(&hosts, &handles, configurations[0], first_epoch, 0).await?;
        let key = handles[0].next_key().map_err(submit)?;
        assert_eq!(handles[0].apply_common(outside, key), Err(SubmitError::InvalidConfiguration));
        assert_eq!(handles[0].next_key().map_err(submit)?, key);
        assert_eq!(common_frame(&handles[0])?.runtime.ok_or("missing initial runtime")?.current, configurations[0]);
        for (stage, target) in [configurations[1], configurations[2], configurations[0]].into_iter().enumerate() {
            let key = handles[0].next_key().map_err(submit)?;
            let mut changed = handles[0].subscribe();
            let accepted = handles[0].apply_common(target, key).map_err(submit)?;
            assert_eq!(handles[0].apply_common(target, key).map_err(submit)?, accepted);
            let conflict = if target == configurations[0] { configurations[1] } else { configurations[0] };
            assert_eq!(handles[0].apply_common(conflict, key), Err(SubmitError::Conflict));
            let mut original_operation = None;
            let completed = timeout(Duration::from_secs(4), async {
                let waiting = handles[0].wait(accepted.operation); tokio::pin!(waiting);
                loop {
                    let frame = common_frame(&handles[0])?;
                    if let Some(operation) = frame.runtime.as_ref().and_then(|actual| actual.operation) {
                        if let Some(original) = original_operation { assert_eq!(operation, original); }
                        else { original_operation = Some(operation); }
                        assert_eq!(operation.origin().epoch.0, first_epoch + stage as u64);
                    }
                    tokio::select! {
                        biased;
                        result = &mut waiting => return result.map_err(submit).map_err(Into::<Error>::into),
                        updated = changed.changed() => { updated?; },
                    }
                }
            }).await??;
            let epoch = first_epoch + stage as u64 + 1;
            assert_eq!(completed, Completed::Common { configuration: target, outcome: Ok(l2tunnel_core::Epoch(epoch)) });
            // Read immediately after completion: a later periodic report must not repair its truth.
            assert_eq!(handles[0].snapshot().phase, Phase::Connected);
            assert!(handles[0].snapshot().operation.is_none());
            assert_eq!(handles[0].snapshot().generation, Some(a));
            assert_common(&common_frame(&handles[0])?, target, epoch, &originals[0], a)?;
            let follower = await_common(&handles[1], target, epoch, 0, None).await?;
            assert_common(&follower, target, epoch, &originals[1], b)?;
            if let Some(operation) = original_operation {
                let final_frame = common_frame(&handles[0])?;
                let final_at = final_frame.runtime.as_ref().ok_or("missing completed Common runtime")?.elapsed_micros / 1000;
                assert!(final_at < operation.expires().0);
                assert_eq!(operation.ticket().digest, target.digest()?);
                assert_eq!(operation.ticket().epoch.0, epoch);
            }
            assert_eq!(handles[0].apply_common(target, key).map_err(submit)?, accepted);
            assert_eq!(handles[0].wait(accepted.operation).await.map_err(submit)?, completed);
            exchange_stage(&hosts, &handles, target, epoch, stage as u8 + 1).await?;
            for side in 0..2 {
                assert_eq!(support::observation(&handles[side], generations[side])?, setup[side]);
                assert_eq!(hosts[side].opened.load(Ordering::SeqCst), 1);
                assert_eq!(hosts[side].live.load(Ordering::SeqCst), 1);
                assert_no_native_replay(&hosts[side])?;
            }
        }
        let stopped = [handles[0].disconnect(handles[0].next_key().map_err(submit)?).map_err(submit)?,
            handles[1].disconnect(handles[1].next_key().map_err(submit)?).map_err(submit)?];
        let (left, right) = timeout(Duration::from_secs(4), async {
            tokio::join!(handles[0].wait(stopped[0].operation), handles[1].wait(stopped[1].operation))
        }).await?;
        assert_eq!(left.map_err(submit)?, Completed::Aborted);
        assert_eq!(right.map_err(submit)?, Completed::Aborted);
        for side in 0..2 {
            assert_eq!(handles[side].wait_stopped(generations[side]).await.map_err(submit)?, Terminal::Aborted);
            let frame = common_frame(&handles[side])?;
            assert_eq!(frame.service_terminal, Some(Terminal::Aborted));
            assert_eq!(frame.info, originals[side].info);
            assert_eq!(hosts[side].live.load(Ordering::SeqCst), 0);
        }
        support::assert_ports_free(addresses)?;
        client_task.abort(); server_task.abort();
        let _ = client_task.await; let _ = server_task.await;
    }
    Ok::<(), Error>(())
    })).await?
}

#[path = "secure_udp_common_local.rs"]
mod local_api;

#[path = "secure_udp_common_carrier.rs"]
mod original_carrier;

#[path = "secure_udp_common_connections.rs"]
mod independent_connections;

#[path = "secure_udp_common_research.rs"]
mod research_common;

#[path = "secure_udp_common_wire.rs"]
mod compact_wire;

#[path = "secure_udp_common_maintained.rs"]
mod maintained_carrier;
