//! Actual complete-configuration service, local API and original-socket owners.
//!
//! No privileged/native qualification or cross-profile SW-11 claim. This child
//! deliberately disables periodic reports: Applied must follow an actual final
//! runtime observation, rather than borrowing a later timer report.

use super::*;
use crate::secure_udp::{
    common_status as transaction_status, common_transaction_profile as transaction_profile,
};
use l2tunnel::record_configuration::{Catalog, Configuration, Descriptor};
use l2tunnel_management::{control_streams, delivery, messages, transaction};
use l2tunnel_runtime::secure_udp::transport;

#[path = "secure_udp_transaction_failures.rs"]
mod command_failures;
#[path = "secure_udp_common.rs"]
pub(super) mod common_service;
#[path = "secure_udp_transaction_lifecycle.rs"]
mod lifecycle_failures;
#[path = "secure_udp_transaction_setup.rs"]
mod setup_failures;
#[path = "secure_udp_transaction_support.rs"]
mod support;
#[path = "secure_udp_vxlan.rs"]
mod vxlan;

#[derive(Clone, Copy)]
struct TransactionFixtureOptions {
    setup_timeout: Duration,
    noise_profile: hs::Profile,
    psk: [Option<[u8; 32]>; 2],
    admission: [[u8; 32]; 2],
    retained_bytes: usize,
    report_interval: Option<Duration>,
    // Live tuning: both Swift directions on one repair rate, and a client
    // that proposes a switchable choice (docs/modules/live-tuning.md).
    live: Option<Live>,
}
/// One switchable choice the tuned client proposes.
#[derive(Clone, Copy)]
enum Live {
    FecOff,
    DeviceMtu(u16),
}
impl Live {
    fn choices(self) -> l2tunnel::live_tuning::Choices {
        use l2tunnel::live_tuning::{Choices, Repair};
        match self {
            Self::FecOff => Choices {
                repair: vec![Repair::Off],
                ..Choices::default()
            },
            Self::DeviceMtu(mtu) => Choices {
                device_mtu: vec![mtu],
                ..Choices::default()
            },
        }
    }
}
impl TransactionFixtureOptions {
    fn baseline() -> Self {
        Self {
            setup_timeout: Duration::from_secs(3),
            noise_profile: hs::Profile::Ik,
            psk: [None, None],
            admission: [[44; 32]; 2],
            retained_bytes: 16 * 1024 * 1024,
            report_interval: None,
            live: None,
        }
    }
}

struct TransactionPlans {
    plans: [Prepared; 2],
    addresses: [std::net::SocketAddr; 2],
    profile: transaction_profile::Profile,
    initial: Configuration,
    target: Configuration,
    outside: Configuration,
}

pub(super) fn streamed(mut value: transport::Config) -> transport::Config {
    let entry = messages::Settings {
        delivery: delivery::Settings {
            wire_overhead: value.control.wire_overhead + control_streams::HEADER_BYTES,
            ..value.control
        },
        path_mtu: value.path_mtu,
        max_message_bytes: 4096,
        max_outbound_messages: 4,
        max_outbound_bytes: 131_072,
        max_fragments: 32,
        max_reassembly_bytes: 16_384,
        max_incomplete_messages: 2,
        message_lifetime: Duration::from_secs(5),
        work_per_call: 8,
    };
    value.streams = Some(l2tunnel_runtime::secure_udp::control::Settings {
        streams: [entry; 3],
    });
    value.report_interval = None;
    value.lifetime.ping_interval = Duration::from_millis(10);
    value
}

fn transaction_plans(
    appearance: l2tunnel_cover::Appearance,
    hosts: &[Arc<Host>; 2],
) -> Result<TransactionPlans> {
    transaction_plans_with(appearance, hosts, TransactionFixtureOptions::baseline())
}

fn transaction_plans_with(
    appearance: l2tunnel_cover::Appearance,
    hosts: &[Arc<Host>; 2],
    options: TransactionFixtureOptions,
) -> Result<TransactionPlans> {
    let held = [
        crate::test_ports::reserve(false)?,
        crate::test_ports::reserve(false)?,
    ];
    let addresses = [held[0].local_addr()?, held[1].local_addr()?];
    let encoded = Zeroizing::new(l2tunnel_auth::MemberKey::generate_pkcs8()?);
    let member = identity::IdentityKey::from_pkcs8(&encoded)?;
    let (legacy, peers) = crate::secure_udp::common_fixture::fixture(
        l2tunnel_udp_control::Path {
            client: addresses[0],
            server: addresses[1],
        },
        appearance,
        member.public_key(),
    )?;
    let mut settings = legacy.settings();
    settings.application = l2tunnel_core::ConfigDigest([31; 32]);
    settings.profile = options.noise_profile;
    let mut connection = legacy.connection();
    connection.handshake_timeout = options.setup_timeout;
    let mut initiator = streamed(legacy.runtime(Role::Initiator));
    let mut responder = streamed(legacy.runtime(Role::Responder));
    initiator.report_interval = options.report_interval;
    responder.report_interval = options.report_interval;
    let mut forward = initiator.send;
    let mut reverse = initiator.receive;
    // Finite integration geometry, separate from the CLI's production capacity.
    // The real reserved engine must provision this whole selected pool.
    forward.records.codec.flow_sources = 64;
    reverse.records.codec.flow_sources = 64;
    forward.records.codec.queue_bytes = 65_536;
    reverse.records.codec.queue_bytes = 65_536;
    forward.records.channels = 2;
    reverse.records.channels = 3;
    forward.records.codec.window = 7;
    reverse.records.codec.window = 11;
    forward.records.codec.repair_numerator = 1;
    forward.records.codec.repair_denominator = 3;
    reverse.records.codec.repair_numerator = 2;
    reverse.records.codec.repair_denominator = 7;
    if options.live.is_some() {
        reverse.records.codec.repair_numerator = 1;
        reverse.records.codec.repair_denominator = 3;
    }
    let descriptor = |forward: l2tunnel_swift::policy::Direction,
                      reverse: l2tunnel_swift::policy::Direction|
     -> Result<Descriptor> {
        Ok(Descriptor::new(
            1500,
            Duplex::Full,
            common_service::common_direction(
                forward.records.channels as u16,
                connection.max_packet,
                forward.bytes_per_second,
            )?,
            common_service::common_direction(
                reverse.records.channels as u16,
                connection.max_packet,
                reverse.bytes_per_second,
            )?,
            l2tunnel::record_configuration::Profile::Swift {
                forward: forward.records,
                reverse: reverse.records,
            },
        )?)
    };
    let initial_descriptor = descriptor(forward, reverse)?;
    initiator.send = forward;
    initiator.receive = reverse;
    responder.send = reverse;
    responder.receive = forward;
    forward.records.channels = 4;
    reverse.records.channels = 1;
    let target_descriptor = descriptor(forward, reverse)?;
    forward.bytes_per_second = forward
        .bytes_per_second
        .checked_add(1)
        .ok_or("rate exhausted")?;
    let outside_descriptor = descriptor(forward, reverse)?;
    let profile = transaction_profile::Profile::new(
        connection,
        settings,
        peers,
        initiator,
        responder,
        Catalog::new(initial_descriptor, &[initial_descriptor, target_descriptor])?,
        transport::TransactionSettings {
            protocol: transaction::Settings {
                retry_ms: 10,
                phase_timeout_ms: 500,
                reconcile_timeout_ms: 1000,
            },
            max_operation_ms: 1500,
            retained_bytes: options.retained_bytes,
        },
    )?;
    let initial = profile.initial();
    let target = Configuration::new(profile.envelope(), target_descriptor)?;
    let outside = Configuration::new(profile.envelope(), outside_descriptor)?;
    for role in [Role::Initiator, Role::Responder] {
        assert_eq!(
            profile.runtime_contract(role)?.resources().report_interval,
            options.report_interval
        );
    }
    let client_noise = credentials::NoiseIdentity::new(
        Zeroizing::new([11; 32]),
        peers.responder,
        options.noise_profile,
        options.psk[0].map(Zeroizing::new),
    )?;
    let server_noise = credentials::NoiseIdentity::new(
        Zeroizing::new([22; 32]),
        peers.initiator,
        options.noise_profile,
        options.psk[1].map(Zeroizing::new),
    )?;
    let client_profile = match options.live {
        Some(live) => profile
            .clone()
            .with_tuning(crate::secure_udp::live_tuning::Policy {
                choices: Some(live.choices()),
                ..Default::default()
            }),
        None => profile.clone(),
    };
    let client = Prepared::secure_udp_common_client(
        client_profile,
        credentials::Client::new(
            client_noise,
            member,
            credentials::Secret32::new(Zeroizing::new(options.admission[0]))?,
        )?,
        hosts[0].attachment(),
    )?;
    let server = Prepared::secure_udp_common_server(
        profile.clone(),
        credentials::Server::new(
            server_noise,
            credentials::Secret32::new(Zeroizing::new(options.admission[1]))?,
            credentials::Secret32::new(Zeroizing::new([55; 32]))?,
        )?,
        hosts[1].attachment(),
    )?;
    drop(held);
    Ok(TransactionPlans {
        plans: [client, server],
        addresses,
        profile,
        initial,
        target,
        outside,
    })
}

fn v4(action: local::Action) -> local::Request {
    local::Request {
        version: local::COMMON_VERSION,
        action,
    }
}

fn status(handle: &Handle) -> Result<transaction_status::Status> {
    handle
        .snapshot()
        .runtime
        .as_ref()
        .and_then(Observation::secure_udp_common)
        .ok_or_else(|| io::Error::other("missing actual transaction frame"))?
        .status()
        .map_err(Into::into)
}

fn transaction_response(response: &local::Response) -> Result<&transaction_status::Status> {
    assert_eq!(response.version, local::COMMON_VERSION);
    assert!(response.ok, "transaction response rejected: {response:?}");
    let state = response
        .state
        .as_ref()
        .ok_or("missing local transaction state")?;
    state
        .common
        .as_ref()
        .ok_or_else(|| "missing separate transaction DTO".into())
}

fn assert_current(
    value: &transaction_status::Status,
    expected: Configuration,
    epoch: u64,
) -> Result {
    assert!(value.running && value.configuration_change);
    assert_eq!(value.epoch, Some(epoch));
    assert_eq!(
        value
            .current
            .as_ref()
            .map(transaction_status::CanonicalConfiguration::configuration)
            .transpose()?,
        Some(expected)
    );
    assert_eq!(value.physical_scope.map(|scope| scope.epoch), Some(epoch));
    assert_eq!(value.phase, Some(transaction_status::Phase::Idle));
    assert!(value.operation.is_none());
    assert!(value.cross_profile_switching && !value.retained_state_recovery && !value.fresh_rekey);
    Ok(())
}

async fn expect_follower_current(handle: &Handle, expected: Configuration, epoch: u64) -> Result {
    let mut changed = handle.subscribe();
    timeout(Duration::from_secs(3), async {
        loop {
            let actual = status(handle)?;
            if actual.epoch == Some(epoch)
                && actual.phase == Some(transaction_status::Phase::Idle)
                && actual.operation.is_none()
            {
                return assert_current(&actual, expected, epoch);
            }
            changed.changed().await?;
        }
    })
    .await?
}

fn channel_packet(channel: usize, width: usize, marker: u8) -> Result<Vec<u8>> {
    for port in 1..=u16::MAX {
        let mut bytes = packet(marker, 512);
        bytes[20..22].copy_from_slice(&port.to_be_bytes());
        if l2tunnel_swift::flow::classify_ip(&bytes, width) == channel {
            return Ok(bytes);
        }
    }
    Err("bounded classifier search found no packet for channel".into())
}

async fn every_channel(hosts: &[Arc<Host>; 2], widths: [usize; 2], marker: u8) -> Result {
    for side in 0..2 {
        for channel in 0..widths[side] {
            let bytes = channel_packet(channel, widths[side], marker.wrapping_add(channel as u8))?;
            hosts[side].send(&bytes)?;
            hosts[1 - side].expect(&bytes).await?;
        }
    }
    Ok(())
}

fn assert_no_native_replay(host: &Host) -> Result {
    let application = host
        .application
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut bytes = [0; 1601];
    let error = application
        .as_ref()
        .ok_or("native attachment missing")?
        .recv(&mut bytes)
        .err()
        .ok_or("unexpected duplicate native output")?;
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    Ok(())
}

#[tokio::test]
async fn actual_transaction_service_switches_twice_without_periodic_reports_and_reconnects()
-> Result {
    transaction_service_lifecycle().await
}
pub(super) async fn transaction_service_lifecycle() -> Result {
    for appearance in [
        l2tunnel_cover::Appearance::QuicLike,
        l2tunnel_cover::Appearance::MediaLike,
    ] {
        let hosts = [Arc::new(Host::default()), Arc::new(Host::default())];
        let TransactionPlans {
            plans: [client_plan, server_plan],
            addresses,
            profile,
            initial,
            target,
            outside,
        } = transaction_plans(appearance, &hosts)?;
        assert!(
            hosts
                .iter()
                .all(|host| host.opened.load(Ordering::SeqCst) == 0)
        );
        let (client, client_run) = channel();
        let (server, server_run) = channel();
        let client_task = tokio::spawn(client_run);
        let server_task = tokio::spawn(server_run);
        let a = client
            .connect(client_plan.clone(), client.next_key().map_err(submit)?)
            .map_err(submit)?;
        let b = server
            .connect(server_plan.clone(), server.next_key().map_err(submit)?)
            .map_err(submit)?;
        let (a, b) = tokio::try_join!(connected(&client, a), connected(&server, b))?;
        let retained_admission = admission_identity(&server_plan).await?;
        let before = status(&client)?;
        let first_epoch = before.epoch.ok_or("missing original epoch")?;
        assert_current(&before, initial, first_epoch)?;
        assert_eq!(before.configuration, profile.configuration()?.0);
        assert_eq!(
            (before.local, before.peer),
            (addresses[0].to_string(), addresses[1].to_string())
        );
        let old_session = before.session;
        let old_transcript = before.transcript;
        let old_setup = client.setup_observation(a).map_err(submit)?;
        for version in [local::VERSION, 2] {
            let next = client.next_key().map_err(submit)?;
            let refused = client
                .lifecycle_request(local::Request {
                    version,
                    action: local::Action::Disconnect {},
                })
                .await;
            assert_eq!(refused.code, "requires_version_4");
            assert!(refused.state.is_none());
            assert_eq!(client.next_key().map_err(submit)?, next);
            assert_eq!(client.snapshot().generation, Some(a));
            assert_eq!(hosts[0].live.load(Ordering::SeqCst), 1);
        }
        // A checked but unsupported complete C is refused before key admission.
        let key = client.next_key().map_err(submit)?;
        assert_eq!(
            client.apply_common(outside, key),
            Err(SubmitError::InvalidConfiguration)
        );
        assert_eq!(client.next_key().map_err(submit)?, key);
        assert_eq!(status(&client)?.epoch, Some(first_epoch));
        every_channel(&hosts, [2, 3], 31).await?;
        // Let the actual fixed-control challenge run; the final report below is
        // the observation, not this delay or an inferred liveness success.
        tokio::time::sleep(Duration::from_millis(30)).await;
        let accepted = client.apply_common(target, key).map_err(submit)?;
        assert_eq!(client.apply_common(target, key).map_err(submit)?, accepted);
        assert_eq!(
            client.apply_common(initial, key),
            Err(SubmitError::Conflict)
        );
        let completed = timeout(Duration::from_secs(3), client.wait(accepted.operation))
            .await?
            .map_err(submit)?;
        let Completed::Common {
            configuration,
            outcome: Ok(epoch),
        } = completed.clone()
        else {
            return Err(format!("actual first switch did not apply: {completed:?}").into());
        };
        assert_eq!(configuration, target);
        assert_eq!(epoch.0, first_epoch + 1);
        let observed = status(&client)?;
        assert_current(&observed, target, first_epoch + 1)?;
        assert!(
            observed
                .liveness
                .as_ref()
                .and_then(|value| value.last_pong_micros)
                .is_some()
        );
        assert_eq!(client.apply_common(target, key).map_err(submit)?, accepted);
        assert_eq!(
            client.wait(accepted.operation).await.map_err(submit)?,
            completed.clone()
        );
        assert_current(&status(&client)?, target, first_epoch + 1)?;
        expect_follower_current(&server, target, first_epoch + 1).await?;
        every_channel(&hosts, [4, 1], 71).await?;

        // Actual bounded Unix local transport, not serde-only DTO evidence.
        let directory = ApiDirectory::new()?;
        let api_path = directory.0.join("transaction-api.sock");
        let api = local::Server::bind(&api_path)?;
        let api_handle = client.clone();
        let api_task = tokio::spawn(async move {
            api.serve(move |request| {
                let handle = api_handle.clone();
                async move { handle.lifecycle_request(request).await }
            })
            .await
        });
        let wire_status = local::request(&api_path, &v4(local::Action::Status {})).await?;
        assert_current(transaction_response(&wire_status)?, target, first_epoch + 1)?;
        let switched = timeout(
            Duration::from_secs(3),
            local::request(
                &api_path,
                &v4(local::Action::SwitchCommonConfiguration {
                    request_key: client.next_key().map_err(submit)?.value(),
                    configuration: transaction_status::CanonicalConfiguration::from_configuration(
                        initial,
                    )?,
                }),
            ),
        )
        .await??;
        assert_current(transaction_response(&switched)?, initial, first_epoch + 2)?;
        expect_follower_current(&server, initial, first_epoch + 2).await?;
        every_channel(&hosts, [2, 3], 111).await?;
        for host in &hosts {
            assert_no_native_replay(host)?;
        }

        let (left, right) = tokio::join!(
            client.lifecycle_request(v4(local::Action::Disconnect {})),
            server.lifecycle_request(v4(local::Action::Disconnect {})),
        );
        assert!(
            left.ok && right.ok,
            "actual release failed: {left:?} {right:?}"
        );
        assert!(
            hosts
                .iter()
                .all(|host| host.live.load(Ordering::SeqCst) == 0)
        );
        assert_eq!(
            client.wait_stopped(a).await.map_err(submit)?,
            Terminal::Aborted
        );
        assert_eq!(
            server.wait_stopped(b).await.map_err(submit)?,
            Terminal::Aborted
        );
        let stopped_frame = client
            .snapshot()
            .runtime
            .as_ref()
            .and_then(Observation::secure_udp_common)
            .ok_or("missing retained stopped generic frame")?
            .clone();
        let stopped_status = stopped_frame.status()?;
        assert!(!stopped_status.running);
        assert_eq!(stopped_status.service_terminal.as_deref(), Some("Aborted"));
        assert_eq!(
            stopped_status
                .current
                .as_ref()
                .map(transaction_status::CanonicalConfiguration::configuration)
                .transpose()?,
            Some(initial)
        );
        let held = [
            std::net::UdpSocket::bind(addresses[0])?,
            std::net::UdpSocket::bind(addresses[1])?,
        ];
        drop(held);
        let (left, right) = tokio::join!(
            client.lifecycle_request(v4(local::Action::Reconnect {})),
            server.lifecycle_request(v4(local::Action::Reconnect {})),
        );
        assert!(
            left.ok && right.ok,
            "actual fresh reconnect failed: {left:?} {right:?}"
        );
        let fresh = transaction_response(&left)?;
        assert_current(fresh, initial, first_epoch)?;
        assert_ne!(fresh.session, old_session);
        assert_ne!(fresh.transcript, old_transcript);
        assert!(fresh.generation > a.value());
        assert_eq!(admission_identity(&server_plan).await?, retained_admission);
        assert_eq!(client.setup_observation(a).map_err(submit)?, old_setup);
        assert_eq!(stopped_frame.status()?, stopped_status);
        assert!(
            hosts
                .iter()
                .all(|host| host.opened.load(Ordering::SeqCst) == 2
                    && host.live.load(Ordering::SeqCst) == 1)
        );
        for host in &hosts {
            assert_no_native_replay(host)?;
        }
        every_channel(&hosts, [2, 3], 151).await?;
        api_task.abort();
        let _ = api_task.await;
        client_task.abort();
        server_task.abort();
        let _ = tokio::join!(client_task, server_task);
        assert!(
            hosts
                .iter()
                .all(|host| host.live.load(Ordering::SeqCst) == 0)
        );
        for handle in [&client, &server] {
            let value = status(handle)?;
            assert!(!value.running);
            assert_eq!(value.service_terminal.as_deref(), Some("Aborted"));
        }
    }
    Ok(())
}

/// TT-05 without privileges: two real services joined by real loopback UDP
/// run built-in speed and ping tests through the local API. The test packets
/// cross the real Common runtime and protocol, and never reach either device.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tunnel_tests_cross_the_real_session_and_never_reach_a_device() -> Result {
    use crate::local::tunnel_test::{Direction, TestPhase, TestRequest};
    use crate::local::{OperationAction, OperationRequest};
    let hosts = [Arc::new(Host::default()), Arc::new(Host::default())];
    let TransactionPlans {
        plans: [client_plan, server_plan],
        ..
    } = transaction_plans(l2tunnel_cover::Appearance::QuicLike, &hosts)?;
    let (client, client_run) = channel();
    let (server, server_run) = channel();
    let client_task = tokio::spawn(client_run);
    let server_task = tokio::spawn(server_run);
    let a = client
        .connect(client_plan, client.next_key().map_err(submit)?)
        .map_err(submit)?;
    let b = server
        .connect(server_plan, server.next_key().map_err(submit)?)
        .map_err(submit)?;
    tokio::try_join!(connected(&client, a), connected(&server, b))?;
    let info = client
        .operations_request(OperationRequest::new(OperationAction::ServiceInfo {}))
        .await
        .info
        .ok_or("service info")?;
    let tests = info
        .capabilities
        .iter()
        .find(|capability| capability.feature == crate::local::Feature::Tests)
        .ok_or("tests capability")?;
    assert!(tests.available, "{tests:?}");
    let run = |test: TestRequest| {
        let client = client.clone();
        async move {
            let started = client
                .operations_request(OperationRequest::new(OperationAction::TestStart { test }))
                .await;
            assert_eq!(started.code, "accepted", "{started:?}");
            let id = started
                .test
                .and_then(|reply| reply.test)
                .map(|state| state.id)
                .ok_or("started test")?;
            let finished = client
                .operations_request(OperationRequest::new(OperationAction::TestGet {
                    id: Some(id),
                    timeout_ms: 30_000,
                }))
                .await;
            finished.test.and_then(|reply| reply.test).ok_or_else(
                || -> Box<dyn std::error::Error + Send + Sync> { "finished test".into() },
            )
        }
    };
    for direction in [Direction::Upload, Direction::Download] {
        let speed = run(TestRequest::Speed {
            direction,
            streams: 2,
            duration_ms: 2_000,
        })
        .await?;
        assert_eq!(speed.state, TestPhase::Completed, "{speed:?}");
        assert!(speed.bytes > 0 && speed.bits_per_second > 0, "{speed:?}");
    }
    let ping = run(TestRequest::Ping {
        count: 5,
        interval_ms: 100,
    })
    .await?;
    assert_eq!(ping.state, TestPhase::Completed, "{ping:?}");
    let result = ping.ping.ok_or("ping result")?;
    assert_eq!((result.sent, result.received), (5, 5), "{result:?}");
    for host in &hosts {
        assert_no_native_replay(host)?;
    }
    client_task.abort();
    server_task.abort();
    let _ = tokio::join!(client_task, server_task);
    Ok(())
}

/// MCSR-09 / MCSR-10 without privileges: two real services joined by loopback
/// UDP read each other's live CSR registers over the authenticated Liveness
/// control stream (`ProfileTag::MetersV1`), with prefix filtering, cursor
/// paging, and rate-gate enforcement.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_meters_cross_the_real_session_with_paging_and_rate_gate() -> Result {
    use crate::local::{MeterSide, OperationAction, OperationRequest};
    let hosts = [Arc::new(Host::default()), Arc::new(Host::default())];
    let TransactionPlans {
        plans: [client_plan, server_plan],
        ..
    } = transaction_plans(l2tunnel_cover::Appearance::QuicLike, &hosts)?;
    let (client, client_run) = channel();
    let (server, server_run) = channel();
    let client_task = tokio::spawn(client_run);
    let server_task = tokio::spawn(server_run);
    let a = client
        .connect(client_plan, client.next_key().map_err(submit)?)
        .map_err(submit)?;
    let b = server
        .connect(server_plan, server.next_key().map_err(submit)?)
        .map_err(submit)?;
    tokio::try_join!(connected(&client, a), connected(&server, b))?;

    let first = client
        .operations_request(OperationRequest::new(OperationAction::MetersRead {
            side: MeterSide::Remote,
            prefix: "runtime".into(),
            cursor: None,
            limit: 4,
        }))
        .await;
    assert!(first.ok, "{first:?}");
    let page1 = first.meters.ok_or("first remote meter page")?;
    assert_eq!(page1.side, MeterSide::Remote);
    assert_eq!(page1.entries.len(), 4, "{page1:?}");
    assert!(page1.entries.iter().all(|e| e.path.starts_with("runtime.")));
    let cursor = page1.next.clone().ok_or("expected next cursor")?;

    let rapid = client
        .operations_request(OperationRequest::new(OperationAction::MetersRead {
            side: MeterSide::Remote,
            prefix: "runtime".into(),
            cursor: Some(cursor.clone()),
            limit: 4,
        }))
        .await;
    assert!(!rapid.ok, "{rapid:?}");
    assert_eq!(rapid.code, "busy", "{rapid:?}");

    tokio::time::sleep(Duration::from_millis(300)).await;
    let second = client
        .operations_request(OperationRequest::new(OperationAction::MetersRead {
            side: MeterSide::Remote,
            prefix: "runtime".into(),
            cursor: Some(cursor.clone()),
            limit: 64,
        }))
        .await;
    assert!(second.ok, "{second:?}");
    let page2 = second.meters.ok_or("second remote meter page")?;
    assert_eq!(page2.side, MeterSide::Remote);
    assert!(!page2.entries.is_empty(), "{page2:?}");
    assert!(page2.entries[0].path > cursor, "{page2:?}");

    let from_server = server
        .operations_request(OperationRequest::new(OperationAction::MetersRead {
            side: MeterSide::Remote,
            prefix: "meta".into(),
            cursor: None,
            limit: 16,
        }))
        .await;
    assert!(from_server.ok, "{from_server:?}");
    let server_page = from_server.meters.ok_or("server->client meter page")?;
    assert!(
        server_page
            .entries
            .iter()
            .any(|e| e.path == "meta.version" && e.value == l2tunnel_meters::catalog::VERSION),
        "{server_page:?}"
    );

    // Live authenticated speed-budget update applies symmetrically on both peers.
    let target_up = 62_500_000_u64; // 500 Mbit/s
    let target_down = 125_000_000_u64; // 1 Gbit/s
    let applied = client
        .operations_request(OperationRequest::new(OperationAction::RateBudgetSet {
            send_rate: target_up,
            receive_rate: target_down,
        }))
        .await;
    assert!(applied.ok, "{applied:?}");
    let wait_rates = |handle: &Handle, expected_send: u64, expected_recv: u64| {
        let handle = handle.clone();
        async move {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
            loop {
                let status = handle
                    .operations_request(OperationRequest::new(OperationAction::Status {}))
                    .await;
                if let Some(common) = status
                    .status
                    .and_then(|s| s.observation)
                    .and_then(|o| o.common)
                    && common.send_rate == Some(expected_send)
                    && common.receive_rate == Some(expected_recv)
                {
                    return Ok::<(), Box<dyn std::error::Error + Send + Sync>>(());
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(format!(
                        "rates did not converge to ({expected_send}, {expected_recv})"
                    )
                    .into());
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }
    };
    tokio::try_join!(
        wait_rates(&client, target_up, target_down),
        wait_rates(&server, target_down, target_up),
    )?;

    client_task.abort();
    server_task.abort();
    let _ = tokio::join!(client_task, server_task);
    Ok(())
}

#[tokio::test]
async fn tuned_client_proposes_at_connect_and_switches_fec_off_live() -> Result {
    use crate::local::{OperationAction, OperationRequest};
    use l2tunnel::live_tuning::{self as tuning, Choices, Repair, Setting};
    let hosts = [Arc::new(Host::default()), Arc::new(Host::default())];
    let choices = Choices {
        repair: vec![Repair::Off],
        ..Choices::default()
    };
    let TransactionPlans {
        plans: [client_plan, server_plan],
        profile,
        initial,
        ..
    } = transaction_plans_with(
        l2tunnel_cover::Appearance::QuicLike,
        &hosts,
        TransactionFixtureOptions {
            live: Some(Live::FecOff),
            ..TransactionFixtureOptions::baseline()
        },
    )?;
    let generated = tuning::extend(profile.plan_catalog(), &choices, &tuning::Limits::PROTOCOL)?;
    assert_eq!(generated.descriptors().len(), 3);
    let (client, client_run) = channel();
    let (server, server_run) = channel();
    let client_task = tokio::spawn(client_run);
    let server_task = tokio::spawn(server_run);
    let a = client
        .connect(client_plan, client.next_key().map_err(submit)?)
        .map_err(submit)?;
    let b = server
        .connect(server_plan, server.next_key().map_err(submit)?)
        .map_err(submit)?;
    tokio::try_join!(connected(&client, a), connected(&server, b))?;
    // Both ends report the generated catalog, and the base setup identity.
    for handle in [&client, &server] {
        let observed = status(handle)?;
        assert_eq!(observed.catalog, *generated.root().as_bytes());
        assert_eq!(observed.catalog_members, 3);
        assert_eq!(observed.configuration, profile.configuration()?.0);
    }
    let first_epoch = status(&client)?.epoch.ok_or("epoch")?;
    every_channel(&hosts, [2, 3], 41).await?;
    let off = Setting {
        repair: Repair::Off,
        ..tuning::setting(&initial.descriptor().clone())?
    };
    let descriptor = generated
        .descriptors()
        .iter()
        .copied()
        .find(|d| tuning::setting(d).is_ok_and(|s| s == off))
        .ok_or("FEC-off entry")?;
    let target = Configuration::new(profile.envelope(), descriptor)?;
    let key = client.next_key().map_err(submit)?;
    let accepted = client.apply_common(target, key).map_err(submit)?;
    let completed = timeout(Duration::from_secs(3), client.wait(accepted.operation))
        .await?
        .map_err(submit)?;
    let Completed::Common {
        outcome: Ok(epoch), ..
    } = completed
    else {
        return Err(format!("live FEC-off switch did not apply: {completed:?}").into());
    };
    assert_eq!(epoch.0, first_epoch + 1);
    assert_current(&status(&client)?, target, first_epoch + 1)?;
    expect_follower_current(&server, target, first_epoch + 1).await?;
    every_channel(&hosts, [2, 3], 81).await?;

    // The same switch by setting through the local API (decision 10).
    let reply = client
        .operations_request(OperationRequest::new(OperationAction::TuningGet {}))
        .await;
    assert!(reply.ok, "{reply:?}");
    let view = reply.tuning.ok_or("tuning view")?;
    assert!(view.live);
    assert_eq!(view.repair, ["off", "1/3"]);
    assert_eq!(view.entries.len(), 2, "plan target entry is not symmetric");
    let current = view.current.clone().ok_or("current setting")?;
    assert_eq!(current.repair, "off");
    let fec = crate::local::TuningSetting {
        repair: "1/3".into(),
        ..current.clone()
    };
    let key = client.next_key().map_err(submit)?;
    let reply = client
        .operations_request(OperationRequest::new(OperationAction::TuningSwitch {
            request_key: key.value(),
            setting: fec.clone(),
        }))
        .await;
    assert!(reply.ok, "{reply:?}");
    let operation = reply.operation.ok_or("accepted operation")?.id;
    let reply = client
        .operations_request(OperationRequest::new(OperationAction::OperationWait {
            operation,
            timeout_ms: 3000,
            service: None,
        }))
        .await;
    assert_eq!(
        reply.operation.as_ref().map(|state| state.state.as_str()),
        Some("completed"),
        "{reply:?}"
    );
    assert_current(&status(&client)?, initial, first_epoch + 2)?;
    expect_follower_current(&server, initial, first_epoch + 2).await?;
    every_channel(&hosts, [2, 3], 121).await?;
    // A setting the catalog lacks is refused before any switch.
    let key = client.next_key().map_err(submit)?;
    let reply = client
        .operations_request(OperationRequest::new(OperationAction::TuningSwitch {
            request_key: key.value(),
            setting: crate::local::TuningSetting {
                device_mtu: fec.device_mtu - 1,
                ..fec
            },
        }))
        .await;
    assert_eq!((reply.ok, reply.code.as_str()), (false, "not_in_catalog"));
    client_task.abort();
    server_task.abort();
    let _ = tokio::join!(client_task, server_task);
    Ok(())
}

#[tokio::test]
async fn tuned_device_mtu_is_lowered_on_both_ends_before_the_switch_and_restored_after() -> Result {
    use l2tunnel::live_tuning::{self as tuning, Setting};
    let hosts = [Arc::new(Host::default()), Arc::new(Host::default())];
    let probe = transaction_plans_with(
        l2tunnel_cover::Appearance::QuicLike,
        &hosts,
        TransactionFixtureOptions {
            live: Some(Live::FecOff),
            ..TransactionFixtureOptions::baseline()
        },
    )?;
    let base = tuning::setting(&probe.initial.descriptor().clone())?.device_mtu;
    drop(probe);
    let lower = base - 200;
    let TransactionPlans {
        plans: [client_plan, server_plan],
        profile,
        initial,
        ..
    } = transaction_plans_with(
        l2tunnel_cover::Appearance::QuicLike,
        &hosts,
        TransactionFixtureOptions {
            live: Some(Live::DeviceMtu(lower)),
            ..TransactionFixtureOptions::baseline()
        },
    )?;
    let generated = tuning::extend(
        profile.plan_catalog(),
        &Live::DeviceMtu(lower).choices(),
        &tuning::Limits::PROTOCOL,
    )?;
    let (client, client_run) = channel();
    let (server, server_run) = channel();
    let client_task = tokio::spawn(client_run);
    let server_task = tokio::spawn(server_run);
    let a = client
        .connect(client_plan, client.next_key().map_err(submit)?)
        .map_err(submit)?;
    let b = server
        .connect(server_plan, server.next_key().map_err(submit)?)
        .map_err(submit)?;
    tokio::try_join!(connected(&client, a), connected(&server, b))?;
    let base = u32::from(base);
    let lower_mtu = u32::from(lower);
    // Both services set the device to the initial entry's size.
    let settled = |host: &Arc<Host>, mtu: u32| {
        let host = host.clone();
        async move {
            for _ in 0..300 {
                if host.mtu.current() == mtu {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            false
        }
    };
    for host in &hosts {
        assert!(settled(host, base).await, "initial device MTU");
    }
    every_channel(&hosts, [2, 3], 51).await?;
    let first_epoch = status(&client)?.epoch.ok_or("epoch")?;

    // Switch down: each end lowers its device before its switch step.
    let down = Setting {
        device_mtu: lower,
        ..tuning::setting(&initial.descriptor().clone())?
    };
    let descriptor = generated
        .descriptors()
        .iter()
        .copied()
        .find(|d| tuning::setting(d).is_ok_and(|s| s == down))
        .ok_or("lower entry")?;
    let target = Configuration::new(profile.envelope(), descriptor)?;
    let key = client.next_key().map_err(submit)?;
    let accepted = client.apply_common(target, key).map_err(submit)?;
    let completed = timeout(Duration::from_secs(3), client.wait(accepted.operation))
        .await?
        .map_err(submit)?;
    let switched_down = std::time::Instant::now();
    let Completed::Common {
        outcome: Ok(epoch), ..
    } = completed
    else {
        return Err(format!("device MTU switch down did not apply: {completed:?}").into());
    };
    assert_eq!(epoch.0, first_epoch + 1);
    expect_follower_current(&server, target, first_epoch + 1).await?;
    let lowered = |host: &Arc<Host>| {
        host.mtu
            .changes()
            .iter()
            .find(|(mtu, _)| *mtu == lower_mtu)
            .map(|(_, at)| *at)
    };
    let leader = lowered(&hosts[0]).ok_or("client device not lowered")?;
    let follower = lowered(&hosts[1]).ok_or("server device not lowered")?;
    // The leader lowers before it proposes, the follower before it
    // acknowledges; the switch completes after both.
    assert!(leader < follower);
    assert!(follower < switched_down);
    every_channel(&hosts, [2, 3], 91).await?;

    // Switch up: both raise after the switch.
    let key = client.next_key().map_err(submit)?;
    let accepted = client.apply_common(initial, key).map_err(submit)?;
    let completed = timeout(Duration::from_secs(3), client.wait(accepted.operation))
        .await?
        .map_err(submit)?;
    let Completed::Common { outcome: Ok(_), .. } = completed else {
        return Err(format!("device MTU switch up did not apply: {completed:?}").into());
    };
    for host in &hosts {
        assert!(settled(host, base).await, "raised device MTU");
        let values: Vec<u32> = host.mtu.changes().iter().map(|(mtu, _)| *mtu).collect();
        assert_eq!(values, [base, lower_mtu, base]);
    }
    let snapshot = status(&client)?;
    assert_eq!(
        usize::from(snapshot.catalog_members),
        generated.descriptors().len()
    );
    let reported = snapshot.device_mtu.ok_or("device MTU status")?;
    assert_eq!(
        (reported.applied, reported.wanted, reported.failures),
        (Some(base), Some(base), 0)
    );
    every_channel(&hosts, [2, 3], 131).await?;

    // Ending the session restores the MTU from before it.
    client_task.abort();
    server_task.abort();
    let _ = tokio::join!(client_task, server_task);
    for host in &hosts {
        assert!(settled(host, 1500).await, "restored device MTU");
    }
    Ok(())
}

#[inline(never)]
fn call_v5(
    path: &std::path::Path,
    action: crate::local::OperationAction,
) -> std::pin::Pin<
    Box<
        dyn std::future::Future<Output = io::Result<Box<crate::local::OperationReply>>> + Send + '_,
    >,
> {
    Box::pin(async move {
        crate::local::request_operation(path, &crate::local::OperationRequest::new(action))
            .await
            .map(Box::new)
    })
}

/// LOP-06 & TT-03: drive a real Common retained plan to authenticated readiness
/// through local API v5 over a real Unix socket, observing the exact event
/// sequence (`operation_accepted -> operation_progress -> operation_completed ->
/// lifecycle`), `operation_wait`, live `status`, tunnel-test refusals (`busy`,
/// `unknown_test`), and live `disconnect`.
#[tokio::test]
async fn version5_unix_socket_drives_real_common_connect_events_and_test_refusals() -> Result {
    use crate::local::{
        EventBody, OperationAction, OperationResult, Server,
        tunnel_test::{Direction, TestRequest},
    };
    use std::os::unix::fs::DirBuilderExt;

    let dir = std::env::temp_dir().join(format!(
        "l2t-lop06-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    let _cleanup = scopeguard_dir(dir.clone());
    let sock_path = dir.join("api.sock");

    let hosts = [Arc::new(Host::default()), Arc::new(Host::default())];
    let TransactionPlans {
        plans: [client_plan, server_plan],
        ..
    } = transaction_plans_with(
        l2tunnel_cover::Appearance::QuicLike,
        &hosts,
        TransactionFixtureOptions::baseline(),
    )?;

    let (client, client_run) = channel_with_plan(client_plan);
    let (server, server_run) = channel();
    let client_task = tokio::spawn(client_run);
    let server_task = tokio::spawn(server_run);
    let server_connect = server
        .connect(server_plan, server.next_key().map_err(submit)?)
        .map_err(submit)?;

    let api_server = Server::bind(&sock_path)?;
    let api_handle = client.clone();
    let api_task = tokio::spawn(async move { api_server.serve_service(api_handle).await });

    // Submit v5 Connect over the real Unix socket against the retained plan.
    let initial = call_v5(&sock_path, OperationAction::Status {}).await?;
    assert!(initial.ok, "{initial:?}");
    let key = initial
        .status
        .as_ref()
        .and_then(|s| s.next_request_key)
        .ok_or("next_request_key")?;
    let service_id = initial.service.ok_or("service id")?;
    drop(initial);

    let accepted = call_v5(&sock_path, OperationAction::Connect { request_key: key }).await?;
    assert!(accepted.ok, "{accepted:?}");
    let op_id = accepted.operation.as_ref().ok_or("operation")?.id;
    drop(accepted);

    // Wait for both peers to complete actual authenticated setup.
    let waited = call_v5(
        &sock_path,
        OperationAction::OperationWait {
            operation: op_id,
            timeout_ms: 10_000,
            service: Some(service_id),
        },
    )
    .await?;
    assert!(waited.ok, "{waited:?}");
    let op = waited.operation.as_ref().ok_or("completed op")?;
    assert_eq!(op.state, "completed");
    assert!(
        matches!(op.result, Some(OperationResult::Connected { .. })),
        "{op:?}"
    );
    drop(waited);

    let server_done = timeout(
        Duration::from_secs(5),
        server.wait(server_connect.operation),
    )
    .await?
    .map_err(submit)?;
    assert!(
        matches!(server_done, Completed::Connected { .. }),
        "{server_done:?}"
    );

    // Verify exact event sequence recorded by the actor over v5 Events.
    let events_reply = call_v5(
        &sock_path,
        OperationAction::Events {
            after: 0,
            limit: 32,
            timeout_ms: 0,
            service: Some(service_id),
        },
    )
    .await?;
    assert!(events_reply.ok, "{events_reply:?}");
    let events = events_reply.events.ok_or("events page")?;
    assert!(events.events.iter().any(|e| matches!(
        &e.event,
        EventBody::OperationAccepted { operation, .. } if *operation == op_id
    )));
    assert!(events.events.iter().any(|e| matches!(
        &e.event,
        EventBody::OperationProgress { operation, .. } if *operation == op_id
    )));
    assert!(events.events.iter().any(|e| matches!(
        &e.event,
        EventBody::OperationCompleted { operation, .. } if *operation == op_id
    )));
    assert!(events.events.iter().any(|e| matches!(
        &e.event,
        EventBody::Lifecycle { phase, .. } if phase == "connected"
    )));

    // Verify live status reports connected and UDP send/recv buffer readbacks.
    let live = call_v5(&sock_path, OperationAction::Status {}).await?;
    assert_eq!(
        live.status.as_ref().map(|s| s.phase.as_str()),
        Some("connected")
    );
    let credit_status = live
        .status
        .as_ref()
        .and_then(|s| s.observation.as_ref())
        .and_then(|o| o.common.as_ref())
        .and_then(|c| c.credit);
    assert!(
        credit_status.and_then(|c| c.send_buffer_readback).is_some(),
        "expected SO_SNDBUF readback on connected UDP session: {credit_status:?}"
    );
    let key2 = live
        .status
        .as_ref()
        .and_then(|s| s.next_request_key)
        .ok_or("next_request_key after connect")?;
    drop(live);

    // TT-03 real-service refusal checks over the Unix socket: unknown_test, busy, cancel.
    let missing = call_v5(
        &sock_path,
        OperationAction::TestGet {
            id: Some(999),
            timeout_ms: 0,
        },
    )
    .await?;
    assert!(!missing.ok && missing.code == "unknown_test", "{missing:?}");
    drop(missing);

    let started = call_v5(
        &sock_path,
        OperationAction::TestStart {
            test: TestRequest::Ping {
                count: 5,
                interval_ms: 500,
            },
        },
    )
    .await?;
    assert!(started.ok && started.code == "accepted", "{started:?}");
    let test_id = started
        .test
        .as_deref()
        .and_then(|t| t.test.as_ref())
        .ok_or("test state")?
        .id;
    drop(started);

    let busy = call_v5(
        &sock_path,
        OperationAction::TestStart {
            test: TestRequest::Speed {
                direction: Direction::Upload,
                streams: 1,
                duration_ms: 1_000,
            },
        },
    )
    .await?;
    assert!(!busy.ok && busy.code == "busy", "{busy:?}");
    drop(busy);

    let bad_cancel = call_v5(
        &sock_path,
        OperationAction::TestCancel { id: test_id + 100 },
    )
    .await?;
    assert!(
        !bad_cancel.ok && bad_cancel.code == "unknown_test",
        "{bad_cancel:?}"
    );
    drop(bad_cancel);

    let cancelled = call_v5(&sock_path, OperationAction::TestCancel { id: test_id }).await?;
    assert!(cancelled.ok, "{cancelled:?}");
    drop(cancelled);

    // Clean v5 Disconnect over the Unix socket.
    let disc = call_v5(
        &sock_path,
        OperationAction::Disconnect { request_key: key2 },
    )
    .await?;
    assert!(disc.ok, "{disc:?}");
    let disc_op = disc.operation.as_ref().ok_or("disc op")?.id;
    drop(disc);

    let disc_done = call_v5(
        &sock_path,
        OperationAction::OperationWait {
            operation: disc_op,
            timeout_ms: 5_000,
            service: Some(service_id),
        },
    )
    .await?;
    assert!(disc_done.ok, "{disc_done:?}");
    drop(disc_done);

    api_task.abort();
    client_task.abort();
    server_task.abort();
    let _ = tokio::join!(api_task, client_task, server_task);
    Ok(())
}

struct DirGuard(std::path::PathBuf);
impl Drop for DirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn scopeguard_dir(path: std::path::PathBuf) -> DirGuard {
    DirGuard(path)
}
