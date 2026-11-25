//! Pure plan validation and owner custody; no authenticated runtime is constructed.

use super::*;
use crate::secure_udp::{common_transaction_profile as transaction_profile, credentials};
use l2tunnel::pipeline as l2tunnel_pipeline;
use l2tunnel::record_configuration::{Catalog, Descriptor};
use l2tunnel_cover::Appearance;
use l2tunnel_handshake as hs;
use l2tunnel_identity::IdentityKey;
use l2tunnel_management::{control_streams, delivery, messages, transaction};
use l2tunnel_runtime::secure_udp::transport;
use l2tunnel_security::Role;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicUsize, Ordering};
use zeroize::Zeroizing;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn unhex<const N: usize>(text: &str) -> Result<[u8; N]> {
    if text.len() != N * 2 {
        return Err("invalid public test vector length".into());
    }
    let mut bytes = [0; N];
    for (destination, pair) in bytes.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *destination = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    Ok(bytes)
}

fn member(other: bool) -> Result<IdentityKey> {
    // Public RFC8032 section7.1 vectors, never provisioning examples.
    let (seed, public) = if other {
        (
            unhex::<32>("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")?,
            unhex::<32>("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")?,
        )
    } else {
        (
            unhex::<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")?,
            unhex::<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")?,
        )
    };
    let mut encoded = unhex::<16>("3051020101300506032b657004220420")?.to_vec();
    encoded.extend_from_slice(&seed);
    encoded.extend_from_slice(&[0x81, 0x21, 0]);
    encoded.extend_from_slice(&public);
    Ok(IdentityKey::from_pkcs8(&encoded)?)
}

fn noise(local: u8, remote: u8, pattern: hs::Profile) -> io::Result<credentials::NoiseIdentity> {
    credentials::NoiseIdentity::new(
        Zeroizing::new([local; 32]),
        hs::LocalSecret::new(Zeroizing::new([remote; 32])).public_key(),
        pattern,
        matches!(pattern, hs::Profile::IkPsk2).then(|| Zeroizing::new([66; 32])),
    )
}
fn client(
    other_member: bool,
    local: u8,
    remote: u8,
    pattern: hs::Profile,
) -> Result<credentials::Client> {
    Ok(credentials::Client::new(
        noise(local, remote, pattern)?,
        member(other_member)?,
        credentials::Secret32::new(Zeroizing::new([44; 32]))?,
    )?)
}
fn server(local: u8, remote: u8, pattern: hs::Profile) -> io::Result<credentials::Server> {
    credentials::Server::new(
        noise(local, remote, pattern)?,
        credentials::Secret32::new(Zeroizing::new([44; 32]))?,
        credentials::Secret32::new(Zeroizing::new([55; 32]))?,
    )
}

fn streamed(mut value: transport::Config) -> transport::Config {
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
    value
}

pub(in crate::service) fn descriptor(
    forward: l2tunnel_swift::policy::Direction,
    reverse: l2tunnel_swift::policy::Direction,
    native: usize,
) -> Result<Descriptor> {
    use l2tunnel::record_configuration as common;
    let direction = |value: l2tunnel_swift::policy::Direction| -> Result<common::CommonDirection> {
        let queue = l2tunnel_pipeline::QueueLimits {
            bytes: 65_536,
            packets: 8,
        };
        Ok(common::CommonDirection::new(
            l2tunnel_core::traffic::TrafficPolicy {
                layer: l2tunnel_core::traffic::NetworkLayer::Tun,
                tcp: l2tunnel_core::traffic::TcpControl::System,
                qos: l2tunnel_core::traffic::Qos::WeightedDeficit,
            },
            l2tunnel_pipeline::PipelineConfig {
                profile: l2tunnel_pipeline::Profile::TunDrr(l2tunnel_pipeline::TunQosConfig {
                    base_quantum_bytes: native as u32,
                    max_weight: 1,
                    per_flow: queue,
                }),
                flows: l2tunnel_pipeline::FlowTableConfig {
                    capacity: 8,
                    channels: value.records.channels as u16,
                    mapping: l2tunnel_pipeline::Mapping::Crc32,
                    idle_timeout: Duration::from_secs(5),
                },
                parse: l2tunnel_pipeline::ParseLimits {
                    max_packet_bytes: native,
                    ..Default::default()
                },
                queue,
            },
            value.bytes_per_second,
            65_536,
            common::NativeWindow::Disabled,
        )?)
    };
    Ok(Descriptor::new(
        1500,
        l2tunnel_core::Duplex::Full,
        direction(forward)?,
        direction(reverse)?,
        common::Profile::Swift {
            forward: forward.records,
            reverse: reverse.records,
        },
    )?)
}

struct Plans {
    generic: transaction_profile::Profile,
    // Holding both endpoints makes an accidental bind inside Prepared observable.
    _ports: [UdpSocket; 2],
}
fn plans(appearance: Appearance) -> Result<Plans> {
    let client = crate::test_ports::reserve(false)?;
    let server = crate::test_ports::reserve(false)?;
    let (legacy, peers) = crate::secure_udp::common_fixture::fixture(
        l2tunnel_udp_control::Path {
            client: client.local_addr()?,
            server: server.local_addr()?,
        },
        appearance,
        member(false)?.public_key(),
    )?;
    let mut settings = legacy.settings();
    settings.application = l2tunnel_core::ConfigDigest([31; 32]);
    let mut initiator = streamed(legacy.runtime(Role::Initiator));
    let mut responder = streamed(legacy.runtime(Role::Responder));
    let mut forward = initiator.send;
    let mut reverse = initiator.receive;
    forward.records.channels = 2;
    reverse.records.channels = 3;
    forward.bytes_per_second = 1_250_001;
    reverse.bytes_per_second = 625_013;
    forward.records.codec.window = 7;
    reverse.records.codec.window = 11;
    forward.records.codec.repair_numerator = 1;
    forward.records.codec.repair_denominator = 3;
    reverse.records.codec.repair_numerator = 2;
    reverse.records.codec.repair_denominator = 7;
    forward.records.codec.datagram_bytes = 1200;
    reverse.records.codec.datagram_bytes = 1024;
    let initial = descriptor(forward, reverse, legacy.connection().max_packet)?;
    forward.records.channels = 4;
    reverse.records.channels = 1;
    let target = descriptor(forward, reverse, legacy.connection().max_packet)?;
    initiator.send = forward;
    initiator.send.records.channels = 2;
    initiator.receive = reverse;
    initiator.receive.records.channels = 3;
    responder.send = initiator.receive;
    responder.receive = initiator.send;
    let generic = transaction_profile::Profile::new(
        legacy.connection(),
        settings,
        peers,
        initiator,
        responder,
        Catalog::new(initial, &[target, initial])?,
        transport::TransactionSettings {
            protocol: transaction::Settings {
                retry_ms: 10,
                phase_timeout_ms: 500,
                reconcile_timeout_ms: 1000,
            },
            max_operation_ms: 1500,
            retained_bytes: 16 * 1024 * 1024,
        },
    )?;
    Ok(Plans {
        generic,
        _ports: [client, server],
    })
}

fn attachment(opened: &Arc<AtomicUsize>, layer: PacketLayer, readable: bool) -> Attachment {
    let opened = opened.clone();
    if readable {
        Attachment::readable(layer, move || {
            opened.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::other("test attachment invoked"))
        })
    } else {
        Attachment::new(layer, move || {
            opened.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::other("test attachment invoked"))
        })
    }
}

impl Prepared {
    pub(crate) fn unpolled_common_fixture() -> Result<Self> {
        let plans = plans(Appearance::QuicLike)?;
        Self::secure_udp_common_client(
            plans.generic,
            client(false, 11, 22, hs::Profile::Ik)?,
            Attachment::readable(PacketLayer::Ip, || {
                Err(io::Error::other("unpolled Common fixture"))
            }),
        )
        .map_err(Into::into)
    }
}

fn refused(result: io::Result<Prepared>, expected: io::ErrorKind) -> Result {
    let error = result.err().ok_or("invalid transaction plan accepted")?;
    assert_eq!(error.kind(), expected);
    Ok(())
}

#[test]
fn explicit_transaction_plans_preserve_complete_contract_before_any_io() -> Result {
    for appearance in [Appearance::QuicLike, Appearance::MediaLike] {
        let plans = plans(appearance)?;
        let opened = Arc::new(AtomicUsize::new(0));
        for role in [Role::Initiator, Role::Responder] {
            let prepared = match role {
                Role::Initiator => Prepared::secure_udp_common_client(
                    plans.generic.clone(),
                    client(false, 11, 22, hs::Profile::Ik)?,
                    attachment(&opened, PacketLayer::Ip, true),
                )?,
                Role::Responder => Prepared::secure_udp_common_server(
                    plans.generic.clone(),
                    server(22, 11, hs::Profile::Ik)?,
                    attachment(&opened, PacketLayer::Ip, true),
                )?,
            };
            assert!(prepared.secure_udp_common());
            assert_eq!(
                prepared.setup_timeout(),
                plans.generic.connection().handshake_timeout
            );
            let Transport::SecureUdpCommon(profile) = &prepared.data.transport else {
                return Err("transaction constructor selected another backend".into());
            };
            assert_eq!(profile.configuration()?, plans.generic.configuration()?);
            assert_eq!(profile.initial(), plans.generic.initial());
            assert_eq!(profile.peers(), plans.generic.peers());
            assert_eq!(profile.catalog().root(), plans.generic.catalog().root());
            let contract = profile.runtime_contract(role)?;
            assert_eq!(contract.role(), role);
            assert_eq!(contract.expected_configuration(), profile.configuration()?);
            assert_eq!(contract.initial(), profile.initial());
            for descriptor in profile.catalog().descriptors() {
                let value = l2tunnel::record_configuration::Configuration::new(
                    profile.envelope(),
                    *descriptor,
                )?;
                assert_eq!(contract.resolve(value)?, value);
            }
            assert_eq!(opened.load(Ordering::SeqCst), 0);
            let cloned = prepared.clone();
            assert!(Arc::ptr_eq(&prepared.identity, &cloned.identity));
            assert!(Arc::ptr_eq(&prepared.data, &cloned.data));
            assert!(cloned.open_native().is_err());
            assert_eq!(opened.fetch_sub(1, Ordering::SeqCst), 1);
        }
    }
    Ok(())
}

#[tokio::test]
async fn native_provisioning_preserves_disconnected_api4_without_device_io() -> Result {
    let plans = plans(Appearance::QuicLike)?;
    let opens = Arc::new(AtomicUsize::new(0));
    let plan = Prepared::secure_udp_common_client(
        plans.generic,
        client(false, 11, 22, hs::Profile::Ik)?,
        attachment(&opens, PacketLayer::Ip, true),
    )?;
    let (handle, _owner) = crate::service::channel_with_plan(plan);
    let state = handle
        .lifecycle_request(crate::local::Request {
            version: crate::local::COMMON_VERSION,
            action: crate::local::Action::Status {},
        })
        .await;
    assert!(state.ok);
    let observed = state.state.ok_or("missing idle state")?;
    assert_eq!(observed.phase, "disconnected");
    assert!(observed.common.is_none());
    assert_eq!(opens.load(Ordering::SeqCst), 0);
    Ok(())
}

/// Version-5 keyed submission with the retained plan: acceptance without
/// waiting, exact replay of an identical retry and conflict for another
/// action under the same key. The owner is never polled, so no I/O occurs.
#[tokio::test]
async fn version5_retained_submission_replays_identical_retry_only() -> Result {
    use crate::local::{OperationAction, OperationRequest};
    let plans = plans(Appearance::QuicLike)?;
    let opens = Arc::new(AtomicUsize::new(0));
    let plan = Prepared::secure_udp_common_client(
        plans.generic,
        client(false, 11, 22, hs::Profile::Ik)?,
        attachment(&opens, PacketLayer::Ip, true),
    )?;
    let (handle, _owner) = crate::service::channel_with_plan(plan);
    let submit = |action| handle.operations_request(OperationRequest::new(action));
    let first = submit(OperationAction::Reconnect { request_key: 1 }).await;
    assert_eq!((first.ok, first.code.as_str()), (true, "accepted"));
    let accepted = first.operation.ok_or("missing accepted operation")?;
    assert_eq!((accepted.id, accepted.kind.as_str()), (1, "connect"));
    assert_eq!(accepted.state, "pending");
    assert!(accepted.deadline_ms.is_some());
    let cursor = handle.event_cursor();
    let retry = submit(OperationAction::Reconnect { request_key: 1 }).await;
    assert_eq!(retry.code, "accepted");
    assert_eq!(retry.operation.map(|state| state.id), Some(1));
    assert_eq!(handle.event_cursor(), cursor, "a replay records no event");
    let other = submit(OperationAction::Disconnect { request_key: 1 }).await;
    assert_eq!((other.ok, other.code.as_str()), (false, "conflict"));
    let busy = submit(OperationAction::Connect { request_key: 2 }).await;
    assert_eq!(busy.code, "busy");
    let skipped = submit(OperationAction::Connect { request_key: 9 }).await;
    assert_eq!(skipped.code, "future_key");
    let status = submit(OperationAction::Status {}).await;
    let status = status.status.ok_or("missing status")?;
    assert_eq!(
        (status.phase.as_str(), status.operation),
        ("preparing", Some(1))
    );
    assert_eq!(opens.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn current_common_plans_keep_explicit_carrier_appearance() -> Result {
    let quic = plans(Appearance::QuicLike)?;
    let media = plans(Appearance::MediaLike)?;
    assert_eq!(
        quic.generic.settings().cover.appearance,
        Appearance::QuicLike
    );
    assert_eq!(
        media.generic.settings().cover.appearance,
        Appearance::MediaLike
    );
    assert_ne!(
        quic.generic.configuration()?,
        media.generic.configuration()?
    );
    let opened = Arc::new(AtomicUsize::new(0));
    for plans in [quic, media] {
        let prepared = Prepared::secure_udp_common_client(
            plans.generic,
            client(false, 11, 22, hs::Profile::Ik)?,
            attachment(&opened, PacketLayer::Ip, true),
        )?;
        assert!(prepared.secure_udp_common());
        assert!(matches!(
            &prepared.data.transport,
            Transport::SecureUdpCommon(_)
        ));
    }
    assert_eq!(opened.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn transaction_member_and_actual_ordered_pins_are_checked_before_provider() -> Result {
    for appearance in [Appearance::QuicLike, Appearance::MediaLike] {
        let plans = plans(appearance)?;
        let opened = Arc::new(AtomicUsize::new(0));
        refused(
            Prepared::secure_udp_common_client(
                plans.generic.clone(),
                client(true, 11, 22, hs::Profile::Ik)?,
                attachment(&opened, PacketLayer::Ip, true),
            ),
            io::ErrorKind::PermissionDenied,
        )?;
        // Own key, remote pin, and reversed role ordering are independently invalid.
        for (local, remote) in [(33, 22), (11, 33), (22, 11)] {
            refused(
                Prepared::secure_udp_common_client(
                    plans.generic.clone(),
                    client(false, local, remote, hs::Profile::Ik)?,
                    attachment(&opened, PacketLayer::Ip, true),
                ),
                io::ErrorKind::PermissionDenied,
            )?;
        }
        for (local, remote) in [(33, 11), (22, 33), (11, 22)] {
            refused(
                Prepared::secure_udp_common_server(
                    plans.generic.clone(),
                    server(local, remote, hs::Profile::Ik)?,
                    attachment(&opened, PacketLayer::Ip, true),
                ),
                io::ErrorKind::PermissionDenied,
            )?;
        }
        assert_eq!(opened.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[test]
fn transaction_pattern_layer_and_readiness_refusals_do_not_open_attachment() -> Result {
    for appearance in [Appearance::QuicLike, Appearance::MediaLike] {
        let plans = plans(appearance)?;
        let opened = Arc::new(AtomicUsize::new(0));
        for role in [Role::Initiator, Role::Responder] {
            for (pattern, layer, readable) in [
                (hs::Profile::IkPsk2, PacketLayer::Ip, true),
                (hs::Profile::Ik, PacketLayer::Ethernet, true),
                (hs::Profile::Ik, PacketLayer::Ip, false),
            ] {
                let result = match role {
                    Role::Initiator => Prepared::secure_udp_common_client(
                        plans.generic.clone(),
                        client(false, 11, 22, pattern)?,
                        attachment(&opened, layer, readable),
                    ),
                    Role::Responder => Prepared::secure_udp_common_server(
                        plans.generic.clone(),
                        server(22, 11, pattern)?,
                        attachment(&opened, layer, readable),
                    ),
                };
                refused(result, io::ErrorKind::InvalidInput)?;
            }
        }
        assert_eq!(opened.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[test]
fn transaction_server_clone_retains_one_real_admission_owner_and_new_plan_does_not() -> Result {
    let plans = plans(Appearance::MediaLike)?;
    let opened = Arc::new(AtomicUsize::new(0));
    let prepared = Prepared::secure_udp_common_server(
        plans.generic.clone(),
        server(22, 11, hs::Profile::Ik)?,
        attachment(&opened, PacketLayer::Ip, true),
    )?;
    let Endpoint::SecureServer(original) = &prepared.data.endpoint else {
        return Err("missing server credentials".into());
    };
    *original.admission.try_lock()? = Some(crate::secure_udp::Server::new(
        plans.generic.settings(),
        plans.generic.peers(),
        original.credentials.admission(),
        original.credentials.cookie(),
        tokio::time::Instant::now(),
    )?);
    let cloned = prepared.clone();
    let Endpoint::SecureServer(retained) = &cloned.data.endpoint else {
        return Err("clone changed server endpoint".into());
    };
    assert!(std::ptr::eq(original.as_ref(), retained.as_ref()));
    assert!(retained.admission.try_lock()?.is_some());
    let fresh = Prepared::secure_udp_common_server(
        plans.generic,
        server(22, 11, hs::Profile::Ik)?,
        attachment(&opened, PacketLayer::Ip, true),
    )?;
    assert!(!Arc::ptr_eq(&prepared.identity, &fresh.identity));
    let Endpoint::SecureServer(fresh) = &fresh.data.endpoint else {
        return Err("new plan changed server endpoint".into());
    };
    assert!(fresh.admission.try_lock()?.is_none());
    assert_eq!(opened.load(Ordering::SeqCst), 0);
    Ok(())
}
