//! Bounded construction/projection evidence; no running authentication or device proof.

use super::*;
use l2tunnel::swift_configuration::{Catalog, Descriptor};
use l2tunnel_core::ConfigDigest;
use l2tunnel_management::{control_streams, delivery, messages, transaction};
use std::time::Duration;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn profile(
    appearance: l2tunnel_cover::Appearance,
    count: usize,
    report: Option<Duration>,
) -> Result<Profile> {
    let (legacy, peers) = crate::secure_udp::profile::tests::fixture(
        l2tunnel_udp_control::Path {
            client: "127.0.0.1:41421".parse()?,
            server: "127.0.0.1:41422".parse()?,
        },
        appearance,
        l2tunnel_identity::MemberPublicKey([7; 32]),
    )?;
    let mut settings = legacy.settings();
    settings.application = ConfigDigest([31; 32]);
    let mut initiator = legacy.runtime(Role::Initiator);
    let mut responder = legacy.runtime(Role::Responder);
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
    let mut descriptors = (0..count)
        .map(|index| {
            let mut direction = forward;
            direction.bytes_per_second += u64::try_from(index)?;
            Ok(Descriptor::new(1500, direction, reverse)?)
        })
        .collect::<Result<Vec<_>>>()?;
    let initial = *descriptors.last().ok_or("missing initial descriptor")?;
    // Input order and chosen initial member differ from printed canonical order.
    descriptors.reverse();
    initiator.send = initial.forward();
    initiator.receive = initial.reverse();
    responder.send = initial.reverse();
    responder.receive = initial.forward();
    for template in [&mut initiator, &mut responder] {
        let stream = messages::Settings {
            delivery: delivery::Settings {
                wire_overhead: template.control.wire_overhead + control_streams::HEADER_BYTES,
                ..template.control
            },
            path_mtu: template.path_mtu,
            max_message_bytes: 4096,
            max_outbound_messages: 4,
            max_outbound_bytes: 131_072,
            max_fragments: 32,
            max_reassembly_bytes: 16_384,
            max_incomplete_messages: 2,
            message_lifetime: Duration::from_secs(5),
            work_per_call: 8,
        };
        template.streams = Some(l2tunnel_runtime::secure_udp::control::Settings {
            streams: [stream; 3],
        });
        template.report_interval = report;
    }
    Ok(Profile::new(
        legacy.connection(),
        settings,
        peers,
        initiator,
        responder,
        Catalog::new(initial, &descriptors)?,
        crate::secure_udp::transaction_profile::Parameters {
            protocol: transaction::Settings {
                retry_ms: 10,
                phase_timeout_ms: 500,
                reconcile_timeout_ms: 1000,
            },
            max_operation_ms: 1500,
            retained_bytes: 16 << 20,
        },
    )?)
}

fn assert_no_private_fields(value: &Value) -> Result {
    let object = value.as_object().ok_or("output object")?;
    for field in [
        "private",
        "psk",
        "cookie",
        "admission",
        "path",
        "device",
        "control_socket",
        "credentials",
        "error",
    ] {
        assert!(
            !object.contains_key(field),
            "unexpected output field {field}"
        );
    }
    Ok(())
}

#[test]
fn inspection_preserves_all64_canonical_values_complete_identities_parameters_and_bounds() -> Result
{
    for appearance in [
        l2tunnel_cover::Appearance::QuicLike,
        l2tunnel_cover::Appearance::MediaLike,
    ] {
        let profile = profile(appearance, 64, None)?;
        let expected = profile.catalog().configurations(profile.envelope());
        for role in [Role::Initiator, Role::Responder] {
            let value = inspection(&profile, role)?;
            assert_eq!(value["event"], "secure_udp_transaction_plan");
            assert_eq!(value["schema"], 1);
            assert_eq!(value["requested"], true);
            assert_eq!(value["validated"], true);
            assert_eq!(value["authenticated"], false);
            assert_eq!(value["resource_preallocation_complete"], false);
            assert_eq!(value["catalog_members"], 64);
            assert_eq!(
                value["configuration"],
                serde_json::to_value(profile.configuration()?.0)?
            );
            assert_eq!(
                value["envelope"],
                serde_json::to_value(profile.envelope().as_bytes())?
            );
            assert_eq!(
                value["catalog"],
                serde_json::to_value(profile.catalog().root().as_bytes())?
            );
            assert_eq!(
                value["data_digest"],
                serde_json::to_value(profile.data_digest().0)?
            );
            let actual = value["configurations"]
                .as_array()
                .ok_or("complete catalog array")?;
            assert_eq!(actual.len(), 64);
            for (encoded, expected) in actual.iter().zip(&expected) {
                let value =
                    CanonicalConfiguration::parse(encoded.as_str().ok_or("canonical string")?)?
                        .configuration()?;
                assert_eq!(&value, expected);
                assert_eq!(value.envelope(), profile.envelope());
                assert_eq!(
                    value
                        .descriptor()
                        .forward()
                        .records
                        .codec
                        .repair_denominator,
                    3
                );
                assert_eq!(value.descriptor().reverse().records.channels, 3);
            }
            let initial =
                CanonicalConfiguration::parse(value["initial"].as_str().ok_or("initial string")?)?
                    .configuration()?;
            assert_eq!(initial, profile.initial());
            assert_eq!(&initial, expected.last().ok_or("last canonical member")?);
            assert_eq!(value["parameters"]["retry_ms"], 10);
            assert_eq!(value["parameters"]["phase_timeout_ms"], 500);
            assert_eq!(value["parameters"]["reconcile_timeout_ms"], 1000);
            assert_eq!(value["parameters"]["max_operation_ms"], 1500);
            assert_eq!(value["parameters"]["retained_bytes"], 16 << 20);
            let path = profile.settings().gate.path;
            let (local, peer) = match role {
                Role::Initiator => (path.client, path.server),
                Role::Responder => (path.server, path.client),
            };
            assert_eq!(value["local"], local.to_string());
            assert_eq!(value["peer"], peer.to_string());
            assert_eq!(value["report_interval"], Value::Null);
            assert_no_private_fields(&value)?;
            assert!(serde_json::to_vec(&value)?.len() <= MAX_VALUE_BYTES);
            let mut with_health = value;
            with_health.as_object_mut().ok_or("object")?.insert(
                "log_health".into(),
                json!({
                    "disabled": true, "write_errors":u64::MAX, "broken_pipe":u64::MAX,
                    "would_block":u64::MAX, "projection_errors":u64::MAX, "dropped_lines":u64::MAX,
                    "dropped_bytes":u64::MAX, "written_bytes":u64::MAX, "queue_bytes_high":u64::MAX,
                }),
            );
            assert!(serde_json::to_vec(&with_health)?.len() < 128 * 1024);
        }
    }
    Ok(())
}

#[test]
fn report_cadence_is_exact_local_metadata_and_does_not_change_identity() -> Result {
    let first = profile(l2tunnel_cover::Appearance::QuicLike, 2, None)?;
    let cadence = Duration::new(2, 13_001);
    let second = profile(l2tunnel_cover::Appearance::QuicLike, 2, Some(cadence))?;
    assert_eq!(first.envelope(), second.envelope());
    assert_eq!(first.configuration()?, second.configuration()?);
    assert_eq!(first.data_digest(), second.data_digest());
    for role in [Role::Initiator, Role::Responder] {
        let value = inspection(&second, role)?;
        assert_eq!(
            value["report_interval"],
            json!({"seconds":2,"nanoseconds":13001})
        );
        assert_eq!(
            second.runtime_contract(role)?.config().report_interval,
            Some(cadence)
        );
    }
    Ok(())
}

#[test]
fn serialized_value_bound_counts_json_escaping_and_keeps_health_headroom() -> Result {
    let exact = Value::String("x".repeat(MAX_VALUE_BYTES - 2));
    assert_eq!(serde_json::to_vec(&bounded(exact)?)?.len(), MAX_VALUE_BYTES);
    assert!(bounded(Value::String("x".repeat(MAX_VALUE_BYTES - 1))).is_err());
    // Raw text fits; its JSON escape expansion must still be rejected.
    assert!(bounded(Value::String("\n".repeat(MAX_VALUE_BYTES / 2))).is_err());
    let mut count = Count(MAX_VALUE_BYTES);
    assert!(count.write(&[1]).is_err());
    assert_eq!(count.0, MAX_VALUE_BYTES);
    assert_eq!(MAX_VALUE_BYTES + 2048, 128 * 1024);
    Ok(())
}

#[test]
fn direct_canonical_parse_uses_the_same_strict_complete_decoder_as_serde() -> Result {
    let profile = profile(l2tunnel_cover::Appearance::QuicLike, 2, None)?;
    let value = CanonicalConfiguration::from_configuration(profile.initial())?;
    assert_eq!(CanonicalConfiguration::parse(value.as_str())?, value);
    assert_eq!(
        CanonicalConfiguration::parse(value.as_str())?.configuration()?,
        profile.initial()
    );
    assert_eq!(
        serde_json::from_value::<CanonicalConfiguration>(json!(value.as_str()))?,
        value
    );
    let mut wrong_prefix = value.as_str().to_owned();
    wrong_prefix.replace_range(..2, "00");
    let mut wrong_fraction = value.as_str().to_owned();
    wrong_fraction.replace_range(208..224, "0000000000000000");
    for text in [
        String::new(),
        value.as_str()[..607].to_owned(),
        format!("{}0", value.as_str()),
        value.as_str().to_ascii_uppercase(),
        format!(" {}", &value.as_str()[1..]),
        wrong_prefix,
        wrong_fraction,
        "é".repeat(304),
    ] {
        assert!(CanonicalConfiguration::parse(&text).is_err());
        assert!(serde_json::from_value::<CanonicalConfiguration>(json!(text)).is_err());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod events {
    use super::*;
    use crate::service::Failure;
    use l2tunnel_core::Epoch;
    use l2tunnel_runtime::secure_udp::{establish, member, transport};
    use l2tunnel_security as security;
    use l2tunnel_swift::records;
    use std::sync::Arc;

    fn frame(appearance: l2tunnel_cover::Appearance) -> Result<SecureUdpTransactionFrame> {
        let profile = Arc::new(profile(appearance, 2, None)?);
        let config = profile.runtime_contract(Role::Initiator)?.config();
        let settings = profile.settings();
        // Explicit logical observation fixture, not a fabricated authentication proof.
        let binding = security::SessionBinding {
            session: security::SessionId([1; 16]),
            transcript: [2; 32],
        };
        let info = member::Info {
            binding,
            authenticated: settings
                .runtime(Role::Initiator, profile.peers())?
                .expected_binding(profile.peers(), binding.session)?,
            member: settings.member,
            peers: profile.peers(),
            role: Role::Initiator,
            local_addr: settings.gate.path.client,
            peer_addr: settings.gate.path.server,
            statistics: establish::Statistics::default(),
        };
        let runtime = transport::TransactionSnapshot {
            running: true,
            elapsed_micros: 12345,
            info,
            configuration: profile.configuration()?,
            physical_scope: l2tunnel::secure_record::Scope {
                epoch: security::Epoch(1),
                configuration: security::ConfigDigest(profile.data_digest().0),
            },
            current: profile.initial(),
            requested: None,
            operation: None,
            epoch: Epoch(1),
            phase: transaction::Phase::Idle,
            storage: l2tunnel_swift::storage::Usage {
                limit_bytes: 16 << 20,
                fixed_bytes: 1,
                external_bytes: 2,
                engine_bytes: 3,
                building_bytes: 0,
                peak_bytes: 6,
            },
            resource_preallocation_complete: false,
            send: config.send,
            receive: config.receive,
            swift: records::Stats::default(),
            swift_unconfirmed: 7,
            channels: Vec::new(),
            performance: transport::Performance::default(),
            control: l2tunnel_recovery::Retained::default(),
            counters: transport::Counters {
                native_written: 3,
                native_pending_packets: 2,
                wire_packets: 11,
                wire_bytes: 2200,
                ..transport::Counters::default()
            },
            liveness: transport::Liveness {
                outstanding: Some(8),
                deadline_micros: Some(20000),
                last_verified_micros: Some(12000),
                last_pong_micros: Some(11000),
            },
            terminal: None,
        };
        Ok(SecureUdpTransactionFrame {
            requested: profile,
            info,
            runtime: Some(runtime),
            generation: 55,
            service_terminal: None,
        })
    }

    #[test]
    fn actual_status_is_wrapped_without_replacing_runtime_or_native_observations() -> Result {
        for appearance in [
            l2tunnel_cover::Appearance::QuicLike,
            l2tunnel_cover::Appearance::MediaLike,
        ] {
            let mut frame = frame(appearance)?;
            frame
                .runtime
                .as_mut()
                .ok_or("runtime")?
                .swift
                .receiver
                .packets = 999;
            let expected = serde_json::to_value(frame.status()?)?;
            for event in [ready(&frame, 55)?, status(&frame, 55)?] {
                assert_eq!(event["schema"], 1);
                assert_eq!(event["status"], expected);
                assert_eq!(event["status"]["native"]["written"], 3);
                assert_eq!(event["status"]["elapsed_micros"], 12345);
                assert_eq!(event["status"]["resource_preallocation_complete"], false);
                assert!(serde_json::to_vec(&event)?.len() <= MAX_VALUE_BYTES);
                assert_no_private_fields(&event)?;
            }
            assert_eq!(ready(&frame, 55)?["event"], "secure_udp_transaction_ready");
            assert_eq!(
                status(&frame, 55)?["event"],
                "secure_udp_transaction_status"
            );
        }
        Ok(())
    }

    #[test]
    fn wrong_generation_and_false_readiness_never_emit_an_event() -> Result {
        let frame = frame(l2tunnel_cover::Appearance::QuicLike)?;
        assert!(ready(&frame, 54).is_err());
        assert!(status(&frame, 54).is_err());
        assert!(terminal(&frame, 54, Terminal::Aborted).is_err());
        let mut absent = frame.clone();
        absent.runtime = None;
        assert!(ready(&absent, 55).is_err());
        let observed = status(&absent, 55)?;
        assert!(observed["status"]["current"].is_null());
        assert!(observed["status"]["elapsed_micros"].is_null());
        let mut stopped = frame.clone();
        stopped.runtime.as_mut().ok_or("runtime")?.running = false;
        assert!(ready(&stopped, 55).is_err());
        let mut failed = frame.clone();
        failed.runtime.as_mut().ok_or("runtime")?.terminal =
            Some(transport::StopReason::NativeStall);
        assert!(ready(&failed, 55).is_err());
        let mut released = frame;
        released.service_terminal = Some(Terminal::Aborted);
        assert!(ready(&released, 55).is_err());
        Ok(())
    }

    #[test]
    fn exact_terminal_overlay_preserves_original_time_counters_and_runtime_reason() -> Result {
        let mut frame = frame(l2tunnel_cover::Appearance::MediaLike)?;
        let runtime = frame.runtime.as_mut().ok_or("runtime")?;
        runtime.running = false;
        runtime.terminal = Some(transport::StopReason::NativeStall);
        let outcome = Terminal::Failed(Failure {
            kind: io::ErrorKind::TimedOut,
        });
        assert!(terminal(&frame, 55, outcome).is_err());
        frame.service_terminal = Some(outcome);
        assert!(terminal(&frame, 55, Terminal::Aborted).is_err());
        let event = terminal(&frame, 55, outcome)?;
        assert_eq!(event["event"], "secure_udp_transaction_terminal");
        assert_eq!(event["outcome"], format!("{outcome:?}"));
        assert_eq!(event["status"], serde_json::to_value(frame.status()?)?);
        assert_eq!(event["status"]["terminal"], "NativeStall");
        assert_eq!(event["status"]["elapsed_micros"], 12345);
        assert_eq!(event["status"]["native"]["written"], 3);
        assert_eq!(event["status"]["running"], false);
        assert_ne!(
            event["status"]["terminal"],
            event["status"]["service_terminal"]
        );
        Ok(())
    }
}
