//! Independent canonical/profile and exact-envelope boundary fixtures.
use super::*;
use crate::{Compression, RuntimeConfig};
use l2tunnel_flow_control::Credit;
use l2tunnel_tcp_proxy::{Scope, Window, adaptive};
use std::time::Duration;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

pub(in crate::proxy) fn config() -> io::Result<Config> {
    Ok(Config {
        fixed: super::super::Config::new(
            RuntimeConfig {
                layer: PacketLayer::Ip,
                max_packet: 1600,
                compression: Compression::None,
                queue_packets: 4,
                poll_interval: Duration::from_millis(1),
            },
            Duplex::Full,
            super::super::RoutePolicy::new(Vec::new())?,
        )?,
        measured: measurement::MeasuredConfig {
            allocation: adaptive::Config {
                target: adaptive::TargetConfig {
                    initial: Credit {
                        bytes: 32768,
                        records: 32,
                    },
                    minimum: Credit {
                        bytes: 2048,
                        records: 1,
                    },
                    session_cap: Credit {
                        bytes: 1048576,
                        records: 1024,
                    },
                    per_flow_cap: Credit {
                        bytes: 65536,
                        records: 64,
                    },
                    policy_cap: Credit {
                        bytes: 1048576,
                        records: 1024,
                    },
                    queue_allowance_bytes: 65536,
                    queue_delay_target_micros: 5000,
                    many_flow_step: Credit {
                        bytes: 2048,
                        records: 1,
                    },
                    few_flow_threshold: 4,
                    max_flows: 16,
                    bootstrap_rtt_micros: 1000,
                    recovery_rtts: 2,
                },
                minimum_per_flow: Window {
                    bytes: 2048,
                    records: 1,
                },
            },
            ownership: measurement::OwnerConfig {
                pending_ttl_micros: 20000,
                probe_interval_micros: 10000,
                probe_timeout_micros: 30000,
                handoff_timeout_micros: 50000,
                emission_interval_micros: 10000,
                max_records_per_interval: 8,
            },
            observation: measurement::ObservationConfig {
                report_interval_micros: 10000,
                sample_ttl_micros: 40000,
                demand_idle_micros: 20000,
                rate_interval_micros: 10000,
                rate_bins: 4,
            },
        },
        service: ServicePolicy {
            report_work_per_turn: 4,
            admission_work_per_turn: 4,
            callback_work_per_turn: 4,
            plan_interval_micros: 10000,
            status_interval_micros: 20000,
        },
    })
}

fn hex(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    if !input.len().is_multiple_of(2) {
        return Err("odd literal hex fixture".into());
    }
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect()
}

#[test]
fn independent_literal_canonical_profile_pins_fixed_and_measured_digests() -> TestResult {
    let cfg = config()?;
    // Independently calculated with Python hashlib/struct from the reviewed
    // canonical field schema and explicit fixture values, not Rust's encoder.
    let expected = hex(concat!(
        "6c3274756e6e656c2f74756e2d7463702d70726f78792d61646170746976652f76312f66697865642d72696e67732f6d",
        "656173757265642d72656c6179001c7bd285da9de9ac6e05facec873c2b3ff3ed6a736bec4b0be4c5ccb21d11a830102",
        "010100000000000080000000000000000020000000000000080000000000000000010000000000100000000000000000",
        "040000000000000100000000000000000040000000000010000000000000000004000000000000010000000000000000",
        "1388000000000000080000000000000000010000000000000004000000000000001000000000000003e8000000000000",
        "0002000000000000080000000000000000010000000000004e2000000000000027100000000000007530000000000000",
        "c3500000000000002710000000000000000800000000000027100000000000009c400000000000004e20000000000000",
        "271000000000000000040000000000000004000000000000000400000000000000040000000000002710000000000000",
        "4e20000000000000002c0000000000000004000000000000001800000000000000300000000000000068000000000000",
        "003800000000000000020000000000000001000000000000000100000000000000010000000000000068",
    ))?;
    assert_eq!(expected.len(), 474);
    assert_eq!(cfg.canonical_bytes()?, expected);
    let fixed = super::super::session_config(&cfg.fixed)?;
    assert_eq!(
        fixed.digest.0.as_slice(),
        hex("1c7bd285da9de9ac6e05facec873c2b3ff3ed6a736bec4b0be4c5ccb21d11a83")?
    );
    let measured = session_config(&cfg)?;
    assert_eq!(measured.layer, PacketLayer::Ip);
    assert_eq!(
        measured.digest.0.as_slice(),
        hex("b422312517fa6653716e28abd2bf97b17093bc2c80b09e41d4b95ce5abc2f786")?
    );
    assert_ne!(fixed, measured);
    assert_eq!(super::super::session_config(&cfg.fixed)?, fixed);
    Ok(())
}

#[test]
fn every_measured_and_service_field_is_bound_or_rejected() -> TestResult {
    let baseline = config()?;
    let original = session_config(&baseline)?;
    macro_rules! mutation {
        ($($field:ident).+, $value:expr) => {{
            let mut changed = baseline.clone();
            changed.$($field).+ = $value;
            if let Ok(binding) = session_config(&changed) {
                assert_ne!(binding, original, "unbound field {}", stringify!($($field).+));
                assert_ne!(changed.canonical_bytes()?, baseline.canonical_bytes()?);
            } else {
                assert!(changed.validate().is_err());
            }
        }};
    }
    mutation!(measured.allocation.target.initial.bytes, 32769);
    mutation!(measured.allocation.target.initial.records, 33);
    mutation!(measured.allocation.target.minimum.bytes, 2049);
    mutation!(measured.allocation.target.minimum.records, 2);
    mutation!(measured.allocation.target.session_cap.bytes, 1048575);
    mutation!(measured.allocation.target.session_cap.records, 1023);
    mutation!(measured.allocation.target.per_flow_cap.bytes, 65535);
    mutation!(measured.allocation.target.per_flow_cap.records, 63);
    mutation!(measured.allocation.target.policy_cap.bytes, 1048575);
    mutation!(measured.allocation.target.policy_cap.records, 1023);
    mutation!(measured.allocation.target.queue_allowance_bytes, 65537);
    mutation!(measured.allocation.target.queue_delay_target_micros, 5001);
    mutation!(measured.allocation.target.many_flow_step.bytes, 2049);
    mutation!(measured.allocation.target.many_flow_step.records, 2);
    mutation!(measured.allocation.target.few_flow_threshold, 3);
    mutation!(measured.allocation.target.max_flows, 15);
    mutation!(measured.allocation.target.bootstrap_rtt_micros, 1001);
    mutation!(measured.allocation.target.recovery_rtts, 3);
    mutation!(measured.allocation.minimum_per_flow.bytes, 2047);
    mutation!(measured.allocation.minimum_per_flow.records, 2);
    mutation!(measured.ownership.pending_ttl_micros, 20001);
    mutation!(measured.ownership.probe_interval_micros, 10001);
    mutation!(measured.ownership.probe_timeout_micros, 30001);
    mutation!(measured.ownership.handoff_timeout_micros, 50001);
    mutation!(measured.ownership.emission_interval_micros, 10001);
    mutation!(measured.ownership.max_records_per_interval, 9);
    mutation!(measured.observation.report_interval_micros, 10001);
    mutation!(measured.observation.sample_ttl_micros, 40001);
    mutation!(measured.observation.demand_idle_micros, 20001);
    mutation!(measured.observation.rate_interval_micros, 10001);
    mutation!(measured.observation.rate_bins, 5);
    mutation!(service.report_work_per_turn, 5);
    mutation!(service.admission_work_per_turn, 5);
    mutation!(service.callback_work_per_turn, 5);
    mutation!(service.plan_interval_micros, 10001);
    mutation!(service.status_interval_micros, 20001);
    // Existing fixed fields enter the new profile through the independently
    // pinned fixed digest, including duplex, native close policy and common QoS.
    mutation!(fixed.duplex, Duplex::Half);
    mutation!(
        fixed.native.time_wait_reset_policy,
        l2tunnel_tcp_proxy::TimeWaitResetPolicy::IgnoreInTimeWait
    );
    mutation!(fixed.mux.channels, 17);
    mutation!(fixed.timeouts.shutdown, Duration::from_secs(119));
    Ok(())
}

#[test]
fn duration_conversion_and_service_sweep_boundaries_are_exact() -> TestResult {
    let baseline = config()?;
    for extra in [1, 999, 1001] {
        let mut cfg = baseline.clone();
        cfg.fixed.runtime.poll_interval += Duration::from_nanos(extra);
        // Legacy fixed policy binds nanoseconds; new measured policy cannot
        // silently truncate them into its microsecond observation clock.
        assert!(super::super::session_config(&cfg.fixed).is_ok());
        assert!(session_config(&cfg).is_err());
    }
    for slot in 0..4 {
        let mut cfg = baseline.clone();
        let timer = match slot {
            0 => &mut cfg.fixed.timeouts.startup,
            1 => &mut cfg.fixed.timeouts.control_idle,
            2 => &mut cfg.fixed.timeouts.shutdown,
            _ => &mut cfg.fixed.relay.admission_timeout,
        };
        *timer += Duration::from_nanos(1);
        assert!(session_config(&cfg).is_err());
    }
    let mut exact = baseline.clone();
    exact.measured.observation.report_interval_micros = 4000;
    exact.validate()?; // Sixteen configured slots, four visits each millisecond.
    exact.measured.observation.report_interval_micros = 3999;
    assert!(exact.validate().is_err());
    let mut callbacks = baseline.clone();
    callbacks.service.callback_work_per_turn = 1;
    callbacks.measured.ownership.handoff_timeout_micros = 33001;
    callbacks.validate()?; // 2*16+1 slots must finish strictly before expiry.
    callbacks.measured.ownership.handoff_timeout_micros = 33000;
    assert!(callbacks.validate().is_err());
    for interval in [Duration::ZERO, Duration::from_micros(10001)] {
        let mut cfg = baseline.clone();
        cfg.fixed.runtime.poll_interval = interval;
        assert!(cfg.validate().is_err());
    }
    Ok(())
}

#[test]
fn invalid_geometry_and_hard_memory_limits_fail_before_authority() -> TestResult {
    let baseline = config()?;
    let memory = baseline.validate()?;
    assert_eq!(memory.token_slots, 33);
    assert_eq!(memory.immutable_proof_bytes, 3432);
    assert_eq!(memory.all_measurement_copy_bytes, 4992);
    assert_eq!(memory.controller.flow_slots, 16);
    assert_eq!(memory.controller.rate_bins, 4);
    assert!(memory.handoff_bytes >= memory.immutable_proof_bytes);
    assert!(memory.base_and_controller_bytes > memory.fixed.payload_bytes);
    assert!(memory.base_and_controller_bytes <= 268435456);
    let mut maximum = baseline.clone();
    maximum.fixed.relay.max_flows = 64;
    maximum.measured.allocation.target.max_flows = 64;
    maximum.measured.allocation.target.session_cap = Credit {
        bytes: 4194304,
        records: 4096,
    };
    maximum.measured.allocation.target.policy_cap = maximum.measured.allocation.target.session_cap;
    maximum.service.report_work_per_turn = 8;
    let memory = maximum.validate()?;
    assert_eq!(memory.token_slots, 129);
    assert!(memory.base_and_controller_bytes <= 268435456);
    maximum.fixed.relay.max_flows = 65;
    maximum.measured.allocation.target.max_flows = 65;
    assert!(maximum.validate().is_err());
    let invalid: &[fn(&mut Config)] = &[
        |c| c.fixed.runtime.layer = PacketLayer::Ethernet,
        |c| c.fixed.mux.queue_bytes = usize::MAX,
        |c| c.fixed.mux.per_flow_bytes = 1,
        |c| c.fixed.mux.queue_records = 0,
        |c| c.fixed.relay.max_flows = usize::MAX,
        |c| c.measured.allocation.target.max_flows = usize::MAX,
        |c| c.measured.allocation.target.bootstrap_rtt_micros = u64::MAX,
        |c| c.measured.allocation.minimum_per_flow.bytes = 1599,
        |c| c.measured.allocation.target.session_cap.bytes = 262143,
        |c| c.measured.allocation.target.per_flow_cap.bytes = 65537,
        |c| c.measured.ownership.max_records_per_interval = 257,
        |c| c.measured.ownership.pending_ttl_micros = 999,
        |c| c.measured.observation.rate_bins = 17,
        |c| c.measured.observation.sample_ttl_micros = 29999,
        |c| c.measured.observation.demand_idle_micros = 9999,
        |c| c.measured.observation.rate_interval_micros = u64::MAX,
        |c| c.service.report_work_per_turn = 0,
        |c| c.service.admission_work_per_turn = 65,
        |c| c.service.callback_work_per_turn = 0,
        |c| c.service.plan_interval_micros = 999,
        |c| c.service.status_interval_micros = 120000001,
    ];
    for (index, change) in invalid.iter().enumerate() {
        let mut cfg = baseline.clone();
        change(&mut cfg);
        assert!(cfg.validate().is_err(), "invalid geometry {index}");
        assert!(cfg.canonical_bytes().is_err(), "canonical geometry {index}");
        assert!(session_config(&cfg).is_err(), "binding geometry {index}");
    }
    Ok(())
}

fn echo() -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut bytes = vec![0; measurement::wire::ECHO_BYTES];
    measurement::wire::encode(
        measurement::wire::Record {
            header: measurement::wire::Header {
                scope: Scope {
                    session: [0x11; 16],
                    epoch: 1,
                    flow: 1,
                },
                direction: measurement::wire::Direction::OriginatorToAcceptor,
                serial: 7,
            },
            body: measurement::wire::Body::EchoRequest { nonce: 9 },
        },
        &mut bytes,
    )?;
    Ok(bytes)
}

#[test]
fn literal_v2_measurement_envelope_has_exact_offsets_and_failure_atomic_output() -> TestResult {
    let cfg = config()?;
    let body = echo()?;
    let value = envelope::StructuralEnvelope {
        kind: envelope::Kind::Measurement,
        channel: 3,
        flow: 1,
        body: &body,
    };
    let expected = hex(concat!(
        "4c5450570202000000030000000000000000000100000038",
        "4c54504d0102010011111111111111111111111111111111",
        "0000000000000001000000000000000100000000000000070000000000000009",
    ))?;
    assert_eq!(expected.len(), 80);
    let mut out = [0xa5; 256];
    assert_eq!(envelope::encode(&cfg, value, &mut out)?, expected.len());
    assert_eq!(&out[..80], expected);
    assert!(out[80..].iter().all(|byte| *byte == 0xa5));
    assert_eq!(envelope::decode(&cfg, &expected)?, value);
    for end in 0..expected.len() {
        assert!(envelope::decode(&cfg, &expected[..end]).is_err());
        let mut small = vec![0xa5; end];
        assert!(envelope::encode(&cfg, value, &mut small).is_err());
        assert!(small.iter().all(|byte| *byte == 0xa5));
    }
    let mut excess = expected.clone();
    excess.push(0);
    assert!(envelope::decode(&cfg, &excess).is_err());
    for offset in [0, 4, 5, 6, 7, 10, 11, 20, 23, 24 + 7] {
        let mut bad = expected.clone();
        bad[offset] = 0xff;
        assert!(
            envelope::decode(&cfg, &bad).is_err(),
            "accepted byte {offset}"
        );
    }
    let mut bad_body = body.clone();
    bad_body[32..40].copy_from_slice(&2u64.to_be_bytes());
    let mut zero_nonce = body.clone();
    zero_nonce[48..].fill(0);
    for bad in [
        envelope::StructuralEnvelope {
            channel: cfg.fixed.mux.channels,
            ..value
        },
        envelope::StructuralEnvelope { flow: 0, ..value },
        envelope::StructuralEnvelope { flow: 17, ..value },
        envelope::StructuralEnvelope {
            body: &bad_body,
            ..value
        },
        envelope::StructuralEnvelope {
            body: &zero_nonce,
            ..value
        },
        envelope::StructuralEnvelope { body: &[], ..value },
        envelope::StructuralEnvelope {
            kind: envelope::Kind::Transparent,
            ..value
        },
    ] {
        let mut untouched = [0xa5; 256];
        assert!(envelope::encode(&cfg, bad, &mut untouched).is_err());
        assert_eq!(untouched, [0xa5; 256]);
    }
    Ok(())
}

#[test]
fn common_class_is_explicit_and_nested_measurement_magic_confers_no_authority() -> TestResult {
    let cfg = config()?;
    let body = echo()?;
    // Class zero is still transparent work, even when payload begins LTPM.
    // A decoder returns only borrowed structural claims; it never grants ingress.
    for (kind, flow) in [(envelope::Kind::Transparent, 0), (envelope::Kind::Proxy, 1)] {
        let value = envelope::StructuralEnvelope {
            kind,
            channel: 0,
            flow,
            body: &body,
        };
        let mut out = vec![0; 256];
        let len = envelope::encode(&cfg, value, &mut out)?;
        assert_eq!(envelope::decode(&cfg, &out[..len])?, value);
    }
    let maximum = cfg.fixed.max_user()? - envelope::HEADER_BYTES;
    let payload = vec![0x3c; maximum];
    let value = envelope::StructuralEnvelope {
        kind: envelope::Kind::Transparent,
        channel: 15,
        flow: 0,
        body: &payload,
    };
    let mut out = vec![0xa5; maximum + envelope::HEADER_BYTES];
    let len = envelope::encode(&cfg, value, &mut out)?;
    assert_eq!(len, out.len());
    assert_eq!(envelope::decode(&cfg, &out)?, value);
    let oversized = vec![0x3c; maximum + 1];
    let mut untouched = vec![0xa5; out.len() + 1];
    assert!(
        envelope::encode(
            &cfg,
            envelope::StructuralEnvelope {
                body: &oversized,
                ..value
            },
            &mut untouched
        )
        .is_err()
    );
    assert!(untouched.iter().all(|byte| *byte == 0xa5));
    Ok(())
}
