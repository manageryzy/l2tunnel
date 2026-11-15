use super::*;
use l2tunnel::{pipeline, record_configuration as common};
use l2tunnel_core::{Duplex, traffic};
use std::time::Duration;

#[test]
fn same_flow_recovery_observation_has_exact_bounded_fields_without_authority() -> io::Result<()> {
    let value = PathRecovery {
        unavailable: true,
        send_failures: 2,
        retry_attempts: 1,
        resumptions: 0,
        last_error: Some("NetworkDown".into()),
        retry_at_micros: Some(123_456),
    };
    let encoded = serde_json::to_string(&value).map_err(io::Error::other)?;
    assert_eq!(
        encoded,
        r#"{"unavailable":true,"send_failures":2,"retry_attempts":1,"resumptions":0,"last_error":"NetworkDown","retry_at_micros":123456}"#
    );
    assert_eq!(
        serde_json::from_str::<PathRecovery>(&encoded).map_err(io::Error::other)?,
        value
    );
    assert!(encoded.len() < 256);
    let mut invalid = serde_json::to_value(value).map_err(io::Error::other)?;
    invalid["authenticated"] = serde_json::json!(true);
    assert!(serde_json::from_value::<PathRecovery>(invalid).is_err());
    Ok(())
}
pub(crate) fn descriptor(rate: u64) -> io::Result<common::Descriptor> {
    let queue = pipeline::QueueLimits {
        bytes: 65536,
        packets: 8,
    };
    let common = common::CommonDirection::new(
        traffic::TrafficPolicy {
            layer: traffic::NetworkLayer::Tun,
            tcp: traffic::TcpControl::System,
            qos: traffic::Qos::WeightedDeficit,
        },
        pipeline::PipelineConfig {
            profile: pipeline::Profile::TunDrr(pipeline::TunQosConfig {
                base_quantum_bytes: 1500,
                max_weight: 1,
                per_flow: queue,
            }),
            flows: pipeline::FlowTableConfig {
                capacity: 8,
                channels: 2,
                mapping: pipeline::Mapping::Crc32,
                idle_timeout: Duration::from_secs(5),
            },
            parse: pipeline::ParseLimits {
                max_packet_bytes: 1500,
                ..pipeline::ParseLimits::default()
            },
            queue,
        },
        rate,
        65536,
        common::NativeWindow::Disabled,
    )
    .map_err(io::Error::other)?;
    let codec = l2tunnel_swift::Config {
        datagram_bytes: 1200,
        window: 7,
        repair_numerator: 1,
        repair_denominator: 3,
        flow_sources: 64,
        queue_bytes: 8192,
        max_packet: 1500 + l2tunnel_swift::header::MAX_EXPANSION,
        flush_micros: 123,
        feedback_micros: 5003,
        tail_micros: 10001,
        min_rto_micros: 20003,
        max_rto_micros: 1_000_007,
    };
    let records = l2tunnel_swift::records::Config {
        channels: 2,
        layer: l2tunnel_swift::records::Layer::Ip,
        max_native: 1500,
        codec,
    };
    common::Descriptor::new(
        1500,
        Duplex::Full,
        common,
        common,
        common::Profile::Swift {
            forward: records,
            reverse: records,
        },
    )
    .map_err(io::Error::other)
}
#[test]
fn canonical_v4_rejects_lengths_case_padding_and_legacy_action_versions() -> io::Result<()> {
    let value = Configuration::new(
        common::EnvelopeDigest::new([0x17; 32]),
        descriptor(1_250_001)?,
    )
    .map_err(io::Error::other)?;
    let canonical = CanonicalConfiguration::from_configuration(value)?;
    assert_eq!(canonical.as_str().len(), 2608);
    assert_eq!(canonical.configuration()?, value);
    for text in [
        canonical.as_str()[..2606].to_owned(),
        format!("{}00", canonical.as_str()),
        canonical.as_str().to_uppercase(),
    ] {
        assert!(CanonicalConfiguration::parse(&text).is_err());
    }
    let mut padding = canonical.as_str().as_bytes().to_vec();
    padding[2607] = b'1';
    assert!(
        CanonicalConfiguration::parse(std::str::from_utf8(&padding).map_err(io::Error::other)?)
            .is_err()
    );
    let action = crate::local::Action::SwitchCommonConfiguration {
        configuration: canonical,
        request_key: 7,
    };
    for version in 1..=3 {
        assert!(
            serde_json::from_value::<crate::local::Request>(
                serde_json::json!({"version":version,"action":action})
            )
            .is_err()
        );
    }
    assert!(
        serde_json::from_value::<crate::local::Request>(
            serde_json::json!({"version":4,"action":action})
        )
        .is_ok()
    );
    assert!(serde_json::from_str::<crate::local::Response>(r#"{"version":3,"ok":true,"code":"ok","state":{"epoch":1,"phase":"forwarding","compression":"off","common":null}}"#).is_err());
    Ok(())
}
#[test]
fn v4_literal_catalog_request_and_legacy_status_bytes_are_unchanged() -> io::Result<()> {
    let request = crate::local::Request {
        version: 4,
        action: crate::local::Action::CommonCatalog {
            generation: 7,
            catalog: [0; 32],
            offset: 60,
            limit: 4,
        },
    };
    let expected = r#"{"version":4,"action":{"command":"common_catalog","generation":7,"catalog":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"offset":60,"limit":4}}"#;
    assert_eq!(
        serde_json::to_string(&request).map_err(io::Error::other)?,
        expected
    );
    for version in 1..=3 {
        let request = crate::local::Request {
            version,
            action: crate::local::Action::Status {},
        };
        assert_eq!(
            serde_json::to_string(&request).map_err(io::Error::other)?,
            format!("{{\"version\":{version},\"action\":{{\"command\":\"status\"}}}}")
        );
    }
    Ok(())
}
