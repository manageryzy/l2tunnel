//! Test-only: one valid complete canonical configuration, built like the
//! client-core status tests build theirs.
use l2tunnel::{pipeline, record_configuration as common};
use l2tunnel_client_core::secure_udp::common_status::CanonicalConfiguration;
use l2tunnel_core::{Duplex, traffic};
use std::{io, time::Duration};

pub fn configuration(rate: u64) -> io::Result<CanonicalConfiguration> {
    let queue = pipeline::QueueLimits {
        bytes: 65536,
        packets: 8,
    };
    let direction = common::CommonDirection::new(
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
    let descriptor = common::Descriptor::new(
        1500,
        Duplex::Full,
        direction,
        direction,
        common::Profile::Swift {
            forward: records,
            reverse: records,
        },
    )
    .map_err(io::Error::other)?;
    let value = common::Configuration::new(common::EnvelopeDigest::new([0x17; 32]), descriptor)
        .map_err(io::Error::other)?;
    CanonicalConfiguration::from_configuration(value)
}
