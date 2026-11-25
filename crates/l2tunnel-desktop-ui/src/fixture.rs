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

pub fn snapshot(
    generation: u64,
    catalog: [u8; 32],
    epoch: Option<u64>,
) -> io::Result<l2tunnel_client_core::local::Snapshot> {
    let initial = configuration(1_250_001)?;
    let common = l2tunnel_client_core::secure_udp::common_status::Status {
        generation,
        next_request_key: Some(1),
        carrier: "quic-like".into(),
        original_carrier: None,
        raw_carrier: None,
        maintained_carrier: None,
        algorithm: "swift".into(),
        protection: "aead".into(),
        compact_wire: None,
        backend: "common".into(),
        running: true,
        elapsed_micros: None,
        terminal: None,
        service_terminal: None,
        session: [0; 16],
        transcript: [0; 32],
        outer: [0; 32],
        member: [0; 32],
        initiator_noise: [0; 32],
        responder_noise: [0; 32],
        local: "127.0.0.1:24440".into(),
        peer: "127.0.0.1:24441".into(),
        configuration: [0; 32],
        catalog,
        catalog_members: 1,
        device_mtu: None,
        initial,
        kcp_like_initial: None,
        kcp_like_current: None,
        kcp_like_requested: None,
        current: None,
        requested: None,
        epoch,
        phase: None,
        operation: None,
        physical_scope: None,
        storage: None,
        send_rate: None,
        receive_rate: None,
        send_channels: None,
        receive_channels: None,
        resource_preallocation_complete: true,
        native_storage_capacity_bytes: None,
        workspace_capacity_bytes: None,
        loop_input_capacity_bytes: None,
        wire: None,
        native: None,
        native_delivery: [None, None],
        control: None,
        security: None,
        liveness: None,
        path_recovery: None,
        configuration_change: true,
        coordinator: true,
        reconnect: true,
        cross_profile_switching: false,
        retained_state_recovery: false,
        fresh_rekey: false,
        rolling_work: None,
        rolling_wire_profiles: Default::default(),
        rolling_repair_budget: None,
        striped_sources: None,
        rolling_native_reorder: None,
        rolling_delivery: None,
        research_recovery: None,
        credit: None,
        ack_coalescing: None,
        rolling_ingress: None,
        connection_ingress: None,
        connections: None,
        connection_reuse: None,
        connection_reuse_result: None,
        rolling_fragments: None,
        rolling_scheduler_steps: None,
        rolling_work_used: None,
        udp_rolling_pressure_yields: None,
        catalog_page: None,
        result: None,
    };
    Ok(l2tunnel_client_core::local::Snapshot {
        epoch: epoch.unwrap_or(0),
        phase: "ready".into(),
        compression: l2tunnel_client_core::local::Compression::Off,
        proxy: None,
        common: Some(common),
    })
}
