use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn config(profile: Profile) -> PipelineConfig {
    PipelineConfig {
        profile,
        flows: FlowTableConfig {
            capacity: 2,
            channels: 2,
            mapping: Mapping::ConnectionRoundRobin,
            idle_timeout: Duration::from_secs(1),
        },
        parse: ParseLimits {
            max_packet_bytes: 64,
            ..ParseLimits::default()
        },
        queue: QueueLimits {
            bytes: 128,
            packets: 2,
        },
    }
}

fn tun(max_weight: u32, base_quantum_bytes: u32) -> Profile {
    Profile::TunDrr(TunQosConfig {
        max_weight,
        base_quantum_bytes,
        per_flow: QueueLimits {
            bytes: 64,
            packets: 1,
        },
    })
}

fn expect_error(config: PipelineConfig, expected: PipelineError) {
    assert_eq!(config.validate(), Err(expected));
    assert!(matches!(Pipeline::new(config), Err(error) if error == expected));
}

#[test]
fn scalar_pipeline_validation_preserves_parser_flow_and_policy_precedence() {
    let mut value = config(Profile::TapSystem);
    value.parse.max_packet_bytes = 13;
    value.parse.max_vlan_tags = 5;
    value.flows.capacity = 0;
    expect_error(value, PipelineError::InvalidConfig);
    value.parse.max_packet_bytes = 14;
    expect_error(value, PipelineError::Parse(ParseError::InvalidLimits));
    value.parse.max_vlan_tags = 0;
    expect_error(
        value,
        PipelineError::Flow(l2tunnel_packet::FlowError::InvalidConfig),
    );

    value.profile = tun(0, 0);
    value.parse.max_packet_bytes = 20;
    expect_error(
        value,
        PipelineError::Flow(l2tunnel_packet::FlowError::InvalidConfig),
    );
    value.flows.capacity = 2;
    expect_error(value, PipelineError::InvalidConfig);
    value.profile = tun(1, 0);
    expect_error(
        value,
        PipelineError::QosConfig(l2tunnel_qos::ConfigError::ZeroLimit),
    );
    value.profile = Profile::TunDrr(TunQosConfig {
        per_flow: QueueLimits {
            bytes: 19,
            packets: 1,
        },
        max_weight: 1,
        base_quantum_bytes: 1,
    });
    expect_error(
        value,
        PipelineError::QosConfig(l2tunnel_qos::ConfigError::InconsistentBounds),
    );
}

#[test]
fn scalar_maximum_weight_check_keeps_qos_configuration_before_flow_arithmetic() {
    let Ok(maximum_packet) = usize::try_from(1_u64 << 34) else {
        return;
    };
    let mut value = config(Profile::TunDrr(TunQosConfig {
        max_weight: u32::MAX,
        base_quantum_bytes: u32::MAX,
        per_flow: QueueLimits {
            bytes: maximum_packet,
            packets: 1,
        },
    }));
    value.parse.max_packet_bytes = maximum_packet;
    value.queue.bytes = maximum_packet;
    expect_error(
        value,
        PipelineError::QosFlow(l2tunnel_qos::FlowError::Arithmetic),
    );
    if let Profile::TunDrr(ref mut policy) = value.profile {
        policy.per_flow.packets = 0;
    }
    expect_error(
        value,
        PipelineError::QosConfig(l2tunnel_qos::ConfigError::ZeroLimit),
    );
}

#[test]
fn minimum_native_formats_and_extreme_weight_preserve_actual_fresh_handoff() -> TestResult {
    let mut tap = config(Profile::TapSystem);
    tap.parse.max_packet_bytes = 14;
    tap.flows.channels = 256;
    tap.queue = QueueLimits {
        bytes: 14,
        packets: 1,
    };
    let mut ethernet = vec![0; 14];
    ethernet[12..14].copy_from_slice(&0x88b5_u16.to_be_bytes());
    tap.validate()?;
    let mut pipeline = Pipeline::new(tap)?;
    assert_eq!(pipeline.registered_flows(), 0);
    let admitted = pipeline.enqueue(ethernet.clone(), Duration::ZERO)?;
    assert_eq!(
        admitted.binding,
        Binding {
            id: FlowId(1),
            channel: 0
        }
    );
    assert_eq!(
        pipeline.dequeue()?.ok_or("missing TAP frame")?.payload,
        ethernet
    );
    assert_eq!(pipeline.usage(), QueueUsage::default());

    let mut ip = config(tun(u32::MAX, u32::MAX));
    ip.parse.max_packet_bytes = 20;
    let mut packet = vec![0; 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&20_u16.to_be_bytes());
    packet[9] = 255;
    packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
    packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
    ip.validate()?;
    let mut pipeline = Pipeline::new(ip)?;
    assert_eq!(pipeline.registered_flows(), 0);
    let admitted = pipeline.enqueue_weighted(packet.clone(), u32::MAX, Duration::ZERO)?;
    assert_eq!(
        admitted.binding,
        Binding {
            id: FlowId(1),
            channel: 0
        }
    );
    assert_eq!(
        pipeline.dequeue()?.ok_or("missing TUN packet")?.payload,
        packet
    );
    assert_eq!(pipeline.usage(), QueueUsage::default());
    Ok(())
}
