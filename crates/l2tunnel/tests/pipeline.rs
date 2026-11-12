//! Integration boundaries between pure modules, without claiming a network runtime.
use l2tunnel::{core::Epoch, management as mg, mux::Mux, qos, vxlan, wire};

#[test]
fn scheduled_vxlan_bytes_survive_mux_and_wire_without_control_authority() -> Result<(), String> {
    let map = |error| format!("{error:?}");
    let vni = vxlan::Vni::new(4097).map_err(map)?;
    let mut frame = vec![0xab; 128];
    // Include an experimental management-looking EtherType and discriminator.
    frame[12..18].copy_from_slice(&[0x88, 0xb5, b'L', b'2', b'M', b'C']);
    let mut vx = vec![0; frame.len() + vxlan::HEADER_LEN];
    vxlan::encode(vni, &frame, &mut vx).map_err(|e| format!("{e:?}"))?;
    let class = qos::ClassId::new(1);
    let flow = qos::FlowId::new(1);
    let mut scheduler = qos::Scheduler::new(
        qos::SchedulerConfig {
            base_quantum_bytes: 64,
            max_classes: 1,
            max_flows: 2,
            max_packet_bytes: 1600,
            max_queued_bytes: 3200,
            max_queued_packets: 2,
            per_flow_bytes: 3200,
            per_flow_packets: 2,
        },
        &[qos::ClassConfig {
            id: class,
            weight: 1,
        }],
    )
    .map_err(|e| e.to_string())?;
    scheduler
        .register_flow(qos::FlowConfig {
            id: flow,
            class,
            weight: 1,
        })
        .map_err(|e| e.to_string())?;
    scheduler.enqueue(flow, vx).map_err(|e| format!("{e:?}"))?;
    let scheduled = scheduler
        .dequeue()
        .map_err(|e| e.to_string())?
        .ok_or("missing scheduled packet")?;
    let mut mux = Mux::new(2, 3200, 2)?;
    mux.push(1, scheduled.payload)
        .map_err(|e| format!("{e:?}"))?;
    let (_, payload) = mux.pop().ok_or("missing MUX packet")?;
    let wire = wire::encode(
        wire::Header {
            kind: wire::Kind::Data,
            epoch: Epoch(7),
            packet_number: 11,
            session: [8; 16],
            lane: 0,
        },
        &payload,
    )
    .map_err(|e| format!("{e:?}"))?;
    let (header, decoded) = wire::decode(&wire, 1600).map_err(|e| format!("{e:?}"))?;
    assert_eq!(header.kind, wire::Kind::Data);
    let packet = vxlan::decode(decoded, 1600).map_err(|e| format!("{e:?}"))?;
    assert_eq!(packet.vni, vni);
    assert_eq!(packet.ethernet, frame);
    let mut gate = mg::AdmissionGate::new(
        mg::SessionBinding {
            session: mg::SessionId([8; 16]),
            remote_role: mg::Role::Client,
            remote_endpoint: mg::EndpointId(1),
            local_endpoint: mg::EndpointId(2),
        },
        mg::Limits::default(),
    )
    .map_err(|e| e.to_string())?;
    assert_eq!(
        gate.admit(mg::Ingress::UserTraffic, packet.ethernet),
        Err(mg::Error::UntrustedOrigin)
    );
    Ok(())
}
