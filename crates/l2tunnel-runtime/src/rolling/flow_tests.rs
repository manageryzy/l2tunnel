use super::*;

struct Device {
    input: Option<Vec<u8>>,
}
impl PacketDevice for Device {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ip
    }
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        Ok(self.input.take().map(|bytes| {
            out[..bytes.len()].copy_from_slice(&bytes);
            bytes.len()
        }))
    }
    fn transmit(&mut self, _: &[u8]) -> io::Result<()> {
        Ok(())
    }
}
fn packet(port: u16) -> Vec<u8> {
    let mut bytes = vec![0; 28];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&28u16.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 17;
    bytes[12..16].copy_from_slice(&[10, 0, 0, 1]);
    bytes[16..20].copy_from_slice(&[10, 0, 1, 1]);
    bytes[20..22].copy_from_slice(&port.to_be_bytes());
    bytes[22..24].copy_from_slice(&5000u16.to_be_bytes());
    bytes[24..26].copy_from_slice(&8u16.to_be_bytes());
    bytes
}
#[test]
fn rolling_default_flow_1025_retains_ingress_after_idle() -> io::Result<()> {
    let rt = RuntimeConfig {
        layer: PacketLayer::Ip,
        max_packet: 1600,
        compression: crate::Compression::None,
        queue_packets: 2,
        poll_interval: Duration::from_millis(1),
    };
    let transport = udp::Config::new(
        Duplex::Full,
        l2tunnel_datagram::CoverProfile::OpenVpnLike,
        l2tunnel_datagram::Protection::HmacSha256,
        576,
        false,
    )?;
    let config = Config::for_udp(rt, transport, 4, crate::rolling::config::test_delivery(rt))?;
    assert_eq!(config.pipeline.flows.capacity, 1024);
    let mut pipeline = Pipeline::new(config.pipeline).map_err(io::Error::other)?;
    for port in 10000..11024 {
        pipeline
            .enqueue(packet(port), Duration::ZERO)
            .map_err(io::Error::other)?;
        pipeline.dequeue().map_err(io::Error::other)?;
    }
    let original = packet(20000);
    let mut device = Device {
        input: Some(original.clone()),
    };
    let mut ingress = None;
    let mut buffer = vec![0; l2tunnel_device::READ_BUFFER_BYTES];
    ingress_step(
        &mut device,
        &mut pipeline,
        &mut ingress,
        &mut buffer,
        rt,
        config,
        Duration::from_secs(61),
    )?;
    assert_eq!(ingress, Some(original.clone()));
    let mut cursor = None;
    retire_registration(&mut pipeline, None, &mut cursor, Duration::from_secs(61))?;
    ingress_step(
        &mut device,
        &mut pipeline,
        &mut ingress,
        &mut buffer,
        rt,
        config,
        Duration::from_secs(61),
    )?;
    assert!(ingress.is_none());
    assert_eq!(
        pipeline
            .dequeue()
            .map_err(io::Error::other)?
            .ok_or_else(|| invalid("retried"))?
            .payload,
        original
    );
    Ok(())
}

#[test]
fn rolling_retirement_preserves_selected_and_1100_successive_originals() -> io::Result<()> {
    let rt = RuntimeConfig {
        layer: PacketLayer::Ip,
        max_packet: 1600,
        compression: crate::Compression::None,
        queue_packets: 2,
        poll_interval: Duration::from_millis(1),
    };
    let transport = udp::Config::new(
        Duplex::Full,
        l2tunnel_datagram::CoverProfile::OpenVpnLike,
        l2tunnel_datagram::Protection::HmacSha256,
        576,
        false,
    )?;
    let mut config = Config::for_udp(rt, transport, 4, crate::rolling::config::test_delivery(rt))?;
    config.pipeline.flows.idle_timeout = Duration::from_millis(1);
    let mut pipeline = Pipeline::new(config.pipeline).map_err(io::Error::other)?;
    let metadata = pipeline
        .enqueue(packet(9999), Duration::ZERO)
        .map_err(io::Error::other)?;
    let selected = pipeline
        .dequeue()
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("selected"))?;
    let mut cursor = None;
    for _ in 0..3 {
        retire_registration(
            &mut pipeline,
            Some(&selected),
            &mut cursor,
            Duration::from_millis(1),
        )?;
    }
    assert_eq!(
        pipeline
            .flow(&metadata.classification.key)
            .map(|v| v.binding),
        Some(metadata.binding)
    );
    assert_eq!(selected.payload, packet(9999));
    let mut device = Device { input: None };
    let mut ingress = None;
    let mut buffer = vec![0; l2tunnel_device::READ_BUFFER_BYTES];
    let mut previous = metadata.binding.id.0;
    for offset in 0..1100u16 {
        let now = Duration::from_millis(u64::from(offset) + 2);
        retire_registration(&mut pipeline, None, &mut cursor, now)?;
        let original = packet(10000 + offset);
        device.input = Some(original.clone());
        ingress_step(
            &mut device,
            &mut pipeline,
            &mut ingress,
            &mut buffer,
            rt,
            config,
            now,
        )?;
        assert!(ingress.is_none());
        let output = pipeline
            .dequeue()
            .map_err(io::Error::other)?
            .ok_or_else(|| invalid("dequeued"))?;
        assert_eq!(output.payload, original);
        assert!(output.metadata.binding.id.0 > previous);
        previous = output.metadata.binding.id.0;
        assert!(pipeline.registered_flows() <= 2);
    }
    Ok(())
}
