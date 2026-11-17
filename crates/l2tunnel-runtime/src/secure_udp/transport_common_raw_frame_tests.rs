//! Current single-protection replacement for standalone Frame/ARQ/FEC raw entries.
use super::*;

pub(super) struct LayerDevice {
    pub inner: Device,
    pub layer: PacketLayer,
}
impl AsRawFd for LayerDevice {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.inner.as_raw_fd()
    }
}
impl PacketDevice for LayerDevice {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        self.layer
    }
    fn receive(&mut self, output: &mut [u8]) -> io::Result<Option<usize>> {
        self.inner.receive(output)
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<()> {
        self.inner.transmit(packet)
    }
}

pub(super) fn payload(port: u16, number: u8) -> Vec<u8> {
    let mut bytes = frame(port, number);
    bytes.resize(4000, number);
    bytes[16..18].copy_from_slice(&3986_u16.to_be_bytes());
    bytes[38..40].copy_from_slice(&3966_u16.to_be_bytes());
    bytes[24..26].fill(0);
    let sum: u32 = bytes[14..34]
        .chunks_exact(2)
        .map(|part| u32::from(u16::from_be_bytes([part[0], part[1]])))
        .sum();
    let sum = (sum & 0xffff) + (sum >> 16);
    let sum = (sum & 0xffff) + (sum >> 16);
    bytes[24..26].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    // Meaningful terminal zeros must survive both shorter-only and raw bodies.
    bytes[3996..].fill(0);
    bytes
}

pub(super) fn catalog(original: &Catalog, layer: PacketLayer) -> Result<Catalog> {
    let base = original
        .descriptors()
        .iter()
        .find(|d| matches!(d.profile(), c::Profile::Aligned { .. }))
        .ok_or("actual Aligned owner")?;
    let c::Profile::Aligned { forward, reverse } = *base.profile() else {
        return Err("actual Aligned profile".into());
    };
    let common = |role| -> Result<c::CommonDirection> {
        let direction = base.direction(role);
        let old = direction.common();
        let mut pipeline = old.pipeline();
        pipeline.parse.max_packet_bytes = 4096;
        let traffic = if layer == PacketLayer::Ip {
            pipeline.profile =
                l2tunnel_pipeline::Profile::TunDrr(l2tunnel_pipeline::TunQosConfig {
                    base_quantum_bytes: 1500,
                    max_weight: 1,
                    per_flow: pipeline.queue,
                });
            core::traffic::TrafficPolicy {
                layer: core::traffic::NetworkLayer::Tun,
                tcp: core::traffic::TcpControl::System,
                qos: core::traffic::Qos::WeightedDeficit,
            }
        } else {
            core::traffic::TrafficPolicy::tap()
        };
        Ok(c::CommonDirection::new(
            traffic,
            pipeline,
            old.bytes_per_second(),
            old.burst_bytes(),
            c::NativeWindow::Delivery(l2tunnel::flow_control::delivery_window::Config {
                target_bandwidth_bps: 80_000_000,
                bootstrap_rtt_micros: 70_000,
                min_rtt_micros: 1,
                max_rtt_micros: 1_000_000,
                headroom_percent: 125,
                minimum_bytes: 4096,
                max_inflight_bytes: 4096 * 8,
                max_records: 8,
                max_packet_bytes: 4096,
                metadata_limit_bytes: 1 << 20,
                sample_ttl_micros: 4_000_000,
                flush_timeout_micros: 5_000_000,
            }),
        )?)
    };
    let mut descriptors = Vec::new();
    for lz4 in [false, true] {
        for cauchy in [false, true] {
            let change = |mut config: l2tunnel_aligned::Config| {
                use l2tunnel_aligned::NativePolicy;
                config.native_policy = match (layer, lz4) {
                    (PacketLayer::Ethernet, false) => NativePolicy::RawEthernet,
                    (PacketLayer::Ethernet, true) => NativePolicy::Lz4Ethernet,
                    (PacketLayer::Ip, false) => NativePolicy::RawIp,
                    (PacketLayer::Ip, true) => NativePolicy::Lz4Ip,
                };
                config.receiver.body.max_frame_bytes = 4096;
                config.receiver.body.predictive = false;
                config.receiver.body.elide_payload_length = false;
                config.receiver.body.timestamp_pair_dictionary = false;
                config.receiver.body.independent_short_frame_bytes = 0;
                config.receiver.lifetime_ticks = 5_000_000;
                config.recovery.repair_symbols = usize::from(cauchy);
                config
            };
            descriptors.push(c::Descriptor::new(
                base.path_mtu(),
                base.duplex(),
                common(mg::Role::Client)?,
                common(mg::Role::Server)?,
                c::Profile::Aligned {
                    forward: change(forward),
                    reverse: change(reverse),
                },
            )?);
        }
    }
    Ok(Catalog::new(descriptors[0], &descriptors)?)
}

#[tokio::test]
async fn current_raw_frame_none_lz4_direct_arq_cauchy_native_delivery_full_half_tap_tun() -> Result
{
    for half in [false, true] {
        for layer in [PacketLayer::Ethernet, PacketLayer::Ip] {
            eprintln!("current raw Frame matrix half={half}, layer={layer:?}");
            let selection = record::compact::Selection {
                protection: if half {
                    security::compact::Protection::HmacSha256
                } else {
                    security::compact::Protection::ChaCha20Poly1305
                },
                limits: security::compact::Selection {
                    max_forward_packets: 4096,
                    max_failed_checks: 128,
                },
            };
            let pair =
                Box::pin(establish_original_pair_inner(half, selection, Some(layer))).await?;
            Box::pin(exercise_established_raw(half, pair)).await?;
        }
    }
    Ok(())
}
