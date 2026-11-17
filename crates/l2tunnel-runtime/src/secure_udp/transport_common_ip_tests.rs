//! Actual current Common IP codecs over authenticated test session material and UDP.
//! Unix packet-device evidence is not privileged TUN-device qualification.
use super::*;
use l2tunnel::record_configuration as c;
use l2tunnel_codec::{aligned_envelope, aligned_receiver as rx, packed_envelope};
use l2tunnel_core::traffic;
use l2tunnel_pipeline as pipeline;

// The native-IP literals also occur in tcp_header::ip_tests. Expected context
// and delta bytes below are literals, not output from another Rust encoder.
const FIRST: &str = "45000037ffff4000400626bf0a0000010a00000201bb1388fffffffe000000098018ffff5c5b00000101080affffffff000000070102f0";
const NEXT: &str = "4500003600004000400626c00a0000010a00000201bb138800000001000000098018ffff4c5e00000101080a000000000000000700ff";
const CONTEXT: &str = "08003445000037ffff4000400626bf0a0000010a00000201bb1388fffffffe000000098018ffff5c5b00000101080affffffff00000007";
// The second payload shrinks from three bytes to two, so its length cannot
// be elided even when the selected policy enables that optimization.
const DELTA: &[u8] = &[9, 0, 2, 0x43, 1, 3, 1, 0, 0xff];

fn hex(value: &str) -> Result<Vec<u8>> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect()
}

struct IpDevice(Device);
impl AsRawFd for IpDevice {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.0.as_raw_fd()
    }
}
impl PacketDevice for IpDevice {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ip
    }
    fn receive(&mut self, bytes: &mut [u8]) -> io::Result<Option<usize>> {
        self.0.receive(bytes)
    }
    fn transmit(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.0.transmit(bytes)
    }
}

fn ip_fixture(fixture: Fixture) -> Result<Fixture<IpDevice>> {
    let convert = |endpoint: Endpoint| -> Result<Endpoint<IpDevice>> {
        let Endpoint {
            socket,
            driver,
            device,
            host,
            original,
        } = endpoint;
        let native_fd = device.get_ref().as_raw_fd();
        let device = AsyncFd::with_interest(
            IpDevice(device.into_inner()),
            Interest::READABLE.add(Interest::WRITABLE),
        )?;
        assert_eq!(device.get_ref().as_raw_fd(), native_fd);
        assert_eq!(device.get_ref().layer(), PacketLayer::Ip);
        assert_eq!(
            driver
                .common
                .as_ref()
                .ok_or("Common absent")?
                .contract
                .native_layer(),
            PacketLayer::Ip
        );
        Ok(Endpoint {
            socket,
            driver,
            device,
            host,
            original,
        })
    };
    let [a, b] = fixture.endpoints;
    Ok(Fixture {
        endpoints: [convert(a)?, convert(b)?],
        now: fixture.now,
    })
}

fn selected_ip(kind: cover::Appearance) -> Result<([CommonTransactionContract; 2], C)> {
    let originals = udp_values(kind)?;
    let direction = |old: &c::CommonDirection| -> Result<c::CommonDirection> {
        let mut queues = old.pipeline();
        queues.profile = pipeline::Profile::TunDrr(pipeline::TunQosConfig {
            base_quantum_bytes: 1500,
            max_weight: 1,
            per_flow: queues.queue,
        });
        Ok(c::CommonDirection::new(
            traffic::TrafficPolicy {
                layer: traffic::NetworkLayer::Tun,
                tcp: traffic::TcpControl::System,
                qos: traffic::Qos::WeightedDeficit,
            },
            queues,
            old.bytes_per_second(),
            old.burst_bytes(),
            old.native_window(),
        )?)
    };
    let mut descriptors = Vec::new();
    for value in &originals[1..] {
        let old = value.descriptor();
        let profile = match *old.profile() {
            c::Profile::Aligned {
                mut forward,
                mut reverse,
            } => {
                forward.native_policy = l2tunnel_aligned::NativePolicy::IpHeaders;
                forward.receiver.body.elide_payload_length = true;
                reverse.native_policy = l2tunnel_aligned::NativePolicy::IpHeaders;
                reverse.receiver.body.elide_payload_length = true;
                c::Profile::Aligned { forward, reverse }
            }
            c::Profile::Packed {
                mut forward,
                mut reverse,
            } => {
                forward.base.native_policy = l2tunnel_aligned::NativePolicy::IpHeaders;
                forward.base.receiver.body.elide_payload_length = true;
                reverse.base.native_policy = l2tunnel_aligned::NativePolicy::IpHeaders;
                reverse.base.receiver.body.elide_payload_length = true;
                c::Profile::Packed { forward, reverse }
            }
            _ => return Err("expected maintained Aligned/Packed configurations".into()),
        };
        descriptors.push(c::Descriptor::new(
            old.path_mtu(),
            old.duplex(),
            direction(old.direction(mg::Role::Client).common())?,
            direction(old.direction(mg::Role::Server).common())?,
            profile,
        )?);
    }
    let catalog = Catalog::new(descriptors[0], &descriptors)?;
    let templates = contracts_with_catalog(kind, catalog.clone(), 16)?;
    let make = |role: security::Role, mut resources: Config| -> Result<CommonTransactionContract> {
        // These Swift fields are inactive templates, never the selected codec.
        resources.send.records.layer = records::Layer::Ip;
        resources.receive.records.layer = records::Layer::Ip;
        let value = CommonTransactionContract::new_compact_wire(
            security::ConfigDigest([3; 32]),
            role,
            [resources; 2],
            appearance(kind, role == security::Role::Initiator)?,
            false,
            c::EnvelopeDigest::new([0x39; 32]),
            catalog.clone(),
            TransactionSettings {
                protocol: transaction::Settings {
                    retry_ms: 10,
                    phase_timeout_ms: 1000,
                    reconcile_timeout_ms: 2000,
                },
                max_operation_ms: 3000,
                retained_bytes: 256 << 20,
            },
            default_record_selection(),
        )?;
        assert_eq!(value.native_layer(), PacketLayer::Ip);
        Ok(value)
    };
    let contracts = [
        make(security::Role::Initiator, templates[0].resources())?,
        make(security::Role::Responder, templates[1].resources())?,
    ];
    Ok((
        contracts,
        C::new(c::EnvelopeDigest::new([0x39; 32]), descriptors[1])?,
    ))
}

struct Captured {
    wire: Vec<u8>,
    body: Vec<u8>,
}
async fn retain_source(fixture: &mut Fixture<IpDevice>) -> Result<Captured> {
    for _ in 0..16 {
        fixture.now = fixture.now.checked_add(1000).ok_or("fixture time")?;
        let now = fixture.now;
        let endpoint = &mut fixture.endpoints[0];
        endpoint.driver.progress_common(now)?;
        assert!(
            !endpoint
                .driver
                .send_common_user_with(now, |_| Err(io::ErrorKind::WouldBlock.into()))?
        );
        let runtime = endpoint.driver.common.as_ref().ok_or("Common absent")?;
        let Some(pending) = runtime.sealed.as_ref() else {
            continue;
        };
        let emission = pending
            .carrier
            .as_ref()
            .ok_or("actual physical token absent")?
            .emission();
        assert!(matches!(
            emission.kind,
            l2tunnel::record_engine::EmissionKind::Source(_)
        ));
        let captured = Captured {
            wire: runtime.wire[..pending.sealed.bytes].to_vec(),
            body: endpoint.driver.buffers.frame[..emission.bytes].to_vec(),
        };
        let number = endpoint.driver.records.next_number(Class::User);
        let debit = endpoint.driver.bucket.tokens;
        assert!(
            !endpoint
                .driver
                .send_common_user_with(now, |_| Err(io::ErrorKind::WouldBlock.into()))?
        );
        let runtime = endpoint.driver.common.as_ref().ok_or("Common absent")?;
        let pending = runtime.sealed.as_ref().ok_or("retained output lost")?;
        assert_eq!(&runtime.wire[..pending.sealed.bytes], captured.wire);
        assert_eq!(endpoint.driver.records.next_number(Class::User), number);
        assert_eq!(endpoint.driver.bucket.tokens, debit);
        assert!(
            endpoint
                .driver
                .flush_common_wire_with(now, |bytes| endpoint.socket.try_send(bytes))?
        );
        assert_eq!(endpoint.driver.records.next_number(Class::User), number);
        return Ok(captured);
    }
    Err("real IP source did not become ready under original finite service".into())
}

fn assert_body(fixture: &Fixture<IpDevice>, packet: &[u8], expected: &[u8]) -> Result {
    let endpoint = &fixture.endpoints[0];
    let state = endpoint.driver.common_state()?;
    let local = state.current().descriptor().local(mg::Role::Client);
    let (base, packed) = match local.send().profile() {
        c::DirectionProfile::Aligned(config) => (*config, None),
        c::DirectionProfile::Packed(config) => (config.base, Some(*config)),
        _ => return Err("IP source came from wrong real family".into()),
    };
    assert_eq!(
        base.native_policy,
        l2tunnel_aligned::NativePolicy::IpHeaders
    );
    assert!(packet.len() <= base.max_recovery_packet_bytes);
    // Observe the actual direct/systematic selected union through its maintained
    // parser. This separate observer grants no authentication or recovery custody.
    let mut observer = l2tunnel_reliable::Reliable::new(
        base.recovery,
        l2tunnel_recovery::RecoveryContext {
            session: u128::from_be_bytes(endpoint.driver.info.binding.session.0),
            epoch: state.epoch().0,
            role: l2tunnel_recovery::EndpointRole::Initiator,
        },
    )?;
    observer.enable_compact_wire(endpoint.driver.config.control.wire_overhead)?;
    let observed = observer.inspect_output_record(packet)?;
    assert!(matches!(
        observed.kind,
        l2tunnel_reliable::RecordKind::Source | l2tunnel_reliable::RecordKind::Systematic
    ));
    let (source, payload) = observed
        .source
        .ok_or("real source did not contain originals")?;
    let scope = rx::Scope {
        session: endpoint.driver.info.binding.session.0,
        epoch: state.epoch(),
        direction: rx::Direction::InitiatorToResponder,
    };
    let source = rx::SourceId(source.0);
    if let Some(config) = packed {
        let source = packed_envelope::decode_compact(
            packed_envelope::Config {
                symbol_bytes: base.receiver.body.symbol_bytes,
                channels: base.receiver.channels,
                max_units: config.max_units,
            },
            scope,
            source,
            payload,
        )?;
        let units = source.units()?.collect::<Vec<_>>();
        assert!(
            units.iter().all(|unit| unit.bytes[3] != 2),
            "raw fallback cannot qualify IP header coding"
        );
        assert!(
            units.iter().any(|unit| &unit.bytes[3..] == expected),
            "literal IP context/delta absent from actual Packed source"
        );
    } else {
        let source = aligned_envelope::decode_compact(
            scope,
            source,
            base.receiver.body.symbol_bytes,
            base.receiver.channels,
            payload,
        )?;
        let body = &source.symbol[3..];
        assert_eq!(
            &body[..expected.len()],
            expected,
            "literal IP context/delta absent from actual Aligned source"
        );
        assert!(body[expected.len()..].iter().all(|byte| *byte == 0));
    }
    Ok(())
}

async fn receive_packet(endpoint: &mut Endpoint<IpDevice>, now: u64, expected: &[u8]) -> Result {
    let mut input = [0; 1501];
    let bytes =
        tokio::time::timeout(Duration::from_secs(1), endpoint.socket.recv(&mut input)).await??;
    assert_eq!(&input[..bytes], expected);
    endpoint.driver.receive_selected(
        &input[..bytes],
        now,
        endpoint.driver.origin + duration(now),
    )?;
    Ok(())
}

async fn native_exact(fixture: &mut Fixture<IpDevice>, expected: [Vec<Vec<u8>>; 2]) -> Result {
    let mut actual: [Vec<Vec<u8>>; 2] = [Vec::new(), Vec::new()];
    let mut done = false;
    for _ in 0..500 {
        fixture.turn().await?;
        for (side, packets) in actual.iter_mut().enumerate() {
            let mut bytes = [0; 1024];
            for _ in 0..16 {
                match fixture.endpoints[side].host.recv(&mut bytes) {
                    Ok(length) => packets.push(bytes[..length].to_vec()),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error.into()),
                }
            }
            assert!(
                packets.len() <= expected[side].len(),
                "duplicate native delivery"
            );
        }
        if actual == expected
            && fixture.endpoints.iter().all(|endpoint| {
                endpoint.driver.common_state().is_ok_and(|state| {
                    state
                        .engine(state.epoch())
                        .is_ok_and(|engine| engine.drained().unwrap_or(false))
                })
            })
        {
            done = true;
            break;
        }
    }
    assert!(
        done,
        "actual IP native delivery/recovery drain did not finish"
    );
    assert_eq!(actual, expected);
    Ok(())
}

#[test]
fn selected_ip_tcp_context_loss_delta_replay_and_negotiated_packed_preserve_native_bytes() -> Result
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let kind = cover::Appearance::QuicLike;
            let (contracts, packed) = selected_ip(kind)?;
            let mut fixture = ip_fixture(Fixture::from_contracts(kind, contracts).await?)?;
            let first = hex(FIRST)?;
            let next = hex(NEXT)?;
            let context = hex(CONTEXT)?;
            for phase in 0..2 {
                if phase == 1 {
                    assert_eq!(fixture.switch(packed).await?, core::Epoch(2));
                }
                for endpoint in &fixture.endpoints {
                    let current = endpoint.driver.common_state()?.current();
                    assert_eq!(
                        current
                            .descriptor()
                            .direction(mg::Role::Client)
                            .common()
                            .traffic()
                            .layer,
                        traffic::NetworkLayer::Tun
                    );
                    assert_eq!(endpoint.device.get_ref().layer(), PacketLayer::Ip);
                }
                fixture.admit(0, &first).await?;
                fixture.admit(1, &first).await?;
                let lost = retain_source(&mut fixture).await?;
                assert_body(&fixture, &lost.body, &context)?;
                let mut discarded = [0; 1501];
                let bytes = tokio::time::timeout(
                    Duration::from_secs(1),
                    fixture.endpoints[1].socket.recv(&mut discarded),
                )
                .await??;
                assert_eq!(&discarded[..bytes], lost.wire);
                // A whole physically accepted original is missing at the receiver;
                // existing FEC/ARQ must restore its context before exact native output.
                native_exact(&mut fixture, [vec![first.clone()], vec![first.clone()]]).await?;
                fixture.admit(0, &next).await?;
                let delta = retain_source(&mut fixture).await?;
                assert_body(&fixture, &delta.body, DELTA)?;
                let now = fixture.now;
                receive_packet(&mut fixture.endpoints[1], now, &delta.wire).await?;
                native_exact(&mut fixture, [vec![], vec![next.clone()]]).await?;
                // Deliver the old context's genuine protected original after its
                // recovery and after the newer delta. It must not roll context back.
                assert_eq!(
                    fixture.endpoints[0].socket.try_send(&lost.wire)?,
                    lost.wire.len()
                );
                let before = fixture.endpoints[1].driver.counters;
                let now = fixture.now;
                receive_packet(&mut fixture.endpoints[1], now, &lost.wire).await?;
                assert_eq!(
                    fixture.endpoints[1].driver.counters.replay_rejections,
                    before.replay_rejections
                );
                assert_eq!(
                    fixture.endpoints[1].driver.counters.received_packets,
                    before.received_packets + 1
                );
                let verified = fixture.endpoints[1].driver.live.last_verified_micros;
                assert_eq!(
                    fixture.endpoints[0].socket.try_send(&lost.wire)?,
                    lost.wire.len()
                );
                receive_packet(&mut fixture.endpoints[1], now, &lost.wire).await?;
                assert_eq!(
                    fixture.endpoints[1].driver.counters.replay_rejections,
                    before.replay_rejections + 1
                );
                assert_eq!(
                    fixture.endpoints[1].driver.live.last_verified_micros,
                    verified
                );
                fixture.admit(0, &next).await?;
                native_exact(&mut fixture, [vec![], vec![next.clone()]]).await?;
                for (side, expected) in [3, 1].into_iter().enumerate() {
                    let endpoint = &fixture.endpoints[side];
                    let state = endpoint.driver.common_state()?;
                    let counts = state.engine(state.epoch())?.native_counts()?;
                    assert_eq!(counts.admitted.iter().sum::<u64>(), expected);
                    assert_eq!(counts.prepared.iter().sum::<u64>(), 4 - expected);
                    assert_eq!(counts.prepared, counts.committed);
                }
            }
            for _ in 0..200 {
                if fixture
                    .endpoints
                    .iter()
                    .all(|endpoint| endpoint.driver.live.last_pong_micros.is_some())
                {
                    break;
                }
                fixture.turn().await?;
            }
            assert!(
                fixture.endpoints.iter().all(|endpoint| endpoint
                    .driver
                    .live
                    .last_pong_micros
                    .is_some())
            );
            Ok(())
        })
}
