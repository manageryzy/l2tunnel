//! Real selected Common UDP/native consumption after the last user input.
//! The fixture imports actual secure parts; it does not run a fresh handshake.
use super::*;

fn short_contracts(kind: cover::Appearance) -> Result<[CommonTransactionContract; 2]> {
    let mut selected = values(kind, rolling::wire::SourceWire::Exact)?;
    let old = selected[3];
    let descriptor = old.descriptor();
    let c::Profile::Rolling { mut config, stream } = *descriptor.profile() else {
        return Err("actual rolling fixture absent".into());
    };
    for direction in [&mut config.forward, &mut config.reverse] {
        // Each literal original fits one source. The first native exceeds the
        // explicit short threshold; its later same-flow successor does not.
        direction.receiver.body.symbol_bytes = 256;
        direction.receiver.body.independent_short_frame_bytes = 128;
        direction.packing.sender.body = direction.receiver.body;
        direction.packing.packing.symbol_bytes = 256;
        direction.scheduler.repair_numerator = 0;
        direction.scheduler.tail_ticks = 100_000;
    }
    selected[3] = C::new(
        old.envelope(),
        c::Descriptor::new(
            descriptor.path_mtu(),
            descriptor.duplex(),
            *descriptor.direction(mg::Role::Client).common(),
            *descriptor.direction(mg::Role::Server).common(),
            c::Profile::Rolling { config, stream },
        )?,
    )?;
    let descriptors = selected.map(|value| *value.descriptor());
    contracts_with_catalog_and_work(
        kind,
        Catalog::new(descriptors[3], &descriptors)?,
        1,
        Some(rolling::WorkBudget {
            field: 1,
            copies: 1,
            metadata: 1,
        }),
    )
}

fn long_frame() -> Result<Vec<u8>> {
    let mut packet = frame(40_000, 81);
    packet.resize(200, 81);
    let total = u16::try_from(packet.len() - 14)?;
    let udp = u16::try_from(packet.len() - 34)?;
    packet[16..18].copy_from_slice(&total.to_be_bytes());
    packet[38..40].copy_from_slice(&udp.to_be_bytes());
    packet[24..26].fill(0);
    let sum: u32 = packet[14..34]
        .chunks_exact(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], pair[1]])))
        .sum();
    let sum = (sum & 0xffff) + (sum >> 16);
    let sum = (sum & 0xffff) + (sum >> 16);
    packet[24..26].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    Ok(packet)
}

fn transmit_source(fixture: &mut Fixture, expected: rolling::SourceId) -> Result<Vec<u8>> {
    for turn in 0..20_000 {
        // Advance the real packing hold first, then service bounded work at the
        // same injected tick. This does not extend any source/operation cap.
        if turn < 3 {
            fixture.now = fixture.now.checked_add(1000).ok_or("fixture time")?;
        }
        let now = fixture.now;
        let endpoint = &mut fixture.endpoints[0];
        endpoint.driver.progress_common(now)?;
        endpoint.driver.service_common_rolling(now)?;
        assert!(
            !endpoint.driver.send_common_user_with(now, |_| {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            })?
        );
        let Some(runtime) = endpoint.driver.common.as_ref() else {
            return Err("actual Common runtime absent".into());
        };
        let Some(pending) = runtime.sealed.as_ref() else {
            continue;
        };
        let token = pending.carrier.as_ref().ok_or("actual carrier token")?;
        assert!(matches!(
            token.emission().kind,
            engine::EmissionKind::Source(_)
        ));
        let local = endpoint
            .driver
            .common_state()?
            .current()
            .descriptor()
            .local(common_contract::mg_role(endpoint.driver.info.role));
        let c::DirectionProfile::Rolling { config, stream, .. } = local.send().profile() else {
            return Err("selected rolling owner absent".into());
        };
        let context = token.context();
        let scope = rolling::Scope {
            session: context.session.to_be_bytes(),
            epoch: context.epoch,
            stream,
            direction: match context.role {
                mg::Role::Client => 0,
                mg::Role::Server => 1,
            },
        };
        let rolling::wire::compact::View::Data(rolling::wire::View::Source { id, .. }) =
            rolling::wire::compact::inspect(
                config.scheduler.recovery,
                scope,
                &endpoint.driver.buffers.frame[..token.emission().bytes],
            )?
        else {
            return Err("actual original source absent".into());
        };
        assert_eq!(id, expected);
        let wire = runtime.wire[..pending.sealed.bytes].to_vec();
        assert!(
            endpoint
                .driver
                .flush_common_wire_with(now, |bytes| { endpoint.socket.try_send(bytes) })?
        );
        return Ok(wire);
    }
    Err("bounded actual source preparation did not finish".into())
}

#[test]
fn actual_common_silent_tail_rearms_native_after_bounded_short_preview() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let kind = cover::Appearance::QuicLike;
            let mut fixture = Fixture::from_contracts(kind, short_contracts(kind)?).await?;
            let older = long_frame()?;
            let short = frame(40_000, 82);
            fixture.admit(0, &older).await?;
            let lost = transmit_source(&mut fixture, rolling::SourceId(0))?;
            let mut input = [0; 1501];
            let length = tokio::time::timeout(
                Duration::from_secs(1),
                fixture.endpoints[1].socket.recv(&mut input),
            )
            .await??;
            assert_eq!(&input[..length], lost);
            // The original UDP socket accepted source0, but the real receiver never
            // observes that dropped datagram. No later repair or User input follows.
            assert_eq!(fixture.endpoints[1].driver.counters.native_written, 0);
            fixture.admit(0, &short).await?;
            let wire = transmit_source(&mut fixture, rolling::SourceId(1))?;
            let now = fixture.now;
            let endpoint = &mut fixture.endpoints[1];
            let before = endpoint.driver.counters;
            let length =
                tokio::time::timeout(Duration::from_secs(1), endpoint.socket.recv(&mut input))
                    .await??;
            assert_eq!(&input[..length], wire);
            endpoint.driver.receive_selected(
                &input[..length],
                now,
                endpoint.driver.origin + duration(now),
            )?;
            assert_eq!(
                endpoint.driver.counters.received_packets,
                before.received_packets + 1
            );
            assert_eq!(
                endpoint.driver.counters.native_backpressure_drops,
                before.native_backpressure_drops
            );
            let epoch = endpoint.driver.common_state()?.epoch();
            // Arrival only stages decoding. The one-byte GF/preview turns must
            // rearm native delivery even if the socket remains silent.
            assert_eq!(
                endpoint
                    .driver
                    .common
                    .as_ref()
                    .ok_or("Common runtime")?
                    .native_work[(epoch.0 % 2) as usize],
                0
            );
            assert!(endpoint.driver.native.is_empty());
            let mut delivered = false;
            let mut output = [0; 1024];
            for _ in 0..20_000 {
                endpoint.driver.progress_common(now)?;
                endpoint.driver.collect_native(now)?;
                endpoint.driver.service_common_rolling(now)?;
                endpoint.driver.service_selected_control(now)?;
                endpoint.driver.submit_control(now)?;
                endpoint.driver.collect_native(now)?;
                if !endpoint.driver.native.is_empty() {
                    let pending = endpoint
                        .driver
                        .common_state()?
                        .engine(epoch)?
                        .pending_native()
                        .ok_or("actual native token")?;
                    assert!(pending.early());
                    let mut ready = tokio::time::timeout(
                        Duration::from_secs(1),
                        endpoint.device.ready_mut(Interest::WRITABLE),
                    )
                    .await??;
                    assert!(endpoint.driver.write_native(&mut ready, || Ok(now))?);
                    let length = endpoint.host.recv(&mut output)?;
                    assert_eq!(&output[..length], short);
                    delivered = true;
                    break;
                }
            }
            assert!(
                delivered,
                "silent short preview never reached the actual native device"
            );
            assert_eq!(
                endpoint.driver.counters.received_packets,
                before.received_packets + 1
            );
            assert_eq!(endpoint.driver.counters.native_written, 1);
            assert_eq!(
                endpoint.driver.counters.native_backpressure_drops,
                before.native_backpressure_drops
            );
            assert!(endpoint.driver.native.is_empty() && endpoint.driver.terminal.is_none());
            assert_eq!(endpoint.driver.common_state()?.epoch(), epoch);
            let counts = endpoint
                .driver
                .common_state()?
                .engine(epoch)?
                .native_counts()?;
            assert_eq!(counts.prepared.iter().sum::<u64>(), 1);
            assert_eq!(counts.committed.iter().sum::<u64>(), 1);
            assert_eq!(
                (endpoint.socket.local_addr()?, endpoint.socket.peer_addr()?),
                endpoint.original
            );
            assert_eq!(
                endpoint
                    .host
                    .recv(&mut output)
                    .err()
                    .map(|error| error.kind()),
                Some(io::ErrorKind::WouldBlock)
            );
            assert_eq!(
                endpoint
                    .socket
                    .try_recv(&mut input)
                    .err()
                    .map(|error| error.kind()),
                Some(io::ErrorKind::WouldBlock)
            );
            Ok(())
        })
}

#[path = "transport_common_rolling_ingress_tests.rs"]
mod wire_ingress;

#[path = "transport_common_targeted_tests.rs"]
mod targeted;
