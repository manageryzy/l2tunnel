//! Two authenticated Common drivers, connected UDP sockets and Unix packet devices.
use super::*;

fn tcp_golden(name: &str) -> Result<Vec<u8>> {
    let fields = include_str!("../../../l2tunnel-codec/tests/data/tcp-header-goldens.tsv")
        .lines()
        .map(|line| line.split('\t').collect::<Vec<_>>())
        .find(|row| row.first() == Some(&"tcp_timestamp") && row.get(1) == Some(&name))
        .ok_or("TCP golden absent")?;
    fields[3]
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair)?, 16).map_err(Into::into))
        .collect::<Result<Vec<_>>>()
}

fn contracts_targeted(kind: cover::Appearance) -> Result<[CommonTransactionContract; 2]> {
    let mut selected = values(kind, rolling::wire::SourceWire::TargetedExact)?;
    let old = selected[3];
    let d = old.descriptor();
    let c::Profile::Rolling { mut config, stream } = *d.profile() else {
        return Err("rolling absent".into());
    };
    for dir in [&mut config.forward, &mut config.reverse] {
        dir.scheduler.repair_numerator = 0;
        dir.receiver.body.independent_short_frame_bytes = 32;
        dir.packing.sender.body = dir.receiver.body;
    }
    selected[3] = C::new(
        old.envelope(),
        c::Descriptor::new(
            d.path_mtu(),
            d.duplex(),
            *d.direction(mg::Role::Client).common(),
            *d.direction(mg::Role::Server).common(),
            c::Profile::Rolling { config, stream },
        )?,
    )?;
    let all = selected.map(|item| *item.descriptor());
    contracts_with_catalog_and_work(kind, Catalog::new(all[3], &all)?, 16, Some(work()))
}

async fn read_datagram(fixture: &Fixture, side: usize) -> Result<Vec<u8>> {
    let mut buf = [0; 1501];
    let n = tokio::time::timeout(
        Duration::from_secs(1),
        fixture.endpoints[side].socket.recv(&mut buf),
    )
    .await??;
    Ok(buf[..n].to_vec())
}
fn ingest(fixture: &mut Fixture, side: usize, wire: &[u8]) -> Result {
    let e = &mut fixture.endpoints[side];
    e.driver
        .receive_selected(wire, fixture.now, e.driver.origin + duration(fixture.now))?;
    Ok(())
}
async fn early_native(fixture: &mut Fixture) -> Result<Vec<u8>> {
    let now = fixture.now;
    let e = &mut fixture.endpoints[1];
    for _ in 0..256 {
        e.driver.progress_common(now)?;
        e.driver.service_common_rolling(now)?;
        e.driver.collect_native(now)?;
        if !e.driver.native.is_empty() {
            let mut ready = e.device.ready_mut(Interest::WRITABLE).await?;
            assert!(e.driver.write_native(&mut ready, || Ok(now))?);
            let mut buf = [0; 256];
            let n = e.host.recv(&mut buf)?;
            return Ok(buf[..n].to_vec());
        }
    }
    Err("second channel could not deliver its complete TCP record across source zero".into())
}
async fn reverse_request(fixture: &mut Fixture) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    let mut prior_ack = None;
    for _ in 0..100 {
        fixture.now += 200;
        let now = fixture.now;
        let e = &mut fixture.endpoints[1];
        e.driver.progress_common(now)?;
        e.driver.service_common_rolling(now)?;
        e.driver
            .send_common_user_with(now, |_| Err(io::ErrorKind::WouldBlock.into()))?;
        let Some(held) = e.driver.common.as_ref().and_then(|r| r.sealed.as_ref()) else {
            continue;
        };
        let token = held.carrier.as_ref().ok_or("feedback token")?;
        assert_eq!(token.emission().kind, engine::EmissionKind::Feedback);
        let plain = &e.driver.buffers.frame[..token.emission().bytes];
        let tag = plain[0];
        assert!(
            e.driver
                .flush_common_wire_with(now, |bytes| e.socket.try_send(bytes))?
        );
        let wire = read_datagram(fixture, 0).await?;
        if tag == 5 {
            return Ok((wire, prior_ack));
        }
        assert_eq!(tag, 3);
        prior_ack = Some(wire);
    }
    Err("no actual reverse named feedback".into())
}

#[test]
fn protected_udp_targeted_gap_retries_retained_original_and_charges_local_mux_pressure() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let kind = cover::Appearance::QuicLike;
            let mut fixture = Fixture::from_contracts(kind, contracts_targeted(kind)?).await?;
            let a = tcp_golden("initial")?;
            let b = tcp_golden("new_static_context")?;
            let epoch = fixture.endpoints[0].driver.common_state()?.epoch();
            fixture.admit(0, &a).await?;
            let original = transmit_source(&mut fixture, rolling::SourceId(0))?;
            assert_eq!(read_datagram(&fixture, 1).await?, original);
            // Source zero was physically accepted on the selected socket but lost.
            fixture.admit(0, &b).await?;
            // Timestamp context and context-dependent data are separate sources.
            // Channel zero's data waits; both complete units of channel one can pass.
            for id in 1..=3 {
                let delivered = transmit_source(&mut fixture, rolling::SourceId(id))?;
                assert_eq!(read_datagram(&fixture, 1).await?, delivered);
                ingest(&mut fixture, 1, &delivered)?;
                let e = &mut fixture.endpoints[1];
                for _ in 0..16 {
                    e.driver.service_common_rolling(fixture.now)?;
                }
            }
            assert_eq!(
                early_native(&mut fixture)
                    .await
                    .map_err(|e| format!("early B: {e}"))?,
                b
            );
            let (request, old_ack) = reverse_request(&mut fixture).await?;
            let filler = frame(41_001, 97);
            fixture.admit(0, &filler).await?;
            fixture.now += 20_000;
            let before = fixture.endpoints[0]
                .driver
                .common_state()?
                .engine(epoch)?
                .rolling_repair_budget()
                .ok_or("sender budget")?;
            ingest(&mut fixture, 0, &request)?;
            ingest(
                &mut fixture,
                0,
                &old_ack.ok_or("fixture did not retain early ACK")?,
            )?;
            let now = fixture.now;
            // Bind the actual emitted retry through WouldBlock and repeated preparation.
            let sender = &mut fixture.endpoints[0];
            sender.driver.service_common_rolling(now)?;
            for _ in 0..8 {
                sender
                    .driver
                    .send_common_user_with(now, |_| Err(io::ErrorKind::WouldBlock.into()))?;
                if sender
                    .driver
                    .common
                    .as_ref()
                    .is_some_and(|r| r.sealed.is_some())
                {
                    break;
                }
                sender.driver.service_common_rolling(now)?;
            }
            let runtime = sender.driver.common.as_ref().ok_or("runtime")?;
            let held = runtime.sealed.as_ref().ok_or("retry was not sealed")?;
            let token = held.carrier.as_ref().ok_or("immutable physical token")?;
            let cost = held.cost;
            let retry = runtime.wire[..held.sealed.bytes].to_vec();
            let plain = &sender.driver.buffers.frame[..token.emission().bytes];
            assert_eq!(plain.first(), Some(&1));
            assert_eq!(plain.get(1), Some(&0));
            assert_eq!(
                sender
                    .driver
                    .common_state()?
                    .engine(epoch)?
                    .rolling_repair_budget(),
                Some(before)
            );
            sender
                .driver
                .send_common_user_with(now, |_| Err(io::ErrorKind::WouldBlock.into()))?;
            assert!(
                sender
                    .driver
                    .flush_common_wire_with(now, |bytes| sender.socket.try_send(bytes))?
            );
            let after = sender
                .driver
                .common_state()?
                .engine(epoch)?
                .rolling_repair_budget()
                .ok_or("charged")?;
            assert_eq!(after.full_weight_retries, before.full_weight_retries + 1);
            assert_eq!(
                after.earned_half_bytes - before.earned_half_bytes,
                2 * cost as u64
            );
            assert_ne!(retry, original);
            assert_eq!(read_datagram(&fixture, 1).await?, retry);
            ingest(&mut fixture, 1, &retry)?;
            assert_eq!(
                early_native(&mut fixture)
                    .await
                    .map_err(|e| format!("recovered A: {e}"))?,
                a
            );
            // Authentic duplicate Records data cannot deliver an original twice.
            ingest(&mut fixture, 1, &retry)?;
            let mut extra = Vec::new();
            for _ in 0..500 {
                fixture.turn().await?;
                let e = &fixture.endpoints[1];
                let mut b = [0; 512];
                if let Ok(n) = e.host.recv(&mut b) {
                    extra.push(b[..n].to_vec());
                }
                if fixture.endpoints.iter().all(|e| {
                    e.driver
                        .common_state()
                        .is_ok_and(|s| s.engine(epoch).is_ok_and(|x| x.drained().unwrap_or(false)))
                }) {
                    break;
                }
            }
            for e in &fixture.endpoints {
                assert!(e.driver.common_state()?.engine(epoch)?.drained()?);
                assert_eq!((e.socket.local_addr()?, e.socket.peer_addr()?), e.original);
            }
            assert_eq!(extra, [filler]);
            Ok(())
        })
}
