//! Actual original-socket loss recovery and effective repair byte accounting.
use super::*;

fn current_contracts() -> Result<([CommonTransactionContract; 2], rolling::Config)> {
    let kind = cover::Appearance::QuicLike;
    let old = values(kind, rolling::wire::SourceWire::Exact)?[3];
    let descriptor = old.descriptor();
    let c::Profile::Rolling { mut config, stream } = *descriptor.profile() else {
        return Err("Rolling template missing".into());
    };
    let selection = record::compact::Selection {
        protection: security::compact::Protection::ChaCha20Poly1305,
        limits: security::compact::Selection {
            max_forward_packets: 8192,
            max_failed_checks: 16,
        },
    };
    let overhead = 28 + selection.data_overhead();
    config.geometry = engine::Geometry {
        forward_overhead_bytes: overhead,
        reverse_overhead_bytes: overhead,
    };
    for direction in [&mut config.forward, &mut config.reverse] {
        direction.native_policy = l2tunnel_aligned::NativePolicy::RawEthernet;
        direction.receiver.body.elide_payload_length = false;
        direction.receiver.body.predictive = false;
        direction.receiver.body.timestamp_pair_dictionary = false;
        direction.receiver.body.independent_short_frame_bytes = 0;
        direction.packing.sender.body = direction.receiver.body;
        direction.packing.max_units = 1;
    }
    let recovery = config.forward.scheduler.recovery;
    let selected = c::Descriptor::new(
        descriptor.path_mtu(),
        descriptor.duplex(),
        *descriptor.direction(mg::Role::Client).common(),
        *descriptor.direction(mg::Role::Server).common(),
        c::Profile::Rolling { config, stream },
    )?;
    let catalog = Catalog::new(selected, &[selected])?;
    let base = contracts(kind)?;
    let mut resources = base[0].resources();
    resources.rolling_work = Some(work());
    resources.control.wire_overhead = 28 + record::compact::AUTHENTICATED_OVERHEAD;
    for stream in &mut resources.streams.as_mut().ok_or("streams missing")?.streams {
        stream.delivery.wire_overhead = resources.control.wire_overhead + streams::HEADER_BYTES;
    }
    let make = |role| -> Result<CommonTransactionContract> {
        Ok(CommonTransactionContract::new_compact_wire(
            security::ConfigDigest([0xe7; 32]),
            role,
            [resources; 2],
            appearance(kind, role == security::Role::Initiator)?,
            false,
            old.envelope(),
            catalog.clone(),
            base[0].settings(),
            selection,
        )?)
    };
    Ok((
        [
            make(security::Role::Initiator)?,
            make(security::Role::Responder)?,
        ],
        recovery,
    ))
}

fn packet(length: usize) -> Result<Vec<u8>> {
    let mut bytes = frame(43_197, 0x93);
    bytes.resize(length, 0x93);
    bytes[length - 2..].fill(0);
    bytes[16..18].copy_from_slice(&u16::try_from(length - 14)?.to_be_bytes());
    bytes[38..40].copy_from_slice(&u16::try_from(length - 34)?.to_be_bytes());
    bytes[24..26].fill(0);
    let mut sum = bytes[14..34].chunks_exact(2).fold(0u32, |sum, pair| {
        sum + u32::from(u16::from_be_bytes([pair[0], pair[1]]))
    });
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    bytes[24..26].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    Ok(bytes)
}

#[test]
fn actual_current_udp_repair_extent_loses_source_and_preserves_zero_tail_and_charge() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let (contracts, recovery) = current_contracts()?;
            let expected = contracts[0].expected_configuration();
            let mut fixture = Fixture::from_contracts_setup(
                cover::Appearance::QuicLike,
                contracts,
                true,
                Some(expected),
            )
            .await?;
            let mut extents = Vec::new();
            for length in [46, 100] {
                let original = packet(length)?;
                fixture.admit(0, &original).await?;
                let now = retain_first_source(&mut fixture)?;
                let sender = &mut fixture.endpoints[0];
                let runtime = sender.driver.common.as_ref().ok_or("runtime missing")?;
                let pending = runtime.sealed.as_ref().ok_or("source missing")?;
                let emission = pending
                    .carrier
                    .as_ref()
                    .ok_or("source token missing")?
                    .emission();
                assert!(matches!(emission.kind, engine::EmissionKind::Source(_)));
                let scope = rolling::Scope {
                    session: sender.driver.info.binding.session.0,
                    epoch: pending.scope.epoch.0,
                    stream: 17,
                    direction: 0,
                };
                let rolling::wire::compact::View::Data(rolling::wire::View::Source {
                    original: source,
                    ..
                }) = rolling::wire::compact::inspect(
                    recovery,
                    scope,
                    &sender.driver.buffers.frame[..emission.bytes],
                )?
                else {
                    return Err("source union missing".into());
                };
                let extent = source.len() + 2;
                assert!(
                    source.ends_with(&[0, 0]),
                    "meaningful native zeros remain encoded"
                );
                assert!(extent < recovery.max_payload + 2);
                extents.push(extent);
                let source_wire = runtime.wire[..pending.sealed.bytes].to_vec();
                assert_eq!(pending.cost, source_wire.len() + 28);
                assert!(
                    sender
                        .driver
                        .flush_common_wire_with(now, |bytes| sender.socket.try_send(bytes))?
                );
                // Discard the actual whole source only after the socket accepted it.
                let mut input = [0; 1501];
                let received = tokio::time::timeout(
                    Duration::from_secs(1),
                    fixture.endpoints[1].socket.recv(&mut input),
                )
                .await??;
                assert_eq!(&input[..received], source_wire);

                let repair_now = retain_first_source(&mut fixture)?;
                let sender = &mut fixture.endpoints[0];
                let runtime = sender.driver.common.as_ref().ok_or("runtime missing")?;
                let pending = runtime.sealed.as_ref().ok_or("repair missing")?;
                let emission = pending
                    .carrier
                    .as_ref()
                    .ok_or("repair token missing")?
                    .emission();
                assert_eq!(emission.kind, engine::EmissionKind::Repair);
                let rolling::wire::compact::View::Data(rolling::wire::View::Repair(repair)) =
                    rolling::wire::compact::inspect(
                        recovery,
                        scope,
                        &sender.driver.buffers.frame[..emission.bytes],
                    )?
                else {
                    return Err("repair union missing".into());
                };
                assert_eq!(repair.bytes.len(), extent);
                let wire = runtime.wire[..pending.sealed.bytes].to_vec();
                assert_eq!(
                    wire.len(),
                    emission.bytes + record::compact::AUTHENTICATED_OVERHEAD
                );
                assert_eq!(pending.cost, wire.len() + 28);
                assert_eq!(emission.wire_bytes, pending.cost);
                let retained = (
                    pending.scope,
                    pending.sealed,
                    pending.cost,
                    pending.deadline,
                );
                let number = sender.driver.records.next_number(Class::User);
                let accepted = sender.driver.counters.socket_accepted_ip_bytes;
                assert!(!sender.driver.send_common_user_with(repair_now, |_| Err(
                    io::ErrorKind::WouldBlock.into()
                ))?);
                let runtime = sender.driver.common.as_ref().ok_or("runtime missing")?;
                let pending = runtime.sealed.as_ref().ok_or("retained repair missing")?;
                assert_eq!(
                    (
                        pending.scope,
                        pending.sealed,
                        pending.cost,
                        pending.deadline
                    ),
                    retained
                );
                assert_eq!(&runtime.wire[..wire.len()], wire);
                assert_eq!(sender.driver.records.next_number(Class::User), number);
                assert!(
                    sender
                        .driver
                        .flush_common_wire_with(repair_now, |bytes| sender
                            .socket
                            .try_send(bytes))?
                );
                assert_eq!(
                    sender.driver.counters.socket_accepted_ip_bytes - accepted,
                    (wire.len() + 28) as u64
                );
                let receiver = &mut fixture.endpoints[1];
                let received =
                    tokio::time::timeout(Duration::from_secs(1), receiver.socket.recv(&mut input))
                        .await??;
                assert_eq!(&input[..received], wire);
                receiver.driver.receive_selected(
                    &input[..received],
                    repair_now,
                    receiver.driver.origin + duration(repair_now),
                )?;

                let mut delivered = false;
                let mut drained = false;
                for _ in 0..500 {
                    fixture.turn().await?;
                    let mut output = [0; 1024];
                    match fixture.endpoints[1].host.recv(&mut output) {
                        Ok(bytes) => {
                            assert!(!delivered);
                            assert_eq!(&output[..bytes], original);
                            delivered = true;
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                        Err(error) => return Err(error.into()),
                    }
                    drained = fixture.endpoints.iter().all(|endpoint| {
                        endpoint.driver.common_state().is_ok_and(|state| {
                            state
                                .engine(state.epoch())
                                .is_ok_and(|engine| engine.drained().unwrap_or(false))
                        })
                    });
                    if delivered && drained {
                        break;
                    }
                }
                assert!(
                    delivered && drained,
                    "actual repair/native custody did not complete"
                );
            }
            assert_ne!(extents[0], extents[1]);
            Ok(())
        })
}
