//! Actual protected original UDP, one reserved fragment group and native custody.
//! Imported secure test Parts are real; no fresh Noise/member handshake is claimed.
use super::*;
use codec::source_copy::{Policy, Scope as CopyScope};
use l2tunnel::record_engine::{FragmentDirection, FragmentPolicy, ReassemblyPolicies};

fn fragmented(kind: cover::Appearance) -> Result<([CommonTransactionContract; 2], [C; 4])> {
    let (templates, mut selected) = selected(kind, rolling::wire::SourceWire::Padded, 3)?;
    let old = selected[3];
    let descriptor = old.descriptor();
    let c::Profile::Rolling { mut config, stream } = *descriptor.profile() else {
        return Err("actual Rolling fixture absent".into());
    };
    for direction in [&mut config.forward, &mut config.reverse] {
        direction.receiver.body.symbol_bytes = 1460;
        direction.packing.sender.body = direction.receiver.body;
        direction.packing.packing.symbol_bytes = 1460;
        direction.packing.max_units = 1;
        direction.scheduler.recovery.max_payload = 1524;
    }
    let copies = rolling_records::CopyPolicies {
        forward: Policy {
            max_unit_bytes: 1460,
            copies: 3,
            scope: CopyScope::AllShort,
        },
        reverse: Policy::ONE,
    };
    selected[3] = C::new(
        old.envelope(),
        c::Descriptor::new(
            descriptor.path_mtu(),
            descriptor.duplex(),
            *descriptor.direction(mg::Role::Client).common(),
            *descriptor.direction(mg::Role::Server).common(),
            c::Profile::RollingCopies {
                config,
                stream,
                copies,
            },
        )?,
    )?;
    let direction =
        |actual: rolling_records::DirectionConfig, outer, label| -> Result<FragmentDirection> {
            let maximum = actual.maximum_packet_bytes()?;
            let framing = codec::FragmentConfig {
                path_mtu: 1500,
                outer_overhead_bytes: outer,
                max_message_bytes: maximum,
                max_fragments: 4,
            };
            let geometry = framing.geometry(maximum)?;
            assert!(geometry.fragments() > 1);
            let chunk = u16::try_from(geometry.chunk_bytes())?;
            let receive = |bytes| codec::ReassemblyConfig {
                max_message_bytes: bytes,
                max_messages: 2,
                max_fragment_payload_bytes: chunk,
                max_fragments_per_message: 4,
                max_total_fragments: 8,
                max_reserved_bytes: 2 * bytes,
                max_lifetime_ticks: 5_000_000,
                replay_window: 64,
            };
            Ok(FragmentDirection {
                framing,
                labels: [
                    codec::SessionId(label),
                    codec::SessionId(label + 1),
                    codec::SessionId(label + 2),
                ],
                first_message: codec::MessageId(1),
                reassembly: ReassemblyPolicies {
                    systematic: receive(maximum),
                    repair: receive(maximum),
                    feedback: receive(64),
                },
            })
        };
    let policy = FragmentPolicy {
        forward: direction(config.forward, config.geometry.forward_overhead_bytes, 11)?,
        reverse: direction(config.reverse, config.geometry.reverse_overhead_bytes, 21)?,
    };
    let descriptors = selected.map(|value| *value.descriptor());
    let catalog = Catalog::new(descriptors[3], &descriptors)?;
    let make = |role: security::Role, mut resources: Config| -> Result<CommonTransactionContract> {
        resources.rolling_fragments = Some(policy);
        resources.rolling_ingress = Some(rolling_records::IngressLimits {
            slots: 2,
            capacity_bytes: 100_000,
        });
        resources.security.max_body_bytes = 1500 - resources.control.wire_overhead;
        let (local, peer) = if role == security::Role::Initiator {
            (1, 2)
        } else {
            (2, 1)
        };
        let cover = cover::Config::new(
            kind,
            cover::ConnectionIds {
                local: cover::ConnectionId([local; 8]),
                peer: cover::ConnectionId([peer; 8]),
            },
            cover::MediaConfig {
                local_ssrc: cover::Ssrc(u32::from(local)),
                peer_ssrc: cover::Ssrc(u32::from(peer)),
                payload_type: 96,
            },
            cover::Limits {
                max_packet_bytes: 1500,
                max_protected_bytes: 1470,
            },
        )?;
        Ok(CommonTransactionContract::new(
            security::ConfigDigest([3; 32]),
            role,
            resources,
            cover,
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
        )?)
    };
    Ok((
        [
            make(security::Role::Initiator, templates[0].resources())?,
            make(security::Role::Responder, templates[1].resources())?,
        ],
        selected,
    ))
}

fn packet() -> Result<Vec<u8>> {
    let mut packet = frame(40_000, 103);
    packet.resize(1000, 103);
    let ip_length = u16::try_from(packet.len() - 14)?;
    let udp_length = u16::try_from(packet.len() - 34)?;
    packet[16..18].copy_from_slice(&ip_length.to_be_bytes());
    packet[38..40].copy_from_slice(&udp_length.to_be_bytes());
    packet[24..26].fill(0);
    let sum: u32 = packet[14..34]
        .chunks_exact(2)
        .map(|p| u32::from(u16::from_be_bytes([p[0], p[1]])))
        .sum();
    let sum = (sum & 0xffff) + (sum >> 16);
    let sum = (sum & 0xffff) + (sum >> 16);
    packet[24..26].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    Ok(packet)
}

#[test]
fn selected_fragment_groups_use_fresh_records_and_original_udp_before_native_and_switch() -> Result
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
                let (contracts, selected) = fragmented(kind)?;
                let mut fixture = Fixture::from_contracts(kind, contracts).await?;
                let original = packet()?;
                fixture.admit(0, &original).await?;
                let mut first = None;
                for _ in 0..64 {
                    fixture.now += 1000;
                    let endpoint = &mut fixture.endpoints[0];
                    endpoint.driver.progress_common(fixture.now)?;
                    endpoint.driver.service_common_rolling(fixture.now)?;
                    assert!(!endpoint.driver.send_common_user_with(fixture.now, |_| Err(
                        io::Error::from(io::ErrorKind::WouldBlock)
                    ))?);
                    if let Some(pending) = endpoint
                        .driver
                        .common
                        .as_ref()
                        .and_then(|r| r.sealed.as_ref())
                    {
                        let token = pending.fragment.as_ref().ok_or("actual fragment witness")?;
                        assert!(pending.carrier.is_none());
                        let metadata = token.emission();
                        assert_eq!(metadata.index, 0);
                        assert!(metadata.count > 1);
                        first = Some((
                            pending.scope,
                            pending.sealed,
                            pending.cost,
                            pending.deadline,
                            metadata,
                        ));
                        break;
                    }
                }
                let first = first.ok_or("bounded actual fragmented source preparation")?;
                let epoch = core::Epoch(first.0.epoch.0);
                let group = fixture.endpoints[0]
                    .driver
                    .common_state()?
                    .engine(epoch)?
                    .pending_fragment_group()
                    .ok_or("actual complete group reservation")?;
                let start = fixture.endpoints[0].driver.bucket.tokens;
                let wire = {
                    let r = fixture.endpoints[0]
                        .driver
                        .common
                        .as_ref()
                        .ok_or("Common")?;
                    r.wire[..first.1.bytes].to_vec()
                };
                let next = fixture.endpoints[0].driver.records.next_number(Class::User);
                for _ in 0..3 {
                    let driver = &mut fixture.endpoints[0].driver;
                    assert!(!driver.send_common_user_with(fixture.now, |_| Err(
                        io::Error::from(io::ErrorKind::WouldBlock)
                    ))?);
                    let runtime = driver.common.as_ref().ok_or("Common")?;
                    let pending = runtime.sealed.as_ref().ok_or("held exact ciphertext")?;
                    assert_eq!(
                        (
                            pending.scope,
                            pending.sealed,
                            pending.cost,
                            pending.deadline,
                            pending
                                .fragment
                                .as_ref()
                                .ok_or("retained fragment witness")?
                                .emission()
                        ),
                        first
                    );
                    assert_eq!(&runtime.wire[..pending.sealed.bytes], wire);
                    assert_eq!(driver.records.next_number(Class::User), next);
                    assert_eq!(driver.bucket.tokens, start);
                }
                let mut numbers = Vec::new();
                let mut replay = None;
                // Entire first actual copy is lost only after all real UDP writes;
                // the next same-source copy reuses recovery identity, not Records PNs.
                for copy in 0..2 {
                    let before = fixture.endpoints[0].driver.bucket.tokens;
                    for index in 0..group.packets {
                        let endpoint = &mut fixture.endpoints[0];
                        if !(copy == 0 && index == 0) {
                            assert!(!endpoint.driver.send_common_user_with(fixture.now, |_| {
                                Err(io::Error::from(io::ErrorKind::WouldBlock))
                            })?);
                        }
                        let runtime = endpoint.driver.common.as_ref().ok_or("Common")?;
                        let pending = runtime
                            .sealed
                            .as_ref()
                            .ok_or("actual next physical fragment")?;
                        let actual = pending
                            .fragment
                            .as_ref()
                            .ok_or("actual fragment token")?
                            .emission();
                        assert_eq!((actual.index, actual.count), (index, group.packets));
                        assert!(pending.sealed.bytes + endpoint.driver.ip <= 1500);
                        numbers.push(pending.sealed.number);
                        let bytes = runtime.wire[..pending.sealed.bytes].to_vec();
                        assert!(
                            endpoint
                                .driver
                                .flush_common_wire_with(fixture.now, |data| endpoint
                                    .socket
                                    .try_send(data))?
                        );
                        if index + 1 < group.packets {
                            assert_eq!(
                                endpoint
                                    .driver
                                    .common_state()?
                                    .engine(epoch)?
                                    .fragment_statistics()
                                    .ok_or("actual fragment physical counters")?
                                    .groups_written,
                                copy as u64
                            );
                        }
                        let target = &mut fixture.endpoints[1];
                        let mut input = [0; 1501];
                        let length = tokio::time::timeout(
                            Duration::from_secs(1),
                            target.socket.recv(&mut input),
                        )
                        .await??;
                        assert_eq!(&input[..length], bytes);
                        if copy == 1 {
                            target.driver.receive_selected(
                                &input[..length],
                                fixture.now,
                                target.driver.origin + duration(fixture.now),
                                None,
                            )?;
                            replay = Some(bytes);
                        }
                        assert_eq!(target.driver.counters.native_written, 0);
                    }
                    let after = fixture.endpoints[0].driver.bucket.tokens;
                    let debit = if copy == 0 {
                        0
                    } else {
                        group.wire_bytes as u128 * SCALE
                    };
                    assert_eq!(
                        before - after,
                        debit,
                        "only a new complete copy reserves the shared bucket"
                    );
                }
                assert!(numbers.windows(2).all(|pair| pair[0] < pair[1]));
                let target = &mut fixture.endpoints[1];
                let before = target.driver.counters.replay_rejections;
                target.driver.receive_selected(
                    &replay.ok_or("actual delivered protected fragment")?,
                    fixture.now,
                    target.driver.origin + duration(fixture.now),
                    None,
                )?;
                assert_eq!(target.driver.counters.replay_rejections, before + 1);
                let mut originals = Vec::new();
                let mut done = false;
                for _ in 0..500 {
                    fixture.turn().await?;
                    let mut output = [0; 1600];
                    for _ in 0..16 {
                        match fixture.endpoints[1].host.recv(&mut output) {
                            Ok(length) => originals.push(output[..length].to_vec()),
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                            Err(error) => return Err(error.into()),
                        }
                    }
                    if originals.len() == 1
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
                    "actual native, source copies, feedback and reassembly must drain"
                );
                assert_eq!(originals, vec![original]);
                for endpoint in &fixture.endpoints {
                    let snapshot = endpoint.driver.snapshot_common(fixture.now, true)?;
                    assert!(snapshot.rolling_fragments.is_some());
                    assert!(snapshot.fragment_statistics.is_some());
                    assert_eq!(
                        (
                            snapshot.fragment_data_drops,
                            snapshot.fragment_feedback_drops
                        ),
                        (0, 0)
                    );
                    assert_eq!(
                        snapshot
                            .fragment_ingress
                            .ok_or("actual three reassemblers")?
                            .pending,
                        [0; 3]
                    );
                    assert_eq!(
                        (endpoint.socket.local_addr()?, endpoint.socket.peer_addr()?),
                        endpoint.original
                    );
                }
                assert_eq!(fixture.endpoints[1].driver.counters.native_written, 1);
                for _ in 0..30 {
                    fixture.turn().await?;
                }
                assert!(
                    fixture.endpoints.iter().all(|endpoint| endpoint
                        .driver
                        .live
                        .last_pong_micros
                        .is_some())
                );
                fixture.switch(selected[0]).await?;
                assert!(fixture.endpoints.iter().all(|endpoint| {
                    endpoint
                        .driver
                        .snapshot_common(fixture.now, true)
                        .is_ok_and(|s| {
                            s.rolling_fragments.is_none() && s.fragment_statistics.is_none()
                        })
                }));
                fixture.exchange_all_channels(104).await?;
            }
            Ok(())
        })
}
