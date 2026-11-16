//! Genuine catalog-H0 Noise/member setup, original UDP and selected final framing.
use super::*;
use l2tunnel::secure_record::compact::{Kind, Selection};

fn selected(
    kind: cover::Appearance,
    protection: security::compact::Protection,
) -> Result<([CommonTransactionContract; 2], C)> {
    let legacy = contracts(kind)?;
    let initial = legacy[0].initial();
    let descriptor = initial.descriptor();
    let l2tunnel::record_configuration::Profile::Swift {
        mut forward,
        mut reverse,
    } = *descriptor.profile()
    else {
        return Err("expected real Swift profile".into());
    };
    forward.codec.datagram_bytes -= 8;
    reverse.codec.datagram_bytes -= 8;
    let target = l2tunnel::record_configuration::Descriptor::new(
        descriptor.path_mtu(),
        descriptor.duplex(),
        *descriptor.direction(mg::Role::Client).common(),
        *descriptor.direction(mg::Role::Server).common(),
        l2tunnel::record_configuration::Profile::Swift { forward, reverse },
    )?;
    let catalog = Catalog::new(*descriptor, &[*descriptor, target])?;
    let mut resources = legacy[0].resources();
    resources.control.wire_overhead = 28 + record::compact::AUTHENTICATED_OVERHEAD;
    for stream in &mut resources.streams.as_mut().ok_or("streams absent")?.streams {
        stream.delivery.wire_overhead = resources.control.wire_overhead + streams::HEADER_BYTES;
    }
    let selection = Selection {
        protection,
        limits: security::compact::Selection {
            max_forward_packets: 1024,
            max_failed_checks: 16,
        },
    };
    let make = |role| -> Result<CommonTransactionContract> {
        Ok(CommonTransactionContract::new_compact_wire(
            security::ConfigDigest([0xc1; 32]),
            role,
            [resources; 2],
            appearance(kind, role == security::Role::Initiator)?,
            false,
            initial.envelope(),
            catalog.clone(),
            legacy[0].settings(),
            selection,
        )?)
    };
    let pair = [
        make(security::Role::Initiator)?,
        make(security::Role::Responder)?,
    ];
    assert_eq!(
        pair[0].expected_configuration(),
        pair[1].expected_configuration()
    );
    Ok((pair, C::new(initial.envelope(), target)?))
}

async fn receive(endpoint: &mut Endpoint, now: u64) -> Result<Vec<u8>> {
    let mut input = [0; 1501];
    let bytes =
        tokio::time::timeout(Duration::from_secs(1), endpoint.socket.recv(&mut input)).await??;
    endpoint.driver.receive_selected(
        &input[..bytes],
        now,
        endpoint.driver.origin + duration(now),
        None,
    )?;
    Ok(input[..bytes].to_vec())
}

#[test]
fn selected_compact_wire_genuine_setup_original_udp_bytes_feedback_and_switch() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            for appearance in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
                for protection in [
                    security::compact::Protection::Aes128Ccm4,
                    security::compact::Protection::ChaCha20Crc32c,
                ] {
                    let (contracts, target) = selected(appearance, protection)?;
                    let expected = contracts[0].expected_configuration();
                    let mut fixture =
                        Fixture::from_contracts_setup(appearance, contracts, true, Some(expected))
                            .await?;
                    for endpoint in &fixture.endpoints {
                        assert_eq!(endpoint.driver.info.authenticated.configuration, expected.0);
                        assert!(endpoint.driver.records.is_compact());
                        assert_eq!(
                            endpoint
                                .driver
                                .records
                                .capacity_for(Kind::Data, 46)?
                                .packet_bytes,
                            55
                        );
                        assert_eq!(
                            endpoint
                                .driver
                                .records
                                .capacity_for(Kind::Feedback, 12)?
                                .packet_bytes,
                            33
                        );
                        assert_eq!(
                            endpoint
                                .driver
                                .records
                                .capacity_for(Kind::Control, 12)?
                                .packet_bytes,
                            33
                        );
                    }
                    let packet = frame(43000, 119);
                    fixture.admit(0, &packet).await?;
                    let mut held = false;
                    for _ in 0..100 {
                        fixture.now += 1000;
                        let driver = &mut fixture.endpoints[0].driver;
                        driver.bucket.refill(fixture.now)?;
                        assert!(!driver.send_common_user_with(fixture.now, |_| {
                            Err(io::ErrorKind::WouldBlock.into())
                        })?);
                        if driver
                            .common
                            .as_ref()
                            .is_some_and(|runtime| runtime.sealed.is_some())
                        {
                            held = true;
                            break;
                        }
                    }
                    assert!(held, "real Swift source was not prepared");
                    let now = fixture.now;
                    let a = &mut fixture.endpoints[0];
                    let runtime = a.driver.common.as_ref().ok_or("runtime absent")?;
                    let pending = runtime.sealed.as_ref().ok_or("actual wire absent")?;
                    assert!(!pending.feedback);
                    let cap = pending.deadline;
                    let source = runtime.wire[..pending.sealed.bytes].to_vec();
                    let source_body = source.len() - record::compact::DATA_OVERHEAD;
                    assert_eq!(
                        a.driver.buffers.frame[0] & swift::KIND_MASK,
                        swift::KIND_SOURCE
                    );
                    assert_eq!(
                        pending.cost,
                        source_body + record::compact::DATA_OVERHEAD + 28
                    );
                    let next = a.driver.records.next_number(Class::User);
                    let tokens = a.driver.bucket.tokens;
                    assert!(
                        !a.driver.send_common_user_with(now, |_| Err(
                            io::ErrorKind::WouldBlock.into()
                        ))?
                    );
                    assert_eq!(a.driver.records.next_number(Class::User), next);
                    assert_eq!(a.driver.bucket.tokens, tokens);
                    assert_eq!(
                        a.driver
                            .common
                            .as_ref()
                            .and_then(|r| r.sealed.as_ref())
                            .map(|p| p.deadline),
                        Some(cap)
                    );
                    assert_eq!(
                        a.driver.common.as_ref().ok_or("runtime absent")?.wire[..source.len()],
                        source
                    );
                    assert!(
                        a.driver
                            .send_common_user_with(now, |wire| a.socket.try_send(wire))?
                    );

                    let b = &mut fixture.endpoints[1];
                    let verified = b.driver.live.last_verified_micros;
                    let mut tampered = source.clone();
                    *tampered.last_mut().ok_or("empty source")? ^= 1;
                    b.driver.receive_selected(
                        &tampered,
                        now,
                        b.driver.origin + duration(now),
                        None,
                    )?;
                    assert_eq!(b.driver.live.last_verified_micros, verified);
                    assert_eq!(
                        b.driver
                            .records
                            .compact_check_status()
                            .ok_or("compact status absent")?
                            .data,
                        1
                    );
                    assert_eq!(receive(b, now).await?, source);
                    if protection == security::compact::Protection::ChaCha20Crc32c {
                        assert_eq!(
                            b.driver.live.last_verified_micros, verified,
                            "a CRC-selected source is not authenticated liveness"
                        );
                    }
                    let replay = b.driver.counters.replay_rejections;
                    b.driver.receive_selected(
                        &source,
                        now,
                        b.driver.origin + duration(now),
                        None,
                    )?;
                    assert_eq!(b.driver.counters.replay_rejections, replay + 1);

                    // Retiring feedback uses a distinct actual PN and strong check;
                    // its additional twelve bytes are charged before codec commit.
                    let mut feedback = None;
                    for _ in 0..100 {
                        fixture.now += 1000;
                        let b = &mut fixture.endpoints[1];
                        b.driver.bucket.refill(fixture.now)?;
                        assert!(!b.driver.send_common_user_with(fixture.now, |_| {
                            Err(io::ErrorKind::WouldBlock.into())
                        })?);
                        if let Some(pending) =
                            b.driver.common.as_ref().and_then(|r| r.sealed.as_ref())
                        {
                            assert!(pending.feedback);
                            feedback = Some(
                                b.driver.common.as_ref().ok_or("runtime absent")?.wire
                                    [..pending.sealed.bytes]
                                    .to_vec(),
                            );
                            break;
                        }
                    }
                    let feedback = feedback.ok_or("actual strong feedback absent")?;
                    let b = &fixture.endpoints[1].driver;
                    assert_eq!(b.buffers.frame[0] & swift::KIND_MASK, swift::KIND_FEEDBACK);
                    let body = feedback.len() - record::compact::AUTHENTICATED_OVERHEAD;
                    assert_eq!(
                        b.records.capacity_for(Kind::Feedback, body)?.packet_bytes,
                        feedback.len()
                    );
                    assert_eq!(b.records.next_number(Class::User).0, 0);
                    assert_eq!(b.records.next_feedback_number()?.0, 1);
                    assert_eq!(
                        b.snapshot_common(fixture.now, true)?
                            .compact_feedback_number,
                        Some(security::PacketNumber(0))
                    );
                    // Even a correctly checked Data packet cannot retire sender
                    // debt by smuggling an algorithm feedback body across domains.
                    let wrong_route = {
                        let b = &mut fixture.endpoints[1];
                        let plaintext = b.driver.buffers.frame[..body].to_vec();
                        let mut wire = vec![0; 1500];
                        let sealed = b.driver.records.seal_user_in(
                            b.driver.source_scope,
                            meta(0, cover::Phase::Established),
                            &plaintext,
                            &mut b.driver.buffers.seal,
                            &mut wire,
                        )?;
                        wire.truncate(sealed.bytes);
                        assert_eq!(b.socket.try_send(&wire)?, wire.len());
                        wire
                    };
                    let a = &mut fixture.endpoints[0];
                    let rejected = a.driver.counters.rejected_packets;
                    let verified = a.driver.live.last_verified_micros;
                    assert_eq!(receive(a, fixture.now).await?, wrong_route);
                    assert_eq!(a.driver.counters.rejected_packets, rejected + 1);
                    assert_eq!(a.driver.live.last_verified_micros, verified);
                    assert!(
                        !a.driver
                            .common_state()?
                            .engine(a.driver.common_state()?.epoch())?
                            .drained()?
                    );
                    let b = &mut fixture.endpoints[1];
                    assert!(
                        b.driver
                            .send_common_user_with(fixture.now, |wire| b.socket.try_send(wire))?
                    );
                    assert_eq!(
                        receive(&mut fixture.endpoints[0], fixture.now).await?,
                        feedback
                    );
                    let mut delivered = false;
                    for _ in 0..100 {
                        fixture.turn().await?;
                        let mut output = [0; 513];
                        match fixture.endpoints[1].host.recv(&mut output) {
                            Ok(bytes) => {
                                assert_eq!(&output[..bytes], packet);
                                delivered = true;
                                break;
                            }
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                            Err(error) => return Err(error.into()),
                        }
                    }
                    assert!(delivered);
                    fixture.exchange_all_channels(121).await?;
                    let epoch = fixture.endpoints[0].driver.source_scope.epoch.0;
                    assert_eq!(fixture.switch(target).await?, core::Epoch(epoch + 1));
                    fixture.exchange_all_channels(124).await?;
                    for _ in 0..20 {
                        fixture.turn().await?;
                    }
                    for endpoint in &fixture.endpoints {
                        let snapshot = endpoint.driver.snapshot_common(fixture.now, true)?;
                        assert_eq!(snapshot.current, target);
                        assert_eq!(snapshot.configuration, expected);
                        assert!(snapshot.compact_wire.is_some());
                        assert_eq!(
                            snapshot.compact_check_status,
                            endpoint.driver.records.compact_check_status()
                        );
                        assert!(endpoint.driver.live.last_pong_micros.is_some());
                        assert!(endpoint.driver.records.next_number(Class::Control).0 > 0);
                        assert_eq!(
                            (endpoint.socket.local_addr()?, endpoint.socket.peer_addr()?),
                            endpoint.original
                        );
                    }
                }
            }
            Ok(())
        })
}
