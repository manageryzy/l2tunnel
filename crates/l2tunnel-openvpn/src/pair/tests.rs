use super::*;

#[tokio::test]
async fn fixed_join_requires_both_actual_directional_keys() -> Result<(), Box<dyn std::error::Error>>
{
    fn keys() -> Keys {
        Keys {
            forward: [
                hmac::Key::new(hmac::HMAC_SHA256, &[1; 32]),
                hmac::Key::new(hmac::HMAC_SHA256, &[2; 32]),
            ],
            reverse: [
                hmac::Key::new(hmac::HMAC_SHA256, &[3; 32]),
                hmac::Key::new(hmac::HMAC_SHA256, &[4; 32]),
            ],
        }
    }
    let (mut a, mut b) = tokio::io::duplex(256);
    let (a, b) = tokio::join!(
        join(&mut a, [9; 32], keys(), false, [1; 16]),
        join(&mut b, [9; 32], keys(), true, [2; 16])
    );
    a?;
    b?;
    let group = [9; 32];
    let challenges = [[1; 16], [2; 16]];
    let correct = keys();
    let tag = correct.sign(&group, &challenges, 1, 2);
    let mut wrong = keys();
    wrong.forward[0] = hmac::Key::new(hmac::HMAC_SHA256, &[8; 32]);
    assert!(wrong.verify(&group, &challenges, 1, 2, &tag).is_err());
    let mut wrong = keys();
    wrong.reverse[0] = hmac::Key::new(hmac::HMAC_SHA256, &[8; 32]);
    assert!(wrong.verify(&group, &challenges, 1, 2, &tag).is_err());
    assert!(correct.verify(&group, &challenges, 2, 2, &tag).is_err());
    assert!(correct.verify(&group, &challenges, 1, 3, &tag).is_err());
    assert!(correct.verify(&[8; 32], &challenges, 1, 2, &tag).is_err());
    assert!(
        correct
            .verify(&group, &[[2; 16], [1; 16]], 1, 2, &tag)
            .is_err()
    );
    Ok(())
}

fn config(
    path: l2tunnel_udp_control::Path,
    index: usize,
    protection: crate::Protection,
) -> Result<Config, Error> {
    let mut value = Config::new(
        path,
        l2tunnel_auth::SessionConfig {
            layer: l2tunnel_device::PacketLayer::Ip,
            digest: l2tunnel_core::ConfigDigest([7; 32]),
        },
        protection,
    )?;
    value.profile.lane = crate::LaneId(10 + index as u32);
    value.profile.traffic = Traffic::HalfDuplex {
        sender: if index == 0 {
            DataDirection::ClientToServer
        } else {
            DataDirection::ServerToClient
        },
    };
    value.wire_budget.packets = 8;
    value.wire_budget.ip_bytes = 8 * 1200;
    value.wire_budget.maximum_control_packets = 6;
    value.inactivity_timeout = std::time::Duration::from_secs(5);
    Ok(value)
}

#[tokio::test]
async fn actual_paired_udp_ipv4_loss_and_ipv6_integrity_transfer_both_bulk_directions()
-> Result<(), Box<dyn std::error::Error>> {
    for (host, protection, impaired) in [
        ("127.0.0.1:0", crate::Protection::ChaCha20Poly1305, true),
        ("[::1]:0", crate::Protection::HmacSha256, false),
    ] {
        let ca = UdpSocket::bind(host).await?;
        let cb = UdpSocket::bind(host).await?;
        let sa = UdpSocket::bind(host).await?;
        let sb = UdpSocket::bind(host).await?;
        let configs = [
            config(
                l2tunnel_udp_control::Path {
                    client: ca.local_addr()?,
                    server: sa.local_addr()?,
                },
                0,
                protection,
            )?,
            config(
                l2tunnel_udp_control::Path {
                    client: cb.local_addr()?,
                    server: sb.local_addr()?,
                },
                1,
                protection,
            )?,
        ];
        if impaired {
            for socket in [&ca, &cb, &sa, &sb] {
                crate::test_wire::install(socket.local_addr()?, crate::test_wire::Mode::Impaired)?;
            }
        }
        let cert = rcgen::generate_simple_self_signed(vec!["paired.test".to_owned()])?;
        let chain = vec![cert.cert.der().to_vec()];
        let client_tls = ClientTls::from_der_roots(&chain)?;
        let server_tls = ServerTls::from_der(&chain, &cert.signing_key.serialize_der())?;
        let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
        let members = MemberAllowlist::new(&[member.public_key()])?;
        let (client, server) = timeout(std::time::Duration::from_secs(8), async {
            tokio::try_join!(
                client_pair(
                    [ca, cb],
                    configs,
                    ClientPairCredentials {
                        tls: &client_tls,
                        server_name: "paired.test",
                        member: &member,
                        admissions: [Secret::new([1; 32]), Secret::new([2; 32])]
                    }
                ),
                server_pair(
                    [sa, sb],
                    configs,
                    ServerPairCredentials {
                        tls: &server_tls,
                        members: &members,
                        admissions: [Secret::new([1; 32]), Secret::new([2; 32])],
                        cookies: [Secret::new([3; 32]), Secret::new([4; 32])]
                    }
                ),
            )
        })
        .await??;
        assert_eq!(client.info().digest, server.info().digest);
        assert_ne!(
            client.info().lanes[0].session_id,
            client.info().lanes[1].session_id
        );
        let (cc, ct, mut cr) = client.split();
        let (sc, st, mut sr) = server.split();
        timeout(std::time::Duration::from_secs(8), async {
            tokio::try_join!(
                async {
                    for n in 0..40_u8 {
                        ct.send(&vec![n; 900]).await?;
                    }
                    Ok::<_, Error>(())
                },
                async {
                    for n in 0..33_u8 {
                        st.send(&vec![200 - n; 700]).await?;
                    }
                    Ok::<_, Error>(())
                },
                async {
                    let mut output = [0; 1024];
                    for n in 0..40_u8 {
                        assert_eq!(sr.receive(&mut output).await?, 900);
                        assert_eq!(&output[..900], &vec![n; 900]);
                    }
                    Ok::<_, Error>(())
                },
                async {
                    let mut output = [0; 1024];
                    for n in 0..33_u8 {
                        assert_eq!(cr.receive(&mut output).await?, 700);
                        assert_eq!(&output[..700], &vec![200 - n; 700]);
                    }
                    Ok::<_, Error>(())
                },
            )?;
            Ok::<_, Error>(())
        })
        .await??;
        let status = cc.status()?;
        assert_eq!(status.lanes[0].admitted_packets, 40);
        assert_eq!(status.lanes[1].admitted_packets, 0);
        assert!(
            status.wire.admitted_datagrams
                >= status.lanes[0].admitted_datagrams + status.lanes[1].admitted_datagrams
        );
        if impaired {
            assert!(
                status
                    .lanes
                    .iter()
                    .map(|s| s.discarded_datagrams)
                    .sum::<u64>()
                    > 0
            );
        }
        let lanes = [
            cc.controls[0].shared.clone(),
            cc.controls[1].shared.clone(),
            sc.controls[0].shared.clone(),
            sc.controls[1].shared.clone(),
        ];
        eprintln!(
            "PAIR_CLOSE_START host={host} impaired={impaired} shared={:?} states={:?}",
            lanes.iter().map(std::sync::Arc::as_ptr).collect::<Vec<_>>(),
            lanes
                .iter()
                .map(|v| v.modify(|s| Ok((s.status, s.data_drained, s.tls_finished))))
                .collect::<Vec<_>>()
        );
        let results = tokio::join!(cc.close(), sc.close());
        eprintln!(
            "PAIR_CLOSE_END host={host} impaired={impaired} results={results:?} states={:?}",
            lanes
                .iter()
                .map(|v| v.modify(|s| Ok((
                    s.status,
                    s.data_drained,
                    s.tls_finished,
                    s.close_started.map(|t| t.elapsed())
                ))))
                .collect::<Vec<_>>()
        );
        let (a, b) = (results.0?, results.1?);
        assert!(
            a.into_iter()
                .chain(b)
                .all(|r| r.status.terminal == Some(crate::Terminal::Clean))
        );
    }
    Ok(())
}

#[test]
fn pairing_rejects_duplicate_swapped_and_mismatched_actual_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    let configs = [
        config(
            l2tunnel_udp_control::Path {
                client: "127.0.0.1:2001".parse()?,
                server: "127.0.0.1:2002".parse()?,
            },
            0,
            crate::Protection::ChaCha20Poly1305,
        )?,
        config(
            l2tunnel_udp_control::Path {
                client: "127.0.0.1:2003".parse()?,
                server: "127.0.0.1:2004".parse()?,
            },
            1,
            crate::Protection::ChaCha20Poly1305,
        )?,
    ];
    let infos = [
        SessionInfo {
            session_id: [1; 16],
            peer_member: None,
            member: l2tunnel_auth::MemberPublicKey([7; 32]),
            server: l2tunnel_auth::ServerIdentity([8; 32]),
            config: configs[0].session_config()?,
        },
        SessionInfo {
            session_id: [2; 16],
            peer_member: None,
            member: l2tunnel_auth::MemberPublicKey([7; 32]),
            server: l2tunnel_auth::ServerIdentity([8; 32]),
            config: configs[1].session_config()?,
        },
    ];
    let baseline = binding(infos, configs, false)?;
    assert!(binding([infos[1], infos[0]], configs, false).is_err());
    assert!(binding(infos, configs, true).is_err());
    for case in 0..5 {
        let mut changed = infos;
        match case {
            0 => changed[1].member.0[0] ^= 1,
            1 => changed[1].server.0[0] ^= 1,
            2 => changed[1].session_id = changed[0].session_id,
            3 => changed[1].config.digest.0[0] ^= 1,
            _ => changed[1].peer_member = Some(changed[1].member),
        }
        assert!(binding(changed, configs, false).is_err());
    }
    let mut changed = infos;
    changed[0].session_id[0] ^= 3;
    assert_ne!(binding(changed, configs, false)?, baseline);
    for case in 0..5 {
        let mut changed = configs;
        match case {
            0 => changed[1].profile.lane = changed[0].profile.lane,
            1 => changed.swap(0, 1),
            2 => changed[1].base.digest.0[0] ^= 1,
            3 => changed[1].wire_budget.ip_bytes += 1,
            _ => changed[1].bootstrap.path.client = changed[0].bootstrap.path.client,
        }
        assert!(validate(changed).is_err());
    }
    Ok(())
}

#[tokio::test]
async fn join_replay_phase_and_silent_peer_are_bounded_failures()
-> Result<(), Box<dyn std::error::Error>> {
    fn keys() -> Keys {
        Keys {
            forward: [
                hmac::Key::new(hmac::HMAC_SHA256, &[1; 32]),
                hmac::Key::new(hmac::HMAC_SHA256, &[2; 32]),
            ],
            reverse: [
                hmac::Key::new(hmac::HMAC_SHA256, &[3; 32]),
                hmac::Key::new(hmac::HMAC_SHA256, &[4; 32]),
            ],
        }
    }
    let group = [9; 32];
    let (mut a, mut b) = tokio::io::duplex(256);
    let (result, peer) = tokio::join!(join(&mut a, group, keys(), false, [1; 16]), async {
        receive(&mut b, group, 1, 1).await?;
        send(&mut b, frame(group, [2; 16], 2, 1, [0; 32])).await?;
        receive(&mut b, group, 1, 2).await?;
        // A replayed valid Hello cannot advance the one-use proof state.
        send(&mut b, frame(group, [2; 16], 2, 1, [0; 32])).await
    });
    peer?;
    assert!(matches!(
        result,
        Err(Error::Configuration("pair frame scope/state"))
    ));
    let (mut a, _held_peer) = tokio::io::duplex(256);
    assert!(
        timeout(
            std::time::Duration::from_millis(20),
            join(&mut a, group, keys(), false, [1; 16])
        )
        .await
        .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn failed_second_lane_cancels_both_prepared_owners_without_data_capability()
-> Result<(), Box<dyn std::error::Error>> {
    let ca = UdpSocket::bind("127.0.0.1:0").await?;
    let cb = UdpSocket::bind("127.0.0.1:0").await?;
    let sa = UdpSocket::bind("127.0.0.1:0").await?;
    let sb = UdpSocket::bind("127.0.0.1:0").await?;
    let locals = [
        ca.local_addr()?,
        cb.local_addr()?,
        sa.local_addr()?,
        sb.local_addr()?,
    ];
    let mut configs = [
        config(
            l2tunnel_udp_control::Path {
                client: locals[0],
                server: locals[2],
            },
            0,
            crate::Protection::ChaCha20Poly1305,
        )?,
        config(
            l2tunnel_udp_control::Path {
                client: locals[1],
                server: locals[3],
            },
            1,
            crate::Protection::ChaCha20Poly1305,
        )?,
    ];
    for value in &mut configs {
        value.pairing_timeout = std::time::Duration::from_millis(200);
    }
    let cert = rcgen::generate_simple_self_signed(vec!["cancel-pair.test".to_owned()])?;
    let chain = vec![cert.cert.der().to_vec()];
    let client_tls = ClientTls::from_der_roots(&chain)?;
    let server_tls = ServerTls::from_der(&chain, &cert.signing_key.serialize_der())?;
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let members = MemberAllowlist::new(&[member.public_key()])?;
    let (client, server) = tokio::join!(
        client_pair(
            [ca, cb],
            configs,
            ClientPairCredentials {
                tls: &client_tls,
                server_name: "cancel-pair.test",
                member: &member,
                admissions: [Secret::new([1; 32]), Secret::new([99; 32])]
            }
        ),
        server_pair(
            [sa, sb],
            configs,
            ServerPairCredentials {
                tls: &server_tls,
                members: &members,
                admissions: [Secret::new([1; 32]), Secret::new([2; 32])],
                cookies: [Secret::new([3; 32]), Secret::new([4; 32])]
            }
        ),
    );
    assert!(matches!(client, Err(Error::Timeout)) && matches!(server, Err(Error::Timeout)));
    tokio::task::yield_now().await;
    for local in locals {
        let _released = UdpSocket::bind(local).await?;
    }
    Ok(())
}
