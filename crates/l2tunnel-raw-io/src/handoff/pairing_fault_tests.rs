use super::test_support::*;
use super::*;
use std::{future::poll_fn, sync::atomic::Ordering};

#[tokio::test]
async fn real_certificate_member_and_profile_mismatches_fail_owned_group() -> R {
    for case in 0..4 {
        let (c, s, m, allowed) = fixture()?;
        let (foreign, _, other, _) = fixture()?;
        let wrong_members = MemberAllowlist::new(&[other.public_key()])?;
        let (ai, bi, probes) = inputs(true);
        let mut server_config = config();
        if case == 3 {
            server_config.session.digest.0[0] ^= 1;
        }
        let mut a = begin_pair_client(
            ai,
            if case == 1 { &foreign } else { &c },
            if case == 0 {
                "wrong.test"
            } else {
                "tunnel.test"
            },
            &m,
            config(),
        )?;
        let mut b = begin_pair_server(
            bi,
            &s,
            if case == 2 { &wrong_members } else { &allowed },
            server_config,
        )?;
        let (failed, error) = poll_fn(|cx| {
            for (index, setup) in [(0, &mut a), (1, &mut b)] {
                if let Poll::Ready(result) = Pin::new(setup).poll(cx) {
                    return Poll::Ready((index, result.err()));
                }
            }
            Poll::Pending
        })
        .await;
        assert!(
            matches!(error, Some(PairError::Setup(_))),
            "case {case}: {error:?}"
        );
        let status = if failed == 0 { a.status() } else { b.status() }.ok_or("status")?;
        assert!(status.fault.is_some());
        assert!(
            status
                .bridges
                .iter()
                .flatten()
                .any(|s| s.driver.raw_received_bytes > 0)
        );
        assert!(
            status
                .bridges
                .iter()
                .flatten()
                .any(|s| s.driver.raw_sent_bytes > 0)
        );
        drop((a, b));
        for p in probes {
            assert_eq!(p.dropped.load(Ordering::SeqCst), 1);
        }
    }
    Ok(())
}
#[tokio::test]
async fn authenticated_bad_pair_phase_or_binding_terminates_without_keys() -> R {
    for case in 0..5 {
        let (c, s, m, allowed) = fixture()?;
        let (ai, bi, probes) = inputs(false);
        let mut a = begin_pair_client(ai, &c, "tunnel.test", &m, config())?;
        let mut b = begin_pair_server(bi, &s, &allowed, config())?;
        let target = if case == 4 { 3 } else { 1 };
        poll_fn(|cx| {
            for setup in [&mut a, &mut b] {
                if setup.phase < target {
                    if let Poll::Ready(result) = Pin::new(setup).poll(cx) {
                        return Poll::Ready(result.map(|_| ()));
                    }
                } else {
                    setup.group.as_mut().ok_or(PairError::Identity)?.drive(cx)?;
                }
            }
            if a.phase == target && b.phase == target {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        })
        .await?;
        let transcript = b.transcript.ok_or("transcript")?;
        let mut bad = encode(1, 0, &transcript);
        match case {
            0 => bad[5] = 2,            // valid authenticated Confirm in the Offer phase
            1 => bad[6] = 1,            // another physical lane
            2 => bad[8 + 132 + 4] ^= 1, // a different actual session
            3 => bad[8 + 184] = 1,      // nonzero absent full lane slot
            4 => {}                     // Duplicate original Offer while awaiting Accepted.
            _ => return Err("case".into()),
        }
        b.group.as_mut().ok_or("group")?.owners[0]
            .as_mut()
            .ok_or("owner")?
            .stage_message(&bad)?;
        let error = poll_fn(|cx| {
            let group = b.group.as_mut().ok_or(PairError::Identity)?;
            group.drive(cx)?;
            if let Poll::Ready(result) = group.owners[0]
                .as_mut()
                .ok_or(PairError::Identity)?
                .poll_send(cx)
            {
                result.map_err(PairError::Message)?;
            }
            if let Poll::Ready(result) = Pin::new(&mut a).poll(cx) {
                return Poll::Ready(result.map(|_| ()));
            }
            Poll::Pending
        })
        .await;
        assert!(matches!(error, Err(PairError::Protocol)));
        let group = a.group.as_ref().ok_or("failed group")?;
        assert!(group.owners.iter().all(Option::is_none));
        assert!(group.keys.is_none());
        assert!(group.roots.iter().all(Option::is_none));
        drop((a, b));
        for p in probes {
            assert_eq!(p.dropped.load(Ordering::SeqCst), 1);
        }
    }
    Ok(())
}
#[tokio::test]
async fn actual_groups_derive_distinct_private_keys_and_keep_common_policy() -> R {
    let (a, b, _) = paired(true).await?;
    let (c, d, _) = paired(true).await?;
    assert_eq!(a.info().profile, c.info().profile);
    assert_ne!(a.info().transcript_digest, c.info().transcript_digest);
    let ka = &a.group.keys.as_ref().ok_or("keys")?._values;
    let kb = &b.group.keys.as_ref().ok_or("keys")?._values;
    let kc = &c.group.keys.as_ref().ok_or("keys")?._values;
    assert_eq!(ka, kb);
    for i in 0..12 {
        assert_ne!(ka[i], kc[i]);
    }
    assert_eq!(kc, &d.group.keys.as_ref().ok_or("keys")?._values);
    Ok(())
}

#[tokio::test]
async fn injected_provider_error_or_missing_root_exposes_no_partial_key_set() -> R {
    use l2tunnel_auth::{
        Direction::{ClientToServer, ServerToClient},
        KeyPurpose::{LaneJoin, Management},
    };
    for case in 0..3 {
        let (c, s, m, allowed) = fixture()?;
        let (ai, bi, probes) = inputs(true);
        let mut a = begin_pair_client(ai, &c, "tunnel.test", &m, config())?;
        let mut b = begin_pair_server(bi, &s, &allowed, config())?;
        poll_fn(|cx| {
            for setup in [&mut a, &mut b] {
                if setup.phase == 0 {
                    if let Poll::Ready(result) = Pin::new(setup).poll(cx) {
                        return Poll::Ready(result.map(|_| ()));
                    }
                } else {
                    setup.group.as_mut().ok_or(PairError::Identity)?.drive(cx)?;
                }
            }
            if a.phase == 1 && b.phase == 1 {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        })
        .await?;
        let g = b.group.as_mut().ok_or("group")?;
        assert!(g.keys.is_none());
        let error = match case {
            0 => {
                let mut calls = 0;
                let result = g.proposal(|_| {
                    calls += 1;
                    Err(PairError::Keys)
                });
                assert_eq!(calls, 1);
                result.err().ok_or("accepted entropy error")?
            }
            1 => {
                let mut roots: std::collections::VecDeque<_> =
                    g.roots[0].take().ok_or("roots")?.into();
                let mut calls = Vec::new();
                let result = tls_owner::collect_roots(1, |purpose, direction, lane| {
                    calls.push((purpose, direction, lane));
                    if calls.len() == 3 {
                        Err(l2tunnel_auth::Error::Random)
                    } else {
                        roots.pop_front().ok_or(l2tunnel_auth::Error::Random)
                    }
                });
                assert!(matches!(result, Err(l2tunnel_auth::Error::Random)));
                assert_eq!(
                    calls,
                    vec![
                        (LaneJoin, ClientToServer, 1),
                        (LaneJoin, ServerToClient, 1),
                        (Management, ClientToServer, 1)
                    ]
                );
                PairError::Keys
            }
            2 => {
                g.roots[1] = None;
                g.complete(b.transcript.ok_or("transcript")?)
                    .err()
                    .ok_or("accepted missing root")?
            }
            _ => return Err("case".into()),
        };
        assert!(matches!(b.fail(error), Poll::Ready(Err(PairError::Keys))));
        let g = b.group.as_ref().ok_or("failed group")?;
        assert!(g.keys.is_none());
        assert!(g.info.is_none());
        assert!(g.roots.iter().all(Option::is_none));
        assert!(g.owners.iter().all(Option::is_none));
        assert!(g.drivers.iter().all(Option::is_none));
        drop((a, b));
        for p in probes {
            assert_eq!(p.dropped.load(Ordering::SeqCst), 1);
        }
    }
    Ok(())
}
