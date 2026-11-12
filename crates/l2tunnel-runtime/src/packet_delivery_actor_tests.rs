//! One generated actual-carrier contract, instantiated by both base test adapters.
macro_rules! actual_native_flight {
    () => {
#[tokio::test]
async fn actual_bytes_more_than64_sent_and_outstanding_with_local2_then_exact128_release()
-> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        for layer in [PacketLayer::Ethernet, PacketLayer::Ip] {
            for compression in [Compression::None, Compression::Lz4IfSmaller] {
                for recovery in [
                    RecoveryMode::SelectiveRepeat,
                    RecoveryMode::Cauchy {
                        sources: 3,
                        repairs: 2,
                        flush_after: Duration::from_millis(2),
                    },
                ] {
                    let mut rt = runtime(layer);
                    rt.compression = compression;
                    assert_eq!(rt.queue_packets, 2);
                    let mut policy = native_delivery(rt);
                    for direction in [&mut policy.forward, &mut policy.reverse] {
                        direction.max_records = 128;
                        direction.max_inflight_bytes = 131072;
                    }
                    let (transport, a_link, b_link, relays) =
                        delivery_links(rt, duplex, recovery, policy).await?;
                    assert_eq!(transport.arq.send_records, 64);
                    assert_eq!(transport.arq.receive_records, 64);
                    let a = Device::new(layer);
                    let b = Device::new(layer);
                    let input = |offset: u8| {
                        (0..128u8)
                            .map(|i| {
                                packet(
                                    layer,
                                    i.wrapping_add(offset),
                                    if i % 2 == 0 { 1500 } else { 40 },
                                )
                            })
                            .collect::<Vec<_>>()
                    };
                    let forward = input(0);
                    let reverse = input(100);
                    let total = forward.iter().map(|p| p.len() as u64).sum::<u64>();
                    assert_eq!(total, 98560);
                    a.change(|n| {
                        n.blocked = true;
                        n.outgoing = forward.clone().into()
                    })?;
                    b.change(|n| {
                        n.blocked = true;
                        n.outgoing = reverse.clone().into()
                    })?;
                    let (ao, ar) = crate::udp::observations();
                    let (bo, br) = crate::udp::observations();
                    let mut tasks = tokio::task::JoinSet::new();
                    tasks.spawn(run_observed(
                        a.clone(),
                        a_link,
                        rt,
                        transport,
                        Some(ar),
                        policy,
                    ));
                    tasks.spawn(run_observed(
                        b.clone(),
                        b_link,
                        rt,
                        transport,
                        Some(br),
                        policy,
                    ));
                    tokio::time::timeout(Duration::from_secs(3),async {
                        loop {
                            let ready=[&ao,&bo].iter().all(|observer| {
                                let status=observer.status();
                                status.lanes.iter().flatten().any(|s|s.delivery.outstanding.records>64
                                    &&s.delivery.flushed_total.records>64&&s.delivery.delivered.records==0)
                                    &&status.lanes.iter().flatten().any(|s|s.device_blocked)
                            });
                            if ready {return Ok::<_,io::Error>(());}
                            tokio::select! {
                                result=tasks.join_next()=>return Err(io::Error::other(format!("base actor ended under pressure: {result:?}"))),
                                _=tokio::time::sleep(Duration::from_millis(1))=>{},
                            }
                        }
                    }).await.map_err(|e|format!("{duplex:?}/{layer:?}/{compression:?}/{recovery:?} pressure {e}; a={:?},b={:?}",ao.status(),bo.status()))??;
                    for observer in [&ao, &bo] {
                        for lane in observer.status().lanes.iter().flatten() {
                            assert_eq!(lane.local_queue_limit, 2);
                            assert!(lane.local_queued <= 2);
                            assert!(lane.recovery.send_records <= 64);
                            assert!(lane.recovery.receive_records <= 64);
                            assert_eq!(lane.delivery.outstanding, lane.delivery.admitted);
                            assert_eq!(lane.delivery.delivered.records, 0);
                            assert!(lane.native_pending_bytes <= policy.forward.max_inflight_bytes);
                            assert!(lane.local_queued + lane.bank_records <= 128);
                        }
                    }
                    for device in [&a, &b] {
                        assert!(device.change(|n| n.delivered.is_empty())?);
                        device.change(|n| n.blocked = false)?;
                    }
                    tokio::time::timeout(Duration::from_secs(8),async {
                        loop {
                            let all=[&ao,&bo].iter().all(|o|o.status().lanes.iter().flatten().filter(|s|s.delivery.admitted.records!=0).all(|s|s.delivery.delivered.records==128&&s.delivery.retained_records==0));
                            if a.change(|n|n.delivered.len()==128)?&&b.change(|n|n.delivered.len()==128)?&&all {return Ok::<_,io::Error>(());}
                            tokio::select! {
                                result=tasks.join_next()=>return Err(io::Error::other(format!("base actor ended before exact release: {result:?}"))),
                                _=tokio::time::sleep(Duration::from_millis(1))=>{},
                            }
                        }
                    }).await.map_err(|e|format!("{duplex:?}/{layer:?}/{compression:?}/{recovery:?} release {e};a={:?},b={:?}",ao.status(),bo.status()))??;
                    assert_eq!(a.change(|n| n.delivered.clone())?, reverse);
                    assert_eq!(b.change(|n| n.delivered.clone())?, forward);
                    for observer in [&ao, &bo] {
                        for lane in observer
                            .status()
                            .lanes
                            .iter()
                            .flatten()
                            .filter(|s| s.delivery.admitted.records != 0)
                        {
                            for credit in [
                                lane.delivery.admitted,
                                lane.delivery.delivered,
                                lane.delivery.delivered_prefix,
                                lane.delivery.flushed,
                                lane.delivery.flushed_total,
                            ] {
                                assert_eq!(credit.records, 128);
                                assert_eq!(credit.bytes, total);
                            }
                            assert_eq!(lane.delivery.outstanding.bytes, 0);
                            assert_eq!(lane.delivery.outstanding.records, 0);
                            assert_eq!(lane.delivery.retained_records, 0);
                            assert!(lane.delivery.next_flush_deadline.is_none());
                        }
                    }
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    drop(relays);
                }
            }
        }
    }
    Ok(())
}

    };
}
pub(crate) use actual_native_flight;
