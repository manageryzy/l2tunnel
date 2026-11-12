use super::*;

#[test]
fn default_flow_capacity_after_idle_must_not_terminate_ingress() -> TestResult {
    let rt = runtime(PacketLayer::Ip);
    let transport = udp_transport(Duplex::Full, CoverProfile::QuicLike, Protection::HmacSha256)?;
    let config = Config::for_udp(rt, transport, 4, delivery(rt))?;
    assert_eq!(config.pipeline.flows.capacity, 1024);
    let mut pipeline = Pipeline::new(config.pipeline)?;
    let mut device = Device::new(rt.layer);
    let mut ingress = None;
    let mut buffer = vec![0; l2tunnel_device::READ_BUFFER_BYTES];
    for index in 0..1024u16 {
        let mut bytes = packet(rt.layer, 1, 100);
        bytes[20..22].copy_from_slice(&(10000 + index).to_be_bytes());
        device.change(|state| state.outgoing.push_back(bytes.clone()))?;
        ingress_step(
            &mut device,
            &mut pipeline,
            &mut ingress,
            &mut buffer,
            rt,
            config,
            Duration::ZERO,
        )?;
        assert_eq!(
            pipeline.dequeue()?.ok_or("missing native packet")?.payload,
            bytes
        );
    }
    assert_eq!(pipeline.usage().packets, 0);
    assert_eq!(pipeline.registered_flows(), 1024);
    let mut next = packet(rt.layer, 1, 100);
    next[20..22].copy_from_slice(&20000u16.to_be_bytes());
    device.change(|state| state.outgoing.push_back(next.clone()))?;
    let result = ingress_step(
        &mut device,
        &mut pipeline,
        &mut ingress,
        &mut buffer,
        rt,
        config,
        Duration::from_secs(61),
    );
    assert!(
        result.is_ok(),
        "empty + idle default table terminated session: {result:?}"
    );
    assert_eq!(ingress, Some(next.clone()));
    let mut cursor = None;
    retire_registration(&mut pipeline, None, &mut cursor, Duration::from_secs(61))?;
    ingress_step(
        &mut device,
        &mut pipeline,
        &mut ingress,
        &mut buffer,
        rt,
        config,
        Duration::from_secs(61),
    )?;
    assert!(ingress.is_none());
    assert_eq!(pipeline.dequeue()?.ok_or("retried original")?.payload, next);
    Ok(())
}

#[test]
fn selected_binding_is_pinned_then_same_key_relearns_identical_channel() -> TestResult {
    let rt = runtime(PacketLayer::Ip);
    let transport = udp_transport(Duplex::Full, CoverProfile::QuicLike, Protection::HmacSha256)?;
    let config = Config::for_udp(rt, transport, 4, delivery(rt))?;
    let mut pipeline = Pipeline::new(config.pipeline)?;
    let bytes = packet(rt.layer, 1, 100);
    let original = pipeline.enqueue(bytes.clone(), Duration::ZERO)?;
    let selected = pipeline.dequeue()?.ok_or("selected")?;
    let mut cursor = None;
    retire_registration(
        &mut pipeline,
        Some(&selected),
        &mut cursor,
        Duration::from_secs(61),
    )?;
    assert_eq!(pipeline.registered_flows(), 1);
    assert_eq!(selected.metadata, original);
    assert_eq!(selected.payload, bytes);
    retire_registration(&mut pipeline, None, &mut cursor, Duration::from_secs(61))?;
    // A cursor at the last key wraps on one turn before finding it next turn.
    retire_registration(&mut pipeline, None, &mut cursor, Duration::from_secs(61))?;
    assert_eq!(pipeline.registered_flows(), 0);
    let next = pipeline.enqueue(bytes.clone(), Duration::from_secs(61))?;
    assert_eq!(next.binding.channel, original.binding.channel);
    assert!(next.binding.id.0 > original.binding.id.0);
    assert_eq!(pipeline.dequeue()?.ok_or("relearned")?.payload, bytes);
    Ok(())
}

#[tokio::test]
async fn aligned_retirement_churn_keeps_recovery_and_native_held_bytes() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        let rt = runtime(PacketLayer::Ip);
        let transport = udp_transport(duplex, CoverProfile::QuicLike, Protection::HmacSha256)?;
        let mut config = Config::for_udp(rt, transport, 4, delivery(rt))?;
        config.pipeline.flows.capacity = 4;
        config.pipeline.flows.idle_timeout = Duration::from_millis(10);
        let (a_link, b_link, relays) = udp_links(rt, transport, config, true).await?;
        let a = Device::new(rt.layer);
        let b = Device::new(rt.layer);
        let mut tasks = JoinSet::new();
        tasks.spawn(run_udp(a.clone(), a_link, rt, transport, config));
        tasks.spawn(run_udp(b.clone(), b_link, rt, transport, config));
        let inputs = (1..17)
            .map(|n| packet(rt.layer, n, 100 + usize::from(n)))
            .collect::<Vec<_>>();
        let reverse = (21..37)
            .map(|n| packet(rt.layer, n, 100 + usize::from(n)))
            .collect::<Vec<_>>();
        a.change(|state| state.outgoing.extend(inputs.iter().cloned()))?;
        b.change(|state| {
            state.blocked = true;
            state.outgoing.extend(reverse.iter().cloned());
        })?;
        sleep(Duration::from_millis(70)).await;
        assert!(b.change(|state| state.delivered.is_empty())?);
        b.change(|state| state.blocked = false)?;
        wait_delivery(&mut tasks, &a, &b, inputs.len()).await?;
        for (device, mut expected) in [(&a, reverse), (&b, inputs)] {
            let mut actual = device.change(|state| state.delivered.clone())?;
            expected.sort();
            actual.sort();
            assert_eq!(actual, expected);
        }
        assert!(relays.observations.dropped.load(Ordering::Relaxed) > 0);
        assert!(relays.observations.reordered.load(Ordering::Relaxed) > 0);
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    Ok(())
}

#[test]
fn endpoint_recovery_and_blocked_native_survive_registration_retirement() -> TestResult {
    let rt = runtime(PacketLayer::Ip);
    let transport = udp_transport(Duplex::Full, CoverProfile::QuicLike, Protection::HmacSha256)?;
    let aligned = Config::for_udp(rt, transport, 4, delivery(rt))?;
    let packed = crate::packed::Config::for_udp(
        rt,
        transport,
        4,
        crate::packed::Options {
            hold_micros: 1000,
            max_units: 4,
            work_limit: 16,
        },
        delivery(rt),
    )?;
    for selection in [Selection::Aligned(aligned), Selection::Packed(packed)] {
        let mut config = selection.base().pipeline;
        config.flows.idle_timeout = Duration::from_millis(1);
        let mut pipeline = Pipeline::new(config)?;
        let bytes = packet(rt.layer, 1, 100);
        let metadata = pipeline.enqueue(bytes.clone(), Duration::ZERO)?;
        let selected = pipeline.dequeue()?.ok_or("selected original")?;
        let context = |role| RecoveryContext {
            session: 55,
            epoch: 1,
            role,
        };
        let mut sender = selection.endpoint(context(EndpointRole::Initiator))?;
        let mut receiver = selection.endpoint(context(EndpointRole::Responder))?;
        let channel = protocol::ChannelId(metadata.binding.channel as u8);
        sender.enqueue_identified(channel, &selected.payload, Duration::ZERO)?;
        let staged = sender.status();
        assert!(
            staged.staged_frame
                || staged.recovery.arq.send_records > 0
                || staged
                    .packing
                    .is_some_and(|packing| packing.packing.units > 0)
        );
        let mut cursor = None;
        retire_registration(&mut pipeline, None, &mut cursor, Duration::from_millis(1))?;
        assert_eq!(pipeline.registered_flows(), 0);
        assert_eq!(sender.status(), staged);
        let mut wire = vec![0; transport.policy()?.payload_bytes];
        let mut budget = l2tunnel_reliable::OutboundBudget {
            packets: 64,
            wire_bytes: 65536,
        };
        for tick in 1..=5 {
            let now = Duration::from_millis(tick);
            sender.tick(now)?;
            for _ in 0..16 {
                let Some(length) = sender.poll_data(now, &mut wire, &mut budget)? else {
                    break;
                };
                receiver.receive_authenticated(&wire[..length], now)?;
            }
            receiver.prepare(channel, now, 16)?;
            if receiver.pending().is_some() {
                break;
            }
        }
        let frame = receiver.pending().ok_or("recovered native bytes")?;
        assert_eq!(frame.bytes, bytes);
        assert_eq!(frame.channel, channel);
        let learned = pipeline.learn(
            metadata.classification.key,
            u16::from(channel.0),
            1,
            Duration::from_millis(5),
        )?;
        assert!(learned.id.0 > metadata.binding.id.0);
        let held = receiver.status();
        let mut native = Device::new(rt.layer);
        native.change(|state| state.blocked = true)?;
        assert_eq!(
            native
                .transmit(receiver.pending().ok_or("held")?.bytes)
                .err()
                .ok_or("must block")?
                .kind(),
            io::ErrorKind::WouldBlock
        );
        for _ in 0..2 {
            retire_registration(&mut pipeline, None, &mut cursor, Duration::from_millis(6))?;
        }
        assert_eq!(pipeline.registered_flows(), 0);
        assert_eq!(receiver.status(), held);
        assert_eq!(receiver.pending().ok_or("retained pending")?.bytes, bytes);
        let rebound = pipeline.learn(
            metadata.classification.key,
            u16::from(channel.0),
            1,
            Duration::from_millis(6),
        )?;
        assert_eq!(rebound.channel, metadata.binding.channel);
        assert!(rebound.id.0 > learned.id.0);
        native.change(|state| state.blocked = false)?;
        native.transmit(receiver.pending().ok_or("deliver")?.bytes)?;
        receiver.commit_delivery(Duration::from_millis(6))?;
        assert_eq!(native.change(|state| state.delivered.clone())?, vec![bytes]);
        assert!(receiver.pending().is_none());
    }
    Ok(())
}
