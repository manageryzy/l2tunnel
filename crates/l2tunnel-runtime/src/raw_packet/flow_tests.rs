use super::*;

#[tokio::test]
async fn raw_default_flow_1025_retains_ingress_after_idle() -> R {
    let config = config(PacketLayer::Ip, false, false, Protection::ChaCha20Poly1305)?;
    let (mut a, _b, _probes) = links(config).await?;
    let device = Device::new(PacketLayer::Ip);
    let mut owner = Owner::new(
        device.clone(),
        a.carrier.take().ok_or("carrier")?,
        config,
        a.status.clone(),
    )?;
    assert_eq!(owner.config.pipeline.flows.capacity, 1024);
    for port in 10000..11024u16 {
        let mut bytes = packet(PacketLayer::Ip, 1, 100);
        bytes[20..22].copy_from_slice(&port.to_be_bytes());
        owner.pipeline.enqueue(bytes, Duration::ZERO)?;
        owner.pipeline.dequeue()?;
    }
    let original = packet(PacketLayer::Ip, 1, 100);
    device.change(|state| state.outgoing.push_back(original.clone()))?;
    owner.ingress(Duration::from_secs(61))?;
    assert_eq!(owner.ingress, Some(original.clone()));
    owner.retire_registration(Duration::from_secs(61))?;
    owner.ingress(Duration::from_secs(61))?;
    assert!(owner.ingress.is_none());
    assert_eq!(
        owner.pipeline.dequeue()?.ok_or("retried original")?.payload,
        original
    );
    Ok(())
}

#[tokio::test]
async fn raw_reverse_capacity_keeps_completed_reassembly() -> R {
    let mut config = config(PacketLayer::Ip, false, false, Protection::ChaCha20Poly1305)?;
    config.pipeline.flows.idle_timeout = Duration::from_millis(1);
    let (mut a, mut b, _probes) = links(config).await?;
    let device = Device::new(PacketLayer::Ip);
    let mut owner = Owner::new(
        device.clone(),
        a.carrier.take().ok_or("carrier")?,
        config,
        a.status.clone(),
    )?;
    let mut sender = Owner::new(
        Device::new(PacketLayer::Ip),
        b.carrier.take().ok_or("peer carrier")?,
        config,
        b.status.clone(),
    )?;
    for port in 10000..11024u16 {
        let mut bytes = packet(PacketLayer::Ip, 1, 100);
        bytes[20..22].copy_from_slice(&port.to_be_bytes());
        owner.pipeline.enqueue(bytes, Duration::ZERO)?;
        owner.pipeline.dequeue()?;
    }
    let original = packet(PacketLayer::Ip, 1, 100);
    let metadata = sender.pipeline.enqueue(original.clone(), Duration::ZERO)?;
    let mut record = metadata.binding.channel.to_be_bytes().to_vec();
    record.extend_from_slice(&[0; 2]);
    record.extend_from_slice(&sender.codec.encode_vec(&original)?);
    for fragment in sender.lanes[0].fragmenter.fragment(&record)?.fragments {
        sender.lanes[0].engine.submit(&fragment, Duration::ZERO)?;
    }
    let mut wire = vec![0; config.recovery_bytes()?];
    let mut budget = OutboundBudget {
        packets: 64,
        wire_bytes: 65536,
    };
    while let Some(length) =
        sender.lanes[0]
            .engine
            .poll(false, Duration::ZERO, &mut wire, &mut budget)?
    {
        owner.lanes[0]
            .engine
            .receive(&wire[..length], Duration::ZERO)?;
    }
    owner.native(0, Duration::ZERO)?;
    assert_eq!(owner.status.received[0], 1);
    assert_eq!(owner.status.delivered[0], 0);
    assert_eq!(owner.lanes[0].native.len(), 1);
    assert!(device.change(|state| state.delivered.is_empty())?);
    device.change(|state| state.blocked = true)?;
    owner.native(0, Duration::ZERO)?;
    assert!(!owner.lanes[0].native.front().ok_or("held native")?.prepared);
    assert_eq!(owner.lanes[0].native.front().ok_or("held")?.bytes, original);
    owner.retire_registration(Duration::from_millis(1))?;
    owner.native(0, Duration::from_millis(1))?;
    assert!(owner.lanes[0].native.front().ok_or("prepared")?.prepared);
    assert_eq!(owner.status.delivered[0], 0);
    let key = owner.pipeline.classify(&original)?.key;
    owner.idle_cursor = None;
    owner.retire_registration(Duration::from_millis(2))?;
    assert!(owner.pipeline.flow(&key).is_none());
    assert_eq!(
        owner.lanes[0]
            .native
            .front()
            .ok_or("retained after retirement")?
            .bytes,
        original
    );
    device.change(|state| state.blocked = false)?;
    owner.native(0, Duration::from_millis(2))?;
    assert_eq!(
        device.change(|state| state.delivered.clone())?,
        vec![original]
    );
    assert_eq!(owner.status.delivered[0], 1);
    assert!(owner.lanes[0].native.is_empty());
    Ok(())
}

#[tokio::test]
async fn raw_selected_and_recovery_ownership_survive_1100_successive_flows() -> R {
    let mut config = config(PacketLayer::Ip, false, false, Protection::ChaCha20Poly1305)?;
    config.pipeline.flows.idle_timeout = Duration::from_millis(1);
    let (mut a, _b, _probes) = links(config).await?;
    let device = Device::new(PacketLayer::Ip);
    let mut owner = Owner::new(
        device.clone(),
        a.carrier.take().ok_or("carrier")?,
        config,
        a.status.clone(),
    )?;
    let original = packet(PacketLayer::Ip, 1, 4000);
    let metadata = owner.pipeline.enqueue(original.clone(), Duration::ZERO)?;
    owner.selected = owner.pipeline.dequeue()?;
    for _ in 0..3 {
        owner.retire_registration(Duration::from_millis(1))?;
    }
    assert_eq!(
        owner
            .pipeline
            .flow(&metadata.classification.key)
            .map(|v| v.binding),
        Some(metadata.binding)
    );
    assert_eq!(
        owner.selected.as_ref().map(|v| v.payload.as_slice()),
        Some(original.as_slice())
    );
    owner.admit(0, Duration::from_millis(1))?;
    assert!(owner.selected.is_none());
    let fragments = owner.lanes[0].fragments.clone();
    let sources = owner.status.sources;
    for _ in 0..2 {
        owner.retire_registration(Duration::from_millis(2))?;
    }
    assert_eq!(owner.pipeline.registered_flows(), 0);
    assert_eq!(owner.lanes[0].fragments, fragments);
    assert_eq!(owner.status.sources, sources);
    let mut last_id = metadata.binding.id.0;
    for offset in 0..1100u16 {
        let now = Duration::from_millis(u64::from(offset) + 3);
        owner.retire_registration(now)?;
        let mut bytes = packet(PacketLayer::Ip, 1, 100);
        bytes[20..22].copy_from_slice(&(10000 + offset).to_be_bytes());
        device.change(|state| state.outgoing.push_back(bytes.clone()))?;
        owner.ingress(now)?;
        let selected = owner.pipeline.dequeue()?.ok_or("retained input")?;
        assert_eq!(selected.payload, bytes);
        assert!(selected.metadata.binding.id.0 > last_id);
        last_id = selected.metadata.binding.id.0;
        assert!(owner.pipeline.registered_flows() <= 2);
    }
    // The first real frame's original recovery state remains owned throughout.
    assert_eq!(owner.lanes[0].fragments, fragments);
    assert_eq!(owner.status.sources, sources);
    Ok(())
}

#[tokio::test]
async fn raw_flow_churn_keeps_full_half_native_credit_order_and_recovery() -> R {
    for (half, cauchy) in [(false, false), (true, true)] {
        let mut config = config(PacketLayer::Ip, half, cauchy, Protection::ChaCha20Poly1305)?;
        config.pipeline.flows.capacity = 4;
        config.pipeline.flows.idle_timeout = Duration::from_millis(10);
        let (a, b, probes) = links(config).await?;
        for probe in &probes {
            probe.impair.store(true, Ordering::SeqCst);
        }
        let ad = Device::new(PacketLayer::Ip);
        let bd = Device::new(PacketLayer::Ip);
        let forward = (1..17)
            .map(|n| packet(PacketLayer::Ip, n, 100))
            .collect::<Vec<_>>();
        let reverse = (21..37)
            .map(|n| packet(PacketLayer::Ip, n, 100))
            .collect::<Vec<_>>();
        ad.change(|s| s.outgoing.extend(forward.iter().cloned()))?;
        bd.change(|s| {
            s.blocked = true;
            s.outgoing.extend(reverse.iter().cloned());
        })?;
        let ast = a.subscribe();
        let bst = b.subscribe();
        let ar = tokio::spawn(run(ad.clone(), a));
        let br = tokio::spawn(run(bd.clone(), b));
        tokio::time::sleep(Duration::from_millis(70)).await;
        assert!(bd.change(|s| s.delivered.is_empty())?);
        assert_eq!(bst.borrow().delivered.iter().sum::<u64>(), 0);
        bd.change(|s| s.blocked = false)?;
        wait_native(&ad, &bd, forward.len()).await?;
        assert_eq!(ad.change(|s| s.delivered.clone())?, reverse);
        assert_eq!(bd.change(|s| s.delivered.clone())?, forward);
        assert_eq!(ast.borrow().fault, None);
        assert_eq!(bst.borrow().fault, None);
        ar.abort();
        br.abort();
        let _ = ar.await;
        let _ = br.await;
        assert!(probes.iter().any(|p| p.loss.load(Ordering::SeqCst) > 0));
        assert!(probes.iter().all(|p| p.dropped.load(Ordering::SeqCst) == 1));
    }
    Ok(())
}

#[tokio::test]
async fn raw_reverse_1100_native_flows_preserve_exact_bytes_and_local_ids() -> R {
    let mut config = config(PacketLayer::Ip, false, false, Protection::ChaCha20Poly1305)?;
    config.pipeline.flows.idle_timeout = Duration::from_millis(1);
    let (mut a, _b, _probes) = links(config).await?;
    let device = Device::new(PacketLayer::Ip);
    let mut owner = Owner::new(
        device.clone(),
        a.carrier.take().ok_or("carrier")?,
        config,
        a.status.clone(),
    )?;
    let mut expected = Vec::new();
    let mut last_id = 0;
    for offset in 0..1100u16 {
        let now = Duration::from_millis(u64::from(offset));
        owner.retire_registration(now)?;
        let mut original = packet(PacketLayer::Ip, 1, 100);
        original[20..22].copy_from_slice(&(20000 + offset).to_be_bytes());
        let mut sender = Pipeline::new(config.pipeline)?;
        let metadata = sender.enqueue(original.clone(), Duration::ZERO)?;
        // This fixture starts at the validated reassembly handoff. The separate
        // reverse-capacity regression traverses actual encoded recovery bytes.
        owner.lanes[0].native_bytes += original.len() as u64;
        owner.lanes[0].native.push_back(NativeFrame {
            bytes: original.clone(),
            channel: metadata.binding.channel,
            prepared: false,
        });
        increment(&mut owner.status.received[0])?;
        owner.native(0, now)?;
        assert!(owner.lanes[0].native.is_empty());
        let binding = owner
            .pipeline
            .flow(&metadata.classification.key)
            .ok_or("learned reverse")?
            .binding;
        assert_eq!(binding.channel, metadata.binding.channel);
        assert!(binding.id.0 > last_id);
        last_id = binding.id.0;
        expected.push(original);
        assert!(owner.pipeline.registered_flows() <= 2);
    }
    assert_eq!(device.change(|v| v.delivered.clone())?, expected);
    assert_eq!(owner.status.delivered[0], 1100);
    Ok(())
}

#[tokio::test]
async fn raw_full_flow_table_does_not_hide_bad_inner_or_channel_before_native_write() -> R {
    let config = config(PacketLayer::Ip, false, false, Protection::ChaCha20Poly1305)?;
    let (mut a, _b, _probes) = links(config).await?;
    let device = Device::new(PacketLayer::Ip);
    let mut owner = Owner::new(
        device.clone(),
        a.carrier.take().ok_or("carrier")?,
        config,
        a.status.clone(),
    )?;
    for port in 10000..11024u16 {
        let mut bytes = packet(PacketLayer::Ip, 1, 100);
        bytes[20..22].copy_from_slice(&port.to_be_bytes());
        owner.pipeline.enqueue(bytes, Duration::ZERO)?;
        owner.pipeline.dequeue()?;
    }
    for malformed in [true, false] {
        let mut bytes = packet(PacketLayer::Ip, 1, 100);
        let mut sender = Pipeline::new(config.pipeline)?;
        let channel = sender
            .enqueue(bytes.clone(), Duration::ZERO)?
            .binding
            .channel;
        if malformed {
            bytes.truncate(28);
            bytes[2..4].copy_from_slice(&28u16.to_be_bytes());
        }
        owner.lanes[0].native_bytes += bytes.len() as u64;
        owner.lanes[0].native.push_back(NativeFrame {
            bytes,
            channel: if malformed {
                channel
            } else {
                (channel + 1) % 4
            },
            prepared: false,
        });
        assert!(owner.native(0, Duration::ZERO).is_err());
        assert!(device.change(|state| state.delivered.is_empty())?);
        assert_eq!(owner.status.delivered[0], 0);
        owner.lanes[0].native.clear();
    }
    Ok(())
}
