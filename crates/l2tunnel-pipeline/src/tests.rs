use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn config(profile: Profile) -> PipelineConfig {
    PipelineConfig {
        profile,
        flows: FlowTableConfig {
            capacity: 64,
            channels: 3,
            mapping: Mapping::ConnectionRoundRobin,
            idle_timeout: Duration::from_secs(5),
        },
        parse: ParseLimits {
            max_packet_bytes: 1600,
            ..ParseLimits::default()
        },
        queue: QueueLimits {
            bytes: 1_000_000,
            packets: 10_000,
        },
    }
}

fn tun() -> Profile {
    Profile::TunDrr(TunQosConfig {
        base_quantum_bytes: 1500,
        max_weight: 16,
        per_flow: QueueLimits {
            bytes: 500_000,
            packets: 5_000,
        },
    })
}

fn ip(port: u16, length: usize, reverse: bool, value: u8) -> Vec<u8> {
    let mut bytes = vec![value; length];
    bytes[..40].fill(0);
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&(length as u16).to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 6;
    let (source, destination, sport, dport) = if reverse {
        ([10, 0, 0, 2], [10, 0, 0, 1], 443, port)
    } else {
        ([10, 0, 0, 1], [10, 0, 0, 2], port, 443)
    };
    bytes[12..16].copy_from_slice(&source);
    bytes[16..20].copy_from_slice(&destination);
    bytes[20..22].copy_from_slice(&sport.to_be_bytes());
    bytes[22..24].copy_from_slice(&dport.to_be_bytes());
    bytes[32] = 0x50;
    bytes[33] = 0x10;
    bytes
}

fn ethernet(protocol: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![1; 12];
    bytes[6..12].fill(2);
    bytes.extend_from_slice(&protocol.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

#[test]
fn explicit_drain_and_fresh_pipeline_inheritance_preserve_queued_bytes_and_ids() -> TestResult {
    let mut old = Pipeline::new(config(tun()))?;
    let mut next_config = config(tun());
    next_config.flows.channels = 1;
    let mut next = Pipeline::new(next_config)?;
    let bytes = ip(1000, 100, false, 7);
    let meta = old.enqueue_weighted(bytes.clone(), 2, Duration::ZERO)?;
    let before = old.usage();
    assert_eq!(
        old.retire_drained(&meta.classification.key),
        Err(PipelineError::Busy)
    );
    assert_eq!(next.continue_ids_from(&old), Err(PipelineError::Busy));
    assert_eq!(old.usage(), before);
    assert_eq!(old.dequeue()?.ok_or("packet")?.payload, bytes);
    assert_eq!(next.continue_ids_from(&old), Err(PipelineError::Busy));
    assert_eq!(
        old.retire_idle_drained(&meta.classification.key, Duration::ZERO),
        Err(PipelineError::Flow(l2tunnel_packet::FlowError::NotIdle))
    );
    old.retire_drained(&meta.classification.key)?;
    next.continue_ids_from(&old)?;
    let new_meta = next.enqueue_weighted(bytes, 4, Duration::ZERO)?;
    assert_eq!(new_meta.binding.id.0, 2);
    assert_eq!(new_meta.binding.channel, 0);
    assert_eq!(
        next.flow(&new_meta.classification.key)
            .ok_or("flow")?
            .weight,
        4
    );
    Ok(())
}

#[test]
fn tap_preserves_arp_vlan_opaque_and_fifo_round_robin_without_custom_qos() -> TestResult {
    let mut pipeline = Pipeline::new(config(Profile::TapSystem))?;
    let opaque = ethernet(0x88b5, b"management-shaped user data");
    let mut arp = [0; 28];
    arp[..8].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
    arp[14..18].copy_from_slice(&[10, 0, 0, 1]);
    arp[24..28].copy_from_slice(&[10, 0, 0, 2]);
    let arp = ethernet(0x0806, &arp);
    let mut tagged = vec![0, 7, 8, 0];
    tagged.extend_from_slice(&ip(1234, 100, false, 9));
    let vlan = ethernet(0x8100, &tagged);
    let first = pipeline.enqueue(opaque.clone(), Duration::ZERO)?;
    pipeline.enqueue(opaque.clone(), Duration::ZERO)?;
    let second = pipeline.enqueue(arp.clone(), Duration::ZERO)?;
    let third = pipeline.enqueue(vlan.clone(), Duration::ZERO)?;
    assert_eq!(
        (
            first.binding.channel,
            second.binding.channel,
            third.binding.channel
        ),
        (0, 1, 2)
    );
    assert_eq!(
        pipeline
            .enqueue_weighted(opaque.clone(), 2, Duration::ZERO)
            .map_err(|error| error.kind),
        Err(PipelineError::TunOnly)
    );
    assert!(matches!(
        pipeline.dequeue_with(|_| true, |_| Ok::<(), Infallible>(())),
        Err(DequeueError::Pipeline(PipelineError::TunOnly))
    ));
    for expected in [opaque.clone(), arp, vlan, opaque] {
        let packet = pipeline.dequeue()?.ok_or("queued frame")?;
        assert_eq!(packet.payload, expected);
        assert_eq!(packet.payload.capacity(), packet.payload.len());
    }
    assert_eq!(pipeline.usage(), QueueUsage::default());
    assert_eq!(pipeline.dequeue()?, None);
    Ok(())
}

#[test]
fn reverse_crc_affinity_and_round_robin_conflicts_are_explicit() -> TestResult {
    let mut cfg = config(tun());
    cfg.flows.mapping = Mapping::Crc32;
    let mut pipeline = Pipeline::new(cfg)?;
    let forward = pipeline.enqueue(ip(1234, 100, false, 1), Duration::ZERO)?;
    let reverse = pipeline.enqueue(ip(1234, 100, true, 2), Duration::ZERO)?;
    assert_eq!(forward.binding, reverse.binding);
    assert_eq!(pipeline.registered_flows(), 1);
    let key = forward.classification.key;
    assert!(matches!(
        pipeline.learn(key, (forward.binding.channel + 1) % 3, 1, Duration::ZERO),
        Err(PipelineError::Flow(
            l2tunnel_packet::FlowError::BindingConflict { .. }
        ))
    ));
    let mut a = Pipeline::new(config(tun()))?;
    let mut b = Pipeline::new(config(tun()))?;
    let key1 = a.classify(&ip(1, 40, false, 0))?.key;
    let key2 = a.classify(&ip(2, 40, false, 0))?.key;
    a.learn(key1, 2, 1, Duration::ZERO)?;
    assert_eq!(
        a.enqueue(ip(2, 40, false, 0), Duration::ZERO)?
            .binding
            .channel,
        0
    );
    b.enqueue(ip(3, 40, false, 0), Duration::ZERO)?;
    assert_eq!(
        b.enqueue(ip(2, 40, true, 0), Duration::ZERO)?
            .binding
            .channel,
        1
    );
    assert!(matches!(
        a.learn(key2, 1, 1, Duration::ZERO),
        Err(PipelineError::Flow(
            l2tunnel_packet::FlowError::BindingConflict { .. }
        ))
    ));
    Ok(())
}

#[test]
fn global_queue_rejection_preserves_flow_ids_channels_timers_and_input() -> TestResult {
    for profile in [Profile::TapSystem, tun()] {
        let mut cfg = config(profile);
        cfg.queue.packets = 1;
        if let Profile::TunDrr(ref mut policy) = cfg.profile {
            policy.per_flow.packets = 1;
        }
        let mut pipeline = Pipeline::new(cfg)?;
        let packet = |port| match profile {
            Profile::TapSystem => ethernet(0x0800, &ip(port, 100, false, 3)),
            _ => ip(port, 100, false, 3),
        };
        let first = pipeline.enqueue(packet(1), Duration::from_secs(1))?;
        let usage = pipeline.usage();
        let mut rejected = Vec::with_capacity(10000);
        rejected.extend_from_slice(&packet(2));
        let capacity = rejected.capacity();
        let error = pipeline
            .enqueue(rejected, Duration::from_secs(100))
            .err()
            .ok_or("full queue rejection")?;
        assert_eq!(error.kind, PipelineError::Budget(Budget::Packets));
        assert_eq!(error.payload.capacity(), capacity);
        assert_eq!(pipeline.usage(), usage);
        assert_eq!(pipeline.registered_flows(), 1);
        assert_eq!(
            pipeline
                .flow(&first.classification.key)
                .ok_or("flow")?
                .last_activity,
            Duration::from_secs(1)
        );
        pipeline.dequeue()?.ok_or("first packet")?;
        let second = pipeline.enqueue(error.payload, Duration::from_secs(2))?;
        assert_eq!(
            second.binding,
            Binding {
                id: FlowId(2),
                channel: 1
            }
        );
    }
    Ok(())
}

#[test]
fn byte_flow_and_policy_failures_are_atomic() -> TestResult {
    let mut cfg = config(tun());
    cfg.flows.capacity = 1;
    cfg.queue.bytes = 3200;
    if let Profile::TunDrr(ref mut policy) = cfg.profile {
        policy.per_flow.bytes = 1600;
        policy.per_flow.packets = 2;
    }
    let mut pipeline = Pipeline::new(cfg)?;
    assert!(matches!(
        pipeline.enqueue(vec![0; 40], Duration::ZERO),
        Err(EnqueueError {
            kind: PipelineError::Parse(_),
            ..
        })
    ));
    assert_eq!(pipeline.registered_flows(), 0);
    assert_eq!(
        pipeline
            .enqueue_weighted(ip(1, 100, false, 0), 0, Duration::ZERO)
            .map_err(|error| error.kind),
        Err(PipelineError::InvalidWeight)
    );
    let first = pipeline.enqueue(ip(1, 1000, false, 7), Duration::ZERO)?;
    assert_eq!(
        pipeline
            .enqueue(ip(1, 700, false, 8), Duration::ZERO)
            .map_err(|error| error.kind),
        Err(PipelineError::Budget(Budget::FlowBytes))
    );
    assert_eq!(
        pipeline
            .enqueue(ip(2, 100, false, 8), Duration::ZERO)
            .map_err(|error| error.kind),
        Err(PipelineError::Flow(l2tunnel_packet::FlowError::Capacity))
    );
    assert_eq!(
        pipeline
            .enqueue_weighted(ip(1, 100, false, 8), 2, Duration::ZERO)
            .map_err(|error| error.kind),
        Err(PipelineError::WeightChanged)
    );
    assert_eq!(
        pipeline.usage(),
        QueueUsage {
            bytes: 1000,
            packets: 1
        }
    );
    assert_eq!(
        pipeline
            .flow(&first.classification.key)
            .ok_or("flow")?
            .queued,
        pipeline.usage()
    );
    assert_eq!(
        pipeline.dequeue()?.ok_or("first retained packet")?.payload,
        ip(1, 1000, false, 7)
    );
    assert_eq!(pipeline.usage(), QueueUsage::default());
    Ok(())
}

#[test]
fn weighted_small_bulk_byte_fairness_and_common_control_admission() -> TestResult {
    let mut pipeline = Pipeline::new(config(tun()))?;
    for _ in 0..200 {
        pipeline.enqueue_weighted(ip(1, 100, false, 1), 1, Duration::ZERO)?;
        pipeline.enqueue_weighted(ip(2, 1500, false, 2), 3, Duration::ZERO)?;
    }
    let mut bytes = [0usize; 2];
    for _ in 0..120 {
        let packet = pipeline.dequeue()?.ok_or("backlogged packet")?;
        let index = usize::from(packet.payload[21] == 2);
        bytes[index] += packet.payload.len();
        let original = ip(
            (index + 1) as u16,
            packet.payload.len(),
            false,
            (index + 1) as u8,
        );
        assert_eq!(packet.payload, original);
    }
    assert!(
        bytes[1].abs_diff(bytes[0] * 3) <= 4500,
        "byte shares {bytes:?}"
    );
    // ACK/SYN payload patterns and probe-shaped data do not bypass count budgets.
    let mut cfg = config(tun());
    cfg.queue.packets = 2;
    if let Profile::TunDrr(ref mut policy) = cfg.profile {
        policy.per_flow.packets = 2;
    }
    let mut pipeline = Pipeline::new(cfg)?;
    let mut syn = ip(1, 40, false, 0);
    syn[33] = 2;
    let ack = ip(1, 40, true, 0);
    pipeline.enqueue(syn.clone(), Duration::ZERO)?;
    pipeline.enqueue(ack.clone(), Duration::ZERO)?;
    assert_eq!(
        pipeline
            .enqueue(ip(9, 40, false, 0), Duration::ZERO)
            .map_err(|error| error.kind),
        Err(PipelineError::Budget(Budget::Packets))
    );
    assert_eq!(pipeline.dequeue()?.ok_or("SYN")?.payload, syn);
    assert_eq!(pipeline.dequeue()?.ok_or("ACK")?.payload, ack);
    Ok(())
}

#[test]
fn blocked_flow_skipping_and_failed_commit_retain_original_payloads() -> TestResult {
    let mut pipeline = Pipeline::new(config(tun()))?;
    let blocked = pipeline.enqueue(ip(1, 1500, false, 1), Duration::ZERO)?;
    let ready = pipeline.enqueue(ip(2, 100, false, 2), Duration::ZERO)?;
    let original = pipeline.usage();
    let mut checks = BTreeMap::new();
    let error = pipeline.dequeue_with(
        |candidate| {
            *checks.entry(candidate.binding.id).or_insert(0) += 1;
            candidate.binding.id == ready.binding.id
        },
        |_| Err::<(), _>("credit changed"),
    );
    assert!(matches!(error, Err(DequeueError::Commit("credit changed"))));
    assert_eq!(checks.values().copied().collect::<Vec<_>>(), vec![1, 1]);
    assert_eq!(pipeline.usage(), original);
    let selected = pipeline
        .dequeue_with(
            |candidate| candidate.binding.id == ready.binding.id,
            |candidate| Ok::<_, Infallible>(candidate.packet_bytes),
        )?
        .ok_or("eligible packet")?;
    assert_eq!(selected.packet.payload, ip(2, 100, false, 2));
    assert_eq!(selected.permit, 100);
    for _ in 0..100 {
        let mut commits = 0;
        assert_eq!(
            pipeline.dequeue_with(
                |_| false,
                |_| {
                    commits += 1;
                    Ok::<_, Infallible>(())
                }
            )?,
            None
        );
        assert_eq!(commits, 0);
    }
    assert_eq!(
        pipeline
            .flow(&blocked.classification.key)
            .ok_or("blocked flow")?
            .queued,
        QueueUsage {
            bytes: 1500,
            packets: 1
        }
    );
    assert_eq!(
        pipeline.dequeue()?.ok_or("unblocked packet")?.payload,
        ip(1, 1500, false, 1)
    );
    assert_eq!(pipeline.usage(), QueueUsage::default());
    Ok(())
}

#[test]
fn retirement_requires_idle_and_local_drain_without_tombstones() -> TestResult {
    let mut cfg = config(tun());
    cfg.flows.capacity = 1;
    let mut pipeline = Pipeline::new(cfg)?;
    let first = pipeline.enqueue(ip(1, 100, false, 1), Duration::ZERO)?;
    let key = first.classification.key;
    assert_eq!(
        pipeline.retire_idle_drained(&key, Duration::from_secs(10)),
        Err(PipelineError::Busy)
    );
    assert_eq!(pipeline.idle_candidate(Duration::from_secs(10))?, None);
    pipeline.dequeue()?.ok_or("packet")?;
    assert_eq!(
        pipeline.retire_idle_drained(&key, Duration::from_secs(4)),
        Err(PipelineError::Flow(l2tunnel_packet::FlowError::NotIdle))
    );
    assert_eq!(
        pipeline.idle_candidate(Duration::from_secs(5))?,
        Some((key, first.binding))
    );
    assert_eq!(
        pipeline.retire_idle_drained(&key, Duration::from_secs(5))?,
        first.binding
    );
    assert_eq!(pipeline.registered_flows(), 0);
    assert_eq!(pipeline.flow(&key), None);
    let mut last = first.binding.id;
    for index in 1..100 {
        let now = Duration::from_secs(index * 5);
        let next = pipeline.enqueue(ip(1, 100, false, 1), now)?;
        assert!(next.binding.id > last);
        pipeline.dequeue()?.ok_or("next packet")?;
        pipeline.retire_idle_drained(&key, now + Duration::from_secs(5))?;
        last = next.binding.id;
        assert_eq!(pipeline.states.len(), 0);
        assert_eq!(pipeline.by_id.len(), 0);
        assert_eq!(
            pipeline
                .qos
                .as_ref()
                .ok_or("TUN scheduler")?
                .registered_flows(),
            0
        );
    }
    Ok(())
}

#[test]
fn real_cumulative_credit_adapter_only_consumes_on_selected_handoff() -> TestResult {
    use l2tunnel_flow_control as credit;
    let scope = credit::Scope {
        session: 1,
        epoch: 0,
        direction: credit::Direction::Forward,
    };
    let capacity = credit::Capacity {
        credit: credit::Credit {
            bytes: 100,
            records: 1,
        },
        max_flows: 1,
    };
    let mut sender = credit::SenderCredits::new(scope, capacity)?;
    let mut receiver = credit::ReceiverCredits::new(scope, capacity)?;
    let mut pipeline = Pipeline::new(config(tun()))?;
    let metadata = pipeline.enqueue(ip(1, 100, false, 7), Duration::ZERO)?;
    let id = credit::FlowId(metadata.binding.id.0);
    sender.open_flow(id)?;
    receiver.open_flow(id)?;
    pipeline.enqueue(ip(1, 100, false, 8), Duration::ZERO)?;
    assert_eq!(sender.admitted(), credit::Credit::default());
    // Eligibility uses the actor's authenticated grant snapshot; only commit
    // calls admit. The pipeline does not pretend to exchange these messages.
    assert_eq!(
        pipeline.dequeue_with(
            |_| false,
            |candidate| sender.admit(id, candidate.packet_bytes as u64)
        )?,
        None
    );
    sender.apply_grant(receiver.grant(
        id,
        credit::Credit {
            bytes: 100,
            records: 1,
        },
    )?)?;
    let first = pipeline
        .dequeue_with(
            |_| true,
            |candidate| sender.admit(id, candidate.packet_bytes as u64),
        )?
        .ok_or("first grant")?;
    assert_eq!(first.packet.payload, ip(1, 100, false, 7));
    assert_eq!(
        sender.admitted(),
        credit::Credit {
            bytes: 100,
            records: 1
        }
    );
    assert!(matches!(
        pipeline.dequeue_with(
            |_| true,
            |candidate| sender.admit(id, candidate.packet_bytes as u64)
        ),
        Err(DequeueError::Commit(_))
    ));
    assert_eq!(
        pipeline.usage(),
        QueueUsage {
            bytes: 100,
            packets: 1
        }
    );
    receiver.receive(first.permit)?;
    sender.apply_release(receiver.release_next(id)?)?;
    sender.apply_grant(receiver.grant(
        id,
        credit::Credit {
            bytes: 200,
            records: 2,
        },
    )?)?;
    let second = pipeline
        .dequeue_with(
            |_| true,
            |candidate| sender.admit(id, candidate.packet_bytes as u64),
        )?
        .ok_or("replenished grant")?;
    assert_eq!(second.packet.payload, ip(1, 100, false, 8));
    assert_eq!(
        sender.admitted(),
        credit::Credit {
            bytes: 200,
            records: 2
        }
    );
    assert_eq!(pipeline.usage(), QueueUsage::default());
    Ok(())
}

#[test]
fn exact_shared_bytes_per_flow_counts_and_regressed_time_preserve_state() -> TestResult {
    let mut cfg = config(tun());
    cfg.queue.bytes = 1600;
    if let Profile::TunDrr(ref mut policy) = cfg.profile {
        policy.per_flow.bytes = 1600;
        policy.per_flow.packets = 1;
    }
    let mut pipeline = Pipeline::new(cfg)?;
    let first = pipeline.enqueue(ip(1, 1000, false, 1), Duration::from_secs(10))?;
    assert_eq!(
        pipeline
            .enqueue(ip(2, 700, false, 2), Duration::from_secs(20))
            .map_err(|error| error.kind),
        Err(PipelineError::Budget(Budget::Bytes))
    );
    assert_eq!(
        pipeline
            .enqueue(ip(1, 100, false, 3), Duration::from_secs(20))
            .map_err(|error| error.kind),
        Err(PipelineError::Budget(Budget::FlowPackets))
    );
    assert_eq!(
        pipeline
            .enqueue(ip(2, 100, false, 4), Duration::from_secs(9))
            .map_err(|error| error.kind),
        Err(PipelineError::Flow(
            l2tunnel_packet::FlowError::TimeRegression
        ))
    );
    let second_key = pipeline.classify(&ip(2, 100, false, 4))?.key;
    assert_eq!(
        pipeline.learn(second_key, 1, 1, Duration::from_secs(9)),
        Err(PipelineError::Flow(
            l2tunnel_packet::FlowError::TimeRegression
        ))
    );
    assert_eq!(
        pipeline.usage(),
        QueueUsage {
            bytes: 1000,
            packets: 1
        }
    );
    assert_eq!(pipeline.registered_flows(), 1);
    assert_eq!(
        pipeline
            .flow(&first.classification.key)
            .ok_or("flow")?
            .last_activity,
        Duration::from_secs(10)
    );
    let second = pipeline.enqueue(ip(2, 600, false, 2), Duration::from_secs(11))?;
    assert_eq!(
        second.binding,
        Binding {
            id: FlowId(2),
            channel: 1
        }
    );
    assert_eq!(
        pipeline.usage(),
        QueueUsage {
            bytes: 1600,
            packets: 2
        }
    );
    pipeline.dequeue()?.ok_or("first packet")?;
    pipeline.dequeue()?.ok_or("second packet")?;
    assert_eq!(pipeline.usage(), QueueUsage::default());
    Ok(())
}

#[test]
fn invalid_configuration_and_minimal_valid_tap_are_explicit() -> TestResult {
    let mut invalid = config(tun());
    invalid.queue.bytes = 1599;
    assert!(matches!(
        Pipeline::new(invalid),
        Err(PipelineError::InvalidConfig)
    ));
    invalid = config(tun());
    invalid.queue.packets = 0;
    assert!(matches!(
        Pipeline::new(invalid),
        Err(PipelineError::InvalidConfig)
    ));
    invalid = config(tun());
    invalid.parse.max_ipv6_extensions = 17;
    assert!(matches!(
        Pipeline::new(invalid),
        Err(PipelineError::Parse(ParseError::InvalidLimits))
    ));
    invalid = config(tun());
    invalid.flows.capacity = 0;
    assert!(matches!(
        Pipeline::new(invalid),
        Err(PipelineError::Flow(
            l2tunnel_packet::FlowError::InvalidConfig
        ))
    ));
    invalid = config(tun());
    if let Profile::TunDrr(ref mut policy) = invalid.profile {
        policy.max_weight = 0;
    }
    assert!(matches!(
        Pipeline::new(invalid),
        Err(PipelineError::InvalidConfig)
    ));
    invalid = config(tun());
    if let Profile::TunDrr(ref mut policy) = invalid.profile {
        policy.per_flow.bytes = 1599;
    }
    assert!(matches!(
        Pipeline::new(invalid),
        Err(PipelineError::QosConfig(_))
    ));
    let mut minimum = config(Profile::TapSystem);
    minimum.parse.max_packet_bytes = 14;
    minimum.queue = QueueLimits {
        bytes: 14,
        packets: 1,
    };
    let mut pipeline = Pipeline::new(minimum)?;
    let opaque = ethernet(0x88b5, b"");
    pipeline.enqueue(opaque.clone(), Duration::ZERO)?;
    assert_eq!(pipeline.dequeue()?.ok_or("minimum frame")?.payload, opaque);
    Ok(())
}

#[test]
fn read_only_heads_preserve_fifo_deficit_and_tap_policy() -> TestResult {
    let mut observed = Pipeline::new(config(tun()))?;
    let mut reference = Pipeline::new(config(tun()))?;
    for (port, length, weight) in [(1200, 1500, 1), (1201, 100, 3), (1200, 80, 1)] {
        observed.enqueue_weighted(ip(port, length, false, 1), weight, Duration::ZERO)?;
        reference.enqueue_weighted(ip(port, length, false, 1), weight, Duration::ZERO)?;
    }
    let before = observed.usage();
    for _ in 0..100 {
        let heads: Vec<_> = observed.tun_flow_heads()?.collect();
        assert_eq!(heads.len(), 2);
        assert!(
            heads
                .iter()
                .any(|head| head.packet_bytes == Some(1500) && head.snapshot.queued.bytes == 1580)
        );
        assert!(heads.iter().any(|head| head.packet_bytes == Some(100)));
        assert_eq!(observed.usage(), before);
    }
    for _ in 0..3 {
        assert_eq!(observed.dequeue()?, reference.dequeue()?);
    }
    assert!(
        observed
            .tun_flow_heads()?
            .all(|head| head.packet_bytes.is_none() && head.snapshot.queued.packets == 0)
    );
    assert!(matches!(
        Pipeline::new(config(Profile::TapSystem))?.tun_flow_heads(),
        Err(PipelineError::TunOnly)
    ));
    Ok(())
}
