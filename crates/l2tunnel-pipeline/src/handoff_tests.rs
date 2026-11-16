use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn config(profile: Profile) -> PipelineConfig {
    PipelineConfig {
        profile,
        flows: FlowTableConfig {
            capacity: 8,
            channels: 3,
            mapping: Mapping::ConnectionRoundRobin,
            idle_timeout: Duration::from_secs(5),
        },
        parse: ParseLimits {
            max_packet_bytes: 512,
            ..ParseLimits::default()
        },
        queue: QueueLimits {
            bytes: 8192,
            packets: 32,
        },
    }
}

fn tun() -> Profile {
    Profile::TunDrr(TunQosConfig {
        base_quantum_bytes: 64,
        max_weight: 4,
        per_flow: QueueLimits {
            bytes: 4096,
            packets: 16,
        },
    })
}

fn packet(profile: Profile, port: u16, length: usize, value: u8) -> Vec<u8> {
    let mut bytes = vec![value; length];
    bytes[..40].fill(0);
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&(length as u16).to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 6;
    bytes[12..16].copy_from_slice(&[10, 0, 0, 1]);
    bytes[16..20].copy_from_slice(&[10, 0, 0, 2]);
    bytes[20..22].copy_from_slice(&port.to_be_bytes());
    bytes[22..24].copy_from_slice(&443_u16.to_be_bytes());
    bytes[32] = 0x50;
    bytes[33] = 0x10;
    if matches!(profile, Profile::TapSystem) {
        let mut ethernet = vec![1; 6];
        ethernet.extend_from_slice(&[2; 6]);
        ethernet.extend_from_slice(&0x0800_u16.to_be_bytes());
        ethernet.extend(bytes);
        ethernet
    } else {
        bytes
    }
}

#[test]
fn tap_and_tun_refusal_preserve_exact_ingress_metadata_bytes_and_retained_allocation() -> TestResult
{
    for profile in [Profile::TapSystem, tun()] {
        let mut offered = Pipeline::new(config(profile))?;
        let mut legacy = Pipeline::new(config(profile))?;
        let mut originals = Vec::new();
        for (port, length, value) in [
            (1001, 100, 7),
            (1002, 80, 8),
            (1003, 40, 9),
            (1001, 120, 10),
        ] {
            let bytes = packet(profile, port, length, value);
            let metadata = offered.enqueue(bytes.clone(), Duration::ZERO)?;
            assert_eq!(legacy.enqueue(bytes.clone(), Duration::ZERO)?, metadata);
            originals.push((bytes, metadata));
        }
        assert_eq!(
            originals
                .iter()
                .map(|(_, metadata)| metadata.binding.channel)
                .collect::<Vec<_>>(),
            [0, 1, 2, 0]
        );
        let usage = offered.usage();
        let mut retained = None;
        for _ in 0..3 {
            assert_eq!(
                offered.offer_front(|metadata, bytes| {
                    assert!(
                        originals
                            .iter()
                            .any(|(original, expected)| bytes == original && metadata == *expected)
                    );
                    let observed = (metadata, bytes.as_ptr());
                    if let Some(expected) = retained {
                        assert_eq!(observed, expected);
                    } else {
                        retained = Some(observed);
                    }
                    Ok::<Option<()>, &str>(None)
                }),
                Ok(None)
            );
            assert_eq!(
                offered.offer_front(|metadata, bytes| {
                    assert_eq!(Some((metadata, bytes.as_ptr())), retained);
                    Err::<Option<()>, _>("no admission")
                }),
                Err(DequeueError::Commit("no admission"))
            );
            assert_eq!(offered.usage(), usage);
            for (_, metadata) in &originals {
                assert_eq!(
                    offered.flow(&metadata.classification.key),
                    legacy.flow(&metadata.classification.key)
                );
            }
        }
        let admitted = offered
            .offer_front(|metadata, bytes| {
                assert_eq!(Some((metadata, bytes.as_ptr())), retained);
                Ok::<_, &str>(Some(metadata.binding.channel))
            })
            .map_err(|_| "offer")?
            .ok_or("packet")?;
        assert_eq!(admitted.permit, admitted.packet.metadata.binding.channel);
        assert_eq!(
            admitted.packet.payload.as_ptr(),
            retained.ok_or("observed allocation")?.1
        );
        assert_eq!(Some(admitted.packet), legacy.dequeue()?);
        while let Some(expected) = legacy.dequeue()? {
            let admitted = offered
                .offer_front(|metadata, bytes| {
                    assert!(
                        originals
                            .iter()
                            .any(|(original, expected)| bytes == original && metadata == *expected)
                    );
                    Ok::<_, &str>(Some(()))
                })
                .map_err(|_| "offer")?
                .ok_or("packet")?;
            assert_eq!(admitted.packet, expected);
            assert_eq!(offered.usage(), legacy.usage());
        }
        assert_eq!(
            offered.offer_front(|_, _| -> Result<Option<()>, &str> { Err("empty callback") }),
            Ok(None)
        );
        assert_eq!(offered.usage(), QueueUsage::default());
        assert_eq!(offered.registered_flows(), 3);
        for (_, metadata) in &originals {
            assert_eq!(
                offered
                    .flow(&metadata.classification.key)
                    .ok_or("flow")?
                    .queued,
                QueueUsage::default()
            );
        }
    }
    Ok(())
}

#[test]
fn tun_eligibility_skips_real_blocked_head_and_retains_selected_bytes_on_full() -> TestResult {
    let profile = tun();
    let mut pipeline = Pipeline::new(config(profile))?;
    let first_bytes = packet(profile, 1001, 100, 1);
    let second_bytes = packet(profile, 1002, 130, 2);
    let first = pipeline.enqueue(first_bytes.clone(), Duration::ZERO)?;
    let second = pipeline.enqueue(second_bytes.clone(), Duration::ZERO)?;
    let usage = pipeline.usage();
    let mut inspected = Vec::new();
    assert_eq!(
        pipeline.offer_with(
            |candidate| {
                inspected.push(candidate.key);
                false
            },
            |_, _| -> Result<Option<()>, &str> { Err("all blocked callback") }
        ),
        Ok(None)
    );
    assert_eq!(inspected.len(), 2);
    assert!(inspected.contains(&first.classification.key));
    assert!(inspected.contains(&second.classification.key));
    assert_eq!(pipeline.usage(), usage);
    let mut pointer = None;
    assert_eq!(
        pipeline.offer_with(
            |candidate| candidate.key != first.classification.key,
            |metadata, bytes| {
                assert_eq!(metadata, second);
                assert_eq!(bytes, second_bytes);
                pointer = Some(bytes.as_ptr());
                Ok::<Option<()>, &str>(None)
            }
        ),
        Ok(None)
    );
    assert_eq!(pipeline.usage(), usage);
    let admitted = pipeline
        .offer_with(
            |candidate| candidate.key != first.classification.key,
            |metadata, bytes| {
                assert_eq!(metadata, second);
                assert_eq!(Some(bytes.as_ptr()), pointer);
                Ok::<_, &str>(Some(29))
            },
        )
        .map_err(|_| "offer")?
        .ok_or("eligible packet")?;
    assert_eq!(admitted.packet.payload, second_bytes);
    assert_eq!(Some(admitted.packet.payload.as_ptr()), pointer);
    assert_eq!(admitted.permit, 29);
    assert_eq!(
        pipeline.usage(),
        QueueUsage {
            bytes: first_bytes.len(),
            packets: 1
        }
    );
    assert_eq!(
        pipeline.offer_with(
            |candidate| candidate.key != first.classification.key,
            |_, _| -> Result<Option<()>, &str> { Err("blocked remainder callback") }
        ),
        Ok(None)
    );
    assert_eq!(
        pipeline.dequeue()?.ok_or("retained first")?.payload,
        first_bytes
    );
    assert_eq!(pipeline.usage(), QueueUsage::default());
    Ok(())
}

#[test]
fn tap_rejects_tun_policy_before_callbacks_without_losing_the_real_head() -> TestResult {
    let mut pipeline = Pipeline::new(config(Profile::TapSystem))?;
    let bytes = packet(Profile::TapSystem, 1001, 40, 1);
    let metadata = pipeline.enqueue(bytes.clone(), Duration::ZERO)?;
    let usage = pipeline.usage();
    let mut eligibility_called = false;
    assert_eq!(
        pipeline.offer_with(
            |_| {
                eligibility_called = true;
                true
            },
            |_, _| -> Result<Option<()>, &str> { Err("TAP policy callback") }
        ),
        Err(DequeueError::Pipeline(PipelineError::TunOnly))
    );
    assert!(!eligibility_called);
    assert_eq!(pipeline.usage(), usage);
    let admitted = pipeline
        .offer_front(|actual, actual_bytes| {
            assert_eq!(actual, metadata);
            assert_eq!(actual_bytes, bytes);
            Ok::<_, &str>(Some(()))
        })
        .map_err(|_| "offer")?
        .ok_or("packet")?;
    assert_eq!(
        admitted.packet,
        Packet {
            payload: bytes,
            metadata
        }
    );
    Ok(())
}

#[test]
fn metadata_accounting_and_busy_transit_fail_before_actual_downstream_admission() -> TestResult {
    for profile in [Profile::TapSystem, tun()] {
        let mut pipeline = Pipeline::new(config(profile))?;
        let bytes = packet(profile, 1001, 100, 7);
        let metadata = pipeline.enqueue(bytes.clone(), Duration::ZERO)?;
        let usage = pipeline.usage();
        for invalid_bytes in [0, usage.bytes + 1] {
            pipeline.usage.bytes = invalid_bytes;
            assert_eq!(
                pipeline
                    .offer_front(|_, _| -> Result<Option<()>, &str> { Err("accounting callback") }),
                Err(DequeueError::Pipeline(PipelineError::Invariant))
            );
        }
        pipeline.usage = usage;
        if matches!(profile, Profile::TapSystem) {
            pipeline.channel_metadata[usize::from(metadata.binding.channel)]
                .front_mut(&mut pipeline.metadata_pool)
                .ok_or("metadata")?
                .classification
                .observed_bytes += 1;
        } else {
            pipeline
                .states
                .get_mut(&metadata.classification.key)
                .ok_or("flow")?
                .metadata
                .front_mut(&mut pipeline.metadata_pool)
                .ok_or("metadata")?
                .classification
                .observed_bytes += 1;
        }
        assert_eq!(
            pipeline.offer_front(|_, _| -> Result<Option<()>, &str> { Err("metadata callback") }),
            Err(DequeueError::Pipeline(PipelineError::Invariant))
        );
        if matches!(profile, Profile::TapSystem) {
            pipeline.channel_metadata[usize::from(metadata.binding.channel)]
                .front_mut(&mut pipeline.metadata_pool)
                .ok_or("metadata")?
                .classification = metadata.classification;
        } else {
            *pipeline
                .states
                .get_mut(&metadata.classification.key)
                .ok_or("flow")?
                .metadata
                .front_mut(&mut pipeline.metadata_pool)
                .ok_or("metadata")? = metadata;
            pipeline
                .mux
                .push(0, vec![99])
                .map_err(|_| "occupied transit")?;
            assert_eq!(
                pipeline.offer_front(|_, _| -> Result<Option<()>, &str> { Err("busy callback") }),
                Err(DequeueError::Pipeline(PipelineError::Invariant))
            );
            assert_eq!(pipeline.mux.pop(), Some((0, vec![99])));
        }
        assert_eq!(pipeline.usage(), usage);
        let admitted = pipeline
            .offer_front(|actual, actual_bytes| {
                assert_eq!(actual, metadata);
                assert_eq!(actual_bytes, bytes);
                Ok::<_, &str>(Some(()))
            })
            .map_err(|_| "offer")?
            .ok_or("original packet")?;
        assert_eq!(
            admitted.packet,
            Packet {
                payload: bytes,
                metadata
            }
        );
        assert_eq!(pipeline.usage(), QueueUsage::default());
    }
    Ok(())
}

#[path = "timing_tests.rs"]
mod timing;
