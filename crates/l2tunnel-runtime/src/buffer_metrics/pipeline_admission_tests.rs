use super::*;
use std::time::Duration;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn identity(epoch: u64) -> Identity {
    Identity {
        epoch,
        configuration: [epoch as u8; 32],
    }
}
fn packet(port: u16) -> Vec<u8> {
    let mut bytes = vec![0; 100];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&100_u16.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 6;
    bytes[12..20].copy_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
    bytes[20..22].copy_from_slice(&port.to_be_bytes());
    bytes[22..24].copy_from_slice(&443_u16.to_be_bytes());
    bytes[32] = 0x50;
    bytes[33] = 0x10;
    bytes
}
fn owner() -> Result<pipeline::Pipeline, Box<dyn std::error::Error>> {
    let config = pipeline::PipelineConfig {
        profile: pipeline::Profile::TunDrr(pipeline::TunQosConfig {
            base_quantum_bytes: 1500,
            max_weight: 4,
            per_flow: pipeline::QueueLimits {
                bytes: 4096,
                packets: 8,
            },
        }),
        flows: pipeline::FlowTableConfig {
            capacity: 4,
            channels: 2,
            mapping: pipeline::Mapping::ConnectionRoundRobin,
            idle_timeout: Duration::from_secs(1),
        },
        parse: pipeline::ParseLimits {
            max_packet_bytes: 1500,
            ..Default::default()
        },
        queue: pipeline::QueueLimits {
            bytes: 8192,
            packets: 16,
        },
    };
    let plan = pipeline::storage::Plan::for_pipeline(config)?;
    Ok(pipeline::Pipeline::new_reserved(
        config,
        pipeline::storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?)
}
fn refuse(
    owner: &mut pipeline::Pipeline,
    observed: &mut PipelineAdmission,
    scope: Identity,
    binding: pipeline::Binding,
    now: u64,
    reason: AdmissionBlock,
) -> TestResult {
    let usage = owner.usage();
    let result = owner.offer_with_borrowed(
        |candidate| candidate.binding == binding,
        |metadata, bytes| {
            observed.refused(
                scope,
                now,
                AdmissionRefusal {
                    flow: metadata.binding.id,
                    channel: metadata.binding.channel,
                    timing: metadata.timing,
                    bytes: bytes.len(),
                    reason,
                },
            );
            Ok::<Option<()>, std::io::Error>(None)
        },
    )?;
    assert!(result.is_none());
    assert_eq!(owner.usage(), usage, "refusal cannot pop or debit the head");
    Ok(())
}
fn admit(
    owner: &mut pipeline::Pipeline,
    observed: &mut PipelineAdmission,
    scope: Identity,
    binding: pipeline::Binding,
    now: u64,
) -> Result<pipeline::PacketMetadata, Box<dyn std::error::Error>> {
    let actual = owner
        .offer_with_borrowed(
            |candidate| candidate.binding == binding,
            |_, _| Ok::<_, std::io::Error>(Some(())),
        )?
        .ok_or("actual FIFO admission")?;
    observed.admitted(scope, now, actual.metadata);
    Ok(actual.metadata)
}

#[test]
fn actual_reserved_pipeline_identical_heads_and_other_flows_do_not_merge_waits() -> TestResult {
    let mut owner = owner()?;
    let capacity = owner.storage_usage();
    let mut observed = PipelineAdmission::new(4)?;
    let heap = observed.heap_bytes();
    let a = owner.enqueue_borrowed(&packet(2001), Duration::ZERO)?;
    let duplicate = owner.enqueue_borrowed(&packet(2001), Duration::ZERO)?;
    assert_eq!(
        a, duplicate,
        "timestamps are deliberately not unique packet IDs"
    );
    let b = owner.enqueue_borrowed(&packet(2002), Duration::ZERO)?;
    assert_ne!(a.binding.id, b.binding.id);
    assert_ne!(a.binding.channel, b.binding.channel);
    let scope = identity(1);
    refuse(
        &mut owner,
        &mut observed,
        scope,
        a.binding,
        10,
        AdmissionBlock::CodecStage,
    )?;
    refuse(
        &mut owner,
        &mut observed,
        scope,
        a.binding,
        20,
        AdmissionBlock::CodecStage,
    )?;
    assert_eq!(
        owner.retire_drained(&a.classification.key),
        Err(pipeline::PipelineError::Busy)
    );
    admit(&mut owner, &mut observed, scope, b.binding, 25)?;
    assert_eq!(
        observed.rows.len(),
        1,
        "unblocked success creates no wait row"
    );
    assert!(
        observed.rows[0].pending.is_some(),
        "another flow cannot clear A"
    );
    let selected = owner.offer_with_borrowed(
        |_| false,
        |_, _| -> io::Result<Option<()>> { Err(io::Error::other("ineligible head was offered")) },
    )?;
    assert!(
        selected.is_none(),
        "DRR eligibility hold is not a refusal callback"
    );
    assert_eq!(observed.rows[0].union.episodes, 1);
    assert_eq!(admit(&mut owner, &mut observed, scope, a.binding, 50)?, a);
    refuse(
        &mut owner,
        &mut observed,
        scope,
        a.binding,
        60,
        AdmissionBlock::CodecStage,
    )?;
    admit(&mut owner, &mut observed, scope, a.binding, 70)?;
    assert_eq!(observed.rows[0].union.completed_episodes, 2);
    assert_eq!(observed.rows[0].union.completed_us, 50);
    assert_eq!(observed.rows[0].union.maximum_us, 40);
    owner.retire_drained(&a.classification.key)?;
    let reused_tuple = owner.enqueue_borrowed(&packet(2001), Duration::from_micros(80))?;
    assert_ne!(reused_tuple.binding.id, a.binding.id);
    refuse(
        &mut owner,
        &mut observed,
        scope,
        reused_tuple.binding,
        90,
        AdmissionBlock::CodecStage,
    )?;
    observed.finish(100, true);
    let current = observed
        .rows
        .iter()
        .find(|row| row.key.flow == reused_tuple.binding.id.0)
        .ok_or("fresh flow row")?;
    assert_eq!(current.union.censored_us, 10);
    assert_eq!(observed.identity_errors, 0);
    assert_eq!(
        observed.heap_bytes(),
        heap,
        "events cannot allocate diagnostic storage"
    );
    assert_eq!(
        owner.storage_usage(),
        capacity,
        "protocol allocation inventory is unchanged"
    );
    Ok(())
}

#[test]
fn pipeline_wait_scope_retirement_and_terminal_do_not_extend_stale_observations() -> TestResult {
    let mut first = owner()?;
    let mut second = owner()?;
    let a = first.enqueue_borrowed(&packet(2101), Duration::ZERO)?;
    let b = second.enqueue_borrowed(&packet(2101), Duration::ZERO)?;
    assert_eq!(
        a, b,
        "new epoch deliberately repeats all local packet metadata"
    );
    let mut observed = PipelineAdmission::new(4)?;
    refuse(
        &mut first,
        &mut observed,
        identity(1),
        a.binding,
        10,
        AdmissionBlock::NativeDeliveryWindow,
    )?;
    refuse(
        &mut first,
        &mut observed,
        identity(1),
        a.binding,
        20,
        AdmissionBlock::CodecStage,
    )?;
    refuse(
        &mut second,
        &mut observed,
        identity(2),
        b.binding,
        30,
        AdmissionBlock::CodecStage,
    )?;
    admit(&mut second, &mut observed, identity(2), b.binding, 40)?;
    assert!(
        observed.rows[0].pending.is_some(),
        "other epoch cannot complete old head"
    );
    observed.reconcile(50, [Some(identity(2)), None]);
    assert_eq!(observed.rows[0].union.censored_us, 40);
    assert_eq!(observed.rows[0].causes[0].completed_us, 10);
    assert_eq!(observed.rows[0].causes[2].censored_us, 30);
    observed.finish(5000, false);
    assert_eq!(observed.terminal, Some(50));
    assert_eq!(observed.unavailable_terminal, 1);
    let mut bytes = Vec::new();
    observed.write(&mut bytes)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(value["flows"][0]["retired_at_us"], 50);
    assert_eq!(value["flows"][1]["blocked_heads"]["completed_us"], 10);
    assert_eq!(value["terminal_at_us"], 50);
    Ok(())
}

#[test]
fn pipeline_wait_diagnostic_saturation_and_regressed_clock_never_change_actual_owner() -> TestResult
{
    let mut owner = owner()?;
    let mut observed = PipelineAdmission::new(1)?;
    assert_eq!(
        observed.limit, 2,
        "reserve from the supplied live flow bound"
    );
    let mut entries = Vec::new();
    for port in [2201, 2202, 2203] {
        entries.push(owner.enqueue_borrowed(&packet(port), Duration::ZERO)?);
    }
    for (index, metadata) in entries.iter().enumerate() {
        refuse(
            &mut owner,
            &mut observed,
            identity(1),
            metadata.binding,
            10 + index as u64,
            AdmissionBlock::CodecStage,
        )?;
    }
    assert_eq!(observed.rows.len(), 2);
    assert_eq!(observed.omitted_refusals, 1);
    refuse(
        &mut owner,
        &mut observed,
        identity(1),
        entries[0].binding,
        9,
        AdmissionBlock::CodecStage,
    )?;
    assert_eq!(observed.clock_regressions, 1);
    for metadata in &entries {
        admit(&mut owner, &mut observed, identity(1), metadata.binding, 20)?;
    }
    assert_eq!(owner.usage().packets, 0);
    assert!(observed.rows.iter().all(|row| row.pending.is_none()));
    observed.finish(30, true);
    assert_eq!(observed.rows[0].union.completed_us, 10);
    assert_eq!(observed.rows[1].union.completed_us, 9);
    Ok(())
}

#[test]
fn actual_pipeline_wait_uses_existing_observer_export_and_charges_optional_heap() -> TestResult {
    let path = std::env::temp_dir().join(format!(
        "l2tunnel-pipeline-wait-{}.bmetrics",
        std::process::id()
    ));
    let mut observer = super::super::Observer::for_test(tokio::time::Instant::now(), path.clone())?;
    let before = observer.heap_bytes();
    observer.configure_pipeline_admission(4)?;
    assert!(observer.heap_bytes() > before);
    let after = observer.heap_bytes();
    let mut owner = owner()?;
    let metadata = owner.enqueue_borrowed(&packet(2301), Duration::ZERO)?;
    refuse(
        &mut owner,
        observer.pipeline_admission().ok_or("configured provider")?,
        identity(1),
        metadata.binding,
        10,
        AdmissionBlock::CodecStage,
    )?;
    observer.source_terminal_attempt(super::super::SourceBoundary::LoopStop, Some(30));
    observer
        .pipeline_admission()
        .ok_or("provider before terminal")?
        .finish(30, true);
    observer.finish_at(30);
    assert_eq!(observer.heap_bytes(), after);
    drop(observer);
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    std::fs::remove_file(path)?;
    assert_eq!(value["source_terminal_sample"]["boundary"], "loop_stop");
    assert_eq!(value["pipeline_admission"]["terminal_at_us"], 30);
    assert_eq!(
        value["pipeline_admission"]["flows"][0]["blocked_heads"]["censored_us"],
        20
    );
    assert_eq!(value["pipeline_admission"]["unavailable_terminal"], 0);
    assert_eq!(value["diagnostic_heap_bytes"], after);
    Ok(())
}
