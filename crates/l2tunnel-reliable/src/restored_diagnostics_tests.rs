use super::*;

fn sources(
    policy: ReliableConfig,
    count: u8,
    bytes: usize,
) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let mut sender = observed(policy, EndpointRole::Initiator)?;
    let mut packets = Vec::new();
    for id in 0..count {
        sender.submit(&vec![id; bytes], time(0))?;
        packets.push(actual_source(&mut sender, 0)?);
    }
    Ok(packets)
}
fn service(owner: &mut Reliable, tick: u64) -> TestResult {
    let mut output = vec![0; owner.max_packet_bytes()];
    assert_eq!(
        owner.poll_data(time(tick), &mut output, &mut budget())?,
        None
    );
    Ok(())
}
fn receive_wait(
    owner: &Reliable,
    tick: u64,
) -> Result<diagnostics::restored::Snapshot, Box<dyn std::error::Error>> {
    Ok(owner
        .output_wait_snapshot(time(tick))
        .ok_or("observer")?
        .restored)
}

#[test]
fn restored_waits_follow_real_slots_when_a_lower_source_replaces_the_sorted_head() -> TestResult {
    let mut policy = config();
    policy.repair_symbols = 0;
    let packets = sources(policy, 4, 8)?;
    policy.arq.send_records = 2;
    policy.arq.receive_records = 2;
    policy.fec.block.max_sources = 2;
    let mut receiver = observed(policy, EndpointRole::Responder)?;
    let usage = receiver.storage_usage();
    receiver.receive(&packets[3], time(1))?;
    receiver.receive(&packets[2], time(2))?;
    let wait = receive_wait(&receiver, 2)?;
    assert_eq!(wait.open.episodes, 2);
    assert_eq!(wait.maximum_open.ok_or("source 3")?.operation.source, 3);
    assert_eq!(wait.maximum_open.ok_or("source 3")?.since, time(1));
    receiver.receive(&packets[0], time(3))?;
    let mut delivery = [0; 64];
    assert_eq!(receiver.poll_delivered(&mut delivery)?, Some((0, 8)));
    service(&mut receiver, 5)?;
    let wait = receive_wait(&receiver, 5)?;
    assert_eq!(wait.sources.completed_episodes, 1);
    assert_eq!(
        wait.last_completed
            .ok_or("source 2")?
            .pending
            .operation
            .source,
        2
    );
    assert_eq!(wait.sources.completed, time(3));
    assert_eq!(wait.open.episodes, 1);
    assert_eq!(wait.maximum_open.ok_or("source 3 remains")?.since, time(1));
    receiver.receive(&packets[1], time(6))?;
    assert_eq!(receiver.poll_delivered(&mut delivery)?, Some((1, 8)));
    assert_eq!(receiver.poll_delivered(&mut delivery)?, Some((2, 8)));
    let retained = receiver.storage();
    let deadline = receiver.deadline();
    let raw = receiver
        .output_wait_snapshot(time(7))
        .ok_or("fresh snapshot")?;
    let terminal = raw.censor(time(7));
    assert_eq!(terminal.restored.sources.censored_episodes, 1);
    assert_eq!(terminal.restored.sources.censored, time(6));
    assert_eq!(
        terminal
            .restored
            .maximum_censored
            .ok_or("censored source")?
            .pending
            .operation
            .source,
        3
    );
    assert_eq!(terminal, terminal.censor(time(9)));
    assert_eq!(receiver.storage(), retained);
    assert_eq!(receiver.deadline(), deadline);
    assert!(
        raw.censor(time(8)).restored.terminal_unavailable,
        "cached time cannot extend source waits"
    );
    service(&mut receiver, 8)?;
    let wait = receive_wait(&receiver, 8)?;
    assert_eq!(wait.sources.completed_episodes, 2);
    assert_eq!(wait.sources.completed, time(10)); // 3 + 7 source-ms; not an owner union.
    assert_eq!(
        wait.maximum_completed
            .ok_or("maximum")?
            .pending
            .operation
            .source,
        3
    );
    assert_eq!(
        wait.maximum_completed.ok_or("maximum")?.pending.since,
        time(1)
    );
    assert_eq!(wait.open.episodes, 0);
    assert_eq!(wait.omitted_refusals, 0);
    assert!(!wait.identity_mismatch && !wait.clock_regression && !wait.overflow);
    assert_eq!(receiver.storage_usage(), usage);
    assert_eq!(receiver.poll_delivered(&mut delivery)?, Some((3, 8)));
    Ok(())
}

#[test]
fn restored_capacity_wait_is_actual_admission_not_passive_occupancy_or_feedback_hold() -> TestResult
{
    let mut policy = config();
    policy.repair_symbols = 0;
    policy.arq.receive_bytes = 64;
    let packets = sources(policy, 2, 40)?;
    let mut receiver = observed(policy, EndpointRole::Responder)?;
    let mut plain = physical::owner(policy, EndpointRole::Responder, true)?;
    plain.enable_physical_send_confirmation()?;
    plain.enable_compact_wire_with_overheads(37, 49)?;
    for owner in [&mut receiver, &mut plain] {
        owner.receive(&packets[0], time(1))?;
    }
    assert_eq!(receive_wait(&receiver, 1)?.open.episodes, 0);
    for owner in [&mut receiver, &mut plain] {
        owner.receive(&packets[1], time(2))?;
        service(owner, 3)?;
    }
    let wait = receive_wait(&receiver, 3)?;
    assert_eq!(wait.refusals, [2, 0]);
    assert_eq!(wait.open.episodes, 1);
    assert_eq!(
        wait.maximum_open.ok_or("capacity source")?.operation.source,
        1
    );
    assert_eq!(receiver.storage(), plain.storage());
    assert_eq!(receiver.deadline(), plain.deadline());
    assert_eq!(receiver.arq_statistics(), plain.arq_statistics());
    let mut bytes = [0; 64];
    for owner in [&mut receiver, &mut plain] {
        assert_eq!(owner.poll_delivered(&mut bytes)?, Some((0, 40)));
        service(owner, 4)?;
    }
    assert_eq!(receive_wait(&receiver, 4)?.sources.completed, time(2));
    assert_eq!(receive_wait(&receiver, 4)?.reasons[0].completed, time(2));
    assert_eq!(receiver.storage(), plain.storage());
    assert!(plain.output_wait_snapshot(time(4)).is_none());
    let before = receive_wait(&receiver, 4)?;
    assert_eq!(
        receiver.receive(&packets[0], time(3)),
        Err(Error::NonMonotonicTime)
    );
    assert_eq!(receive_wait(&receiver, 4)?, before);
    assert!(receiver.receive(&[1], time(5)).is_err());
    assert_eq!(receive_wait(&receiver, 5)?.sources, before.sources);
    Ok(())
}

#[test]
fn restored_fec_recovery_preserves_exact_source_provenance_across_terminal_censor() -> TestResult {
    let mut sender = observed(config(), EndpointRole::Initiator)?;
    let mut generations = Vec::new();
    for _ in 0..2 {
        for source in [b"zero".as_slice(), b"one", b"two"] {
            sender.submit(source, time(0))?;
        }
        let mut packets = Vec::new();
        for _ in 0..5 {
            packets.push(actual_source(&mut sender, 0)?);
        }
        generations.push(packets);
    }
    let mut policy = config();
    policy.arq.send_records = 3;
    policy.arq.receive_records = 3;
    let mut receiver = observed(policy, EndpointRole::Responder)?;
    // Keep the original receive frontier at zero. Lose systematic sources 3/4;
    // systematic 5 and both second-generation repairs restore sources 3/4.
    let packets = &generations[1];
    receiver.receive(&packets[2], time(1))?;
    receiver.receive(&packets[3], time(2))?;
    receiver.receive(&packets[4], time(3))?;
    let wait = receive_wait(&receiver, 4)?;
    // Source 4 is retained behind refused source 3 but has not been attempted.
    assert_eq!(wait.open.episodes, 2);
    let direct = wait.maximum_open.ok_or("direct source 5")?;
    assert_eq!(direct.operation.source, 5);
    assert!(!direct.operation.recovered);
    // Deliver source zero to open exactly one place in the original window.
    receiver.receive(&generations[0][0], time(4))?;
    let mut bytes = [0; 64];
    assert_eq!(receiver.poll_delivered(&mut bytes)?, Some((0, 4)));
    service(&mut receiver, 5)?;
    let wait = receive_wait(&receiver, 5)?;
    let recovered = wait.last_completed.ok_or("recovered source 3 admitted")?;
    assert_eq!(recovered.pending.operation.source, 3);
    assert!(recovered.pending.operation.recovered);
    assert_eq!(recovered.pending.since, time(3));
    assert_eq!(wait.sources.completed_episodes, 1);
    assert_eq!(wait.open.episodes, 2);
    let terminal = receiver
        .output_wait_snapshot(time(5))
        .ok_or("fresh snapshot")?
        .censor(time(5));
    assert_eq!(terminal.restored.sources.censored_episodes, 2);
    assert_eq!(terminal.restored.last_completed, Some(recovered));
    let longest = terminal
        .restored
        .maximum_censored
        .ok_or("direct source still retained")?;
    assert_eq!(longest.pending.operation.source, 5);
    assert!(!longest.pending.operation.recovered);
    assert_eq!(receiver.poll_delivered(&mut bytes)?, None);
    Ok(())
}
