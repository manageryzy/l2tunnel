//! Generated behavioral events from actual maintained Python Compact methods.
//! Python's52-byte modeled feedback cost is not this selected v2 byte codec.
use super::*;

#[derive(Clone, Copy)]
enum Operation {
    Source,
    SourceReceipt,
    FeedbackReceipt,
    Timeout,
    FeedbackTimer,
}
#[derive(Clone, Copy)]
enum Output {
    Source {
        source: u64,
        serial: u64,
        accepted: u64,
    },
    Feedback {
        prefix: u64,
        start: u64,
        count: u16,
        bitmap: u64,
        echo: u64,
        delay_us: u64,
        serial: u64,
    },
}
struct Trace {
    name: &'static str,
    mode: u8,
    feedback_ns: u64,
    events: &'static [Event],
}
struct Event {
    at: u64,
    op: Operation,
    argument: usize,
    outputs: &'static [Output],
    expected: Expected,
}
struct Flight {
    source: u64,
    serial: u64,
    attempts: u32,
    accepted_ns: u64,
    retry_ns: u64,
}
struct Expected {
    base: u64,
    sampled: u64,
    rto_ns: u64,
    prefix: u64,
    feedback_cursor: u64,
    feedback_serial: u64,
    received_feedback_serial: u64,
    feedback_events: usize,
    feedback_repeats: u8,
    data_outputs: usize,
    feedback_outputs: usize,
    srtt: Option<f64>,
    rttvar: f64,
    feedback_due: Option<u64>,
    flights: &'static [Flight],
    history: &'static [(u64, u64)],
}
#[path = "python_events.rs"]
mod python_events;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
fn at(nanos: u64) -> Duration {
    Duration::from_nanos(nanos)
}
fn context(role: EndpointRole) -> RecoveryContext {
    RecoveryContext {
        session: 0x71,
        epoch: 7,
        role,
    }
}
fn policy(trace: &Trace) -> Result<CompactArqConfig, RecoveryError> {
    CompactArqConfig::new(
        CompactBounds {
            max_source_bytes: 4,
            send_bytes: 64,
            receive_bytes: 64,
            send_records: 16,
            receive_records: 16,
        },
        CompactTiming {
            nominal_rtt: Duration::from_millis(70),
            feedback_interval: at(trace.feedback_ns),
            feedback_packets: 64,
        },
        COMPACT_FEEDBACK_HEADER_BYTES + 1,
        64,
        8,
        match trace.mode {
            1 => CompactRecovery::Guarded,
            2 => CompactRecovery::FirstFlight,
            3 => CompactRecovery::BoundedGap {
                min_interval: Duration::from_millis(5),
            },
            _ => return Err(RecoveryError::InvalidConfig),
        },
    )
}
fn exact_time(actual: Duration, expected: u64, label: &str) {
    // Python's binary64 event time is exported once to nearest nanoseconds.
    // At most one nanosecond can separate sum-then-quantize from Duration sums.
    assert!(
        actual.as_nanos().abs_diff(u128::from(expected)) <= 1,
        "{label}: actual {actual:?}, expected {expected}ns"
    );
}
fn expected_state(
    sender: &CompactRepeat,
    receiver: &CompactRepeat,
    expected: &Expected,
    data: usize,
    feedback: usize,
    label: &str,
) -> TestResult {
    let send = sender
        .engine
        .compact
        .as_ref()
        .ok_or("selected sender state")?;
    let receive = receiver
        .engine
        .compact
        .as_ref()
        .ok_or("selected receiver state")?;
    assert_eq!(send.base, expected.base, "{label}: cumulative sending base");
    assert_eq!(
        send.sampled, expected.sampled,
        "{label}: sampled actual transmission"
    );
    match (send.srtt, expected.srtt) {
        (Some(actual), Some(wanted)) => assert!((actual - wanted).abs() < 1e-15, "{label}: SRTT"),
        (None, None) => {}
        value => return Err(format!("{label}: inconsistent sample {value:?}").into()),
    }
    assert!(
        (send.rttvar - expected.rttvar).abs() < 1e-15,
        "{label}: deviation"
    );
    exact_time(sender.timing()?.rto, expected.rto_ns, label);
    assert_eq!(
        send.received_feedback_serial, expected.received_feedback_serial,
        "{label}: feedback freshness"
    );
    let mut flights = sender.engine.sent.iter().collect::<Vec<_>>();
    flights.sort_by_key(|(source, _)| **source);
    assert_eq!(
        flights.len(),
        expected.flights.len(),
        "{label}: actual retained flights"
    );
    for ((source, flight), wanted) in flights.into_iter().zip(expected.flights) {
        assert_eq!(source.0, wanted.source, "{label}: source identity");
        assert_eq!(flight.attempts, wanted.attempts, "{label}: actual attempts");
        let meta = send.meta(*source);
        assert_eq!(meta.serial, wanted.serial, "{label}: actual latest serial");
        exact_time(
            meta.accepted.ok_or("actual accepted source")?,
            wanted.accepted_ns,
            label,
        );
        exact_time(
            flight.retry_at.ok_or("original RTO")?,
            wanted.retry_ns,
            label,
        );
    }
    let mut history = send
        .history
        .iter()
        .flatten()
        .map(|entry| (entry.serial, entry.accepted))
        .collect::<Vec<_>>();
    history.sort_by_key(|entry| entry.0);
    assert_eq!(
        history.len(),
        expected.history.len(),
        "{label}: actual unsampled history"
    );
    for ((serial, accepted), &(wanted_serial, wanted_at)) in
        history.into_iter().zip(expected.history)
    {
        assert_eq!(serial, wanted_serial, "{label}: unsampled serial");
        exact_time(
            accepted.ok_or("physical history receipt")?,
            wanted_at,
            label,
        );
    }
    assert_eq!(
        receiver.engine.receive_prefix, expected.prefix,
        "{label}: receive prefix"
    );
    assert_eq!(
        receive.bitmap_cursor, expected.feedback_cursor,
        "{label}: rotating bitmap"
    );
    assert_eq!(
        receive.feedback_serial, expected.feedback_serial,
        "{label}: feedback identity"
    );
    assert_eq!(
        receive.feedback_events, expected.feedback_events,
        "{label}: receipt events"
    );
    assert_eq!(
        receive.feedback_repeats, expected.feedback_repeats,
        "{label}: ordinary repeats"
    );
    match (receiver.feedback_deadline(), expected.feedback_due) {
        (Some(actual), Some(wanted)) => exact_time(actual, wanted, label),
        (None, None) => {}
        value => return Err(format!("{label}: feedback deadline {value:?}").into()),
    }
    assert_eq!(
        (data, feedback),
        (expected.data_outputs, expected.feedback_outputs),
        "{label}: real outputs"
    );
    assert_eq!(
        sender.statistics().transmissions,
        data as u64,
        "{label}: actual physical preparations"
    );
    assert_eq!(
        receiver.statistics().feedback_sent,
        feedback as u64,
        "{label}: actual feedback outputs"
    );
    Ok(())
}

#[test]
fn actual_python_event_traces_match_selected_rust_behavior_and_physical_timing() -> TestResult {
    for trace in python_events::TRACES {
        let policy = policy(trace)?;
        let mut sender = CompactRepeat::new(policy, context(EndpointRole::Initiator))?;
        let mut receiver = CompactRepeat::new(policy, context(EndpointRole::Responder))?;
        let send_usage = sender.storage_usage();
        let receive_usage = receiver.storage_usage();
        let mut data: Vec<Vec<u8>> = Vec::new();
        let mut feedback: Vec<Vec<u8>> = Vec::new();
        for (number, event) in trace.events.iter().enumerate() {
            let label = format!("{} event{number} at{}ns", trace.name, event.at);
            let now = at(event.at);
            match event.op {
                Operation::Source => {
                    let source = sender.next_source_id()?;
                    // Python models this source's length, not its payload bytes.
                    // Rust carries actual opaque bytes and verifies their identity.
                    assert_eq!(sender.submit(&[source.0 as u8; 4], now)?, source.0);
                }
                Operation::SourceReceipt => receiver.receive_at(&data[event.argument], now, now)?,
                Operation::FeedbackReceipt => {
                    sender.receive_at(&feedback[event.argument], now, now)?
                }
                Operation::Timeout | Operation::FeedbackTimer => {}
            }
            for output in event.outputs {
                match *output {
                    Output::Source {
                        source,
                        serial,
                        accepted,
                    } => {
                        let mut bytes = vec![0; sender.send_max_packet_bytes()];
                        let size = sender
                            .poll_source(now, &mut bytes)?
                            .ok_or("actual Python source/retry absent")?;
                        bytes.truncate(size);
                        let parsed = inspect_compact_packet(
                            &bytes,
                            context(EndpointRole::Responder),
                            policy,
                        )?;
                        assert_eq!(
                            parsed,
                            CompactPacketView::Data {
                                source: SourceId(source),
                                serial,
                                payload: &[source as u8; 4]
                            },
                            "{label}: selected v2 payload/serial"
                        );
                        // No feedback receipt or local enqueue is used as a
                        // physical confirmation. Use the oracle's actual finish.
                        let token = sender
                            .pending_transmission(SourceId(source))
                            .ok_or("actual physical token")?;
                        sender.confirm_transmission_at(at(accepted), at(accepted), token)?;
                        data.push(bytes);
                    }
                    Output::Feedback {
                        prefix,
                        start,
                        count,
                        bitmap,
                        echo,
                        delay_us,
                        serial,
                    } => {
                        let mut bytes = vec![0; receiver.send_max_packet_bytes()];
                        let size = receiver
                            .poll_feedback(now, &mut bytes)?
                            .ok_or("actual Python feedback absent")?;
                        bytes.truncate(size);
                        let CompactPacketView::Feedback(parsed) = inspect_compact_packet(
                            &bytes,
                            context(EndpointRole::Initiator),
                            policy,
                        )?
                        else {
                            return Err("selected feedback kind".into());
                        };
                        assert_eq!(
                            (
                                parsed.prefix,
                                parsed.start,
                                parsed.count,
                                parsed.echo,
                                parsed.receiver_delay_us,
                                parsed.serial
                            ),
                            (prefix, start, count, echo, delay_us, serial),
                            "{label}: actual feedback fields"
                        );
                        assert_eq!(
                            parsed.bitmap,
                            &bitmap.to_le_bytes()[..usize::from(count).div_ceil(8)],
                            "{label}: actual bitmap"
                        );
                        feedback.push(bytes);
                    }
                }
            }
            if matches!(event.op, Operation::FeedbackReceipt)
                && !event
                    .outputs
                    .iter()
                    .any(|output| matches!(output, Output::Source { .. }))
            {
                assert_eq!(
                    sender.poll_source(now, &mut [0; 128])?,
                    None,
                    "{label}: no premature or repeated fast retransmission"
                );
            }
            if matches!(event.op, Operation::FeedbackTimer) && event.outputs.is_empty() {
                assert_eq!(
                    receiver.poll_feedback(now, &mut [0; 128])?,
                    None,
                    "{label}: cancelled old timer must not emit"
                );
            }
            expected_state(
                &sender,
                &receiver,
                &event.expected,
                data.len(),
                feedback.len(),
                &label,
            )?;
            assert_eq!(
                sender.storage_usage(),
                send_usage,
                "{label}: same reserved source/history owners"
            );
            assert_eq!(
                receiver.storage_usage(),
                receive_usage,
                "{label}: same reserved receive owners"
            );
        }
    }
    Ok(())
}
