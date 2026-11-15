// Generated from actual Python methods by generate.py; do not hand edit.
use super::{Event, Expected, Flight, Operation, Output, Trace};
#[rustfmt::skip]
pub(super) const TRACES: &[Trace] = &[
    Trace { name: "rtt_stale_feedback_newer_echo_and_retransmission", mode: 1, feedback_ns: 5000000, events: &[
        Event { at: 0, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 0, serial: 1, accepted: 1000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 1, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
        ], history: &[(1, 1000000)] } },
        Event { at: 2000000, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 1, serial: 2, accepted: 3000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 2, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
        ], history: &[(1, 1000000), (2, 3000000)] } },
        Event { at: 40000000, op: Operation::SourceReceipt, argument: 1, outputs: &[
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 1, feedback_repeats: 2, data_outputs: 2, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: Some(45000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
        ], history: &[(1, 1000000), (2, 3000000)] } },
        Event { at: 45000000, op: Operation::FeedbackTimer, argument: 0, outputs: &[
            Output::Feedback { prefix: 0, start: 0, count: 2, bitmap: 2, echo: 2, delay_us: 5000, serial: 1 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 1, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 1, data_outputs: 2, feedback_outputs: 1, srtt: None, rttvar: 0.0, feedback_due: Some(50000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
        ], history: &[(1, 1000000), (2, 3000000)] } },
        Event { at: 50000000, op: Operation::SourceReceipt, argument: 0, outputs: &[
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 2, feedback_cursor: 0, feedback_serial: 1, received_feedback_serial: 0, feedback_events: 1, feedback_repeats: 2, data_outputs: 2, feedback_outputs: 1, srtt: None, rttvar: 0.0, feedback_due: Some(50000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
        ], history: &[(1, 1000000), (2, 3000000)] } },
        Event { at: 50000000, op: Operation::FeedbackTimer, argument: 0, outputs: &[
            Output::Feedback { prefix: 2, start: 2, count: 0, bitmap: 0, echo: 1, delay_us: 0, serial: 2 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 2, feedback_cursor: 2, feedback_serial: 2, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 1, data_outputs: 2, feedback_outputs: 2, srtt: None, rttvar: 0.0, feedback_due: Some(55000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
        ], history: &[(1, 1000000), (2, 3000000)] } },
        Event { at: 55000000, op: Operation::FeedbackTimer, argument: 0, outputs: &[
            Output::Feedback { prefix: 2, start: 2, count: 0, bitmap: 0, echo: 1, delay_us: 5000, serial: 3 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 2, feedback_cursor: 2, feedback_serial: 3, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 2, feedback_outputs: 3, srtt: None, rttvar: 0.0, feedback_due: Some(60000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
        ], history: &[(1, 1000000), (2, 3000000)] } },
        Event { at: 60000000, op: Operation::FeedbackTimer, argument: 0, outputs: &[
            Output::Feedback { prefix: 2, start: 2, count: 0, bitmap: 0, echo: 1, delay_us: 10000, serial: 4 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 2, feedback_cursor: 2, feedback_serial: 4, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 2, feedback_outputs: 4, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
        ], history: &[(1, 1000000), (2, 3000000)] } },
        Event { at: 80000000, op: Operation::FeedbackReceipt, argument: 1, outputs: &[
        ], expected: Expected { base: 2, sampled: 1, rto_ns: 247000000, prefix: 2, feedback_cursor: 2, feedback_serial: 4, received_feedback_serial: 2, feedback_events: 0, feedback_repeats: 0, data_outputs: 2, feedback_outputs: 4, srtt: Some(0.079), rttvar: 0.0395, feedback_due: None, flights: &[
        ], history: &[(2, 3000000)] } },
        Event { at: 90000000, op: Operation::FeedbackReceipt, argument: 0, outputs: &[
        ], expected: Expected { base: 2, sampled: 2, rto_ns: 210875000, prefix: 2, feedback_cursor: 2, feedback_serial: 4, received_feedback_serial: 2, feedback_events: 0, feedback_repeats: 0, data_outputs: 2, feedback_outputs: 4, srtt: Some(0.079375), rttvar: 0.030374999999999996, feedback_due: None, flights: &[
        ], history: &[] } },
        Event { at: 100000000, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 2, serial: 3, accepted: 101000000 },
        ], expected: Expected { base: 2, sampled: 2, rto_ns: 210875000, prefix: 2, feedback_cursor: 2, feedback_serial: 4, received_feedback_serial: 2, feedback_events: 0, feedback_repeats: 0, data_outputs: 3, feedback_outputs: 4, srtt: Some(0.079375), rttvar: 0.030374999999999996, feedback_due: None, flights: &[
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 101000000, retry_ns: 311875000 },
        ], history: &[(3, 101000000)] } },
        Event { at: 311875000, op: Operation::Timeout, argument: 2, outputs: &[
            Output::Source { source: 2, serial: 4, accepted: 312875000 },
        ], expected: Expected { base: 2, sampled: 2, rto_ns: 210875000, prefix: 2, feedback_cursor: 2, feedback_serial: 4, received_feedback_serial: 2, feedback_events: 0, feedback_repeats: 0, data_outputs: 4, feedback_outputs: 4, srtt: Some(0.079375), rttvar: 0.030374999999999996, feedback_due: None, flights: &[
            Flight { source: 2, serial: 4, attempts: 2, accepted_ns: 312875000, retry_ns: 523750000 },
        ], history: &[(3, 101000000), (4, 312875000)] } },
        Event { at: 346875000, op: Operation::SourceReceipt, argument: 3, outputs: &[
        ], expected: Expected { base: 2, sampled: 2, rto_ns: 210875000, prefix: 3, feedback_cursor: 2, feedback_serial: 4, received_feedback_serial: 2, feedback_events: 1, feedback_repeats: 2, data_outputs: 4, feedback_outputs: 4, srtt: Some(0.079375), rttvar: 0.030374999999999996, feedback_due: Some(351875000), flights: &[
            Flight { source: 2, serial: 4, attempts: 2, accepted_ns: 312875000, retry_ns: 523750000 },
        ], history: &[(3, 101000000), (4, 312875000)] } },
        Event { at: 351875000, op: Operation::FeedbackTimer, argument: 0, outputs: &[
            Output::Feedback { prefix: 3, start: 3, count: 0, bitmap: 0, echo: 4, delay_us: 5000, serial: 5 },
        ], expected: Expected { base: 2, sampled: 2, rto_ns: 210875000, prefix: 3, feedback_cursor: 3, feedback_serial: 5, received_feedback_serial: 2, feedback_events: 0, feedback_repeats: 1, data_outputs: 4, feedback_outputs: 5, srtt: Some(0.079375), rttvar: 0.030374999999999996, feedback_due: Some(356875000), flights: &[
            Flight { source: 2, serial: 4, attempts: 2, accepted_ns: 312875000, retry_ns: 523750000 },
        ], history: &[(3, 101000000), (4, 312875000)] } },
        Event { at: 386875000, op: Operation::FeedbackReceipt, argument: 4, outputs: &[
        ], expected: Expected { base: 3, sampled: 4, rto_ns: 189578125, prefix: 3, feedback_cursor: 3, feedback_serial: 5, received_feedback_serial: 5, feedback_events: 0, feedback_repeats: 1, data_outputs: 4, feedback_outputs: 5, srtt: Some(0.078078125), rttvar: 0.025374999999999995, feedback_due: Some(356875000), flights: &[
        ], history: &[] } },
    ] },
    Trace { name: "guarded", mode: 1, feedback_ns: 5000000, events: &[
        Event { at: 0, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 0, serial: 1, accepted: 1000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 1, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
        ], history: &[(1, 1000000)] } },
        Event { at: 2000000, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 1, serial: 2, accepted: 3000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 2, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
        ], history: &[(1, 1000000), (2, 3000000)] } },
        Event { at: 4000000, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 2, serial: 3, accepted: 5000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 3, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 155000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000)] } },
        Event { at: 6000000, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 3, serial: 4, accepted: 7000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 4, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 155000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 157000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000)] } },
        Event { at: 30000000, op: Operation::SourceReceipt, argument: 1, outputs: &[
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 1, feedback_repeats: 2, data_outputs: 4, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: Some(35000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 155000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 157000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000)] } },
        Event { at: 30000000, op: Operation::SourceReceipt, argument: 2, outputs: &[
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 2, feedback_repeats: 2, data_outputs: 4, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: Some(35000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 155000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 157000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000)] } },
        Event { at: 30000000, op: Operation::SourceReceipt, argument: 3, outputs: &[
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 3, feedback_repeats: 2, data_outputs: 4, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: Some(35000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 155000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 157000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000)] } },
        Event { at: 35000000, op: Operation::FeedbackTimer, argument: 0, outputs: &[
            Output::Feedback { prefix: 0, start: 0, count: 4, bitmap: 14, echo: 4, delay_us: 5000, serial: 1 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 1, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 1, data_outputs: 4, feedback_outputs: 1, srtt: None, rttvar: 0.0, feedback_due: Some(40000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 155000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 157000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000)] } },
        Event { at: 40000000, op: Operation::FeedbackReceipt, argument: 0, outputs: &[
        ], expected: Expected { base: 0, sampled: 4, rto_ns: 94000000, prefix: 0, feedback_cursor: 0, feedback_serial: 1, received_feedback_serial: 1, feedback_events: 0, feedback_repeats: 1, data_outputs: 4, feedback_outputs: 1, srtt: Some(0.028), rttvar: 0.014, feedback_due: Some(40000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
        ], history: &[] } },
        Event { at: 40000000, op: Operation::FeedbackTimer, argument: 0, outputs: &[
            Output::Feedback { prefix: 0, start: 0, count: 4, bitmap: 14, echo: 4, delay_us: 10000, serial: 2 },
        ], expected: Expected { base: 0, sampled: 4, rto_ns: 94000000, prefix: 0, feedback_cursor: 0, feedback_serial: 2, received_feedback_serial: 1, feedback_events: 0, feedback_repeats: 0, data_outputs: 4, feedback_outputs: 2, srtt: Some(0.028), rttvar: 0.014, feedback_due: Some(45000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
        ], history: &[] } },
        Event { at: 42000000, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 4, serial: 5, accepted: 43000000 },
        ], expected: Expected { base: 0, sampled: 4, rto_ns: 94000000, prefix: 0, feedback_cursor: 0, feedback_serial: 2, received_feedback_serial: 1, feedback_events: 0, feedback_repeats: 0, data_outputs: 5, feedback_outputs: 2, srtt: Some(0.028), rttvar: 0.014, feedback_due: Some(45000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 43000000, retry_ns: 137000000 },
        ], history: &[(5, 43000000)] } },
        Event { at: 45000000, op: Operation::FeedbackTimer, argument: 0, outputs: &[
            Output::Feedback { prefix: 0, start: 0, count: 4, bitmap: 14, echo: 4, delay_us: 15000, serial: 3 },
        ], expected: Expected { base: 0, sampled: 4, rto_ns: 94000000, prefix: 0, feedback_cursor: 0, feedback_serial: 3, received_feedback_serial: 1, feedback_events: 0, feedback_repeats: 0, data_outputs: 5, feedback_outputs: 3, srtt: Some(0.028), rttvar: 0.014, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 43000000, retry_ns: 137000000 },
        ], history: &[(5, 43000000)] } },
        Event { at: 65000000, op: Operation::SourceReceipt, argument: 4, outputs: &[
        ], expected: Expected { base: 0, sampled: 4, rto_ns: 94000000, prefix: 0, feedback_cursor: 0, feedback_serial: 3, received_feedback_serial: 1, feedback_events: 1, feedback_repeats: 2, data_outputs: 5, feedback_outputs: 3, srtt: Some(0.028), rttvar: 0.014, feedback_due: Some(70000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 43000000, retry_ns: 137000000 },
        ], history: &[(5, 43000000)] } },
        Event { at: 70000000, op: Operation::FeedbackTimer, argument: 0, outputs: &[
            Output::Feedback { prefix: 0, start: 0, count: 5, bitmap: 30, echo: 5, delay_us: 5000, serial: 4 },
        ], expected: Expected { base: 0, sampled: 4, rto_ns: 94000000, prefix: 0, feedback_cursor: 0, feedback_serial: 4, received_feedback_serial: 1, feedback_events: 0, feedback_repeats: 1, data_outputs: 5, feedback_outputs: 4, srtt: Some(0.028), rttvar: 0.014, feedback_due: Some(75000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 43000000, retry_ns: 137000000 },
        ], history: &[(5, 43000000)] } },
        Event { at: 75000000, op: Operation::FeedbackReceipt, argument: 3, outputs: &[
        ], expected: Expected { base: 0, sampled: 5, rto_ns: 80875000, prefix: 0, feedback_cursor: 0, feedback_serial: 4, received_feedback_serial: 4, feedback_events: 0, feedback_repeats: 1, data_outputs: 5, feedback_outputs: 4, srtt: Some(0.027875), rttvar: 0.010750000000000001, feedback_due: Some(75000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
        ], history: &[] } },
        Event { at: 75000000, op: Operation::FeedbackTimer, argument: 0, outputs: &[
            Output::Feedback { prefix: 0, start: 0, count: 5, bitmap: 30, echo: 5, delay_us: 10000, serial: 5 },
        ], expected: Expected { base: 0, sampled: 5, rto_ns: 80875000, prefix: 0, feedback_cursor: 0, feedback_serial: 5, received_feedback_serial: 4, feedback_events: 0, feedback_repeats: 0, data_outputs: 5, feedback_outputs: 5, srtt: Some(0.027875), rttvar: 0.010750000000000001, feedback_due: Some(80000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
        ], history: &[] } },
        Event { at: 80000000, op: Operation::FeedbackTimer, argument: 0, outputs: &[
            Output::Feedback { prefix: 0, start: 0, count: 5, bitmap: 30, echo: 5, delay_us: 15000, serial: 6 },
        ], expected: Expected { base: 0, sampled: 5, rto_ns: 80875000, prefix: 0, feedback_cursor: 0, feedback_serial: 6, received_feedback_serial: 4, feedback_events: 0, feedback_repeats: 0, data_outputs: 5, feedback_outputs: 6, srtt: Some(0.027875), rttvar: 0.010750000000000001, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
        ], history: &[] } },
        Event { at: 90000000, op: Operation::FeedbackReceipt, argument: 4, outputs: &[
            Output::Source { source: 0, serial: 6, accepted: 91000000 },
        ], expected: Expected { base: 0, sampled: 5, rto_ns: 80875000, prefix: 0, feedback_cursor: 0, feedback_serial: 6, received_feedback_serial: 5, feedback_events: 0, feedback_repeats: 0, data_outputs: 6, feedback_outputs: 6, srtt: Some(0.027875), rttvar: 0.010750000000000001, feedback_due: None, flights: &[
            Flight { source: 0, serial: 6, attempts: 2, accepted_ns: 91000000, retry_ns: 171875000 },
        ], history: &[(6, 91000000)] } },
        Event { at: 122000000, op: Operation::FeedbackReceipt, argument: 5, outputs: &[
        ], expected: Expected { base: 0, sampled: 5, rto_ns: 80875000, prefix: 0, feedback_cursor: 0, feedback_serial: 6, received_feedback_serial: 6, feedback_events: 0, feedback_repeats: 0, data_outputs: 6, feedback_outputs: 6, srtt: Some(0.027875), rttvar: 0.010750000000000001, feedback_due: None, flights: &[
            Flight { source: 0, serial: 6, attempts: 2, accepted_ns: 91000000, retry_ns: 171875000 },
        ], history: &[(6, 91000000)] } },
    ] },
    Trace { name: "first_flight_then_original_guard", mode: 2, feedback_ns: 5000000, events: &[
        Event { at: 0, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 0, serial: 1, accepted: 1000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 1, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
        ], history: &[(1, 1000000)] } },
        Event { at: 2000000, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 1, serial: 2, accepted: 3000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 2, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
        ], history: &[(1, 1000000), (2, 3000000)] } },
        Event { at: 4000000, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 2, serial: 3, accepted: 5000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 3, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 155000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000)] } },
        Event { at: 6000000, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 3, serial: 4, accepted: 7000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 4, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 155000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 157000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000)] } },
        Event { at: 30000000, op: Operation::SourceReceipt, argument: 1, outputs: &[
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 1, feedback_repeats: 2, data_outputs: 4, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: Some(35000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 155000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 157000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000)] } },
        Event { at: 30000000, op: Operation::SourceReceipt, argument: 2, outputs: &[
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 2, feedback_repeats: 2, data_outputs: 4, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: Some(35000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 155000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 157000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000)] } },
        Event { at: 30000000, op: Operation::SourceReceipt, argument: 3, outputs: &[
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 3, feedback_repeats: 2, data_outputs: 4, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: Some(35000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 155000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 157000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000)] } },
        Event { at: 35000000, op: Operation::FeedbackTimer, argument: 0, outputs: &[
            Output::Feedback { prefix: 0, start: 0, count: 4, bitmap: 14, echo: 4, delay_us: 5000, serial: 1 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 1, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 1, data_outputs: 4, feedback_outputs: 1, srtt: None, rttvar: 0.0, feedback_due: Some(40000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 155000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 157000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000)] } },
        Event { at: 40000000, op: Operation::FeedbackReceipt, argument: 0, outputs: &[
            Output::Source { source: 0, serial: 5, accepted: 41000000 },
        ], expected: Expected { base: 0, sampled: 4, rto_ns: 94000000, prefix: 0, feedback_cursor: 0, feedback_serial: 1, received_feedback_serial: 1, feedback_events: 0, feedback_repeats: 1, data_outputs: 5, feedback_outputs: 1, srtt: Some(0.028), rttvar: 0.014, feedback_due: Some(40000000), flights: &[
            Flight { source: 0, serial: 5, attempts: 2, accepted_ns: 41000000, retry_ns: 135000000 },
        ], history: &[(5, 41000000)] } },
        Event { at: 40000000, op: Operation::FeedbackTimer, argument: 0, outputs: &[
            Output::Feedback { prefix: 0, start: 0, count: 4, bitmap: 14, echo: 4, delay_us: 10000, serial: 2 },
        ], expected: Expected { base: 0, sampled: 4, rto_ns: 94000000, prefix: 0, feedback_cursor: 0, feedback_serial: 2, received_feedback_serial: 1, feedback_events: 0, feedback_repeats: 0, data_outputs: 5, feedback_outputs: 2, srtt: Some(0.028), rttvar: 0.014, feedback_due: Some(45000000), flights: &[
            Flight { source: 0, serial: 5, attempts: 2, accepted_ns: 41000000, retry_ns: 135000000 },
        ], history: &[(5, 41000000)] } },
        Event { at: 42000000, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 4, serial: 6, accepted: 43000000 },
        ], expected: Expected { base: 0, sampled: 4, rto_ns: 94000000, prefix: 0, feedback_cursor: 0, feedback_serial: 2, received_feedback_serial: 1, feedback_events: 0, feedback_repeats: 0, data_outputs: 6, feedback_outputs: 2, srtt: Some(0.028), rttvar: 0.014, feedback_due: Some(45000000), flights: &[
            Flight { source: 0, serial: 5, attempts: 2, accepted_ns: 41000000, retry_ns: 135000000 },
            Flight { source: 4, serial: 6, attempts: 1, accepted_ns: 43000000, retry_ns: 137000000 },
        ], history: &[(5, 41000000), (6, 43000000)] } },
        Event { at: 45000000, op: Operation::FeedbackTimer, argument: 0, outputs: &[
            Output::Feedback { prefix: 0, start: 0, count: 4, bitmap: 14, echo: 4, delay_us: 15000, serial: 3 },
        ], expected: Expected { base: 0, sampled: 4, rto_ns: 94000000, prefix: 0, feedback_cursor: 0, feedback_serial: 3, received_feedback_serial: 1, feedback_events: 0, feedback_repeats: 0, data_outputs: 6, feedback_outputs: 3, srtt: Some(0.028), rttvar: 0.014, feedback_due: None, flights: &[
            Flight { source: 0, serial: 5, attempts: 2, accepted_ns: 41000000, retry_ns: 135000000 },
            Flight { source: 4, serial: 6, attempts: 1, accepted_ns: 43000000, retry_ns: 137000000 },
        ], history: &[(5, 41000000), (6, 43000000)] } },
        Event { at: 65000000, op: Operation::SourceReceipt, argument: 5, outputs: &[
        ], expected: Expected { base: 0, sampled: 4, rto_ns: 94000000, prefix: 0, feedback_cursor: 0, feedback_serial: 3, received_feedback_serial: 1, feedback_events: 1, feedback_repeats: 2, data_outputs: 6, feedback_outputs: 3, srtt: Some(0.028), rttvar: 0.014, feedback_due: Some(70000000), flights: &[
            Flight { source: 0, serial: 5, attempts: 2, accepted_ns: 41000000, retry_ns: 135000000 },
            Flight { source: 4, serial: 6, attempts: 1, accepted_ns: 43000000, retry_ns: 137000000 },
        ], history: &[(5, 41000000), (6, 43000000)] } },
        Event { at: 70000000, op: Operation::FeedbackTimer, argument: 0, outputs: &[
            Output::Feedback { prefix: 0, start: 0, count: 5, bitmap: 30, echo: 6, delay_us: 5000, serial: 4 },
        ], expected: Expected { base: 0, sampled: 4, rto_ns: 94000000, prefix: 0, feedback_cursor: 0, feedback_serial: 4, received_feedback_serial: 1, feedback_events: 0, feedback_repeats: 1, data_outputs: 6, feedback_outputs: 4, srtt: Some(0.028), rttvar: 0.014, feedback_due: Some(75000000), flights: &[
            Flight { source: 0, serial: 5, attempts: 2, accepted_ns: 41000000, retry_ns: 135000000 },
            Flight { source: 4, serial: 6, attempts: 1, accepted_ns: 43000000, retry_ns: 137000000 },
        ], history: &[(5, 41000000), (6, 43000000)] } },
        Event { at: 75000000, op: Operation::FeedbackReceipt, argument: 3, outputs: &[
        ], expected: Expected { base: 0, sampled: 6, rto_ns: 80875000, prefix: 0, feedback_cursor: 0, feedback_serial: 4, received_feedback_serial: 4, feedback_events: 0, feedback_repeats: 1, data_outputs: 6, feedback_outputs: 4, srtt: Some(0.027875), rttvar: 0.010750000000000001, feedback_due: Some(75000000), flights: &[
            Flight { source: 0, serial: 5, attempts: 2, accepted_ns: 41000000, retry_ns: 135000000 },
        ], history: &[] } },
        Event { at: 75000000, op: Operation::FeedbackTimer, argument: 0, outputs: &[
            Output::Feedback { prefix: 0, start: 0, count: 5, bitmap: 30, echo: 6, delay_us: 10000, serial: 5 },
        ], expected: Expected { base: 0, sampled: 6, rto_ns: 80875000, prefix: 0, feedback_cursor: 0, feedback_serial: 5, received_feedback_serial: 4, feedback_events: 0, feedback_repeats: 0, data_outputs: 6, feedback_outputs: 5, srtt: Some(0.027875), rttvar: 0.010750000000000001, feedback_due: Some(80000000), flights: &[
            Flight { source: 0, serial: 5, attempts: 2, accepted_ns: 41000000, retry_ns: 135000000 },
        ], history: &[] } },
        Event { at: 80000000, op: Operation::FeedbackTimer, argument: 0, outputs: &[
            Output::Feedback { prefix: 0, start: 0, count: 5, bitmap: 30, echo: 6, delay_us: 15000, serial: 6 },
        ], expected: Expected { base: 0, sampled: 6, rto_ns: 80875000, prefix: 0, feedback_cursor: 0, feedback_serial: 6, received_feedback_serial: 4, feedback_events: 0, feedback_repeats: 0, data_outputs: 6, feedback_outputs: 6, srtt: Some(0.027875), rttvar: 0.010750000000000001, feedback_due: None, flights: &[
            Flight { source: 0, serial: 5, attempts: 2, accepted_ns: 41000000, retry_ns: 135000000 },
        ], history: &[] } },
        Event { at: 90000000, op: Operation::FeedbackReceipt, argument: 4, outputs: &[
        ], expected: Expected { base: 0, sampled: 6, rto_ns: 80875000, prefix: 0, feedback_cursor: 0, feedback_serial: 6, received_feedback_serial: 5, feedback_events: 0, feedback_repeats: 0, data_outputs: 6, feedback_outputs: 6, srtt: Some(0.027875), rttvar: 0.010750000000000001, feedback_due: None, flights: &[
            Flight { source: 0, serial: 5, attempts: 2, accepted_ns: 41000000, retry_ns: 135000000 },
        ], history: &[] } },
        Event { at: 122000000, op: Operation::FeedbackReceipt, argument: 5, outputs: &[
            Output::Source { source: 0, serial: 7, accepted: 123000000 },
        ], expected: Expected { base: 0, sampled: 6, rto_ns: 80875000, prefix: 0, feedback_cursor: 0, feedback_serial: 6, received_feedback_serial: 6, feedback_events: 0, feedback_repeats: 0, data_outputs: 7, feedback_outputs: 6, srtt: Some(0.027875), rttvar: 0.010750000000000001, feedback_due: None, flights: &[
            Flight { source: 0, serial: 7, attempts: 3, accepted_ns: 123000000, retry_ns: 203875000 },
        ], history: &[(7, 123000000)] } },
    ] },
    Trace { name: "duplicate_three_reports_rotating_bitmap", mode: 1, feedback_ns: 5000000, events: &[
        Event { at: 0, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 0, serial: 1, accepted: 1000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 1, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
        ], history: &[(1, 1000000)] } },
        Event { at: 2000000, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 1, serial: 2, accepted: 3000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 2, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
        ], history: &[(1, 1000000), (2, 3000000)] } },
        Event { at: 4000000, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 2, serial: 3, accepted: 5000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 3, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 155000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000)] } },
        Event { at: 6000000, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 3, serial: 4, accepted: 7000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 4, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 155000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 157000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000)] } },
        Event { at: 8000000, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 4, serial: 5, accepted: 9000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 5, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 155000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 157000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 159000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000)] } },
        Event { at: 10000000, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 5, serial: 6, accepted: 11000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 6, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 155000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 157000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 159000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 161000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000)] } },
        Event { at: 12000000, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 6, serial: 7, accepted: 13000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 7, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 155000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 157000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 159000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 161000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 163000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000)] } },
        Event { at: 14000000, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 7, serial: 8, accepted: 15000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 8, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 155000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 157000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 159000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 161000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 163000000 },
            Flight { source: 7, serial: 8, attempts: 1, accepted_ns: 15000000, retry_ns: 165000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000), (8, 15000000)] } },
        Event { at: 16000000, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 8, serial: 9, accepted: 17000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 9, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 155000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 157000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 159000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 161000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 163000000 },
            Flight { source: 7, serial: 8, attempts: 1, accepted_ns: 15000000, retry_ns: 165000000 },
            Flight { source: 8, serial: 9, attempts: 1, accepted_ns: 17000000, retry_ns: 167000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000), (8, 15000000), (9, 17000000)] } },
        Event { at: 18000000, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 9, serial: 10, accepted: 19000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 10, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 155000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 157000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 159000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 161000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 163000000 },
            Flight { source: 7, serial: 8, attempts: 1, accepted_ns: 15000000, retry_ns: 165000000 },
            Flight { source: 8, serial: 9, attempts: 1, accepted_ns: 17000000, retry_ns: 167000000 },
            Flight { source: 9, serial: 10, attempts: 1, accepted_ns: 19000000, retry_ns: 169000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000), (8, 15000000), (9, 17000000), (10, 19000000)] } },
        Event { at: 20000000, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 10, serial: 11, accepted: 21000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 11, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 155000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 157000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 159000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 161000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 163000000 },
            Flight { source: 7, serial: 8, attempts: 1, accepted_ns: 15000000, retry_ns: 165000000 },
            Flight { source: 8, serial: 9, attempts: 1, accepted_ns: 17000000, retry_ns: 167000000 },
            Flight { source: 9, serial: 10, attempts: 1, accepted_ns: 19000000, retry_ns: 169000000 },
            Flight { source: 10, serial: 11, attempts: 1, accepted_ns: 21000000, retry_ns: 171000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000), (8, 15000000), (9, 17000000), (10, 19000000), (11, 21000000)] } },
        Event { at: 22000000, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 11, serial: 12, accepted: 23000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 12, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 155000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 157000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 159000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 161000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 163000000 },
            Flight { source: 7, serial: 8, attempts: 1, accepted_ns: 15000000, retry_ns: 165000000 },
            Flight { source: 8, serial: 9, attempts: 1, accepted_ns: 17000000, retry_ns: 167000000 },
            Flight { source: 9, serial: 10, attempts: 1, accepted_ns: 19000000, retry_ns: 169000000 },
            Flight { source: 10, serial: 11, attempts: 1, accepted_ns: 21000000, retry_ns: 171000000 },
            Flight { source: 11, serial: 12, attempts: 1, accepted_ns: 23000000, retry_ns: 173000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000), (8, 15000000), (9, 17000000), (10, 19000000), (11, 21000000), (12, 23000000)] } },
        Event { at: 40000000, op: Operation::SourceReceipt, argument: 9, outputs: &[
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 1, feedback_repeats: 2, data_outputs: 12, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: Some(45000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 155000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 157000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 159000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 161000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 163000000 },
            Flight { source: 7, serial: 8, attempts: 1, accepted_ns: 15000000, retry_ns: 165000000 },
            Flight { source: 8, serial: 9, attempts: 1, accepted_ns: 17000000, retry_ns: 167000000 },
            Flight { source: 9, serial: 10, attempts: 1, accepted_ns: 19000000, retry_ns: 169000000 },
            Flight { source: 10, serial: 11, attempts: 1, accepted_ns: 21000000, retry_ns: 171000000 },
            Flight { source: 11, serial: 12, attempts: 1, accepted_ns: 23000000, retry_ns: 173000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000), (8, 15000000), (9, 17000000), (10, 19000000), (11, 21000000), (12, 23000000)] } },
        Event { at: 45000000, op: Operation::FeedbackTimer, argument: 0, outputs: &[
            Output::Feedback { prefix: 0, start: 0, count: 8, bitmap: 0, echo: 10, delay_us: 5000, serial: 1 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 8, feedback_serial: 1, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 1, data_outputs: 12, feedback_outputs: 1, srtt: None, rttvar: 0.0, feedback_due: Some(50000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 155000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 157000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 159000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 161000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 163000000 },
            Flight { source: 7, serial: 8, attempts: 1, accepted_ns: 15000000, retry_ns: 165000000 },
            Flight { source: 8, serial: 9, attempts: 1, accepted_ns: 17000000, retry_ns: 167000000 },
            Flight { source: 9, serial: 10, attempts: 1, accepted_ns: 19000000, retry_ns: 169000000 },
            Flight { source: 10, serial: 11, attempts: 1, accepted_ns: 21000000, retry_ns: 171000000 },
            Flight { source: 11, serial: 12, attempts: 1, accepted_ns: 23000000, retry_ns: 173000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000), (8, 15000000), (9, 17000000), (10, 19000000), (11, 21000000), (12, 23000000)] } },
        Event { at: 50000000, op: Operation::FeedbackTimer, argument: 0, outputs: &[
            Output::Feedback { prefix: 0, start: 8, count: 2, bitmap: 2, echo: 10, delay_us: 10000, serial: 2 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 2, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 12, feedback_outputs: 2, srtt: None, rttvar: 0.0, feedback_due: Some(55000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 155000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 157000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 159000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 161000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 163000000 },
            Flight { source: 7, serial: 8, attempts: 1, accepted_ns: 15000000, retry_ns: 165000000 },
            Flight { source: 8, serial: 9, attempts: 1, accepted_ns: 17000000, retry_ns: 167000000 },
            Flight { source: 9, serial: 10, attempts: 1, accepted_ns: 19000000, retry_ns: 169000000 },
            Flight { source: 10, serial: 11, attempts: 1, accepted_ns: 21000000, retry_ns: 171000000 },
            Flight { source: 11, serial: 12, attempts: 1, accepted_ns: 23000000, retry_ns: 173000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000), (8, 15000000), (9, 17000000), (10, 19000000), (11, 21000000), (12, 23000000)] } },
        Event { at: 55000000, op: Operation::FeedbackTimer, argument: 0, outputs: &[
            Output::Feedback { prefix: 0, start: 0, count: 8, bitmap: 0, echo: 10, delay_us: 15000, serial: 3 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 8, feedback_serial: 3, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 12, feedback_outputs: 3, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 155000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 157000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 159000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 161000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 163000000 },
            Flight { source: 7, serial: 8, attempts: 1, accepted_ns: 15000000, retry_ns: 165000000 },
            Flight { source: 8, serial: 9, attempts: 1, accepted_ns: 17000000, retry_ns: 167000000 },
            Flight { source: 9, serial: 10, attempts: 1, accepted_ns: 19000000, retry_ns: 169000000 },
            Flight { source: 10, serial: 11, attempts: 1, accepted_ns: 21000000, retry_ns: 171000000 },
            Flight { source: 11, serial: 12, attempts: 1, accepted_ns: 23000000, retry_ns: 173000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000), (8, 15000000), (9, 17000000), (10, 19000000), (11, 21000000), (12, 23000000)] } },
        Event { at: 60000000, op: Operation::SourceReceipt, argument: 9, outputs: &[
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 8, feedback_serial: 3, received_feedback_serial: 0, feedback_events: 1, feedback_repeats: 2, data_outputs: 12, feedback_outputs: 3, srtt: None, rttvar: 0.0, feedback_due: Some(65000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 155000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 157000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 159000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 161000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 163000000 },
            Flight { source: 7, serial: 8, attempts: 1, accepted_ns: 15000000, retry_ns: 165000000 },
            Flight { source: 8, serial: 9, attempts: 1, accepted_ns: 17000000, retry_ns: 167000000 },
            Flight { source: 9, serial: 10, attempts: 1, accepted_ns: 19000000, retry_ns: 169000000 },
            Flight { source: 10, serial: 11, attempts: 1, accepted_ns: 21000000, retry_ns: 171000000 },
            Flight { source: 11, serial: 12, attempts: 1, accepted_ns: 23000000, retry_ns: 173000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000), (8, 15000000), (9, 17000000), (10, 19000000), (11, 21000000), (12, 23000000)] } },
        Event { at: 65000000, op: Operation::FeedbackTimer, argument: 0, outputs: &[
            Output::Feedback { prefix: 0, start: 8, count: 2, bitmap: 2, echo: 10, delay_us: 5000, serial: 4 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 4, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 1, data_outputs: 12, feedback_outputs: 4, srtt: None, rttvar: 0.0, feedback_due: Some(70000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 155000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 157000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 159000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 161000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 163000000 },
            Flight { source: 7, serial: 8, attempts: 1, accepted_ns: 15000000, retry_ns: 165000000 },
            Flight { source: 8, serial: 9, attempts: 1, accepted_ns: 17000000, retry_ns: 167000000 },
            Flight { source: 9, serial: 10, attempts: 1, accepted_ns: 19000000, retry_ns: 169000000 },
            Flight { source: 10, serial: 11, attempts: 1, accepted_ns: 21000000, retry_ns: 171000000 },
            Flight { source: 11, serial: 12, attempts: 1, accepted_ns: 23000000, retry_ns: 173000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000), (8, 15000000), (9, 17000000), (10, 19000000), (11, 21000000), (12, 23000000)] } },
        Event { at: 70000000, op: Operation::FeedbackTimer, argument: 0, outputs: &[
            Output::Feedback { prefix: 0, start: 0, count: 8, bitmap: 0, echo: 10, delay_us: 10000, serial: 5 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 8, feedback_serial: 5, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 12, feedback_outputs: 5, srtt: None, rttvar: 0.0, feedback_due: Some(75000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 155000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 157000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 159000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 161000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 163000000 },
            Flight { source: 7, serial: 8, attempts: 1, accepted_ns: 15000000, retry_ns: 165000000 },
            Flight { source: 8, serial: 9, attempts: 1, accepted_ns: 17000000, retry_ns: 167000000 },
            Flight { source: 9, serial: 10, attempts: 1, accepted_ns: 19000000, retry_ns: 169000000 },
            Flight { source: 10, serial: 11, attempts: 1, accepted_ns: 21000000, retry_ns: 171000000 },
            Flight { source: 11, serial: 12, attempts: 1, accepted_ns: 23000000, retry_ns: 173000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000), (8, 15000000), (9, 17000000), (10, 19000000), (11, 21000000), (12, 23000000)] } },
        Event { at: 75000000, op: Operation::FeedbackTimer, argument: 0, outputs: &[
            Output::Feedback { prefix: 0, start: 8, count: 2, bitmap: 2, echo: 10, delay_us: 15000, serial: 6 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 150000000, prefix: 0, feedback_cursor: 0, feedback_serial: 6, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 12, feedback_outputs: 6, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 151000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 153000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 155000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 157000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 159000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 161000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 163000000 },
            Flight { source: 7, serial: 8, attempts: 1, accepted_ns: 15000000, retry_ns: 165000000 },
            Flight { source: 8, serial: 9, attempts: 1, accepted_ns: 17000000, retry_ns: 167000000 },
            Flight { source: 9, serial: 10, attempts: 1, accepted_ns: 19000000, retry_ns: 169000000 },
            Flight { source: 10, serial: 11, attempts: 1, accepted_ns: 21000000, retry_ns: 171000000 },
            Flight { source: 11, serial: 12, attempts: 1, accepted_ns: 23000000, retry_ns: 173000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000), (8, 15000000), (9, 17000000), (10, 19000000), (11, 21000000), (12, 23000000)] } },
    ] },
    Trace { name: "bounded_gap_uses_any_last_feedback_and_cancels_old_timer", mode: 3, feedback_ns: 10000000, events: &[
        Event { at: 0, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 0, serial: 1, accepted: 1000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 160000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 1, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 161000000 },
        ], history: &[(1, 1000000)] } },
        Event { at: 2000000, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 1, serial: 2, accepted: 3000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 160000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 2, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 161000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 163000000 },
        ], history: &[(1, 1000000), (2, 3000000)] } },
        Event { at: 4000000, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 2, serial: 3, accepted: 5000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 160000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 3, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 161000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 163000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 165000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000)] } },
        Event { at: 6000000, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 3, serial: 4, accepted: 7000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 160000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 4, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 161000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 163000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 165000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 167000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000)] } },
        Event { at: 8000000, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 4, serial: 5, accepted: 9000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 160000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 5, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 161000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 163000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 165000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 167000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 169000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000)] } },
        Event { at: 10000000, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 5, serial: 6, accepted: 11000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 160000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 6, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 161000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 163000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 165000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 167000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 169000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 171000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000)] } },
        Event { at: 12000000, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 6, serial: 7, accepted: 13000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 160000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 7, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 161000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 163000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 165000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 167000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 169000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 171000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 173000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000)] } },
        Event { at: 14000000, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 7, serial: 8, accepted: 15000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 160000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 8, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 161000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 163000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 165000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 167000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 169000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 171000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 173000000 },
            Flight { source: 7, serial: 8, attempts: 1, accepted_ns: 15000000, retry_ns: 175000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000), (8, 15000000)] } },
        Event { at: 16000000, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 8, serial: 9, accepted: 17000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 160000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 9, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 161000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 163000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 165000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 167000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 169000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 171000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 173000000 },
            Flight { source: 7, serial: 8, attempts: 1, accepted_ns: 15000000, retry_ns: 175000000 },
            Flight { source: 8, serial: 9, attempts: 1, accepted_ns: 17000000, retry_ns: 177000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000), (8, 15000000), (9, 17000000)] } },
        Event { at: 18000000, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 9, serial: 10, accepted: 19000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 160000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 10, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 161000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 163000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 165000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 167000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 169000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 171000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 173000000 },
            Flight { source: 7, serial: 8, attempts: 1, accepted_ns: 15000000, retry_ns: 175000000 },
            Flight { source: 8, serial: 9, attempts: 1, accepted_ns: 17000000, retry_ns: 177000000 },
            Flight { source: 9, serial: 10, attempts: 1, accepted_ns: 19000000, retry_ns: 179000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000), (8, 15000000), (9, 17000000), (10, 19000000)] } },
        Event { at: 20000000, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 10, serial: 11, accepted: 21000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 160000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 11, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 161000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 163000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 165000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 167000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 169000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 171000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 173000000 },
            Flight { source: 7, serial: 8, attempts: 1, accepted_ns: 15000000, retry_ns: 175000000 },
            Flight { source: 8, serial: 9, attempts: 1, accepted_ns: 17000000, retry_ns: 177000000 },
            Flight { source: 9, serial: 10, attempts: 1, accepted_ns: 19000000, retry_ns: 179000000 },
            Flight { source: 10, serial: 11, attempts: 1, accepted_ns: 21000000, retry_ns: 181000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000), (8, 15000000), (9, 17000000), (10, 19000000), (11, 21000000)] } },
        Event { at: 22000000, op: Operation::Source, argument: 0, outputs: &[
            Output::Source { source: 11, serial: 12, accepted: 23000000 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 160000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 0, data_outputs: 12, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: None, flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 161000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 163000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 165000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 167000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 169000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 171000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 173000000 },
            Flight { source: 7, serial: 8, attempts: 1, accepted_ns: 15000000, retry_ns: 175000000 },
            Flight { source: 8, serial: 9, attempts: 1, accepted_ns: 17000000, retry_ns: 177000000 },
            Flight { source: 9, serial: 10, attempts: 1, accepted_ns: 19000000, retry_ns: 179000000 },
            Flight { source: 10, serial: 11, attempts: 1, accepted_ns: 21000000, retry_ns: 181000000 },
            Flight { source: 11, serial: 12, attempts: 1, accepted_ns: 23000000, retry_ns: 183000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000), (8, 15000000), (9, 17000000), (10, 19000000), (11, 21000000), (12, 23000000)] } },
        Event { at: 30000000, op: Operation::SourceReceipt, argument: 1, outputs: &[
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 160000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 1, feedback_repeats: 2, data_outputs: 12, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: Some(40000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 161000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 163000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 165000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 167000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 169000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 171000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 173000000 },
            Flight { source: 7, serial: 8, attempts: 1, accepted_ns: 15000000, retry_ns: 175000000 },
            Flight { source: 8, serial: 9, attempts: 1, accepted_ns: 17000000, retry_ns: 177000000 },
            Flight { source: 9, serial: 10, attempts: 1, accepted_ns: 19000000, retry_ns: 179000000 },
            Flight { source: 10, serial: 11, attempts: 1, accepted_ns: 21000000, retry_ns: 181000000 },
            Flight { source: 11, serial: 12, attempts: 1, accepted_ns: 23000000, retry_ns: 183000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000), (8, 15000000), (9, 17000000), (10, 19000000), (11, 21000000), (12, 23000000)] } },
        Event { at: 30000000, op: Operation::SourceReceipt, argument: 3, outputs: &[
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 160000000, prefix: 0, feedback_cursor: 0, feedback_serial: 0, received_feedback_serial: 0, feedback_events: 2, feedback_repeats: 2, data_outputs: 12, feedback_outputs: 0, srtt: None, rttvar: 0.0, feedback_due: Some(40000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 161000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 163000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 165000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 167000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 169000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 171000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 173000000 },
            Flight { source: 7, serial: 8, attempts: 1, accepted_ns: 15000000, retry_ns: 175000000 },
            Flight { source: 8, serial: 9, attempts: 1, accepted_ns: 17000000, retry_ns: 177000000 },
            Flight { source: 9, serial: 10, attempts: 1, accepted_ns: 19000000, retry_ns: 179000000 },
            Flight { source: 10, serial: 11, attempts: 1, accepted_ns: 21000000, retry_ns: 181000000 },
            Flight { source: 11, serial: 12, attempts: 1, accepted_ns: 23000000, retry_ns: 183000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000), (8, 15000000), (9, 17000000), (10, 19000000), (11, 21000000), (12, 23000000)] } },
        Event { at: 30000000, op: Operation::SourceReceipt, argument: 4, outputs: &[
            Output::Feedback { prefix: 0, start: 0, count: 5, bitmap: 26, echo: 5, delay_us: 0, serial: 1 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 160000000, prefix: 0, feedback_cursor: 0, feedback_serial: 1, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 1, data_outputs: 12, feedback_outputs: 1, srtt: None, rttvar: 0.0, feedback_due: Some(40000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 161000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 163000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 165000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 167000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 169000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 171000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 173000000 },
            Flight { source: 7, serial: 8, attempts: 1, accepted_ns: 15000000, retry_ns: 175000000 },
            Flight { source: 8, serial: 9, attempts: 1, accepted_ns: 17000000, retry_ns: 177000000 },
            Flight { source: 9, serial: 10, attempts: 1, accepted_ns: 19000000, retry_ns: 179000000 },
            Flight { source: 10, serial: 11, attempts: 1, accepted_ns: 21000000, retry_ns: 181000000 },
            Flight { source: 11, serial: 12, attempts: 1, accepted_ns: 23000000, retry_ns: 183000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000), (8, 15000000), (9, 17000000), (10, 19000000), (11, 21000000), (12, 23000000)] } },
        Event { at: 31000000, op: Operation::SourceReceipt, argument: 5, outputs: &[
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 160000000, prefix: 0, feedback_cursor: 0, feedback_serial: 1, received_feedback_serial: 0, feedback_events: 1, feedback_repeats: 2, data_outputs: 12, feedback_outputs: 1, srtt: None, rttvar: 0.0, feedback_due: Some(40000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 161000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 163000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 165000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 167000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 169000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 171000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 173000000 },
            Flight { source: 7, serial: 8, attempts: 1, accepted_ns: 15000000, retry_ns: 175000000 },
            Flight { source: 8, serial: 9, attempts: 1, accepted_ns: 17000000, retry_ns: 177000000 },
            Flight { source: 9, serial: 10, attempts: 1, accepted_ns: 19000000, retry_ns: 179000000 },
            Flight { source: 10, serial: 11, attempts: 1, accepted_ns: 21000000, retry_ns: 181000000 },
            Flight { source: 11, serial: 12, attempts: 1, accepted_ns: 23000000, retry_ns: 183000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000), (8, 15000000), (9, 17000000), (10, 19000000), (11, 21000000), (12, 23000000)] } },
        Event { at: 32000000, op: Operation::SourceReceipt, argument: 0, outputs: &[
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 160000000, prefix: 2, feedback_cursor: 0, feedback_serial: 1, received_feedback_serial: 0, feedback_events: 2, feedback_repeats: 2, data_outputs: 12, feedback_outputs: 1, srtt: None, rttvar: 0.0, feedback_due: Some(40000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 161000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 163000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 165000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 167000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 169000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 171000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 173000000 },
            Flight { source: 7, serial: 8, attempts: 1, accepted_ns: 15000000, retry_ns: 175000000 },
            Flight { source: 8, serial: 9, attempts: 1, accepted_ns: 17000000, retry_ns: 177000000 },
            Flight { source: 9, serial: 10, attempts: 1, accepted_ns: 19000000, retry_ns: 179000000 },
            Flight { source: 10, serial: 11, attempts: 1, accepted_ns: 21000000, retry_ns: 181000000 },
            Flight { source: 11, serial: 12, attempts: 1, accepted_ns: 23000000, retry_ns: 183000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000), (8, 15000000), (9, 17000000), (10, 19000000), (11, 21000000), (12, 23000000)] } },
        Event { at: 35000000, op: Operation::SourceReceipt, argument: 6, outputs: &[
            Output::Feedback { prefix: 2, start: 2, count: 5, bitmap: 30, echo: 7, delay_us: 0, serial: 2 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 160000000, prefix: 2, feedback_cursor: 2, feedback_serial: 2, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 1, data_outputs: 12, feedback_outputs: 2, srtt: None, rttvar: 0.0, feedback_due: Some(45000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 161000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 163000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 165000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 167000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 169000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 171000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 173000000 },
            Flight { source: 7, serial: 8, attempts: 1, accepted_ns: 15000000, retry_ns: 175000000 },
            Flight { source: 8, serial: 9, attempts: 1, accepted_ns: 17000000, retry_ns: 177000000 },
            Flight { source: 9, serial: 10, attempts: 1, accepted_ns: 19000000, retry_ns: 179000000 },
            Flight { source: 10, serial: 11, attempts: 1, accepted_ns: 21000000, retry_ns: 181000000 },
            Flight { source: 11, serial: 12, attempts: 1, accepted_ns: 23000000, retry_ns: 183000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000), (8, 15000000), (9, 17000000), (10, 19000000), (11, 21000000), (12, 23000000)] } },
        Event { at: 40000000, op: Operation::FeedbackTimer, argument: 0, outputs: &[
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 160000000, prefix: 2, feedback_cursor: 2, feedback_serial: 2, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 1, data_outputs: 12, feedback_outputs: 2, srtt: None, rttvar: 0.0, feedback_due: Some(45000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 161000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 163000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 165000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 167000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 169000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 171000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 173000000 },
            Flight { source: 7, serial: 8, attempts: 1, accepted_ns: 15000000, retry_ns: 175000000 },
            Flight { source: 8, serial: 9, attempts: 1, accepted_ns: 17000000, retry_ns: 177000000 },
            Flight { source: 9, serial: 10, attempts: 1, accepted_ns: 19000000, retry_ns: 179000000 },
            Flight { source: 10, serial: 11, attempts: 1, accepted_ns: 21000000, retry_ns: 181000000 },
            Flight { source: 11, serial: 12, attempts: 1, accepted_ns: 23000000, retry_ns: 183000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000), (8, 15000000), (9, 17000000), (10, 19000000), (11, 21000000), (12, 23000000)] } },
        Event { at: 41000000, op: Operation::SourceReceipt, argument: 6, outputs: &[
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 160000000, prefix: 2, feedback_cursor: 2, feedback_serial: 2, received_feedback_serial: 0, feedback_events: 1, feedback_repeats: 2, data_outputs: 12, feedback_outputs: 2, srtt: None, rttvar: 0.0, feedback_due: Some(45000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 161000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 163000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 165000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 167000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 169000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 171000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 173000000 },
            Flight { source: 7, serial: 8, attempts: 1, accepted_ns: 15000000, retry_ns: 175000000 },
            Flight { source: 8, serial: 9, attempts: 1, accepted_ns: 17000000, retry_ns: 177000000 },
            Flight { source: 9, serial: 10, attempts: 1, accepted_ns: 19000000, retry_ns: 179000000 },
            Flight { source: 10, serial: 11, attempts: 1, accepted_ns: 21000000, retry_ns: 181000000 },
            Flight { source: 11, serial: 12, attempts: 1, accepted_ns: 23000000, retry_ns: 183000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000), (8, 15000000), (9, 17000000), (10, 19000000), (11, 21000000), (12, 23000000)] } },
        Event { at: 45000000, op: Operation::FeedbackTimer, argument: 0, outputs: &[
            Output::Feedback { prefix: 2, start: 2, count: 5, bitmap: 30, echo: 7, delay_us: 4000, serial: 3 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 160000000, prefix: 2, feedback_cursor: 2, feedback_serial: 3, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 1, data_outputs: 12, feedback_outputs: 3, srtt: None, rttvar: 0.0, feedback_due: Some(55000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 161000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 163000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 165000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 167000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 169000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 171000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 173000000 },
            Flight { source: 7, serial: 8, attempts: 1, accepted_ns: 15000000, retry_ns: 175000000 },
            Flight { source: 8, serial: 9, attempts: 1, accepted_ns: 17000000, retry_ns: 177000000 },
            Flight { source: 9, serial: 10, attempts: 1, accepted_ns: 19000000, retry_ns: 179000000 },
            Flight { source: 10, serial: 11, attempts: 1, accepted_ns: 21000000, retry_ns: 181000000 },
            Flight { source: 11, serial: 12, attempts: 1, accepted_ns: 23000000, retry_ns: 183000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000), (8, 15000000), (9, 17000000), (10, 19000000), (11, 21000000), (12, 23000000)] } },
        Event { at: 46000000, op: Operation::SourceReceipt, argument: 2, outputs: &[
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 160000000, prefix: 7, feedback_cursor: 2, feedback_serial: 3, received_feedback_serial: 0, feedback_events: 1, feedback_repeats: 2, data_outputs: 12, feedback_outputs: 3, srtt: None, rttvar: 0.0, feedback_due: Some(55000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 161000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 163000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 165000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 167000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 169000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 171000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 173000000 },
            Flight { source: 7, serial: 8, attempts: 1, accepted_ns: 15000000, retry_ns: 175000000 },
            Flight { source: 8, serial: 9, attempts: 1, accepted_ns: 17000000, retry_ns: 177000000 },
            Flight { source: 9, serial: 10, attempts: 1, accepted_ns: 19000000, retry_ns: 179000000 },
            Flight { source: 10, serial: 11, attempts: 1, accepted_ns: 21000000, retry_ns: 181000000 },
            Flight { source: 11, serial: 12, attempts: 1, accepted_ns: 23000000, retry_ns: 183000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000), (8, 15000000), (9, 17000000), (10, 19000000), (11, 21000000), (12, 23000000)] } },
        Event { at: 47000000, op: Operation::SourceReceipt, argument: 8, outputs: &[
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 160000000, prefix: 7, feedback_cursor: 2, feedback_serial: 3, received_feedback_serial: 0, feedback_events: 2, feedback_repeats: 2, data_outputs: 12, feedback_outputs: 3, srtt: None, rttvar: 0.0, feedback_due: Some(55000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 161000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 163000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 165000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 167000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 169000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 171000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 173000000 },
            Flight { source: 7, serial: 8, attempts: 1, accepted_ns: 15000000, retry_ns: 175000000 },
            Flight { source: 8, serial: 9, attempts: 1, accepted_ns: 17000000, retry_ns: 177000000 },
            Flight { source: 9, serial: 10, attempts: 1, accepted_ns: 19000000, retry_ns: 179000000 },
            Flight { source: 10, serial: 11, attempts: 1, accepted_ns: 21000000, retry_ns: 181000000 },
            Flight { source: 11, serial: 12, attempts: 1, accepted_ns: 23000000, retry_ns: 183000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000), (8, 15000000), (9, 17000000), (10, 19000000), (11, 21000000), (12, 23000000)] } },
        Event { at: 47000000, op: Operation::SourceReceipt, argument: 9, outputs: &[
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 160000000, prefix: 7, feedback_cursor: 2, feedback_serial: 3, received_feedback_serial: 0, feedback_events: 3, feedback_repeats: 2, data_outputs: 12, feedback_outputs: 3, srtt: None, rttvar: 0.0, feedback_due: Some(55000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 161000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 163000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 165000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 167000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 169000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 171000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 173000000 },
            Flight { source: 7, serial: 8, attempts: 1, accepted_ns: 15000000, retry_ns: 175000000 },
            Flight { source: 8, serial: 9, attempts: 1, accepted_ns: 17000000, retry_ns: 177000000 },
            Flight { source: 9, serial: 10, attempts: 1, accepted_ns: 19000000, retry_ns: 179000000 },
            Flight { source: 10, serial: 11, attempts: 1, accepted_ns: 21000000, retry_ns: 181000000 },
            Flight { source: 11, serial: 12, attempts: 1, accepted_ns: 23000000, retry_ns: 183000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000), (8, 15000000), (9, 17000000), (10, 19000000), (11, 21000000), (12, 23000000)] } },
        Event { at: 47000000, op: Operation::SourceReceipt, argument: 10, outputs: &[
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 160000000, prefix: 7, feedback_cursor: 2, feedback_serial: 3, received_feedback_serial: 0, feedback_events: 4, feedback_repeats: 2, data_outputs: 12, feedback_outputs: 3, srtt: None, rttvar: 0.0, feedback_due: Some(55000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 161000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 163000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 165000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 167000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 169000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 171000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 173000000 },
            Flight { source: 7, serial: 8, attempts: 1, accepted_ns: 15000000, retry_ns: 175000000 },
            Flight { source: 8, serial: 9, attempts: 1, accepted_ns: 17000000, retry_ns: 177000000 },
            Flight { source: 9, serial: 10, attempts: 1, accepted_ns: 19000000, retry_ns: 179000000 },
            Flight { source: 10, serial: 11, attempts: 1, accepted_ns: 21000000, retry_ns: 181000000 },
            Flight { source: 11, serial: 12, attempts: 1, accepted_ns: 23000000, retry_ns: 183000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000), (8, 15000000), (9, 17000000), (10, 19000000), (11, 21000000), (12, 23000000)] } },
        Event { at: 50000000, op: Operation::SourceReceipt, argument: 11, outputs: &[
            Output::Feedback { prefix: 7, start: 7, count: 5, bitmap: 30, echo: 12, delay_us: 0, serial: 4 },
        ], expected: Expected { base: 0, sampled: 0, rto_ns: 160000000, prefix: 7, feedback_cursor: 7, feedback_serial: 4, received_feedback_serial: 0, feedback_events: 0, feedback_repeats: 1, data_outputs: 12, feedback_outputs: 4, srtt: None, rttvar: 0.0, feedback_due: Some(60000000), flights: &[
            Flight { source: 0, serial: 1, attempts: 1, accepted_ns: 1000000, retry_ns: 161000000 },
            Flight { source: 1, serial: 2, attempts: 1, accepted_ns: 3000000, retry_ns: 163000000 },
            Flight { source: 2, serial: 3, attempts: 1, accepted_ns: 5000000, retry_ns: 165000000 },
            Flight { source: 3, serial: 4, attempts: 1, accepted_ns: 7000000, retry_ns: 167000000 },
            Flight { source: 4, serial: 5, attempts: 1, accepted_ns: 9000000, retry_ns: 169000000 },
            Flight { source: 5, serial: 6, attempts: 1, accepted_ns: 11000000, retry_ns: 171000000 },
            Flight { source: 6, serial: 7, attempts: 1, accepted_ns: 13000000, retry_ns: 173000000 },
            Flight { source: 7, serial: 8, attempts: 1, accepted_ns: 15000000, retry_ns: 175000000 },
            Flight { source: 8, serial: 9, attempts: 1, accepted_ns: 17000000, retry_ns: 177000000 },
            Flight { source: 9, serial: 10, attempts: 1, accepted_ns: 19000000, retry_ns: 179000000 },
            Flight { source: 10, serial: 11, attempts: 1, accepted_ns: 21000000, retry_ns: 181000000 },
            Flight { source: 11, serial: 12, attempts: 1, accepted_ns: 23000000, retry_ns: 183000000 },
        ], history: &[(1, 1000000), (2, 3000000), (3, 5000000), (4, 7000000), (5, 9000000), (6, 11000000), (7, 13000000), (8, 15000000), (9, 17000000), (10, 19000000), (11, 21000000), (12, 23000000)] } },
    ] },
];
