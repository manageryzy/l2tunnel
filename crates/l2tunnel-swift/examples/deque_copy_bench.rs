//! Finite copy microcases and actual Swift packet recovery, without native I/O.
//!
//! Exact byte comparisons are authoritative. DefaultHasher is only a replay
//! fingerprint under the pinned toolchain, not a cryptographic integrity claim.
//! Capacity changes observe caller buffers, never allocator call counts or the
//! private queues' geometry. No wall-clock threshold decides correctness.

use l2tunnel_swift::{
    Config, FEEDBACK_HEADER, FRAME_PREFIX, KIND_MASK, KIND_SOURCE, MAX_REQUESTS, Receiver, Sender,
};
use std::{
    collections::{VecDeque, hash_map::DefaultHasher},
    error::Error,
    hash::Hasher,
    hint::black_box,
    time::Instant,
};

type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;

struct Options {
    packets: u32,
    rounds: u32,
    label: String,
}

impl Options {
    fn parse() -> Result<Option<Self>> {
        let mut result = Self {
            packets: 20_000,
            rounds: 3,
            label: String::from("unlabeled"),
        };
        let mut seen = [false; 3];
        let mut arguments = std::env::args().skip(1);
        while let Some(argument) = arguments.next() {
            if argument == "--help" {
                println!(
                    "deque_copy_bench [--packets 32..200000] [--rounds 1..9] [--label ASCII_NAME]"
                );
                return Ok(None);
            }
            let index = match argument.as_str() {
                "--packets" => 0,
                "--rounds" => 1,
                "--label" => 2,
                _ => return Err(format!("unknown argument: {argument}").into()),
            };
            if seen[index] {
                return Err("duplicate argument".into());
            }
            seen[index] = true;
            let value = arguments.next().ok_or("missing argument value")?;
            match index {
                0 => result.packets = value.parse()?,
                1 => result.rounds = value.parse()?,
                _ => result.label = value,
            }
        }
        if !(32..=200_000).contains(&result.packets) || !(1..=9).contains(&result.rounds) {
            return Err("packet or round count exceeds the finite benchmark bound".into());
        }
        if result.label.is_empty()
            || result.label.len() > 32
            || !result
                .label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
        {
            return Err(
                "label must contain1..32 ASCII letters, digits, hyphens, underscores or dots"
                    .into(),
            );
        }
        Ok(Some(result))
    }
}

fn fingerprint(hasher: &mut DefaultHasher, bytes: &[u8]) {
    hasher.write_u64(bytes.len() as u64);
    hasher.write(bytes);
}

#[derive(Clone, Copy)]
enum Geometry {
    Contiguous,
    Ring,
}

impl Geometry {
    fn name(self) -> &'static str {
        match self {
            Self::Contiguous => "contiguous_prefix",
            Self::Ring => "retained_tail_ring",
        }
    }
}

#[derive(Clone, Copy)]
enum CopyMethod {
    Iterator,
    Slices,
}

impl CopyMethod {
    fn name(self) -> &'static str {
        match self {
            Self::Iterator => "iterator_reference",
            Self::Slices => "two_slice_reference",
        }
    }
}

struct Micro {
    elapsed_ns: u128,
    drain_elapsed_ns: u128,
    copied_bytes: u64,
    contiguous: u32,
    wrapped: u32,
    deque_capacity: usize,
    output_capacity: usize,
    capacity_growth_events: u32,
    fingerprint: u64,
}

fn copy_prefix(
    method: CopyMethod,
    queue: &mut VecDeque<u8>,
    length: usize,
    output: &mut Vec<u8>,
) -> Result {
    if queue.len() < length {
        return Err("microcase deque underflow".into());
    }
    output.clear();
    match method {
        CopyMethod::Iterator => output.extend(queue.drain(..length)),
        CopyMethod::Slices => {
            let (first, second) = queue.as_slices();
            let take = first.len().min(length);
            output.extend_from_slice(&first[..take]);
            output.extend_from_slice(&second[..length - take]);
            drop(queue.drain(..length));
        }
    }
    Ok(())
}

fn micro(geometry: Geometry, method: CopyMethod, bytes: usize, iterations: u32) -> Result<Micro> {
    let mut template: Vec<_> = (0..bytes)
        .map(|index| (index as u8).wrapping_mul(37))
        .collect();
    template[bytes / 2..].fill(0);
    let mut queue = VecDeque::with_capacity(2 * bytes + 17);
    queue.extend(template.iter().copied());
    queue.extend(template[..17].iter().copied());
    let mut output = Vec::with_capacity(bytes);
    let initial_deque_capacity = queue.capacity();
    let initial_output_capacity = output.capacity();
    let mut result = Micro {
        elapsed_ns: 0,
        drain_elapsed_ns: 0,
        copied_bytes: 0,
        contiguous: 0,
        wrapped: 0,
        deque_capacity: initial_deque_capacity,
        output_capacity: initial_output_capacity,
        capacity_growth_events: 0,
        fingerprint: 0,
    };
    let mut digest = DefaultHasher::new();
    let start = Instant::now();
    for _ in 0..iterations {
        if matches!(geometry, Geometry::Contiguous) {
            queue.make_contiguous();
        }
        if queue.as_slices().0.len() < bytes {
            result.wrapped += 1;
        } else {
            result.contiguous += 1;
        }
        let before = Instant::now();
        copy_prefix(method, black_box(&mut queue), bytes, black_box(&mut output))?;
        result.drain_elapsed_ns += before.elapsed().as_nanos();
        if output != template || queue.len() != 17 {
            return Err("microcase prefix bytes or retained tail changed".into());
        }
        fingerprint(&mut digest, black_box(&output));
        result.copied_bytes += output.len() as u64;
        // The surviving17 bytes begin the next identical logical prefix.
        queue.extend(template[17..].iter().copied());
        queue.extend(template[..17].iter().copied());
        if queue.capacity() > result.deque_capacity || output.capacity() > result.output_capacity {
            result.capacity_growth_events += 1;
        }
        result.deque_capacity = queue.capacity();
        result.output_capacity = output.capacity();
    }
    result.elapsed_ns = start.elapsed().as_nanos();
    result.fingerprint = digest.finish();
    if matches!(geometry, Geometry::Contiguous) && result.wrapped != 0 {
        return Err("contiguous microcase had a wrapped prefix".into());
    }
    if matches!(geometry, Geometry::Ring) && (result.wrapped == 0 || result.contiguous == 0) {
        return Err("ring microcase did not observe both actual prefix geometries".into());
    }
    if result.deque_capacity != initial_deque_capacity
        || result.output_capacity != initial_output_capacity
    {
        return Err("preallocated microcase buffers grew".into());
    }
    Ok(result)
}

#[derive(Clone, Copy)]
enum Queueing {
    EmptyBatches,
    RetainedTail,
}

impl Queueing {
    fn name(self) -> &'static str {
        match self {
            Self::EmptyBatches => "empty_between_batches",
            Self::RetainedTail => "retained_tail_refill_wrap_stimulus",
        }
    }
}

fn config() -> Config {
    Config {
        datagram_bytes: 1424,
        window: 64,
        repair_numerator: 0,
        repair_denominator: 1,
        flow_sources: 64,
        queue_bytes: 32_768,
        max_packet: 1600,
        flush_micros: 1000,
        feedback_micros: 1000,
        tail_micros: 10_000,
        min_rto_micros: 1000,
        max_rto_micros: 100_000,
    }
}

fn corpus() -> Vec<Vec<u8>> {
    [1, 64, 1514, 1600, 66, 511, 1414, 97]
        .into_iter()
        .enumerate()
        .map(|(index, length)| {
            let mut packet: Vec<_> = (0..length)
                .map(|offset| (offset as u8).wrapping_mul(19).wrapping_add(index as u8))
                .collect();
            if index.is_multiple_of(3) {
                packet[length / 2..].fill(0);
            }
            if index == 1 {
                packet.fill(0);
            }
            packet
        })
        .collect()
}

struct Production {
    elapsed_ns: u128,
    poll_elapsed_ns: u128,
    pop_elapsed_ns: u128,
    native_bytes: u64,
    delivered_bytes: u64,
    source_body_bytes: u64,
    repair_body_bytes: u64,
    feedback_bytes: u64,
    dropped_sources: u64,
    dropped_feedback: u64,
    poll_calls: u64,
    pop_calls: u64,
    retained_queue_steps: u64,
    output_capacity_growth_events: u64,
    sender: l2tunnel_swift::SenderStats,
    receiver: l2tunnel_swift::ReceiverStats,
    payload_fingerprint: u64,
    body_fingerprint: u64,
    feedback_fingerprint: u64,
    logical_micros: u64,
}

fn production(queueing: Queueing, loss: bool, packets: u32) -> Result<Production> {
    let config = config();
    let mut sender = Sender::new(config)?;
    let mut receiver = Receiver::new(config)?;
    let corpus = corpus();
    let mut body = Vec::with_capacity(config.datagram_bytes);
    let mut feedback = Vec::with_capacity(FEEDBACK_HEADER + 2 * MAX_REQUESTS);
    let mut native = Vec::with_capacity(config.max_packet);
    let capacities = [body.capacity(), feedback.capacity(), native.capacity()];
    let mut sent_digest = DefaultHasher::new();
    let mut received_digest = DefaultHasher::new();
    let mut body_digest = DefaultHasher::new();
    let mut feedback_digest = DefaultHasher::new();
    let mut offered = 0u32;
    let mut delivered = 0u32;
    let mut number = 1u64 << 40;
    let mut batch_remaining = 0u32;
    let mut result = Production {
        elapsed_ns: 0,
        poll_elapsed_ns: 0,
        pop_elapsed_ns: 0,
        native_bytes: 0,
        delivered_bytes: 0,
        source_body_bytes: 0,
        repair_body_bytes: 0,
        feedback_bytes: 0,
        dropped_sources: 0,
        dropped_feedback: 0,
        poll_calls: 0,
        pop_calls: 0,
        retained_queue_steps: 0,
        output_capacity_growth_events: 0,
        sender: Default::default(),
        receiver: Default::default(),
        payload_fingerprint: 0,
        body_fingerprint: 0,
        feedback_fingerprint: 0,
        logical_micros: 0,
    };
    let started = Instant::now();
    let maximum_steps = u64::from(packets) * 20 + 10_000;
    for step in 1..=maximum_steps {
        let now = step * 1000;
        if matches!(queueing, Queueing::EmptyBatches)
            && sender.queued() == 0
            && sender.unconfirmed() == 0
        {
            batch_remaining = (packets - offered).min(32);
        }
        while offered < packets
            && sender.has_room()
            && match queueing {
                Queueing::EmptyBatches => batch_remaining > 0,
                Queueing::RetainedTail => sender.queued() < 16_384,
            }
        {
            let packet = &corpus[offered as usize % corpus.len()];
            if !sender.push_packet(now, black_box(packet))? {
                return Err("admitted production packet was refused".into());
            }
            fingerprint(&mut sent_digest, packet);
            result.native_bytes += packet.len() as u64;
            offered += 1;
            batch_remaining = batch_remaining.saturating_sub(1);
        }
        let quota = if matches!(queueing, Queueing::EmptyBatches) {
            64
        } else {
            8
        };
        for _ in 0..quota {
            let previous_sources = sender.stats().sources;
            let before = Instant::now();
            let emitted = sender.poll(now, number, black_box(&mut body))?;
            result.poll_elapsed_ns += before.elapsed().as_nanos();
            result.poll_calls += 1;
            if !emitted {
                break;
            }
            if body.len() > config.datagram_bytes {
                return Err("production datagram exceeds its original body limit".into());
            }
            fingerprint(&mut body_digest, &body);
            body_digest.write_u64(number);
            let source = body[0] & KIND_MASK == KIND_SOURCE;
            if source {
                result.source_body_bytes += body.len() as u64;
            } else {
                result.repair_body_bytes += body.len() as u64;
            }
            let original = sender.stats().sources > previous_sources;
            let drop = loss && source && original && sender.stats().sources % 17 == 6;
            if drop {
                result.dropped_sources += 1;
            } else {
                receiver.on_datagram(number, black_box(&body))?;
                loop {
                    let before = Instant::now();
                    let present = receiver.pop_packet(black_box(&mut native))?;
                    result.pop_elapsed_ns += before.elapsed().as_nanos();
                    result.pop_calls += 1;
                    if !present {
                        break;
                    }
                    if delivered >= packets || native != corpus[delivered as usize % corpus.len()] {
                        return Err(
                            "production recovery changed packet order, length or bytes".into()
                        );
                    }
                    fingerprint(&mut received_digest, black_box(&native));
                    result.delivered_bytes += native.len() as u64;
                    delivered += 1;
                }
            }
            number += 1;
        }
        if sender.queued() > 0 {
            result.retained_queue_steps += 1;
        }
        if receiver.feedback(now, &mut feedback) {
            fingerprint(&mut feedback_digest, &feedback);
            result.feedback_bytes += feedback.len() as u64;
            if loss && receiver.stats().feedback % 23 == 7 {
                result.dropped_feedback += 1;
            } else {
                sender.on_feedback(now, black_box(&feedback))?;
            }
        }
        if [body.capacity(), feedback.capacity(), native.capacity()] != capacities {
            result.output_capacity_growth_events += 1;
        }
        if offered == packets && delivered == packets && sender.unconfirmed() == 0 {
            result.elapsed_ns = started.elapsed().as_nanos();
            result.sender = sender.stats();
            result.receiver = receiver.stats();
            result.logical_micros = now;
            result.payload_fingerprint = received_digest.finish();
            result.body_fingerprint = body_digest.finish();
            result.feedback_fingerprint = feedback_digest.finish();
            if sender.queued() != 0
                || result.native_bytes != result.delivered_bytes
                || sent_digest.finish() != result.payload_fingerprint
                || result.sender.packets != u64::from(packets)
                || result.receiver.packets != u64::from(packets)
                || result.sender.packed_bytes
                    != result.native_bytes + u64::from(packets) * FRAME_PREFIX as u64
            {
                return Err(
                    "production terminal byte, queue or recovery accounting mismatch".into(),
                );
            }
            if loss && (result.dropped_sources == 0 || result.sender.retransmits == 0) {
                return Err("scripted source loss did not exercise explicit retransmission".into());
            }
            return Ok(result);
        }
    }
    Err("production pipeline exhausted its original finite logical-work bound".into())
}

fn main() -> Result {
    let Some(options) = Options::parse()? else {
        return Ok(());
    };
    println!(
        "{{\"schema\":1,\"label\":\"{}\",\"scope\":\"finite library CPU cases; no carrier, native devices, kernel throughput or QoS claim\",\"fingerprint\":\"noncryptographic DefaultHasher; exact bytes are authoritative\",\"capacity_scope\":\"caller output growth observations, not allocator counts\",\"packets\":{},\"rounds\":{},\"micro\":[",
        options.label, options.packets, options.rounds
    );
    let mut separator = "";
    for round in 0..options.rounds {
        for bytes in [64, 1416] {
            for geometry in [Geometry::Contiguous, Geometry::Ring] {
                let mut expected = None;
                for method in [CopyMethod::Iterator, CopyMethod::Slices] {
                    let measured = micro(geometry, method, bytes, options.packets)?;
                    if expected.is_some_and(|digest| digest != measured.fingerprint) {
                        return Err("paired copy reference fingerprints differ".into());
                    }
                    expected = Some(measured.fingerprint);
                    println!(
                        "{separator}{{\"round\":{round},\"geometry\":\"{}\",\"method\":\"{}\",\"bytes_per_copy\":{bytes},\"copies\":{},\"copied_bytes\":{},\"contiguous_prefix_copies\":{},\"wrapped_prefix_copies\":{},\"deque_capacity\":{},\"output_capacity\":{},\"capacity_growth_events\":{},\"fingerprint\":\"{:016x}\",\"drain_elapsed_ns\":{},\"elapsed_including_refill_check_hash_ns\":{}}}",
                        geometry.name(),
                        method.name(),
                        options.packets,
                        measured.copied_bytes,
                        measured.contiguous,
                        measured.wrapped,
                        measured.deque_capacity,
                        measured.output_capacity,
                        measured.capacity_growth_events,
                        measured.fingerprint,
                        measured.drain_elapsed_ns,
                        measured.elapsed_ns
                    );
                    separator = ",";
                }
            }
        }
    }
    println!("],\"production\":[");
    separator = "";
    for round in 0..options.rounds {
        for queueing in [Queueing::EmptyBatches, Queueing::RetainedTail] {
            for loss in [false, true] {
                let measured = production(queueing, loss, options.packets)?;
                println!(
                    "{separator}{{\"round\":{round},\"queueing\":\"{}\",\"private_queue_geometry_observed\":false,\"scripted_loss\":{loss},\"native_packets\":{},\"native_payload_bytes\":{},\"source_queue_to_payload_bytes\":{},\"receiver_stream_to_native_bytes\":{},\"source_body_attempt_bytes\":{},\"repair_body_attempt_bytes\":{},\"feedback_body_attempt_bytes\":{},\"sources\":{},\"retransmits\":{},\"repairs\":{},\"tail_repairs\":{},\"recovered\":{},\"feedback_records\":{},\"dropped_original_sources\":{},\"dropped_feedback\":{},\"poll_calls\":{},\"pop_calls\":{},\"retained_send_queue_steps\":{},\"caller_output_capacity_growth_observations\":{},\"payload_fingerprint\":\"{:016x}\",\"body_fingerprint\":\"{:016x}\",\"feedback_fingerprint\":\"{:016x}\",\"logical_micros\":{},\"sender_poll_elapsed_ns\":{},\"receiver_pop_elapsed_ns\":{},\"elapsed_ns\":{}}}",
                    queueing.name(),
                    options.packets,
                    measured.native_bytes,
                    measured.sender.packed_bytes,
                    measured.delivered_bytes,
                    measured.source_body_bytes,
                    measured.repair_body_bytes,
                    measured.feedback_bytes,
                    measured.sender.sources,
                    measured.sender.retransmits,
                    measured.sender.repairs,
                    measured.sender.tail_repairs,
                    measured.receiver.recovered,
                    measured.receiver.feedback,
                    measured.dropped_sources,
                    measured.dropped_feedback,
                    measured.poll_calls,
                    measured.pop_calls,
                    measured.retained_queue_steps,
                    measured.output_capacity_growth_events,
                    measured.payload_fingerprint,
                    measured.body_fingerprint,
                    measured.feedback_fingerprint,
                    measured.logical_micros,
                    measured.poll_elapsed_ns,
                    measured.pop_elapsed_ns,
                    measured.elapsed_ns
                );
                separator = ",";
            }
        }
    }
    println!("]}}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_prefixes_keep_real_wrapped_and_contiguous_geometry() -> Result {
        for geometry in [Geometry::Contiguous, Geometry::Ring] {
            let old = micro(geometry, CopyMethod::Iterator, 64, 256)?;
            let candidate = micro(geometry, CopyMethod::Slices, 64, 256)?;
            assert_eq!(old.fingerprint, candidate.fingerprint);
            assert_eq!(old.copied_bytes, 64 * 256);
            assert_eq!(
                (old.contiguous, old.wrapped),
                (candidate.contiguous, candidate.wrapped)
            );
            assert_eq!(old.capacity_growth_events, 0);
            assert_eq!(candidate.capacity_growth_events, 0);
        }
        Ok(())
    }

    #[test]
    fn real_recovery_preserves_zero_tails_and_source_accounting() -> Result {
        for queueing in [Queueing::EmptyBatches, Queueing::RetainedTail] {
            let clean = production(queueing, false, 256)?;
            let impaired = production(queueing, true, 256)?;
            assert_eq!(clean.payload_fingerprint, impaired.payload_fingerprint);
            assert_eq!(clean.native_bytes, impaired.native_bytes);
            assert_eq!(clean.sender.packed_bytes, clean.native_bytes + 2 * 256);
            assert_eq!(
                impaired.sender.packed_bytes,
                impaired.native_bytes + 2 * 256
            );
            assert_eq!(clean.sender.retransmits, 0);
            assert!(impaired.sender.retransmits > 0);
            assert_eq!(clean.output_capacity_growth_events, 0);
            assert_eq!(impaired.output_capacity_growth_events, 0);
        }
        Ok(())
    }
}
