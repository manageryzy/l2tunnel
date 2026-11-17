//! Actual Compact recovery and unchanged native bodies, not a carrier proof.
use super::*;
use l2tunnel_codec::source_copy;
use l2tunnel_recovery::{CompactArqConfig, CompactBounds, CompactRecovery, CompactTiming};
use l2tunnel_reliable::CompactReliableConfig;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn policy(reverse: bool, packed: bool) -> TestResult<packed::CompactConfig> {
    let mut receiver = tests::config(if reverse { 256 } else { 128 }).receiver;
    receiver.channels = if reverse { 3 } else { 2 };
    receiver.first_record = receiver::RecordId(if reverse { 19 } else { 7 });
    let max_units = if reverse { 3 } else { 2 };
    if packed {
        receiver.lookahead_bytes = usize::from(max_units) * 65_535;
        receiver.lookahead_fragments = usize::from(max_units) * receiver.max_fragments_per_record;
    }
    let source = if packed {
        l2tunnel_codec::packed_envelope::Config {
            symbol_bytes: receiver.body.symbol_bytes,
            channels: receiver.channels,
            max_units,
        }
        .max_source_bytes()?
    } else {
        l2tunnel_codec::aligned_envelope::HEADER_BYTES + receiver.body.symbol_bytes
    };
    let recovery = CompactReliableConfig::new(
        CompactArqConfig::new(
            CompactBounds {
                max_source_bytes: source,
                send_bytes: source * 8,
                receive_bytes: source * 8,
                send_records: 8,
                receive_records: 8,
            },
            CompactTiming {
                nominal_rtt: Duration::from_millis(if reverse { 90 } else { 70 }),
                feedback_interval: Duration::from_millis(if reverse { 3 } else { 5 }),
                feedback_packets: 64,
            },
            if reverse { 79 } else { 77 },
            if reverse { 48 } else { 32 },
            8,
            if reverse {
                CompactRecovery::FirstFlight
            } else {
                CompactRecovery::Guarded
            },
        )?,
        if reverse { 73 } else { 17 },
    )?;
    Ok(packed::CompactConfig {
        base: CompactConfig {
            native_policy: NativePolicy::EthernetHeaders,
            receiver,
            recovery,
            max_recovery_packet_bytes: 1024,
            copies: source_copy::Policy::ONE,
        },
        hold_micros: if reverse { 900 } else { 500 },
        max_units,
        work_limit: if reverse { 1 } else { 2 },
    })
}

// This adapter only forwards the real public owners; it stores no second state.
enum Body {
    Aligned(Endpoint),
    Packed(packed::Endpoint),
}
macro_rules! body {
    ($this:expr, $method:ident($($argument:expr),* $(,)?)) => {
        match $this {
            Body::Aligned(owner) => owner.$method($($argument),*),
            Body::Packed(owner) => owner.$method($($argument),*),
        }
    };
}
impl Body {
    fn construct(
        send: packed::CompactConfig,
        receive: packed::CompactConfig,
        role: EndpointRole,
        is_packed: bool,
        limit: usize,
    ) -> Result<Self, storage::Error> {
        let context = tests::context(role);
        let limits = storage::Limits {
            capacity_bytes: limit,
        };
        if is_packed {
            packed::Endpoint::new_compact_duplex_reserved(send, receive, context, limits)
                .map(Self::Packed)
        } else {
            Endpoint::new_compact_duplex_reserved(send.base, receive.base, context, limits)
                .map(Self::Aligned)
        }
    }
    fn usage(&self) -> Option<storage::Usage> {
        body!(self, storage_usage())
    }
    fn status(&self) -> Status {
        body!(self, status())
    }
    fn statistics(&self) -> l2tunnel_reliable::Statistics {
        body!(self, statistics())
    }
    fn drained(&self) -> bool {
        body!(self, drained())
    }
    fn maximum(&self) -> usize {
        body!(self, max_packet_bytes())
    }
    fn enqueue(&mut self, frame: &[u8]) -> Result<(), Error> {
        body!(self, enqueue_admitted(ChannelId(0), frame, Duration::ZERO))
    }
    fn poll(
        &mut self,
        now: Duration,
        feedback: bool,
        output: &mut [u8],
        budget: &mut OutboundBudget,
    ) -> Result<Option<usize>, Error> {
        if feedback {
            body!(self, poll_feedback_independent(now, output, budget))
        } else {
            body!(self, poll_data_independent(now, output, budget))
        }
    }
    fn token(&self, feedback: bool) -> Option<PreparedOutput> {
        if feedback {
            body!(self, pending_feedback_output())
        } else {
            body!(self, pending_data_output())
        }
    }
    fn confirm(&mut self, now: Duration, token: PreparedOutput) -> Result<(), Error> {
        body!(self, confirm_output_at(now, now, token))
    }
    fn receive(&mut self, now: Duration, bytes: &[u8]) -> Result<(), Error> {
        body!(self, receive_authenticated_at(bytes, now, now))
    }
    fn collect(&mut self, now: Duration, delivered: &mut Vec<Vec<u8>>) -> TestResult {
        for _ in 0..4 {
            match body!(&mut *self, prepare(ChannelId(0), now, 1))? {
                Prepared::Idle => break,
                Prepared::Progress => {}
                Prepared::Ready => {
                    let pending = body!(&*self, pending()).ok_or("real native output")?;
                    assert_eq!(pending.channel, ChannelId(0));
                    delivered.push(pending.bytes.to_vec());
                    body!(&mut *self, commit_delivery(now))?;
                }
            }
        }
        Ok(())
    }
}

fn transfer(
    from: &mut Body,
    to: &mut Body,
    now: Duration,
    feedback: bool,
    dropped: &mut bool,
    drop_first: bool,
) -> TestResult {
    let mut output = vec![0xa5; from.maximum()];
    let mut budget = OutboundBudget {
        packets: 1,
        wire_bytes: 100_000,
    };
    let Some(length) = from.poll(now, feedback, &mut output, &mut budget)? else {
        return Ok(());
    };
    let token = from.token(feedback).ok_or("actual physical token")?;
    assert_eq!(token.bytes, length);
    assert_eq!(budget.packets, 0);
    assert_eq!(budget.wire_bytes, 100_000 - token.wire_bytes);
    assert_eq!(
        token.kind,
        if feedback {
            l2tunnel_reliable::RecordKind::Feedback
        } else {
            l2tunnel_reliable::RecordKind::Source
        }
    );
    assert_eq!(
        body!(&*from, inspect_output(&output[..length]))?,
        token.kind
    );
    let mut held = vec![0x5a; from.maximum()];
    let unchanged = budget;
    assert_eq!(from.poll(now, feedback, &mut held, &mut budget)?, None);
    assert!(held.iter().all(|byte| *byte == 0x5a));
    assert_eq!(budget, unchanged);
    assert_eq!(from.token(feedback), Some(token));
    from.confirm(now, token)?;
    if drop_first && !*dropped && !feedback {
        // The carrier accepted this actual source before the network lost it.
        *dropped = true;
    } else {
        to.receive(now, &output[..length])?;
    }
    Ok(())
}

#[test]
fn reserved_compact_aligned_and_packed_deliver_asymmetric_native_bytes_after_actual_source_loss()
-> TestResult {
    asymmetric_loss(false)
}

#[test]
fn selected_compact_wire_preserves_asymmetric_loss_recovery_physical_custody_and_native_bytes()
-> TestResult {
    asymmetric_loss(true)
}

fn asymmetric_loss(compact_wire: bool) -> TestResult {
    let frames = tests::native_frames()?;
    assert!(frames.len() >= 2);
    for is_packed in [false, true] {
        let forward = policy(false, is_packed)?;
        let reverse = policy(true, is_packed)?;
        let plan = |send: packed::CompactConfig, receive: packed::CompactConfig| {
            if is_packed {
                compact_storage::Plan::for_packed_duplex(send, receive)
            } else {
                compact_storage::Plan::for_duplex(send.base, receive.base)
            }
        };
        let a_plan = plan(forward, reverse)?;
        let b_plan = plan(reverse, forward)?;
        assert_eq!(a_plan.send_config(), forward.base);
        assert_eq!(a_plan.receive_config(), reverse.base);
        assert!(
            matches!(Body::construct(forward, reverse, EndpointRole::Initiator, is_packed,
            a_plan.capacity_bytes() - 1), Err(storage::Error::Limit { required, limit })
            if required == a_plan.capacity_bytes() && limit + 1 == required)
        );
        let mut a = Body::construct(
            forward,
            reverse,
            EndpointRole::Initiator,
            is_packed,
            a_plan.capacity_bytes(),
        )?;
        let mut b = Body::construct(
            reverse,
            forward,
            EndpointRole::Responder,
            is_packed,
            b_plan.capacity_bytes(),
        )?;
        if compact_wire {
            body!(&mut a, enable_compact_wire(41))?;
            body!(&mut b, enable_compact_wire(97))?;
        }
        let a_usage = a.usage().ok_or("actual A heap")?;
        let b_usage = b.usage().ok_or("actual B heap")?;
        assert_eq!(a_usage.capacity_bytes, a_plan.capacity_bytes());
        assert_eq!(b_usage.capacity_bytes, b_plan.capacity_bytes());
        a.enqueue(&frames[0])?;
        b.enqueue(&frames[1])?;
        let mut to_a = Vec::new();
        let mut to_b = Vec::new();
        let mut dropped = false;
        let mut never_drop = true;
        for tick in 0..500 {
            let now = Duration::from_millis(tick);
            transfer(&mut a, &mut b, now, false, &mut dropped, true)?;
            transfer(&mut b, &mut a, now, false, &mut never_drop, false)?;
            transfer(&mut a, &mut b, now, true, &mut never_drop, false)?;
            transfer(&mut b, &mut a, now, true, &mut never_drop, false)?;
            a.collect(now, &mut to_a)?;
            b.collect(now, &mut to_b)?;
        }
        assert!(dropped);
        assert_eq!(to_a, vec![frames[1].clone()]);
        assert_eq!(to_b, vec![frames[0].clone()]);
        assert!(a.drained() && b.drained());
        assert!(a.statistics().retry_packets > 0);
        for (owner, usage) in [(&a, a_usage), (&b, b_usage)] {
            assert_eq!(owner.usage(), Some(usage));
            let status = owner.status();
            assert_eq!(status.failure, None);
            assert_eq!(status.recovery.fec_reserved_bytes, 0);
            assert_eq!(status.recovery.building_packets, 0);
            assert_eq!(owner.statistics().systematic_packets, 0);
            assert_eq!(owner.statistics().repair_packets, 0);
        }
    }
    Ok(())
}

#[test]
fn packed_requested_copies_remain_canonical_but_refuse_before_storage_admission() -> TestResult {
    let forward = policy(false, true)?;
    let reverse = policy(true, true)?;
    let plan = compact_storage::Plan::for_packed_duplex(forward, reverse)?;
    assert!(plan.capacity_bytes() > 0);
    let one = packed::Endpoint::new_compact_duplex_reserved(
        forward,
        reverse,
        tests::context(EndpointRole::Initiator),
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?;
    assert_eq!(
        one.storage_usage()
            .ok_or("actual one-copy storage")?
            .capacity_bytes,
        plan.capacity_bytes()
    );
    for copy_direction in 0..2 {
        let mut selected = [forward, reverse];
        selected[copy_direction].base.copies = source_copy::Policy {
            max_unit_bytes: 128,
            copies: 3,
            scope: source_copy::Scope::ContextAndIndependent,
        };
        // Representability and authenticated requested bytes retain all copies.
        let mut encoded = [0; packed::COMPACT_CONFIG_BYTES];
        selected[copy_direction].encode_into(&mut encoded)?;
        let decoded = packed::CompactConfig::decode(&encoded)?;
        assert_eq!(decoded, selected[copy_direction]);
        assert_eq!(decoded.base.copies.copies, 3);
        assert_eq!(
            compact_storage::Plan::for_packed_duplex(selected[0], selected[1]),
            Err(storage::Error::Endpoint(Error::UnsupportedCopies)),
        );
        // A zero storage limit must not mask this unsupported capability.
        assert!(matches!(
            packed::Endpoint::new_compact_duplex_reserved(
                selected[0],
                selected[1],
                tests::context(EndpointRole::Initiator),
                storage::Limits { capacity_bytes: 0 },
            ),
            Err(storage::Error::Endpoint(Error::UnsupportedCopies)),
        ));
    }
    Ok(())
}

#[path = "native_compression_tests.rs"]
mod native_compression;
