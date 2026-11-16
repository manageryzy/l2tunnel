//! Exact original ACK events and actual reserved Pipeline refusal/custody.
use super::*;
use crate::{FlowTableConfig, Mapping, ParseLimits, QueueLimits, TunQosConfig};
use smoltcp::{
    phy::ChecksumCapabilities,
    wire::{
        IpAddress, IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr, TcpControl, TcpPacket,
        TcpRepr, TcpSeqNumber, TcpTimestampRepr,
    },
};
use std::{
    convert::Infallible,
    net::{Ipv4Addr, Ipv6Addr},
};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn config(l2: bool, packets: usize) -> PipelineConfig {
    let queue = QueueLimits {
        bytes: 4096,
        packets,
    };
    PipelineConfig {
        profile: if l2 {
            Profile::TapSystem
        } else {
            Profile::TunDrr(TunQosConfig {
                base_quantum_bytes: 256,
                max_weight: 1,
                per_flow: queue,
            })
        },
        flows: FlowTableConfig {
            capacity: 4,
            channels: 2,
            mapping: Mapping::ConnectionRoundRobin,
            idle_timeout: Duration::from_secs(1),
        },
        parse: ParseLimits {
            max_packet_bytes: 256,
            ..ParseLimits::default()
        },
        queue,
    }
}
fn policy() -> Policy {
    Policy {
        selection: Selection::Benchmark,
        interval: Duration::from_millis(5),
        max_hold: Duration::from_millis(20),
        max_flows: 4,
        max_ack_bytes: 130,
    }
}
fn pair(l2: bool, packets: usize) -> TestResult<(Pipeline, Ingress)> {
    let config = config(l2, packets);
    let pipeline = Pipeline::new_reserved(
        config,
        crate::storage::Limits {
            capacity_bytes: crate::storage::Plan::for_pipeline(config)?.capacity_bytes(),
        },
    )?;
    let plan = Plan::for_pipeline(config, policy())?;
    let ingress = Ingress::new(
        plan,
        Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?;
    Ok((pipeline, ingress))
}

// Maintained smoltcp emits complete checksum-valid fixtures. The coalescer must
// preserve these exact original bytes; no second coalescer encoder is involved.
fn ack(ipv6: bool, l2: bool, number: u32, timestamp: u32, window: u16, sack: bool) -> Vec<u8> {
    let (source, destination) = if ipv6 {
        (
            IpAddress::Ipv6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
            IpAddress::Ipv6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)),
        )
    } else {
        (
            IpAddress::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddress::Ipv4(Ipv4Addr::new(10, 0, 0, 2)),
        )
    };
    let tcp = TcpRepr {
        src_port: 40000,
        dst_port: 443,
        control: TcpControl::None,
        seq_number: TcpSeqNumber(123),
        ack_number: Some(TcpSeqNumber(number as i32)),
        window_len: window,
        max_seg_size: None,
        window_scale: None,
        sack_permitted: false,
        sack_ranges: [
            sack.then(|| (number.wrapping_add(20), number.wrapping_add(30))),
            None,
            None,
        ],
        timestamp: Some(TcpTimestampRepr::new(timestamp, timestamp + 7)),
        payload: &[],
    };
    let header = if ipv6 { 40 } else { 20 };
    let mut bytes = vec![0; header + tcp.buffer_len()];
    let checksum = ChecksumCapabilities::default();
    match (source, destination) {
        (IpAddress::Ipv4(src_addr), IpAddress::Ipv4(dst_addr)) => Ipv4Repr {
            src_addr,
            dst_addr,
            next_header: IpProtocol::Tcp,
            payload_len: tcp.buffer_len(),
            hop_limit: 64,
        }
        .emit(
            &mut Ipv4Packet::new_unchecked(&mut bytes[..header]),
            &checksum,
        ),
        (IpAddress::Ipv6(src_addr), IpAddress::Ipv6(dst_addr)) => Ipv6Repr {
            src_addr,
            dst_addr,
            next_header: IpProtocol::Tcp,
            payload_len: tcp.buffer_len(),
            hop_limit: 64,
        }
        .emit(&mut Ipv6Packet::new_unchecked(&mut bytes[..header])),
        _ => unreachable!("fixture address families match"),
    }
    tcp.emit(
        &mut TcpPacket::new_unchecked(&mut bytes[header..]),
        &source,
        &destination,
        &checksum,
    );
    if l2 {
        let mut frame = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        frame.extend_from_slice(&(if ipv6 { 0x86ddu16 } else { 0x0800 }).to_be_bytes());
        frame.extend_from_slice(&bytes);
        frame
    } else {
        bytes
    }
}
fn take(pipeline: &mut Pipeline) -> TestResult<Vec<u8>> {
    let value = pipeline
        .offer_front_borrowed(|metadata, bytes| {
            Ok::<_, Infallible>(Some((metadata, bytes.to_vec())))
        })?
        .ok_or("actual Pipeline packet absent")?;
    assert_eq!(value.metadata, value.permit.0);
    Ok(value.permit.1)
}
fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}

#[test]
fn advancing_timer_duplicate_semantics_and_unsafe_options_use_actual_pipeline() -> TestResult {
    for (ipv6, l2) in [(false, false), (true, false), (false, true)] {
        let (mut pipeline, mut ingress) = pair(l2, 16)?;
        let backing = ingress.usage();
        let first = ack(ipv6, l2, 100, 1, 4096, false);
        assert!(matches!(
            ingress.ingest(&mut pipeline, &first, ms(0), ms(50))?,
            Admission::Forwarded(_)
        ));
        assert_eq!(take(&mut pipeline)?, first);
        let a = ack(ipv6, l2, 101, 2, 4096, false);
        let b = ack(ipv6, l2, 102, 3, 4096, false);
        assert_eq!(
            ingress.ingest(&mut pipeline, &a, ms(1), ms(50))?,
            Admission::Held
        );
        assert_eq!(
            ingress.ingest(&mut pipeline, &b, ms(3), ms(70))?,
            Admission::Superseded
        );
        let pending = ingress
            .pending()
            .next()
            .ok_or("actual pending ACK absent")?;
        assert_eq!(
            (
                pending.first_created,
                pending.latest_created,
                pending.deadline,
                pending.expires
            ),
            (ms(1), ms(3), ms(6), ms(21))
        );
        assert_eq!(
            ingress.advance(&mut pipeline, ms(5), false, 4)?.forwarded,
            0
        );
        assert_eq!(pipeline.usage().packets, 0);
        assert_eq!(
            ingress.advance(&mut pipeline, ms(6), false, 4)?.forwarded,
            1
        );
        assert_eq!(take(&mut pipeline)?, b);
        // Every generated duplicate remains distinct, including its own echo.
        for (at, timestamp) in [(7, 4), (8, 5)] {
            let duplicate = ack(ipv6, l2, 102, timestamp, 4096, false);
            assert!(matches!(
                ingress.ingest(&mut pipeline, &duplicate, ms(at), ms(50))?,
                Admission::Forwarded(_)
            ));
            assert_eq!(take(&mut pipeline)?, duplicate);
        }
        let advancing = ack(ipv6, l2, 103, 6, 4096, false);
        let duplicate = ack(ipv6, l2, 103, 7, 4096, false);
        assert_eq!(
            ingress.ingest(&mut pipeline, &advancing, ms(9), ms(50))?,
            Admission::Held
        );
        ingress.ingest(&mut pipeline, &duplicate, ms(10), ms(50))?;
        assert_eq!(take(&mut pipeline)?, advancing);
        assert_eq!(take(&mut pipeline)?, duplicate);
        let held = ack(ipv6, l2, 104, 8, 4096, false);
        let window = ack(ipv6, l2, 105, 9, 4097, false);
        ingress.ingest(&mut pipeline, &held, ms(11), ms(50))?;
        ingress.ingest(&mut pipeline, &window, ms(12), ms(50))?;
        assert_eq!(take(&mut pipeline)?, held);
        assert_eq!(take(&mut pipeline)?, window);
        let sack = ack(ipv6, l2, 106, 10, 4097, true);
        assert!(matches!(
            ingress.ingest(&mut pipeline, &sack, ms(13), ms(50))?,
            Admission::Forwarded(_)
        ));
        assert_eq!(take(&mut pipeline)?, sack);
        let ordinary = ack(ipv6, l2, 107, 11, 4097, false);
        assert!(matches!(
            ingress.ingest(&mut pipeline, &ordinary, ms(14), ms(50))?,
            Admission::Forwarded(_)
        ));
        assert_eq!(take(&mut pipeline)?, ordinary);
        let mut bad_checksum = ack(ipv6, l2, 108, 12, 4097, false);
        let at = bad_checksum.len() - 1;
        bad_checksum[at] ^= 0x80;
        ingress.ingest(&mut pipeline, &bad_checksum, ms(15), ms(50))?;
        assert_eq!(take(&mut pipeline)?, bad_checksum);
        assert!(ingress.is_empty());
        assert_eq!(ingress.statistics().duplicates, 3);
        assert_eq!(ingress.statistics().superseded, 1);
        assert_eq!(ingress.usage().capacity_bytes, backing.capacity_bytes);
        assert_eq!(ingress.usage().allocations, 2);
        // Empty old history can retire only through the actual Pipeline owner.
        ingress.retire_drained(&mut pipeline, &pending.flow)?;
        let wrap = ack(ipv6, l2, u32::MAX - 1, 13, 4096, false);
        ingress.ingest(&mut pipeline, &wrap, ms(16), ms(50))?;
        assert_eq!(take(&mut pipeline)?, wrap);
        let zero = ack(ipv6, l2, 0, 14, 4096, false);
        assert_eq!(
            ingress.ingest(&mut pipeline, &zero, ms(17), ms(50))?,
            Admission::Held
        );
        assert_eq!(
            ingress.advance(&mut pipeline, ms(18), true, 4)?.forwarded,
            1
        );
        assert_eq!(take(&mut pipeline)?, zero);
        let ambiguous = ack(ipv6, l2, 1 << 31, 15, 4096, false);
        assert!(matches!(
            ingress.ingest(&mut pipeline, &ambiguous, ms(19), ms(50))?,
            Admission::Forwarded(_)
        ));
        assert_eq!(take(&mut pipeline)?, ambiguous);
        assert!(ingress.is_empty());
    }
    Ok(())
}

#[test]
fn downstream_refusal_keeps_duplicate_input_and_original_expiry_without_false_drain() -> TestResult
{
    let (mut pipeline, mut ingress) = pair(false, 2)?;
    assert_eq!(
        Plan::for_pipeline(
            config(true, 2),
            Policy {
                selection: Selection::OwnedTcp,
                ..policy()
            }
        ),
        Err(Error::Policy)
    );
    let plan = Plan::for_pipeline(config(false, 2), policy())?;
    assert!(matches!(
        Ingress::new(
            plan,
            Limits {
                capacity_bytes: plan.capacity_bytes() - 1
            }
        ),
        Err(Error::Limit { .. })
    ));
    let first = ack(false, false, 100, 1, 4096, false);
    let held = ack(false, false, 101, 2, 4096, false);
    let duplicate = ack(false, false, 101, 3, 4096, false);
    ingress.ingest(&mut pipeline, &first, ms(0), ms(50))?;
    ingress.ingest(&mut pipeline, &held, ms(1), ms(50))?;
    let usage = pipeline.usage();
    assert!(
        pipeline
            .offer_front_borrowed(|_, _| Ok::<Option<()>, Infallible>(None))?
            .is_none()
    );
    assert_eq!(pipeline.usage(), usage);
    assert_eq!(ingress.usage().held.packets, 1);
    assert!(matches!(
        ingress.ingest(&mut pipeline, &duplicate, ms(2), ms(50)),
        Err(Error::Pipeline(PipelineError::Budget(Budget::Packets)))
    ));
    assert_eq!(ingress.statistics().received, 2);
    assert_eq!(ingress.statistics().flushed, 1);
    assert!(ingress.is_empty());
    assert_eq!(pipeline.usage().packets, 2);
    assert_eq!(take(&mut pipeline)?, first);
    assert_eq!(take(&mut pipeline)?, held);
    ingress.ingest(&mut pipeline, &duplicate, ms(2), ms(50))?;
    assert_eq!(take(&mut pipeline)?, duplicate);
    assert_eq!(ingress.statistics().duplicates, 1);
    let a = ack(false, false, 102, 4, 4096, false);
    let b = ack(false, false, 103, 5, 4096, false);
    ingress.ingest(&mut pipeline, &a, ms(4), ms(9))?;
    let key = ingress.pending().next().ok_or("held original absent")?.flow;
    assert_eq!(
        ingress.retire_drained(&mut pipeline, &key),
        Err(Error::Busy)
    );
    ingress.ingest(&mut pipeline, &b, ms(6), ms(80))?;
    let pending = ingress.pending().next().ok_or("held replacement absent")?;
    assert_eq!(
        (
            pending.first_created,
            pending.latest_created,
            pending.deadline,
            pending.expires
        ),
        (ms(4), ms(6), ms(9), ms(9))
    );
    assert_eq!(ingress.wake_at(ms(8), ms(5))?, Some(ms(9)));
    assert_eq!(
        ingress.advance(&mut pipeline, ms(9), true, 4),
        Err(Error::Expired)
    );
    assert_eq!(ingress.failure(), Some(Error::Expired));
    assert_eq!(
        ingress.advance(&mut pipeline, ms(8), true, 4),
        Err(Error::Expired)
    );
    assert!(!ingress.is_empty());
    assert_eq!(ingress.pending().next(), Some(pending));
    assert_eq!(pipeline.usage().packets, 0);
    assert_eq!(ingress.usage().held.packets, 1);
    let index = ingress
        .slots
        .iter()
        .position(|state| state.is_some_and(|state| state.pending.is_some()))
        .ok_or("actual held slab absent")?;
    let start = index * ingress.plan.policy.max_ack_bytes;
    assert_eq!(&ingress.slab[start..start + b.len()], b);
    Ok(())
}
