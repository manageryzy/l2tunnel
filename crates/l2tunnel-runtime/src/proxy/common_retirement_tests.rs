//! Component loss/custody proofs using actual maintained direct ARQ owners.
//! The service child separately proves the real actor fences and joined hook.
use super::*;
use l2tunnel_codec::aligned_receiver::{ChannelId, RecordId};
use l2tunnel_recovery::{ArqConfig, EndpointRole, RecoveryContext, SourceId};
use l2tunnel_reliable::{OutboundBudget, PreparedOutput, RecordKind, Reliable, ReliableConfig};
use std::future::Future;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}
fn policy() -> ReliableConfig {
    let source = l2tunnel_recovery::DATA_HEADER_BYTES + 64;
    ReliableConfig {
        arq: ArqConfig {
            max_source_bytes: 64,
            send_bytes: 512,
            receive_bytes: 512,
            send_records: 8,
            receive_records: 8,
            initial_rto: ms(10),
            maximum_rto: ms(80),
            ack_delay: ms(1),
            max_retries: 8,
        },
        fec: l2tunnel_fec::DecoderConfig {
            block: l2tunnel_fec::BlockConfig {
                max_sources: 3,
                max_source_bytes: source,
                max_packet_bytes: l2tunnel_fec::HEADER_BYTES + 3 + 2 + source,
                max_work_per_symbol: 4096,
            },
            max_generations: 4,
            max_symbols_per_generation: 3,
            max_reserved_bytes: 1_000_000,
            max_lifetime_ticks: 50,
            generation_window: 32,
        },
        repair_symbols: 0,
        flush_after: ms(5),
        max_restored_packets: 16,
        max_restored_bytes: 16 * source,
        outer_overhead_bytes: 28,
    }
}
struct Endpoint {
    port: RecordPort,
    stream: Stream,
    bridge: Bridge,
    owner: Reliable,
    source: SourceId,
    first: Vec<u8>,
}
fn emit(owner: &mut Reliable, now: u64, feedback: bool) -> TestResult<(Vec<u8>, PreparedOutput)> {
    let mut packet = vec![0; owner.send_max_packet_bytes()];
    let mut budget = OutboundBudget {
        packets: 1,
        wire_bytes: 4096,
    };
    let count = if feedback {
        owner.poll_feedback_independent(ms(now), &mut packet, &mut budget)?
    } else {
        owner.poll_data_independent(ms(now), &mut packet, &mut budget)?
    }
    .ok_or("missing actual Reliable output")?;
    let witness = if feedback {
        owner.pending_feedback_output()
    } else {
        owner.pending_data_output()
    }
    .ok_or("missing actual physical witness")?;
    assert_eq!(
        witness.kind,
        if feedback {
            RecordKind::Feedback
        } else {
            RecordKind::Source
        }
    );
    assert_eq!(witness.bytes, count);
    assert_eq!(budget.packets, 0);
    packet.truncate(count);
    Ok((packet, witness))
}
fn poll_shutdown(stream: &mut Stream) -> Poll<io::Result<()>> {
    Pin::new(stream).poll_shutdown(&mut Context::from_waker(Waker::noop()))
}
async fn endpoint(role: EndpointRole, record: u64, cap: Instant) -> TestResult<Endpoint> {
    let (mut port, mut stream, bridge) = pair_retained(64, ms(100))?;
    bridge.set_drain_cap(cap)?;
    stream.socket.writable().await?;
    assert!(poll_shutdown(&mut stream).is_pending());
    let mut original = [0; 64];
    assert_eq!(port.receive(&mut original)?, Some(1));
    assert_eq!(original[0], 0);
    let config = policy();
    let plan = l2tunnel_reliable::storage::Plan::for_duplex(config, config)?;
    let mut owner = Reliable::new_duplex_reserved(
        config,
        config,
        RecoveryContext {
            session: 0x1234,
            epoch: 7,
            role,
        },
        l2tunnel_reliable::storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?;
    owner.enable_physical_send_confirmation()?;
    let source = SourceId(owner.submit(&original[..1], Duration::ZERO)?);
    let identity = RecordIdentity {
        channel: ChannelId(0),
        record: RecordId(record),
    };
    assert_ne!(
        identity.record.0, source.0,
        "record and ARQ source namespaces are distinct"
    );
    bridge.admitted(identity)?;
    let (first, witness) = emit(&mut owner, 0, false)?;
    assert_eq!(owner.inspect_output_source(&first)?, Some(source));
    bridge.bind_final_source(identity, source)?;
    owner.confirm_output(Duration::ZERO, witness)?;
    let now = Instant::now();
    bridge.complete(identity, now, now)?;
    assert!(matches!(poll_shutdown(&mut stream), Poll::Ready(Ok(()))));
    Ok(Endpoint {
        port,
        stream,
        bridge,
        owner,
        source,
        first,
    })
}
async fn receive_eof(
    endpoint: &mut Endpoint,
    bytes: &[u8],
    now: u64,
    duplicate: bool,
) -> TestResult {
    endpoint.owner.receive(bytes, ms(now))?;
    let mut restored = [0xff; 64];
    let delivered = endpoint.owner.poll_delivered(&mut restored)?;
    if duplicate {
        assert_eq!(
            delivered, None,
            "a final-source retry must not redeliver EOF"
        );
    } else {
        let (_, count) = delivered.ok_or("actual EOF source was not delivered")?;
        assert_eq!(&restored[..count], &[0]);
        endpoint.port.transmit(&restored[..count])?;
        endpoint.stream.socket.readable().await?;
        let mut byte = [0xff];
        let mut output = ReadBuf::new(&mut byte);
        assert!(matches!(
            Pin::new(&mut endpoint.stream)
                .poll_read(&mut Context::from_waker(Waker::noop()), &mut output),
            Poll::Ready(Ok(()))
        ));
        assert!(
            output.filled().is_empty(),
            "real stream EOF, not application bytes"
        );
    }
    Ok(())
}
fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

#[tokio::test(start_paused = true)]
async fn final_source_and_first_feedback_loss_recover_before_original_retirement_cap() -> TestResult
{
    let start = Instant::now();
    let cap = start + ms(100);
    let mut a = endpoint(EndpointRole::Initiator, 37, cap).await?;
    let mut b = endpoint(EndpointRole::Responder, 91, cap).await?;
    // A's first final source is lost after a real physical receipt. B's is real.
    assert!(!a.owner.source_retired(a.source)?);
    receive_eof(&mut a, &b.first, 0, false).await?;
    let (ack_b, ack_token) = emit(&mut a.owner, 1, true)?;
    a.owner.confirm_output(ms(1), ack_token)?;
    b.owner.receive(&ack_b, ms(1))?;
    assert!(b.owner.source_retired(b.source)?);
    let (retry, retry_token) = emit(&mut a.owner, 10, false)?;
    assert_eq!(retry, a.first);
    a.owner.confirm_output(ms(10), retry_token)?;
    receive_eof(&mut b, &retry, 10, false).await?;
    let (lost_ack, ack_token) = emit(&mut b.owner, 11, true)?;
    b.owner.confirm_output(ms(11), ack_token)?;
    assert!(!lost_ack.is_empty()); // First actual final feedback is lost.
    assert!(!a.owner.source_retired(a.source)?);
    let (retry_again, retry_token) = emit(&mut a.owner, 30, false)?;
    assert_eq!(retry_again, a.first);
    a.owner.confirm_output(ms(30), retry_token)?;
    receive_eof(&mut b, &retry_again, 30, true).await?;
    let (duplicate_ack, ack_token) = emit(&mut b.owner, 31, true)?;
    b.owner.confirm_output(ms(31), ack_token)?;
    a.owner.receive(&duplicate_ack, ms(31))?;
    assert_eq!(a.owner.arq_statistics().retransmissions, 2);
    assert_eq!(b.owner.arq_statistics().duplicates, 1);
    assert!(a.owner.source_retired(a.source)? && b.owner.source_retired(b.source)?);
    assert!(a.owner.drained() && b.owner.drained());
    tokio::time::advance(ms(31)).await;
    a.bridge
        .advance_retirement(Some(a.source), true, a.owner.drained())?;
    b.bridge
        .advance_retirement(Some(b.source), true, b.owner.drained())?;
    let a_wait = a.bridge.wait_retired();
    let b_wait = b.bridge.wait_retired();
    tokio::pin!(a_wait, b_wait);
    // Only this component fixture invokes the post-join hook directly. The
    // service test separately drives actual actor quiesce/fences/native/joins.
    assert!(poll_once(a_wait.as_mut()).is_pending());
    assert!(poll_once(b_wait.as_mut()).is_pending());
    tokio::time::advance(ms(68)).await;
    a.bridge.advance_retirement(Some(a.source), true, true)?;
    assert!(poll_once(a_wait.as_mut()).is_pending());
    tokio::time::advance(ms(1)).await;
    a.bridge
        .advance_retirement(Some(a.source), true, a.owner.drained())?;
    b.bridge
        .advance_retirement(Some(b.source), true, b.owner.drained())?;
    assert!(matches!(poll_once(a_wait.as_mut()), Poll::Ready(Ok(()))));
    assert!(matches!(poll_once(b_wait.as_mut()), Poll::Ready(Ok(()))));
    assert_eq!(Instant::now(), cap);
    assert_eq!(a.bridge.retirement_deadline()?, None);
    assert_eq!(b.bridge.retirement_deadline()?, None);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn acknowledged_but_physically_retained_final_retry_fails_without_false_peer_outcome()
-> TestResult {
    let start = Instant::now();
    let cap = start + ms(100);
    let mut a = endpoint(EndpointRole::Initiator, 37, cap).await?;
    let mut b = endpoint(EndpointRole::Responder, 91, cap).await?;
    receive_eof(&mut b, &a.first, 0, false).await?;
    receive_eof(&mut a, &b.first, 0, false).await?;
    let (delayed_ack, ack_token) = emit(&mut b.owner, 1, true)?;
    b.owner.confirm_output(ms(1), ack_token)?;
    let (ack_b, ack_token) = emit(&mut a.owner, 1, true)?;
    a.owner.confirm_output(ms(1), ack_token)?;
    b.owner.receive(&ack_b, ms(1))?;
    let (held, retry_token) = emit(&mut a.owner, 10, false)?;
    assert_eq!(held, a.first);
    a.owner.receive(&delayed_ack, ms(11))?;
    assert!(a.owner.source_confirmed(a.source)?);
    assert!(!a.owner.source_retired(a.source)?);
    assert_eq!(a.owner.pending_data_output(), Some(retry_token));
    let a_wait = a.bridge.wait_retired();
    let b_wait = b.bridge.wait_retired();
    tokio::pin!(a_wait, b_wait);
    assert!(poll_once(a_wait.as_mut()).is_pending());
    assert!(poll_once(b_wait.as_mut()).is_pending());
    tokio::time::advance(ms(99)).await;
    a.bridge.advance_retirement(
        Some(a.source),
        a.owner.source_retired(a.source)?,
        a.owner.drained(),
    )?;
    b.bridge.advance_retirement(
        Some(b.source),
        b.owner.source_retired(b.source)?,
        b.owner.drained(),
    )?;
    assert!(poll_once(a_wait.as_mut()).is_pending());
    tokio::time::advance(ms(1)).await;
    assert_eq!(
        a.bridge
            .advance_retirement(
                Some(a.source),
                a.owner.source_retired(a.source)?,
                a.owner.drained()
            )
            .err()
            .ok_or("retirement must fail at original cap")?
            .kind(),
        io::ErrorKind::TimedOut
    );
    b.bridge.advance_retirement(
        Some(b.source),
        b.owner.source_retired(b.source)?,
        b.owner.drained(),
    )?;
    assert!(
        matches!(poll_once(a_wait.as_mut()), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::TimedOut)
    );
    assert!(
        matches!(poll_once(b_wait.as_mut()), Poll::Ready(Ok(()))),
        "do not invent the peer's unobserved result"
    );
    assert_eq!(a.owner.pending_data_output(), Some(retry_token));
    // The late physical fact is consumed by the actual owner, but can never
    // resurrect the failed bridge or renew its original retirement cap.
    a.owner.confirm_output_at(ms(101), ms(10), retry_token)?;
    assert!(a.owner.source_retired(a.source)?);
    assert_eq!(
        a.bridge
            .advance_retirement(Some(a.source), true, true)
            .err()
            .ok_or("retirement must fail at original cap")?
            .kind(),
        io::ErrorKind::TimedOut
    );
    Ok(())
}
