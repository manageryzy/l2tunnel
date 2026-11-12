use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::task::JoinSet;
fn at(value: u64) -> Duration {
    Duration::from_micros(value)
}
fn policy(records: usize) -> delivery_window::Config {
    delivery_window::Config {
        target_bandwidth_bps: 80_000_000,
        bootstrap_rtt_micros: 70_000,
        min_rtt_micros: 2_000,
        max_rtt_micros: 2_000_000,
        headroom_percent: 125,
        minimum_bytes: 4000,
        max_inflight_bytes: 131072,
        max_records: records,
        max_packet_bytes: 4000,
        metadata_limit_bytes: 8 * 1024 * 1024,
        sample_ttl_micros: 1_000_000,
        flush_timeout_micros: 1_000_000,
    }
}
#[test]
fn all_original_fragments_and_early_native_receipt_keep_exact_bytes_and_original_times()
-> Result<(), Box<dyn std::error::Error>> {
    let mut f = Flight::new(policy(128), 2)?;
    f.admit(0, 1500, 2, at(0))?;
    f.submitted(0, 0)?;
    f.submitted(0, 1)?;
    f.admit(1, 40, 1, at(1))?;
    f.submitted(1, 2)?;
    let a0 = f.witness(0)?.ok_or("a0")?;
    let a1 = f.witness(1)?.ok_or("a1")?;
    let b = f.witness(2)?.ok_or("b")?;
    assert!(f.witness(3).is_err());
    f.sent(b, at(30), at(30))?;
    let s = f.status(at(30))?;
    assert_eq!(s.flushed.records, 0);
    assert_eq!(s.flushed_total.bytes, 40);
    f.feedback(2, at(35), at(35))?;
    let s = f.status(at(35))?;
    assert_eq!(s.delivered.bytes, 1540);
    assert_eq!(s.outstanding.bytes, 0);
    assert_eq!(s.retained_records, 2);
    assert_eq!(s.sample.map(|s| s.raw_micros), Some(5));
    f.sent(a0, at(10), at(40))?;
    assert_eq!(f.status(at(40))?.flushed.records, 0);
    f.sent(a1, at(20), at(40))?;
    let s = f.status(at(40))?;
    assert_eq!(s.flushed.records, 2);
    assert_eq!(s.flushed_total.bytes, 1540);
    assert_eq!(s.retained_records, 0);
    assert_eq!(s.sample.map(|s| s.raw_micros), Some(5));
    assert!(f.witness(0)?.is_none());
    f.sent(a1, at(21), at(41))?;
    assert_eq!(f.status(at(41))?.flushed_total.bytes, 1540);
    Ok(())
}
#[test]
fn early_ack_and_late_or_duplicate_callbacks_cannot_renew_original_first_send_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    let mut p = policy(2);
    p.flush_timeout_micros = 100;
    let mut f = Flight::new(p, 2)?;
    f.admit(0, 1500, 2, at(0))?;
    f.submitted(0, 0)?;
    f.submitted(0, 1)?;
    let a = f.witness(0)?.ok_or("a")?;
    let b = f.witness(1)?.ok_or("b")?;
    f.sent(a, at(10), at(10))?;
    f.feedback(1, at(20), at(20))?;
    f.sent(a, at(50), at(50))?;
    assert_eq!(f.status(at(99))?.next_flush_deadline, Some(Micros(100)));
    assert!(f.sent(b, at(90), at(100)).is_err());
    assert!(f.status(at(100))?.failed);
    assert!(f.sent(b, at(90), at(101)).is_err());
    Ok(())
}
#[test]
fn ring_source_ranges_wrap_without_whole_capacity_lookup_or_retirement_work()
-> Result<(), Box<dyn std::error::Error>> {
    for capacity in [4, 8192] {
        let mut f = Flight::new(policy(capacity), 2)?;
        for message in 0..24u64 {
            let now = message * 100;
            f.admit(
                message,
                if message % 2 == 0 { 1500 } else { 40 },
                2,
                at(now),
            )?;
            f.submitted(message, message * 2)?;
            f.submitted(message, message * 2 + 1)?;
            let steps = f.lookup_steps.get();
            let a = f.witness(message * 2)?.ok_or("start")?;
            let b = f.witness(message * 2 + 1)?.ok_or("end")?;
            assert_eq!(
                f.lookup_steps.get() - steps,
                2,
                "small active span must not scan configured capacity"
            );
            assert!(f.witness(message * 2 + 2).is_err());
            f.sent(a, at(now + 1), at(now + 1))?;
            f.sent(b, at(now + 2), at(now + 2))?;
            f.feedback(message + 1, at(now + 3), at(now + 3))?;
            assert_eq!(f.retire_steps, message as usize + 1);
            assert_eq!(f.status(at(now + 3))?.retained_records, 0);
            assert!(f.witness(message * 2)?.is_none());
        }
    }
    Ok(())
}
#[test]
fn multi_entry_binary_ranges_preserve_boundaries_and_pending_final_submission()
-> Result<(), Box<dyn std::error::Error>> {
    let mut f = Flight::new(policy(128), 2)?;
    for message in 0..80 {
        f.admit(message, 40, 2, at(message))?;
        f.submitted(message, message * 2)?;
        f.submitted(message, message * 2 + 1)?;
    }
    f.admit(80, 40, 2, at(80))?;
    for source in 0..160 {
        let steps = f.lookup_steps.get();
        let witness = f.witness(source)?.ok_or("range")?;
        assert_eq!(witness.ordinal, source / 2 + 1);
        assert_eq!(witness.index, (source % 2) as usize);
        assert!(f.lookup_steps.get() - steps <= 7);
    }
    assert!(f.witness(160).is_err());
    f.submitted(80, 160)?;
    assert_eq!(f.witness(160)?.ok_or("last")?.ordinal, 81);
    assert!(f.submitted(80, 162).is_err());
    Ok(())
}
#[test]
fn constructor_preflights_policy_parts_and_metadata_before_allocation() {
    for capacity in [0, 8193, usize::MAX] {
        assert!(Flight::new(policy(capacity), 1).is_err());
    }
    for parts in [0, usize::from(u16::MAX) + 1, usize::MAX] {
        assert!(Flight::new(policy(128), parts).is_err());
    }
    let mut p = policy(8192);
    p.metadata_limit_bytes = 1;
    assert!(Flight::new(p, 1).is_err());
}
#[test]
fn exhausted_source_lookup_rejects_without_wrapping_the_ordinal_ring()
-> Result<(), Box<dyn std::error::Error>> {
    let mut flight = Flight::new(policy(2), 1)?;
    flight.retired_ordinal = u64::MAX;
    flight.admitted_ordinal = u64::MAX;
    assert!(flight.witness(u64::MAX).is_err());
    Ok(())
}
struct Sender {
    attempts: Arc<AtomicUsize>,
    fail: bool,
}
impl crate::udp::DatagramSend for Sender {
    async fn send(&mut self, _bytes: &[u8]) -> io::Result<()> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            Err(io::Error::other("deliberate send failure"))
        } else {
            Ok(())
        }
    }
}
#[tokio::test]
async fn writer_reserves_bounded_callback_ownership_before_send_and_failure_never_confirms()
-> Result<(), Box<dyn std::error::Error>> {
    let attempts = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = mpsc::channel(2);
    let (events, mut delivered) = mpsc::channel(1);
    let (returned, mut buffers) = mpsc::channel(1);
    let witness = Witness {
        ordinal: 1,
        index: 0,
    };
    events
        .send(Sent {
            lane: 0,
            witness,
            at: Instant::now(),
        })
        .await?;
    let mut tasks = JoinSet::new();
    tasks.spawn(write(
        Sender {
            attempts: attempts.clone(),
            fail: false,
        },
        rx,
        events,
        0,
        returned,
    ));
    tx.send(Packet {
        bytes: vec![1],
        length: 1,
        witness: Some(witness),
    })
    .await?;
    tokio::task::yield_now().await;
    assert_eq!(attempts.load(Ordering::SeqCst), 0);
    delivered.recv().await.ok_or("occupied callback")?;
    let sent = tokio::time::timeout(Duration::from_secs(1), delivered.recv())
        .await?
        .ok_or("actual send")?;
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    assert!(sent.at <= Instant::now());
    assert_eq!(buffers.recv().await.ok_or("returned original")?.1, vec![1]);
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    let (tx, rx) = mpsc::channel(1);
    let (events, mut delivered) = mpsc::channel(1);
    let (returned, mut buffers) = mpsc::channel(1);
    tx.send(Packet {
        bytes: vec![1],
        length: 1,
        witness: Some(witness),
    })
    .await?;
    assert!(
        write(
            Sender {
                attempts,
                fail: true
            },
            rx,
            events,
            0,
            returned
        )
        .await
        .is_err()
    );
    assert!(delivered.recv().await.is_none());
    assert!(buffers.recv().await.is_none());
    Ok(())
}

#[tokio::test]
async fn owned_writer_recycles_original_allocation_and_preserves_exact_lengths()
-> Result<(), Box<dyn std::error::Error>> {
    struct ExactSender {
        next: u8,
        pointer: usize,
    }
    impl crate::udp::DatagramSend for ExactSender {
        async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
            assert_eq!(bytes.as_ptr() as usize, self.pointer);
            assert_eq!(bytes, vec![self.next; usize::from(self.next) + 1]);
            self.next += 1;
            Ok(())
        }
    }
    let (tx, rx) = mpsc::channel(1);
    let (events, mut sent) = mpsc::channel(1);
    let (returned, mut buffers) = mpsc::channel(1);
    let mut buffer = vec![0u8; 128];
    let pointer = buffer.as_ptr() as usize;
    let writer = tokio::spawn(write(
        ExactSender { next: 0, pointer },
        rx,
        events,
        0,
        returned,
    ));
    for value in 0..100u8 {
        let length = usize::from(value) + 1;
        buffer[..length].fill(value);
        tx.send(Packet {
            bytes: buffer,
            length,
            witness: Some(Witness {
                ordinal: u64::from(value) + 1,
                index: 0,
            }),
        })
        .await?;
        let event = sent.recv().await.ok_or("physical success")?;
        buffer = buffers.recv().await.ok_or("owned buffer")?.1;
        assert_eq!(buffer.as_ptr() as usize, pointer);
        assert_eq!(buffer.len(), 128);
        assert!(event.at <= Instant::now());
    }
    writer.abort();
    let _ = writer.await;
    Ok(())
}
#[test]
fn configured8192_metadata_backing_accounting_is_explicit() -> Result<(), Box<dyn std::error::Error>>
{
    let p = policy(8192);
    let f = Flight::new(p, 2)?;
    let controller = p.metadata_bytes()?;
    let entries = f.entries.len() * size_of::<Option<Native>>();
    let bitmaps = f.bits.len() * size_of::<u64>();
    assert_eq!(metadata(p, 2)?, controller + entries + bitmaps);
    eprintln!(
        "flight_backing_bytes: controller={controller} entries={entries} bitmaps={bitmaps} total={}",
        controller + entries + bitmaps
    );
    Ok(())
}
