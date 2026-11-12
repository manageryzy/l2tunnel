use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::Notify;
struct Sender {
    entered: Arc<AtomicBool>,
    release: Arc<Notify>,
    fail: bool,
}
impl DatagramSend for Sender {
    const BOUNDARY: crate::datagram::SendBoundary =
        crate::datagram::SendBoundary::OsDatagramAccepted;
    async fn send(&mut self, bytes: &[u8]) -> io::Result<crate::datagram::DatagramSent> {
        self.entered.store(true, Ordering::SeqCst);
        self.release.notified().await;
        if self.fail {
            Err(io::Error::other("injected datagram send failure"))
        } else {
            Ok(crate::datagram::DatagramSent {
                actual_at: tokio::time::Instant::now(),
                payload_bytes: bytes.len(),
                boundary: crate::datagram::SendBoundary::OsDatagramAccepted,
            })
        }
    }
}
#[tokio::test]
async fn first_flight_timestamp_requires_actual_successful_datagram_handoff() -> io::Result<()> {
    for fail in [false, true] {
        let entered = Arc::new(AtomicBool::new(false));
        let release = Arc::new(Notify::new());
        let (tx, rx) = mpsc::channel(1);
        let (sent, mut events) = mpsc::channel(1);
        let (recycled, mut returned) = mpsc::channel(2);
        let task = tokio::spawn(write_datagrams(
            Sender {
                entered: entered.clone(),
                release: release.clone(),
                fail,
            },
            rx,
            0,
            sent,
            recycled,
        ));
        tx.send(owner::Outbound {
            bytes: vec![1, 2, 3],
            native_complete: Some(7),
        })
        .await
        .map_err(io::Error::other)?;
        tokio::time::timeout(Duration::from_secs(1), async {
            while !entered.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(io::Error::other)?;
        assert!(
            events.try_recv().is_err(),
            "queue handoff and pending send are not first-flight success"
        );
        assert!(
            returned.try_recv().is_err(),
            "pending send retains its buffer"
        );
        let released = Instant::now();
        release.notify_one();
        if fail {
            assert!(task.await.map_err(io::Error::other)?.is_err());
            assert!(events.try_recv().is_err());
            assert!(returned.try_recv().is_err());
        } else {
            let deadline = Instant::now() + Duration::from_secs(1);
            let (lane, ordinal, at) = tokio::time::timeout_at(deadline, events.recv())
                .await
                .map_err(io::Error::other)?
                .ok_or_else(|| invalid("completion event"))?;
            assert_eq!((lane, ordinal), (0, 7));
            assert!(at >= released && at <= Instant::now());
            assert_eq!(
                tokio::time::timeout_at(deadline, returned.recv())
                    .await
                    .map_err(io::Error::other)?,
                Some(vec![1, 2, 3])
            );
            task.abort();
            let _ = task.await;
        }
    }
    Ok(())
}

struct BlockedSender {
    entered: mpsc::Sender<(usize, Vec<u8>)>,
    release: Arc<Notify>,
}
impl DatagramSend for BlockedSender {
    const BOUNDARY: crate::datagram::SendBoundary =
        crate::datagram::SendBoundary::OsDatagramAccepted;
    async fn send(&mut self, bytes: &[u8]) -> io::Result<crate::datagram::DatagramSent> {
        let original = bytes.to_vec();
        self.entered
            .send((bytes.as_ptr() as usize, original.clone()))
            .await
            .map_err(io::Error::other)?;
        self.release.notified().await;
        assert_eq!(
            bytes, original,
            "writer-owned bytes changed while send was blocked"
        );
        Ok(crate::datagram::DatagramSent {
            actual_at: tokio::time::Instant::now(),
            payload_bytes: bytes.len(),
            boundary: crate::datagram::SendBoundary::OsDatagramAccepted,
        })
    }
}
#[tokio::test]
async fn two_preallocated_datagrams_are_owned_until_send_and_reused_without_third_buffer()
-> io::Result<()> {
    let runtime = RuntimeConfig {
        layer: PacketLayer::Ip,
        max_packet: 1600,
        compression: crate::Compression::None,
        queue_packets: 2,
        poll_interval: Duration::from_millis(1),
    };
    let transport = udp::Config::new(
        Duplex::Full,
        l2tunnel_datagram::CoverProfile::OpenVpnLike,
        l2tunnel_datagram::Protection::HmacSha256,
        576,
        false,
    )?;
    let policy = transport.policy()?;
    let config = Config::for_udp(
        runtime,
        transport,
        4,
        crate::rolling::config::test_delivery(runtime),
    )?;
    let (tx, rx) = mpsc::channel(1);
    let (feedback, _) = watch::channel(udp::Feedback::default());
    let mut state = State::new(
        LaneContext {
            session: [4; 16],
            index: 0,
            initiator: true,
        },
        runtime,
        policy,
        config,
        feedback,
        Some(tx.clone()),
    )?;
    assert_eq!(state.free_outbound.len(), 2);
    let length = state.free_outbound[0].len();
    assert_eq!(
        length,
        config
            .scheduler
            .recovery
            .width()
            .map_err(io::Error::other)?
            + protocol::wire::HEADER_BYTES
    );
    assert!(length <= policy.payload_bytes);
    let initial: Vec<_> = state
        .free_outbound
        .iter()
        .map(|b| (b.as_ptr() as usize, b.capacity()))
        .collect();
    assert_ne!(initial[0].0, initial[1].0);
    assert!(initial.iter().all(|(_, capacity)| *capacity >= length));
    let (entered_tx, mut entered) = mpsc::channel(1);
    let release = Arc::new(Notify::new());
    let (sent, mut events) = mpsc::channel(1);
    let task = tokio::spawn(write_datagrams(
        BlockedSender {
            entered: entered_tx,
            release: release.clone(),
        },
        rx,
        0,
        sent,
        state
            .recycle_outbound
            .take()
            .ok_or_else(|| invalid("recycle owner"))?,
    ));
    let deadline = Instant::now() + Duration::from_secs(2);
    for ordinal in 0..2_u64 {
        let mut bytes = state
            .free_outbound
            .pop()
            .ok_or_else(|| invalid("initial buffer"))?;
        bytes.fill(ordinal as u8);
        tokio::time::timeout_at(
            deadline,
            tx.send(owner::Outbound {
                bytes,
                native_complete: Some(ordinal + 1),
            }),
        )
        .await
        .map_err(io::Error::other)?
        .map_err(io::Error::other)?;
    }
    for ordinal in 0..6_u64 {
        let (pointer, bytes) = tokio::time::timeout_at(deadline, entered.recv())
            .await
            .map_err(io::Error::other)?
            .ok_or_else(|| invalid("send entry"))?;
        assert_eq!(bytes, vec![ordinal as u8; length]);
        assert!(initial.iter().any(|(p, _)| *p == pointer));
        state.reclaim_outbound()?;
        if ordinal < 4 {
            assert!(
                state.free_outbound.is_empty(),
                "both slots owned; no third buffer"
            );
        }
        assert!(events.try_recv().is_err(), "blocked send is not completed");
        release.notify_one();
        let (_, completed, _) = tokio::time::timeout_at(deadline, events.recv())
            .await
            .map_err(io::Error::other)?
            .ok_or_else(|| invalid("send completion"))?;
        assert_eq!(completed, ordinal + 1);
        state.reclaim_outbound()?;
        let returned = state
            .free_outbound
            .pop()
            .ok_or_else(|| invalid("returned buffer"))?;
        assert_eq!(returned.as_ptr() as usize, pointer);
        assert!(initial.contains(&(pointer, returned.capacity())));
        if ordinal < 4 {
            let mut bytes = returned;
            bytes.fill((ordinal + 2) as u8);
            tokio::time::timeout_at(
                deadline,
                tx.send(owner::Outbound {
                    bytes,
                    native_complete: Some(ordinal + 3),
                }),
            )
            .await
            .map_err(io::Error::other)?
            .map_err(io::Error::other)?;
        } else {
            state.free_outbound.push(returned);
        }
    }
    assert_eq!(state.free_outbound.len(), 2);
    task.abort();
    let _ = task.await;
    Ok(())
}
