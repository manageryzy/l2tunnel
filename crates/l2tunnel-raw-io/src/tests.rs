use super::*;
use std::net::{Ipv4Addr, SocketAddrV4};
use tokio::sync::mpsc;

struct MemoryIo {
    incoming: mpsc::Receiver<Vec<u8>>,
    outgoing: mpsc::Sender<Vec<u8>>,
    calls: usize,
    lossy: bool,
}
impl PacketIo for MemoryIo {
    fn receive(&mut self, output: &mut [u8]) -> io::Result<Option<usize>> {
        match self.incoming.try_recv() {
            Ok(bytes) => {
                output[..bytes.len()].copy_from_slice(&bytes);
                Ok(Some(bytes.len()))
            }
            Err(_) => Ok(None),
        }
    }
    fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        self.calls += 1;
        // Exercise retaining the exact popped packet through repeated WouldBlock.
        if self.calls.is_multiple_of(5) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if self.lossy && self.calls.is_multiple_of(7) {
            return Ok(());
        }
        self.outgoing
            .try_send(packet.to_vec())
            .map_err(|_| io::ErrorKind::WouldBlock.into())
    }
}
fn config(client: bool) -> Config {
    let local = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 40001);
    let peer = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 2), 40002);
    Config {
        local: if client { local } else { peer },
        peer: if client { peer } else { local },
        mtu: 1200,
        send_bytes: 4096,
        receive_bytes: 4096,
        packet_slots: 4,
        random_seed: if client { 101 } else { 202 },
        ack_delay_millis: 20,
        keepalive_millis: 1000,
        idle_timeout_millis: 30_000,
    }
}
fn pair(
    lossy: bool,
) -> io::Result<(
    DuplexStream,
    Driver<MemoryIo>,
    DuplexStream,
    Driver<MemoryIo>,
)> {
    let (a_tx, b_rx) = mpsc::channel(4);
    let (b_tx, a_rx) = mpsc::channel(4);
    // Actual malformed input must be rejected, without taking the stream down.
    a_tx.try_send(vec![0; 12]).map_err(io::Error::other)?;
    let (a, ad) = bridge(
        config(true),
        Role::Client,
        MemoryIo {
            incoming: a_rx,
            outgoing: a_tx,
            calls: 0,
            lossy,
        },
    )?;
    let (b, bd) = bridge(
        config(false),
        Role::Server,
        MemoryIo {
            incoming: b_rx,
            outgoing: b_tx,
            calls: 0,
            lossy,
        },
    )?;
    Ok((a, ad, b, bd))
}

#[tokio::test(start_paused = true)]
async fn independent_bridges_preserve_bytes_through_loss_and_wouldblock() -> io::Result<()> {
    for lossy in [false, true] {
        let (mut a, ad, mut b, bd) = pair(lossy)?;
        let a_driver = tokio::spawn(ad.run());
        let b_driver = tokio::spawn(bd.run());
        let payload: Vec<u8> = (0..32_768).map(|n| (n % 251) as u8).collect();
        let expected = payload.clone();
        let server = tokio::spawn(async move {
            let mut bytes = vec![0; expected.len()];
            b.read_exact(&mut bytes).await?;
            assert_eq!(bytes, expected);
            b.write_all(&bytes).await?;
            b.shutdown().await?;
            let mut tail = Vec::new();
            b.read_to_end(&mut tail).await?;
            assert!(tail.is_empty());
            io::Result::Ok(())
        });
        tokio::time::timeout(Duration::from_secs(120), async {
            a.write_all(&payload).await?;
            a.shutdown().await?;
            let mut received = Vec::new();
            a.read_to_end(&mut received).await?;
            assert_eq!(received, payload);
            server.await.map_err(io::Error::other)??;
            let ac = a_driver.await.map_err(io::Error::other)??;
            let bc = b_driver.await.map_err(io::Error::other)??;
            assert_eq!(ac.sent_bytes, payload.len() as u64);
            assert_eq!(bc.received_bytes, payload.len() as u64);
            assert!(bc.discarded_packets >= 1);
            Ok::<_, io::Error>(())
        })
        .await
        .map_err(io::Error::other)??;
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_blocked_reader_backpressures_and_driver_cancellation_closes_bridge() -> io::Result<()> {
    let (mut a, ad, mut b, bd) = pair(false)?;
    let a_driver = tokio::spawn(ad.run());
    let b_driver = tokio::spawn(bd.run());
    let payload = vec![7; 1_048_576];
    let pending = a.write_all(&payload);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), pending)
            .await
            .is_err()
    );
    b_driver.abort();
    assert!(b_driver.await.is_err());
    let mut bytes = [0; 1200];
    // The finite bridge can still contain previously delivered bytes before EOF.
    loop {
        if b.read(&mut bytes).await? == 0 {
            break;
        }
    }
    a_driver.abort();
    assert!(a_driver.await.is_err());
    assert!(a.write_all(&[1]).await.is_err());
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn absent_peer_has_finite_handshake_deadline() -> io::Result<()> {
    let (mut a, ad, _b, bd) = pair(false)?;
    drop(bd);
    let task = tokio::spawn(ad.run());
    tokio::time::advance(Duration::from_secs(31)).await;
    let error = tokio::time::timeout(Duration::from_secs(31), task)
        .await
        .map_err(io::Error::other)?
        .map_err(io::Error::other)?
        .err()
        .ok_or_else(|| io::Error::other("missing deadline error"))?;
    assert!(matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::ConnectionAborted
    ));
    assert_eq!(a.read(&mut [0]).await?, 0);
    Ok(())
}

struct FinalAckGate {
    inner: MemoryIo,
    allow: std::sync::Arc<std::sync::atomic::AtomicBool>,
    blocked: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    peer_fin: bool,
    retained: Option<Vec<u8>>,
}
impl PacketIo for FinalAckGate {
    fn receive(&mut self, output: &mut [u8]) -> io::Result<Option<usize>> {
        let size = self.inner.receive(output)?;
        if self.peer_fin {
            // Deterministic loss of later FIN retries lets the local maintained
            // TimeWait expire while the exact original ACK is still unsent.
            return Ok(None);
        }
        if size.is_some_and(|size| size > 33 && output[33] & 1 != 0) {
            self.peer_fin = true;
        }
        Ok(size)
    }
    fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        if self.peer_fin && !self.allow.load(std::sync::atomic::Ordering::SeqCst) {
            if let Some(retained) = &self.retained {
                assert_eq!(retained, packet);
            } else {
                self.retained = Some(packet.to_vec());
            }
            self.blocked
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.inner.send(packet)
    }
}

#[tokio::test(start_paused = true)]
async fn final_ack_remains_owned_after_timewait_until_send_or_finite_drain_deadline()
-> io::Result<()> {
    for release in [true, false] {
        let (mut a, ad, mut b, bd) = pair(false)?;
        let allow = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let blocked = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let gated = Driver {
            io: FinalAckGate {
                inner: ad.io,
                allow: allow.clone(),
                blocked: blocked.clone(),
                peer_fin: false,
                retained: None,
            },
            engine: ad.engine,
            bridge: ad.bridge,
            chunk_bytes: ad.chunk_bytes,
            drain_timeout_millis: ad.drain_timeout_millis,
            counters: ad.counters,
            handshake_timeout: ad.handshake_timeout,
        };
        let a_driver = tokio::spawn(gated.run());
        let b_driver = tokio::spawn(bd.run());
        a.shutdown().await?;
        assert_eq!(b.read(&mut [0]).await?, 0);
        b.shutdown().await?;
        assert_eq!(a.read(&mut [0]).await?, 0);
        tokio::time::advance(Duration::from_secs(11)).await;
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert!(blocked.load(std::sync::atomic::Ordering::SeqCst) > 1);
        assert!(
            !a_driver.is_finished(),
            "clean TCP closure cannot discard a blocked final ACK"
        );
        if release {
            allow.store(true, std::sync::atomic::Ordering::SeqCst);
            tokio::time::timeout(Duration::from_secs(20), a_driver)
                .await
                .map_err(io::Error::other)?
                .map_err(io::Error::other)??;
            tokio::time::timeout(Duration::from_secs(20), b_driver)
                .await
                .map_err(io::Error::other)?
                .map_err(io::Error::other)??;
        } else {
            let error = tokio::time::timeout(Duration::from_secs(45), a_driver)
                .await
                .map_err(io::Error::other)?
                .map_err(io::Error::other)?
                .err()
                .ok_or_else(|| io::Error::other("missing final-drain timeout"))?;
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            let _ = b_driver.await;
        }
    }
    Ok(())
}
