use super::*;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

fn config() -> RuntimeConfig {
    RuntimeConfig {
        layer: PacketLayer::Ethernet,
        max_packet: 1600,
        compression: Compression::Lz4IfSmaller,
        queue_packets: 2,
        poll_interval: Duration::from_millis(1),
    }
}
fn data(number: u64, session: [u8; 16], payload: &[u8]) -> io::Result<Vec<u8>> {
    let payload = config()
        .codec()?
        .encode_vec(payload)
        .map_err(io::Error::other)?;
    wire::encode(
        Header {
            kind: Kind::Data,
            epoch: Epoch(1),
            packet_number: number,
            session,
            lane: 0,
        },
        &payload,
    )
    .map_err(wire_error)
}
#[tokio::test]
async fn fragmented_stream_is_retained_and_next_record_is_checked() -> io::Result<()> {
    let (mut write, read) = tokio::io::duplex(32);
    let (tx, mut rx) = mpsc::channel(1);
    let task = tokio::spawn(read_packets(read, [7; 16], config(), tx));
    let packet = vec![8; 100];
    let record = data(0, [7; 16], &packet)?;
    write.write_u32(record.len() as u32).await?;
    for chunk in record.chunks(3) {
        write.write_all(chunk).await?;
        tokio::task::yield_now().await;
    }
    assert_eq!(rx.recv().await, Some(packet));
    let replay = data(0, [7; 16], &[9; 14])?;
    write.write_u32(replay.len() as u32).await?;
    write.write_all(&replay).await?;
    let result = task.await.map_err(io::Error::other)?;
    assert_eq!(
        result.err().map(|e| e.kind()),
        Some(io::ErrorKind::InvalidData)
    );
    Ok(())
}
#[tokio::test]
async fn oversized_prefix_and_wrong_session_fail_before_delivery() -> io::Result<()> {
    for wrong_session in [false, true] {
        let (mut write, read) = tokio::io::duplex(256);
        let (tx, mut rx) = mpsc::channel(1);
        let task = tokio::spawn(read_packets(read, [7; 16], config(), tx));
        if wrong_session {
            let record = data(0, [8; 16], &[0; 14])?;
            write.write_u32(record.len() as u32).await?;
            write.write_all(&record).await?;
        } else {
            write.write_u32(u32::MAX).await?;
        }
        assert!(task.await.map_err(io::Error::other)?.is_err());
        assert!(rx.recv().await.is_none());
    }
    Ok(())
}
struct Device {
    outgoing: VecDeque<Vec<u8>>,
    delivered: Arc<Mutex<Vec<Vec<u8>>>>,
    blocked_once: bool,
}
impl PacketDevice for Device {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ethernet
    }
    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
        Ok(self.outgoing.pop_front().map(|p| {
            buffer[..p.len()].copy_from_slice(&p);
            p.len()
        }))
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<()> {
        if self.blocked_once {
            self.blocked_once = false;
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.delivered
            .lock()
            .map_err(|_| io::Error::other("poisoned test device"))?
            .push(packet.to_vec());
        Ok(())
    }
}
#[tokio::test]
async fn native_packets_roundtrip_and_wouldblock_keeps_packet() -> io::Result<()> {
    let (peer, local) = tokio::io::duplex(32);
    let (read, write) = tokio::io::split(local);
    let link = Link {
        managed_metadata: None,
        reader: Box::pin(read),
        writer: Box::pin(write),
        reverse_reader: None,
        reverse_writer: None,
        receive_session: [2; 16],
        send_session: [2; 16],
        layer: PacketLayer::Ethernet,
    };
    let delivered = Arc::new(Mutex::new(Vec::new()));
    let device = Device {
        outgoing: VecDeque::from([vec![4; 40], vec![5; 80]]),
        delivered: delivered.clone(),
        blocked_once: true,
    };
    let runtime = tokio::spawn(run(device, link, config()));
    let (peer_read, peer_write) = tokio::io::split(peer);
    let (tx, rx) = mpsc::channel(2);
    tx.send(vec![1; 24]).await.map_err(io::Error::other)?;
    tx.send(vec![3; 30]).await.map_err(io::Error::other)?;
    let writer = tokio::spawn(write_packets(peer_write, [2; 16], rx, config()));
    let (packet_tx, mut packet_rx) = mpsc::channel(2);
    let reader = tokio::spawn(read_packets(peer_read, [2; 16], config(), packet_tx));
    let result = tokio::time::timeout(Duration::from_secs(2), async {
        assert_eq!(packet_rx.recv().await, Some(vec![4; 40]));
        assert_eq!(packet_rx.recv().await, Some(vec![5; 80]));
        loop {
            if delivered
                .lock()
                .map_err(|_| io::Error::other("poisoned"))?
                .len()
                == 2
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(
            *delivered.lock().map_err(|_| io::Error::other("poisoned"))?,
            vec![vec![1; 24], vec![3; 30]]
        );
        Ok::<(), io::Error>(())
    })
    .await
    .map_err(io::Error::other)?;
    runtime.abort();
    writer.abort();
    reader.abort();
    result
}
#[test]
fn configuration_and_ip_shape_are_checked() {
    assert!(
        RuntimeConfig {
            queue_packets: 0,
            ..config()
        }
        .validate()
        .is_err()
    );
    assert!(
        RuntimeConfig {
            poll_interval: Duration::ZERO,
            ..config()
        }
        .validate()
        .is_err()
    );
    let mut ipv4 = vec![0; 20];
    ipv4[0] = 0x45;
    ipv4[3] = 20;
    assert!(packet_valid(PacketLayer::Ip, &ipv4));
    ipv4[0] = 0x4f;
    assert!(!packet_valid(PacketLayer::Ip, &ipv4));
    let mut ipv6 = vec![0; 40];
    ipv6[0] = 0x60;
    assert!(packet_valid(PacketLayer::Ip, &ipv6));
    ipv6[5] = 1;
    assert!(!packet_valid(PacketLayer::Ip, &ipv6));
}
