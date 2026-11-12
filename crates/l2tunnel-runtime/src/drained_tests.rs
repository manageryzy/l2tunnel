use super::*;
use l2tunnel_auth::{
    ClientTls, MemberAllowlist, MemberKey, ServerTls, client_connect, server_accept,
};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

type Failure = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), Failure>;
fn config(duplex: Duplex) -> Config {
    Config {
        runtime: RuntimeConfig {
            layer: PacketLayer::Ip,
            max_packet: 1600,
            compression: Compression::None,
            queue_packets: 2,
            poll_interval: Duration::from_millis(1),
        },
        duplex,
        drain_timeout: Duration::from_millis(300),
        carrier_context: ConfigDigest([17; 32]),
    }
}
async fn links(config: Config) -> Result<(Link, Link), Failure> {
    let cert = rcgen::generate_simple_self_signed(vec!["drain.test".to_owned()])?;
    let chain = vec![cert.cert.der().to_vec()];
    let client_tls = ClientTls::from_der_roots(&chain)?;
    let server_tls = ServerTls::from_der(&chain, &cert.signing_key.serialize_der())?;
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let allowlist = MemberAllowlist::new(&[member.public_key()])?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let mut lanes = Vec::new();
    for _ in 0..if config.duplex == Duplex::Half { 2 } else { 1 } {
        let client = TcpStream::connect(listener.local_addr()?).await?;
        client.set_nodelay(true)?;
        let (server, _) = listener.accept().await?;
        server.set_nodelay(true)?;
        let pair = tokio::try_join!(
            client_connect(
                client,
                &client_tls,
                "drain.test",
                &member,
                session_config(config)?,
                Duration::from_secs(3)
            ),
            server_accept(
                server,
                &server_tls,
                &allowlist,
                session_config(config)?,
                Duration::from_secs(3)
            ),
        )?;
        lanes.push(pair);
    }
    let (client, server) = lanes.remove(0);
    if config.duplex == Duplex::Half {
        let (client2, server2) = lanes.remove(0);
        Ok(tokio::try_join!(
            client_pair(client, client2),
            server_pair(server, server2)
        )?)
    } else {
        Ok((Link::full(client), Link::full(server)))
    }
}
#[derive(Default)]
struct Native {
    outgoing: VecDeque<Vec<u8>>,
    received: Vec<Vec<u8>>,
    blocked: bool,
    reads: usize,
    minimum_buffer: Option<usize>,
}
#[derive(Clone, Default)]
struct Device(Arc<Mutex<Native>>);
impl Device {
    fn change<T>(&self, f: impl FnOnce(&mut Native) -> T) -> io::Result<T> {
        let mut state = self.0.lock().map_err(|_| invalid("poisoned test device"))?;
        Ok(f(&mut state))
    }
}
impl PacketDevice for Device {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ip
    }
    fn receive(&mut self, output: &mut [u8]) -> io::Result<Option<usize>> {
        if output.len() < l2tunnel_device::READ_BUFFER_BYTES {
            return Err(invalid("native sentinel buffer required"));
        }
        self.change(|state| {
            state.reads += 1;
            state.minimum_buffer = Some(
                state
                    .minimum_buffer
                    .map_or(output.len(), |old| old.min(output.len())),
            );
            if let Some(packet) = state.outgoing.pop_front() {
                let n = packet.len().min(output.len());
                output[..n].copy_from_slice(&packet[..n]);
                Ok(Some(n))
            } else {
                Err(io::ErrorKind::WouldBlock.into())
            }
        })?
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<()> {
        self.change(|state| {
            if state.blocked {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            state.received.push(packet.to_vec());
            Ok(())
        })?
    }
}
fn packet(value: u8) -> Vec<u8> {
    let mut bytes = vec![value; 400];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&400_u16.to_be_bytes());
    bytes
}
async fn delivered(device: &Device, count: usize) -> TestResult {
    timeout(Duration::from_secs(3), async {
        while device.change(|state| state.received.len())? < count {
            sleep(Duration::from_millis(1)).await;
        }
        Ok::<_, io::Error>(())
    })
    .await??;
    Ok(())
}
fn exact(report: DrainReport, local: u64, remote: u64, duplex: Duplex) {
    assert_eq!(report.local_admitted, local);
    assert_eq!(report.local_handed, local);
    assert_eq!(report.local_flushed, local);
    assert_eq!(report.local_barrier, local);
    assert_eq!(report.peer_ack, local);
    assert_eq!(report.peer_barrier, remote);
    assert_eq!(report.native_confirmed, remote);
    assert_eq!(report.local_ack, remote);
    assert_eq!(
        report.tls_lanes_closed,
        if duplex == Duplex::Half { 2 } else { 1 }
    );
}
#[tokio::test]
async fn authenticated_full_and_paired_simultaneous_stop_exact_native_fences() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        for compression in [Compression::None, Compression::Lz4IfSmaller] {
            let mut cfg = config(duplex);
            cfg.runtime.compression = compression;
            let (a, b) = links(cfg).await?;
            let ad = Device::default();
            let bd = Device::default();
            ad.change(|state| state.outgoing.extend([packet(1), packet(2), packet(3)]))?;
            bd.change(|state| state.outgoing.extend([packet(4), packet(5)]))?;
            let (asend, astop) = oneshot::channel();
            let (bsend, bstop) = oneshot::channel();
            let arun = tokio::spawn(run(ad.clone(), a, cfg, astop));
            let brun = tokio::spawn(run(bd.clone(), b, cfg, bstop));
            delivered(&ad, 2).await?;
            delivered(&bd, 3).await?;
            asend.send(()).map_err(|_| "stop A")?;
            bsend.send(()).map_err(|_| "stop B")?;
            exact(timeout(Duration::from_secs(2), arun).await???, 3, 2, duplex);
            exact(timeout(Duration::from_secs(2), brun).await???, 2, 3, duplex);
            assert_eq!(ad.change(|s| s.received.clone())?, [packet(4), packet(5)]);
            assert_eq!(
                bd.change(|s| s.received.clone())?,
                [packet(1), packet(2), packet(3)]
            );
            assert_eq!(
                ad.change(|s| s.minimum_buffer)?,
                Some(l2tunnel_device::READ_BUFFER_BYTES)
            );
        }
    }
    Ok(())
}
#[tokio::test]
async fn one_peer_request_stops_both_without_second_local_request() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        let cfg = config(duplex);
        let (a, b) = links(cfg).await?;
        let (asend, astop) = oneshot::channel();
        let (_bsend, bstop) = oneshot::channel();
        let arun = tokio::spawn(run(Device::default(), a, cfg, astop));
        let brun = tokio::spawn(run(Device::default(), b, cfg, bstop));
        asend.send(()).map_err(|_| "stop A")?;
        exact(timeout(Duration::from_secs(2), arun).await???, 0, 0, duplex);
        exact(timeout(Duration::from_secs(2), brun).await???, 0, 0, duplex);
    }
    Ok(())
}
#[tokio::test]
async fn unread_native_output_blocks_ack_until_real_write_and_freezes_admission() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        let cfg = config(duplex);
        let (a, b) = links(cfg).await?;
        let ad = Device::default();
        let bd = Device::default();
        ad.change(|s| s.outgoing.push_back(packet(9)))?;
        bd.change(|s| s.blocked = true)?;
        let (asend, astop) = oneshot::channel();
        let (bsend, bstop) = oneshot::channel();
        let arun = tokio::spawn(run(ad.clone(), a, cfg, astop));
        let brun = tokio::spawn(run(bd.clone(), b, cfg, bstop));
        timeout(Duration::from_secs(2), async {
            while !ad.change(|s| s.outgoing.is_empty())? {
                sleep(Duration::from_millis(1)).await;
            }
            Ok::<_, io::Error>(())
        })
        .await??;
        asend.send(()).map_err(|_| "stop A")?;
        bsend.send(()).map_err(|_| "stop B")?;
        sleep(Duration::from_millis(30)).await;
        assert!(!arun.is_finished());
        assert!(!brun.is_finished());
        assert!(bd.change(|s| s.received.is_empty())?);
        ad.change(|s| s.outgoing.push_back(packet(10)))?;
        bd.change(|s| s.blocked = false)?;
        exact(timeout(Duration::from_secs(2), arun).await???, 1, 0, duplex);
        exact(timeout(Duration::from_secs(2), brun).await???, 0, 1, duplex);
        assert_eq!(ad.change(|s| s.outgoing.len())?, 1);
        assert_eq!(bd.change(|s| s.received.clone())?, [packet(9)]);
    }
    Ok(())
}
#[tokio::test]
async fn permanently_blocked_native_and_writer_never_report_clean() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        let mut cfg = config(duplex);
        cfg.drain_timeout = Duration::from_millis(50);
        let (a, b) = links(cfg).await?;
        let ad = Device::default();
        let bd = Device::default();
        ad.change(|s| s.outgoing.push_back(packet(1)))?;
        bd.change(|s| s.blocked = true)?;
        let (asend, astop) = oneshot::channel();
        let (bsend, bstop) = oneshot::channel();
        let arun = tokio::spawn(run(ad.clone(), a, cfg, astop));
        let brun = tokio::spawn(run(bd, b, cfg, bstop));
        timeout(Duration::from_secs(2), async {
            while !ad.change(|s| s.outgoing.is_empty())? {
                sleep(Duration::from_millis(1)).await;
            }
            Ok::<_, io::Error>(())
        })
        .await??;
        asend.send(()).map_err(|_| "stop A")?;
        bsend.send(()).map_err(|_| "stop B")?;
        assert!(timeout(Duration::from_secs(2), arun).await??.is_err());
        assert!(timeout(Duration::from_secs(2), brun).await??.is_err());
        let (mut a, b) = links(cfg).await?;
        a.writer = Box::pin(BlockedWriter);
        let (asend, astop) = oneshot::channel();
        let (_bsend, bstop) = oneshot::channel();
        let arun = tokio::spawn(run(Device::default(), a, cfg, astop));
        let brun = tokio::spawn(run(Device::default(), b, cfg, bstop));
        asend.send(()).map_err(|_| "stop A")?;
        assert_eq!(
            timeout(Duration::from_secs(2), arun)
                .await??
                .err()
                .ok_or("blocked writer succeeded")?
                .kind(),
            io::ErrorKind::TimedOut
        );
        brun.abort();
        let _ = brun.await;
    }
    Ok(())
}
struct BlockedWriter;
impl AsyncWrite for BlockedWriter {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Pending
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}
async fn send_record(link: &mut Link, sequence: u64, kind: Kind, body: &[u8]) -> io::Result<()> {
    let bytes = wire::encode(
        Header {
            kind,
            epoch: Epoch(1),
            packet_number: sequence,
            session: link.send_session,
            lane: 0,
        },
        body,
    )
    .map_err(wire_error)?;
    link.writer
        .write_u32(u32::try_from(bytes.len()).map_err(io::Error::other)?)
        .await?;
    link.writer.write_all(&bytes).await?;
    link.writer.flush().await
}
#[tokio::test]
async fn authenticated_mismatched_barrier_ack_replay_and_early_reverse_eof_fail() -> TestResult {
    for attack in 0..5 {
        let cfg = config(if attack == 4 {
            Duplex::Half
        } else {
            Duplex::Full
        });
        let (a, mut b) = links(cfg).await?;
        let (_asend, astop) = oneshot::channel();
        let arun = tokio::spawn(run(Device::default(), a, cfg, astop));
        match attack {
            0 => send_record(&mut b, 0, Kind::Control, &control(1, 1)).await?,
            1 => {
                send_record(&mut b, 0, Kind::Control, &control(1, 0)).await?;
                send_record(&mut b, 1, Kind::Control, &control(2, 1)).await?;
            }
            2 => {
                send_record(&mut b, 0, Kind::Control, &control(1, 0)).await?;
                send_record(&mut b, 0, Kind::Control, &control(2, 0)).await?;
            }
            3 => {
                b.writer.shutdown().await?;
            }
            _ => {
                b.reverse_writer
                    .as_mut()
                    .ok_or("missing reverse writer")?
                    .shutdown()
                    .await?;
            }
        }
        assert!(timeout(Duration::from_secs(2), arun).await??.is_err());
    }
    Ok(())
}
#[tokio::test]
async fn strict_parser_rejects_reserved_truncation_data_after_barrier_and_wrong_context()
-> TestResult {
    let cfg = config(Duplex::Full).runtime;
    for attack in 0..7 {
        let (mut sending, receiving) = tokio::io::duplex(8192);
        let (events, _input) = mpsc::channel(8);
        let (remote, _arrival) = watch::channel(None);
        let task = tokio::spawn(reader(receiving, [3; 16], cfg, events, remote));
        let mut body = control(1, 0).to_vec();
        let mut session = [3; 16];
        let mut number = 0;
        match attack {
            0 => body[9] = 1,
            1 => body.truncate(23),
            2 => session = [4; 16],
            3 => number = 1,
            _ => {}
        }
        if attack == 4 {
            sending.write_all(&[0, 0]).await?;
        } else {
            let bytes = wire::encode(
                Header {
                    kind: Kind::Control,
                    epoch: Epoch(1),
                    packet_number: number,
                    session,
                    lane: 0,
                },
                &body,
            )
            .map_err(wire_error)?;
            sending
                .write_u32(u32::try_from(bytes.len()).map_err(io::Error::other)?)
                .await?;
            sending.write_all(&bytes).await?;
            if attack == 5 {
                let data = cfg.codec()?.encode_vec(&packet(1))?;
                let bytes = wire::encode(
                    Header {
                        kind: Kind::Data,
                        epoch: Epoch(1),
                        packet_number: 1,
                        session,
                        lane: 0,
                    },
                    &data,
                )
                .map_err(wire_error)?;
                sending
                    .write_u32(u32::try_from(bytes.len()).map_err(io::Error::other)?)
                    .await?;
                sending.write_all(&bytes).await?;
            }
        }
        sending.shutdown().await?;
        assert!(timeout(Duration::from_secs(2), task).await??.is_err());
    }
    Ok(())
}
#[tokio::test]
async fn negotiated_settings_mismatch_and_cancel_reject_before_native_reads() -> TestResult {
    let cfg = config(Duplex::Full);
    let (a, _b) = links(cfg).await?;
    let mut changed = cfg;
    changed.drain_timeout += Duration::from_millis(1);
    assert_ne!(session_config(cfg)?, session_config(changed)?);
    let device = Device::default();
    let (_send, stop) = oneshot::channel();
    assert!(run(device.clone(), a, changed, stop).await.is_err());
    assert_eq!(device.change(|s| s.reads)?, 0);
    let (a, _b) = links(cfg).await?;
    let (send, stop) = oneshot::channel();
    drop(send);
    assert!(
        timeout(Duration::from_secs(2), run(Device::default(), a, cfg, stop))
            .await?
            .is_err()
    );
    for bound in [Duration::ZERO, Duration::from_secs(121)] {
        let mut changed = cfg;
        changed.drain_timeout = bound;
        assert!(session_config(changed).is_err());
    }
    Ok(())
}

struct BlockedShutdown(Pin<Box<dyn AsyncWrite + Send>>);
impl AsyncWrite for BlockedShutdown {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0.as_mut().poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.as_mut().poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}
#[tokio::test]
async fn matching_fences_cannot_bypass_blocked_shutdown_or_missing_peer_ack() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        let mut cfg = config(duplex);
        cfg.drain_timeout = Duration::from_millis(50);
        let (mut a, b) = links(cfg).await?;
        a.writer = Box::pin(BlockedShutdown(a.writer));
        let (asend, astop) = oneshot::channel();
        let (_bsend, bstop) = oneshot::channel();
        let arun = tokio::spawn(run(Device::default(), a, cfg, astop));
        let brun = tokio::spawn(run(Device::default(), b, cfg, bstop));
        asend.send(()).map_err(|_| "stop A")?;
        assert!(timeout(Duration::from_secs(2), arun).await??.is_err());
        assert!(timeout(Duration::from_secs(2), brun).await??.is_err());
        let (a, mut b) = links(cfg).await?;
        let (_asend, astop) = oneshot::channel();
        let arun = tokio::spawn(run(Device::default(), a, cfg, astop));
        send_record(&mut b, 0, Kind::Control, &control(1, 0)).await?;
        let error = timeout(Duration::from_secs(2), arun)
            .await??
            .err()
            .ok_or("missing peer ACK succeeded")?;
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
    Ok(())
}

#[tokio::test]
async fn peer_only_barrier_deadline_is_not_hidden_behind_blocked_native_output() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        let mut cfg = config(duplex);
        cfg.drain_timeout = Duration::from_millis(50);
        let (a, mut b) = links(cfg).await?;
        let native = Device::default();
        native.change(|s| s.blocked = true)?;
        let (_asend, astop) = oneshot::channel();
        let arun = tokio::spawn(run(native.clone(), a, cfg, astop));
        let encoded = cfg.runtime.codec()?.encode_vec(&packet(8))?;
        send_record(&mut b, 0, Kind::Data, &encoded).await?;
        send_record(&mut b, 1, Kind::Control, &control(1, 1)).await?;
        let error = timeout(Duration::from_secs(2), arun)
            .await??
            .err()
            .ok_or("blocked remote-only drain succeeded")?;
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(native.change(|s| s.received.is_empty())?);
    }
    Ok(())
}
