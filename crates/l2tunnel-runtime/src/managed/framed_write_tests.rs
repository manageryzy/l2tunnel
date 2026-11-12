//! Byte-identical contiguous framing and authoritative full-flush progress.
use super::*;
use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
#[derive(Default)]
struct State {
    bytes: Vec<u8>,
    maximum: usize,
    fail_after: Option<usize>,
    fail_flush: bool,
    flushes: usize,
}
#[derive(Clone, Default)]
struct Writer(Arc<Mutex<State>>);
impl AsyncWrite for Writer {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut state = self.0.lock().map_err(|_| invalid("writer fixture lock"))?;
        let remaining = state
            .fail_after
            .map_or(usize::MAX, |limit| limit.saturating_sub(state.bytes.len()));
        if remaining == 0 {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let maximum = if state.maximum == 0 {
            usize::MAX
        } else {
            state.maximum
        };
        let size = bytes.len().min(maximum).min(remaining);
        state.bytes.extend_from_slice(&bytes[..size]);
        Poll::Ready(Ok(size))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.0.lock().map_err(|_| invalid("writer fixture lock"))?;
        state.flushes += 1;
        Poll::Ready(if state.fail_flush {
            Err(io::ErrorKind::BrokenPipe.into())
        } else {
            Ok(())
        })
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
#[tokio::test]
async fn contiguous_framing_preserves_reference_bytes_under_short_writes_and_wire_maximum()
-> TestResult {
    let mut writer = Writer::default();
    writer.0.lock().map_err(|_| invalid("lock"))?.maximum = 7;
    let (handle, sink) = profiling_channel(Duration::from_millis(100))?;
    let mut number = 0;
    let mut reference = Vec::new();
    for (kind, size) in [
        (Kind::Data, 1616),
        (Kind::Feedback, 8),
        (Kind::Control, 4096),
        (Kind::Data, wire::MAX_PAYLOAD),
    ] {
        let payload = vec![0xa5; size];
        let body = wire::encode(
            Header {
                kind,
                epoch: Epoch(1),
                packet_number: number,
                session: [7; 16],
                lane: 0,
            },
            &payload,
        )
        .map_err(wire_error)?;
        reference.extend_from_slice(&u32::try_from(body.len())?.to_be_bytes());
        reference.extend_from_slice(&body);
        write_record(
            &mut writer,
            [7; 16],
            &mut number,
            kind,
            Epoch(1),
            &payload,
            Some(&sink),
        )
        .await?;
    }
    assert_eq!(
        writer.0.lock().map_err(|_| invalid("lock"))?.bytes,
        reference
    );
    assert_eq!(writer.0.lock().map_err(|_| invalid("lock"))?.flushes, 4);
    sink.publish(true);
    let profile = handle.status().ok_or("profile")?;
    assert_eq!(profile.counters["records_flushed"], 4);
    assert_eq!(
        profile.counters["plaintext_record_bytes_flushed"],
        reference.len() as u64
    );
    assert_eq!(profile.timings["transport_framed_write"].count, 4);
    assert_eq!(
        profile.timings["transport_prefix_write"],
        ProfileTiming::default()
    );
    assert_eq!(
        profile.timings["transport_body_write"],
        ProfileTiming::default()
    );
    Ok(())
}
#[tokio::test]
async fn partial_write_or_flush_failure_cannot_publish_any_kind_of_completion_or_credit()
-> TestResult {
    for kind in [Kind::Data, Kind::Feedback, Kind::Control] {
        for fail_after in [Some(3), Some(11), None] {
            let writer = Writer::default();
            {
                let mut state = writer.0.lock().map_err(|_| invalid("lock"))?;
                state.maximum = 7;
                state.fail_after = fail_after;
                state.fail_flush = fail_after.is_none();
            }
            let (data_tx, data) = mpsc::channel(1);
            let (control_tx, control) = mpsc::channel(1);
            let (credit_tx, credit) = watch::channel(0);
            match kind {
                Kind::Data => {
                    data_tx
                        .send(OutData {
                            epoch: Epoch(1),
                            payload: vec![4; 32],
                            admitted: 1,
                        })
                        .await?;
                }
                Kind::Control => {
                    control_tx
                        .send(OutControl {
                            sequence: 1,
                            bytes: vec![4; 32],
                        })
                        .await?;
                }
                Kind::Feedback => {
                    credit_tx.send_replace(1);
                }
                Kind::Repair => return Err("unsupported test kind".into()),
            }
            let (control_progress, control_observed) = watch::channel(0);
            let (credit_progress, credit_observed) = watch::channel(0);
            let (data_progress, data_observed) = watch::channel(0);
            let (events, mut event_observed) = mpsc::channel(1);
            let (profile, sink) = profiling_channel(Duration::from_millis(100))?;
            let failure = tokio::time::timeout(
                Duration::from_secs(1),
                write_records(
                    writer.clone(),
                    [7; 16],
                    data,
                    control,
                    credit,
                    WriterProgress {
                        control: control_progress,
                        credit: credit_progress,
                        data: data_progress,
                        delivery: Some(events),
                    },
                    Some(sink.clone()),
                ),
            )
            .await?
            .err()
            .ok_or("failed original write must terminate")?;
            assert_eq!(failure.kind(), io::ErrorKind::BrokenPipe);
            assert_eq!(
                (
                    *control_observed.borrow(),
                    *credit_observed.borrow(),
                    *data_observed.borrow()
                ),
                (0, 0, 0)
            );
            assert!(event_observed.try_recv().is_err());
            sink.publish(true);
            assert_eq!(
                profile.status().ok_or("profile")?.counters["records_flushed"],
                0
            );
            assert_eq!(
                writer.0.lock().map_err(|_| invalid("lock"))?.flushes,
                usize::from(fail_after.is_none())
            );
        }
    }
    Ok(())
}

struct CapturedTcp {
    stream: tokio::net::TcpStream,
    captured: Arc<Mutex<Vec<u8>>>,
}
impl AsyncRead for CapturedTcp {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buffer)
    }
}
impl AsyncWrite for CapturedTcp {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.stream).poll_write(cx, bytes) {
            Poll::Ready(Ok(size)) => {
                let mut captured = self
                    .captured
                    .lock()
                    .map_err(|_| invalid("TLS fixture lock"))?;
                if captured.len().checked_add(size).is_none_or(|n| n > 65_536) {
                    return Poll::Ready(Err(invalid("bounded TLS fixture exhausted")));
                }
                captured.extend_from_slice(&bytes[..size]);
                Poll::Ready(Ok(size))
            }
            other => other,
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
fn application_tls_records(bytes: &[u8]) -> io::Result<usize> {
    let mut offset = 0usize;
    let mut records = 0;
    while offset < bytes.len() {
        let header = bytes
            .get(offset..offset + 5)
            .ok_or_else(|| invalid("partial TLS fixture header"))?;
        if header[0] != 23 {
            return Err(invalid("unexpected post-auth TLS record kind"));
        }
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        offset = offset
            .checked_add(5 + length)
            .ok_or_else(|| invalid("TLS fixture overflow"))?;
        if offset > bytes.len() {
            return Err(invalid("partial TLS fixture body"));
        }
        records += 1;
    }
    Ok(records)
}
#[tokio::test]
async fn actual_pinned_tls_separate_prefix_has_two_records_contiguous_frame_has_one() -> TestResult
{
    use l2tunnel_auth::{
        ClientTls, MemberAllowlist, MemberKey, ServerTls, client_connect_io, server_accept,
    };
    use tokio::net::{TcpListener, TcpStream};
    let cert = rcgen::generate_simple_self_signed(vec!["framed-write.test".into()])?;
    let chain = [cert.cert.der().to_vec()];
    let client = ClientTls::from_der_roots(&chain)?;
    let server = ServerTls::from_der(&chain, &cert.signing_key.serialize_der())?;
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let allow = MemberAllowlist::new(&[member.public_key()])?;
    let runtime = RuntimeConfig {
        layer: PacketLayer::Ip,
        max_packet: 1600,
        compression: Compression::None,
        queue_packets: 2,
        poll_interval: Duration::from_millis(1),
    };
    let binding = session_config(runtime, &mode_config(runtime, Duplex::Full)?)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let raw = TcpStream::connect(listener.local_addr()?).await?;
    raw.set_nodelay(true)?;
    let (peer, _) = listener.accept().await?;
    peer.set_nodelay(true)?;
    let captured = Arc::new(Mutex::new(Vec::new()));
    let (mut a, mut b) = tokio::try_join!(
        client_connect_io(
            CapturedTcp {
                stream: raw,
                captured: captured.clone()
            },
            &client,
            "framed-write.test",
            &member,
            binding,
            Duration::from_secs(3)
        ),
        server_accept(peer, &server, &allow, binding, Duration::from_secs(3))
    )?;
    let payload = vec![9; 128];
    let body = wire::encode(
        Header {
            kind: Kind::Data,
            epoch: Epoch(1),
            packet_number: 0,
            session: [7; 16],
            lane: 0,
        },
        &payload,
    )
    .map_err(wire_error)?;
    let mut reference = u32::try_from(body.len())?.to_be_bytes().to_vec();
    reference.extend_from_slice(&body);
    captured.lock().map_err(|_| invalid("lock"))?.clear();
    a.write_u32(u32::try_from(body.len())?).await?;
    a.write_all(&body).await?;
    a.flush().await?;
    let mut received = vec![0; reference.len()];
    tokio::time::timeout(Duration::from_secs(3), b.read_exact(&mut received)).await??;
    assert_eq!(received, reference);
    assert_eq!(
        application_tls_records(&captured.lock().map_err(|_| invalid("lock"))?)?,
        2
    );
    captured.lock().map_err(|_| invalid("lock"))?.clear();
    let mut number = 0;
    write_record(
        &mut a,
        [7; 16],
        &mut number,
        Kind::Data,
        Epoch(1),
        &payload,
        None,
    )
    .await?;
    tokio::time::timeout(Duration::from_secs(3), b.read_exact(&mut received)).await??;
    assert_eq!(received, reference);
    assert_eq!(
        application_tls_records(&captured.lock().map_err(|_| invalid("lock"))?)?,
        1
    );
    // This counts maintained TLS records at its socket adapter, not kernel packets.
    Ok(())
}
