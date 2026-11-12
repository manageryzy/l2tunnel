//! Actual pinned TLS regressions over the original tracked raw bridge.
//! Fixture-only secret extraction uses maintained encryption; no freeze/handoff/native claim.
use crate::{
    PacketIo,
    handoff::{SwitchHandle, SwitchLimits, TrackedStream, bridge_switchable},
};
use l2tunnel_raw_tcp::{Config, Role};
use rustls::crypto::cipher::{MessageEncrypter, OutboundChunks, OutboundPlainMessage};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{
    ClientConfig, ConnectionTrafficSecrets, ContentType, ProtocolVersion, RootCertStore,
    ServerConfig,
};
use std::{
    io::{self, Write as _},
    net::{Ipv4Addr, SocketAddrV4},
    pin::Pin,
    sync::Arc,
    task::Poll,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf},
    sync::mpsc,
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
type R<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct PacketLink {
    incoming: mpsc::Receiver<Vec<u8>>,
    outgoing: mpsc::Sender<Vec<u8>>,
}
impl PacketIo for PacketLink {
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        assert_eq!(out.len(), 65536);
        match self.incoming.try_recv() {
            Ok(p) => {
                out[..p.len()].copy_from_slice(&p);
                Ok(Some(p.len()))
            }
            Err(_) => Ok(None),
        }
    }
    fn send(&mut self, p: &[u8]) -> io::Result<()> {
        self.outgoing
            .try_send(p.to_vec())
            .map_err(|_| io::ErrorKind::WouldBlock.into())
    }
}
fn raw(client: bool) -> Config {
    let a = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 41), 42001);
    let b = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 42), 42002);
    Config {
        local: if client { a } else { b },
        peer: if client { b } else { a },
        mtu: 576,
        send_bytes: 4096,
        receive_bytes: 4096,
        packet_slots: 8,
        random_seed: if client { 0x1212 } else { 0x2323 },
        ack_delay_millis: 1,
        keepalive_millis: 1000,
        idle_timeout_millis: 30000,
    }
}
use super::{RecordIo, RecordLimits};
type Boundary = RecordIo<TrackedStream>;
fn attach(stream: TrackedStream) -> R<Boundary> {
    Boundary::attach(stream, RecordLimits::default()).map_err(|(_, e)| e.into())
}
type Client = tokio_rustls::client::TlsStream<Boundary>;
type Server = tokio_rustls::server::TlsStream<Boundary>;
struct Pair {
    client: Client,
    server: Option<Server>,
    ch: SwitchHandle,
    sh: SwitchHandle,
    tasks: Vec<JoinHandle<()>>,
}
impl Drop for Pair {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}
impl Pair {
    async fn new(fragment: Option<usize>) -> R<Self> {
        let cert = rcgen::generate_simple_self_signed(vec!["tunnel.test".to_owned()])?;
        let mut roots = RootCertStore::empty();
        roots.add(cert.cert.der().clone())?;
        let provider = rustls::crypto::ring::default_provider();
        let mut cc = ClientConfig::builder_with_provider(Arc::new(provider.clone()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth();
        cc.enable_sni = false;
        let mut sc = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
            )?;
        sc.send_tls13_tickets = 0;
        sc.max_fragment_size = fragment;
        sc.enable_secret_extraction = true;
        let (at, br) = mpsc::channel(32);
        let (bt, ar) = mpsc::channel(32);
        let (a, ch, ad) = bridge_switchable(
            raw(true),
            Role::Client,
            PacketLink {
                incoming: ar,
                outgoing: at,
            },
            SwitchLimits::default(),
        )?;
        let (b, sh, bd) = bridge_switchable(
            raw(false),
            Role::Server,
            PacketLink {
                incoming: br,
                outgoing: bt,
            },
            SwitchLimits::default(),
        )?;
        let tasks = vec![
            tokio::spawn(async move {
                let _ = ad.run().await;
            }),
            tokio::spawn(async move {
                let _ = bd.run().await;
            }),
        ];
        let connector = TlsConnector::from(Arc::new(cc));
        let acceptor = TlsAcceptor::from(Arc::new(sc));
        let (client, server) = timeout(Duration::from_secs(5), async {
            tokio::try_join!(
                connector.connect(ServerName::try_from("tunnel.test")?, attach(a)?),
                acceptor.accept(attach(b)?)
            )
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })
        })
        .await??;
        Ok(Self {
            client,
            server: Some(server),
            ch,
            sh,
            tasks,
        })
    }
    async fn queued(&self) -> R {
        let target = self.sh.status().endpoint.written;
        timeout(Duration::from_secs(2), async {
            while self.ch.status().driver.inbound_written < target {
                sleep(Duration::from_millis(1)).await;
            }
        })
        .await?;
        Ok(())
    }
    fn assert_counts(&self) {
        assert_eq!(
            self.client.get_ref().0.status().incoming.wire_bytes,
            self.ch.status().endpoint.read
        );
    }
    async fn finish(mut self) -> R {
        for t in self.tasks.drain(..) {
            t.abort();
            let e = t.await.err().ok_or("expected failure")?;
            assert!(e.is_cancelled());
        }
        Ok(())
    }
}
struct FaultPeer {
    io: Boundary,
    crypt: Box<dyn MessageEncrypter>,
    seq: u64,
}
impl FaultPeer {
    fn take(pair: &mut Pair) -> R<Self> {
        let server = pair.server.take().ok_or("missing fixture value")?;
        let (io, conn) = server.into_inner();
        let alg = conn
            .negotiated_cipher_suite()
            .ok_or("missing fixture value")?
            .tls13()
            .ok_or("missing fixture value")?
            .aead_alg;
        let secret = conn.dangerous_extract_secrets()?;
        let (key, iv) = match secret.tx.1 {
            ConnectionTrafficSecrets::Aes128Gcm { key, iv }
            | ConnectionTrafficSecrets::Aes256Gcm { key, iv }
            | ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => (key, iv),
            _ => return Err("unsupported fixture cipher".into()),
        };
        Ok(Self {
            io,
            crypt: alg.encrypter(key, iv),
            seq: secret.tx.0,
        })
    }
    fn encode(&mut self, kind: ContentType, bytes: &[u8]) -> R<Vec<u8>> {
        let record = self
            .crypt
            .encrypt(
                OutboundPlainMessage {
                    typ: kind,
                    version: ProtocolVersion::TLSv1_2,
                    payload: OutboundChunks::Single(bytes),
                },
                self.seq,
            )?
            .encode();
        self.seq += 1;
        Ok(record)
    }
    async fn record(&mut self, kind: ContentType, bytes: &[u8]) -> R<usize> {
        let record = self.encode(kind, bytes)?;
        self.io.write_all(&record).await?;
        Ok(record.len())
    }
}

#[tokio::test]
async fn exact_read_leaves_partial_next_header_outside_original_counted_bridge() -> R {
    let mut p = Pair::new(None).await?;
    let before = p.ch.status().endpoint.read;
    let s = p.server.as_mut().ok_or("missing fixture value")?;
    s.write_all(b"SEAL").await?;
    s.flush().await?;
    let seal_end = p.sh.status().endpoint.written;
    p.server
        .as_mut()
        .ok_or("missing fixture value")?
        .get_mut()
        .0
        .inner
        .write_all(&[23, 3])
        .await?;
    p.queued().await?;
    let mut out = [0; 4];
    p.client.read_exact(&mut out).await?;
    assert_eq!(&out, b"SEAL");
    assert!(p.client.get_ref().0.status().incoming.at_boundary());
    assert_eq!(p.ch.status().endpoint.read, seal_end);
    assert!(seal_end > before);
    assert_eq!(
        p.ch.status().driver.inbound_written - p.ch.status().endpoint.read,
        2
    );
    p.assert_counts();
    let st = p.client.get_mut().1.process_new_packets()?;
    assert_eq!(st.plaintext_bytes_to_read(), 0);
    p.finish().await
}
#[tokio::test]
async fn wide_read_prefetches_partial_header_despite_record_bounded_io() -> R {
    let mut p = Pair::new(None).await?;
    let s = p.server.as_mut().ok_or("missing fixture value")?;
    s.write_all(b"SEAL").await?;
    s.flush().await?;
    p.server
        .as_mut()
        .ok_or("missing fixture value")?
        .get_mut()
        .0
        .inner
        .write_all(&[23, 3])
        .await?;
    p.queued().await?;
    let mut out = [0; 8];
    assert_eq!(p.client.read(&mut out).await?, 4);
    assert_eq!(&out[..4], b"SEAL");
    assert_eq!(p.client.get_ref().0.status().incoming.header_bytes, 2);
    assert!(!p.client.get_ref().0.status().incoming.at_boundary());
    assert_eq!(p.ch.status().endpoint.read, p.sh.status().endpoint.written);
    p.assert_counts();
    let st = p.client.get_mut().1.process_new_packets()?;
    assert_eq!(st.plaintext_bytes_to_read(), 0);
    assert_eq!(st.tls_bytes_to_write(), 0);
    p.finish().await
}
#[tokio::test]
async fn wide_read_hides_partial_handshake_at_complete_record_boundary() -> R {
    let mut p = Pair::new(None).await?;
    let mut peer = FaultPeer::take(&mut p)?;
    peer.record(ContentType::ApplicationData, b"SEAL").await?;
    peer.record(ContentType::Handshake, &[24, 0, 0, 1]).await?;
    p.queued().await?;
    let mut out = [0; 8];
    assert_eq!(p.client.read(&mut out).await?, 4);
    assert!(p.client.get_ref().0.status().incoming.at_boundary());
    p.assert_counts();
    let st = p.client.get_mut().1.process_new_packets()?;
    assert_eq!(st.plaintext_bytes_to_read(), 0);
    assert_eq!(st.tls_bytes_to_write(), 0);
    assert!(!p.client.get_ref().1.wants_write());
    // A real next appdata record exposes that the private handshake fragment survived.
    peer.record(ContentType::ApplicationData, b"NEXT").await?;
    let error = timeout(Duration::from_secs(2), p.client.read_exact(&mut out[..4]))
        .await?
        .err()
        .ok_or("expected failure")?;
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    drop(peer);
    p.finish().await
}
#[tokio::test]
async fn exact_read_leaves_complete_handshake_fragment_outside_counted_bridge() -> R {
    let mut p = Pair::new(None).await?;
    let mut peer = FaultPeer::take(&mut p)?;
    peer.record(ContentType::ApplicationData, b"SEAL").await?;
    let seal_end = p.sh.status().endpoint.written;
    let extra = peer.record(ContentType::Handshake, &[24, 0, 0, 1]).await?;
    p.queued().await?;
    let mut out = [0; 4];
    p.client.read_exact(&mut out).await?;
    assert_eq!(&out, b"SEAL");
    assert!(p.client.get_ref().0.status().incoming.at_boundary());
    assert_eq!(p.ch.status().endpoint.read, seal_end);
    assert_eq!(
        p.ch.status().driver.inbound_written - seal_end,
        extra as u64
    );
    p.assert_counts();
    drop(peer);
    p.finish().await
}
#[tokio::test]
async fn same_record_extra_plaintext_is_visible_without_more_ciphertext_io() -> R {
    let mut p = Pair::new(None).await?;
    let s = p.server.as_mut().ok_or("missing fixture value")?;
    s.write_all(b"SEALX").await?;
    s.flush().await?;
    p.queued().await?;
    let mut out = [0; 4];
    p.client.read_exact(&mut out).await?;
    assert!(p.client.get_ref().0.status().incoming.at_boundary());
    let before = p.ch.status().endpoint.read;
    let state = p.client.get_mut().1.process_new_packets()?;
    assert_eq!(state.plaintext_bytes_to_read(), 1);
    assert_eq!(p.ch.status().endpoint.read, before);
    p.assert_counts();
    p.finish().await
}
#[tokio::test]
async fn requested_key_update_is_hidden_from_flush_until_zero_plaintext_write() -> R {
    let mut p = Pair::new(None).await?;
    // Local terminal plaintext was already sent and consumed before peer update+Seal.
    p.client.write_all(b"SEAL").await?;
    p.client.flush().await?;
    let mut out = [0; 4];
    p.server
        .as_mut()
        .ok_or("missing fixture value")?
        .read_exact(&mut out)
        .await?;
    let s = p.server.as_mut().ok_or("missing fixture value")?;
    s.get_mut().1.refresh_traffic_keys()?;
    s.write_all(b"SEAL").await?;
    s.flush().await?;
    p.client.read_exact(&mut out).await?;
    assert_eq!(&out, b"SEAL");
    assert!(p.client.get_ref().0.status().incoming.at_boundary());
    let before = p.ch.status().endpoint.written;
    let state = p.client.get_mut().1.process_new_packets()?;
    assert_eq!(state.tls_bytes_to_write(), 0);
    assert_eq!(state.plaintext_bytes_to_read(), 0);
    assert!(!p.client.get_ref().1.wants_write());
    p.client.flush().await?;
    assert_eq!(p.ch.status().endpoint.written, before);
    assert!(!p.client.get_ref().1.wants_write());
    assert_eq!(p.client.get_mut().1.writer().write(&[])?, 0);
    assert!(p.client.get_ref().1.wants_write());
    assert!(
        p.client
            .get_mut()
            .1
            .process_new_packets()?
            .tls_bytes_to_write()
            > 0
    );
    assert_eq!(p.ch.status().endpoint.written, before);
    // Reject here. No post-Seal response is sent and no application byte is admitted.
    p.assert_counts();
    p.finish().await
}
#[tokio::test]
async fn zero_plaintext_write_on_clean_boundary_emits_nothing() -> R {
    let mut p = Pair::new(None).await?;
    let s = p.server.as_mut().ok_or("missing fixture value")?;
    s.write_all(b"SEAL").await?;
    s.flush().await?;
    let mut out = [0; 4];
    p.client.read_exact(&mut out).await?;
    let before = p.ch.status().endpoint;
    assert_eq!(p.client.get_mut().1.writer().write(&[])?, 0);
    let st = p.client.get_mut().1.process_new_packets()?;
    assert_eq!(st.tls_bytes_to_write(), 0);
    assert_eq!(st.plaintext_bytes_to_read(), 0);
    assert_eq!(p.ch.status().endpoint, before);
    p.finish().await
}
#[tokio::test]
async fn fragmented_terminal_plaintext_ends_on_authenticated_record_boundary() -> R {
    let mut p = Pair::new(Some(32)).await?;
    let before = p.client.get_ref().0.status().incoming.completed_records;
    let payload = [0x5a; 100];
    let s = p.server.as_mut().ok_or("missing fixture value")?;
    s.write_all(&payload).await?;
    s.flush().await?;
    let mut out = [0; 100];
    p.client.read_exact(&mut out).await?;
    assert_eq!(out, payload);
    assert!(p.client.get_ref().0.status().incoming.completed_records - before >= 4);
    assert!(p.client.get_ref().0.status().incoming.at_boundary());
    assert_eq!(
        p.client
            .get_mut()
            .1
            .process_new_packets()?
            .plaintext_bytes_to_read(),
        0
    );
    p.assert_counts();
    p.finish().await
}
#[tokio::test]
async fn partial_post_handshake_message_before_seal_is_rejected_by_rustls() -> R {
    let mut p = Pair::new(None).await?;
    let mut peer = FaultPeer::take(&mut p)?;
    peer.record(ContentType::Handshake, &[24, 0, 0, 1]).await?;
    peer.record(ContentType::ApplicationData, b"SEAL").await?;
    let mut out = [0; 4];
    let e = timeout(Duration::from_secs(2), p.client.read_exact(&mut out))
        .await?
        .err()
        .ok_or("expected failure")?;
    assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    drop(peer);
    p.finish().await
}
#[tokio::test]
async fn queued_output_is_distinct_from_counted_ciphertext_acceptance() -> R {
    let mut p = Pair::new(None).await?;
    let before = p.ch.status().endpoint.written;
    assert_eq!(p.client.get_mut().1.writer().write(b"SEAL")?, 4);
    assert!(p.client.get_ref().1.wants_write());
    assert_eq!(p.ch.status().endpoint.written, before);
    p.client.flush().await?;
    assert!(!p.client.get_ref().1.wants_write());
    assert!(p.ch.status().endpoint.written > before);
    let mut out = [0; 4];
    p.server
        .as_mut()
        .ok_or("missing fixture value")?
        .read_exact(&mut out)
        .await?;
    assert_eq!(&out, b"SEAL");
    p.finish().await
}

#[tokio::test]
async fn every_partial_and_complete_next_record_stays_outside_exact_terminal_read() -> R {
    // Ciphertext payload is 4 plaintext + 1 inner type + 16 tag; 5 header = 26.
    for prefix in 1..=26 {
        let mut p = Pair::new(None).await?;
        let mut peer = FaultPeer::take(&mut p)?;
        peer.record(ContentType::ApplicationData, b"SEAL").await?;
        let seal_end = p.sh.status().endpoint.written;
        let next = peer.encode(ContentType::ApplicationData, b"NEXT")?;
        assert_eq!(next.len(), 26);
        peer.io.inner.write_all(&next[..prefix]).await?;
        p.queued().await?;
        let mut out = [0; 4];
        p.client.read_exact(&mut out).await?;
        assert_eq!(&out, b"SEAL");
        assert!(p.client.get_ref().0.status().incoming.at_boundary());
        assert_eq!(p.ch.status().endpoint.read, seal_end);
        assert_eq!(
            p.ch.status().driver.inbound_written - seal_end,
            prefix as u64
        );
        p.assert_counts();
        let state = p.client.get_mut().1.process_new_packets()?;
        assert_eq!(state.plaintext_bytes_to_read(), 0);
        assert_eq!(state.tls_bytes_to_write(), 0);
        assert!(!state.peer_has_closed());
        drop(peer);
        p.finish().await?;
    }
    Ok(())
}
#[tokio::test]
async fn oversized_read_can_return_seal_while_hiding_a_following_tls_error() -> R {
    let mut p = Pair::new(None).await?;
    let mut peer = FaultPeer::take(&mut p)?;
    peer.record(ContentType::ApplicationData, b"SEAL").await?;
    peer.record(ContentType::Alert, &[2, 40]).await?;
    p.queued().await?;
    let mut out = [0; 8];
    assert_eq!(p.client.read(&mut out).await?, 4);
    assert_eq!(&out[..4], b"SEAL");
    assert!(p.client.get_ref().0.status().incoming.at_boundary());
    p.assert_counts();
    assert!(p.client.get_mut().1.process_new_packets().is_err());
    drop(peer);
    p.finish().await
}
#[tokio::test]
async fn same_record_extra_and_hidden_keyupdate_are_symmetric_on_server() -> R {
    let mut p = Pair::new(None).await?;
    let server = p.server.as_mut().ok_or("missing fixture value")?;
    server.write_all(b"SEAL").await?;
    server.flush().await?;
    let mut out = [0; 4];
    p.client.read_exact(&mut out).await?;
    p.client.get_mut().1.refresh_traffic_keys()?;
    p.client.write_all(b"SEALX").await?;
    p.client.flush().await?;
    let server = p.server.as_mut().ok_or("missing fixture value")?;
    server.read_exact(&mut out).await?;
    assert_eq!(&out, b"SEAL");
    assert!(server.get_ref().0.status().incoming.at_boundary());
    let state = server.get_mut().1.process_new_packets()?;
    assert_eq!(state.plaintext_bytes_to_read(), 1);
    assert_eq!(state.tls_bytes_to_write(), 0);
    assert!(!server.get_ref().1.wants_write());
    let before = p.sh.status().endpoint.written;
    server.flush().await?;
    assert_eq!(p.sh.status().endpoint.written, before);
    assert_eq!(server.get_mut().1.writer().write(&[])?, 0);
    assert!(server.get_ref().1.wants_write());
    assert_eq!(p.sh.status().endpoint.written, before);
    assert_eq!(
        server.get_ref().0.status().incoming.wire_bytes,
        p.sh.status().endpoint.read
    );
    p.finish().await
}

#[tokio::test]
async fn complete_fragmented_post_handshake_ticket_before_seal_is_accepted() -> R {
    // TLS 1.3 NewSessionTicket with finite lifetime, empty nonce/extensions,
    // and a one-byte opaque ticket. Only the existing backend encrypts it.
    let message = [4, 0, 0, 14, 0, 0, 0, 60, 0, 0, 0, 0, 0, 0, 1, 0x42, 0, 0];
    for split in 1..message.len() {
        let mut p = Pair::new(None).await?;
        let mut peer = FaultPeer::take(&mut p)?;
        peer.record(ContentType::Handshake, &message[..split])
            .await?;
        peer.record(ContentType::Handshake, &message[split..])
            .await?;
        peer.record(ContentType::ApplicationData, b"SEAL").await?;
        let mut out = [0; 4];
        timeout(Duration::from_secs(2), p.client.read_exact(&mut out)).await??;
        assert_eq!(&out, b"SEAL");
        assert!(p.client.get_ref().0.status().incoming.at_boundary());
        let state = p.client.get_mut().1.process_new_packets()?;
        assert_eq!(state.plaintext_bytes_to_read(), 0);
        assert_eq!(state.tls_bytes_to_write(), 0);
        p.assert_counts();
        drop(peer);
        p.finish().await?;
    }
    Ok(())
}
#[tokio::test]
async fn complete_fragmented_keyupdate_queues_hidden_response_without_terminal_plaintext() -> R {
    let mut p = Pair::new(None).await?;
    let mut peer = FaultPeer::take(&mut p)?;
    peer.record(ContentType::Handshake, &[24, 0]).await?;
    peer.record(ContentType::Handshake, &[0, 1, 1]).await?;
    p.queued().await?;
    let mut output = [0; 4];
    let result = std::future::poll_fn(|cx| {
        let mut read = ReadBuf::new(&mut output);
        let polled = Pin::new(&mut p.client).poll_read(cx, &mut read);
        assert_eq!(read.filled().len(), 0);
        Poll::Ready(polled)
    })
    .await;
    assert!(result.is_pending());
    assert!(p.client.get_ref().0.status().incoming.at_boundary());
    p.assert_counts();
    let state = p.client.get_mut().1.process_new_packets()?;
    assert_eq!(state.tls_bytes_to_write(), 0);
    assert_eq!(state.plaintext_bytes_to_read(), 0);
    let before = p.ch.status().endpoint.written;
    assert_eq!(p.client.get_mut().1.writer().write(&[])?, 0);
    assert!(p.client.get_ref().1.wants_write());
    assert_eq!(p.ch.status().endpoint.written, before);
    // No terminal Seal was delivered, so no freeze candidate exists.
    drop(peer);
    p.finish().await
}

#[tokio::test]
async fn actual_bidirectional_tls_matches_original_endpoint_identity_and_both_counters() -> R {
    let mut p = Pair::new(None).await?;
    assert!(p.client.get_ref().0.belongs_to(&p.ch));
    assert!(!p.client.get_ref().0.belongs_to(&p.sh));
    let s = p.server.as_mut().ok_or("missing fixture server")?;
    assert!(s.get_ref().0.belongs_to(&p.sh));
    assert!(!s.get_ref().0.belongs_to(&p.ch));
    p.client.write_all(b"FORWARD").await?;
    p.client.flush().await?;
    let mut forward = [0; 7];
    s.read_exact(&mut forward).await?;
    assert_eq!(&forward, b"FORWARD");
    s.write_all(b"REVERSE").await?;
    s.flush().await?;
    let mut reverse = [0; 7];
    p.client.read_exact(&mut reverse).await?;
    assert_eq!(&reverse, b"REVERSE");
    for (status, original) in [
        (p.client.get_ref().0.status(), p.ch.status().endpoint),
        (s.get_ref().0.status(), p.sh.status().endpoint),
    ] {
        assert_eq!(status.incoming.wire_bytes, original.read);
        assert_eq!(status.outgoing.wire_bytes, original.written);
        assert!(status.incoming.at_boundary());
        assert!(status.outgoing.at_boundary());
        assert!(status.incoming.started_records > 0);
        assert!(status.outgoing.started_records > 0);
        assert!(!status.shutdown_started);
        assert!(status.fault.is_none());
    }
    p.finish().await
}
