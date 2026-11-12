use super::*;
use crate::{
    PacketIo,
    handoff::{SwitchLimits, bridge_switchable},
};
use l2tunnel_raw_tcp::{Config, Role};
use std::{
    collections::VecDeque,
    future::poll_fn,
    io::Write as _,
    net::{Ipv4Addr, SocketAddrV4},
    task::Waker,
};
use tokio::{io::AsyncWriteExt, sync::mpsc, task::JoinHandle, time::timeout};
type R<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
fn base() -> SessionConfig {
    SessionConfig {
        layer: PacketLayer::Ip,
        digest: ConfigDigest([0x61; 32]),
    }
}
fn frame(payload: &[u8]) -> Vec<u8> {
    let mut b = MAGIC.to_vec();
    b.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    b.extend_from_slice(payload);
    b
}
struct Mock {
    input: VecDeque<u8>,
    output: Vec<u8>,
    chunk: usize,
    pending: bool,
    calls: [usize; 3],
    delay: Duration,
    errno: Option<i32>,
    zero: bool,
}
impl Mock {
    fn new(bytes: Vec<u8>, chunk: usize) -> Self {
        Self {
            input: bytes.into(),
            output: vec![],
            chunk,
            pending: false,
            calls: [0; 3],
            delay: Duration::ZERO,
            errno: None,
            zero: false,
        }
    }
    fn pre(&mut self, index: usize) -> Poll<io::Result<()>> {
        self.calls[index] += 1;
        if !self.delay.is_zero() {
            std::thread::sleep(self.delay);
        }
        if self.pending {
            return Poll::Pending;
        }
        if let Some(e) = self.errno {
            return Poll::Ready(Err(io::Error::from_raw_os_error(e)));
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncRead for Mock {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.pre(0) {
            Poll::Ready(Ok(())) => (),
            v => return v,
        }
        let n = this.input.len().min(this.chunk).min(buf.remaining());
        for _ in 0..n {
            if let Some(b) = this.input.pop_front() {
                buf.put_slice(&[b]);
            }
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Mock {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.pre(1) {
            Poll::Ready(Ok(())) => (),
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        }
        let n = if this.zero {
            0
        } else {
            this.chunk.min(b.len())
        };
        this.output.extend_from_slice(&b[..n]);
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().pre(2)
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::other("must not shutdown")))
    }
}
fn exact(input: Vec<u8>, chunk: usize) -> Exact<Mock> {
    Exact::new(
        Mock::new(input, chunk),
        MessageLimits::default(),
        Instant::now() + Duration::from_secs(10),
    )
}
fn receive(io: &mut Exact<Mock>) -> Poll<Result<(), MessageError>> {
    io.poll_receive(&mut Context::from_waker(Waker::noop()))
}
fn send(io: &mut Exact<Mock>) -> Poll<Result<(), MessageError>> {
    io.poll_send(&mut Context::from_waker(Waker::noop()))
}

#[test]
fn canonical_digest_covers_each_budget_and_layer_and_rejects_asymmetry() -> R {
    let l = MessageLimits::default();
    let original = message_session_config(base(), l)?;
    assert_ne!(original, base());
    assert_eq!(original, message_session_config(base(), l)?);
    for kind in 0..7 {
        let mut limits = l;
        let mut b = base();
        match kind {
            0 => limits.records.incoming.wire_bytes -= 1,
            1 => limits.records.incoming.records -= 1,
            2 => limits.records.max_payload -= 1,
            3 => limits.max_payload -= 1,
            4 => limits.messages_per_direction -= 1,
            5 => limits.bytes_per_direction -= 1,
            _ => b.layer = PacketLayer::Ethernet,
        };
        limits.records.outgoing = limits.records.incoming;
        assert_ne!(original, message_session_config(b, limits)?);
    }
    let mut asym = l;
    asym.records.outgoing.records -= 1;
    assert_eq!(
        message_session_config(base(), asym),
        Err(StartError::Limits)
    );
    for kind in 0..6 {
        let mut limits = l;
        match kind {
            0 => limits.max_payload = 0,
            1 => limits.max_payload = 4097,
            2 => limits.messages_per_direction = 0,
            3 => limits.messages_per_direction = 257,
            4 => limits.bytes_per_direction = 8,
            _ => limits.bytes_per_direction = MAX_BYTES + 1,
        };
        assert_eq!(
            message_session_config(base(), limits),
            Err(StartError::Limits)
        );
    }
    Ok(())
}
#[tokio::test]
async fn every_header_split_and_body_length_is_exact_and_completed_delivery_blocks_prefetch() -> R {
    for size in [1, 31, 4096] {
        for chunk in 1..=9 {
            let payload = vec![0x5a; size];
            let wire = frame(&payload);
            let mut io = exact([wire.clone(), frame(b"NEXT")].concat(), chunk);
            poll_fn(|cx| io.poll_receive(cx)).await?;
            assert_eq!(io.message(), Some(payload.as_slice()));
            assert_eq!(io.incoming.progress.plaintext_bytes, wire.len() as u64);
            assert_eq!(io.io.input.len(), 12);
            let calls = io.io.calls;
            assert!(matches!(receive(&mut io), Poll::Ready(Ok(()))));
            assert_eq!(calls, io.io.calls);
            io.stage(&payload)?;
            poll_fn(|cx| io.poll_send(cx)).await?;
            assert_eq!(io.io.output, wire);
            assert_eq!(io.outgoing.progress, io.incoming.progress);
            assert_eq!(io.io.calls[2], 1);
            io.consume()?;
            assert!(io.message().is_none());
            poll_fn(|cx| io.poll_receive(cx)).await?;
            assert_eq!(io.message(), Some(&b"NEXT"[..]));
        }
    }
    Ok(())
}
#[tokio::test]
async fn malformed_header_is_counted_and_never_returns_partial_payload_or_reads_body() -> R {
    for field in 0..8 {
        let mut data = frame(b"X");
        data[field] = match field {
            6 => 0xff,
            7 => 0,
            _ => data[field] ^ 0x80,
        };
        let mut io = exact(data, 3);
        assert_eq!(
            poll_fn(|cx| io.poll_receive(cx)).await,
            Err(MessageError::Envelope)
        );
        assert_eq!(io.incoming.progress.plaintext_bytes, 8);
        assert_eq!(io.io.input.len(), 1);
        assert!(io.message().is_none());
        let calls = io.io.calls;
        assert!(io.stage(b"x").is_err());
        assert!(matches!(
            receive(&mut io),
            Poll::Ready(Err(MessageError::Envelope))
        ));
        assert_eq!(calls, io.io.calls);
    }
    let mut io = exact(frame(&[]), 8);
    assert_eq!(
        poll_fn(|cx| io.poll_receive(cx)).await,
        Err(MessageError::Envelope)
    );
    Ok(())
}
#[tokio::test]
async fn capacity_and_staging_failures_preserve_owned_message_and_exact_final_boundary() -> R {
    let wire = frame(b"abc");
    let mut io = exact([wire.clone(), frame(b"x")].concat(), 2);
    io.limits.messages_per_direction = 1;
    io.limits.bytes_per_direction = 11;
    io.stage(b"abc")?;
    let before = io.outgoing.progress;
    let bytes = io.outgoing.bytes;
    assert_eq!(io.stage(b"x"), Err(MessageError::Busy));
    assert_eq!(io.outgoing.progress, before);
    assert_eq!(io.outgoing.bytes, bytes);
    poll_fn(|cx| io.poll_send(cx)).await?;
    assert_eq!(io.stage(b"x"), Err(MessageError::Payload));
    assert!(io.fault.is_none());
    poll_fn(|cx| io.poll_receive(cx)).await?;
    assert_eq!(io.message(), Some(&b"abc"[..]));
    io.consume()?;
    let calls = io.io.calls;
    assert!(matches!(
        receive(&mut io),
        Poll::Ready(Err(MessageError::Capacity))
    ));
    assert_eq!(io.io.calls, calls);
    let mut io = exact(frame(b"four"), 99);
    io.limits.bytes_per_direction = 11;
    assert_eq!(
        poll_fn(|cx| io.poll_receive(cx)).await,
        Err(MessageError::Capacity)
    );
    assert_eq!(io.io.input.len(), 4);
    assert_eq!(io.incoming.progress.plaintext_bytes, 8);
    Ok(())
}
#[tokio::test]
async fn pending_cancellation_preserves_partial_offsets_and_needs_real_flush() -> R {
    let wire = frame(b"original");
    let mut io = exact(wire.clone(), 2);
    io.stage(b"original")?;
    assert!(send(&mut io).is_pending());
    assert_eq!(io.outgoing.offset, 2);
    assert!(receive(&mut io).is_pending());
    assert_eq!(io.incoming.offset, 2);
    io.io.pending = true;
    let read = io.incoming.progress;
    let write = io.outgoing.progress;
    assert!(send(&mut io).is_pending());
    assert!(receive(&mut io).is_pending());
    assert_eq!(read, io.incoming.progress);
    assert_eq!(write, io.outgoing.progress);
    io.io.pending = false;
    while io.outgoing.offset < io.outgoing.length {
        assert!(send(&mut io).is_pending());
    }
    assert_eq!(io.outgoing.progress.completed_messages, 0);
    io.io.pending = true;
    assert!(send(&mut io).is_pending());
    assert_eq!(io.outgoing.progress.completed_messages, 0);
    io.io.pending = false;
    poll_fn(|cx| io.poll_send(cx)).await?;
    poll_fn(|cx| io.poll_receive(cx)).await?;
    assert_eq!(io.io.output, wire);
    assert_eq!(io.message(), Some(&b"original"[..]));
    Ok(())
}
#[tokio::test]
async fn eof_every_header_and_payload_phase_is_terminal_including_boundary() -> R {
    let wire = frame(b"short");
    for length in 0..wire.len() {
        let mut io = exact(wire[..length].to_vec(), 2);
        assert_eq!(
            poll_fn(|cx| io.poll_receive(cx)).await,
            Err(MessageError::Eof)
        );
        assert_eq!(io.incoming.progress.plaintext_bytes, length as u64);
        assert!(io.message().is_none());
    }
    Ok(())
}
#[tokio::test]
async fn errors_zero_writes_and_checked_exhaustion_never_restart_io() -> R {
    for reading in [false, true] {
        let mut io = exact(frame(b"x"), 99);
        io.stage(b"x")?;
        io.io.errno = Some(13);
        let expected = MessageError::Io {
            kind: io::ErrorKind::PermissionDenied,
            raw_os_error: Some(13),
        };
        let r = if reading {
            receive(&mut io)
        } else {
            send(&mut io)
        };
        assert!(matches!(r,Poll::Ready(Err(e)) if e==expected));
        let calls = io.io.calls;
        io.io.errno = None;
        assert_eq!(io.stage(b"next"), Err(expected));
        assert!(matches!(receive(&mut io),Poll::Ready(Err(e)) if e==expected));
        assert_eq!(io.io.calls, calls);
    }
    let mut io = exact(vec![], 99);
    io.stage(b"x")?;
    io.io.zero = true;
    assert!(matches!(
        send(&mut io),
        Poll::Ready(Err(MessageError::WriteZero))
    ));
    assert_eq!(io.outgoing.progress.plaintext_bytes, 0);
    let mut io = exact(frame(b"x"), 99);
    io.incoming.progress.plaintext_bytes = u64::MAX;
    assert!(matches!(
        receive(&mut io),
        Poll::Ready(Err(MessageError::Arithmetic))
    ));
    assert_eq!(io.io.calls, [0; 3]);
    let mut io = exact(vec![], 99);
    io.outgoing.progress.reserved_bytes = u64::MAX;
    assert_eq!(io.stage(b"x"), Err(MessageError::Arithmetic));
    assert_eq!(io.io.calls, [0; 3]);
    Ok(())
}
#[tokio::test]
async fn ready_progress_after_original_deadline_is_counted_but_never_success() -> R {
    for reading in [false, true] {
        let mut io = exact(frame(b"x"), 99);
        io.stage(b"x")?;
        io.deadline = Instant::now() + Duration::from_millis(30);
        io.io.delay = Duration::from_millis(40);
        let result = if reading {
            receive(&mut io)
        } else {
            send(&mut io)
        };
        assert!(matches!(result, Poll::Ready(Err(MessageError::Expired))));
        assert!(if reading {
            io.incoming.progress.plaintext_bytes > 0
        } else {
            io.outgoing.progress.plaintext_bytes > 0
        });
        let calls = io.io.calls;
        assert!(matches!(
            send(&mut io),
            Poll::Ready(Err(MessageError::Expired))
        ));
        assert_eq!(calls, io.io.calls);
    }
    let mut io = exact(vec![], 99);
    io.stage(b"x")?;
    while io.outgoing.offset < io.outgoing.length {
        assert!(send(&mut io).is_pending());
    }
    io.deadline = Instant::now() + Duration::from_millis(30);
    io.io.delay = Duration::from_millis(40);
    assert!(matches!(
        send(&mut io),
        Poll::Ready(Err(MessageError::Expired))
    ));
    assert_eq!(io.outgoing.progress.completed_messages, 0);
    Ok(())
}
#[tokio::test(start_paused = true)]
async fn pending_operation_wakes_at_original_deadline_and_expired_message_is_hidden() -> R {
    let mut io = exact(frame(b"x"), 99);
    poll_fn(|cx| io.poll_receive(cx)).await?;
    let deadline = io.deadline;
    tokio::time::advance(deadline - Instant::now()).await;
    assert!(io.message().is_none());
    assert_eq!(io.consume(), Err(MessageError::Expired));
    let mut io = exact(vec![], 99);
    io.io.pending = true;
    assert_eq!(
        poll_fn(|cx| io.poll_receive(cx)).await,
        Err(MessageError::Expired)
    );
    Ok(())
}

struct PacketLink {
    incoming: mpsc::Receiver<Vec<u8>>,
    outgoing: mpsc::Sender<Vec<u8>>,
}
impl PacketIo for PacketLink {
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        assert_eq!(out.len(), 65_536);
        match self.incoming.try_recv() {
            Ok(v) => {
                out[..v.len()].copy_from_slice(&v);
                Ok(Some(v.len()))
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
    let a = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 61), 42001);
    let b = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 62), 42002);
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
        idle_timeout_millis: 30_000,
    }
}
struct Drivers {
    tasks: Vec<JoinHandle<io::Result<super::super::SwitchExit<PacketLink>>>>,
}
impl Drop for Drivers {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}
impl Drivers {
    async fn finish(mut self) -> R {
        for t in self.tasks.drain(..) {
            t.abort();
            match t.await {
                Err(e) if e.is_cancelled() => (),
                Err(e) => return Err(e.into()),
                Ok(_) => (),
            }
        }
        Ok(())
    }
}
fn bridges() -> R<(
    TrackedStream,
    SwitchHandle,
    TrackedStream,
    SwitchHandle,
    Drivers,
)> {
    let (at, br) = mpsc::channel(32);
    let (bt, ar) = mpsc::channel(32);
    let (a, ah, ad) = bridge_switchable(
        raw(true),
        Role::Client,
        PacketLink {
            incoming: ar,
            outgoing: at,
        },
        SwitchLimits::default(),
    )?;
    let (b, bh, bd) = bridge_switchable(
        raw(false),
        Role::Server,
        PacketLink {
            incoming: br,
            outgoing: bt,
        },
        SwitchLimits::default(),
    )?;
    Ok((
        a,
        ah,
        b,
        bh,
        Drivers {
            tasks: vec![tokio::spawn(ad.run()), tokio::spawn(bd.run())],
        },
    ))
}
fn fixture() -> R<(ClientTls, ServerTls, MemberKey, MemberAllowlist)> {
    let cert = rcgen::generate_simple_self_signed(vec!["tunnel.test".to_owned()])?;
    let chain = vec![cert.cert.der().to_vec()];
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let members = MemberAllowlist::new(&[member.public_key()])?;
    Ok((
        ClientTls::from_der_roots(&chain)?,
        ServerTls::from_der(&chain, &cert.signing_key.serialize_der())?,
        member,
        members,
    ))
}
async fn pair() -> R<(TlsMessageOwner, TlsMessageOwner, Drivers)> {
    pair_limits(MessageLimits::default()).await
}
async fn pair_limits(limits: MessageLimits) -> R<(TlsMessageOwner, TlsMessageOwner, Drivers)> {
    let (tls, server, member, members) = fixture()?;
    let (a, ah, b, bh, tasks) = bridges()?;
    let left = begin_client(
        a,
        ah,
        &tls,
        "tunnel.test",
        &member,
        base(),
        limits,
        Duration::from_secs(5),
    )?;
    let right = begin_server(
        b,
        bh,
        &server,
        &members,
        base(),
        limits,
        Duration::from_secs(5),
    )?;
    let (a, b) = tokio::try_join!(left, right)?;
    Ok((a, b, tasks))
}
async fn transfer(a: &mut TlsMessageOwner, b: &mut TlsMessageOwner, bytes: &[u8]) -> R {
    a.stage_message(bytes)?;
    tokio::try_join!(
        poll_fn(|cx| a.poll_send(cx)),
        poll_fn(|cx| b.poll_receive(cx))
    )?;
    assert_eq!(b.message(), Some(bytes));
    Ok(())
}
fn backend_state(
    tls: &mut TlsStream<RecordIo<TrackedStream>>,
) -> Result<tokio_rustls::rustls::IoState, tokio_rustls::rustls::Error> {
    match tls {
        TlsStream::Client(s) => s.get_mut().1.process_new_packets(),
        TlsStream::Server(s) => s.get_mut().1.process_new_packets(),
    }
}
fn backend_zero(tls: &mut TlsStream<RecordIo<TrackedStream>>) -> io::Result<usize> {
    match tls {
        TlsStream::Client(s) => s.get_mut().1.writer().write(&[]),
        TlsStream::Server(s) => s.get_mut().1.writer().write(&[]),
    }
}
fn refresh(
    tls: &mut TlsStream<RecordIo<TrackedStream>>,
) -> Result<(), tokio_rustls::rustls::Error> {
    match tls {
        TlsStream::Client(s) => s.get_mut().1.refresh_traffic_keys(),
        TlsStream::Server(s) => s.get_mut().1.refresh_traffic_keys(),
    }
}
fn capture(tls: &mut TlsStream<RecordIo<TrackedStream>>, payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut v = vec![];
    match tls {
        TlsStream::Client(s) => {
            s.get_mut().1.writer().write_all(payload)?;
            s.get_mut().1.write_tls(&mut v)?;
        }
        TlsStream::Server(s) => {
            s.get_mut().1.writer().write_all(payload)?;
            s.get_mut().1.write_tls(&mut v)?;
        }
    }
    Ok(v)
}

#[tokio::test]
async fn real_auth_bidirectional_messages_keep_original_counters_and_deadline() -> R {
    let (mut a, mut b, tasks) = pair().await?;
    let ad = a.deadline();
    let bd = b.deadline();
    assert_eq!(a.info().session_id, b.info().session_id);
    assert_eq!(a.info().member, b.info().member);
    assert_eq!(
        a.info().config,
        message_session_config(base(), MessageLimits::default())?
    );
    transfer(&mut a, &mut b, b"forward\0\xff").await?;
    transfer(&mut b, &mut a, b"reverse").await?;
    for io in [&a, &b] {
        let r = io.status().records;
        let e = io.handle.status().endpoint;
        assert_eq!(
            (r.incoming.wire_bytes, r.outgoing.wire_bytes),
            (e.read, e.written)
        );
        assert!(!r.shutdown_started);
        assert!(r.fault.is_none());
    }
    assert_eq!(a.deadline(), ad);
    assert_eq!(b.deadline(), bd);
    drop((a, b));
    tasks.finish().await
}
#[tokio::test]
async fn borrowed_setup_poll_cancellation_retains_authentication_and_never_resets_prefix() -> R {
    let (tls, server, member, members) = fixture()?;
    let (a, ah, b, bh, tasks) = bridges()?;
    let mut left = begin_client(
        a,
        ah,
        &tls,
        "tunnel.test",
        &member,
        base(),
        MessageLimits::default(),
        Duration::from_secs(5),
    )?;
    let deadline = left.deadline;
    let result = poll_fn(|cx| Poll::Ready(Pin::new(&mut left).poll(cx))).await;
    assert!(result.is_pending());
    let before = left
        .handle
        .as_ref()
        .ok_or("handle")?
        .status()
        .endpoint
        .written;
    assert!(before > 0);
    let right = begin_server(
        b,
        bh,
        &server,
        &members,
        base(),
        MessageLimits::default(),
        Duration::from_secs(5),
    )?;
    let (mut a, mut b) = tokio::try_join!(&mut left, right)?;
    assert_eq!(a.deadline(), deadline);
    assert!(a.handle.status().endpoint.written >= before);
    assert!(matches!(
        poll_fn(|cx| Poll::Ready(Pin::new(&mut left).poll(cx))).await,
        Poll::Ready(Err(SetupFailure::Completed))
    ));
    transfer(&mut a, &mut b, b"same owner").await?;
    drop((a, b));
    tasks.finish().await
}
#[tokio::test]
async fn wrong_certificate_name_member_and_configuration_cannot_publish_owner() -> R {
    for kind in 0..4 {
        let (mut tls, server, member, mut members) = fixture()?;
        let (a, ah, b, bh, tasks) = bridges()?;
        let mut expected = base();
        let name = if kind == 0 {
            "wrong.test"
        } else {
            "tunnel.test"
        };
        if kind == 1 {
            tls = fixture()?.0;
        }
        if kind == 2 {
            members = fixture()?.3;
        }
        if kind == 3 {
            expected.digest.0[0] ^= 1;
        }
        let left = begin_client(
            a,
            ah,
            &tls,
            name,
            &member,
            base(),
            MessageLimits::default(),
            Duration::from_millis(250),
        )?;
        let right = begin_server(
            b,
            bh,
            &server,
            &members,
            expected,
            MessageLimits::default(),
            Duration::from_millis(250),
        )?;
        let (a, b) = tokio::join!(left, right);
        assert!(a.is_err());
        assert!(b.is_err());
        tasks.finish().await?;
    }
    Ok(())
}
#[tokio::test]
async fn wrong_handles_and_invalid_policy_return_exact_owners_before_io() -> R {
    let (tls, _, member, _) = fixture()?;
    let (a, ah, b, bh, tasks) = bridges()?;
    let shared = a.shared.clone();
    let wrong = bh.shared.clone();
    let failure = begin_client(
        a,
        bh,
        &tls,
        "tunnel.test",
        &member,
        base(),
        MessageLimits::default(),
        Duration::from_secs(1),
    )
    .err()
    .ok_or("accepted mismatch")?;
    assert_eq!(failure.error, StartError::Identity);
    assert!(Arc::ptr_eq(&shared, &failure.stream.shared));
    assert!(Arc::ptr_eq(&wrong, &failure.handle.shared));
    assert_eq!(
        failure.handle.status().endpoint,
        super::super::EndpointProgress::default()
    );
    drop((failure, ah, b));
    tasks.finish().await
}
#[tokio::test(start_paused = true)]
async fn factory_time_before_first_poll_and_auth_time_share_original_deadline() -> R {
    let (tls, _, member, _) = fixture()?;
    let (a, ah, b, bh, tasks) = bridges()?;
    let mut setup = begin_client(
        a,
        ah,
        &tls,
        "tunnel.test",
        &member,
        base(),
        MessageLimits::default(),
        Duration::from_millis(10),
    )?;
    tokio::time::advance(Duration::from_millis(10)).await;
    assert!(matches!(
        Pin::new(&mut setup).await,
        Err(SetupFailure::Expired)
    ));
    assert!(setup.future.is_none());
    assert!(setup.handle.is_none());
    drop((setup, b, bh));
    tasks.finish().await
}
#[tokio::test]
async fn same_record_extra_plaintext_is_retained_and_never_claimed_as_quiescent() -> R {
    let (mut a, mut b, tasks) = pair().await?;
    let mut bytes = frame(b"SEAL");
    bytes.push(b'X');
    b.exact.io.write_all(&bytes).await?;
    b.exact.io.flush().await?;
    poll_fn(|cx| a.poll_receive(cx)).await?;
    assert_eq!(a.message(), Some(&b"SEAL"[..]));
    assert_eq!(backend_state(&mut a.exact.io)?.plaintext_bytes_to_read(), 1);
    let before = a.handle.status().endpoint.read;
    assert!(matches!(
        poll_fn(|cx| Poll::Ready(a.poll_receive(cx))).await,
        Poll::Ready(Ok(()))
    ));
    assert_eq!(a.handle.status().endpoint.read, before);
    drop((a, b));
    tasks.finish().await
}
#[tokio::test]
async fn exact_message_leaves_every_partial_or_complete_following_record_outside_counted_bridge()
-> R {
    for prefix in 1..=34 {
        let (mut a, mut b, tasks) = pair().await?;
        b.exact.io.write_all(&frame(b"SEAL")).await?;
        b.exact.io.flush().await?;
        let boundary = b.handle.status().endpoint.written;
        let next = capture(&mut b.exact.io, &frame(b"NEXT"))?;
        assert_eq!(next.len(), 34);
        b.exact.io.get_mut().0.write_all(&next[..prefix]).await?;
        timeout(Duration::from_secs(2), async {
            while a.handle.status().driver.inbound_written < boundary + prefix as u64 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await?;
        poll_fn(|cx| a.poll_receive(cx)).await?;
        assert_eq!(a.message(), Some(&b"SEAL"[..]));
        assert_eq!(a.handle.status().endpoint.read, boundary);
        assert_eq!(
            a.handle.status().driver.inbound_written - boundary,
            prefix as u64
        );
        assert!(a.status().records.incoming.at_boundary());
        drop((a, b));
        tasks.finish().await?;
    }
    Ok(())
}
#[tokio::test]
async fn requested_keyupdate_stays_hidden_after_exact_message_and_flush_until_backend_zero_write()
-> R {
    let (mut a, mut b, tasks) = pair().await?;
    transfer(&mut a, &mut b, b"local").await?;
    refresh(&mut b.exact.io)?;
    transfer(&mut b, &mut a, b"SEAL").await?;
    let before = a.handle.status().endpoint.written;
    assert_eq!(backend_state(&mut a.exact.io)?.tls_bytes_to_write(), 0);
    assert!(!a.exact.io.get_ref().1.wants_write());
    a.exact.io.flush().await?;
    assert_eq!(a.handle.status().endpoint.written, before);
    assert_eq!(backend_zero(&mut a.exact.io)?, 0);
    assert!(a.exact.io.get_ref().1.wants_write());
    assert_eq!(a.handle.status().endpoint.written, before);
    drop((a, b));
    tasks.finish().await
}

#[tokio::test]
async fn factory_invalid_timeout_limits_and_name_preserve_exact_original_owners() -> R {
    for case in 0..5 {
        let (tls, _, member, _) = fixture()?;
        let (a, ah, b, bh, tasks) = bridges()?;
        let original = a.shared.clone();
        let before = ah.status().endpoint;
        let mut limits = MessageLimits::default();
        let duration = match case {
            0 => Duration::ZERO,
            1 => Duration::from_secs(31),
            _ => Duration::from_secs(1),
        };
        if case == 2 {
            limits.max_payload = 0;
        }
        if case == 3 {
            limits.records.outgoing.records -= 1;
        }
        let name = if case == 4 { "bad name" } else { "tunnel.test" };
        let failure = begin_client(a, ah, &tls, name, &member, base(), limits, duration)
            .err()
            .ok_or("invalid factory accepted")?;
        assert!(Arc::ptr_eq(&original, &failure.stream.shared));
        assert!(Arc::ptr_eq(&original, &failure.handle.shared));
        assert_eq!(failure.handle.status().endpoint, before);
        drop((failure, b, bh));
        tasks.finish().await?;
    }
    Ok(())
}
#[tokio::test]
async fn setup_cancellation_drop_is_terminal_and_original_driver_tasks_are_joined() -> R {
    let (tls, _, member, _) = fixture()?;
    let (a, ah, b, bh, tasks) = bridges()?;
    let original = a.shared.clone();
    let mut setup = begin_client(
        a,
        ah,
        &tls,
        "tunnel.test",
        &member,
        base(),
        MessageLimits::default(),
        Duration::from_secs(1),
    )?;
    assert!(
        poll_fn(|cx| Poll::Ready(Pin::new(&mut setup).poll(cx)))
            .await
            .is_pending()
    );
    drop(setup);
    {
        let gate = original.lock().map_err(|_| "gate")?;
        assert!(!gate.stream_alive);
        assert!(!gate.handle_alive);
    }
    drop((b, bh));
    tasks.finish().await
}
#[tokio::test]
async fn completed_message_is_not_a_tls_freeze_on_either_endpoint_role() -> R {
    for reverse in [false, true] {
        let (mut a, mut b, tasks) = pair().await?;
        let (sender, receiver) = if reverse {
            (&mut a, &mut b)
        } else {
            (&mut b, &mut a)
        };
        let mut wire = frame(b"control");
        wire.extend_from_slice(b"trailing");
        sender.exact.io.write_all(&wire).await?;
        sender.exact.io.flush().await?;
        poll_fn(|cx| receiver.poll_receive(cx)).await?;
        assert_eq!(receiver.message(), Some(&b"control"[..]));
        assert_eq!(
            backend_state(&mut receiver.exact.io)?.plaintext_bytes_to_read(),
            8
        );
        assert!(receiver.status().records.incoming.at_boundary());
        assert!(!receiver.status().records.shutdown_started);
        drop((a, b));
        tasks.finish().await?;
    }
    Ok(())
}
#[tokio::test]
async fn exact_body_pause_at_each_offset_preserves_cancellation_and_next_frame() -> R {
    for split in 1..32 {
        let payload = [0xa5; 32];
        let mut io = exact([frame(&payload), frame(b"next")].concat(), 8);
        assert!(receive(&mut io).is_pending());
        assert_eq!(io.incoming.offset, 8);
        io.io.chunk = split;
        assert!(receive(&mut io).is_pending());
        let offset = io.incoming.offset;
        io.io.pending = true;
        assert!(receive(&mut io).is_pending());
        assert_eq!(io.incoming.offset, offset);
        io.io.pending = false;
        poll_fn(|cx| io.poll_receive(cx)).await?;
        assert_eq!(io.message(), Some(payload.as_slice()));
        assert_eq!(io.io.input.len(), 12);
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn timer_ready_branch_is_terminal_even_when_the_prior_clock_check_was_live() -> R {
    // Force the precise second-check branch without relying on a wall-clock race.
    let mut io = exact(vec![], 99);
    io.io.pending = true;
    io.timer = Box::pin(sleep_until(Instant::now()));
    assert!(matches!(
        receive(&mut io),
        Poll::Ready(Err(MessageError::Expired))
    ));
    let (tls, _, member, _) = fixture()?;
    let (a, ah, b, bh, tasks) = bridges()?;
    let mut setup = begin_client(
        a,
        ah,
        &tls,
        "tunnel.test",
        &member,
        base(),
        MessageLimits::default(),
        Duration::from_secs(1),
    )?;
    setup.timer = Box::pin(sleep_until(Instant::now()));
    assert!(matches!(
        poll_fn(|cx| Poll::Ready(Pin::new(&mut setup).poll(cx))).await,
        Poll::Ready(Err(SetupFailure::Expired))
    ));
    assert!(setup.future.is_none());
    assert!(setup.handle.is_none());
    drop((setup, b, bh));
    tasks.finish().await
}
#[tokio::test]
async fn actual_ciphertext_record_exhaustion_preserves_root_cause_and_original_counters() -> R {
    let (a, b, tasks) = pair().await?;
    let cap = a
        .status()
        .records
        .outgoing
        .started_records
        .max(b.status().records.outgoing.started_records);
    drop((a, b));
    tasks.finish().await?;
    let mut limits = MessageLimits::default();
    limits.records.incoming.records = cap;
    limits.records.outgoing.records = cap;
    let (mut a, mut b, tasks) = pair_limits(limits).await?;
    let owner = if a.status().records.outgoing.started_records == cap {
        &mut a
    } else {
        &mut b
    };
    let before = owner.handle.status().endpoint.written;
    let wire = owner.status().records.outgoing;
    owner.stage_message(b"exceeds original ciphertext record budget")?;
    let error = poll_fn(|cx| owner.poll_send(cx))
        .await
        .err()
        .ok_or("missing exhaustion")?;
    assert!(matches!(
        error,
        MessageError::Record(RecordFault {
            direction: super::super::RecordDirection::Outgoing,
            kind: super::super::RecordFaultKind::RecordLimit
        })
    ));
    assert_eq!(owner.status().fault, Some(error));
    assert_eq!(owner.handle.status().endpoint.written, before);
    assert_eq!(owner.status().records.outgoing, wire);
    assert_eq!(owner.stage_message(b"must not restart"), Err(error));
    assert!(
        matches!(poll_fn(|cx|Poll::Ready(owner.poll_receive(cx))).await,Poll::Ready(Err(e)) if e==error)
    );
    assert_eq!(owner.handle.status().endpoint.written, before);
    drop((a, b));
    tasks.finish().await
}

#[test]
fn canonical_v1_digest_matches_independent_python_sha256_vector() -> R {
    // Python hashlib.sha256(domain + [0x61]*32 + b'\x02' +
    // struct.pack('>QQHHHQ',4194304,16384,18431,4096,256,1048576) +
    // b'L2RM\x01\0' + struct.pack('>H',8)); this is a new profile, not simulator parity.
    let expected = [
        0x4c, 0xd3, 0x3c, 0x06, 0xc8, 0x63, 0x59, 0x01, 0x53, 0x67, 0xc8, 0x6b, 0x25, 0x14, 0x8c,
        0x5c, 0xe2, 0x39, 0xcd, 0x84, 0x9d, 0xb0, 0xb9, 0x3b, 0x64, 0x2b, 0x98, 0x95, 0x74, 0x27,
        0x84, 0x1b,
    ];
    assert_eq!(
        message_session_config(base(), MessageLimits::default())?.digest,
        ConfigDigest(expected)
    );
    Ok(())
}
#[tokio::test]
async fn setup_ready_after_original_deadline_drops_same_tls_without_publishing_owner() -> R {
    let (tls, server, member, members) = fixture()?;
    let (a, ah, b, bh, tasks) = bridges()?;
    let shared = a.shared.clone();
    let mut left = begin_client(
        a,
        ah,
        &tls,
        "tunnel.test",
        &member,
        base(),
        MessageLimits::default(),
        Duration::from_millis(250),
    )?;
    let right = begin_server(
        b,
        bh,
        &server,
        &members,
        base(),
        MessageLimits::default(),
        Duration::from_secs(1),
    )?;
    // Obtain an actual auth result from the very same retained future; then force its
    // synchronous completion to straddle the original deadline, without a fake TLS owner.
    let (client, server) = tokio::join!(left.future.as_mut().ok_or("missing future")?, right);
    let authenticated = client?;
    let server = server?;
    let delay = left.deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(5);
    left.future = Some(Box::pin(async move {
        std::thread::sleep(delay);
        Ok(authenticated)
    }));
    assert!(matches!(
        Pin::new(&mut left).await,
        Err(SetupFailure::Expired)
    ));
    {
        let gate = shared.lock().map_err(|_| "gate")?;
        assert!(!gate.stream_alive);
        assert!(!gate.handle_alive);
    }
    assert!(left.future.is_none());
    assert!(left.handle.is_none());
    drop((left, server));
    tasks.finish().await
}
