use super::*;
use l2tunnel_auth::{
    ClientTls, MemberAllowlist, MemberKey, ServerTls, client_connect, server_accept,
};
use l2tunnel_core::ConfigDigest;
use l2tunnel_device::PacketLayer;
use std::{future::poll_fn, task::Waker};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    net::{TcpListener, TcpStream},
};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn limits() -> Limits {
    Limits {
        max_record_bytes: 1024,
        record_timeout: Duration::from_secs(1),
    }
}
fn config() -> l2tunnel_auth::SessionConfig {
    l2tunnel_auth::SessionConfig {
        layer: PacketLayer::Ethernet,
        digest: ConfigDigest([0x63; 32]),
    }
}
async fn real_links(
    duplex: Duplex,
) -> Result<(Link, Link), Box<dyn std::error::Error + Send + Sync>> {
    let certificate = rcgen::generate_simple_self_signed(vec!["retained.test".to_owned()])?;
    let chain = vec![certificate.cert.der().to_vec()];
    let client_tls = ClientTls::from_der_roots(&chain)?;
    let server_tls = ServerTls::from_der(&chain, &certificate.signing_key.serialize_der())?;
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let members = MemberAllowlist::new(&[member.public_key()])?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let setup_deadline = Instant::now() + Duration::from_secs(5);
    let mut connections = Vec::new();
    for _ in 0..if duplex == Duplex::Half { 2 } else { 1 } {
        let client = TcpStream::connect(listener.local_addr()?).await?;
        let (server, _) = listener.accept().await?;
        client.set_nodelay(true)?;
        server.set_nodelay(true)?;
        connections.push(tokio::try_join!(
            client_connect(
                client,
                &client_tls,
                "retained.test",
                &member,
                config(),
                Duration::from_secs(4)
            ),
            server_accept(
                server,
                &server_tls,
                &members,
                config(),
                Duration::from_secs(4)
            )
        )?);
    }
    let mut connections = connections.into_iter();
    let (client, server) = connections
        .next()
        .ok_or_else(|| invalid("missing actual TLS pair"))?;
    if duplex == Duplex::Full {
        Ok((
            Link::full(client, setup_deadline)?,
            Link::full(server, setup_deadline)?,
        ))
    } else {
        let (second_client, second_server) = connections
            .next()
            .ok_or_else(|| invalid("missing actual second TLS pair"))?;
        Ok(tokio::try_join!(
            client_pair(client, second_client, setup_deadline),
            server_pair(server, second_server, setup_deadline)
        )?)
    }
}
fn adapter(link: Link) -> io::Result<Adapter> {
    let plan = Plan::new(&link, limits())?;
    Adapter::new(link, plan)
}

#[tokio::test]
async fn retained_tls_real_full_half_keep_original_membership_lanes_and_framed_receipts()
-> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        let (client_link, server_link) = real_links(duplex).await?;
        let a = client_link.info();
        let b = server_link.info();
        assert_eq!(a.first.session.session_id, b.first.session.session_id);
        assert_eq!(a.first.local_addr, b.first.peer_addr);
        assert_eq!(a.first.peer_addr, b.first.local_addr);
        assert_eq!(a.first.session.member, b.first.session.member);
        assert_eq!(a.first.session.config, config());
        assert_eq!(a.role, Role::Initiator);
        assert_eq!(b.role, Role::Responder);
        assert_eq!(a.duplex, duplex);
        if let (Some(a), Some(b)) = (a.second, b.second) {
            assert_eq!(a.session.session_id, b.session.session_id);
            assert_eq!(a.local_addr, b.peer_addr);
        }
        let mut client = adapter(client_link)?;
        let mut server = adapter(server_link)?;
        for framing in [Framing::Bootstrap, Framing::Final] {
            let deadline = Instant::now() + Duration::from_millis(500);
            let mut ca = client.try_send(Class::User, b"client user", deadline, framing)?;
            let mut cb = client.try_send(Class::Control, b"client control", deadline, framing)?;
            let serial = client.next;
            assert_eq!(
                client
                    .try_send(Class::User, b"duplicate", deadline, framing)
                    .err()
                    .map(|e| e.kind()),
                Some(io::ErrorKind::WouldBlock)
            );
            assert_eq!(client.next, serial);
            let mut sa = server.try_send(Class::User, b"server user", deadline, framing)?;
            let mut sb = server.try_send(Class::Control, b"server control", deadline, framing)?;
            let (client_receipt, server_receipt) = tokio::try_join!(
                poll_fn(|cx| client.poll_send(cx, &mut ca)),
                poll_fn(|cx| server.poll_send(cx, &mut sa))
            )?;
            assert_eq!(client_receipt.boundary, SendBoundary::TlsStreamFlushed);
            assert_eq!(client_receipt.record_bytes, 11);
            assert_eq!(client_receipt.framed_bytes, 16);
            assert_eq!(client_receipt.deadline, deadline);
            assert!(!client_receipt.late);
            assert_eq!(client_receipt.lane, 0);
            assert_eq!(server_receipt.lane, usize::from(duplex == Duplex::Half));
            let (client_control, server_control) = tokio::try_join!(
                poll_fn(|cx| client.poll_send(cx, &mut cb)),
                poll_fn(|cx| server.poll_send(cx, &mut sb))
            )?;
            assert_eq!(client_control.framed_bytes, 19);
            assert_eq!(client_control.lane, server_control.lane);
            let mut client_records = Vec::new();
            let mut server_records = Vec::new();
            for _ in 0..2 {
                let mut a = [0; 1024];
                let mut b = [0; 1024];
                let (ca, sb) = tokio::try_join!(
                    poll_fn(|cx| client.poll_receive(cx, &mut a)),
                    poll_fn(|cx| server.poll_receive(cx, &mut b))
                )?;
                assert_eq!(ca.framing, framing);
                assert_eq!(sb.framing, framing);
                client_records.push(a[..ca.bytes].to_vec());
                server_records.push(b[..sb.bytes].to_vec());
            }
            assert!(client_records.iter().any(|p| p == b"server user"));
            assert!(client_records.iter().any(|p| p == b"server control"));
            assert!(server_records.iter().any(|p| p == b"client user"));
            assert!(server_records.iter().any(|p| p == b"client control"));
        }
    }
    Ok(())
}

// Synthetic streams exercise only the private framing machine. Public construction
// remains restricted to actual member-authenticated original TCP/TLS connections.
pub(super) fn framing_pair(capacity: usize) -> io::Result<(Adapter, DuplexStream)> {
    let (local, peer) = tokio::io::duplex(capacity);
    let (reader, writer) = tokio::io::split(local);
    let session = SessionInfo {
        session_id: [1; 16],
        peer_member: None,
        member: l2tunnel_auth::MemberPublicKey([2; 32]),
        server: l2tunnel_auth::ServerIdentity([3; 32]),
        config: config(),
    };
    let link = Link {
        inner: crate::Link {
            managed_metadata: None,
            reader: Box::pin(reader),
            writer: Box::pin(writer),
            reverse_reader: None,
            reverse_writer: None,
            receive_session: session.session_id,
            send_session: session.session_id,
            layer: PacketLayer::Ethernet,
        },
        info: Info {
            first: LaneInfo {
                session,
                local_addr: "127.0.0.1:10000".parse().map_err(io::Error::other)?,
                peer_addr: "127.0.0.1:10001".parse().map_err(io::Error::other)?,
            },
            second: None,
            role: Role::Initiator,
            duplex: Duplex::Full,
        },
        setup_deadline: Instant::now() + Duration::from_secs(10),
    };
    Ok((adapter(link)?, peer))
}

#[tokio::test(start_paused = true)]
async fn retained_tls_partial_write_keeps_exact_bytes_token_and_original_cap() -> TestResult {
    let (mut adapter, mut peer) = framing_pair(3)?;
    let deadline = Instant::now() + Duration::from_millis(500);
    let body = [0xa5; 64];
    let mut token = adapter.try_send(Class::User, &body, deadline, Framing::Final)?;
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    assert!(adapter.poll_send(&mut cx, &mut token).is_pending());
    let offset = adapter.output[0].pending.as_ref().map(|p| p.offset);
    assert_eq!(offset, Some(3));
    let cap = adapter.next_deadline();
    for _ in 0..3 {
        tokio::time::advance(Duration::from_millis(10)).await;
        assert!(adapter.poll_send(&mut cx, &mut token).is_pending());
        assert_eq!(adapter.output[0].pending.as_ref().map(|p| p.offset), offset);
        assert_eq!(adapter.next_deadline(), cap);
    }
    let mut received = vec![0; body.len() + FRAMING_BYTES];
    let (receipt, _) = tokio::try_join!(
        poll_fn(|cx| adapter.poll_send(cx, &mut token)),
        peer.read_exact(&mut received)
    )?;
    assert_eq!(receipt.deadline, deadline);
    assert_eq!(received[..4], 65_u32.to_be_bytes());
    assert_eq!(received[4], Framing::Final.byte());
    assert_eq!(received[5..], body);
    assert!(
        matches!(adapter.poll_send(&mut cx, &mut token), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidInput)
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn retained_tls_partial_write_original_expiry_is_terminal_and_releases_stream() -> TestResult
{
    let (mut adapter, mut peer) = framing_pair(1)?;
    let deadline = Instant::now() + Duration::from_millis(20);
    let mut token = adapter.try_send(Class::User, &[9; 20], deadline, Framing::Final)?;
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    assert!(adapter.poll_send(&mut cx, &mut token).is_pending());
    assert_eq!(
        adapter.output[0].pending.as_ref().map(|p| p.offset),
        Some(1)
    );
    tokio::time::advance(Duration::from_millis(20)).await;
    assert!(
        matches!(adapter.poll_send(&mut cx, &mut token), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::TimedOut)
    );
    assert!(adapter.lanes.is_empty());
    assert_eq!(
        adapter.check_failure().err().map(|e| e.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    let mut remaining = Vec::new();
    peer.read_to_end(&mut remaining).await?;
    assert_eq!(remaining.len(), 1);
    assert_eq!(
        adapter
            .try_send(
                Class::Control,
                b"new",
                deadline + Duration::from_secs(1),
                Framing::Final
            )
            .err()
            .map(|e| e.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn retained_tls_partial_prefix_and_body_do_not_restart_receive_deadline() -> TestResult {
    let (mut adapter, mut peer) = framing_pair(64)?;
    let frame = [0, 0, 0, 4, 1, 7, 8, 9];
    peer.write_all(&frame[..2]).await?;
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut output = [0; 16];
    assert!(adapter.poll_receive(&mut cx, &mut output).is_pending());
    assert_eq!(adapter.earliest_input_at(), None);
    let deadline = adapter
        .next_deadline()
        .ok_or_else(|| invalid("missing partial input cap"))?;
    tokio::time::advance(Duration::from_millis(400)).await;
    peer.write_all(&frame[2..6]).await?;
    assert!(adapter.poll_receive(&mut cx, &mut output).is_pending());
    assert_eq!(adapter.lanes[0].input.prefix_used, FRAMING_BYTES);
    assert_eq!(adapter.lanes[0].input.body_used, 1);
    assert_eq!(adapter.next_deadline(), Some(deadline));
    tokio::time::advance(deadline - Instant::now()).await;
    assert!(
        matches!(adapter.poll_receive(&mut cx, &mut output), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::TimedOut)
    );
    assert!(adapter.lanes.is_empty());
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn retained_tls_completed_input_timestamp_is_read_only_until_delivery() -> TestResult {
    let (mut adapter, mut peer) = framing_pair(64)?;
    peer.write_all(&[0, 0, 0, 4, 1, 7, 8, 9]).await?;
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let observed = Instant::now();
    assert!(matches!(
        adapter.poll_progress(&mut cx),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(adapter.earliest_input_at(), Some(observed));
    let pending = adapter.lanes[0].input.body_used;
    tokio::time::advance(Duration::from_millis(20)).await;
    assert_eq!(adapter.earliest_input_at(), Some(observed));
    assert_eq!(adapter.lanes[0].input.body_used, pending);
    let mut output = [0; 16];
    let received = poll_fn(|cx| adapter.poll_receive(cx, &mut output)).await?;
    assert_eq!(received.received_at, observed);
    assert_eq!(&output[..received.bytes], &[7, 8, 9]);
    assert_eq!(adapter.earliest_input_at(), None);
    Ok(())
}

#[tokio::test]
async fn retained_tls_invalid_lengths_phase_and_partial_eof_release_before_delivery() -> TestResult
{
    for frame in [
        vec![0, 0, 0, 1, 1],
        vec![0, 0, 4, 2, 1],
        vec![0, 0, 0, 2, 2],
    ] {
        let (mut adapter, mut peer) = framing_pair(64)?;
        peer.write_all(&frame).await?;
        let mut output = [0; 1024];
        assert_eq!(
            poll_fn(|cx| adapter.poll_receive(cx, &mut output))
                .await
                .err()
                .map(|e| e.kind()),
            Some(io::ErrorKind::InvalidData)
        );
        assert!(adapter.lanes.is_empty());
    }
    let (mut adapter, mut peer) = framing_pair(64)?;
    peer.write_all(&[0, 0, 0, 5, 1, 7]).await?;
    drop(peer);
    let mut output = [0; 1024];
    assert_eq!(
        poll_fn(|cx| adapter.poll_receive(cx, &mut output))
            .await
            .err()
            .map(|e| e.kind()),
        Some(io::ErrorKind::UnexpectedEof)
    );
    assert!(adapter.lanes.is_empty());
    Ok(())
}

#[tokio::test]
async fn retained_tls_reserved_control_and_user_alternate_without_reframing_or_extra_slots()
-> TestResult {
    let (mut adapter, mut peer) = framing_pair(256)?;
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut user = adapter.try_send(Class::User, b"user", deadline, Framing::Final)?;
    let mut control = adapter.try_send(Class::Control, b"control1", deadline, Framing::Final)?;
    poll_fn(|cx| adapter.poll_send(cx, &mut control)).await?;
    let mut second = adapter.try_send(Class::Control, b"control2", deadline, Framing::Final)?;
    poll_fn(|cx| adapter.poll_send(cx, &mut user)).await?;
    poll_fn(|cx| adapter.poll_send(cx, &mut second)).await?;
    for expected in [b"control1".as_slice(), b"user", b"control2"] {
        let length = peer.read_u32().await? as usize;
        assert_eq!(length, expected.len() + 1);
        assert_eq!(peer.read_u8().await?, Framing::Final.byte());
        let mut bytes = vec![0; length - 1];
        peer.read_exact(&mut bytes).await?;
        assert_eq!(bytes, expected);
    }
    let actual = std::mem::size_of::<Adapter>()
        + adapter.lanes.capacity() * std::mem::size_of::<Lane>()
        + adapter
            .lanes
            .iter()
            .map(|lane| lane.input.bytes.capacity())
            .sum::<usize>()
        + adapter
            .output
            .iter()
            .map(|output| output.bytes.capacity())
            .sum::<usize>();
    assert_eq!(actual, adapter.plan().capacity_bytes());
    assert_eq!(adapter.plan().allocations(), 4);
    Ok(())
}

#[tokio::test]
async fn retained_tls_tokens_cannot_be_rebound_to_another_actual_adapter() -> TestResult {
    let (mut first, _peer_first) = framing_pair(64)?;
    let (mut second, _peer_second) = framing_pair(64)?;
    let mut token = first.try_send(
        Class::User,
        b"data",
        Instant::now() + Duration::from_secs(1),
        Framing::Final,
    )?;
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    assert!(
        matches!(second.poll_send(&mut cx, &mut token), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidInput)
    );
    assert!(!token.consumed);
    let receipt = poll_fn(|cx| first.poll_send(cx, &mut token)).await?;
    assert_eq!(receipt.record_bytes, 4);
    assert!(token.consumed);
    Ok(())
}
