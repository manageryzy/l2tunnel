use super::*;
use l2tunnel_auth::{MemberAllowlist, MemberKey};
use l2tunnel_device::PacketLayer;
use rustls::pki_types::ServerName;
use std::{future::poll_fn, task::Poll};
use tokio::{
    io::duplex,
    time::{Instant, timeout},
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
fn fixture() -> Result<(ClientTls, ServerTls, MemberKey, MemberAllowlist)> {
    let cert = rcgen::generate_simple_self_signed(vec!["lab.invalid".into()])?;
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
fn config(duplex: Duplex) -> io::Result<Config> {
    Config::new(
        "lab.invalid",
        "/stream",
        SessionConfig {
            layer: PacketLayer::Ip,
            digest: ConfigDigest([6; 32]),
        },
        duplex,
        16384,
        Duration::from_secs(2),
        Duration::from_secs(10),
    )
}
#[tokio::test]
async fn original_tls_http_full_half_exchange_exact_records() -> Result {
    for mode in [Duplex::Full, Duplex::Half] {
        for capacity in [256, 65536] {
            let (ct, st, key, members) = fixture()?;
            let config = config(mode)?;
            let deadline = Instant::now() + Duration::from_secs(5);
            let name = ServerName::try_from("lab.invalid")?.to_owned();
            let (a, b) = duplex(capacity);
            let (c, d) = duplex(capacity);
            let (mut client, mut server) = if mode == Duplex::Full {
                let (c, s) = tokio::join!(
                    client_full(a, &ct, name, &key, config.clone(), deadline),
                    server_full(b, &st, &members, config, deadline)
                );
                (c?, s?)
            } else {
                let (c, s) = tokio::join!(
                    client_half([a, c], &ct, name, &key, config.clone(), deadline),
                    server_half([b, d], &st, &members, config, deadline)
                );
                (c?, s?)
            };
            assert_eq!(
                client.info().count(),
                if mode == Duplex::Full { 1 } else { 2 }
            );
            let first = vec![23; 16384];
            let second = vec![77; 12001];
            client.stage_record(&first)?;
            server.stage_record(&second)?;
            timeout(
                Duration::from_secs(3),
                poll_fn(|cx| {
                    for side in [&mut client, &mut server] {
                        if let Poll::Ready(result) = side.poll_progress(cx) {
                            result?;
                        }
                    }
                    if client.record().is_some() && server.record().is_some() {
                        Poll::Ready(Ok::<(), io::Error>(()))
                    } else {
                        Poll::Pending
                    }
                }),
            )
            .await??;
            assert_eq!(client.record(), Some(second.as_slice()));
            assert_eq!(server.record(), Some(first.as_slice()));
            assert!(
                client
                    .lanes
                    .as_ref()
                    .is_some_and(|l| l[client.receive_lane()].body.held == second.len() + 4)
            );
            client.consume_record()?;
            server.consume_record()?;
            assert_eq!(
                client
                    .lanes
                    .as_ref()
                    .map(|l| l[client.receive_lane()].body.held),
                Some(0)
            );
        }
    }
    Ok(())
}
#[tokio::test]
async fn wrong_certificate_name_or_configuration_drops_original_tls() -> Result {
    for wrong_name in [false, true] {
        let (ct, st, key, members) = fixture()?;
        let (a, b) = duplex(4096);
        let deadline = Instant::now() + Duration::from_secs(1);
        let client = config(Duplex::Full)?;
        let mut server = client.clone();
        if !wrong_name {
            server.session.digest = ConfigDigest([9; 32]);
        }
        let name = ServerName::try_from(if wrong_name {
            "wrong.invalid"
        } else {
            "lab.invalid"
        })?
        .to_owned();
        let (c, s) = tokio::join!(
            client_full(a, &ct, name, &key, client, deadline),
            server_full(b, &st, &members, server, deadline)
        );
        assert!(c.is_err());
        assert!(s.is_err());
    }
    Ok(())
}
#[tokio::test]
async fn expired_deadline_and_invalid_configuration_never_poll_input() -> Result {
    struct Never;
    impl AsyncRead for Never {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::other("unexpected IO")))
        }
    }
    impl AsyncWrite for Never {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::Error::other("unexpected IO")))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::other("unexpected IO")))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::other("unexpected IO")))
        }
    }
    let (ct, _, key, _) = fixture()?;
    let e = client_full(
        Never,
        &ct,
        ServerName::try_from("lab.invalid")?.to_owned(),
        &key,
        config(Duplex::Full)?,
        Instant::now(),
    )
    .await
    .err()
    .ok_or("accepted expired setup")?;
    assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
    let base = config(Duplex::Full)?.session;
    for size in [0, 16385, usize::MAX] {
        assert!(
            Config::new(
                "lab.invalid",
                "/stream",
                base,
                Duplex::Full,
                size,
                Duration::from_secs(1),
                Duration::from_secs(10)
            )
            .is_err()
        );
    }
    Ok(())
}

async fn pair(
    mode: Duplex,
) -> Result<(
    Session<tokio::io::DuplexStream>,
    Session<tokio::io::DuplexStream>,
)> {
    let (ct, st, key, members) = fixture()?;
    let config = config(mode)?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let (a, b) = duplex(256);
    let (c, d) = duplex(256);
    let name = ServerName::try_from("lab.invalid")?.to_owned();
    let (c, s) = if mode == Duplex::Full {
        tokio::join!(
            client_full(a, &ct, name, &key, config.clone(), deadline),
            server_full(b, &st, &members, config, deadline)
        )
    } else {
        tokio::join!(
            client_half([a, c], &ct, name, &key, config.clone(), deadline),
            server_half([b, d], &st, &members, config, deadline)
        )
    };
    Ok((c?, s?))
}
#[tokio::test]
async fn malformed_length_wrong_half_lane_reset_and_eof_fail_closed() -> Result {
    for case in 0..4 {
        let mode = if case == 1 {
            Duplex::Half
        } else {
            Duplex::Full
        };
        let (mut client, mut server) = pair(mode).await?;
        if case == 3 {
            drop(client);
        } else {
            let lane = usize::from(case == 1);
            let body = &mut client.lanes.as_mut().ok_or("missing client")?[lane].body;
            if case == 2 {
                body.send.send_reset(h2::Reason::CANCEL);
            } else {
                body.send
                    .send_data(bytes::Bytes::from_static(&[255; 4]), false)?;
            }
            poll_fn(|cx| {
                for _ in 0..4 {
                    if let Poll::Ready(Err(_)) = client.poll_progress(cx) {
                        break;
                    }
                }
                Poll::Ready(())
            })
            .await;
            // Keep the original driver running while the recipient sees the bad bytes.
            let result = timeout(
                Duration::from_secs(1),
                poll_fn(|cx| {
                    let _ = client.poll_progress(cx);
                    match server.poll_progress(cx) {
                        Poll::Ready(Err(e)) => Poll::Ready(e),
                        _ => Poll::Pending,
                    }
                }),
            )
            .await?;
            assert!(matches!(
                result.kind(),
                io::ErrorKind::InvalidData | io::ErrorKind::Other | io::ErrorKind::UnexpectedEof
            ));
            assert!(server.stopped());
            continue;
        }
        let e = timeout(
            Duration::from_secs(1),
            poll_fn(|cx| match server.poll_progress(cx) {
                Poll::Ready(Err(e)) => Poll::Ready(e),
                _ => Poll::Pending,
            }),
        )
        .await?;
        assert!(matches!(
            e.kind(),
            io::ErrorKind::Other | io::ErrorKind::UnexpectedEof
        ));
        assert!(server.stopped());
    }
    Ok(())
}
#[tokio::test]
async fn stalled_receiver_keeps_actual_http_window_used_and_consumption_reopens_it() -> Result {
    let (mut client, mut server) = pair(Duplex::Full).await?;
    let body = vec![99; 16384];
    let mut staged = 0;
    timeout(
        Duration::from_secs(1),
        poll_fn(|cx| {
            if client.out.is_none() && staged < 6 {
                client.stage_record(&body)?;
                staged += 1;
            }
            for s in [&mut client, &mut server] {
                if let Poll::Ready(result) = s.poll_progress(cx) {
                    result?;
                }
            }
            let capacity = server
                .lanes
                .as_mut()
                .ok_or_else(|| io::Error::other("server stopped"))?[0]
                .body
                .recv
                .flow_control()
                .used_capacity();
            if capacity >= 60000 && client.out.is_some() {
                Poll::Ready(Ok::<(), io::Error>(()))
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }),
    )
    .await??;
    assert_eq!(server.record(), Some(body.as_slice()));
    let held = server.lanes.as_ref().ok_or("stopped")?[0].body.held;
    assert_eq!(held, body.len() + 4);
    for _ in 0..4 {
        poll_fn(|cx| {
            let _ = client.poll_progress(cx);
            let _ = server.poll_progress(cx);
            Poll::Ready(())
        })
        .await;
        assert_eq!(server.lanes.as_ref().ok_or("stopped")?[0].body.held, held);
    }
    let mut consumed = 0;
    timeout(
        Duration::from_secs(1),
        poll_fn(|cx| {
            for s in [&mut client, &mut server] {
                if let Poll::Ready(result) = s.poll_progress(cx) {
                    result?;
                }
            }
            if server.record().is_some() {
                assert_eq!(server.record(), Some(body.as_slice()));
                server.consume_record()?;
                consumed += 1;
            }
            if client.out.is_none() && consumed == staged {
                Poll::Ready(Ok::<(), io::Error>(()))
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }),
    )
    .await??;
    Ok(())
}
#[tokio::test]
async fn cancellation_and_partial_half_expiry_drop_every_original_owner() -> Result {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    struct Owned {
        io: tokio::io::DuplexStream,
        drops: Arc<AtomicUsize>,
    }
    impl Drop for Owned {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }
    impl AsyncRead for Owned {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            b: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.io).poll_read(cx, b)
        }
    }
    impl AsyncWrite for Owned {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            b: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.io).poll_write(cx, b)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.io).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.io).poll_shutdown(cx)
        }
    }
    let (ct, _, key, _) = fixture()?;
    for cancel in [true, false] {
        let drops = Arc::new(AtomicUsize::new(0));
        let (a, _b) = duplex(64);
        let (c, _d) = duplex(64);
        let ios = [
            Owned {
                io: a,
                drops: drops.clone(),
            },
            Owned {
                io: c,
                drops: drops.clone(),
            },
        ];
        let future = client_half(
            ios,
            &ct,
            ServerName::try_from("lab.invalid")?.to_owned(),
            &key,
            config(Duplex::Half)?,
            Instant::now() + Duration::from_millis(20),
        );
        let mut future = Box::pin(future);
        if cancel {
            poll_fn(|cx| {
                assert!(future.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
        } else {
            let result = future.as_mut().await;
            assert_eq!(
                result.err().ok_or("unexpected accepted owners")?.kind(),
                io::ErrorKind::TimedOut
            );
        }
        drop(future);
        assert_eq!(drops.load(Ordering::Relaxed), 2);
    }
    Ok(())
}
#[tokio::test]
async fn swapped_original_half_lane_order_cannot_join() -> Result {
    let (ct, st, key, members) = fixture()?;
    let config = config(Duplex::Half)?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let (a, b) = duplex(256);
    let (c, d) = duplex(256);
    let (c, s) = tokio::join!(
        client_half(
            [a, c],
            &ct,
            ServerName::try_from("lab.invalid")?.to_owned(),
            &key,
            config.clone(),
            deadline
        ),
        server_half([d, b], &st, &members, config, deadline)
    );
    assert!(c.is_err());
    assert!(s.is_err());
    Ok(())
}

#[tokio::test]
async fn expired_lease_or_operation_cannot_stage_or_consume_records() -> Result {
    for operation in [false, true] {
        let (mut client, _server) = pair(Duplex::Full).await?;
        if operation {
            client.operation = Some(Box::pin(tokio::time::sleep(Duration::from_secs(1))));
            client
                .operation
                .as_mut()
                .ok_or("timer")?
                .as_mut()
                .reset(Instant::now());
        } else {
            client.lease.as_mut().reset(Instant::now());
        }
        assert_eq!(
            client.stage_record(b"late").err().map(|e| e.kind()),
            Some(io::ErrorKind::TimedOut)
        );
        assert!(client.stopped());
    }
    let (mut client, mut server) = pair(Duplex::Full).await?;
    client.stage_record(b"held record")?;
    timeout(
        Duration::from_secs(1),
        poll_fn(|cx| {
            let _ = client.poll_progress(cx);
            if let Poll::Ready(Err(e)) = server.poll_progress(cx) {
                return Poll::Ready(Err(e));
            }
            if server.record().is_some() {
                Poll::Ready(Ok::<(), io::Error>(()))
            } else {
                Poll::Pending
            }
        }),
    )
    .await??;
    // A complete unconsumed record retains receive credit and is lease-bounded;
    // local staging/partial-record operation timers make no peer delivery claim.
    assert!(server.operation.is_none());
    server.lease.as_mut().reset(Instant::now());
    assert_eq!(
        server.consume_record().err().map(|e| e.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    assert!(server.stopped());
    Ok(())
}
#[tokio::test]
async fn maintained_tcp_socket_continues_tls_http_data_on_original_connections() -> Result {
    use tokio::net::{TcpListener, TcpStream};
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    for mode in [Duplex::Full, Duplex::Half] {
        let (ct, st, key, members) = fixture()?;
        let config = config(mode)?;
        let deadline = Instant::now() + Duration::from_secs(3);
        let (a, b) = tokio::join!(TcpStream::connect(address), listener.accept());
        let (a, b) = (a?, b?.0);
        let (c, d) = tokio::join!(TcpStream::connect(address), listener.accept());
        let (c, d) = (c?, d?.0);
        assert_eq!(a.local_addr()?, b.peer_addr()?);
        assert_eq!(c.local_addr()?, d.peer_addr()?);
        let name = ServerName::try_from("lab.invalid")?.to_owned();
        let (c, s) = if mode == Duplex::Full {
            tokio::join!(
                client_full(a, &ct, name, &key, config.clone(), deadline),
                server_full(b, &st, &members, config, deadline)
            )
        } else {
            tokio::join!(
                client_half([a, c], &ct, name, &key, config.clone(), deadline),
                server_half([b, d], &st, &members, config, deadline)
            )
        };
        let (mut client, mut server) = (c?, s?);
        client.stage_record(b"client original TCP TLS HTTP2 DATA")?;
        server.stage_record(b"server original TCP TLS HTTP2 DATA")?;
        timeout(
            Duration::from_secs(1),
            poll_fn(|cx| {
                for side in [&mut client, &mut server] {
                    if let Poll::Ready(result) = side.poll_progress(cx) {
                        result?;
                    }
                }
                if client.record().is_some() && server.record().is_some() {
                    Poll::Ready(Ok::<(), io::Error>(()))
                } else {
                    Poll::Pending
                }
            }),
        )
        .await??;
        assert_eq!(
            client.record(),
            Some(b"server original TCP TLS HTTP2 DATA".as_slice())
        );
        assert_eq!(
            server.record(),
            Some(b"client original TCP TLS HTTP2 DATA".as_slice())
        );
    }
    Ok(())
}
#[tokio::test]
async fn shutdown_pending_retry_emits_end_stream_once() -> Result {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    struct Gate {
        io: tokio::io::DuplexStream,
        blocked: Arc<AtomicBool>,
    }
    impl AsyncRead for Gate {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            out: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.io).poll_read(cx, out)
        }
    }
    impl AsyncWrite for Gate {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.io).poll_write(cx, data)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.blocked.load(Ordering::Relaxed) {
                Poll::Pending
            } else {
                Pin::new(&mut self.io).poll_flush(cx)
            }
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.io).poll_shutdown(cx)
        }
    }
    let (ct, st, key, members) = fixture()?;
    let config = config(Duplex::Full)?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let (a, b) = duplex(256);
    let blocked = Arc::new(AtomicBool::new(false));
    let (c, s) = tokio::join!(
        client_full(
            Gate {
                io: a,
                blocked: blocked.clone()
            },
            &ct,
            ServerName::try_from("lab.invalid")?.to_owned(),
            &key,
            config.clone(),
            deadline
        ),
        server_full(
            Gate {
                io: b,
                blocked: Arc::new(AtomicBool::new(false))
            },
            &st,
            &members,
            config,
            deadline
        )
    );
    let (mut client, mut server) = (c?, s?);
    blocked.store(true, Ordering::Relaxed);
    poll_fn(|cx| {
        assert!(
            Pin::new(
                &mut client
                    .lanes
                    .as_mut()
                    .ok_or_else(|| io::Error::other("client"))?[0]
                    .body
            )
            .poll_shutdown(cx)
            .is_pending()
        );
        Poll::Ready(Ok::<(), io::Error>(()))
    })
    .await?;
    blocked.store(false, Ordering::Relaxed);
    timeout(
        Duration::from_secs(1),
        poll_fn(|cx| {
            server
                .lanes
                .as_mut()
                .ok_or_else(|| io::Error::other("server"))?[0]
                .body
                .driver
                .poll(cx)?;
            Pin::new(
                &mut client
                    .lanes
                    .as_mut()
                    .ok_or_else(|| io::Error::other("client"))?[0]
                    .body,
            )
            .poll_shutdown(cx)
        }),
    )
    .await??;
    Ok(())
}
