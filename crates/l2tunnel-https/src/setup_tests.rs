use super::*;
use l2tunnel_device::PacketLayer;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
fn config() -> io::Result<Config> {
    Config::new(
        "lab.invalid",
        "/stream",
        SessionConfig {
            layer: PacketLayer::Ip,
            digest: ConfigDigest([6; 32]),
        },
        Duplex::Full,
        1024,
        Duration::from_secs(1),
        Duration::from_secs(10),
    )
}
#[tokio::test]
async fn ordinary_get_missing_malformed_nonmember_and_wrong_target_have_identical_http() -> Result {
    let cert = rcgen::generate_simple_self_signed(vec!["lab.invalid".into()])?;
    let chain = vec![cert.cert.der().to_vec()];
    let ct = ClientTls::from_der_roots(&chain)?;
    let st = ServerTls::from_der(&chain, &cert.signing_key.serialize_der())?;
    assert!(!ct.0.enable_sni);
    assert!(!ct.0.enable_early_data);
    assert_eq!(ct.0.alpn_protocols, [b"h2".to_vec()]);
    assert_eq!(st.config.alpn_protocols, [b"h2".to_vec()]);
    assert_eq!(st.config.send_tls13_tickets, 0);
    assert_eq!(st.config.max_early_data_size, 0);
    let allowed = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let stranger = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let members = MemberAllowlist::new(&[allowed.public_key()])?;
    let mut replies = Vec::new();
    for case in 0..8 {
        let (a, b) = tokio::io::duplex(256);
        let config = config()?;
        let deadline = Instant::now() + Duration::from_secs(2);
        let client = async {
            let tls: TlsStream<_> = TlsConnector::from(ct.0.clone())
                .connect(
                    ServerName::try_from("lab.invalid")
                        .map_err(io::Error::other)?
                        .to_owned(),
                    a,
                )
                .await?
                .into();
            let (binding, _) = binding(&tls, None)?;
            let proof = https_request::sign(
                if case == 3 { &stranger } else { &allowed },
                &binding,
                config.session,
                &config.request,
            )
            .map_err(io::Error::other)?;
            let mut builder = client_builder();
            if case == 5 {
                builder.initial_stream_id(3);
            }
            let (mut requests, mut driver) = builder
                .handshake::<_, Bytes>(tls)
                .await
                .map_err(io::Error::other)?;
            let mut request = http::Request::builder()
                .method(if case == 0 { "GET" } else { "POST" })
                .uri(if case == 4 {
                    "https://lab.invalid/wrong"
                } else {
                    "https://lab.invalid/stream"
                })
                .header(http::header::CONTENT_TYPE, "application/octet-stream");
            if case >= 2 {
                request = request.header(
                    http::header::AUTHORIZATION,
                    if case == 2 {
                        "Bearer bad".into()
                    } else {
                        encode(proof.as_bytes())
                    },
                );
            }
            if case == 6 {
                for name in [
                    "x-a", "x-b", "x-c", "x-d", "x-e", "x-f", "x-g", "x-h", "x-i",
                ] {
                    request = request.header(name, "bounded");
                }
            }
            if case == 7 {
                request = request.header(http::header::AUTHORIZATION, encode(proof.as_bytes()));
            }
            let (mut response, send) = requests
                .send_request(request.body(()).map_err(io::Error::other)?, true)
                .map_err(io::Error::other)?;
            assert_eq!(send.stream_id().as_u32(), if case == 5 { 3 } else { 1 });
            drop(send);
            drop(requests);
            let response = poll_fn(|cx| {
                if let Poll::Ready(Err(e)) = Pin::new(&mut driver).poll(cx) {
                    return Poll::Ready(Err(io::Error::other(e)));
                }
                Pin::new(&mut response).poll(cx).map_err(io::Error::other)
            })
            .await?;
            let (status, headers) = (response.status(), response.headers().clone());
            let mut recv = response.into_body();
            let mut bytes = Vec::new();
            loop {
                let data = poll_fn(|cx| {
                    if let Poll::Ready(Err(e)) = Pin::new(&mut driver).poll(cx) {
                        return Poll::Ready(Some(Err(e)));
                    }
                    recv.poll_data(cx)
                })
                .await;
                match data {
                    Some(Ok(chunk)) => {
                        bytes.extend_from_slice(&chunk);
                        recv.flow_control()
                            .release_capacity(chunk.len())
                            .map_err(io::Error::other)?;
                    }
                    Some(Err(e)) => return Err(io::Error::other(e)),
                    None => break,
                }
            }
            Ok::<_, io::Error>((status, headers, bytes))
        };
        let (c, s) = tokio::join!(
            bounded(deadline, client),
            server_full(b, &st, &members, config.clone(), deadline)
        );
        let reply = c?;
        assert_eq!(reply.0, http::StatusCode::NOT_FOUND);
        assert_eq!(reply.2, b"Not Found\n");
        assert!(s.is_err());
        replies.push(reply);
    }
    assert!(replies.windows(2).all(|p| p[0] == p[1]));
    Ok(())
}
#[tokio::test]
async fn wrong_alpn_and_untrusted_certificate_never_start_http_membership() -> Result {
    let cert = rcgen::generate_simple_self_signed(vec!["lab.invalid".into()])?;
    let chain = vec![cert.cert.der().to_vec()];
    let st = ServerTls::from_der(&chain, &cert.signing_key.serialize_der())?;
    let key = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let members = MemberAllowlist::new(&[key.public_key()])?;
    for wrong_alpn in [true, false] {
        let mut ct = ClientTls::from_der_roots(&chain)?;
        if wrong_alpn {
            Arc::make_mut(&mut ct.0).alpn_protocols = vec![b"http/1.1".to_vec()];
        } else {
            let other = rcgen::generate_simple_self_signed(vec!["lab.invalid".into()])?;
            ct = ClientTls::from_der_roots(&[other.cert.der().to_vec()])?;
        }
        let (a, b) = tokio::io::duplex(256);
        let deadline = Instant::now() + Duration::from_secs(2);
        let (c, s) = tokio::join!(
            client_full(
                a,
                &ct,
                ServerName::try_from("lab.invalid")?.to_owned(),
                &key,
                config()?,
                deadline
            ),
            server_full(b, &st, &members, config()?, deadline)
        );
        assert!(c.is_err());
        assert!(s.is_err());
    }
    Ok(())
}

#[tokio::test]
async fn original_setup_deadline_rejects_late_ready_actual_io() -> Result {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    struct Late {
        reads: Arc<AtomicUsize>,
    }
    impl AsyncRead for Late {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            out: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            std::thread::sleep(Duration::from_millis(25));
            out.put_slice(b"x");
            Poll::Ready(Ok(()))
        }
    }
    let reads = Arc::new(AtomicUsize::new(0));
    let mut io = Late {
        reads: reads.clone(),
    };
    let deadline = Instant::now() + Duration::from_millis(10);
    let result = bounded(deadline, async {
        let mut byte = [0];
        tokio::io::AsyncReadExt::read_exact(&mut io, &mut byte).await?;
        Ok(byte)
    })
    .await;
    assert_eq!(reads.load(Ordering::Relaxed), 1);
    assert_eq!(
        result.err().ok_or("accepted late-ready input")?.kind(),
        io::ErrorKind::TimedOut
    );
    Ok(())
}
