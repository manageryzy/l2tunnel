use super::*;
use bytes::Bytes;
use l2tunnel_auth::{
    CallerVerifiedChannel, ChannelTransport, MemberAllowlist, MemberKey, MemberPublicKey,
    ServerIdentity,
    https_request::{self, Attempt},
};
use ring::{
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
};
use std::{
    future::{Future, poll_fn},
    sync::Arc,
};
use tokio::time::{Instant, timeout_at};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};

/// Private verified TLS1.3 client policy: no SNI, resumption or early data; ALPNh2.
#[derive(Clone)]
pub struct ClientTls(Arc<ClientConfig>);
impl ClientTls {
    /// Trust DER roots while retaining normal certificate/name verification.
    pub fn from_der_roots(certs: &[Vec<u8>]) -> io::Result<Self> {
        validate_certs(certs, 64)?;
        let mut roots = RootCertStore::empty();
        for c in certs {
            roots
                .add(CertificateDer::from(c.clone()))
                .map_err(io::Error::other)?;
        }
        let mut c =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(io::Error::other)?
                .with_root_certificates(roots)
                .with_no_client_auth();
        c.enable_sni = false;
        c.enable_early_data = false;
        c.resumption = rustls::client::Resumption::disabled();
        c.alpn_protocols = vec![b"h2".to_vec()];
        Ok(Self(Arc::new(c)))
    }
}
/// Private TLS1.3 server policy: ALPNh2, no tickets/resumption/early data.
#[derive(Clone)]
pub struct ServerTls {
    config: Arc<ServerConfig>,
    identity: ServerIdentity,
}
impl ServerTls {
    /// Build validated leaf chain/key; membership follows verified HTTP admission.
    pub fn from_der(certs: &[Vec<u8>], key: &[u8]) -> io::Result<Self> {
        validate_certs(certs, 16)?;
        if key.is_empty() || key.len() > 65536 {
            return Err(invalid("HTTPS key length"));
        }
        let mut c =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(io::Error::other)?
                .with_no_client_auth()
                .with_single_cert(
                    certs.iter().cloned().map(CertificateDer::from).collect(),
                    PrivateKeyDer::try_from(key.to_vec()).map_err(|_| invalid("HTTPS key"))?,
                )
                .map_err(io::Error::other)?;
        c.max_early_data_size = 0;
        c.send_tls13_tickets = 0;
        c.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        c.alpn_protocols = vec![b"h2".to_vec()];
        let mut identity = [0; 32];
        identity.copy_from_slice(digest(&SHA256, &certs[0]).as_ref());
        Ok(Self {
            config: Arc::new(c),
            identity: ServerIdentity(identity),
        })
    }
}
fn validate_certs(certs: &[Vec<u8>], limit: usize) -> io::Result<()> {
    if certs.is_empty()
        || certs.len() > limit
        || certs.iter().any(|c| c.is_empty() || c.len() > 65536)
    {
        Err(invalid("HTTPS certificate bounds"))
    } else {
        Ok(())
    }
}
fn check_deadline(deadline: Instant) -> io::Result<()> {
    let now = Instant::now();
    if deadline <= now || deadline.duration_since(now) > Duration::from_secs(60) {
        Err(invalid(
            "HTTPS setup deadline must be future and within60seconds",
        ))
    } else {
        Ok(())
    }
}
fn mode(config: &Config, wanted: Duplex, deadline: Instant) -> io::Result<()> {
    check_deadline(deadline)?;
    if config.duplex != wanted {
        Err(invalid("HTTPS duplex factory mismatch"))
    } else {
        Ok(())
    }
}
async fn bounded<T>(
    deadline: Instant,
    future: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    if Instant::now() >= deadline {
        return Err(io::Error::from(io::ErrorKind::TimedOut));
    }
    let result = timeout_at(deadline, future)
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
    // timeout_at may observe an inner ready result from I/O that crossed the
    // original deadline within this poll. Late readiness cannot grant ownership.
    if Instant::now() >= deadline {
        return Err(io::Error::from(io::ErrorKind::TimedOut));
    }
    result
}
fn binding<I>(
    tls: &TlsStream<I>,
    server: Option<ServerIdentity>,
) -> io::Result<(CallerVerifiedChannel, Zeroizing<[u8; 32]>)> {
    let connection = tls.get_ref().1;
    if connection.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
        || connection.alpn_protocol() != Some(b"h2")
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "HTTPS TLS policy",
        ));
    }
    let identity = match server {
        Some(id) => id,
        None => {
            let certificate = connection
                .peer_certificates()
                .and_then(|c| c.first())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::PermissionDenied, "HTTPS certificate")
                })?;
            let mut hash = [0; 32];
            hash.copy_from_slice(digest(&SHA256, certificate.as_ref()).as_ref());
            ServerIdentity(hash)
        }
    };
    let exporter = export(tls, ChannelTransport::HttpsH2.exporter_label())?;
    let root = export(tls, b"EXPORTER-l2tunnel-https-h2-lane-join-v1")?;
    Ok((
        CallerVerifiedChannel::new_after_verification(
            ChannelTransport::HttpsH2,
            identity,
            exporter,
        ),
        Zeroizing::new(root),
    ))
}
fn export<I>(tls: &TlsStream<I>, label: &[u8]) -> io::Result<[u8; 32]> {
    match tls {
        TlsStream::Client(c) => c.get_ref().1.export_keying_material([0; 32], label, None),
        TlsStream::Server(c) => c.get_ref().1.export_keying_material([0; 32], label, None),
    }
    .map_err(io::Error::other)
}
fn client_builder() -> h2::client::Builder {
    let mut b = h2::client::Builder::new();
    b.header_table_size(4096)
        .initial_window_size(65535)
        .initial_connection_window_size(65535)
        .max_frame_size(16384)
        .max_header_list_size(4096)
        .max_concurrent_streams(1)
        .initial_max_send_streams(1)
        .max_send_buffer_size(32768)
        .max_concurrent_reset_streams(1)
        .max_local_error_reset_streams(Some(1))
        .max_pending_accept_reset_streams(1)
        .enable_push(false);
    b
}
fn server_builder() -> h2::server::Builder {
    let mut b = h2::server::Builder::new();
    b.header_table_size(4096)
        .initial_window_size(65535)
        .initial_connection_window_size(65535)
        .max_frame_size(16384)
        .max_header_list_size(4096)
        .max_concurrent_streams(1)
        .max_send_buffer_size(32768)
        .max_concurrent_reset_streams(1)
        .max_local_error_reset_streams(Some(1))
        .max_pending_accept_reset_streams(1);
    b
}
fn encode(proof: &[u8]) -> String {
    let mut value = String::with_capacity(7 + 2 * proof.len());
    value.push_str("Bearer ");
    const HEX: &[u8] = b"0123456789abcdef";
    for b in proof {
        value.push(HEX[(b >> 4) as usize] as char);
        value.push(HEX[(b & 15) as usize] as char);
    }
    value
}
fn decode(value: &http::HeaderValue) -> Option<[u8; https_request::PROOF_BYTES]> {
    let raw = value.as_bytes();
    if raw.len() != 7 + 2 * https_request::PROOF_BYTES || &raw[..7] != b"Bearer " {
        return None;
    }
    let mut result = [0; https_request::PROOF_BYTES];
    for (i, pair) in raw[7..].chunks_exact(2).enumerate() {
        let n = |b: u8| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        };
        result[i] = (n(pair[0])? << 4) | n(pair[1])?;
    }
    Some(result)
}
async fn client_lane<I: AsyncRead + AsyncWrite + Unpin>(
    io: I,
    tls: &ClientTls,
    name: ServerName<'static>,
    member: &MemberKey,
    config: &Config,
    deadline: Instant,
) -> io::Result<Lane<I>> {
    let tls: TlsStream<I> = TlsConnector::from(tls.0.clone())
        .connect(name, io)
        .await?
        .into();
    let (binding, root) = binding(&tls, None)?;
    let proof = https_request::sign(member, &binding, config.session, &config.request)
        .map_err(io::Error::other)?;
    let (tls, generation) = body::FlushIo::new(tls, true);
    let mut handshake = Box::pin(client_builder().handshake(tls));
    let (mut requests, mut driver) = poll_fn(|cx| {
        generation.reset();
        handshake.as_mut().poll(cx)
    })
    .await
    .map_err(io::Error::other)?;
    poll_fn(|cx| {
        generation.reset();
        match Pin::new(&mut driver).poll(cx) {
            Poll::Pending => {}
            Poll::Ready(Ok(())) => {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
        }
        requests.poll_ready(cx).map_err(io::Error::other)
    })
    .await?;
    let uri = format!(
        "https://{}{}",
        config.request.authority(),
        config.request.path()
    );
    let request = http::Request::builder()
        .method("POST")
        .uri(uri)
        .header(http::header::AUTHORIZATION, encode(proof.as_bytes()))
        .header(http::header::CONTENT_TYPE, "application/octet-stream")
        .body(())
        .map_err(io::Error::other)?;
    let (mut response, send) = requests
        .send_request(request, false)
        .map_err(io::Error::other)?;
    drop(requests);
    let response = poll_fn(|cx| {
        generation.reset();
        match Pin::new(&mut driver).poll(cx) {
            Poll::Pending => {}
            Poll::Ready(Ok(())) => {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
        }
        Pin::new(&mut response).poll(cx).map_err(io::Error::other)
    })
    .await?;
    if response.status() != http::StatusCode::OK
        || response.headers().len() > 8
        || response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .is_none_or(|v| v != "application/octet-stream")
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "HTTPS admission",
        ));
    }
    let mut body = body::Body::new(
        body::Driver::Client(driver, generation.clone()),
        send,
        response.into_body(),
        generation,
    );
    let info = l2tunnel_auth::client_authenticate_channel(
        &mut body,
        member,
        config.session,
        &binding,
        deadline.saturating_duration_since(Instant::now()),
    )
    .await
    .map_err(io::Error::other)?;
    Ok(Lane { body, info, root })
}
async fn ordinary<I: AsyncRead + AsyncWrite + Unpin>(
    mut driver: h2::server::Connection<body::FlushIo<TlsStream<I>>, Bytes>,
    mut response: h2::server::SendResponse<Bytes>,
    generation: Arc<body::Witness>,
) -> io::Result<Lane<I>> {
    let reply = http::Response::builder()
        .status(404)
        .header(http::header::CONTENT_TYPE, "text/plain")
        .header(http::header::CONTENT_LENGTH, "10")
        .body(())
        .map_err(io::Error::other)?;
    let mut send = response
        .send_response(reply, false)
        .map_err(io::Error::other)?;
    send.send_data(Bytes::from_static(b"Not Found\n"), true)
        .map_err(io::Error::other)?;
    driver.graceful_shutdown();
    // The original setup timeout bounds a peer that refuses to close; no tunnel
    // challenge or application handle is emitted on any rejection path.
    poll_fn(|cx| {
        generation.reset();
        driver.poll_closed(cx).map_err(io::Error::other)
    })
    .await?;
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "ordinary HTTPS request completed",
    ))
}
async fn server_lane<I: AsyncRead + AsyncWrite + Unpin>(
    io: I,
    tls: &ServerTls,
    members: &MemberAllowlist,
    config: &Config,
    deadline: Instant,
) -> io::Result<Lane<I>> {
    let identity = tls.identity;
    let tls: TlsStream<I> = TlsAcceptor::from(tls.config.clone())
        .accept(io)
        .await?
        .into();
    let (binding, root) = binding(&tls, Some(identity))?;
    let (tls, generation) = body::FlushIo::new(tls, false);
    let mut handshake = Box::pin(server_builder().handshake(tls));
    let mut driver = poll_fn(|cx| {
        generation.reset();
        handshake.as_mut().poll(cx)
    })
    .await
    .map_err(io::Error::other)?;
    let (request, mut response) = poll_fn(|cx| {
        generation.reset();
        driver.poll_accept(cx)
    })
    .await
    .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?
    .map_err(io::Error::other)?;
    let mut attempt = Attempt::default();
    let proof = request
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(decode);
    let candidate = proof.as_ref().map_or(&[][..], |p| &p[..]);
    let member = attempt.verify_once(
        candidate,
        members,
        &binding,
        config.session,
        &config.request,
    );
    let valid_target = request.body().stream_id().as_u32() == 1
        && request.method() == http::Method::POST
        && request.uri().scheme_str() == Some("https")
        && request.uri().authority().map(|a| a.as_str()) == Some(config.request.authority())
        && request.uri().path_and_query().map(|p| p.as_str()) == Some(config.request.path())
        && request.headers().len() <= 8
        && request
            .headers()
            .get_all(http::header::AUTHORIZATION)
            .iter()
            .count()
            == 1
        && request
            .headers()
            .get(http::header::CONTENT_TYPE)
            .is_some_and(|v| v == "application/octet-stream");
    let member: MemberPublicKey = match member {
        Ok(m) if valid_target => m,
        _ => return ordinary(driver, response, generation).await,
    };
    let reply = http::Response::builder()
        .status(200)
        .header(http::header::CONTENT_TYPE, "application/octet-stream")
        .body(())
        .map_err(io::Error::other)?;
    let send = response
        .send_response(reply, false)
        .map_err(io::Error::other)?;
    let mut body = body::Body::new(
        body::Driver::Server(driver, generation.clone()),
        send,
        request.into_body(),
        generation,
    );
    let info = l2tunnel_auth::server_authenticate_channel(
        &mut body,
        members,
        config.session,
        &binding,
        deadline.saturating_duration_since(Instant::now()),
    )
    .await
    .map_err(io::Error::other)?;
    if info.member != member {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "HTTPS membership binding",
        ));
    }
    Ok(Lane { body, info, root })
}
/// Complete actual verified TLS/HTTP/member setup on one original I/O.
/// Requires a Tokio timer driver; expiration/cancellation drops the original owner.
pub async fn client_full<I: AsyncRead + AsyncWrite + Unpin>(
    io: I,
    tls: &ClientTls,
    name: ServerName<'static>,
    member: &MemberKey,
    config: Config,
    deadline: Instant,
) -> io::Result<Session<I>> {
    mode(&config, Duplex::Full, deadline)?;
    bounded(deadline, async {
        let lane = client_lane(io, tls, name, member, &config, deadline).await?;
        Ok(Session::new(vec![lane], config, true))
    })
    .await
}
/// Serve one bounded ordinary request or one allowlisted streaming exchange.
/// All admission rejections share the ordinary404 reply and never issue a challenge.
pub async fn server_full<I: AsyncRead + AsyncWrite + Unpin>(
    io: I,
    tls: &ServerTls,
    members: &MemberAllowlist,
    config: Config,
    deadline: Instant,
) -> io::Result<Session<I>> {
    mode(&config, Duplex::Full, deadline)?;
    bounded(deadline, async {
        let lane = server_lane(io, tls, members, &config, deadline).await?;
        Ok(Session::new(vec![lane], config, false))
    })
    .await
}

fn join_bytes<I>(lanes: &[Lane<I>], nonce: &[u8; 32], config: &Config) -> io::Result<Vec<u8>> {
    if lanes.len() != 2
        || lanes[0].info.session_id == lanes[1].info.session_id
        || lanes[0].info.member != lanes[1].info.member
        || lanes[0].info.server != lanes[1].info.server
        || lanes.iter().any(|l| l.info.config != config.session)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "HTTPS lane identity",
        ));
    }
    let mut value = Vec::from(b"l2tunnel/https-h2-half-join/v1\0".as_slice());
    value.extend_from_slice(&config.session.digest.0);
    value.extend_from_slice(&lanes[0].info.member.0);
    value.extend_from_slice(&lanes[0].info.server.0);
    value.extend_from_slice(nonce);
    for l in lanes {
        value.extend_from_slice(&l.info.session_id);
    }
    Ok(value)
}
async fn exchange<I: AsyncRead + AsyncWrite + Unpin>(
    lanes: &mut [Lane<I>],
    messages: [Vec<u8>; 2],
    length: usize,
) -> io::Result<[Vec<u8>; 2]> {
    let mut sent = [0usize; 2];
    let mut read = [0usize; 2];
    let mut replies = [vec![0; length], vec![0; length]];
    poll_fn(|cx| {
        for i in 0..2 {
            lanes[i].body.driver.poll(cx)?;
            if sent[i] < messages[i].len()
                && let Poll::Ready(n) =
                    Pin::new(&mut lanes[i].body).poll_write(cx, &messages[i][sent[i]..])
            {
                let n = n?;
                if n == 0 {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                }
                sent[i] += n;
                cx.waker().wake_by_ref();
            }
            if read[i] < length {
                let mut b = ReadBuf::new(&mut replies[i][read[i]..]);
                if let Poll::Ready(result) = Pin::new(&mut lanes[i].body).poll_read(cx, &mut b) {
                    result?;
                    read[i] += b.filled().len();
                    cx.waker().wake_by_ref();
                }
            }
        }
        let mut flushed = true;
        for lane in lanes.iter_mut() {
            match Pin::new(&mut lane.body).poll_flush(cx) {
                Poll::Pending => flushed = false,
                Poll::Ready(result) => result?,
            }
        }
        if flushed
            && sent.iter().zip(&messages).all(|(s, m)| *s == m.len())
            && read.iter().all(|n| *n == length)
        {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    })
    .await?;
    Ok(replies)
}
async fn half_join<I: AsyncRead + AsyncWrite + Unpin>(
    lanes: &mut [Lane<I>],
    config: &Config,
    client: bool,
) -> io::Result<()> {
    let mut nonce = [0; 32];
    if !client {
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| io::Error::other("HTTPS random"))?;
    }
    let offered = if client {
        [Vec::new(), Vec::new()]
    } else {
        [nonce.to_vec(), nonce.to_vec()]
    };
    let reply = exchange(lanes, offered, if client { 32 } else { 0 }).await?;
    if client {
        if reply[0] != reply[1] {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "HTTPS join nonce",
            ));
        }
        nonce.copy_from_slice(&reply[0]);
    }
    let transcript = join_bytes(lanes, &nonce, config)?;
    let proofs = std::array::from_fn(|i| {
        let mut t = transcript.clone();
        t.extend_from_slice(&[i as u8, if client { 1 } else { 2 }]);
        hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &lanes[i].root[..]), &t)
            .as_ref()
            .to_vec()
    });
    let peer = exchange(lanes, proofs, 32).await?;
    for (i, proof) in peer.iter().enumerate() {
        let mut t = transcript.clone();
        t.extend_from_slice(&[i as u8, if client { 2 } else { 1 }]);
        hmac::verify(
            &hmac::Key::new(hmac::HMAC_SHA256, &lanes[i].root[..]),
            &t,
            proof,
        )
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "HTTPS join proof"))?;
    }
    // Confirm peer verified the same all-lane proof before either releases bulk.
    let confirm = std::array::from_fn(|i| {
        let mut t = transcript.clone();
        t.extend_from_slice(&[i as u8, if client { 3 } else { 4 }]);
        hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &lanes[i].root[..]), &t)
            .as_ref()
            .to_vec()
    });
    let peer = exchange(lanes, confirm, 32).await?;
    for (i, proof) in peer.iter().enumerate() {
        let mut t = transcript.clone();
        t.extend_from_slice(&[i as u8, if client { 4 } else { 3 }]);
        hmac::verify(
            &hmac::Key::new(hmac::HMAC_SHA256, &lanes[i].root[..]),
            &t,
            proof,
        )
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "HTTPS join confirmation"))?;
    }
    Ok(())
}
async fn both<I: AsyncRead + AsyncWrite + Unpin, F: Future<Output = io::Result<Lane<I>>>>(
    a: F,
    b: F,
) -> io::Result<Vec<Lane<I>>> {
    let mut a = Box::pin(a);
    let mut b = Box::pin(b);
    let mut lanes = [None, None];
    poll_fn(|cx| {
        if lanes[0].is_none()
            && let Poll::Ready(result) = a.as_mut().poll(cx)
        {
            lanes[0] = Some(result?);
        }
        if lanes[1].is_none()
            && let Poll::Ready(result) = b.as_mut().poll(cx)
        {
            lanes[1] = Some(result?);
        }
        for lane in lanes.iter_mut().flatten() {
            lane.body.driver.poll(cx)?;
        }
        if lanes.iter().all(Option::is_some) {
            Poll::Ready(Ok::<(), io::Error>(()))
        } else {
            Poll::Pending
        }
    })
    .await?;
    lanes
        .into_iter()
        .map(|l| l.ok_or_else(|| io::Error::other("HTTPS lane completion")))
        .collect()
}
/// Authenticate and join two original client TLS/HTTP owners within one deadline.
pub async fn client_half<I: AsyncRead + AsyncWrite + Unpin>(
    ios: [I; 2],
    tls: &ClientTls,
    name: ServerName<'static>,
    member: &MemberKey,
    config: Config,
    deadline: Instant,
) -> io::Result<Session<I>> {
    mode(&config, Duplex::Half, deadline)?;
    bounded(deadline, async {
        let [a, b] = ios;
        let mut lanes = both(
            client_lane(a, tls, name.clone(), member, &config, deadline),
            client_lane(b, tls, name, member, &config, deadline),
        )
        .await?;
        half_join(&mut lanes, &config, true).await?;
        Ok(Session::new(lanes, config, true))
    })
    .await
}
/// Authenticate and join two original server TLS/HTTP owners within one deadline.
pub async fn server_half<I: AsyncRead + AsyncWrite + Unpin>(
    ios: [I; 2],
    tls: &ServerTls,
    members: &MemberAllowlist,
    config: Config,
    deadline: Instant,
) -> io::Result<Session<I>> {
    mode(&config, Duplex::Half, deadline)?;
    bounded(deadline, async {
        let [a, b] = ios;
        let mut lanes = both(
            server_lane(a, tls, members, &config, deadline),
            server_lane(b, tls, members, &config, deadline),
        )
        .await?;
        half_join(&mut lanes, &config, false).await?;
        Ok(Session::new(lanes, config, false))
    })
    .await
}

#[cfg(test)]
#[path = "setup_tests.rs"]
mod tests;
