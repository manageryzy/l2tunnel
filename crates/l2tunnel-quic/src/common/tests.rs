use super::*;
use l2tunnel_core::ConfigDigest;
use l2tunnel_device::PacketLayer;
use std::{future::poll_fn, time::Duration};

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

#[test]
fn peer_close_classification_excludes_errors_and_local_shutdown() {
    let application = |code| {
        quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
            error_code: quinn::VarInt::from_u32(code),
            reason: bytes::Bytes::new(),
        })
    };
    assert!(normal_peer_close(&application(0)));
    for error in [
        application(1),
        quinn::ConnectionError::Reset,
        quinn::ConnectionError::TimedOut,
        quinn::ConnectionError::LocallyClosed,
    ] {
        assert!(!normal_peer_close(&error));
    }
}

fn base() -> SessionConfig {
    SessionConfig {
        layer: PacketLayer::Ip,
        digest: ConfigDigest([73; 32]),
    }
}
fn profile() -> Profile {
    let mut profile = Profile::new(*b"test-common-quic");
    profile.datagram_format = DatagramFormat::CommonCompact;
    profile.max_datagram_bytes = 1072;
    profile.queued_datagrams = 1;
    profile
}
async fn connections(
    profiles: &[Profile],
) -> Result<Vec<(AuthenticatedConnection, AuthenticatedConnection)>, TestError> {
    let cert = rcgen::generate_simple_self_signed(vec!["common.quic.test".to_owned()])?;
    let chain = vec![cert.cert.der().to_vec()];
    let private = cert.signing_key.serialize_der();
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let members = MemberAllowlist::new(&[member.public_key()])?;
    let mut connections = Vec::new();
    for &profile in profiles {
        let limits = EndpointLimits::default();
        let client = ClientEndpoint::bind(
            "127.0.0.1:0".parse()?,
            &ClientConfig::from_der_roots(&chain, profile, limits)?,
        )?;
        let server = ServerEndpoint::bind(
            "127.0.0.1:0".parse()?,
            &ServerConfig::from_der(&chain, &private, profile, limits)?,
        )?;
        let (a, b) = tokio::try_join!(
            client.connect(server.local_addr()?, "common.quic.test", &member, base()),
            server.accept(&members, base()),
        )?;
        connections.push((a, b));
    }
    Ok(connections)
}
async fn receive(carrier: &mut Carrier) -> Result<Received, TestError> {
    Ok(timeout(
        Duration::from_secs(2),
        poll_fn(|cx| carrier.poll_recv_framed(cx)),
    )
    .await??)
}

#[test]
fn selected_profile_binds_wire_and_recalculates_tiny_record_queue_bound() -> TestResult {
    let selected = profile();
    let mut legacy = selected;
    legacy.datagram_format = DatagramFormat::Legacy;
    legacy.max_datagram_bytes = 1024;
    let mut same_geometry = legacy;
    same_geometry.datagram_format = DatagramFormat::CommonCompact;
    assert_ne!(
        session_config(base(), legacy)?,
        session_config(base(), same_geometry)?
    );
    assert_eq!(selected.maximum_carrier_bytes(), 1072);
    assert_eq!(selected.maximum_bootstrap_bytes(), 1024);
    assert_eq!(selected.datagram_queue_bytes()?, 1136);
    assert_eq!(selected.maximum_queued_send_entries()?, 127);
    assert_eq!(legacy.maximum_queued_send_entries()?, 24);
    let mut impossible = selected;
    impossible.max_datagram_bytes = 1073;
    assert!(impossible.validate().is_err());
    impossible.max_datagram_bytes = usize::MAX;
    assert!(impossible.validate().is_err());
    assert_eq!(impossible.maximum_carrier_bytes(), usize::MAX);
    Ok(())
}

#[tokio::test]
async fn common_outgoing_fifo_backpressures_before_large_user_queue_hides_control() -> TestResult {
    let mut profile = profile();
    profile.queued_datagrams = 1024;
    let (a, b) = connections(&[profile])
        .await?
        .pop()
        .ok_or("missing connection")?;
    let original = Instant::now() + Duration::from_secs(4);
    let mut a = Carrier::new(a, profile, base(), original)?;
    let mut b = Carrier::new(b, profile, base(), original)?;
    a.select_final_records(original)?;
    b.select_final_records(original)?;
    let geometry = a.geometry();
    assert_eq!(geometry.maintained_queue_bytes, (1072 + 64) * 1024);
    assert_eq!(geometry.maintained_send_queue_bytes, (1072 + 64) * 2);
    let body = vec![0x80; 1072];
    let mut context = Context::from_waker(std::task::Waker::noop());
    // Current-thread polling deliberately gives Quinn no background transmit
    // turn. Old code accepts this entire user burst into its large hidden FIFO.
    for _ in 0..2 {
        let mut ticket = a.try_send(Class::User, &body, original, Framing::Final)?;
        assert!(matches!(
            Pin::new(&mut ticket).poll(&mut context),
            Poll::Ready(Ok(_))
        ));
    }
    let mut held = a.try_send(Class::User, &body, original, Framing::Final)?;
    assert!(Pin::new(&mut held).poll(&mut context).is_pending());
    assert_eq!(a.acceptance_status()?.accepted_datagrams, 2);
    assert_eq!(held.deadline(), original);
    drop(held);
    let control = [0x80; 21];
    a.try_send(Class::Control, &control, original, Framing::Final)?
        .await?;
    assert_eq!(receive(&mut b).await?.bytes, body);
    assert_eq!(receive(&mut b).await?.bytes, body);
    assert_eq!(receive(&mut b).await?.bytes, control);
    assert_eq!(a.acceptance_status()?.accepted_datagrams, 3);
    assert_eq!(
        a.acceptance_status()?.accepted_record_bytes,
        (1072 * 2 + 21) as u64
    );
    Ok(())
}

#[test]
fn selected_final_namespace_accepts_all_strong_reader_slots_without_bootstrap_overlap() {
    for route in u8::MIN..=u8::MAX {
        let mut record = [0; 21];
        record[0] = route;
        assert_eq!(
            final_prefix(&record),
            matches!(route, 0..=23 | 80..=121 | 128..=255)
        );
        assert!(!final_prefix(&record[..8]));
    }
    let mut bootstrap = [0; 48];
    bootstrap[..4].copy_from_slice(b"L2QD");
    assert!(!final_prefix(&bootstrap));
}

#[tokio::test]
async fn real_quic_selected_handoff_preserves_framing_custody_and_actual_connection() -> TestResult
{
    let profile = profile();
    let (a, b) = connections(&[profile])
        .await?
        .pop()
        .ok_or("missing connection")?;
    let endpoint = (a.local_addr()?, a.peer_addr());
    let original = Instant::now() + Duration::from_secs(4);
    let mut a = Carrier::new(a, profile, base(), original)?;
    let mut b = Carrier::new(b, profile, base(), original)?;
    let bootstrap = [0x80, 3, 0, 0, 0, 0, 0, 0, 0];
    assert!(
        a.try_send(Class::User, &bootstrap, original, Framing::Final)
            .is_err()
    );
    let pending = a.try_send(Class::Control, &bootstrap, original, Framing::Bootstrap)?;
    assert_eq!(a.acceptance_status()?.accepted_datagrams, 0);
    assert!(
        matches!(a.try_send(Class::Control, &bootstrap, original, Framing::Bootstrap),
        Err(Error::Io(error)) if error.kind() == io::ErrorKind::WouldBlock)
    );
    let receipt = pending.await?;
    assert_eq!(receipt.record_bytes, 9);
    assert_eq!(receipt.carrier_bytes, 57);
    assert_eq!(receipt.charged_bytes, 213);
    assert_eq!(receipt.deadline, original);
    let received = receive(&mut b).await?;
    assert_eq!(received.framing, Framing::Bootstrap);
    assert_eq!(received.bytes, bootstrap);

    a.select_final_records(original)?;
    b.select_final_records(original)?;
    assert!(a.select_final_records(original).is_err());
    let pending = a.try_send(Class::User, &bootstrap, original, Framing::Final)?;
    let independent = a.try_send(Class::Control, &bootstrap, original, Framing::Final)?;
    assert!(
        matches!(a.try_send(Class::User, &bootstrap, original, Framing::Final),
        Err(Error::Io(error)) if error.kind() == io::ErrorKind::WouldBlock)
    );
    drop(independent);
    let receipt = pending.await?;
    assert_eq!(receipt.carrier_bytes, 9);
    assert_eq!(receipt.charged_bytes, 165);
    assert_eq!(a.addresses(), endpoint);
    let received = receive(&mut b).await?;
    assert_eq!(received.framing, Framing::Final);
    assert_eq!(received.bytes, bootstrap);

    // A wrapped tail whose inner byte is a final selector remains explicitly
    // Bootstrap; final ciphertext is never trial-decoded as a bootstrap packet.
    a.try_send(Class::Control, &bootstrap, original, Framing::Bootstrap)?
        .await?;
    assert_eq!(receive(&mut b).await?.framing, Framing::Bootstrap);
    let status = a.acceptance_status()?;
    assert_eq!(status.accepted_datagrams, 3);
    assert_eq!(status.accepted_record_bytes, 27);
    assert_eq!(status.accepted_carrier_bytes, 123);
    assert!(
        a.try_send(Class::User, &bootstrap, Instant::now(), Framing::Final)
            .is_err()
    );
    assert!(
        a.try_send(Class::User, &[0x80; 8], original, Framing::Final)
            .is_err()
    );
    drop(a);
    assert!(
        timeout(Duration::from_secs(2), poll_fn(|cx| b.poll_maintenance(cx)))
            .await?
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn real_quic_selected_half_pairs_keep_bidirectional_control_and_user_direction() -> TestResult
{
    let mut forward = profile();
    forward.traffic = Traffic::HalfDuplex {
        sender: Direction::ClientToServer,
    };
    let mut reverse = forward;
    reverse.traffic = Traffic::HalfDuplex {
        sender: Direction::ServerToClient,
    };
    reverse.lane = 1;
    let mut values = connections(&[forward, reverse]).await?;
    let (a1, b1) = values.pop().ok_or("missing second")?;
    let (a0, b0) = values.pop().ok_or("missing first")?;
    let original = Instant::now() + Duration::from_secs(4);
    let (a, b) = tokio::try_join!(
        client_pair(a0, a1, [forward, reverse], base(), original),
        server_pair(b0, b1, [forward, reverse], base(), original),
    )?;
    let mut a = a;
    let mut b = b;
    assert!(a[0].pair_binding().is_some());
    assert_eq!(a[0].pair_binding(), a[1].pair_binding());
    assert_eq!(a[0].pair_binding(), b[0].pair_binding());
    assert_eq!(a[0].pair_binding(), b[1].pair_binding());
    let mut bytes = [0; 21];
    bytes[0] = 80;
    for lane in 0..2 {
        a[lane].select_final_records(original)?;
        b[lane].select_final_records(original)?;
        a[lane]
            .try_send(Class::Control, &bytes, original, Framing::Final)?
            .await?;
        assert_eq!(receive(&mut b[lane]).await?.bytes, bytes);
        b[lane]
            .try_send(Class::Control, &bytes, original, Framing::Final)?
            .await?;
        assert_eq!(receive(&mut a[lane]).await?.bytes, bytes);
    }
    assert!(matches!(
        a[1].try_send(Class::User, &bytes, original, Framing::Final),
        Err(Error::Direction)
    ));
    assert!(matches!(
        b[0].try_send(Class::User, &bytes, original, Framing::Final),
        Err(Error::Direction)
    ));
    a[0].try_send(Class::User, &bytes, original, Framing::Final)?
        .await?;
    assert_eq!(receive(&mut b[0]).await?.bytes, bytes);
    b[1].try_send(Class::User, &bytes, original, Framing::Final)?
        .await?;
    assert_eq!(receive(&mut a[1]).await?.bytes, bytes);
    Ok(())
}

#[tokio::test]
async fn real_quic_selected_proof_and_bootstrap_capability_fail_closed() -> TestResult {
    let profile = profile();
    let mut values = connections(&[profile, profile]).await?;
    let (bad, _peer) = values.pop().ok_or("missing proof pair")?;
    let mut wrong = base();
    wrong.digest.0[0] ^= 1;
    let original = Instant::now() + Duration::from_secs(4);
    assert!(Carrier::new(bad, profile, wrong, original).is_err());
    let (a, b) = values.pop().ok_or("missing capability pair")?;
    let a = Carrier::new(a, profile, base(), original)?;
    let mut b = Carrier::new(b, profile, base(), original)?;
    let body = b"actual-bootstrap";
    let mut forged = encode_datagram(&a.session, &[0; 16], 700, body)?;
    a.session
        .connection
        .send_datagram_wait(Bytes::from(forged.clone()))
        .await?;
    forged[24..40].copy_from_slice(&a.token[..]);
    a.session
        .connection
        .send_datagram_wait(Bytes::from(forged.clone()))
        .await?;
    assert_eq!(receive(&mut b).await?.bytes, body);
    // Replaying the accepted capability/sequence cannot release another record.
    a.session
        .connection
        .send_datagram_wait(Bytes::from(forged))
        .await?;
    let legitimate = encode_datagram(&a.session, &a.token, 701, b"next-bootstrap")?;
    a.session
        .connection
        .send_datagram_wait(Bytes::from(legitimate))
        .await?;
    assert_eq!(receive(&mut b).await?.bytes, b"next-bootstrap");
    Ok(())
}
