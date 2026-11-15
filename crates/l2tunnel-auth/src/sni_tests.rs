//! Real TLS SNI observation and independent immutable own-server verification.

use super::*;

type Pair = (
    AuthenticatedIo<tokio::io::DuplexStream>,
    AuthenticatedIo<tokio::io::DuplexStream>,
);

fn certified(name: &str) -> Result<(Vec<u8>, ServerTls), TestError> {
    let certified = rcgen::generate_simple_self_signed(vec![name.to_owned()])?;
    let der = certified.cert.der().to_vec();
    let server = ServerTls::from_der(
        std::slice::from_ref(&der),
        &certified.signing_key.serialize_der(),
    )?;
    Ok((der, server))
}

async fn pair(
    tls: &ClientTls,
    server: &ServerTls,
    verify: &str,
    key: &MemberKey,
    allow: &MemberAllowlist,
) -> Result<Pair, TestError> {
    let (a, b) = tokio::io::duplex(4096);
    let config = config(PacketLayer::Ip);
    let (a, b) = tokio::join!(
        client_connect_io(a, tls, verify, key, config, Duration::from_secs(2)),
        server_accept_io(b, server, allow, config, Duration::from_secs(2)),
    );
    Ok((a?, b?))
}

async fn observe(mut pair: Pair, name: Option<&str>) -> TestResult {
    let (a, b) = (&mut pair.0, &mut pair.1);
    match &b.stream {
        TlsStream::Server(server) => assert_eq!(server.get_ref().1.server_name(), name),
        TlsStream::Client(_) => return Err("expected accepted TLS server".into()),
    }
    assert_eq!(a.info().server, b.info().server);
    assert_eq!(a.info().session_id, b.info().session_id);
    assert_eq!(a.info().member, b.info().member);
    assert_eq!(
        a.export_key(KeyPurpose::Data, Direction::ClientToServer, 0)?
            .expose_bytes(),
        b.export_key(KeyPurpose::Data, Direction::ClientToServer, 0)?
            .expose_bytes(),
    );
    let packet = b"named SNI\x00\xffown identity";
    a.write_all(packet).await?;
    a.flush().await?;
    let mut received = vec![0; packet.len()];
    b.read_exact(&mut received).await?;
    assert_eq!(received, packet);
    b.write_all(packet).await?;
    b.flush().await?;
    a.read_exact(&mut received).await?;
    assert_eq!(received, packet);
    Ok(())
}

#[test]
fn explicit_sni_rejects_invalid_dns_before_a_connector_or_io_exists() -> TestResult {
    let (der, _) = certified("tunnel.test")?;
    for name in [
        "".to_owned(),
        "a".repeat(254),
        "127.0.0.1".to_owned(),
        "::1".to_owned(),
        "[::1]".to_owned(),
        "tunnel\0.test".to_owned(),
        "bad name.test".to_owned(),
        "a..test".to_owned(),
        "a/test".to_owned(),
        "tést.test".to_owned(),
    ] {
        assert!(matches!(
            ClientSni::named(&name),
            Err(Error::Configuration(_))
        ));
        assert!(matches!(
            ClientTls::from_der_roots_with_sni(std::slice::from_ref(&der), ClientSni::Named(name)),
            Err(Error::Configuration(_)),
        ));
    }
    let old = ClientTls::from_der_roots(std::slice::from_ref(&der))?;
    let explicit = ClientTls::from_der_roots_with_sni(&[der], ClientSni::Disabled)?;
    for tls in [&old, &explicit] {
        assert_eq!(tls.sni(), &ClientSni::Disabled);
        assert!(!tls.0.enable_sni);
        assert!(!tls.0.enable_early_data);
        assert!(tls.2.is_none());
    }
    Ok(())
}

#[tokio::test]
async fn named_sni_keeps_concurrent_verification_names_exporters_and_member_authority() -> TestResult
{
    let (a_der, a_server) = certified("alpha.test")?;
    let (b_der, b_server) = certified("beta.test")?;
    let tls = ClientTls::from_der_roots_with_sni(
        &[a_der, b_der],
        ClientSni::Named("cover.example".to_owned()),
    )?;
    let key = member()?;
    let allow = MemberAllowlist::new(&[key.public_key()])?;
    let (a, b) = tokio::join!(
        pair(&tls, &a_server, "alpha.test", &key, &allow),
        pair(&tls, &b_server, "beta.test", &key, &allow),
    );
    let (a, b) = (a?, b?);
    assert_ne!(a.0.info().server, b.0.info().server);
    assert_ne!(a.0.info().session_id, b.0.info().session_id);
    assert_eq!(tls.sni(), &ClientSni::Named("cover.example".to_owned()));
    observe(a, Some("cover.example")).await?;
    observe(b, Some("cover.example")).await?;
    Ok(())
}

#[tokio::test]
async fn named_sni_cannot_replace_root_or_each_connections_verification_name() -> TestResult {
    let (a_der, a_server) = certified("alpha.test")?;
    let (b_der, b_server) = certified("beta.test")?;
    let key = member()?;
    let allow = MemberAllowlist::new(&[key.public_key()])?;
    let tls = ClientTls::from_der_roots_with_sni(
        &[a_der.clone(), b_der],
        ClientSni::Named("cover.example".to_owned()),
    )?;
    let (good, wrong_name) = tokio::join!(
        pair(&tls, &a_server, "alpha.test", &key, &allow),
        pair(&tls, &b_server, "alpha.test", &key, &allow),
    );
    observe(good?, Some("cover.example")).await?;
    assert!(wrong_name.is_err());
    let wrong_root =
        ClientTls::from_der_roots_with_sni(&[a_der], ClientSni::Named("cover.example".to_owned()))?;
    assert!(
        pair(&wrong_root, &b_server, "beta.test", &key, &allow)
            .await
            .is_err()
    );
    let (no_sni, server) = fixture()?;
    observe(
        pair(&no_sni, &server, "tunnel.test", &key, &allow).await?,
        None,
    )
    .await?;
    Ok(())
}
