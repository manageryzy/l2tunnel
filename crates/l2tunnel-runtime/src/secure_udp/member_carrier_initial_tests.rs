//! Actual initial-only outer/Noise/member handoff, distinct from managed refresh.
use super::*;

/// Real test provisioning shared with the sole-loop fixture; no public Parts constructor.
pub(in crate::secure_udp) async fn initial_parts<T>(
    outer_config: openvpn::Config,
    build: impl Fn(&factory::AuthenticatedOuter, bool) -> TestResult<(establish::Config, T)>,
) -> TestResult<[(InitialParts, T); 2]> {
    let credentials = credentials()?;
    let (a, b) = sockets().await?;
    let cap = Instant::now() + Duration::from_secs(3);
    let (a, b) = tokio::try_join!(
        Outer::client(
            a,
            outer_config,
            ClientCredentials {
                tls: &credentials.client,
                server_name: "carrier-factory.test",
                member: &credentials.member
            },
            cap
        ),
        Outer::server(
            b,
            outer_config,
            ServerCredentials {
                tls: &credentials.server,
                members: &credentials.members
            },
            cap
        ),
    )?;
    let (a_config, a_value) = build(&a.authenticated(), true)?;
    let (b_config, b_value) = build(&b.authenticated(), false)?;
    let (mut a_entropy, mut b_entropy) = (Entropy(40), Entropy(60));
    let mut admission = factory::InitialServerAdmission::new(
        &b,
        b_config,
        peers(),
        gate::Secret::new([7; 32]),
        gate::Secret::new([8; 32]),
        Instant::now(),
    )?;
    let mut a_observer = |_| {};
    let mut b_observer = |_| {};
    let (a, b) = tokio::try_join!(
        a.connect_initial(
            a_config,
            noise(true),
            gate::Secret::new([7; 32]),
            &mut a_entropy,
            &mut a_observer
        ),
        b.accept_initial(
            noise(false),
            &mut admission,
            &mut b_entropy,
            &mut b_observer
        ),
    )?;
    assert_eq!(a.binding(), b.binding());
    assert_eq!(a.authenticated(), b.authenticated());
    let origins = (a.clock_origin(), b.clock_origin());
    let (a_settings, b_settings) = (initial_settings(&a), initial_settings(&b));
    let mut a_observer = |_| {};
    let mut b_observer = |_| {};
    let (a, b) = tokio::try_join!(
        connect_initial(a, &credentials.inner, a_settings, &mut a_observer),
        accept_initial(
            b,
            identity::Allowlist::new(&[credentials.inner.public_key()])?,
            b_settings,
            &mut b_observer
        ),
    )?;
    let (a, b) = (a.into_parts(), b.into_parts());
    assert_eq!((a.clock_origin(), b.clock_origin()), origins);
    assert_eq!((a.deadline, b.deadline), (cap, cap));
    Ok([(a, a_value), (b, b_value)])
}

fn initial_settings(established: &factory::InitialEstablished) -> Settings {
    let binding = established.binding();
    let authenticated = established.authenticated();
    let peers = established.peers();
    Settings {
        context: identity::Context {
            session: binding.session,
            transcript: binding.transcript,
            configuration: authenticated.configuration,
            carrier: authenticated.carrier,
            outer: authenticated.outer,
            initiator_noise: identity::NoisePublicKey(peers.initiator.0),
            responder_noise: identity::NoisePublicKey(peers.responder.0),
        },
        retry_interval: Duration::from_millis(10),
        max_attempts: 32,
        receive_interval: Duration::from_millis(5),
        receive_packets_per_interval: 8,
    }
}
fn install_initial(parts: InitialParts) -> TestResult<(Live, record::Records)> {
    let origin = parts.clock_origin();
    assert_eq!(parts.root.binding(), parts.info.binding);
    assert_eq!(parts.root.role(), parts.info.role);
    let records = record::Records::new(
        parts.root,
        security::LaneId(3),
        security::Limits {
            max_body_bytes: 256,
            packets_per_key: security::MAX_PACKETS_PER_KEY,
            max_body_bytes_per_key: security::MAX_BODY_BYTES_PER_KEY,
        },
        security::Protection::ChaCha20Poly1305,
        parts.cover,
        record::Scope {
            epoch: security::Epoch(4),
            configuration: security::ConfigDigest([19; 32]),
        },
        record::Scope {
            epoch: security::Epoch(7),
            configuration: security::ConfigDigest([21; 32]),
        },
    )?;
    assert!(matches!(
        records.key_epoch(),
        Err(record::Error::Refresh(security::refresh::Error::Mode))
    ));
    Ok((
        Live {
            socket: parts.datagram,
            cover: parts.cover,
            bootstrap: parts.bootstrap,
            joining: parts.joining,
            next_outer: parts.next_outer,
            deadline: parts.deadline,
            origin,
        },
        records,
    ))
}
async fn initial_record(
    live: &mut Live,
    records: &mut record::Records,
    class: record::Class,
    body: &[u8],
) -> TestResult<Vec<u8>> {
    let mut scratch = [0; 1024];
    let mut output = [0; 1024];
    let sealed = records.seal(
        class,
        metadata(live.next_outer, cover::Phase::Established),
        body,
        &mut scratch,
        &mut output,
    )?;
    advance(&mut live.next_outer)?;
    physical(live, class, &output[..sealed.bytes]).await?;
    Ok(output[..sealed.bytes].to_vec())
}
async fn receive_initial(
    live: &mut Live,
    records: &mut record::Records,
    class: record::Class,
    body: &[u8],
) -> TestResult {
    let mut input = [0; 1025];
    let mut scratch = [0; 1024];
    let mut plaintext = [0; 512];
    timeout_at(live.deadline, async {
        loop {
            let length =
                std::future::poll_fn(|cx| live.socket.poll_receive(cx, &mut input)).await?;
            let now = Instant::now();
            let decoded = live.cover.decode(&input[..length])?;
            if live.bootstrap.receive(decoded, now)? || live.joining.receive(decoded, now)? {
                continue;
            }
            let opened = records.open(&input[..length], &mut scratch, &mut plaintext)?;
            assert_eq!(opened.class, class);
            assert_eq!(&plaintext[..opened.bytes], body);
            return Ok::<_, TestError>(());
        }
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn actual_initial_only_carrier_keeps_original_noise_member_root_and_socket() -> TestResult {
    let credentials = credentials()?;
    let (a, b) = sockets().await?;
    let endpoints = (a.local_addr()?, b.local_addr()?);
    let cap = Instant::now() + Duration::from_secs(3);
    let (mut a_entropy, mut b_entropy) = (Entropy(40), Entropy(60));
    let mut client_observer = |_| {};
    let client = factory::connect_initial(
        a,
        outer_config(),
        ClientCredentials {
            tls: &credentials.client,
            server_name: "carrier-factory.test",
            member: &credentials.member,
        },
        noise(true),
        gate::Secret::new([7; 32]),
        cap,
        &mut a_entropy,
        |outer| effective(outer, true),
        &mut client_observer,
    );
    let server = async {
        let outer = Outer::server(
            b,
            outer_config(),
            ServerCredentials {
                tls: &credentials.server,
                members: &credentials.members,
            },
            cap,
        )
        .await?;
        let config = effective(&outer.authenticated(), false)?;
        let mut admission = factory::InitialServerAdmission::new(
            &outer,
            config,
            peers(),
            gate::Secret::new([7; 32]),
            gate::Secret::new([8; 32]),
            Instant::now(),
        )?;
        let mut server_observer = |_| {};
        let result = outer
            .accept_initial(
                noise(false),
                &mut admission,
                &mut b_entropy,
                &mut server_observer,
            )
            .await?;
        assert_eq!(admission.config(), config);
        Ok::<_, establish::Error>(result)
    };
    let (a, b) = tokio::try_join!(client, server)?;
    assert_eq!(a.binding(), b.binding());
    assert_eq!(a.authenticated(), b.authenticated());
    assert_eq!(a.outer().endpoints(), endpoints);
    assert_eq!((a.deadline(), b.deadline()), (cap, cap));
    assert!(a.statistics().socket_sent_datagrams > 0);
    assert!(b.statistics().socket_sent_datagrams > 0);
    let origins = (a.clock_origin(), b.clock_origin());
    let (a_settings, b_settings) = (initial_settings(&a), initial_settings(&b));
    let mut client_observer = |_| {};
    let mut server_observer = |_| {};
    let (a, b) = tokio::try_join!(
        connect_initial(a, &credentials.inner, a_settings, &mut client_observer),
        accept_initial(
            b,
            identity::Allowlist::new(&[credentials.inner.public_key()])?,
            b_settings,
            &mut server_observer
        ),
    )?;
    assert_eq!(a.info().member, a.outer().info().member);
    assert_eq!(a.info().binding, b.info().binding);
    let (a, b) = (a.into_parts(), b.into_parts());
    assert_eq!((a.clock_origin(), b.clock_origin()), origins);
    assert_eq!((a.deadline, b.deadline), (cap, cap));
    assert_eq!(a.datagram.addresses(), endpoints);
    assert_eq!(b.datagram.addresses(), (endpoints.1, endpoints.0));
    assert_eq!(a.datagram.geometry().extra_wire_bytes, 1);
    let (mut a, mut a_records) = install_initial(a)?;
    let (mut b, mut b_records) = install_initial(b)?;
    let packet = initial_record(
        &mut a,
        &mut a_records,
        record::Class::User,
        b"initial-only user",
    )
    .await?;
    receive_initial(
        &mut b,
        &mut b_records,
        record::Class::User,
        b"initial-only user",
    )
    .await?;
    let mut scratch = [0; 1024];
    let mut plaintext = [0; 512];
    assert!(matches!(
        b_records.open(&packet, &mut scratch, &mut plaintext),
        Err(record::Error::Security(security::Error::Replay))
    ));
    initial_record(
        &mut b,
        &mut b_records,
        record::Class::Control,
        b"initial-only control",
    )
    .await?;
    receive_initial(
        &mut a,
        &mut a_records,
        record::Class::Control,
        b"initial-only control",
    )
    .await?;
    let mut received = [0; 3];
    let a_tls = a.socket.outer_control().ok_or("missing original TLS")?;
    let b_tls = b.socket.outer_control().ok_or("missing original TLS")?;
    let (write, read) = timeout_at(cap, async {
        tokio::join!(a_tls.write_all(b"tls"), b_tls.read_exact(&mut received))
    })
    .await?;
    write?;
    read?;
    assert_eq!(&received, b"tls");
    Ok(())
}
