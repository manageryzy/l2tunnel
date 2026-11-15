//! Shared lower-layer replacement after real transport loss, without record reset.

use super::*;
use l2tunnel::{codec, wire};
use tokio::io::{AsyncRead, AsyncWriteExt};

async fn record<R: AsyncRead + Unpin>(reader: &mut R) -> Result<(wire::Header, Vec<u8>)> {
    let mut prefix = [0; 4];
    reader.read_exact(&mut prefix).await?;
    let length = usize::try_from(u32::from_be_bytes(prefix))?;
    assert!((wire::HEADER_LEN..=wire::HEADER_LEN + 4096).contains(&length));
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes).await?;
    let (header, payload) = wire::decode(&bytes, 4096)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "actual peer record malformed"))?;
    Ok((header, payload.to_vec()))
}

#[tokio::test]
async fn typed_reconnect_after_transport_loss_preserves_unknown_and_authenticates_fresh_native_session()
-> Result {
    let credentials = credentials()?;
    let config = cfg(Duplex::Full);
    let native = Arc::new(Native::default());
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let plan = plan(&credentials, listener.local_addr()?, config, native.clone())?;
    let (handle, run) = channel();
    let first_key = handle.next_key().map_err(submit)?;
    // Reconnect does not manufacture a plan or consume the first service key.
    assert_eq!(
        handle.reconnect(plan.clone(), first_key),
        Err(SubmitError::State)
    );
    assert_eq!(handle.next_key().map_err(submit)?, first_key);
    let first = handle.connect(plan.clone(), first_key).map_err(submit)?;
    let owner = tokio::spawn(run);
    let result = timeout(Duration::from_secs(8), async {
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let mut peer = l2tunnel_auth::server_accept(
            stream,
            &credentials.server,
            &credentials.members,
            config.session()?,
            config.handshake_timeout,
        )
        .await?;
        let old_session = peer.info().session_id;
        let generation = match handle.wait(first.operation).await.map_err(submit)? {
            Completed::Connected { generation } => generation,
            other => return Err(format!("first setup: {other:?}").into()),
        };
        let codec = codec::FrameCodec::new(codec::CodecConfig {
            layer: codec::FrameLayer::Ip,
            max_frame_bytes: config.max_packet,
            compression: codec::Compression::None,
        })?;
        native
            .incoming
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push_back(packet(7));
        let (header, payload) = record(&mut peer).await?;
        assert_eq!(header.kind, wire::Kind::Data);
        assert_eq!(header.session, old_session);
        assert_eq!(codec.decode_vec(&payload)?, packet(7));

        let request = local::Request {
            version: local::VERSION,
            action: local::Action::SwitchCompression {
                compression: local::Compression::Lz4,
            },
        };
        let apply_key = handle.next_key().map_err(submit)?;
        let applied = handle.apply(request.clone(), apply_key).map_err(submit)?;
        // The real authenticated original peer reads the management request but
        // supplies no outcome. Closing that exact TLS owner is a transport fault,
        // not an owner-drop/cancel or fabricated backend-status transition.
        let (header, _) = record(&mut peer).await?;
        assert_eq!(header.kind, wire::Kind::Control);
        assert_eq!(header.session, old_session);
        assert_eq!(handle.snapshot().phase, Phase::Applying);
        assert_eq!(
            handle.cancel(applied.operation),
            Err(SubmitError::Unsupported)
        );
        drop(peer);
        assert_eq!(
            handle.wait(applied.operation).await.map_err(submit)?,
            Completed::OutcomeUnknown
        );
        let terminal = handle.wait_stopped(generation).await.map_err(submit)?;
        assert!(matches!(terminal, Terminal::Failed(_)));
        assert_eq!(handle.snapshot().phase, Phase::Failed);
        assert_eq!(native.live.load(Ordering::SeqCst), 0);
        assert_eq!(
            handle.apply(request.clone(), apply_key).map_err(submit)?,
            applied
        );
        assert_eq!(
            handle.wait(applied.operation).await.map_err(submit)?,
            Completed::OutcomeUnknown
        );
        assert_eq!(
            handle.connect(plan.clone(), first_key).map_err(submit)?,
            first
        );

        // This exact typed admission failed before the fix: backend is absent,
        // while the genuine prior plan and its completed history are retained.
        let replacement_key = handle.next_key().map_err(submit)?;
        let replacement = handle
            .reconnect(plan.clone(), replacement_key)
            .map_err(submit)?;
        assert!(replacement.deadline > first.deadline);
        assert_eq!(
            handle
                .reconnect(plan.clone(), replacement_key)
                .map_err(submit)?,
            replacement
        );
        assert_eq!(
            handle
                .connect(plan.clone(), first_key)
                .map_err(submit)?
                .deadline,
            first.deadline
        );
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let mut peer = l2tunnel_auth::server_accept(
            stream,
            &credentials.server,
            &credentials.members,
            config.session()?,
            config.handshake_timeout,
        )
        .await?;
        let fresh_session = peer.info().session_id;
        assert_ne!(fresh_session, old_session);
        let fresh = match handle.wait(replacement.operation).await.map_err(submit)? {
            Completed::Connected { generation } => generation,
            other => return Err(format!("replacement setup: {other:?}").into()),
        };
        assert_ne!(fresh, generation);
        assert_eq!(
            native
                .events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_slice(),
            &[(true, 1), (false, 1), (true, 2)]
        );
        let actual = handle
            .snapshot()
            .runtime
            .and_then(|observation| observation.managed().cloned())
            .ok_or("replacement runtime observation missing")?;
        assert!(actual.running);
        assert_eq!(actual.epoch.0, 1);
        assert_eq!(actual.compression, codec::Compression::None);

        native
            .incoming
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push_back(packet(91));
        let (header, payload) = record(&mut peer).await?;
        assert_eq!(header.kind, wire::Kind::Data);
        assert_eq!(header.session, fresh_session);
        assert_eq!(codec.decode_vec(&payload)?, packet(91));
        let encoded = codec.encode_vec(&packet(92))?;
        let bytes = wire::encode(
            wire::Header {
                kind: wire::Kind::Data,
                epoch: l2tunnel_core::Epoch(1),
                packet_number: 0,
                session: fresh_session,
                lane: 0,
            },
            &encoded,
        )
        .map_err(|_| io::Error::other("fixture native wire encoding failed"))?;
        peer.write_all(&u32::try_from(bytes.len())?.to_be_bytes())
            .await?;
        peer.write_all(&bytes).await?;
        peer.flush().await?;
        received(&native, &[packet(92)]).await?;
        assert_eq!(
            handle.wait(applied.operation).await.map_err(submit)?,
            Completed::OutcomeUnknown
        );
        assert_eq!(
            handle.wait_stopped(generation).await.map_err(submit)?,
            terminal
        );

        let stopped = handle
            .disconnect(handle.next_key().map_err(submit)?)
            .map_err(submit)?;
        assert_eq!(
            handle.wait(stopped.operation).await.map_err(submit)?,
            Completed::Aborted
        );
        assert_eq!(
            handle.wait_stopped(fresh).await.map_err(submit)?,
            Terminal::Aborted
        );
        assert_eq!(native.live.load(Ordering::SeqCst), 0);
        eof(&mut peer).await?;
        Ok::<_, Error>(())
    })
    .await;
    owner.abort();
    let _ = owner.await;
    result??;
    Ok(())
}
