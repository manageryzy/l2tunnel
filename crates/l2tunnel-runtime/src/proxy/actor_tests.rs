use super::*;
#[path = "measured_actor_tests.rs"]
mod measured_cases;

fn actor(originator: bool) -> io::Result<(Actor, mpsc::Receiver<Vec<u8>>, mpsc::Receiver<Output>)> {
    let prefix = IpPrefix::new("10.112.0.0".parse().map_err(error)?, 24)?;
    let mut config = Config::new(
        RuntimeConfig {
            layer: PacketLayer::Ip,
            max_packet: 1600,
            compression: Compression::None,
            queue_packets: 4,
            poll_interval: Duration::from_millis(1),
        },
        Duplex::Full,
        RoutePolicy::new(vec![RouteRule {
            source: prefix,
            destination: prefix,
            ports: PortRange {
                first: 443,
                last: 443,
            },
        }])?,
    )?;
    config.relay.admission_timeout = Duration::from_millis(10);
    let start = Instant::now();
    let logical = [5; 16];
    let (ctx, crx) = mpsc::channel(8);
    let (utx, urx) = mpsc::channel(1);
    let (_, prx) = watch::channel(Progress {
        ready: true,
        ..Progress::default()
    });
    let writer = Writer {
        control: ctx,
        users: utx,
        progress: prx,
        start: Start {
            digest: session_config(&config)?.digest.0,
            session: logical,
            originator,
            duplex: Duplex::Full,
            lane: 0,
        },
        ready: true,
        last_ping: start,
        next_ping: 1,
        outstanding: None,
        pending_pong: None,
        queued_pong: 0,
        close: false,
    };
    Ok((
        Actor {
            measured: None,
            logical,
            originator,
            table: session::Table::new(config.table(logical, originator, 17), Millis(0))
                .map_err(error)?,
            wire: Arbiter::new(&config, false)?,
            native: Arbiter::new(&config, true)?,
            config,
            bindings: BTreeMap::new(),
            announced: BTreeSet::new(),
            scheduled: BTreeSet::new(),
            native_scheduled: BTreeSet::new(),
            selected_native: None,
            input: None,
            input_transparent: false,
            incoming: None,
            writers: vec![writer],
            starts: vec![true],
            ready: vec![true],
            peer_ping: vec![0],
            eof: vec![false],
            closed: vec![false],
            started: true,
            start,
            deadline: None,
            peer_quiesce: false,
            peer_quiesce_users: 0,
            quiesce_queued: false,
            frozen: false,
            closing: false,
            sent: Credit::default(),
            peer_credit: Credit::default(),
            received: Credit::default(),
            delivered: Credit::default(),
            queued_credit: Credit::default(),
            sent_records: 0,
            received_records: 0,
            local_fence: None,
            peer_fence: None,
            peer_ack: None,
            ack_queued: false,
            reply: None,
        },
        urx,
        crx,
    ))
}
fn syn() -> io::Result<Vec<u8>> {
    let (a, _, _) = actor(true)?;
    let mut cfg = a.config.table([5; 16], true, 19).native;
    cfg.local = ([10, 112, 0, 1], 32001).into();
    cfg.peer = ([10, 112, 0, 2], 443).into();
    let mut engine =
        l2tunnel_raw_tcp::TcpEngine::new_ip(cfg, proxy::Role::Client, Millis(0)).map_err(error)?;
    engine.poll(Millis(0), 4).map_err(error)?;
    engine
        .pop_packet()
        .ok_or_else(|| invalid("test SYN absent"))
}
#[test]
fn queued_ready_does_not_start_or_emit_quiesce_and_never_renews_drain() -> io::Result<()> {
    let (mut a, _users, mut controls) = actor(true)?;
    let (progress, receiver) = watch::channel(Progress::default());
    a.writers[0].progress = receiver;
    a.writers[0].ready = false;
    a.started = false;
    a.drain(Instant::now())?;
    let original = a.deadline;
    a.service_control()?;
    assert!(matches!(
        controls.try_recv(),
        Ok(Output::Control(Frame::Ready(_)))
    ));
    assert!(!a.started);
    a.shutdown()?;
    assert!(!a.quiesce_queued);
    assert!(controls.try_recv().is_err());
    a.drain(Instant::now() + Duration::from_secs(1))?;
    progress.send_replace(Progress {
        ready: true,
        ..Progress::default()
    });
    a.ready[0] = false;
    a.service_control()?;
    assert!(!a.started);
    a.shutdown()?;
    assert!(!a.quiesce_queued);
    a.ready[0] = true;
    a.service_control()?;
    assert!(a.started);
    a.shutdown()?;
    assert!(matches!(
        controls.try_recv(),
        Ok(Output::Control(Frame::Quiesce))
    ));
    assert_eq!(a.deadline, original);
    Ok(())
}
#[test]
fn expired_unannounced_id_is_terminal_without_consuming_queued_open() -> io::Result<()> {
    let (mut a, mut rx, _controls) = actor(true)?;
    // Saturated carrier ownership: the original Open remains in the common arbiter.
    a.writers[0].users.try_send(vec![0]).map_err(error)?;
    assert!(a.receive_native(syn()?)?.is_none());
    a.schedule_table()?;
    a.send_user()?;
    assert_eq!(a.sent_records, 0);
    assert!(!a.announced.contains(&1));
    a.start = Instant::now() - Duration::from_millis(20);
    let failure = a
        .poll_table()
        .err()
        .ok_or_else(|| invalid("unannounced expiry accepted"))?;
    assert!(failure.to_string().contains("unannounced"));
    assert_eq!(rx.try_recv().map_err(error)?, vec![0]);
    assert!(rx.try_recv().is_err());
    assert_eq!(a.table.status().flows, 1);
    Ok(())
}
#[test]
fn expired_staged_ready_is_discarded_before_terminal_replacement_handoff() -> io::Result<()> {
    let (mut local, mut output, _local_controls) = actor(true)?;
    local.receive_native(syn()?)?;
    local.schedule_table()?;
    local.send_user()?;
    let open = output.try_recv().map_err(error)?;
    let (mut remote, mut output, _remote_controls) = actor(false)?;
    remote.receive_user(open)?;
    remote.schedule_table()?;
    assert!(remote.scheduled.contains(&1));
    assert_eq!(remote.sent_records, 0);
    assert!(remote.table.pending_native(1).is_none());
    remote.start = Instant::now() - Duration::from_millis(20);
    remote.poll_table()?;
    assert_eq!(
        remote.table.pending_record(1).and_then(|p| p.get(..4)),
        Some(b"LTPX".as_slice())
    );
    remote.send_user()?;
    assert!(output.try_recv().is_err());
    assert_eq!(remote.sent_records, 0);
    assert!(!remote.scheduled.contains(&1));
    remote.schedule_table()?;
    remote.send_user()?;
    let bytes = output.try_recv().map_err(error)?;
    let user = wire::decode_user(&bytes, &remote.config)?;
    assert_eq!(&user.body[..4], b"LTPX");
    assert_eq!(remote.sent_records, 1);
    assert!(remote.table.pending_record(1).is_none());
    assert!(remote.table.pending_native(1).is_none());
    Ok(())
}

#[tokio::test]
async fn reader_quiesce_watermark_prevents_freezing_earlier_queued_open() -> io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let (mut local, mut output, _controls) = actor(true)?;
    local.receive_native(syn()?)?;
    local.schedule_table()?;
    local.send_user()?;
    let open = output.try_recv().map_err(error)?;
    let (mut remote, _remote_output, _remote_controls) = actor(false)?;
    let expected = local.writers[0].start;
    let (mut input, reader) = tokio::io::duplex(4096);
    let (etx, mut events) = mpsc::channel(8);
    let (utx, mut users) = mpsc::channel(4);
    let (qtx, _qrx) = watch::channel(None);
    let task = tokio::spawn(transport::reader(
        reader,
        Direction {
            index: 0,
            lane: 0,
            session: [9; 16],
            bulk: true,
        },
        expected,
        (remote.config.clone(), false),
        etx,
        utx,
        qtx,
    ));
    let frames = [
        (
            super::super::super::wire::Kind::Control,
            Frame::Start(expected).encode(),
        ),
        (
            super::super::super::wire::Kind::Control,
            Frame::Ready(expected).encode(),
        ),
        (super::super::super::wire::Kind::Data, open),
        (
            super::super::super::wire::Kind::Control,
            Frame::Quiesce.encode(),
        ),
    ];
    for (n, (kind, body)) in frames.into_iter().enumerate() {
        let bytes = super::super::super::wire::encode(
            super::super::super::wire::Header {
                kind,
                epoch: l2tunnel_core::Epoch(1),
                packet_number: n as u64,
                session: [9; 16],
                lane: 0,
            },
            &body,
        )
        .map_err(super::super::super::wire_error)?;
        input.write_u32(bytes.len() as u32).await?;
        input.write_all(&bytes).await?;
    }
    for _ in 0..3 {
        let event = events
            .recv()
            .await
            .ok_or_else(|| invalid("test reader event"))?;
        remote.event(event)?;
    }
    assert!(remote.peer_quiesce);
    assert_eq!(remote.peer_quiesce_users, 1);
    remote.shutdown()?;
    assert!(!remote.frozen);
    remote.receive_user(
        users
            .recv()
            .await
            .ok_or_else(|| invalid("test user frame"))?,
    )?;
    assert_eq!(remote.received_records, 1);
    assert_eq!(remote.table.status().flows, 1);
    remote.shutdown()?;
    assert!(!remote.frozen);
    assert!(matches!(
        remote.table.flow_status(1).map(|s| s.phase),
        Some(session::FlowPhase::Opening(_))
    ));
    task.abort();
    let _ = task.await;
    Ok(())
}

#[tokio::test]
async fn writer_flushes_ready_then_previously_owned_user_before_quiesce() -> io::Result<()> {
    use tokio::io::AsyncReadExt;
    let (writer, mut wire_reader) = tokio::io::duplex(4096);
    let (ctx, crx) = mpsc::channel(8);
    let (utx, urx) = mpsc::channel(1);
    let (ptx, prx) = watch::channel(Progress::default());
    let (etx, _erx) = mpsc::channel(8);
    let (a, _users, _controls) = actor(true)?;
    let start = a.writers[0].start;
    ctx.try_send(Output::Control(Frame::Start(start)))
        .map_err(error)?;
    ctx.try_send(Output::Control(Frame::Ready(start)))
        .map_err(error)?;
    ctx.try_send(Output::Control(Frame::Quiesce))
        .map_err(error)?;
    utx.try_send(vec![17; 24]).map_err(error)?;
    let task = tokio::spawn(transport::writer(
        writer,
        Direction {
            index: 0,
            lane: 0,
            session: [9; 16],
            bulk: true,
        },
        crx,
        urx,
        ptx,
        etx,
    ));
    for number in 0..4 {
        let length = wire_reader.read_u32().await? as usize;
        let mut bytes = vec![0; length];
        wire_reader.read_exact(&mut bytes).await?;
        let (header, body) = super::super::super::wire::decode(&bytes, 1600)
            .map_err(super::super::super::wire_error)?;
        assert_eq!(header.packet_number, number);
        if number == 2 {
            assert_eq!(header.kind, super::super::super::wire::Kind::Data);
            assert_eq!(body, [17; 24]);
        } else {
            assert_eq!(
                Frame::decode(body)?,
                match number {
                    0 => Frame::Start(start),
                    1 => Frame::Ready(start),
                    _ => Frame::Quiesce,
                }
            );
        }
    }
    assert_eq!(prx.borrow().users, 1);
    assert!(prx.borrow().ready);
    assert!(prx.borrow().quiesce);
    task.abort();
    let _ = task.await;
    Ok(())
}

#[test]
fn peer_barrier_can_arrive_before_actor_users_but_not_ack_before_native_write() -> io::Result<()> {
    struct Sink(bool);
    impl PacketDevice for Sink {
        type Error = io::Error;
        fn layer(&self) -> PacketLayer {
            PacketLayer::Ip
        }
        fn receive(&mut self, _: &mut [u8]) -> io::Result<Option<usize>> {
            Ok(None)
        }
        fn transmit(&mut self, _: &[u8]) -> io::Result<()> {
            if self.0 {
                Ok(())
            } else {
                Err(io::ErrorKind::WouldBlock.into())
            }
        }
    }
    let (mut a, _users, _controls) = actor(false)?;
    let mut packet = vec![0; 48];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&8_u16.to_be_bytes());
    packet[6] = 253;
    packet[7] = 64;
    packet[8] = 0xfd;
    packet[23] = 1;
    packet[24] = 0xfd;
    packet[39] = 2;
    let binding = a.binding(&packet)?;
    let channel = a.wire.channel(binding.key, Duration::ZERO)?;
    let body = a
        .config
        .runtime
        .codec()?
        .encode_vec(&packet)
        .map_err(error)?;
    let user = wire::user(channel, 0, &body)?;
    let fence = Fence {
        records: 1,
        transparent: Credit {
            bytes: packet.len() as u64,
            packets: 1,
        },
        flows: 0,
    };
    a.event(Event::Control(0, Frame::Quiesce, 1))?;
    a.event(Event::Control(0, Frame::Barrier(fence), 1))?;
    a.shutdown()?;
    assert!(!a.frozen);
    assert!(!a.ack_queued);
    a.receive_user(user)?;
    a.writers[0].progress = watch::channel(Progress {
        ready: true,
        quiesce: true,
        ..Progress::default()
    })
    .1;
    a.deliver(&mut Sink(false))?;
    a.shutdown()?;
    assert!(a.frozen);
    assert!(a.local_fence.is_some());
    assert!(!a.ack_queued);
    assert_eq!(a.delivered, Credit::default());
    a.deliver(&mut Sink(true))?;
    a.service_control()?;
    a.shutdown()?;
    assert_eq!(a.delivered, fence.transparent);
    assert!(a.ack_queued);
    Ok(())
}
