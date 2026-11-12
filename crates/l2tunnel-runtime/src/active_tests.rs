use super::*;
use l2tunnel_auth::{
    AuthenticatedConnection, ClientTls, MemberAllowlist, MemberKey, ServerTls, client_connect,
    server_accept,
};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, TcpStream};

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

fn runtime() -> RuntimeConfig {
    RuntimeConfig {
        layer: PacketLayer::Ip,
        max_packet: 1600,
        compression: Compression::None,
        queue_packets: 8,
        poll_interval: Duration::from_millis(1),
    }
}
async fn connections(
    runtime: RuntimeConfig,
    settings: Settings,
) -> Result<Vec<(AuthenticatedConnection, AuthenticatedConnection)>, TestError> {
    let cert = rcgen::generate_simple_self_signed(vec!["active.test".to_owned()])?;
    let chain = vec![cert.cert.der().to_vec()];
    let client_tls = ClientTls::from_der_roots(&chain)?;
    let server_tls = ServerTls::from_der(&chain, &cert.signing_key.serialize_der())?;
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let allowlist = MemberAllowlist::new(&[member.public_key()])?;
    let binding = session_config(runtime, settings)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let mut result = Vec::new();
    for _ in 0..if settings.duplex == Duplex::Half {
        2
    } else {
        1
    } {
        let client_tcp = TcpStream::connect(listener.local_addr()?).await?;
        client_tcp.set_nodelay(true)?;
        let (server_tcp, _) = listener.accept().await?;
        server_tcp.set_nodelay(true)?;
        let pair = tokio::try_join!(
            client_connect(
                client_tcp,
                &client_tls,
                "active.test",
                &member,
                binding,
                Duration::from_secs(5)
            ),
            server_accept(
                server_tcp,
                &server_tls,
                &allowlist,
                binding,
                Duration::from_secs(5)
            ),
        )?;
        result.push(pair);
    }
    Ok(result)
}
async fn links(runtime: RuntimeConfig, settings: Settings) -> Result<(Link, Link), TestError> {
    let mut connected = connections(runtime, settings).await?.into_iter();
    let (client, server) = connected.next().ok_or("missing authenticated lane")?;
    if settings.duplex == Duplex::Half {
        let (client2, server2) = connected.next().ok_or("missing second lane")?;
        Ok(tokio::try_join!(
            super::super::client_pair(client, client2),
            super::super::server_pair(server, server2)
        )?)
    } else {
        Ok((Link::full(client), Link::full(server)))
    }
}
#[derive(Default)]
struct Native {
    outgoing: VecDeque<Vec<u8>>,
    delivered: Vec<Vec<u8>>,
    blocked: bool,
    reads: usize,
    smallest_buffer: Option<usize>,
}
#[derive(Clone, Default)]
struct Device {
    state: Arc<Mutex<Native>>,
}
impl Device {
    fn change<T>(&self, f: impl FnOnce(&mut Native) -> T) -> io::Result<T> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| invalid("test device poisoned"))?;
        Ok(f(&mut state))
    }
}
impl PacketDevice for Device {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ip
    }
    fn receive(&mut self, output: &mut [u8]) -> io::Result<Option<usize>> {
        self.change(|state| {
            state.reads += 1;
            state.smallest_buffer = Some(
                state
                    .smallest_buffer
                    .map_or(output.len(), |old| old.min(output.len())),
            );
            state.outgoing.pop_front().map(|packet| {
                output[..packet.len()].copy_from_slice(&packet);
                packet.len()
            })
        })
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<()> {
        self.change(|state| {
            if state.blocked {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            state.delivered.push(packet.to_vec());
            Ok(())
        })?
    }
}
fn packet(port: u16, value: u8, reverse: bool, dscp: u8) -> Vec<u8> {
    let mut bytes = vec![value; 400];
    bytes[..40].fill(0);
    bytes[0] = 0x45;
    bytes[1] = dscp << 2;
    bytes[2..4].copy_from_slice(&400_u16.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 6;
    let (a, b, sport, dport) = if reverse {
        (2, 1, 443, port)
    } else {
        (1, 2, port, 443)
    };
    bytes[12..16].copy_from_slice(&[10, 0, 0, a]);
    bytes[16..20].copy_from_slice(&[10, 0, 0, b]);
    bytes[20..22].copy_from_slice(&sport.to_be_bytes());
    bytes[22..24].copy_from_slice(&dport.to_be_bytes());
    bytes[32] = 0x50;
    bytes[33] = 0x10;
    bytes
}
async fn until(
    observer: &Observer,
    predicate: impl Fn(&Status) -> bool,
) -> Result<Status, TestError> {
    let mut updates = observer.subscribe();
    Ok(timeout(Duration::from_secs(5), async {
        loop {
            if let Some(status) = (*updates.borrow_and_update()).filter(|status| predicate(status))
            {
                return Ok::<_, io::Error>(status);
            }
            updates.changed().await.map_err(io::Error::other)?;
        }
    })
    .await??)
}
fn same_flows(actual: &[Vec<u8>], expected: &[Vec<u8>]) -> bool {
    if actual.len() != expected.len() {
        return false;
    }
    for port in [1000_u16, 1001, 1002] {
        let matching = |packet: &&Vec<u8>| {
            packet[20..22] == port.to_be_bytes() || packet[22..24] == port.to_be_bytes()
        };
        if actual.iter().filter(matching).collect::<Vec<_>>()
            != expected.iter().filter(matching).collect::<Vec<_>>()
        {
            return false;
        }
    }
    true
}

#[tokio::test]
async fn authenticated_full_and_half_preserve_multiple_flows_compression_and_dscp_changes()
-> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        for compression in [Compression::None, Compression::Lz4IfSmaller] {
            let runtime = RuntimeConfig {
                compression,
                ..runtime()
            };
            let mut settings = Settings::new(runtime, duplex)?;
            settings.dscp_weights[8] = 4;
            let (left_link, right_link) = links(runtime, settings).await?;
            let binding = session_config(runtime, settings)?;
            assert_eq!(
                logical_session(&left_link, binding, settings)?.0,
                logical_session(&right_link, binding, settings)?.0
            );
            let left = Device::default();
            let right = Device::default();
            let original: Vec<_> = (0..12)
                .map(|n| packet(1000 + n % 3, n as u8, false, if n < 3 { 8 } else { 0 }))
                .collect();
            let reverse: Vec<_> = (0..12)
                .map(|n| packet(1000 + n % 3, n as u8 + 50, true, 0))
                .collect();
            left.change(|state| state.outgoing.extend(original.clone()))?;
            right.change(|state| state.outgoing.extend(reverse.clone()))?;
            let (lo, lr) = observations();
            let (ro, rr) = observations();
            let mut jobs = JoinSet::new();
            jobs.spawn(run(left.clone(), left_link, runtime, settings, Some(lr)));
            jobs.spawn(run(right.clone(), right_link, runtime, settings, Some(rr)));
            until(&lo, |s| {
                s.delivered == 12 && s.engine.sender_retained.records == 0
            })
            .await?;
            until(&ro, |s| {
                s.delivered == 12 && s.engine.sender_retained.records == 0
            })
            .await?;
            assert_eq!(
                lo.status().ok_or("missing static status")?.feedback,
                l2tunnel_flow_control::target::Feedback::default()
            );
            assert_eq!(
                lo.status()
                    .ok_or("missing static status")?
                    .observation_handed,
                0
            );
            assert!(left.change(|state| same_flows(&state.delivered, &reverse))?);
            assert!(right.change(|state| same_flows(&state.delivered, &original))?);
            assert_eq!(
                left.change(|s| s.smallest_buffer)?,
                Some(l2tunnel_device::READ_BUFFER_BYTES)
            );
            assert_eq!(
                lo.status()
                    .ok_or("missing active status")?
                    .engine
                    .outgoing_flows,
                3
            );
            jobs.abort_all();
            while jobs.join_next().await.is_some() {}
            assert!(!lo.status().ok_or("missing stopped status")?.running);
            assert!(!ro.status().ok_or("missing stopped status")?.running);
        }
    }
    Ok(())
}

#[tokio::test]
async fn blocked_native_does_not_release_credit_and_reverse_control_keeps_progress() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        let runtime = runtime();
        let settings = Settings::new(runtime, duplex)?;
        let (ll, rl) = links(runtime, settings).await?;
        let left = Device::default();
        let right = Device::default();
        let input: Vec<_> = (0..30)
            .map(|n| packet(1000 + n % 3, n as u8, false, 0))
            .collect();
        left.change(|s| s.outgoing.extend(input.clone()))?;
        right.change(|s| {
            s.blocked = true;
            s.outgoing.push_back(packet(1000, 99, true, 0));
        })?;
        let (lo, lr) = observations();
        let (ro, rr) = observations();
        let mut jobs = JoinSet::new();
        jobs.spawn(run(left.clone(), ll, runtime, settings, Some(lr)));
        jobs.spawn(run(right.clone(), rl, runtime, settings, Some(rr)));
        let blocked = until(&ro, |s| s.engine.receiver_payload.records == 3).await?;
        until(&lo, |s| {
            s.delivered == 1 && s.engine.sender_retained.records == 3
        })
        .await?;
        assert_eq!(blocked.delivered, 0);
        tokio::time::sleep(Duration::from_millis(30)).await;
        let state = ro.status().ok_or("missing blocked status")?;
        assert_eq!(state.engine.receiver_payload.records, 3);
        assert_eq!(state.delivered, 0);
        let sender = lo.status().ok_or("missing sender status")?;
        assert!(sender.engine.queued.packets <= runtime.queue_packets);
        assert!(sender.admitted <= 3 + runtime.queue_packets as u64);
        right.change(|s| s.blocked = false)?;
        until(&ro, |s| s.delivered == 30).await?;
        until(&lo, |s| s.engine.sender_retained.records == 0).await?;
        assert!(right.change(|s| same_flows(&s.delivered, &input))?);
        jobs.abort_all();
        while jobs.join_next().await.is_some() {}
    }
    Ok(())
}

#[tokio::test]
async fn authenticated_binding_mismatch_is_rejected_before_native_read() -> TestResult {
    let runtime = runtime();
    let settings = Settings::new(runtime, Duplex::Full)?;
    let (link, _peer) = links(runtime, settings).await?;
    let device = Device::default();
    let changed = Settings {
        channels: settings.channels + 1,
        ..settings
    };
    assert!(
        run(device.clone(), link, runtime, changed, None)
            .await
            .is_err()
    );
    assert_eq!(device.change(|s| s.reads)?, 0);
    let baseline = session_config(runtime, settings)?;
    let changes: [fn(&mut Settings); 11] = [
        |s| s.adaptive = true,
        |s| s.max_flows -= 1,
        |s| s.channels += 1,
        |s| s.base_quantum_bytes += 1,
        |s| s.dscp_weights[1] += 1,
        |s| s.control_packets_per_second += 1,
        |s| s.heartbeat_interval += Duration::from_secs(1),
        |s| s.io_timeout += Duration::from_secs(1),
        |s| s.idle_flow_timeout += Duration::from_secs(1),
        |s| s.retirement_retry += Duration::from_millis(1),
        |s| s.retirement_max_attempts += 1,
    ];
    for change in changes {
        let mut changed = settings;
        change(&mut changed);
        assert_ne!(session_config(runtime, changed)?, baseline);
    }
    assert!(
        Settings::new(
            RuntimeConfig {
                layer: PacketLayer::Ethernet,
                ..runtime
            },
            Duplex::Full
        )
        .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn peer_eof_is_failure_and_cancellation_stops_all_observed_ownership() -> TestResult {
    let runtime = runtime();
    let settings = Settings::new(runtime, Duplex::Half)?;
    let (left, right) = links(runtime, settings).await?;
    let device = Device::default();
    let (observer, reporter) = observations();
    let job = tokio::spawn(run(device, left, runtime, settings, Some(reporter)));
    until(&observer, |s| s.running).await?;
    drop(right);
    assert!(timeout(Duration::from_secs(2), job).await??.is_err());
    assert!(!observer.status().ok_or("missing final status")?.running);
    Ok(())
}

#[test]
fn header_lengths_context_lane_replay_and_channels_are_strict() -> TestResult {
    let session = [7; 16];
    let control = Frame {
        kind: 1,
        channel: 0,
        body: vec![0; WIRE_LEN],
    };
    let valid = header(&control, 0, session)?;
    assert_eq!(
        parse_header(&valid, 0, session, LaneMode::Control, 1800, 4)?,
        (1, 0, WIRE_LEN)
    );
    assert!(parse_header(&valid, 1, session, LaneMode::Control, 1800, 4).is_err());
    assert!(parse_header(&valid, 0, [8; 16], LaneMode::Control, 1800, 4).is_err());
    assert!(parse_header(&valid, 0, session, LaneMode::Bulk, 1800, 4).is_err());
    for (offset, value) in [
        (0, 0),
        (4, 2),
        (5, 4),
        (6, 1),
        (7, 1),
        (38, 1),
        (39, 1),
        (37, 4),
    ] {
        let mut invalid = valid;
        invalid[offset] = value;
        assert!(parse_header(&invalid, 0, session, LaneMode::Mixed, 1800, 4).is_err());
    }
    for length in [0_u32, 71, 73, u32::MAX] {
        let mut invalid = valid;
        invalid[32..36].copy_from_slice(&length.to_be_bytes());
        assert!(parse_header(&invalid, 0, session, LaneMode::Mixed, 1800, 4).is_err());
    }
    let data = header(
        &Frame {
            kind: 2,
            channel: 3,
            body: vec![0; 1800],
        },
        0,
        session,
    )?;
    assert!(parse_header(&data, 0, session, LaneMode::Bulk, 1800, 4).is_ok());
    assert!(parse_header(&data, 0, session, LaneMode::Control, 1800, 4).is_err());
    assert!(parse_header(&data, 0, session, LaneMode::Mixed, 1799, 4).is_err());
    Ok(())
}

#[tokio::test]
async fn reader_retains_partial_records_and_rejects_replay_before_second_dispatch() -> TestResult {
    let settings = Settings::new(runtime(), Duplex::Full)?;
    let (mut writer, reader) = tokio::io::duplex(4096);
    let (control, mut events) = mpsc::channel(2);
    let (data, _data_events) = mpsc::channel(2);
    let task = tokio::spawn(read_lane(
        reader,
        LaneMode::Mixed,
        [3; 16],
        1800,
        settings,
        control,
        data,
    ));
    let frame = Frame {
        kind: 1,
        channel: 0,
        body: vec![0; WIRE_LEN],
    };
    let bytes = header(&frame, 0, [3; 16])?;
    for byte in bytes {
        writer.write_all(&[byte]).await?;
        tokio::task::yield_now().await;
    }
    writer.write_all(&frame.body[..5]).await?;
    assert!(events.try_recv().is_err());
    writer.write_all(&frame.body[5..]).await?;
    assert!(matches!(
        timeout(Duration::from_secs(1), events.recv()).await?,
        Some(Event::Control(_))
    ));
    writer.write_all(&bytes).await?;
    assert!(timeout(Duration::from_secs(1), task).await??.is_err());
    assert!(events.try_recv().is_err());
    Ok(())
}

#[tokio::test]
async fn authenticated_malformed_token_fails_without_native_delivery() -> TestResult {
    for (adaptive, kind, length) in [(false, 1, WIRE_LEN), (true, 4, observation::WIRE_LEN)] {
        let runtime = runtime();
        let settings = Settings {
            adaptive,
            ..Settings::new(runtime, Duplex::Full)?
        };
        let (left, mut right) = links(runtime, settings).await?;
        let session = logical_session(&right, session_config(runtime, settings)?, settings)?.0;
        let device = Device::default();
        let (observer, reporter) = observations();
        let task = tokio::spawn(run(device.clone(), left, runtime, settings, Some(reporter)));
        until(&observer, |s| s.running).await?;
        let frame = Frame {
            kind,
            channel: 0,
            body: vec![0xff; length],
        };
        right.writer.write_all(&header(&frame, 0, session)?).await?;
        right.writer.write_all(&frame.body).await?;
        right.writer.flush().await?;
        assert!(timeout(Duration::from_secs(2), task).await??.is_err());
        assert_eq!(device.change(|s| s.delivered.len())?, 0);
        assert!(!observer.status().ok_or("missing stopped status")?.running);
    }
    Ok(())
}

#[tokio::test]
async fn writer_stall_retains_bounded_input_and_times_out() -> TestResult {
    let mut settings = Settings::new(runtime(), Duplex::Full)?;
    // Private writer accepts a tiny test timeout; public Settings rejects this
    // heartbeat relationship before any network or native work begins.
    settings.io_timeout = Duration::from_millis(25);
    let (writer, _unread) = tokio::io::duplex(1);
    let (sender, receiver) = mpsc::channel(1);
    let (flush, observed) = watch::channel(0);
    sender
        .send(Frame {
            kind: 2,
            channel: 0,
            body: vec![1; 400],
        })
        .await?;
    let task = tokio::spawn(write_lane(
        writer,
        [1; 16],
        settings,
        None,
        Some(receiver),
        Some(flush),
        None,
    ));
    tokio::task::yield_now().await;
    sender
        .send(Frame {
            kind: 2,
            channel: 0,
            body: vec![2; 400],
        })
        .await?;
    assert!(
        sender
            .try_send(Frame {
                kind: 2,
                channel: 0,
                body: vec![3; 400]
            })
            .is_err()
    );
    let error = timeout(Duration::from_secs(1), task)
        .await??
        .err()
        .ok_or("writer unexpectedly succeeded")?;
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(*observed.borrow(), 0);
    Ok(())
}

#[tokio::test]
async fn control_allowance_refills_during_continuously_ready_bulk_data() -> TestResult {
    let settings = Settings {
        control_packets_per_second: 2,
        ..Settings::new(runtime(), Duplex::Full)?
    };
    let (writer, mut reader) = tokio::io::duplex(1024);
    let (control_tx, control_rx) = mpsc::channel(3);
    let (data_tx, data_rx) = mpsc::channel(2);
    for _ in 0..3 {
        control_tx
            .send(Frame {
                kind: 1,
                channel: 0,
                body: vec![0; WIRE_LEN],
            })
            .await?;
    }
    let mut tasks = JoinSet::new();
    tasks.spawn(write_lane(
        writer,
        [9; 16],
        settings,
        Some(control_rx),
        Some(data_rx),
        None,
        None,
    ));
    tasks.spawn(async move {
        for _ in 0..1000 {
            data_tx
                .send(Frame {
                    kind: 2,
                    channel: 0,
                    body: vec![0; 400],
                })
                .await
                .map_err(|_| invalid("test data consumer closed"))?;
        }
        Ok(())
    });
    let started = Instant::now();
    let (controls, data) = timeout(Duration::from_secs(3), async {
        let mut controls = 0;
        let mut data = 0;
        let mut sequence = 0;
        while controls < 3 {
            let mut bytes = [0; HEADER_BYTES];
            reader.read_exact(&mut bytes).await?;
            let (kind, _, length) =
                parse_header(&bytes, sequence, [9; 16], LaneMode::Mixed, 1800, 4)?;
            let mut body = vec![0; length];
            reader.read_exact(&mut body).await?;
            sequence += 1;
            if kind == 1 {
                controls += 1;
            }
            if kind == 2 {
                data += 1;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok::<_, io::Error>((controls, data))
    })
    .await??;
    assert_eq!(controls, 3);
    assert!(data > 5 && data < 1000);
    assert!(started.elapsed() >= Duration::from_millis(900));
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

#[test]
fn retirement_external_barrier_counts_dequeued_but_unflushed_control_and_data() -> TestResult {
    let progress = ExternalOutputs {
        data: 3,
        control: 7,
        observation: 0,
    };
    assert_eq!(progress.drain(2, 7, 0, 0)?.pending_outputs, 1);
    assert_eq!(progress.drain(3, 6, 0, 0)?.pending_outputs, 1);
    assert_eq!(progress.drain(3, 7, 0, 1)?.pending_outputs, 1);
    assert_eq!(
        progress.drain(3, 7, 0, 0)?,
        ExternalDrain {
            pending_outputs: 0,
            pending_recovery_records: 0
        }
    );
    assert!(progress.drain(4, 7, 0, 0).is_err());
    assert!(progress.drain(3, 8, 0, 0).is_err());
    Ok(())
}

#[tokio::test]
async fn retirement_control_watermark_waits_for_actual_writer_flush() -> TestResult {
    let settings = Settings::new(runtime(), Duplex::Full)?;
    let (writer, mut reader) = tokio::io::duplex(1);
    let (sender, receiver) = mpsc::channel(1);
    let (flushed, mut observed) = watch::channel(0);
    sender
        .send(Frame {
            kind: 1,
            channel: 0,
            body: vec![0; WIRE_LEN],
        })
        .await?;
    let mut tasks = JoinSet::new();
    tasks.spawn(write_lane(
        writer,
        [5; 16],
        settings,
        Some(receiver),
        None,
        None,
        Some(flushed.into()),
    ));
    let mut first = [0];
    timeout(Duration::from_secs(1), reader.read_exact(&mut first)).await??;
    assert_eq!(sender.capacity(), 1);
    assert_eq!(*observed.borrow(), 0);
    let progress = ExternalOutputs {
        data: 0,
        control: 1,
        observation: 0,
    };
    assert_eq!(
        progress.drain(0, *observed.borrow(), 0, 0)?.pending_outputs,
        1
    );
    let mut record = vec![0; HEADER_BYTES + WIRE_LEN - 1];
    timeout(Duration::from_secs(1), reader.read_exact(&mut record)).await??;
    timeout(Duration::from_secs(1), async {
        while *observed.borrow_and_update() != 1 {
            observed.changed().await.map_err(io::Error::other)?;
        }
        Ok::<_, io::Error>(())
    })
    .await??;
    assert_eq!(
        progress.drain(0, *observed.borrow(), 0, 0)?.pending_outputs,
        0
    );
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

#[tokio::test]
async fn idle_retirement_reuses_slots_beyond_capacity_in_both_directions() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        for adaptive in [false, true] {
            let runtime = runtime();
            let settings = Settings {
                adaptive,
                max_flows: 2,
                idle_flow_timeout: Duration::from_millis(20),
                retirement_retry: Duration::from_millis(30),
                ..Settings::new(runtime, duplex)?
            };
            let (ll, rl) = links(runtime, settings).await?;
            let left = Device::default();
            let right = Device::default();
            let input: Vec<_> = (0..12)
                .map(|n| packet(1000 + n, n as u8, false, 0))
                .collect();
            let reverse: Vec<_> = (0..12)
                .map(|n| packet(1000 + n, n as u8 + 50, true, 0))
                .collect();
            left.change(|s| s.outgoing.extend(input.clone()))?;
            right.change(|s| s.outgoing.extend(reverse.clone()))?;
            let (lo, lr) = observations();
            let (ro, rr) = observations();
            let mut jobs = JoinSet::new();
            jobs.spawn(run(left.clone(), ll, runtime, settings, Some(lr)));
            jobs.spawn(run(right.clone(), rl, runtime, settings, Some(rr)));
            let complete = |s: &Status| {
                assert!(s.engine.outgoing_flows <= 2 && s.engine.incoming_flows <= 2);
                assert!(s.engine.queued.packets <= runtime.queue_packets);
                s.delivered == 12 && s.retired_flows == 12
            };
            until(&lo, complete).await?;
            until(&ro, complete).await?;
            let mut actual = right.change(|s| s.delivered.clone())?;
            actual.sort();
            let mut expected = input;
            expected.sort();
            assert_eq!(actual, expected);
            let mut actual = left.change(|s| s.delivered.clone())?;
            actual.sort();
            let mut expected = reverse;
            expected.sort();
            assert_eq!(actual, expected);
            // A previously retired tuple may re-open with a new DSCP policy and ID.
            left.change(|s| s.outgoing.push_back(packet(1000, 200, false, 8)))?;
            until(&ro, |s| s.delivered == 13).await?;
            until(&lo, |s| s.retired_flows == 13).await?;
            assert_eq!(
                right.change(|s| s.delivered.last().cloned())?,
                Some(packet(1000, 200, false, 8))
            );
            jobs.abort_all();
            while jobs.join_next().await.is_some() {}
        }
    }
    Ok(())
}

async fn withhold_final_ack(
    mut link: Link,
    runtime: RuntimeConfig,
    settings: Settings,
    finals: watch::Sender<u64>,
) -> io::Result<()> {
    use l2tunnel_flow_control::wire::{self, Message};
    let (session, direction) =
        logical_session(&link, session_config(runtime, settings)?, settings)?;
    let mut engine = Active::new(
        settings.engine_config(runtime, u128::from_be_bytes(session))?,
        direction,
        Micros(0),
    )
    .map_err(io::Error::other)?;
    let codec = runtime.codec()?;
    let (sender, mut events) = mpsc::channel(16);
    let mut tasks = JoinSet::new();
    let mut writer;
    let _retained_bulk;
    if settings.duplex == Duplex::Half {
        tasks.spawn(read_lane(
            link.reader,
            LaneMode::Bulk,
            session,
            WIRE_LEN + codec.max_encoded_len(),
            settings,
            sender.clone(),
            sender.clone(),
        ));
        tasks.spawn(read_lane(
            link.reverse_reader
                .take()
                .ok_or_else(|| invalid("test control reader"))?,
            LaneMode::Control,
            session,
            WIRE_LEN + codec.max_encoded_len(),
            settings,
            sender.clone(),
            sender,
        ));
        writer = link
            .reverse_writer
            .take()
            .ok_or_else(|| invalid("test control writer"))?;
        _retained_bulk = Some(link.writer);
    } else {
        tasks.spawn(read_lane(
            link.reader,
            LaneMode::Mixed,
            session,
            WIRE_LEN + codec.max_encoded_len(),
            settings,
            sender.clone(),
            sender,
        ));
        writer = link.writer;
        _retained_bulk = None;
    }
    let started = Instant::now();
    let mut sequence = 0;
    let mut old_controls = Vec::new();
    loop {
        let event = tokio::select! {
            Some(event) = events.recv() => event,
            Some(result) = tasks.join_next() => return result.map_err(io::Error::other)?,
        };
        let now = micros(started.elapsed())?;
        match event {
            Event::Management(_) => return Err(invalid("unexpected test management event")),
            Event::Observation(_) => {
                return Err(invalid("unexpected optional observation in static peer"));
            }
            Event::Control(token) => engine
                .receive_control(&token, now)
                .map_err(io::Error::other)?,
            Event::Data(channel, body) => {
                let payload = codec
                    .decode_vec(&body[WIRE_LEN..])
                    .map_err(io::Error::other)?;
                engine
                    .receive_data(&body[..WIRE_LEN], channel, &payload, now)
                    .map_err(io::Error::other)?;
                while let Some(delivery) = engine.delivery() {
                    engine
                        .confirm_delivery(delivery.record)
                        .map_err(io::Error::other)?;
                }
            }
        }
        while let Some(token) = engine.poll_control().map_err(io::Error::other)? {
            let messages = if matches!(
                wire::decode(&token).map_err(io::Error::other)?,
                Message::FinalAck { .. }
            ) {
                finals.send_modify(|count| *count += 1);
                // Delayed old scoped Grant/Release messages must not unfreeze the key.
                old_controls.clone()
            } else {
                if old_controls.len() < 3 {
                    old_controls.push(token);
                }
                vec![token]
            };
            for token in messages {
                let frame = Frame {
                    kind: 1,
                    channel: 0,
                    body: token.to_vec(),
                };
                writer
                    .write_all(&header(&frame, sequence, session)?)
                    .await?;
                writer.write_all(&frame.body).await?;
                writer.flush().await?;
                sequence += 1;
            }
        }
    }
}

#[tokio::test]
async fn missing_final_ack_retains_frozen_key_and_fails_without_rollback() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        let runtime = runtime();
        let settings = Settings {
            max_flows: 1,
            idle_flow_timeout: Duration::from_millis(20),
            retirement_retry: Duration::from_millis(30),
            retirement_max_attempts: 3,
            ..Settings::new(runtime, duplex)?
        };
        let (ll, rl) = links(runtime, settings).await?;
        let left = Device::default();
        left.change(|s| {
            s.outgoing.push_back(packet(1000, 1, false, 0));
            s.outgoing.push_back(packet(1001, 2, false, 0));
        })?;
        let (observer, reporter) = observations();
        let (finals, observed) = watch::channel(0);
        let peer = tokio::spawn(withhold_final_ack(rl, runtime, settings, finals));
        let local = tokio::spawn(run(left.clone(), ll, runtime, settings, Some(reporter)));
        let frozen = until(&observer, |s| s.engine.pending_retirement.is_some()).await?;
        assert_eq!(frozen.admitted, 1);
        assert_eq!(frozen.retired_flows, 0);
        assert!(frozen.pending_native);
        let error = timeout(Duration::from_secs(2), local)
            .await??
            .err()
            .ok_or("stuck final unexpectedly succeeded")?;
        assert!(error.to_string().contains("RetirementRetriesExhausted"));
        let final_status = observer.status().ok_or("missing final state")?;
        assert!(!final_status.running);
        assert!(final_status.engine.pending_retirement.is_some());
        assert_eq!(final_status.retired_flows, 0);
        assert_eq!(final_status.admitted, 1);
        assert_eq!(*observed.borrow(), 3);
        peer.abort();
        let _ = peer.await;
    }
    Ok(())
}

#[tokio::test]
async fn adaptive_feedback_uses_real_samples_growth_pressure_and_expiry() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        let runtime = RuntimeConfig {
            queue_packets: 16,
            ..runtime()
        };
        let settings = Settings {
            adaptive: true,
            max_flows: 2,
            control_packets_per_second: 512,
            ..Settings::new(runtime, duplex)?
        };
        let (ll, rl) = links(runtime, settings).await?;
        let left = Device::default();
        let right = Device::default();
        let originals: Vec<_> = (0..1200).map(|n| packet(1000, n as u8, false, 0)).collect();
        left.change(|s| s.outgoing.extend(originals.clone()))?;
        let (lo, lr) = observations();
        let (ro, rr) = observations();
        let mut jobs = JoinSet::new();
        jobs.spawn(run(left.clone(), ll, runtime, settings, Some(lr)));
        jobs.spawn(run(right.clone(), rl, runtime, settings, Some(rr)));
        let grown = until(&ro, |s| s.engine.target.records > 2).await?;
        assert!(grown.adaptive && grown.feedback.rtt_micros.is_some());
        assert!(grown.feedback.delivery_bytes_per_second.is_some());
        assert!(grown.demanding_flows > 0 && grown.delivered > 1);
        assert!(grown.engine.target.records <= runtime.queue_packets as u64);
        right.change(|s| s.blocked = true)?;
        let pressured = until(&ro, |s| s.feedback.receiver_pressure).await?;
        assert!(pressured.engine.receiver_payload.records > 0);
        let confirmed = pressured.delivered;
        tokio::time::sleep(Duration::from_millis(20)).await;
        let still_pressured = ro.status().ok_or("missing pressure status")?;
        assert_eq!(still_pressured.delivered, confirmed);
        assert!(still_pressured.feedback.receiver_pressure);
        // The actor can legitimately grow between observing `grown` and the
        // device actually blocking. Compare two samples under observed pressure.
        assert!(still_pressured.engine.target.records <= pressured.engine.target.records);
        right.change(|s| s.blocked = false)?;
        until(&ro, |s| s.delivered == originals.len() as u64).await?;
        until(&lo, |s| s.engine.sender_retained.records == 0).await?;
        assert_eq!(right.change(|s| s.delivered.clone())?, originals);
        let expired = until(&ro, |s| {
            s.delivered == 1200
                && s.feedback.delivery_bytes_per_second.is_none()
                && s.demanding_flows == 0
        })
        .await?;
        assert_eq!(expired.engine.target, Credit::default());
        assert!(expired.observation_handed > 0 && expired.observation_flushed > 0);
        jobs.abort_all();
        while jobs.join_next().await.is_some() {}
    }
    Ok(())
}

#[test]
fn management_framing_requires_negotiation_control_lane_and_bounded_body() -> TestResult {
    let session = [9; 16];
    for size in [l2tunnel_management::HEADER_LEN, 4096] {
        let frame = Frame {
            kind: 5,
            channel: 0,
            body: vec![0; size],
        };
        let bytes = header(&frame, 0, session)?;
        assert!(parse_header(&bytes, 0, session, LaneMode::Mixed, 500, 1).is_err());
        assert!(parse_header_profile(&bytes, 0, session, LaneMode::Bulk, 500, 256, true).is_err());
        assert_eq!(
            parse_header_profile(&bytes, 0, session, LaneMode::Control, 500, 256, true)?,
            (5, 0, size)
        );
        assert!(parse_header_profile(&bytes, 1, session, LaneMode::Mixed, 500, 256, true).is_err());
        assert!(parse_header_profile(&bytes, 0, [8; 16], LaneMode::Mixed, 500, 256, true).is_err());
    }
    for size in [0, l2tunnel_management::HEADER_LEN - 1, 4097] {
        let frame = Frame {
            kind: 5,
            channel: 0,
            body: vec![0; size],
        };
        assert!(
            parse_header_profile(
                &header(&frame, 0, session)?,
                0,
                session,
                LaneMode::Mixed,
                500,
                256,
                true
            )
            .is_err()
        );
    }
    let frame = Frame {
        kind: 5,
        channel: 1,
        body: vec![0; 112],
    };
    assert!(
        parse_header_profile(
            &header(&frame, 0, session)?,
            0,
            session,
            LaneMode::Mixed,
            500,
            256,
            true
        )
        .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn optional_frames_require_negotiation_exact_bounds_and_control_lane() -> TestResult {
    let settings = Settings::new(runtime(), Duplex::Full)?;
    let body = observation::encode(observation::Message::Ping {
        scope: l2tunnel_flow_control::Scope {
            session: 1,
            epoch: 1,
            direction: Direction::Forward,
        },
        nonce: 1,
    })?;
    let frame = Frame {
        kind: 4,
        channel: 0,
        body: body.to_vec(),
    };
    let valid = header(&frame, 0, [1; 16])?;
    assert!(parse_header(&valid, 0, [1; 16], LaneMode::Bulk, 1800, 4).is_err());
    for len in [0_u32, 95, 97, u32::MAX] {
        let mut bytes = valid;
        bytes[32..36].copy_from_slice(&len.to_be_bytes());
        assert!(parse_header(&bytes, 0, [1; 16], LaneMode::Control, 1800, 4).is_err());
    }
    let (mut writer, reader) = tokio::io::duplex(1024);
    let (control, mut events) = mpsc::channel(1);
    let (data, _) = mpsc::channel(1);
    let task = tokio::spawn(read_lane(
        reader,
        LaneMode::Control,
        [1; 16],
        1800,
        settings,
        control,
        data,
    ));
    writer.write_all(&valid).await?;
    // Rejection happens after the fixed header without waiting for an absent body.
    assert!(timeout(Duration::from_secs(1), task).await??.is_err());
    assert!(events.try_recv().is_err());
    Ok(())
}

#[tokio::test]
async fn optional_output_budget_reserves_mandatory_service_and_actual_flush() -> TestResult {
    let settings = Settings {
        adaptive: true,
        control_packets_per_second: 4,
        ..Settings::new(runtime(), Duplex::Full)?
    };
    let (writer, mut reader) = tokio::io::duplex(1);
    let (controls, control_rx) = mpsc::channel(4);
    let (optional, optional_rx) = mpsc::channel(4);
    let (control_flush, control_observed) = watch::channel(0);
    let (optional_flush, mut optional_observed) = watch::channel(0);
    for _ in 0..4 {
        optional
            .send(Frame {
                kind: 4,
                channel: 0,
                body: vec![0; observation::WIRE_LEN],
            })
            .await?;
    }
    let mut jobs = JoinSet::new();
    jobs.spawn(write_lane(
        writer,
        [1; 16],
        settings,
        Some(control_rx),
        None,
        None,
        Some(ControlWriter {
            flushed: control_flush,
            observations: Some((optional_rx, optional_flush)),
            management: None,
        }),
    ));
    let mut first = [0];
    timeout(Duration::from_secs(1), reader.read_exact(&mut first)).await??;
    assert_eq!(*optional_observed.borrow(), 0);
    assert_eq!(optional.capacity(), 1);
    let progress = ExternalOutputs {
        data: 0,
        control: 0,
        observation: 4,
    };
    assert_eq!(progress.drain(0, 0, 0, 0)?.pending_outputs, 4);
    let mut rest = vec![0; HEADER_BYTES + observation::WIRE_LEN - 1];
    reader.read_exact(&mut rest).await?;
    timeout(Duration::from_secs(1), async {
        while *optional_observed.borrow_and_update() != 1 {
            optional_observed
                .changed()
                .await
                .map_err(io::Error::other)?;
        }
        Ok::<_, io::Error>(())
    })
    .await??;
    // Once two optional slots are used, further optional output is paused while
    // two mandatory records can still complete within the same total allowance.
    for _ in 0..2 {
        controls
            .send(Frame {
                kind: 1,
                channel: 0,
                body: vec![0; WIRE_LEN],
            })
            .await?;
    }
    let mut kinds = Vec::new();
    timeout(Duration::from_millis(500), async {
        for sequence in 1..4 {
            let mut bytes = [0; HEADER_BYTES];
            reader.read_exact(&mut bytes).await?;
            let (kind, _, length) =
                parse_header(&bytes, sequence, [1; 16], LaneMode::Control, 1800, 4)?;
            reader.read_exact(&mut vec![0; length]).await?;
            kinds.push(kind);
        }
        Ok::<_, io::Error>(())
    })
    .await??;
    kinds.sort_unstable();
    assert_eq!(kinds, [1, 1, 4]);
    assert!(
        timeout(Duration::from_millis(30), reader.read_exact(&mut [0]))
            .await
            .is_err()
    );
    assert_eq!(*control_observed.borrow(), 2);
    assert_eq!(*optional_observed.borrow(), 2);
    assert_eq!(progress.drain(0, 0, 2, 0)?.pending_outputs, 2);
    jobs.abort_all();
    while jobs.join_next().await.is_some() {}
    Ok(())
}

#[tokio::test]
async fn management_and_credit_share_finite_fair_service_and_actual_flush() -> TestResult {
    let settings = Settings {
        control_packets_per_second: 4,
        ..Settings::new(runtime(), Duplex::Full)?
    };
    let (writer, mut reader) = tokio::io::duplex(1);
    let (controls, control_rx) = mpsc::channel(4);
    let (management, management_rx) = mpsc::channel(4);
    let (control_flush, control_observed) = watch::channel(0);
    let (management_flush, management_observed) = watch::channel(0);
    for _ in 0..3 {
        management
            .send(Frame {
                kind: 5,
                channel: 0,
                body: vec![0; 112],
            })
            .await?;
    }
    let job = tokio::spawn(write_lane(
        writer,
        [1; 16],
        settings,
        Some(control_rx),
        None,
        None,
        Some(ControlWriter {
            flushed: control_flush,
            observations: None,
            management: Some((management_rx, management_flush)),
        }),
    ));
    let mut prefix = [0];
    timeout(Duration::from_secs(1), reader.read_exact(&mut prefix)).await??;
    assert_eq!(*management_observed.borrow(), 0);
    assert_eq!(management.capacity(), 2);
    for _ in 0..2 {
        controls
            .send(Frame {
                kind: 1,
                channel: 0,
                body: vec![0; WIRE_LEN],
            })
            .await?;
    }
    let mut tail = vec![0; HEADER_BYTES + 112 - 1];
    reader.read_exact(&mut tail).await?;
    for (sequence, kind) in [(1, 1), (2, 5), (3, 1)] {
        let mut bytes = [0; HEADER_BYTES];
        timeout(Duration::from_secs(1), reader.read_exact(&mut bytes)).await??;
        let (actual, _, length) = parse_header_profile(
            &bytes,
            sequence,
            [1; 16],
            LaneMode::Control,
            1800,
            256,
            true,
        )?;
        assert_eq!(actual, kind);
        reader.read_exact(&mut vec![0; length]).await?;
    }
    timeout(Duration::from_secs(1), async {
        while *management_observed.borrow() != 2 || *control_observed.borrow() != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert!(
        timeout(Duration::from_millis(30), reader.read_exact(&mut prefix))
            .await
            .is_err()
    );
    job.abort();
    let _ = job.await;
    Ok(())
}
