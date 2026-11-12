use super::*;
use l2tunnel_active::{Credit, FinalOffset, FlowId, Scope};
use l2tunnel_flow_control::RetirementMode;
use l2tunnel_management::MessageKind;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncWrite, AsyncWriteExt};

struct Fixture {
    driver: Driver,
    engine: Active,
    settings: active::Settings,
    observations: Option<Measurements>,
    outgoing: mpsc::Receiver<Frame>,
    flushed: watch::Sender<u64>,
}
impl Fixture {
    fn new(config: &Config, role: Role, session: [u8; 16]) -> Result<Self, TestError> {
        let runtime = runtime();
        let catalog = config.catalog(runtime)?;
        let (local, remote, direction, sender_role) = if role == Role::Client {
            (
                EndpointId(1),
                EndpointId(2),
                Direction::Forward,
                Role::Server,
            )
        } else {
            (
                EndpointId(2),
                EndpointId(1),
                Direction::Reverse,
                Role::Client,
            )
        };
        let peer = Peer::new(
            Identity {
                session: SessionId(session),
                role,
                local,
                remote,
                lane: LaneId(0),
            },
            Epoch(1),
            catalog.initial.clone(),
            &catalog.policies,
            config.transaction,
            Tick(0),
        )?;
        let (sender, outgoing) = mpsc::channel(SLOTS);
        let (flushed, receiver) = watch::channel(0);
        let engine = Active::new(
            config
                .initial
                .engine_config(runtime, u128::from_be_bytes(session))?,
            direction,
            Micros(0),
        )?;
        let observations = if config.initial.adaptive {
            Some(Measurements::new(
                config.initial.observation_config(runtime)?,
                &engine,
                Micros(0),
            )?)
        } else {
            None
        };
        Ok(Self {
            driver: Driver {
                peer,
                origin: Ingress::AuthenticatedManagement {
                    session: SessionId(session),
                    lane: LaneId(0),
                    sender: sender_role,
                },
                role,
                catalog,
                staged: None,
                retired: None,
                drain: None,
                admitted: vec![0; usize::from(config.initial.channels)],
                handed: vec![0; usize::from(config.initial.channels)],
                delivered: vec![0; usize::from(config.initial.channels)],
                pending: None,
                completion: None,
                output: Output {
                    sender,
                    flushed: receiver,
                    pending: VecDeque::new(),
                    produced: 0,
                },
                rate_at: Tick(0),
                received: 0,
                external: ExternalDrain::default(),
            },
            engine,
            settings: config.initial,
            observations,
            outgoing,
            flushed,
        })
    }
    fn effects(&mut self, effects: Effects<Policy>, now: Micros) -> io::Result<()> {
        self.driver.effects(
            effects,
            &mut self.engine,
            &mut self.settings,
            &mut self.observations,
            runtime(),
            now,
        )
    }
    fn receive(&mut self, body: &[u8], now: Micros) -> io::Result<()> {
        let effects = self
            .driver
            .receive(body, now, self.settings.control_packets_per_second)?;
        self.effects(effects, now)
    }
    fn drain(&mut self, now: Micros) -> io::Result<()> {
        if empty(&self.engine)
            && let Some((local, peer)) = &self.driver.drain
            && matches!(
                self.driver.peer.phase(),
                Phase::Draining | Phase::FollowerReady | Phase::FollowerDraining
            )
        {
            self.driver.retired = Some(
                self.engine
                    .drained_reader(self.driver.external)
                    .map_err(io::Error::other)?,
            );
            let effects = self
                .driver
                .peer
                .confirm_drained(local, peer, tick(now))
                .map_err(io::Error::other)?;
            self.effects(effects, now)?;
        }
        Ok(())
    }
    fn take(&mut self) -> io::Result<Frame> {
        self.outgoing.try_recv().map_err(io::Error::other)
    }
    fn acknowledge_output(&self) {
        self.flushed.send_replace(self.driver.output.produced);
    }
}

#[test]
fn precommit_abort_returns_queued_originals_to_unchanged_epoch_after_reply_flush() -> TestResult {
    let config = managed(runtime(), Duplex::Half, false)?;
    let mut client = Fixture::new(&config, Role::Client, [8; 16])?;
    let mut server = Fixture::new(&config, Role::Server, [8; 16])?;
    let metadata = client
        .engine
        .enqueue_ip(&packet(1000, 1, false, 8), 1, Micros(0))?;
    count(&mut client.driver.admitted, metadata.binding.channel)?;
    let queued = client.engine.status();
    let effects = client
        .driver
        .peer
        .propose(client.driver.catalog.policies[1].clone(), Tick(0))?;
    client.effects(effects, Micros(0))?;
    let prepare = client.take()?;
    client.acknowledge_output();
    server.receive(&prepare.body, Micros(0))?;
    let delayed_ready = server.take()?;
    server.acknowledge_output();
    let now = Micros(config.transaction.phase_timeout_ms * 1000);
    let effects = client.driver.peer.poll(tick(now))?;
    client.effects(effects, now)?;
    assert_eq!(client.driver.peer.phase(), Phase::Aborting);
    assert!(!client.driver.can_admit(&client.engine));
    client.receive(&delayed_ready.body, now)?;
    let abort = client.take()?;
    client.acknowledge_output();
    server.receive(&abort.body, now)?;
    assert_eq!(server.driver.peer.phase(), Phase::Idle);
    assert!(!server.driver.can_admit(&server.engine));
    let ack = server.take()?;
    server.acknowledge_output();
    assert!(server.driver.can_admit(&server.engine));
    client.receive(&ack.body, now)?;
    assert_eq!(client.driver.completion, Some(Err(ControlError::Aborted)));
    assert_eq!(client.driver.peer.active_epoch(), Epoch(1));
    assert_eq!(client.engine.status(), queued);
    assert!(client.driver.staged.is_none());
    assert!(client.driver.can_admit(&client.engine));
    // The exact original remains queued; a later Grant can still hand it out.
    let open = client.engine.poll_control()?.ok_or("queued Open")?;
    server.engine.receive_control(&open, now)?;
    while let Some(grant) = server.engine.poll_control()? {
        client.engine.receive_control(&grant, now)?;
    }
    let data = client.engine.poll_data()?.ok_or("retained original")?;
    assert_eq!(data.payload, packet(1000, 1, false, 8));
    assert_eq!(data.record.flow.0, metadata.binding.id.0);
    Ok(())
}

#[test]
fn asymmetric_fences_and_actual_external_ownership_cannot_create_drain_proof() -> TestResult {
    let config = managed(runtime(), Duplex::Half, true)?;
    for (admitted, handed, delivered, local, peer) in
        [(2, 1, 0, 1, 0), (1, 2, 0, 1, 0), (1, 1, 2, 1, 1)]
    {
        let mut state = Fixture::new(&config, Role::Client, [1; 16])?;
        state.driver.admitted = vec![admitted];
        state.driver.handed = vec![handed];
        state.driver.delivered = vec![delivered];
        let before = state.engine.status();
        let error = state.effects(
            Effects {
                outbound: None,
                event: Some(Event::Drain {
                    local: Fence::new(&[local])?,
                    peer: Fence::new(&[peer])?,
                }),
            },
            Micros(0),
        );
        assert!(error.is_err());
        assert!(state.driver.drain.is_none());
        assert_eq!(state.engine.status(), before);
    }
    let mut state = Fixture::new(&config, Role::Client, [1; 16])?;
    let (data, _data) = mpsc::channel(SLOTS);
    let (control, _control) = mpsc::channel(SLOTS);
    let (observed, _observed) = mpsc::channel(SLOTS);
    let outputs = ExternalOutputs {
        data: 1,
        control: 1,
        observation: 1,
    };
    for flushed in [[0, 1, 1], [1, 0, 1], [1, 1, 0]] {
        let proof = external_drain(
            &outputs,
            flushed,
            [&data, &control, &observed],
            &state.observations,
        )?;
        assert!(proof.pending_outputs > 0);
        assert!(state.engine.drained_reader(proof).is_err());
    }
    state
        .observations
        .as_mut()
        .ok_or("observer")?
        .tick(&state.engine, Micros(0))?;
    let proof = external_drain(
        &outputs,
        [1, 1, 1],
        [&data, &control, &observed],
        &state.observations,
    )?;
    assert!(proof.pending_outputs > 0); // Pure pending Ping also blocks a barrier.
    assert!(state.engine.drained_reader(proof).is_err());
    Ok(())
}

#[test]
fn old_measurements_and_controls_cannot_reopen_barrier_or_update_new_epoch() -> TestResult {
    let config = managed(runtime(), Duplex::Half, true)?;
    let session = [3; 16];
    let mut state = Fixture::new(&config, Role::Client, session)?;
    let scope = Scope {
        session: u128::from_be_bytes(session),
        epoch: 1,
        direction: Direction::Reverse,
    };
    let open = wire::encode(wire::Message::Open {
        scope,
        flow: FlowId(1),
    })?;
    state.engine.receive_control(&open, Micros(0))?;
    while state.engine.poll_control()?.is_some() {}
    let final_token = wire::encode(wire::Message::Final {
        offset: FinalOffset {
            scope,
            flow: FlowId(1),
            admitted: Credit::default(),
        },
        mode: RetirementMode::Drained,
    })?;
    state.engine.receive_control(&final_token, Micros(0))?;
    while state.engine.poll_control()?.is_some() {}
    state.driver.retired = Some(state.engine.drained_reader(ExternalDrain::default())?);
    let mut next = config.initial.engine_config(runtime(), scope.session)?;
    next.epoch = 2;
    let mut staged = Some(state.engine.prepare_epoch(next, Micros(1))?);
    for committed in [false, true] {
        if committed {
            state.driver.retired = Some(state.engine.commit_epoch(
                staged.take().ok_or("staged epoch")?,
                Micros(1),
                ExternalDrain::default(),
            )?);
            state.observations = Some(Measurements::new(
                config.initial.observation_config(runtime())?,
                &state.engine,
                Micros(1),
            )?);
        }
        let before = state.engine.status();
        let feedback_before = state
            .observations
            .as_mut()
            .ok_or("observer")?
            .feedback(&state.engine, Micros(1))?;
        let reader = state.driver.retired.as_ref().ok_or("old reader")?;
        for _ in 0..8 {
            reader.check_control(&open)?;
            reader.check_control(&final_token)?;
        }
        let snapshot = observation::LocalDemand {
            scope,
            flow: FlowId(1),
            queued: Credit {
                bytes: 100,
                records: 1,
            },
            head_bytes: 100,
            in_flight: Credit::default(),
            blocked: observation::BlockReason::FlowCredit,
        };
        for message in [
            observation::Message::Demand {
                sequence: 1,
                snapshot,
            },
            observation::Message::Ping {
                scope: Scope {
                    direction: Direction::Forward,
                    ..scope
                },
                nonce: 1,
            },
            observation::Message::Pong { scope, nonce: 1 },
        ] {
            state.driver.observation(
                &observation::encode(message)?,
                &state.engine,
                &mut state.observations,
                Micros(1),
            )?;
        }
        assert_eq!(state.engine.status(), before);
        assert_eq!(
            state
                .observations
                .as_ref()
                .ok_or("observer")?
                .pending_outputs(),
            0
        );
        let feedback_after = state
            .observations
            .as_mut()
            .ok_or("observer")?
            .feedback(&state.engine, Micros(1))?;
        assert_eq!(feedback_after, feedback_before);
        for bad in [
            observation::Message::Demand {
                sequence: 2,
                snapshot: observation::LocalDemand {
                    flow: FlowId(2),
                    ..snapshot
                },
            },
            observation::Message::Ping { scope, nonce: 2 },
            observation::Message::Pong {
                scope: Scope {
                    session: scope.session + 1,
                    ..scope
                },
                nonce: 2,
            },
        ] {
            assert!(
                state
                    .driver
                    .observation(
                        &observation::encode(bad)?,
                        &state.engine,
                        &mut state.observations,
                        Micros(1)
                    )
                    .is_err()
            );
        }
        if committed {
            break;
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Withheld {
    Final,
    Commit,
    Retire,
}

#[tokio::test]
async fn one_retained_native_packet_survives_capacity_stall_and_policy_switch() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        let runtime = runtime();
        let mut config = managed(runtime, duplex, true)?;
        config.initial.max_flows = 1;
        let (ll, rl) = links(runtime, &config).await?;
        let left = Device::default();
        let right = Device::default();
        right.change(|s| s.blocked = true)?;
        let originals = vec![packet(1000, 1, false, 8), packet(1001, 2, false, 8)];
        left.change(|s| s.outgoing.extend(originals.clone()))?;
        let (lh, lr) = channel();
        let (rh, rr) = channel();
        let mut jobs = JoinSet::new();
        jobs.spawn(run(left.clone(), ll, runtime, config.clone(), lr));
        jobs.spawn(run(right.clone(), rl, runtime, config.clone(), rr));
        until(&rh, |s| s.traffic.engine.receiver_payload.records == 1).await?;
        assert_eq!(left.change(|s| s.reads)?, 2);
        assert_eq!(lh.status().ok_or("source")?.traffic.admitted, 1);
        let handle = lh.clone();
        let mode = config.supported[1];
        let request = tokio::spawn(async move { handle.switch_policy(mode).await });
        until(&lh, |s| !s.admitting && s.phase != Phase::Idle).await?;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!request.is_finished());
        assert_eq!(left.change(|s| s.reads)?, 2);
        assert_eq!(rh.status().ok_or("old delivery")?.traffic.delivered, 0);
        right.change(|s| s.blocked = false)?;
        assert_eq!(
            timeout(Duration::from_secs(5), request).await???.epoch,
            Epoch(2)
        );
        until(&rh, |s| s.traffic.delivered == 2).await?;
        assert_eq!(right.change(|s| s.delivered.clone())?, originals);
        let status = lh.status().ok_or("new source")?;
        assert_eq!(status.traffic.admitted, 2);
        assert_eq!(status.admitted_by_channel.iter().sum::<u64>(), 1);
        assert_eq!(status.traffic.retired_flows, 1);
        jobs.abort_all();
        while jobs.join_next().await.is_some() {}
    }
    Ok(())
}

async fn write_frame(
    writer: &mut std::pin::Pin<Box<dyn AsyncWrite + Send>>,
    frame: Frame,
    sequence: &mut u64,
    session: [u8; 16],
) -> io::Result<()> {
    writer
        .write_all(&active::header(&frame, *sequence, session)?)
        .await?;
    writer.write_all(&frame.body).await?;
    writer.flush().await?;
    *sequence = increment(*sequence)?;
    Ok(())
}

// An authenticated but deliberately faulty peer suppresses selected logical
// replies before encoding them onto TLS. This is not a TCP packet-loss model.
async fn faulty_peer(
    mut link: Link,
    config: Config,
    withheld: Withheld,
    dropping: Arc<AtomicBool>,
    observed: watch::Sender<u64>,
) -> Result<(), TestError> {
    let settings = config.initial;
    let (session, _) = active::logical_session(
        &link,
        crate::active_management::session_config(runtime(), &config)?,
        settings,
    )?;
    let mut state = Fixture::new(&config, Role::Server, session)?;
    let codec = runtime().codec()?;
    let maximum = WIRE_LEN + codec.max_encoded_len();
    let (sender, mut input) = mpsc::channel(SLOTS);
    let mut tasks = JoinSet::new();
    let mut writer;
    let _retained_bulk;
    if settings.duplex == Duplex::Half {
        tasks.spawn(active::read_lane_profile(
            link.reader,
            LaneMode::Bulk,
            session,
            maximum,
            ReadProfile {
                settings,
                management: true,
            },
            sender.clone(),
            sender.clone(),
        ));
        tasks.spawn(active::read_lane_profile(
            link.reverse_reader.take().ok_or("control reader")?,
            LaneMode::Control,
            session,
            maximum,
            ReadProfile {
                settings,
                management: true,
            },
            sender.clone(),
            sender,
        ));
        writer = link.reverse_writer.take().ok_or("control writer")?;
        _retained_bulk = Some(link.writer);
    } else {
        tasks.spawn(active::read_lane_profile(
            link.reader,
            LaneMode::Mixed,
            session,
            maximum,
            ReadProfile {
                settings,
                management: true,
            },
            sender.clone(),
            sender,
        ));
        writer = link.writer;
        _retained_bulk = None;
    }
    let start = Instant::now();
    let mut sequence = 0;
    let mut old_controls: Vec<[u8; WIRE_LEN]> = Vec::new();
    loop {
        let event = tokio::select! {
            Some(event) = input.recv() => event,
            Some(result) = tasks.join_next() => {result??; return Err("faulty peer reader ended".into());},
        };
        let now = micros(start.elapsed())?;
        match event {
            Input::Management(body) => state.receive(&body, now)?,
            Input::Control(token) => state.engine.receive_control(&token, now)?,
            Input::Data(channel, body) => {
                let payload = codec.decode_vec(&body[WIRE_LEN..])?;
                state
                    .engine
                    .receive_data(&body[..WIRE_LEN], channel, &payload, now)?;
                while let Some(delivery) = state.engine.delivery() {
                    let (record, channel) = (delivery.record, delivery.channel);
                    state.engine.confirm_delivery(record)?;
                    count(&mut state.driver.delivered, channel)?;
                }
            }
            Input::Observation(body) => {
                state
                    .driver
                    .observation(&body, &state.engine, &mut state.observations, now)?
            }
        }
        while let Some(token) = state.engine.poll_control()? {
            let final_ack = matches!(wire::decode(&token)?, wire::Message::FinalAck { .. });
            if final_ack && matches!(withheld, Withheld::Final) && dropping.load(Ordering::SeqCst) {
                observed.send_modify(|n| *n += 1);
                for token in &old_controls {
                    write_frame(
                        &mut writer,
                        Frame {
                            kind: 1,
                            channel: 0,
                            body: token.to_vec(),
                        },
                        &mut sequence,
                        session,
                    )
                    .await?;
                }
            } else {
                if !final_ack && old_controls.len() < 4 {
                    old_controls.push(token);
                }
                write_frame(
                    &mut writer,
                    Frame {
                        kind: 1,
                        channel: 0,
                        body: token.to_vec(),
                    },
                    &mut sequence,
                    session,
                )
                .await?;
            }
        }
        state.drain(now)?;
        while let Ok(frame) = state.outgoing.try_recv() {
            let decoded = l2tunnel_management::Frame::decode(
                &frame.body,
                l2tunnel_management::Limits::default(),
            )?;
            let suppress = matches!(
                (withheld, decoded.header.kind),
                (Withheld::Commit, MessageKind::CommitAck)
                    | (Withheld::Retire, MessageKind::Retire)
            ) && dropping.load(Ordering::SeqCst);
            if suppress {
                observed.send_modify(|n| *n += 1);
            } else {
                write_frame(&mut writer, frame, &mut sequence, session).await?;
            }
            // Test peer deliberately disposes suppressed replies. Production
            // completion tests below assert the honest endpoint never follows it.
            state.acknowledge_output();
        }
    }
}

#[tokio::test]
async fn actual_tls_missing_final_ack_preserves_frozen_old_flow_and_fails_request() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        let runtime = runtime();
        let mut config = managed(runtime, duplex, false)?;
        config.initial.retirement_retry = Duration::from_millis(20);
        config.initial.retirement_max_attempts = 3;
        let (ll, rl) = links(runtime, &config).await?;
        let native = Device::default();
        native.change(|s| s.outgoing.push_back(packet(1000, 1, false, 8)))?;
        let (handle, control) = channel();
        let (counter, observed) = watch::channel(0);
        let peer = tokio::spawn(faulty_peer(
            rl,
            config.clone(),
            Withheld::Final,
            Arc::new(AtomicBool::new(true)),
            counter,
        ));
        let local = tokio::spawn(run(native, ll, runtime, config.clone(), control));
        until(&handle, |s| {
            s.traffic.admitted == 1
                && s.traffic.engine.sender_retained.records == 0
                && s.traffic.flushed == 1
        })
        .await?;
        let request_handle = handle.clone();
        let mode = config.supported[1];
        let request = tokio::spawn(async move { request_handle.switch_policy(mode).await });
        let frozen = until(&handle, |s| s.traffic.engine.pending_retirement.is_some()).await?;
        assert_eq!(frozen.epoch, Epoch(1));
        assert!(!frozen.admitting);
        let result = timeout(Duration::from_secs(2), local).await??;
        assert!(
            result
                .err()
                .ok_or("unexpected success")?
                .to_string()
                .contains("RetirementRetriesExhausted")
        );
        assert_eq!(request.await?, Err(ControlError::Closed));
        let status = handle.status().ok_or("final status")?;
        assert_eq!(status.epoch, Epoch(1));
        assert_eq!(status.traffic.retired_flows, 0);
        assert_eq!(status.traffic.engine.outgoing_flows, 1);
        assert!(!status.admitting);
        assert_eq!(*observed.borrow(), 3);
        peer.abort();
        let _ = peer.await;
    }
    Ok(())
}

#[tokio::test]
async fn actual_tls_lost_commit_or_retire_reply_reconciles_only_after_exact_retry() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        for withheld in [Withheld::Commit, Withheld::Retire] {
            let runtime = runtime();
            let mut config = managed(runtime, duplex, false)?;
            config.transaction = transaction::Settings {
                retry_ms: 20,
                phase_timeout_ms: 100,
                reconcile_timeout_ms: 500,
            };
            let (ll, rl) = links(runtime, &config).await?;
            let (handle, control) = channel();
            let dropping = Arc::new(AtomicBool::new(true));
            let (counter, observed) = watch::channel(0);
            let peer = tokio::spawn(faulty_peer(
                rl,
                config.clone(),
                withheld,
                dropping.clone(),
                counter,
            ));
            let local = tokio::spawn(run(Device::default(), ll, runtime, config.clone(), control));
            until(&handle, |s| s.admitting).await?;
            let requester = handle.clone();
            let mode = config.supported[1];
            let request = tokio::spawn(async move { requester.switch_policy(mode).await });
            let uncertain = until(&handle, |s| s.phase == Phase::Uncertain).await.map_err(|error| format!("uncertainty observation: {error}; status={:?}; request_finished={}; local_finished={}; peer_finished={}; suppressed={}", handle.status(), request.is_finished(), local.is_finished(), peer.is_finished(), *observed.borrow()))?;
            assert!(!uncertain.admitting);
            assert!(!request.is_finished());
            assert_eq!(
                uncertain.epoch,
                if matches!(withheld, Withheld::Commit) {
                    Epoch(1)
                } else {
                    Epoch(2)
                }
            );
            assert!(*observed.borrow() > 0);
            dropping.store(false, Ordering::SeqCst);
            let completed = timeout(Duration::from_secs(2), request).await.map_err(|error| format!("reconciliation request: {error}; status={:?}; local_finished={}; peer_finished={}", handle.status(), local.is_finished(), peer.is_finished()))???;
            assert_eq!(completed.epoch, Epoch(2));
            assert_eq!(completed.mode, mode);
            until(&handle, |s| s.epoch == Epoch(2) && s.admitting).await?;
            local.abort();
            peer.abort();
            let _ = local.await;
            let _ = peer.await;
        }
    }
    Ok(())
}

#[tokio::test]
async fn actual_tls_exhausted_uncertainty_closes_without_local_success() -> TestResult {
    let runtime = runtime();
    let mut config = managed(runtime, Duplex::Half, false)?;
    config.transaction = transaction::Settings {
        retry_ms: 20,
        phase_timeout_ms: 80,
        reconcile_timeout_ms: 160,
    };
    let (ll, rl) = links(runtime, &config).await?;
    let (handle, control) = channel();
    let (counter, observed) = watch::channel(0);
    let peer = tokio::spawn(faulty_peer(
        rl,
        config.clone(),
        Withheld::Commit,
        Arc::new(AtomicBool::new(true)),
        counter,
    ));
    let local = tokio::spawn(run(Device::default(), ll, runtime, config.clone(), control));
    until(&handle, |s| s.admitting).await?;
    let requester = handle.clone();
    let mode = config.supported[1];
    let request = tokio::spawn(async move { requester.switch_policy(mode).await });
    until(&handle, |s| s.phase == Phase::Uncertain).await.map_err(|error| format!("exhaustion uncertainty observation: {error}; status={:?}; request_finished={}; local_finished={}; peer_finished={}; suppressed={}", handle.status(), request.is_finished(), local.is_finished(), peer.is_finished(), *observed.borrow()))?;
    assert!(
        timeout(Duration::from_secs(2), local)
            .await
            .map_err(|error| format!(
                "uncertainty runtime termination: {error}; status={:?}",
                handle.status()
            ))??
            .is_err()
    );
    assert_eq!(request.await?, Err(ControlError::Closed));
    assert_eq!(handle.status().ok_or("closed")?.epoch, Epoch(1));
    assert!(!handle.status().ok_or("closed")?.admitting);
    peer.abort();
    let _ = peer.await;
    Ok(())
}
