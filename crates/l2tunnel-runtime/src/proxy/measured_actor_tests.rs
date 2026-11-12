//! Deterministic actual-table tests with bounded mock writer handoffs. Real TLS
//! full-write behavior is exercised separately by proxy_tests' measured matrix.
use super::*;
use crate::proxy::measured as profile;
use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};
use tokio::io::{AsyncReadExt, AsyncWrite};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
struct Side {
    actor: Actor,
    users: mpsc::Receiver<Vec<u8>>,
    progress: watch::Sender<Progress>,
    _controls: mpsc::Receiver<Output>,
}
fn side(originator: bool) -> Result<Side> {
    side_with_initial(originator, None)
}
fn side_with_initial(originator: bool, initial: Option<Window>) -> Result<Side> {
    let (mut actor, users, controls) = actor(originator)?;
    if let Some(initial) = initial {
        actor.config.relay.initial = initial;
    }
    actor.config.relay.admission_timeout = Duration::from_secs(3);
    actor.table =
        session::Table::new(actor.config.table(actor.logical, originator, 17), Millis(0))?;
    let mut config = profile::config_tests::config()?;
    config.fixed = actor.config.clone();
    if let Some(initial) = initial {
        config.measured.allocation.target.initial = l2tunnel_flow_control::Credit {
            bytes: initial.bytes,
            records: initial.records,
        };
    }
    actor.measured = Some(profile::State::new(config, &actor.table)?);
    let (progress, receiver) = watch::channel(Progress {
        ready: true,
        ..Progress::default()
    });
    actor.writers[0].progress = receiver;
    Ok(Side {
        actor,
        users,
        progress,
        _controls: controls,
    })
}
struct Native(l2tunnel_raw_tcp::TcpEngine);
impl PacketDevice for Native {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ip
    }
    fn receive(&mut self, _: &mut [u8]) -> io::Result<Option<usize>> {
        Ok(None)
    }
    fn transmit(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.0.ingest(bytes).map_err(error)
    }
}
struct Lab {
    a: Side,
    b: Side,
    hosts: [Native; 2],
}
impl Lab {
    async fn active() -> Result<Self> {
        Self::active_with_receive_bytes(None, None).await
    }
    async fn active_with_receive_bytes(
        receive_bytes: Option<usize>,
        initial: Option<Window>,
    ) -> Result<Self> {
        let a = side_with_initial(true, initial)?;
        let b = side_with_initial(false, initial)?;
        let mut config = a.actor.config.table(a.actor.logical, true, 31).native;
        if let Some(bytes) = receive_bytes {
            config.receive_bytes = bytes;
        }
        config.local = ([10, 112, 0, 1], 32001).into();
        config.peer = ([10, 112, 0, 2], 443).into();
        let first = Native(l2tunnel_raw_tcp::TcpEngine::new_ip(
            config,
            proxy::Role::Client,
            Millis(0),
        )?);
        std::mem::swap(&mut config.local, &mut config.peer);
        config.random_seed += 1;
        let second = Native(l2tunnel_raw_tcp::TcpEngine::new_ip(
            config,
            proxy::Role::Server,
            Millis(0),
        )?);
        let mut lab = Self {
            a,
            b,
            hosts: [first, second],
        };
        for _ in 0..24 {
            lab.step().await?;
        }
        for side in [&lab.a, &lab.b] {
            assert_eq!(
                side.actor.table.flow_status(1).map(|s| s.phase),
                Some(session::FlowPhase::Active)
            );
        }
        assert!(lab.hosts.iter().all(|h| h.0.status().established));
        Ok(lab)
    }
    async fn step(&mut self) -> Result {
        let [first, second] = &mut self.hosts;
        for (side, host) in [(&mut self.a, first), (&mut self.b, second)] {
            host.0.poll(side.actor.millis()?, 8)?;
            while let Some(bytes) = host.0.pop_packet() {
                assert!(side.actor.receive_native(bytes)?.is_none());
            }
            side.actor.poll_table()?;
            side.actor.schedule_table()?;
            side.actor.schedule_measured()?;
            side.actor.send_user()?;
            side.actor.deliver(host)?;
        }
        fn exchange(source: &mut Side, target: &mut Side) -> Result {
            if let Ok(bytes) = source.users.try_recv() {
                assert!(target.actor.receive_user(bytes)?.is_none());
                source.progress.send_replace(Progress {
                    users: source.actor.sent_records,
                    ready: true,
                    ..Progress::default()
                });
                source.actor.measured_callbacks()?;
            }
            Ok(())
        }
        exchange(&mut self.a, &mut self.b)?;
        exchange(&mut self.b, &mut self.a)?;
        tokio::time::advance(Duration::from_millis(1)).await;
        Ok(())
    }
    fn probe(&mut self) -> Result {
        let now = self.a.actor.micros()?;
        let state = self.a.actor.measured.as_mut().ok_or("Controller")?;
        state.controller.stage_probe(&self.a.actor.table, 1, now)?;
        state.admission_cursor = self.a.actor.config.relay.max_flows + 1;
        self.a.actor.schedule_measured()?;
        assert_eq!(
            self.a
                .actor
                .measured
                .as_ref()
                .ok_or("Controller")?
                .ledger
                .counts(),
            (1, 0)
        );
        Ok(())
    }
}

#[tokio::test(start_paused = true)]
async fn measured_admitted_terminal_flow_survives_quiesce_until_exact_full_flush() -> Result {
    let mut lab = Lab::active().await?;
    lab.probe()?;
    lab.a.actor.table.cancel(1, lab.a.actor.millis()?)?;
    lab.a.actor.drain(Instant::now())?;
    let deadline = lab.a.actor.deadline;
    lab.a.actor.measured_callbacks()?;
    assert_eq!(
        lab.a
            .actor
            .measured
            .as_ref()
            .ok_or("Controller")?
            .ledger
            .counts(),
        (1, 0)
    );
    lab.a.actor.send_user()?;
    let bytes = lab.a.users.try_recv()?;
    assert!(wire::decode_profile(&bytes, &lab.a.actor.config, true)?.measurement);
    lab.a.actor.measured_callbacks()?;
    assert_eq!(
        lab.a
            .actor
            .measured
            .as_ref()
            .ok_or("Controller")?
            .ledger
            .counts(),
        (0, 1)
    );
    assert!(
        !lab.a
            .actor
            .measured
            .as_ref()
            .ok_or("Controller")?
            .controller
            .drained()
    );
    lab.a.progress.send_replace(Progress {
        users: lab.a.actor.sent_records,
        ready: true,
        ..Progress::default()
    });
    lab.a.actor.measured_callbacks()?;
    let state = lab.a.actor.measured.as_ref().ok_or("Controller")?;
    assert_eq!(state.ledger.counts(), (0, 0));
    assert!(state.controller.drained());
    assert_eq!(lab.a.actor.deadline, deadline);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn measured_expired_handoff_keeps_proof_even_when_writer_reports_flush() -> Result {
    let mut lab = Lab::active().await?;
    lab.probe()?;
    lab.a.actor.send_user()?;
    let _bytes = lab.a.users.try_recv()?;
    tokio::time::advance(Duration::from_millis(50)).await;
    lab.a.progress.send_replace(Progress {
        users: lab.a.actor.sent_records,
        ready: true,
        ..Progress::default()
    });
    assert!(lab.a.actor.measured_callbacks().is_err());
    assert_eq!(
        lab.a
            .actor
            .measured
            .as_ref()
            .ok_or("Controller")?
            .ledger
            .counts(),
        (0, 1)
    );
    assert!(lab.a.actor.measured_callbacks().is_err());
    assert!(
        !lab.a
            .actor
            .measured
            .as_ref()
            .ok_or("Controller")?
            .controller
            .drained()
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn measured_original_drain_deadline_precedes_late_successful_callback() -> Result {
    let mut lab = Lab::active().await?;
    lab.probe()?;
    lab.a.actor.send_user()?;
    let _bytes = lab.a.users.try_recv()?;
    lab.a.actor.deadline = Some(Instant::now() + Duration::from_millis(1));
    tokio::time::advance(Duration::from_millis(1)).await;
    lab.a.progress.send_replace(Progress {
        users: lab.a.actor.sent_records,
        ready: true,
        ..Progress::default()
    });
    assert_eq!(
        lab.a
            .actor
            .measured_callbacks()
            .err()
            .ok_or("deadline")?
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(
        lab.a
            .actor
            .measured
            .as_ref()
            .ok_or("Controller")?
            .ledger
            .counts(),
        (0, 1)
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn measured_ready_at_or_after_original_startup_deadline_is_never_published() -> Result {
    for late in [Duration::ZERO, Duration::from_micros(1)] {
        let mut side = side(true)?;
        side.actor.started = false;
        side.actor.config.timeouts.startup = Duration::from_millis(5);
        tokio::time::advance(Duration::from_millis(5) + late).await;
        assert_eq!(
            side.actor
                .service_control()
                .err()
                .ok_or("late Ready")?
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert!(!side.actor.started);
        assert!(side.actor.measured_deadlines(Instant::now()).is_err());
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn measured_ready_empty_join_after_original_deadline_cannot_report_success() -> Result {
    let mut side = side(true)?;
    let end = Instant::now() + Duration::from_millis(1);
    side.actor.deadline = Some(end);
    tokio::time::advance(Duration::from_millis(1)).await;
    let mut tasks = JoinSet::new();
    assert_eq!(
        side.actor
            .join_original(&mut tasks, end)
            .await
            .err()
            .ok_or("expired join")?
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert!(tasks.is_empty());
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn measured_common_saturation_does_not_admit_or_consume_pending_generation() -> Result {
    let mut lab = Lab::active().await?;
    let now = lab.a.actor.micros()?;
    let state = lab.a.actor.measured.as_mut().ok_or("Controller")?;
    state.controller.stage_probe(&lab.a.actor.table, 1, now)?;
    state.admission_cursor = lab.a.actor.config.relay.max_flows + 1;
    let binding = *lab.a.actor.bindings.get(&1).ok_or("binding")?;
    let mut copies = 0;
    loop {
        match lab.a.actor.wire.push(
            binding.key,
            binding.weight,
            vec![0; 80],
            Owner::Transparent(1),
            lab.a.actor.start.elapsed(),
        ) {
            Ok(()) => copies += 1,
            Err(e) if e.pressure => break,
            Err(e) => return Err(e.error.into()),
        }
        assert!(copies <= lab.a.actor.config.mux.queue_records);
    }
    lab.a.actor.schedule_measured()?;
    let state = lab.a.actor.measured.as_ref().ok_or("Controller")?;
    assert_eq!(state.ledger.counts(), (0, 0));
    assert!(state.wire_pressure);
    let observed = state.controller.observations(&lab.a.actor.table, now)?;
    assert_eq!((observed.owner.pending, observed.owner.admitted), (1, 0));
    assert!(lab.a.actor.wire.pop(|_, _| true)?.is_some());
    lab.a
        .actor
        .measured
        .as_mut()
        .ok_or("Controller")?
        .admission_cursor = lab.a.actor.config.relay.max_flows + 1;
    let before = lab.a.actor.wire.usage().0;
    lab.a.actor.schedule_measured()?;
    assert_eq!(lab.a.actor.wire.usage().0 - before, 128); //56+24+44+4
    let state = lab.a.actor.measured.as_ref().ok_or("Controller")?;
    assert_eq!(state.ledger.counts(), (1, 0));
    assert_eq!(state.framed_bytes, 128);
    assert_eq!(state.admitted, [0, 1, 0]);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn measured_rotation_admits_transparent_probe_and_allocated_proxy_without_priority_bypass()
-> Result {
    let mut lab = Lab::active().await?;
    let now = lab.a.actor.micros()?;
    let state = lab.a.actor.measured.as_mut().ok_or("Controller")?;
    state.config.service.admission_work_per_turn = 1;
    state.admission_cursor = lab.a.actor.config.relay.max_flows;
    state.controller.stage_probe(&lab.a.actor.table, 1, now)?;
    let mut transparent = vec![0; 60];
    transparent[0] = 0x60;
    transparent[4..6].copy_from_slice(&20_u16.to_be_bytes());
    transparent[6] = 253;
    transparent[7] = 64;
    transparent[8] = 0xfd;
    transparent[23] = 1;
    transparent[24] = 0xfd;
    transparent[39] = 2;
    lab.a.actor.input = lab.a.actor.receive_native(transparent)?;
    assert!(lab.a.actor.input_transparent);
    let mut cfg = lab
        .a
        .actor
        .config
        .table(lab.a.actor.logical, true, 91)
        .native;
    cfg.local = ([10, 112, 0, 1], 32002).into();
    cfg.peer = ([10, 112, 0, 2], 443).into();
    let mut second =
        l2tunnel_raw_tcp::TcpEngine::new_ip(cfg, proxy::Role::Client, lab.a.actor.millis()?)?;
    second.poll(lab.a.actor.millis()?, 4)?;
    assert!(
        lab.a
            .actor
            .receive_native(second.pop_packet().ok_or("second SYN")?)?
            .is_none()
    );
    for _ in 0..4 {
        lab.a.actor.schedule_measured()?;
    }
    let mut classes = [false; 3];
    while let Some(record) = lab.a.actor.wire.pop(|_, _| true)? {
        let decoded = profile::envelope::decode_fixed(&lab.a.actor.config, &record.bytes)?;
        classes[decoded.kind as usize] = true;
    }
    assert_eq!(classes, [true; 3]);
    assert!(lab.a.actor.input.is_none());
    assert!(!lab.a.actor.input_transparent);
    assert_eq!(
        lab.a
            .actor
            .measured
            .as_ref()
            .ok_or("Controller")?
            .ledger
            .counts(),
        (1, 0)
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn measured_demand_and_echo_costs_and_coalesced_full_flush_release_exact_tokens() -> Result {
    let mut lab = Lab::active().await?;
    let now = lab.a.actor.micros()?;
    let state = lab.a.actor.measured.as_mut().ok_or("Controller")?;
    state.controller.stage_demand(&lab.a.actor.table, 1, now)?;
    state.controller.stage_probe(&lab.a.actor.table, 1, now)?;
    state.config.service.admission_work_per_turn = 64;
    lab.a.actor.schedule_measured()?;
    let state = lab.a.actor.measured.as_ref().ok_or("Controller")?;
    assert_eq!(state.admitted, [1, 1, 0]);
    assert_eq!(state.framed_bytes, 176 + 128);
    assert_eq!(state.ledger.counts(), (2, 0));
    assert_eq!(lab.a.actor.wire.usage(), (176 + 128, 2));
    for _ in 0..2 {
        lab.a.actor.send_user()?;
        let _bytes = lab.a.users.try_recv()?;
    }
    assert_eq!(
        lab.a
            .actor
            .measured
            .as_ref()
            .ok_or("Controller")?
            .ledger
            .counts(),
        (0, 2)
    );
    lab.a.actor.measured_callbacks()?;
    assert_eq!(
        lab.a
            .actor
            .measured
            .as_ref()
            .ok_or("Controller")?
            .ledger
            .counts(),
        (0, 2)
    );
    lab.a.progress.send_replace(Progress {
        users: lab.a.actor.sent_records,
        ready: true,
        ..Progress::default()
    });
    lab.a.actor.measured_callbacks()?;
    assert_eq!(
        lab.a
            .actor
            .measured
            .as_ref()
            .ok_or("Controller")?
            .ledger
            .counts(),
        (0, 0)
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn measured_replay_wrong_channel_and_native_magic_never_authorize_control() -> Result {
    let mut lab = Lab::active().await?;
    lab.probe()?;
    lab.a.actor.send_user()?;
    let bytes = lab.a.users.try_recv()?;
    let mut wrong = bytes.clone();
    let channel = u16::from_be_bytes([wrong[8], wrong[9]]);
    wrong[8..10].copy_from_slice(&((channel + 1) % lab.b.actor.config.mux.channels).to_be_bytes());
    let count = lab.b.actor.received_records;
    assert!(lab.b.actor.receive_user(wrong).is_err());
    assert_eq!(lab.b.actor.received_records, count);
    assert!(lab.b.actor.receive_native(bytes.clone()).is_err());
    assert_eq!(lab.b.actor.received_records, count);
    assert!(lab.b.actor.receive_user(bytes.clone())?.is_none());
    // Same-stream duplicates are allowed as idempotent ingress, but cannot create
    // another echo generation or refresh evidence. Outer packet replay is checked
    // by the actual authenticated reader, not this actor-only fixture.
    let before = lab
        .b
        .actor
        .measured
        .as_ref()
        .ok_or("Controller")?
        .controller
        .observations(&lab.b.actor.table, lab.b.actor.micros()?)?
        .owner;
    assert!(lab.b.actor.receive_user(bytes)?.is_none());
    let after = lab
        .b
        .actor
        .measured
        .as_ref()
        .ok_or("Controller")?
        .controller
        .observations(&lab.b.actor.table, lab.b.actor.micros()?)?
        .owner;
    assert_eq!(before.pending, after.pending);
    assert_eq!(before.incoming_proofs, after.incoming_proofs);
    Ok(())
}

#[derive(Default)]
struct FlushState {
    blocked: bool,
    waiter: Option<Waker>,
}
struct FlushGate {
    stream: tokio::io::DuplexStream,
    state: Arc<Mutex<FlushState>>,
}
impl AsyncWrite for FlushGate {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        {
            let mut state = match self.state.lock() {
                Ok(state) => state,
                Err(_) => return Poll::Ready(Err(invalid("flush gate lock"))),
            };
            if state.blocked {
                state.waiter = Some(cx.waker().clone());
                return Poll::Pending;
            }
        }
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
async fn read_frame(reader: &mut tokio::io::DuplexStream) -> io::Result<Vec<u8>> {
    let len = reader.read_u32().await? as usize;
    if len > 2048 {
        return Err(invalid("test frame bound"));
    }
    let mut bytes = vec![0; len];
    reader.read_exact(&mut bytes).await?;
    Ok(bytes)
}
#[tokio::test(start_paused = true)]
async fn measured_actual_writer_partial_body_and_pending_flush_retain_token_in_both_branches()
-> Result {
    for quiesce in [false, true] {
        let mut lab = Lab::active().await?;
        lab.probe()?;
        let Side {
            mut actor, users, ..
        } = lab.a;
        let (stream, mut reader) = tokio::io::duplex(16);
        let state = Arc::new(Mutex::new(FlushState::default()));
        let gate = FlushGate {
            stream,
            state: state.clone(),
        };
        let (control, controls) = mpsc::channel(8);
        let (progress, prx) = watch::channel(Progress::default());
        actor.writers[0].progress = prx;
        let (events, _events) = mpsc::channel(8);
        let start = actor.writers[0].start;
        control.try_send(Output::Control(Frame::Start(start)))?;
        control.try_send(Output::Control(Frame::Ready(start)))?;
        let task = tokio::spawn(transport::writer(
            gate,
            Direction {
                index: 0,
                lane: 0,
                session: [9; 16],
                bulk: true,
            },
            256,
            controls,
            users,
            progress,
            events,
        ));
        let _start = read_frame(&mut reader).await?;
        let _ready = read_frame(&mut reader).await?;
        // The standalone writer fixture starts after the setup's already-flushed
        // mock handoffs. Add that fixed baseline to this writer's actual count;
        // production keeps the original writer and never resets its ordinal.
        let baseline = actor.sent_records;
        state.lock().map_err(|_| invalid("gate"))?.blocked = true;
        actor.send_user()?;
        if quiesce {
            control.try_send(Output::Control(Frame::Quiesce))?;
        }
        tokio::task::yield_now().await;
        assert_eq!(actor.writers[0].progress.borrow().users, 0);
        let len = reader.read_u32().await? as usize;
        let mut body = vec![0; len];
        reader.read_exact(&mut body[..7]).await?;
        assert_eq!(actor.writers[0].progress.borrow().users, 0);
        let now = actor.micros()?;
        actor
            .measured
            .as_mut()
            .ok_or("Controller")?
            .callbacks(&actor.table, baseline, now)?;
        assert_eq!(
            actor.measured.as_ref().ok_or("Controller")?.ledger.counts(),
            (0, 1)
        );
        reader.read_exact(&mut body[7..]).await?;
        tokio::task::yield_now().await;
        assert_eq!(actor.writers[0].progress.borrow().users, 0);
        let now = actor.micros()?;
        actor
            .measured
            .as_mut()
            .ok_or("Controller")?
            .callbacks(&actor.table, baseline, now)?;
        assert_eq!(
            actor.measured.as_ref().ok_or("Controller")?.ledger.counts(),
            (0, 1)
        );
        {
            let mut gate = state.lock().map_err(|_| invalid("gate"))?;
            gate.blocked = false;
            if let Some(waker) = gate.waiter.take() {
                waker.wake();
            }
        }
        if quiesce {
            let _quiesce = read_frame(&mut reader).await?;
        }
        for _ in 0..8 {
            if actor.writers[0].progress.borrow().users == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(actor.writers[0].progress.borrow().users, 1);
        let now = actor.micros()?;
        actor
            .measured
            .as_mut()
            .ok_or("Controller")?
            .callbacks(&actor.table, baseline + 1, now)?;
        assert_eq!(
            actor.measured.as_ref().ok_or("Controller")?.ledger.counts(),
            (0, 0)
        );
        task.abort();
        let _ = task.await;
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn measured_native_credit_demand_and_downstream_zero_window_pressure_are_distinct() -> Result
{
    let mut lab = Lab::active().await?;
    lab.a.actor.measured_service()?;
    assert!(
        !lab.a
            .actor
            .measured
            .as_ref()
            .ok_or("Controller")?
            .snapshot(&lab.a.actor.table, lab.a.actor.micros()?)?
            .pressure
            .receiver_pressure
    );
    // Both actual maintained hosts and all successful packet writes remain live.
    // The downstream host deliberately does not consume its receive ring.
    let bytes = vec![0x9d; 8192];
    let mut written = 0;
    for _ in 0..600 {
        if written < 393216 {
            written += lab.hosts[0].0.write(&bytes)?;
        }
        lab.step().await?;
        lab.a.actor.measured_service()?;
        lab.b.actor.measured_service()?;
    }
    let relay = lab.a.actor.table.relay_status(1).ok_or("relay")?;
    assert_eq!(
        relay.native.receive_bytes,
        lab.a.actor.config.native.receive_bytes
    );
    assert!(
        relay.produced.bytes == relay.peer_granted.bytes
            || relay.produced.records == relay.peer_granted.records
    );
    assert!(lab.hosts[1].0.status().receive_bytes > 0);
    for side in [&lab.a, &lab.b] {
        let state = side.actor.measured.as_ref().ok_or("Controller")?;
        assert!(!state.receiver_pressure);
        assert!(!state.wire_pressure);
    }
    // A's receive ring is source demand for A->B, while B's send ring is
    // blocked by the actual B application peer's advertised zero receive window.
    assert!(
        !lab.a
            .actor
            .measured
            .as_ref()
            .ok_or("Controller")?
            .snapshot(&lab.a.actor.table, lab.a.actor.micros()?)?
            .pressure
            .receiver_pressure
    );
    let downstream = lab
        .b
        .actor
        .table
        .relay_status(1)
        .ok_or("downstream relay")?;
    assert_eq!(downstream.native.peer_receive_window_bytes, Some(0));
    assert!(downstream.native.send_bytes > 0);
    let downstream = lab
        .b
        .actor
        .measured
        .as_ref()
        .ok_or("Controller")?
        .snapshot(&lab.b.actor.table, lab.b.actor.micros()?)?;
    assert!(downstream.pressure.receiver_pressure);
    assert!(downstream.observations.grant_exhausted);

    let mut received = Vec::new();
    for _ in 0..600 {
        let mut buffer = [0; 4096];
        while let l2tunnel_raw_tcp::ReadOutcome::Data(count) = lab.hosts[1].0.read(&mut buffer)? {
            received.extend_from_slice(&buffer[..count]);
        }
        lab.step().await?;
        lab.a.actor.measured_service()?;
        lab.b.actor.measured_service()?;
    }
    assert_eq!(received, vec![0x9d; written]);
    assert_eq!(
        lab.a
            .actor
            .table
            .relay_status(1)
            .ok_or("relay")?
            .native
            .receive_bytes,
        0
    );
    lab.a.actor.measured_service()?;
    assert!(
        !lab.a
            .actor
            .measured
            .as_ref()
            .ok_or("Controller")?
            .snapshot(&lab.a.actor.table, lab.a.actor.micros()?)?
            .pressure
            .receiver_pressure
    );
    let downstream = lab
        .b
        .actor
        .table
        .relay_status(1)
        .ok_or("downstream relay")?;
    assert_eq!(downstream.native.send_bytes, 0);
    assert!(
        downstream
            .native
            .peer_receive_window_bytes
            .is_some_and(|w| w > 0)
    );
    assert!(
        !lab.b
            .actor
            .measured
            .as_ref()
            .ok_or("Controller")?
            .snapshot(&lab.b.actor.table, lab.b.actor.micros()?)?
            .pressure
            .receiver_pressure
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn measured_continuous_native_readers_keep_source_grant_stall_as_growth_demand() -> Result {
    // Real native receivers have ample externally owned capacity and consume
    // every byte. Source demand may still exhaust a deliberately finite relay
    // grant; that fact must not masquerade as downstream receiver pressure.
    let mut lab = Lab::active_with_receive_bytes(
        Some(1_048_576),
        Some(Window {
            bytes: 2048,
            records: 1,
        }),
    )
    .await?;
    let maximum = 524288;
    let (mut written, mut received) = ([0usize; 2], [Vec::new(), Vec::new()]);
    let mut source_stalls = [false; 2];
    let mut grew = [false; 2];
    for _ in 0..4000 {
        for (index, host) in lab.hosts.iter_mut().enumerate() {
            if written[index] < maximum {
                written[index] += host
                    .0
                    .write(&vec![index as u8 + 1; (maximum - written[index]).min(8192)])?;
            }
            let mut buffer = [0; 8192];
            while let l2tunnel_raw_tcp::ReadOutcome::Data(count) = host.0.read(&mut buffer)? {
                received[index].extend_from_slice(&buffer[..count]);
            }
        }
        lab.step().await?;
        for (index, side) in [&mut lab.a, &mut lab.b].into_iter().enumerate() {
            side.actor.measured_service()?;
            let relay = side.actor.table.relay_status(1).ok_or("actual relay")?;
            let stall = relay.native.receive_bytes != 0
                && (relay.produced.bytes == relay.peer_granted.bytes
                    || relay.produced.records == relay.peer_granted.records);
            let state = side.actor.measured.as_ref().ok_or("Controller")?;
            let snapshot = state.snapshot(&side.actor.table, side.actor.micros()?)?;
            assert!(
                relay
                    .native
                    .peer_receive_window_bytes
                    .is_some_and(|w| w > 0)
            );
            if stall {
                source_stalls[index] = true;
                assert!(
                    !snapshot.pressure.receiver_pressure,
                    "ordinary source grant exhaustion must remain sender demand"
                );
            }
            grew[index] |= snapshot.applied.is_some_and(|a| {
                a.candidate.bytes > state.config.measured.allocation.target.initial.bytes
            });
        }
        if written == [maximum; 2] && received.iter().all(|v| v.len() == maximum) {
            break;
        }
    }
    assert_eq!(written, [maximum; 2]);
    assert_eq!(received[0], vec![2; maximum]);
    assert_eq!(received[1], vec![1; maximum]);
    assert_eq!(source_stalls, [true; 2]);
    assert_eq!(grew, [true; 2]);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn measured_idle_native_zero_window_without_pending_send_is_not_receiver_pressure() -> Result
{
    let mut lab = Lab::active().await?;
    let capacity = lab.b.actor.config.native.receive_bytes;
    let mut written = 0;
    for _ in 0..1000 {
        if written < capacity {
            written += lab.hosts[0].0.write(&vec![0x71; capacity - written])?;
        }
        lab.step().await?;
        let downstream = lab
            .b
            .actor
            .table
            .relay_status(1)
            .ok_or("downstream relay")?;
        if written == capacity
            && lab.hosts[1].0.status().receive_bytes == capacity
            && downstream.native.send_bytes == 0
            && downstream.native.peer_receive_window_bytes == Some(0)
        {
            break;
        }
    }
    assert_eq!(written, capacity);
    let downstream = lab
        .b
        .actor
        .table
        .relay_status(1)
        .ok_or("downstream relay")?;
    assert_eq!(downstream.native.peer_receive_window_bytes, Some(0));
    assert_eq!(downstream.native.send_bytes, 0);
    lab.b.actor.measured_service()?;
    assert!(
        !lab.b
            .actor
            .measured
            .as_ref()
            .ok_or("Controller")?
            .snapshot(&lab.b.actor.table, lab.b.actor.micros()?)?
            .pressure
            .receiver_pressure
    );
    Ok(())
}
