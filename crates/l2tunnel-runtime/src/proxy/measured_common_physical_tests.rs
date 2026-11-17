//! Real Bridge/writer/ledger/Controller custody; physical I/O facts are injected.
//! This does not claim Noise/UDP/native-window integration or peer delivery.
use super::*;
use crate::proxy::common_bridge::{self, Bridge, RecordPort};
use crate::proxy::transport::PhysicalWrite;
use l2tunnel_codec::aligned_receiver::{ChannelId, RecordId, RecordIdentity};
use l2tunnel_tcp_proxy::measurement::{Micros, OutputId};
use std::future::Future;
use tokio::io::AsyncWriteExt;

fn once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}
fn micros(origin: Instant) -> Result<Micros> {
    Ok(Micros(u64::try_from(
        Instant::now().duration_since(origin).as_micros(),
    )?))
}
async fn received(port: &mut RecordPort) -> Result<Vec<u8>> {
    let mut bytes = vec![0; 4097];
    for _ in 0..64 {
        if let Some(length) = port.receive(&mut bytes)? {
            bytes.truncate(length);
            return Ok(bytes);
        }
        tokio::task::yield_now().await;
    }
    Err("bounded actual Common port receive".into())
}
async fn completed(port: &mut RecordPort, bridge: &Bridge, record: u64) -> Result<PhysicalWrite> {
    let bytes = received(port).await?;
    assert!(bytes.len() >= 5);
    let identity = RecordIdentity {
        channel: ChannelId(0),
        record: RecordId(record),
    };
    bridge.admitted(identity)?;
    let accepted_at = Instant::now();
    tokio::time::advance(Duration::from_millis(1)).await;
    let observed_at = Instant::now();
    bridge.complete(identity, accepted_at, observed_at)?;
    Ok(PhysicalWrite {
        ordinal: None,
        generation: record + 1,
        identity,
        accepted_at,
        observed_at,
    })
}
async fn users(progress: &watch::Receiver<Progress>, expected: u64) -> Result<Progress> {
    for _ in 0..64 {
        let value = *progress.borrow();
        if value.users == expected {
            return Ok(value);
        }
        tokio::task::yield_now().await;
    }
    Err("bounded actual writer ordinal".into())
}
fn admit(
    state: &mut profile::State,
    table: &session::Table,
    arbiter: &mut Arbiter,
    binding: Binding,
    at: Micros,
    probe: bool,
) -> Result<(profile::Id, OutputId, Vec<u8>)> {
    if probe {
        state.controller.stage_probe(table, 1, at)?;
    } else {
        state.controller.stage_demand(table, 1, at)?;
    }
    let pending = state
        .controller
        .pending(table, at)?
        .ok_or("maintained pending measurement")?;
    let channel = arbiter.channel(binding.key, Duration::from_micros(at.0))?;
    let ready = state
        .ledger
        .prepare_admission(&pending, channel, at)?
        .ok_or("actual ledger admission")?;
    let id = ready.id();
    let token = ready.token();
    let mut bytes = vec![0; profile::envelope::HEADER_BYTES + pending.bytes.len()];
    profile::envelope::encode_fixed(
        &state.config.fixed,
        profile::envelope::StructuralEnvelope {
            kind: profile::envelope::Kind::Measurement,
            channel,
            flow: pending.flow,
            body: pending.bytes,
        },
        &mut bytes,
    )?;
    arbiter
        .push(
            binding.key,
            binding.weight,
            bytes,
            Owner::Measurement(id),
            Duration::from_micros(at.0),
        )
        .map_err(|e| e.error)?;
    state.controller.confirm_admission(token.clone(), at)?;
    state.ledger.admit(ready)?;
    let selected = arbiter
        .pop(|_, _| true)?
        .ok_or("actual MUX measurement selection")?;
    let view = wire::decode_profile(&selected.bytes, &state.config.fixed, true)?;
    state
        .ledger
        .check_selected(id, view.flow, view.channel, view.body)?;
    Ok((id, token, selected.bytes))
}
async fn handoff(
    state: &mut profile::State,
    tx: &mpsc::Sender<Vec<u8>>,
    id: Option<profile::Id>,
    bytes: Vec<u8>,
    at: Micros,
) -> Result<u64> {
    let permit = tx.clone().reserve_owned().await?;
    let send = state
        .ledger
        .prepare_send(id, at)?
        .ok_or("actual bounded all-user flight")?;
    permit.send(bytes);
    Ok(state.ledger.sent(send)?)
}
struct WriterHarness {
    port: RecordPort,
    bridge: Bridge,
    tx: mpsc::Sender<Vec<u8>>,
    progress: watch::Receiver<Progress>,
    task: tokio::task::JoinHandle<io::Result<()>>,
    controls: mpsc::Sender<Output>,
    events: mpsc::Receiver<transport::Event>,
}
async fn start(start: Start) -> Result<WriterHarness> {
    let (mut port, stream, bridge) = common_bridge::pair_retained(4096, Duration::from_secs(1))?;
    bridge.enable_physical_receipts()?;
    let (controls, control_rx) = mpsc::channel(8);
    let (tx, rx) = mpsc::channel(1);
    let (progress, mut observed) = watch::channel(Progress::default());
    let (events, event_rx) = mpsc::channel(8);
    controls.try_send(Output::Control(Frame::Start(start)))?;
    controls.try_send(Output::Control(Frame::Ready(start)))?;
    let task = tokio::spawn(transport::writer_selected(
        stream,
        Direction {
            index: 0,
            lane: 0,
            bulk: true,
        },
        256,
        control_rx,
        rx,
        progress,
        events,
        Some(bridge.clone()),
    ));
    completed(&mut port, &bridge, 0).await?;
    observed.changed().await?;
    tokio::time::advance(Duration::from_millis(4)).await;
    completed(&mut port, &bridge, 1).await?;
    for _ in 0..64 {
        if observed.borrow().ready {
            return Ok(WriterHarness {
                port,
                bridge,
                tx,
                progress: observed,
                task,
                controls,
                events: event_rx,
            });
        }
        tokio::task::yield_now().await;
    }
    task.abort();
    let _ = task.await;
    Err("bounded actual Ready flush".into())
}

#[tokio::test(start_paused = true)]
async fn measured_common_coalesced_all_user_receipts_keep_exact_token_times_and_callback_custody()
-> Result {
    let mut lab = Lab::active().await?;
    let origin = lab.a.actor.start;
    let mut config = lab
        .a
        .actor
        .measured
        .as_ref()
        .ok_or("actual measured fixture")?
        .config
        .clone();
    config.service.callback_work_per_turn = 1;
    let unselected_bound = config.validate()?.common_physical_metadata_bytes;
    assert_eq!(unselected_bound, transport::physical_metadata_bytes()?);
    let mut state = profile::State::new_at(config.clone(), &lab.a.actor.table, micros(origin)?)?;
    state.enable_physical_receipts()?;
    assert_eq!(
        state.config.validate()?.common_physical_metadata_bytes,
        unselected_bound,
        "inline None and selected receipt layouts are both charged"
    );
    let binding = *lab
        .a
        .actor
        .bindings
        .get(&1)
        .ok_or("actual lifetime binding")?;
    let mut arbiter = Arbiter::new(&config.fixed, false)?;
    let actual_start = Start {
        digest: profile::session_config(&config)?.digest.0,
        ..lab.a.actor.writers[0].start
    };
    let WriterHarness {
        mut port,
        bridge,
        tx,
        progress,
        task,
        controls: _controls,
        events: _events,
    } = start(actual_start).await?;
    let at = micros(origin)?;
    let (first, first_token, first_bytes) = admit(
        &mut state,
        &lab.a.actor.table,
        &mut arbiter,
        binding,
        at,
        false,
    )?;
    let (second, second_token, second_bytes) = admit(
        &mut state,
        &lab.a.actor.table,
        &mut arbiter,
        binding,
        at,
        true,
    )?;
    assert_eq!(
        handoff(&mut state, &tx, Some(first), first_bytes, at).await?,
        1
    );
    assert_eq!(
        handoff(&mut state, &tx, Some(second), second_bytes, at).await?,
        2
    );
    assert!(state.ledger.prepare_send(None, at)?.is_none());
    let one = completed(&mut port, &bridge, 2).await?;
    let two = completed(&mut port, &bridge, 3).await?;
    let coalesced = users(&progress, 2).await?;
    let mut blocked = Box::pin(bridge.prepare_user_receipt(3));
    assert!(once(blocked.as_mut()).is_pending());
    drop(blocked);
    assert_eq!(state.ledger.counts(), (0, 2));
    let mut wrong = coalesced.physical;
    wrong[1].as_mut().ok_or("second actual fact")?.ordinal = Some(1);
    assert!(
        state
            .observe_physical(2, wrong, origin, Instant::now())
            .is_err()
    );
    assert!(
        state.ledger.retained_physical(first)?.is_none(),
        "all facts preflight atomically"
    );
    state.observe_physical(2, coalesced.physical, origin, Instant::now())?;
    state.callbacks_physical(&lab.a.actor.table, 2, origin, Instant::now())?;
    bridge.acknowledge_user_receipts(2)?;
    assert_eq!(state.ledger.counts(), (0, 1));
    assert_eq!(
        state
            .ledger
            .retained_physical(second)?
            .ok_or("held second receipt")?
            .accepted_at,
        two.accepted_at
    );
    let view = state.snapshot(&lab.a.actor.table, micros(origin)?)?;
    let first_view = view
        .physical_callbacks
        .iter()
        .flatten()
        .find(|c| c.ordinal == 1)
        .ok_or("first exact callback")?;
    assert_eq!(first_view.token, first_token);
    assert_eq!(first_view.admitted_at, at);
    assert_eq!(
        (first_view.accepted_at, first_view.physical_observed_at),
        (one.accepted_at, one.observed_at)
    );

    // An actual native TCP packet is ordinary nonmeasurement Data, between the
    // retained second token and a newly admitted third measurement token.
    lab.hosts[0].0.write(b"ordinal provenance")?;
    lab.hosts[0].0.poll(lab.a.actor.millis()?, 8)?;
    let packet = lab.hosts[0]
        .0
        .pop_packet()
        .ok_or("actual native TCP packet")?;
    let channel = arbiter.channel(binding.key, Instant::now().duration_since(origin))?;
    let mut transparent = vec![0; profile::envelope::HEADER_BYTES + packet.len()];
    profile::envelope::encode_fixed(
        &config.fixed,
        profile::envelope::StructuralEnvelope {
            kind: profile::envelope::Kind::Transparent,
            channel,
            flow: 0,
            body: &packet,
        },
        &mut transparent,
    )?;
    arbiter
        .push(
            binding.key,
            binding.weight,
            transparent,
            Owner::Transparent(packet.len()),
            Instant::now().duration_since(origin),
        )
        .map_err(|e| e.error)?;
    let transparent = arbiter
        .pop(|_, _| true)?
        .ok_or("actual transparent MUX selection")?
        .bytes;
    let at = micros(origin)?;
    let (third, third_token, third_bytes) = admit(
        &mut state,
        &lab.a.actor.table,
        &mut arbiter,
        binding,
        at,
        false,
    )?;
    assert_eq!(handoff(&mut state, &tx, None, transparent, at).await?, 3);
    assert_eq!(
        handoff(&mut state, &tx, Some(third), third_bytes, at).await?,
        4
    );
    completed(&mut port, &bridge, 4).await?;
    let four = completed(&mut port, &bridge, 5).await?;
    let coalesced = users(&progress, 4).await?;
    state.observe_physical(4, coalesced.physical, origin, Instant::now())?;
    state.callbacks_physical(&lab.a.actor.table, 4, origin, Instant::now())?;
    bridge.acknowledge_user_receipts(4)?;
    let snapshot = state.snapshot(&lab.a.actor.table, micros(origin)?)?;
    let second_view = snapshot
        .physical_callbacks
        .iter()
        .flatten()
        .find(|c| c.ordinal == 2)
        .ok_or("retained second token callback")?;
    assert_eq!(second_view.token, second_token);
    assert_eq!(second_view.accepted_at, two.accepted_at);
    assert_eq!(state.ledger.counts(), (0, 1));
    state.observe_physical(4, coalesced.physical, origin, Instant::now())?;
    state.callbacks_physical(&lab.a.actor.table, 4, origin, Instant::now())?;
    assert_eq!(state.ledger.counts(), (0, 0));
    let snapshot = state.snapshot(&lab.a.actor.table, micros(origin)?)?;
    let third_view = snapshot
        .physical_callbacks
        .iter()
        .flatten()
        .find(|c| c.ordinal == 4)
        .ok_or("third exact callback")?;
    assert_eq!(third_view.token, third_token);
    assert_eq!(third_view.accepted_at, four.accepted_at);
    assert!(third_view.callback_observed_at >= third_view.physical_observed_at);
    let callbacks = snapshot.physical_callbacks;
    state.observe_physical(4, coalesced.physical, origin, Instant::now())?;
    state.callbacks_physical(&lab.a.actor.table, 4, origin, Instant::now())?;
    assert_eq!(
        state
            .snapshot(&lab.a.actor.table, micros(origin)?)?
            .physical_callbacks,
        callbacks
    );
    task.abort();
    let _ = task.await;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn measured_common_ready_turn_yields_to_sibling_before_another_ready_tick() -> Result {
    let mut side = side(true)?;
    let (_port, _stream, bridge) = common_bridge::pair_retained(4096, Duration::from_secs(1))?;
    bridge.enable_physical_receipts()?;
    side.actor
        .measured
        .as_mut()
        .ok_or("actual measured owner")?
        .enable_physical_receipts()?;
    side.actor.retirement = Some(bridge);
    let now = Instant::now();
    let mut tick =
        tokio::time::interval_at(now - Duration::from_millis(4), Duration::from_millis(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let turns = std::cell::Cell::new(0);
    let worker = async {
        for _ in 0..2 {
            side.actor.wait_service(&mut tick, None).await;
            side.actor.measured_callbacks()?;
            turns.set(turns.get() + 1);
            side.actor.cooperate_after_turn().await;
        }
        Ok::<_, io::Error>(())
    };
    let sibling = async {
        // Both overdue ticks are ready without advancing the paused clock.
        // The production end-turn boundary must release the parent poll once.
        assert_eq!(turns.get(), 1);
    };
    let (result, ()) = tokio::join!(biased; worker, sibling);
    result?;
    assert_eq!(turns.get(), 2);
    assert_eq!(Instant::now(), now);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn measured_common_whole_write_wakes_callback_before_original_handoff_cap() -> Result {
    let mut lab = Lab::active().await?;
    let origin = lab.a.actor.start;
    let config = lab
        .a
        .actor
        .measured
        .as_ref()
        .ok_or("actual measured fixture")?
        .config
        .clone();
    let mut state = profile::State::new_at(config.clone(), &lab.a.actor.table, micros(origin)?)?;
    state.enable_physical_receipts()?;
    let binding = *lab
        .a
        .actor
        .bindings
        .get(&1)
        .ok_or("actual lifetime binding")?;
    let mut arbiter = Arbiter::new(&config.fixed, false)?;
    let WriterHarness {
        mut port,
        bridge,
        tx,
        mut progress,
        task,
        controls: _controls,
        events: _events,
    } = start(Start {
        digest: profile::session_config(&config)?.digest.0,
        ..lab.a.actor.writers[0].start
    })
    .await?;
    progress.borrow_and_update();
    let at = micros(origin)?;
    let (id, token, bytes) = admit(
        &mut state,
        &lab.a.actor.table,
        &mut arbiter,
        binding,
        at,
        true,
    )?;
    assert_eq!(handoff(&mut state, &tx, Some(id), bytes, at).await?, 1);
    assert!(received(&mut port).await?.len() >= 5);
    let identity = RecordIdentity {
        channel: ChannelId(0),
        record: RecordId(2),
    };
    bridge.admitted(identity)?;
    lab.a.actor.measured = Some(state);
    lab.a.actor.retirement = Some(bridge.clone());
    lab.a.actor.writers[0].progress = progress;
    let original =
        origin + Duration::from_micros(at.0 + config.measured.ownership.handoff_timeout_micros);
    tokio::time::advance(original - Duration::from_millis(3) - Instant::now()).await;
    let accepted = Instant::now();
    tokio::time::advance(Duration::from_millis(1)).await;
    let observed = Instant::now();
    bridge.complete(identity, accepted, observed)?;
    // No periodic turn is due before expiry. Only the actual writer's watch
    // publication can release this wait early enough for a fresh callback.
    let mut tick =
        tokio::time::interval_at(original + Duration::from_millis(1), Duration::from_secs(1));
    lab.a.actor.wait_service(&mut tick, Some(original)).await;
    assert!(Instant::now() < original);
    lab.a.actor.measured_callbacks()?;
    let state = lab
        .a
        .actor
        .measured
        .as_ref()
        .ok_or("actual measured owner")?;
    assert_eq!(state.ledger.counts(), (0, 0));
    let snapshot = state.snapshot(&lab.a.actor.table, micros(origin)?)?;
    let callback = snapshot.physical_callbacks[0]
        .as_ref()
        .ok_or("exact callback")?;
    assert_eq!(callback.token, token);
    assert_eq!(callback.ordinal, 1);
    assert_eq!(callback.common_record, identity);
    assert_eq!(callback.accepted_at, accepted);
    assert_eq!(callback.physical_observed_at, observed);
    assert!(callback.callback_observed_at >= observed);
    assert!(callback.callback_observed_at < original);
    task.abort();
    let _ = task.await;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn measured_common_exact_physical_fact_survives_original_callback_and_bridge_expiry() -> Result
{
    let mut lab = Lab::active().await?;
    let origin = lab.a.actor.start;
    let config = lab
        .a
        .actor
        .measured
        .as_ref()
        .ok_or("actual measured fixture")?
        .config
        .clone();
    let mut state = profile::State::new_at(config.clone(), &lab.a.actor.table, micros(origin)?)?;
    state.enable_physical_receipts()?;
    let binding = *lab
        .a
        .actor
        .bindings
        .get(&1)
        .ok_or("actual lifetime binding")?;
    let mut arbiter = Arbiter::new(&config.fixed, false)?;
    let actual_start = Start {
        digest: profile::session_config(&config)?.digest.0,
        ..lab.a.actor.writers[0].start
    };
    let WriterHarness {
        mut port,
        bridge,
        tx,
        progress,
        task,
        controls: _controls,
        events: _events,
    } = start(actual_start).await?;
    let at = micros(origin)?;
    let (id, _token, bytes) = admit(
        &mut state,
        &lab.a.actor.table,
        &mut arbiter,
        binding,
        at,
        true,
    )?;
    handoff(&mut state, &tx, Some(id), bytes, at).await?;
    let actual = completed(&mut port, &bridge, 2).await?;
    assert_eq!(
        progress.borrow().users,
        0,
        "whole write precedes writer watch publication"
    );
    task.abort(); // Do not await a join before importing the terminal fact.
    let original =
        origin + Duration::from_micros(at.0 + config.measured.ownership.handoff_timeout_micros);
    tokio::time::advance(original - Instant::now()).await;
    // Use the actual actor import seam that runs before its deadline/Abort
    // branches, rather than manually importing directly into a separate ledger.
    lab.a.actor.measured = Some(state);
    lab.a.actor.retirement = Some(bridge.clone());
    lab.a.actor.writers[0].progress = progress;
    lab.a.actor.deadline = Some(original);
    let original_error = lab
        .a
        .actor
        .measured_deadlines(Instant::now())
        .err()
        .ok_or("original actor deadline")?;
    assert_eq!(original_error.kind(), io::ErrorKind::TimedOut);
    // At the already expired original cap, terminal import must not depend on
    // either a successful writer flush or awaiting the cancelled writer join.
    assert_eq!(lab.a.actor.writers[0].progress.borrow().users, 0);
    lab.a.actor.observe_measured_physical(true)?;
    assert_eq!(
        lab.a
            .actor
            .measured_deadlines(Instant::now())
            .err()
            .ok_or("unchanged actor error")?
            .to_string(),
        original_error.to_string()
    );
    let state = lab
        .a
        .actor
        .measured
        .as_mut()
        .ok_or("retained actual measured owner")?;
    assert!(
        state
            .callbacks_physical(&lab.a.actor.table, 1, origin, Instant::now())
            .is_err()
    );
    assert_eq!(state.ledger.counts(), (0, 1));
    let retained = state
        .ledger
        .retained_physical(id)?
        .ok_or("late callback retained exact fact")?;
    assert_eq!(
        (retained.accepted_at, retained.observed_at),
        (actual.accepted_at, actual.observed_at)
    );
    assert!(
        state.ledger.next_completed().is_none(),
        "expiry cannot release the original flight"
    );
    assert!(
        state
            .snapshot(&lab.a.actor.table, micros(origin)?)?
            .physical_callbacks
            .iter()
            .all(Option::is_none)
    );
    let _ = task.await;

    let (mut port, mut stream, bridge) =
        common_bridge::pair_retained(128, Duration::from_millis(10))?;
    bridge.enable_physical_receipts()?;
    bridge.prepare_user_receipt(1).await?;
    let first = Instant::now();
    stream.write_all(&[0, 0, 0, 1, 7]).await?;
    let mut flushing = Box::pin(stream.flush());
    let mut actual = false;
    let mut bytes = [0; 129];
    for _ in 0..64 {
        assert!(once(flushing.as_mut()).is_pending());
        if port.receive(&mut bytes)?.is_some() {
            actual = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(actual, "actual complete frame reached the original port");
    bridge.admitted(RecordIdentity {
        channel: ChannelId(0),
        record: RecordId(7),
    })?;
    tokio::time::advance(Duration::from_millis(10)).await;
    let observed = Instant::now();
    // The Stream observes its original expiry BEFORE the physical callback.
    // That first terminal error must survive the later real whole-write fact.
    let original_error = match once(flushing.as_mut()) {
        Poll::Ready(Err(error)) => error,
        _ => return Err("original Bridge expiry did not terminate flush".into()),
    };
    drop(flushing);
    assert_eq!(original_error.kind(), io::ErrorKind::TimedOut);
    let identity = RecordIdentity {
        channel: ChannelId(0),
        record: RecordId(7),
    };
    let completion_error = bridge
        .complete(identity, first + Duration::from_millis(1), observed)
        .err()
        .ok_or("late bridge cap")?;
    assert_eq!(completion_error.to_string(), original_error.to_string());
    let retained = bridge
        .pending_physical_receipt()?
        .ok_or("late bridge physical fact retained")?;
    assert_eq!(retained.ordinal, Some(1));
    assert_eq!(retained.accepted_at, first + Duration::from_millis(1));
    assert_eq!(retained.observed_at, observed);
    let (physical_count, physical) = bridge.retained_user_receipts()?;
    assert_eq!(physical_count, 1);
    assert_eq!(physical[0], Some(retained));
    assert!(
        bridge.take_physical_receipt().is_err(),
        "terminal fact cannot release failed flush"
    );
    assert!(
        bridge
            .complete(identity, first + Duration::from_millis(2), observed)
            .is_err()
    );
    assert_eq!(
        bridge.retained_user_receipts()?,
        (physical_count, physical),
        "physical provenance is immutable after error"
    );
    Ok(())
}
