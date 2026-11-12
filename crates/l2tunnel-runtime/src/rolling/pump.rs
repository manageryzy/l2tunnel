use super::*;
use l2tunnel_flow_control::target::Micros;

pub(super) async fn run_parts<D, C, S, R>(
    mut device: D,
    parts: Vec<DatagramParts<C, S, R>>,
    initiator: bool,
    runtime: RuntimeConfig,
    mut policy: DatagramPolicy,
    config: Config,
) -> io::Result<()>
where
    D: PacketDevice<Error = io::Error>,
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: DatagramSend,
    R: DatagramReceive,
{
    config.validate(runtime, policy)?;
    if device.layer() != runtime.layer
        || parts.len() != if policy.duplex == Duplex::Full { 1 } else { 2 }
    {
        return Err(invalid("rolling authenticated device/lane mismatch"));
    }
    policy.control_magic = *b"L2RC";
    let mut pipeline = Pipeline::new(config.pipeline).map_err(io::Error::other)?;
    let started = Instant::now();
    let budget =
        udp::SharedBudget::from_policy_feedback(policy, started, scheduler::FEEDBACK_BYTES)?;
    let (control_tx, mut control_rx) = mpsc::channel(8);
    let (data_tx, mut data_rx) = mpsc::channel(config.scheduler.recovery.window * parts.len());
    let (sent_tx, mut sent_rx) = mpsc::channel(parts.len());
    let mut states = Vec::new();
    let mut setup = Vec::new();
    // Construct all fallible protocol owners before spawning any carrier task.
    for (index, part) in parts.into_iter().enumerate() {
        let sends = policy.duplex == Duplex::Full || (index == 0) == initiator;
        let (feedback, changes) = watch::channel(udp::Feedback::default());
        let (output, rx) = if sends {
            let (tx, rx) = mpsc::channel(1);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        states.push(State::new(
            LaneContext {
                session: part.session,
                index,
                initiator,
            },
            runtime,
            policy,
            config,
            feedback,
            output,
        )?);
        setup.push((part, changes, rx));
    }
    let mut tasks = JoinSet::new();
    for (index, (part, changes, output)) in setup.into_iter().enumerate() {
        let (reader, writer) = tokio::io::split(part.control);
        tasks.spawn(crate::control::read_control_bound_timed(
            reader,
            index,
            control_tx.clone(),
            policy.control_timeout,
            scheduler::FEEDBACK_BYTES,
            policy.control_magic,
        ));
        tasks.spawn(udp::write_control_bound(
            writer,
            changes,
            policy,
            budget.clone(),
        ));
        if states[index].receiver.is_some() {
            tasks.spawn(udp::read_datagrams(
                part.receiver,
                policy.payload_bytes,
                index,
                data_tx.clone(),
            ));
        }
        if let Some(output) = output {
            let recycled = states[index]
                .recycle_outbound
                .take()
                .ok_or_else(|| invalid("rolling outbound recycle owner"))?;
            tasks.spawn(write_datagrams(
                part.sender,
                output,
                index,
                sent_tx.clone(),
                recycled,
            ));
        }
    }
    drop(sent_tx);
    drop(control_tx);
    drop(data_tx);
    let mut ticker = interval(runtime.poll_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut packet = vec![0; l2tunnel_device::READ_BUFFER_BYTES];
    let mut encoded = vec![0; policy.payload_bytes];
    let mut ingress = None;
    let mut selected = None;
    let mut idle_cursor = None;
    let result = async {
        loop {
            tokio::select! {
                Some(result) = tasks.join_next() => return match result {
                    Ok(Err(error)) => Err(error), Err(error) => Err(io::Error::other(error)),
                    Ok(Ok(())) => Err(invalid("rolling carrier task ended")),
                },
                Some((lane,event,received_at)) = control_rx.recv() => states[lane].control(event,ticks(started.elapsed())?,micros(started,received_at)?,micros(started,Instant::now())?)?,
                Some((lane,ordinal,sent_at))=sent_rx.recv()=>states[lane].first_flight(ordinal,micros(started,sent_at)?,micros(started,Instant::now())?)?,
                Some((lane,bytes)) = data_rx.recv() => states[lane].data(&bytes,ticks(started.elapsed())?,config)?,
                _ = ticker.tick() => (),
            }
            retire_registration(&mut pipeline, selected.as_ref(), &mut idle_cursor, started.elapsed())?;
            ingress_step(&mut device, &mut pipeline, &mut ingress, &mut packet, runtime, config, started.elapsed())?;
            for _ in 0..config.passes_per_turn {
                for state in &mut states {
                    state.service_at(ticks(started.elapsed())?, config,micros(started,Instant::now())?)?;
                    state.deliver(&mut device, &mut pipeline, || ticks(started.elapsed()))?;
                    state.reassemble(runtime, config, ticks(started.elapsed())?)?;
                    if state.sender.is_some() {
                        if selected.is_none() { selected = pipeline.dequeue().map_err(io::Error::other)?; }
                        if let Some(item) = &selected && state.admit(item,micros(started,Instant::now())?)? { selected = None; }
                        state.submit(ticks(started.elapsed())?)?;
                    }
                    state.reclaim_outbound()?;
                    let mut queued=None;
                    if let Some(outbound) = &state.outbound {
                        match outbound.try_reserve() {
                            Ok(permit) => {
                                if let Some(mut buffer) = state.free_outbound.pop() {
                                let now = started.elapsed();
                                let mut emitted=None;
                                let sender = state.sender.as_mut().ok_or_else(|| invalid("rolling missing sender"))?;
                                if let Some(length) = budget.poll_with(false, now, &mut buffer, |output, allowance| {
                                    let Some(value) = sender.pending_output() else { return Ok(None); };
                                    let length = config.scheduler.recovery.width().map_err(io::Error::other)? + protocol::wire::HEADER_BYTES;
                                    if allowance.packets == 0 || allowance.wire_bytes < length { return Ok(None); }
                                    let id = value.id();
                                    if sender.encode_pending(output).map_err(io::Error::other)? != length {
                                        return Err(invalid("rolling encoded length differs from charged fixed width"));
                                    }
                                    sender.confirm_output(id, ticks(now)?).map_err(io::Error::other)?;
                                    emitted=Some(id);
                                    allowance.packets -= 1; allowance.wire_bytes -= length;
                                    Ok(Some(length))
                                })? {
                                    let id=emitted.ok_or_else(||invalid("rolling output identity missing"))?;
                                    let native_complete=state.completion(id);
                                    if buffer.len() != length { return Err(invalid("rolling outbound slot length mismatch")); }
                                    permit.send(owner::Outbound{bytes:buffer,native_complete});
                                    queued=Some(id);
                                } else {
                                    state.free_outbound.push(buffer);
                                }
                                }
                            }
                            Err(mpsc::error::TrySendError::Full(_)) => (),
                            Err(mpsc::error::TrySendError::Closed(_)) => return Err(invalid("rolling data writer closed")),
                        }
                    }
                    if let Some(id)=queued { state.queued(id); }
                    if let Some(receiver) = &mut state.receiver {
                        let now = started.elapsed();
                        if let Some(length) = budget.poll_with(true, now, &mut encoded, |output, allowance| {
                            let Some(value) = receiver.pending_feedback() else { return Ok(None); };
                            if allowance.packets == 0 || allowance.wire_bytes < scheduler::FEEDBACK_BYTES { return Ok(None); }
                            let bytes = receiver.pending_feedback_wire().ok_or_else(|| invalid("rolling feedback bytes absent"))?;
                            output[..scheduler::FEEDBACK_BYTES].copy_from_slice(bytes);
                            receiver.confirm_feedback(value.id, ticks(now)?).map_err(io::Error::other)?;
                            allowance.packets -= 1; allowance.wire_bytes -= scheduler::FEEDBACK_BYTES;
                            Ok(Some(scheduler::FEEDBACK_BYTES))
                        })? { state.feedback.send_modify(|feedback| feedback.ack = Some(encoded[..length].to_vec())); }
                    }
                }
            }
        }
    }.await;
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    result
}
fn micros(origin: Instant, event: Instant) -> io::Result<Micros> {
    let elapsed = event
        .checked_duration_since(origin)
        .ok_or_else(|| invalid("rolling delivery clock regression"))?;
    Ok(Micros(
        u64::try_from(elapsed.as_micros()).map_err(io::Error::other)?,
    ))
}
async fn write_datagrams(
    mut sender: impl DatagramSend,
    mut output: mpsc::Receiver<owner::Outbound>,
    lane: usize,
    sent: mpsc::Sender<(usize, u64, Instant)>,
    recycled: mpsc::Sender<Vec<u8>>,
) -> io::Result<()> {
    while let Some(packet) = output.recv().await {
        // Reserve the non-coalescing completion slot before physical handoff.
        let permit = if packet.native_complete.is_some() {
            Some(
                sent.reserve()
                    .await
                    .map_err(|_| invalid("rolling first-flight consumer closed"))?,
            )
        } else {
            None
        };
        sender.send(&packet.bytes).await?;
        let completed = Instant::now();
        if let (Some(ordinal), Some(permit)) = (packet.native_complete, permit) {
            permit.send((lane, ordinal, completed));
        }
        recycled
            .try_send(packet.bytes)
            .map_err(|_| invalid("rolling outbound recycle channel bound or closure"))?;
    }
    Err(invalid("rolling datagram producer closed"))
}

fn ingress_step<D: PacketDevice<Error = io::Error>>(
    device: &mut D,
    pipeline: &mut Pipeline,
    ingress: &mut Option<Vec<u8>>,
    packet: &mut [u8],
    runtime: RuntimeConfig,
    config: Config,
    now: Duration,
) -> io::Result<()> {
    // Pipeline registrations and learned reverse bindings share the same
    // startup-bound millisecond domain as rolling scopes and service clocks.
    let now = Duration::from_millis(ticks(now)?.0);
    if ingress.is_none()
        && pipeline.usage().packets < config.pipeline.queue.packets
        && let Some(length) = device.receive(packet)?
    {
        if length > runtime.max_packet || !packet_valid(runtime.layer, &packet[..length]) {
            return Err(invalid("device supplied invalid rolling packet"));
        }
        *ingress = Some(packet[..length].to_vec());
    }
    if let Some(bytes) = ingress.take() {
        match pipeline.enqueue(bytes, now) {
            Ok(_) => (),
            Err(error)
                if matches!(error.kind, pipeline::PipelineError::Budget(_))
                    || flow_capacity(&error.kind) =>
            {
                *ingress = Some(error.payload)
            }
            Err(error) => return Err(io::Error::other(error)),
        }
    }
    Ok(())
}

pub(super) fn flow_capacity(error: &pipeline::PipelineError) -> bool {
    matches!(
        error,
        pipeline::PipelineError::Flow(l2tunnel_packet::FlowError::Capacity)
    )
}

pub(super) fn retire_registration(
    pipeline: &mut Pipeline,
    selected: Option<&pipeline::Packet>,
    cursor: &mut Option<pipeline::FlowKey>,
    now: Duration,
) -> io::Result<()> {
    // Only the selected packet retains a local FlowId outside Pipeline. Sender
    // fragments, recovery and prepared native frames retain immutable channel
    // and bytes. Fixed CRC mapping preserves channel affinity across relearn;
    // retiring registration metadata neither releases bytes nor grants credit.
    let now = Duration::from_millis(ticks(now)?.0);
    let scan = pipeline
        .idle_step(
            now,
            *cursor,
            16,
            selected.map(|packet| packet.metadata.classification.key),
        )
        .map_err(io::Error::other)?;
    *cursor = scan.after;
    if let Some((key, _)) = scan.candidate {
        pipeline
            .retire_idle_drained(&key, now)
            .map_err(io::Error::other)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "flow_tests.rs"]
mod flow_retirement_tests;

#[cfg(test)]
#[path = "first_flight_tests.rs"]
mod first_flight_tests;
