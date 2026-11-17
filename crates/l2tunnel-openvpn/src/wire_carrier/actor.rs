//! The sole connected socket owner. Retained emissions survive WouldBlock without
//! another recovery attempt, packet number, encryption operation or wire charge.
use super::common::send::{Custody, Ledger, SendFailure, SendReceipt};
use super::{Activation, Data, Error, Submission, common, control, wire};
use crate::budget::Budget;
use l2tunnel_recovery::RecoveryError;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    net::UdpSocket,
    sync::{mpsc, oneshot},
    time::{Instant, MissedTickBehavior, interval_at},
};

pub(super) struct Inputs {
    pub socket: UdpSocket,
    pub settings: Settings,
    pub transport: control::Transport,
    pub bridge: DuplexStream,
    pub submissions: mpsc::Receiver<Submission>,
    pub priority: Option<mpsc::Receiver<Submission>>,
    pub outputs: mpsc::Sender<common::Received>,
    pub activate: mpsc::Receiver<Activation>,
    pub started: Instant,
    pub budget: Budget,
    pub physical: Option<Ledger>,
    pub final_records: Option<std::sync::Arc<std::sync::OnceLock<Instant>>>,
    #[cfg(test)]
    pub user_gate: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

#[derive(Clone, Copy)]
pub(super) struct Settings {
    pub path_mtu: usize,
    pub ip_overhead: usize,
    pub max_source_bytes: usize,
    pub max_payload_bytes: usize,
    pub crypto_bytes: usize,
    pub poll_interval: std::time::Duration,
    pub work_limit: usize,
    pub receiving: bool,
}

fn bytes(size: usize) -> Result<Vec<u8>, Error> {
    let mut value = Vec::new();
    value
        .try_reserve_exact(size)
        .map_err(|_| Error::Allocation)?;
    value.resize(size, 0);
    Ok(value)
}

// The outer channel deliberately has no tls-auth. Invalid/unbound UDP input
// cannot abort a live TLS/member owner or manufacture authenticated progress.
fn ignorable(error: control::Error) -> bool {
    matches!(
        error,
        control::Error::Wire(_)
            | control::Error::Peer
            | control::Error::State
            | control::Error::Configuration
            | control::Error::Capacity
            | control::Error::Recovery(
                RecoveryError::MalformedPacket
                    | RecoveryError::WrongContext
                    | RecoveryError::WrongProfile
                    | RecoveryError::SourceTooLarge
                    | RecoveryError::Capacity(_)
                    | RecoveryError::SequenceWindow
                    | RecoveryError::UnexpectedSequence
                    | RecoveryError::ConflictingDuplicate
                    | RecoveryError::UnsentAcknowledgement
            )
    )
}

fn poll_control(
    transport: &mut control::Transport,
    budget: &Budget,
    elapsed: std::time::Duration,
    ip_overhead: usize,
    output: &mut [u8],
) -> Result<Option<usize>, Error> {
    budget
        .transaction(|quota| {
            if !quota.permits(true, output.len() + ip_overhead) {
                return Ok(Ok(None));
            }
            let emission = transport.poll(elapsed, output);
            if let Ok(Some(length)) = emission {
                quota.charge(true, length + ip_overhead, None)?;
            }
            Ok(emission)
        })
        .map_err(Error::Admission)?
        .map_err(Error::Control)
}

/// This selected namespace is disjoint from every supported OpenVPN opcode.
/// It conveys routing only; the final Records owner still validates all authority.
pub(super) fn final_prefix(packet: &[u8]) -> bool {
    packet
        .first()
        .is_some_and(|byte| matches!(*byte, 0..=23 | 80..=121 | 128..=255))
}

#[cfg(test)]
pub(super) fn poll_data(
    data: &mut Data,
    payload: &[u8],
    control: bool,
    budget: &Budget,
    settings: Settings,
    crypto: &mut [u8],
    output: &mut [u8],
) -> Result<Option<usize>, Error> {
    poll_selected_data(
        data, payload, control, budget, settings, crypto, output, false,
    )
}

#[allow(clippy::too_many_arguments)]
fn poll_selected_data(
    data: &mut Data,
    payload: &[u8],
    control: bool,
    budget: &Budget,
    settings: Settings,
    crypto: &mut [u8],
    output: &mut [u8],
    final_record: bool,
) -> Result<Option<usize>, Error> {
    budget
        .transaction(|quota| {
            let required = if final_record {
                match payload.len().checked_add(settings.ip_overhead) {
                    Some(value) => value,
                    None => return Ok(Err(Error::Configuration)),
                }
            } else {
                settings.path_mtu
            };
            if !quota.permits(control, required) {
                return Ok(Ok(None));
            }
            let emission = (|| {
                if payload.is_empty() || payload.len() > settings.max_payload_bytes {
                    return Err(Error::Configuration);
                }
                let body = match data {
                    Data::Protected(owner) => {
                        owner.reserve_maximum_send()?;
                        let packet = owner.seal(payload, crypto)?;
                        &crypto[..packet.wire_len]
                    }
                    Data::Opaque => payload,
                };
                if final_record {
                    if !matches!(data, Data::Opaque)
                        || !final_prefix(body)
                        || body.len() > output.len()
                    {
                        return Err(Error::Configuration);
                    }
                    output[..body.len()].copy_from_slice(body);
                    Ok(body.len())
                } else {
                    wire::encode_data(0, None, body, output).map_err(Error::Wire)
                }
            })();
            if let Ok(length) = emission {
                quota.charge(control, length + settings.ip_overhead, None)?;
            }
            Ok(emission.map(Some))
        })
        .map_err(Error::Admission)?
}

pub(super) struct PendingData {
    pub length: usize,
    pub completion: oneshot::Sender<Result<(), Error>>,
    pub custody: Option<Custody>,
}

async fn priority_input(input: &mut Option<mpsc::Receiver<Submission>>) -> Option<Submission> {
    match input {
        Some(input) => input.recv().await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
pub(super) fn flush_data(
    pending: &mut Option<PendingData>,
    output: &[u8],
    send: impl FnMut(&[u8]) -> std::io::Result<usize>,
) -> Result<bool, Error> {
    flush_data_with(pending, output, 0, None, Instant::now, send)
}

pub(super) fn flush_data_with(
    pending: &mut Option<PendingData>,
    output: &[u8],
    ip_overhead: usize,
    physical: Option<&Ledger>,
    mut now: impl FnMut() -> Instant,
    mut send: impl FnMut(&[u8]) -> std::io::Result<usize>,
) -> Result<bool, Error> {
    let Some(packet) = pending.as_ref() else {
        return Ok(false);
    };
    if let Some(custody) = packet.custody.as_ref() {
        let cancelled = custody.response.is_closed();
        if cancelled || now() >= custody.deadline {
            if let Some(physical) = physical {
                physical.refused(cancelled)?;
            }
            let packet = pending.take().ok_or(Error::Closed)?;
            let custody = packet.custody.ok_or(Error::Closed)?;
            let _ = custody
                .response
                .send(Err(SendFailure::Expired { accepted: None }));
            let _ = packet.completion.send(Err(Error::Timeout));
            return Ok(true);
        }
    }
    let bytes = output.get(..packet.length).ok_or(Error::Configuration)?;
    let full_ip = packet
        .length
        .checked_add(ip_overhead)
        .ok_or(Error::Configuration)?;
    match send(bytes) {
        Ok(sent) if sent == packet.length => {
            let accepted_at = now();
            let packet = pending.take().ok_or(Error::Closed)?;
            let late = packet
                .custody
                .as_ref()
                .is_some_and(|value| accepted_at >= value.deadline);
            if let Some(physical) = physical {
                physical.written(
                    packet.custody.as_ref().map(|value| value.class),
                    full_ip,
                    late,
                )?;
            }
            if let Some(custody) = packet.custody {
                let receipt = SendReceipt {
                    record_bytes: custody.record_bytes,
                    udp_bytes: sent,
                    ip_bytes: full_ip,
                    accepted_at,
                    deadline: custody.deadline,
                };
                let result = if late {
                    Err(SendFailure::Expired {
                        accepted: Some(receipt),
                    })
                } else {
                    Ok(receipt)
                };
                let _ = custody.response.send(result);
            }
            let _ = packet.completion.send(Ok(()));
            Ok(true)
        }
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "partial UDP data datagram",
        )
        .into()),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            if let Some(physical) = physical {
                physical.blocked(packet.custody.as_ref().map(|value| value.class))?;
            }
            Ok(false)
        }
        Err(error) => Err(error.into()),
    }
}

fn expire_held(held: &mut Option<Submission>, physical: Option<&Ledger>) -> Result<bool, Error> {
    let Some(custody) = held.as_ref().and_then(|value| value.custody.as_ref()) else {
        return Ok(false);
    };
    let cancelled = custody.response.is_closed();
    if !cancelled && Instant::now() < custody.deadline {
        return Ok(false);
    }
    if let Some(physical) = physical {
        physical.refused(cancelled)?;
    }
    let submission = held.take().ok_or(Error::Closed)?;
    let custody = submission.custody.ok_or(Error::Closed)?;
    let _ = custody
        .response
        .send(Err(SendFailure::Expired { accepted: None }));
    let _ = submission.completion.send(Err(Error::Timeout));
    Ok(true)
}

fn deliver_opaque(
    outputs: &mpsc::Sender<common::Received>,
    payload: &[u8],
    maximum: usize,
) -> Result<(), Error> {
    if payload.is_empty() || payload.len() > maximum || outputs.capacity() == 0 {
        return Ok(());
    }
    let mut packet = Vec::new();
    packet
        .try_reserve_exact(payload.len())
        .map_err(|_| Error::Allocation)?;
    packet.extend_from_slice(payload);
    match outputs.try_send(common::Received {
        bytes: packet,
        framing: common::ReceiveFraming::Final,
    }) {
        Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
        Err(mpsc::error::TrySendError::Closed(_)) => Err(Error::Closed),
    }
}

pub(super) async fn run(inputs: Inputs) -> Result<(), Error> {
    let Inputs {
        socket,
        settings,
        mut transport,
        bridge,
        mut submissions,
        mut priority,
        outputs,
        mut activate,
        started,
        budget,
        physical,
        final_records,
        #[cfg(test)]
        user_gate,
    } = inputs;
    let maximum = transport.config().max_datagram_bytes;
    let ip_overhead = settings.ip_overhead;
    let (mut tls_read, mut tls_write) = tokio::io::split(bridge);
    let mut tls_source = bytes(settings.max_source_bytes)?;
    let mut tls_source_length = 0;
    let mut tls_delivery = bytes(settings.max_source_bytes)?;
    let (mut tls_delivery_start, mut tls_delivery_end) = (0, 0);
    let mut receive = bytes(maximum + 1)?;
    let mut control_output = bytes(maximum)?;
    let mut control_length = None;
    let mut crypto_output = bytes(settings.crypto_bytes)?;
    let mut data_output = bytes(maximum)?;
    let mut priority_output = bytes(if priority.is_some() { maximum } else { 0 })?;
    let mut pending_data: Option<PendingData> = None;
    let mut pending_priority: Option<PendingData> = None;
    let mut held: Option<Submission> = None;
    let mut held_priority: Option<Submission> = None;
    let mut data: Option<Data> = None;
    let mut timer = interval_at(started, settings.poll_interval);
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        // A finite work batch gives socket ingress, TLS and data a shared service turn.
        for _ in 0..settings.work_limit {
            let elapsed = started.elapsed();
            if elapsed >= transport.expires() {
                return Err(Error::Control(control::Error::Expired));
            }
            let setup_open = final_records
                .as_ref()
                .and_then(|selected| selected.get())
                .is_none_or(|cap| Instant::now() < *cap);
            let final_selected = final_records
                .as_ref()
                .is_some_and(|selected| selected.get().is_some());
            let mut progress = false;
            progress |= expire_held(&mut held, physical.as_ref())?;
            progress |= expire_held(&mut held_priority, physical.as_ref())?;
            match socket.try_recv(&mut receive) {
                Ok(length) => {
                    progress = true;
                    if length <= maximum && final_selected && final_prefix(&receive[..length]) {
                        if matches!(data, Some(Data::Opaque)) && settings.receiving {
                            deliver_opaque(
                                &outputs,
                                &receive[..length],
                                settings.max_payload_bytes,
                            )?;
                        }
                    } else if length <= maximum && setup_open {
                        match wire::decode(&receive[..length]) {
                            Ok(wire::Packet::Control(_)) => {
                                match transport.receive(&receive[..length], elapsed) {
                                    Ok(()) => {}
                                    Err(error) if ignorable(error) => {}
                                    Err(error) => return Err(error.into()),
                                }
                            }
                            Ok(wire::Packet::Data {
                                key_id: 0,
                                peer_id: None,
                                payload,
                            }) if settings.receiving => {
                                if let Some(owner) = data.as_mut()
                                    && let Ok(payload) = owner.open(payload)
                                    && payload.len() <= settings.max_payload_bytes
                                    && outputs.capacity() != 0
                                {
                                    // Queue pressure drops records. Opaque activation grants no
                                    // authentication here; its caller must authenticate/replay-check.
                                    let mut packet = Vec::new();
                                    packet
                                        .try_reserve_exact(payload.len())
                                        .map_err(|_| Error::Allocation)?;
                                    packet.extend_from_slice(payload);
                                    match outputs.try_send(common::Received {
                                        bytes: packet,
                                        framing: common::ReceiveFraming::DataV1,
                                    }) {
                                        Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                                        Err(mpsc::error::TrySendError::Closed(_)) => {
                                            return Err(Error::Closed);
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
            if !setup_open {
                // The initial-only selection never renews or periodically services TLS.
                control_length = None;
                tls_source_length = 0;
                tls_delivery_start = tls_delivery_end;
            }
            if setup_open && transport.ready() && tls_source_length != 0 {
                match transport.write_tls(&tls_source[..tls_source_length], elapsed) {
                    Ok(length) => {
                        tls_source.copy_within(length..tls_source_length, 0);
                        tls_source_length -= length;
                        progress = true;
                    }
                    Err(control::Error::Recovery(
                        RecoveryError::Capacity(_) | RecoveryError::SequenceWindow,
                    )) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if setup_open && tls_delivery_start == tls_delivery_end {
                tls_delivery_end = transport.read_tls(&mut tls_delivery, elapsed)?;
                tls_delivery_start = 0;
                progress |= tls_delivery_end != 0;
            }
            if setup_open && control_length.is_none() {
                control_length = poll_control(
                    &mut transport,
                    &budget,
                    elapsed,
                    ip_overhead,
                    &mut control_output,
                )?;
                progress |= control_length.is_some();
            }
            if pending_data.is_none()
                && let (Some(owner), Some(submission)) = (data.as_mut(), held.as_ref())
                && let Some(length) = poll_selected_data(
                    owner,
                    &submission.bytes,
                    submission.control,
                    &budget,
                    settings,
                    &mut crypto_output,
                    &mut data_output,
                    submission.final_record,
                )?
            {
                let submission = held.take().ok_or(Error::Closed)?;
                pending_data = Some(PendingData {
                    length,
                    completion: submission.completion,
                    custody: submission.custody,
                });
                progress = true;
            }
            if pending_priority.is_none()
                && let (Some(owner), Some(submission)) = (data.as_mut(), held_priority.as_ref())
                && let Some(length) = poll_selected_data(
                    owner,
                    &submission.bytes,
                    true,
                    &budget,
                    settings,
                    &mut crypto_output,
                    &mut priority_output,
                    submission.final_record,
                )?
            {
                let submission = held_priority.take().ok_or(Error::Closed)?;
                pending_priority = Some(PendingData {
                    length,
                    completion: submission.completion,
                    custody: submission.custody,
                });
                progress = true;
            }
            if let Some(length) = control_length {
                let original_cap = started
                    .checked_add(transport.expires())
                    .ok_or(Error::Configuration)?;
                if physical.is_some() && Instant::now() >= original_cap {
                    return Err(Error::Control(control::Error::Expired));
                }
                match socket.try_send(&control_output[..length]) {
                    Ok(sent) if sent == length => {
                        let late = physical.is_some() && Instant::now() >= original_cap;
                        if let Some(physical) = &physical {
                            physical.written(
                                None,
                                length
                                    .checked_add(ip_overhead)
                                    .ok_or(Error::Configuration)?,
                                late,
                            )?;
                        }
                        if late {
                            return Err(Error::Control(control::Error::Expired));
                        }
                        control_length = None;
                        progress = true;
                    }
                    Ok(_) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "partial UDP control datagram",
                        )
                        .into());
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error.into()),
                }
            }
            progress |= flush_data_with(
                &mut pending_priority,
                &priority_output,
                ip_overhead,
                physical.as_ref(),
                Instant::now,
                |bytes| socket.try_send(bytes),
            )?;
            progress |= flush_data_with(
                &mut pending_data,
                &data_output,
                ip_overhead,
                physical.as_ref(),
                Instant::now,
                |bytes| {
                    #[cfg(test)]
                    if user_gate
                        .as_ref()
                        .is_some_and(|gate| gate.load(std::sync::atomic::Ordering::Relaxed))
                    {
                        return Err(std::io::ErrorKind::WouldBlock.into());
                    }
                    socket.try_send(bytes)
                },
            )?;
            if !progress {
                break;
            }
        }
        let deadline = [
            held.as_ref()
                .and_then(|value| value.custody.as_ref())
                .map(|value| value.deadline),
            held_priority
                .as_ref()
                .and_then(|value| value.custody.as_ref())
                .map(|value| value.deadline),
            pending_data
                .as_ref()
                .and_then(|value| value.custody.as_ref())
                .map(|value| value.deadline),
            pending_priority
                .as_ref()
                .and_then(|value| value.custody.as_ref())
                .map(|value| value.deadline),
        ]
        .into_iter()
        .flatten()
        .min();
        let setup_open = final_records
            .as_ref()
            .and_then(|selected| selected.get())
            .is_none_or(|cap| Instant::now() < *cap);
        tokio::select! {
            _ = timer.tick() => {},
            _ = async { match deadline { Some(at) => tokio::time::sleep_until(at).await, None => std::future::pending().await } } => {},
            ready = socket.readable() => { ready?; },
            ready = socket.writable(), if control_length.is_some() || pending_priority.is_some() || pending_data.is_some() => { ready?; },
            read = tls_read.read(&mut tls_source), if setup_open && tls_source_length == 0 => {
                let length = read?; if length == 0 { return Err(Error::Closed); } tls_source_length = length;
            },
            write = tls_write.write(&tls_delivery[tls_delivery_start..tls_delivery_end]), if setup_open && tls_delivery_start != tls_delivery_end => {
                let length = write?; if length == 0 { return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into()); } tls_delivery_start += length;
            },
            submission = submissions.recv(), if held.is_none() && pending_data.is_none() && data.is_some() => {
                held = Some(submission.ok_or(Error::Closed)?);
            },
            submission = priority_input(&mut priority), if held_priority.is_none() && pending_priority.is_none() && data.is_some() => {
                held_priority = Some(submission.ok_or(Error::Closed)?);
            },
            activation = activate.recv(), if data.is_none() => {
                let activation = activation.ok_or(Error::Closed)?;
                data = Some(activation.data);
                let _ = activation.reply.send(());
            },
        }
        tokio::task::yield_now().await;
    }
}
