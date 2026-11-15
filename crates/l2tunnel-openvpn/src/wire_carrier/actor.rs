//! The sole connected socket owner. Retained emissions survive WouldBlock without
//! another recovery attempt, packet number, encryption operation or wire charge.
use super::{Activation, Data, Error, Submission, control, wire};
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
    pub outputs: mpsc::Sender<Vec<u8>>,
    pub activate: mpsc::Receiver<Activation>,
    pub started: Instant,
    pub budget: Budget,
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

pub(super) fn poll_data(
    data: &mut Data,
    payload: &[u8],
    control: bool,
    budget: &Budget,
    settings: Settings,
    crypto: &mut [u8],
    output: &mut [u8],
) -> Result<Option<usize>, Error> {
    budget
        .transaction(|quota| {
            if !quota.permits(control, settings.path_mtu) {
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
                wire::encode_data(0, None, body, output).map_err(Error::Wire)
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
}

async fn priority_input(input: &mut Option<mpsc::Receiver<Submission>>) -> Option<Submission> {
    match input {
        Some(input) => input.recv().await,
        None => std::future::pending().await,
    }
}

pub(super) fn flush_data(
    pending: &mut Option<PendingData>,
    output: &[u8],
    mut send: impl FnMut(&[u8]) -> std::io::Result<usize>,
) -> Result<bool, Error> {
    let Some(packet) = pending.as_ref() else {
        return Ok(false);
    };
    let bytes = output.get(..packet.length).ok_or(Error::Configuration)?;
    match send(bytes) {
        Ok(sent) if sent == packet.length => {
            let packet = pending.take().ok_or(Error::Closed)?;
            let _ = packet.completion.send(Ok(()));
            Ok(true)
        }
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "partial UDP data datagram",
        )
        .into()),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
        Err(error) => Err(error.into()),
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
            let mut progress = false;
            match socket.try_recv(&mut receive) {
                Ok(length) => {
                    progress = true;
                    if length <= maximum {
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
                                    match outputs.try_send(packet) {
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
            if transport.ready() && tls_source_length != 0 {
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
            if tls_delivery_start == tls_delivery_end {
                tls_delivery_end = transport.read_tls(&mut tls_delivery, elapsed)?;
                tls_delivery_start = 0;
                progress |= tls_delivery_end != 0;
            }
            if control_length.is_none() {
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
                && let Some(length) = poll_data(
                    owner,
                    &submission.bytes,
                    submission.control,
                    &budget,
                    settings,
                    &mut crypto_output,
                    &mut data_output,
                )?
            {
                let submission = held.take().ok_or(Error::Closed)?;
                pending_data = Some(PendingData {
                    length,
                    completion: submission.completion,
                });
                progress = true;
            }
            if pending_priority.is_none()
                && let (Some(owner), Some(submission)) = (data.as_mut(), held_priority.as_ref())
                && let Some(length) = poll_data(
                    owner,
                    &submission.bytes,
                    true,
                    &budget,
                    settings,
                    &mut crypto_output,
                    &mut priority_output,
                )?
            {
                let submission = held_priority.take().ok_or(Error::Closed)?;
                pending_priority = Some(PendingData {
                    length,
                    completion: submission.completion,
                });
                progress = true;
            }
            if let Some(length) = control_length {
                match socket.try_send(&control_output[..length]) {
                    Ok(sent) if sent == length => {
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
            progress |= flush_data(&mut pending_priority, &priority_output, |bytes| {
                socket.try_send(bytes)
            })?;
            progress |= flush_data(&mut pending_data, &data_output, |bytes| {
                socket.try_send(bytes)
            })?;
            if !progress {
                break;
            }
        }
        tokio::select! {
            _ = timer.tick() => {},
            ready = socket.readable() => { ready?; },
            ready = socket.writable(), if control_length.is_some() || pending_priority.is_some() || pending_data.is_some() => { ready?; },
            read = tls_read.read(&mut tls_source), if tls_source_length == 0 => {
                let length = read?; if length == 0 { return Err(Error::Closed); } tls_source_length = length;
            },
            write = tls_write.write(&tls_delivery[tls_delivery_start..tls_delivery_end]), if tls_delivery_start != tls_delivery_end => {
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
