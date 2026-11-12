//! Separate negotiated finite native shutdown over the original reliable TLS lanes.
//!
//! Success proves exact admitted/native fences and clean TLS shutdown. The caller
//! must additionally supervise any underlying raw driver until its own clean drain.
use super::*;
use l2tunnel_auth::SessionConfig;
use l2tunnel_core::ConfigDigest;
use ring::digest::{SHA256, digest};
use tokio::sync::{oneshot, watch};
use tokio::task::JoinSet;
use tokio::time::{Instant, MissedTickBehavior, interval};

const CONTROL_BYTES: usize = 24;
const MAGIC: &[u8; 8] = b"L2DRAIN1";

/// Immutable settings authenticated before opening a native packet device.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Ordinary bounded frame/device settings.
    pub runtime: RuntimeConfig,
    /// Number and role of the original authenticated TLS lanes.
    pub duplex: Duplex,
    /// Absolute bound from the first local request or valid remote barrier.
    pub drain_timeout: Duration,
    /// Existing carrier-specific parameters, such as exact raw tuples and rings.
    pub carrier_context: ConfigDigest,
}

/// Derive the distinct drain-capable profile; legacy sessions cannot enter it.
pub fn session_config(config: Config) -> io::Result<SessionConfig> {
    config.runtime.validate()?;
    if config.drain_timeout < Duration::from_millis(1)
        || config.drain_timeout > Duration::from_secs(120)
    {
        return Err(invalid("finite native drain timeout outside bound"));
    }
    let mut bytes = b"l2tunnel/native-drain/v1\0".to_vec();
    bytes.extend_from_slice(&config.carrier_context.0);
    bytes.extend_from_slice(&[
        u8::from(config.runtime.layer == PacketLayer::Ip),
        u8::from(config.duplex == Duplex::Half),
        u8::from(config.runtime.compression == Compression::Lz4IfSmaller),
    ]);
    for value in [
        u64::try_from(config.runtime.max_packet).map_err(io::Error::other)?,
        u64::try_from(config.runtime.queue_packets).map_err(io::Error::other)?,
        u64::try_from(config.runtime.poll_interval.as_nanos()).map_err(io::Error::other)?,
        u64::try_from(config.drain_timeout.as_nanos()).map_err(io::Error::other)?,
    ] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    let mut hash = [0; 32];
    hash.copy_from_slice(digest(&SHA256, &bytes).as_ref());
    Ok(SessionConfig {
        layer: config.runtime.layer,
        digest: ConfigDigest(hash),
    })
}

/// Exact successful native/TLS drain evidence; no raw-socket closure is implied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DrainReport {
    /// Originals consumed from the native device before admission froze.
    pub local_admitted: u64,
    /// Originals handed to the retained TLS writer.
    pub local_handed: u64,
    /// Originals whose complete records actually flushed through TLS.
    pub local_flushed: u64,
    /// Exact authenticated remote final original count.
    pub peer_barrier: u64,
    /// Incoming originals actually written successfully to the native device.
    pub native_confirmed: u64,
    /// Locally transmitted final count, after actual barrier flush.
    pub local_barrier: u64,
    /// Exact peer fence acknowledged only after actual native completion.
    pub local_ack: u64,
    /// Exact local fence acknowledged by the peer's native completion.
    pub peer_ack: u64,
    /// Original physical TLS connections closed in both directions.
    pub tls_lanes_closed: u8,
}

#[derive(Clone, Copy, Debug, Default)]
struct Written {
    handed: u64,
    flushed: u64,
    barrier: Option<u64>,
    ack: Option<u64>,
}
enum Out {
    Data(Vec<u8>),
    Barrier(u64),
    Ack(u64),
    Close,
}
enum In {
    Data(Vec<u8>),
    Barrier(u64),
    Ack(u64),
    ReadClosed,
    WriteClosed,
    ReverseReadClosed,
    ReverseWriteClosed,
}
fn checked_next(value: u64) -> io::Result<u64> {
    value
        .checked_add(1)
        .ok_or_else(|| invalid("drain record counter exhausted"))
}
fn control(kind: u8, fence: u64) -> [u8; CONTROL_BYTES] {
    let mut output = [0; CONTROL_BYTES];
    output[..8].copy_from_slice(MAGIC);
    output[8] = kind;
    output[16..].copy_from_slice(&fence.to_be_bytes());
    output
}
fn decode_control(input: &[u8]) -> io::Result<(u8, u64)> {
    if input.len() != CONTROL_BYTES
        || input[..8] != *MAGIC
        || !matches!(input[8], 1 | 2)
        || input[9..16] != [0; 7]
    {
        return Err(invalid("malformed finite drain control"));
    }
    let count = u64::from_be_bytes(input[16..24].try_into().map_err(io::Error::other)?);
    Ok((input[8], count))
}
async fn event(sender: &mpsc::Sender<In>, input: In) -> io::Result<()> {
    sender
        .send(input)
        .await
        .map_err(|_| invalid("finite drain actor stopped"))
}
async fn reader<R: AsyncRead + Unpin>(
    mut stream: R,
    session: [u8; 16],
    config: RuntimeConfig,
    sender: mpsc::Sender<In>,
    remote_drain: watch::Sender<Option<Instant>>,
) -> io::Result<()> {
    let codec = config.codec()?;
    let mut expected = 0;
    let mut records = 0;
    let mut barrier = false;
    let mut ack = false;
    loop {
        let mut prefix = [0; 4];
        if stream.read(&mut prefix[..1]).await? == 0 {
            if !barrier || !ack {
                return Err(invalid("TLS EOF before complete remote drain controls"));
            }
            return event(&sender, In::ReadClosed).await;
        }
        stream.read_exact(&mut prefix[1..]).await?;
        let length = usize::try_from(u32::from_be_bytes(prefix)).map_err(io::Error::other)?;
        if !(wire::HEADER_LEN..=wire::HEADER_LEN + codec.max_encoded_len().max(CONTROL_BYTES))
            .contains(&length)
        {
            return Err(invalid("drain record length outside bound"));
        }
        let mut bytes = vec![0; length];
        stream.read_exact(&mut bytes).await?;
        let (header, payload) =
            wire::decode(&bytes, codec.max_encoded_len().max(CONTROL_BYTES)).map_err(wire_error)?;
        if header.epoch != Epoch(1)
            || header.session != session
            || header.lane != 0
            || header.packet_number != expected
        {
            return Err(invalid("drain record context or sequence"));
        }
        expected = checked_next(expected)?;
        match header.kind {
            Kind::Data if !barrier => {
                if config.compression == Compression::None && payload.get(4) != Some(&0) {
                    return Err(invalid("drain compression mismatch"));
                }
                let packet = codec.decode_vec(payload).map_err(io::Error::other)?;
                if !packet_valid(config.layer, &packet) {
                    return Err(invalid("drain native packet shape"));
                }
                records = checked_next(records)?;
                event(&sender, In::Data(packet)).await?;
            }
            Kind::Control => {
                let (kind, count) = decode_control(payload)?;
                match kind {
                    1 if !barrier && count == records => {
                        barrier = true;
                        // Native backpressure may delay consuming the FIFO barrier
                        // event. Start its absolute deadline independently, while
                        // retaining the FIFO event for exact native confirmation.
                        remote_drain.send_replace(Some(Instant::now()));
                        event(&sender, In::Barrier(count)).await?;
                    }
                    2 if barrier && !ack => {
                        ack = true;
                        event(&sender, In::Ack(count)).await?;
                    }
                    _ => return Err(invalid("duplicate or inconsistent drain fence")),
                }
            }
            _ => return Err(invalid("data after barrier or unexpected drain record")),
        }
    }
}
async fn writer<W: AsyncWrite + Unpin>(
    mut stream: W,
    session: [u8; 16],
    config: RuntimeConfig,
    mut output: mpsc::Receiver<Out>,
    written: watch::Sender<Written>,
    events: mpsc::Sender<In>,
) -> io::Result<()> {
    let codec = config.codec()?;
    let mut sequence = 0;
    let mut progress = Written::default();
    while let Some(message) = output.recv().await {
        let (kind, payload, original) = match message {
            Out::Data(packet) if progress.barrier.is_none() => {
                progress.handed = checked_next(progress.handed)?;
                written.send_replace(progress);
                (
                    Kind::Data,
                    codec.encode_vec(&packet).map_err(io::Error::other)?,
                    true,
                )
            }
            Out::Barrier(count) if progress.barrier.is_none() && count == progress.flushed => {
                (Kind::Control, control(1, count).to_vec(), false)
            }
            Out::Ack(count) if progress.barrier.is_some() && progress.ack.is_none() => {
                (Kind::Control, control(2, count).to_vec(), false)
            }
            Out::Close if progress.barrier.is_some() && progress.ack.is_some() => {
                stream.shutdown().await?;
                return event(&events, In::WriteClosed).await;
            }
            _ => return Err(invalid("invalid local drain writer transition")),
        };
        let bytes = wire::encode(
            Header {
                kind,
                epoch: Epoch(1),
                packet_number: sequence,
                session,
                lane: 0,
            },
            &payload,
        )
        .map_err(wire_error)?;
        stream
            .write_u32(u32::try_from(bytes.len()).map_err(io::Error::other)?)
            .await?;
        stream.write_all(&bytes).await?;
        stream.flush().await?;
        sequence = checked_next(sequence)?;
        if original {
            progress.flushed = checked_next(progress.flushed)?;
        } else {
            let (kind, count) = decode_control(&payload)?;
            if kind == 1 {
                progress.barrier = Some(count);
            } else {
                progress.ack = Some(count);
            }
        }
        written.send_replace(progress);
    }
    Err(invalid("drain output closed without explicit TLS shutdown"))
}

/// Forward until an explicit local/peer drain, then prove exact native and TLS close.
/// Cancellation or any deadline/error drops all owned tasks and reports no success.
pub async fn run<D: PacketDevice<Error = io::Error>>(
    mut device: D,
    link: Link,
    config: Config,
    mut stop: oneshot::Receiver<()>,
) -> io::Result<DrainReport> {
    let expected = session_config(config)?;
    let (got, _, duplex) = link
        .managed_metadata
        .as_ref()
        .ok_or_else(|| invalid("drain requires authenticated metadata"))?
        .snapshot();
    if got != expected
        || duplex != config.duplex
        || device.layer() != expected.layer
        || link.layer != expected.layer
        || (link.reverse_reader.is_some() != (duplex == Duplex::Half))
        || (link.reverse_writer.is_some() != (duplex == Duplex::Half))
    {
        return Err(invalid("drain profile or physical lane mismatch"));
    }
    let runtime = config.runtime;
    let (out, output) = mpsc::channel(runtime.queue_packets);
    let (events, mut input) = mpsc::channel(runtime.queue_packets);
    let (written, progress) = watch::channel(Written::default());
    let (close, mut closing) = watch::channel(false);
    let (remote_drain, mut remote_arrival) = watch::channel(None);
    let mut remote_watch_open = true;
    let mut tasks = JoinSet::new();
    tasks.spawn(reader(
        link.reader,
        link.receive_session,
        runtime,
        events.clone(),
        remote_drain,
    ));
    tasks.spawn(writer(
        link.writer,
        link.send_session,
        runtime,
        output,
        written,
        events.clone(),
    ));
    if let Some(mut reverse) = link.reverse_reader {
        let sender = events.clone();
        tasks.spawn(async move {
            let mut byte = [0];
            if reverse.read(&mut byte).await? != 0 {
                return Err(invalid("unexpected reverse drain application data"));
            }
            event(&sender, In::ReverseReadClosed).await
        });
    }
    if let Some(mut reverse) = link.reverse_writer {
        let sender = events.clone();
        tasks.spawn(async move {
            while !*closing.borrow_and_update() {
                closing.changed().await.map_err(io::Error::other)?;
            }
            reverse.shutdown().await?;
            event(&sender, In::ReverseWriteClosed).await
        });
    }
    drop(events);
    let mut timer = interval(runtime.poll_interval);
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut native = vec![0; l2tunnel_device::READ_BUFFER_BYTES];
    let mut pending = None::<Vec<u8>>;
    let mut admitted = 0;
    let mut confirmed = 0;
    let mut peer_barrier = None;
    let mut peer_ack = None;
    let mut deadline = None;
    let mut stop_pending = true;
    let mut barrier_sent = false;
    let mut ack_sent = false;
    let mut close_sent = false;
    let mut read_closed = false;
    let mut write_closed = false;
    let mut reverse_read_closed = duplex == Duplex::Full;
    let mut reverse_write_closed = duplex == Duplex::Full;
    loop {
        if deadline.is_some_and(|limit| Instant::now() >= limit) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "finite native/TLS drain deadline",
            ));
        }
        tokio::select! {
            result = &mut stop, if stop_pending => {
                result.map_err(|_| invalid("local drain controller cancelled"))?;
                stop_pending = false;
                deadline.get_or_insert(Instant::now() + config.drain_timeout);
            }
            incoming = input.recv(), if pending.is_none() => {
                match incoming.ok_or_else(|| invalid("drain event producers stopped"))? {
                    In::Data(packet) => pending = Some(packet),
                    In::Barrier(count) => {
                        if peer_barrier.replace(count).is_some() || confirmed != count {
                            return Err(invalid("unconfirmed native barrier"));
                        }
                        deadline.get_or_insert(Instant::now() + config.drain_timeout);
                    }
                    In::Ack(count) => {
                        if peer_ack.replace(count).is_some() || count != admitted || !barrier_sent {
                            return Err(invalid("mismatched local drain acknowledgment"));
                        }
                    }
                    In::ReadClosed => read_closed = true,
                    In::WriteClosed => write_closed = true,
                    In::ReverseReadClosed => {
                        if peer_barrier.is_none() || !ack_sent {
                            return Err(invalid("asymmetric early paired TLS close"));
                        }
                        reverse_read_closed = true;
                    }
                    In::ReverseWriteClosed => reverse_write_closed = true,
                }
            }
            changed = remote_arrival.changed(), if remote_watch_open => {
                if changed.is_err() { remote_watch_open = false; }
            }
            result = tasks.join_next(), if !tasks.is_empty() => {
                result.ok_or_else(|| invalid("missing drain task"))?.map_err(io::Error::other)??;
            }
            _ = tokio::time::sleep_until(deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(120))), if deadline.is_some() => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "finite native/TLS drain deadline"));
            }
            _ = timer.tick() => {}
        }
        if let Some(arrived) = *remote_arrival.borrow_and_update() {
            let remote_limit = arrived + config.drain_timeout;
            deadline = Some(deadline.map_or(remote_limit, |old| old.min(remote_limit)));
        }
        if let Some(packet) = &pending {
            match device.transmit(packet) {
                Ok(()) => {
                    pending = None;
                    confirmed = checked_next(confirmed)?;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        if deadline.is_none() {
            for _ in 0..runtime.queue_packets.min(32) {
                let Ok(permit) = out.try_reserve() else {
                    break;
                };
                match device.receive(&mut native) {
                    Ok(Some(length))
                        if length <= runtime.max_packet
                            && packet_valid(runtime.layer, &native[..length]) =>
                    {
                        admitted = checked_next(admitted)?;
                        permit.send(Out::Data(native[..length].to_vec()));
                    }
                    Ok(Some(_)) => return Err(invalid("invalid or oversized native drain packet")),
                    Ok(None) => break,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                }
            }
        } else if !barrier_sent && let Ok(permit) = out.try_reserve() {
            permit.send(Out::Barrier(admitted));
            barrier_sent = true;
        }
        let written = *progress.borrow();
        if !ack_sent
            && written.barrier == Some(admitted)
            && let Some(fence) = peer_barrier
            && confirmed == fence
            && pending.is_none()
            && let Ok(permit) = out.try_reserve()
        {
            permit.send(Out::Ack(fence));
            ack_sent = true;
        }
        if !close_sent
            && peer_ack == Some(admitted)
            && written.barrier == Some(admitted)
            && written.ack == peer_barrier
            && written.ack.is_some()
            && let Ok(permit) = out.try_reserve()
        {
            permit.send(Out::Close);
            close.send_replace(true);
            close_sent = true;
        }
        if close_sent && read_closed && write_closed && reverse_read_closed && reverse_write_closed
        {
            if admitted != written.handed
                || admitted != written.flushed
                || peer_barrier != Some(confirmed)
            {
                return Err(invalid("final native drain ownership mismatch"));
            }
            // Workers send each terminal event as their final await. Keep even
            // future worker cleanup inside the original absolute drain bound.
            let limit = deadline.ok_or_else(|| invalid("missing final drain deadline"))?;
            tokio::time::timeout_at(limit, async {
                while let Some(result) = tasks.join_next().await {
                    result.map_err(io::Error::other)??;
                }
                Ok::<_, io::Error>(())
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "final drain task deadline"))??;
            return Ok(DrainReport {
                local_admitted: admitted,
                local_handed: written.handed,
                local_flushed: written.flushed,
                peer_barrier: confirmed,
                native_confirmed: confirmed,
                local_barrier: admitted,
                local_ack: confirmed,
                peer_ack: admitted,
                tls_lanes_closed: if duplex == Duplex::Half { 2 } else { 1 },
            });
        }
    }
}

#[cfg(test)]
#[path = "drained_tests.rs"]
mod tests;
