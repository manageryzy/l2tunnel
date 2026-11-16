use super::super::{wire as outer, wire_error};
use super::wire::{ControlFrame, Fence, Start};
use super::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, sleep_until, timeout};

pub(super) enum Event {
    Control(usize, ControlFrame, u64),
    Eof(usize),
    WriteClosed(usize),
}
pub(super) enum Output {
    Control(ControlFrame),
    Close,
}
/// Exact local whole-frame fact; ordinal is bound before any Data bytes write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PhysicalWrite {
    pub(crate) ordinal: Option<u64>,
    pub(crate) generation: u64,
    pub(crate) identity: l2tunnel_codec::aligned_receiver::RecordIdentity,
    pub(crate) accepted_at: Instant,
    pub(crate) observed_at: Instant,
}
/// Two actual unobserved all-user writes, not two measurement-only tokens.
pub(super) const PHYSICAL_SLOTS: usize = 2;
pub(super) fn physical_metadata_bytes() -> io::Result<usize> {
    // Actual writer state, watch value and one actor observation copy.
    let bytes = std::mem::size_of::<[Option<PhysicalWrite>; PHYSICAL_SLOTS]>()
        .checked_mul(3)
        .ok_or_else(|| invalid("physical progress metadata overflow"))?;
    // The fixed Common bound already counts its entire Bridge metadata owner.
    Ok(bytes)
}
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Progress {
    pub ready: bool,
    pub users: u64,
    pub physical: [Option<PhysicalWrite>; PHYSICAL_SLOTS],
    pub quiesce: bool,
    pub barrier: Option<Fence>,
    pub ack: Option<Fence>,
    pub credit: wire::Credit,
    pub pong: u64,
}
#[derive(Clone, Copy)]
pub(super) struct Direction {
    pub index: usize,
    pub lane: u8,
    pub session: [u8; 16],
    pub bulk: bool,
}
pub(super) async fn reader<R: AsyncRead + Unpin>(
    mut stream: R,
    direction: Direction,
    expected: Start,
    profile: (Config, bool),
    events: mpsc::Sender<Event>,
    users: mpsc::Sender<Vec<u8>>,
    quiesce: watch::Sender<Option<Instant>>,
) -> io::Result<()> {
    let (config, measured) = profile;
    let mut sequence = 0u64;
    let mut seen_users = 0u64;
    let mut start = false;
    let mut ready = false;
    let control_interval = control_interval(config.control_rate)?;
    let mut control_due = Instant::now();
    let mut saw_quiesce = false;
    let mut saw_barrier = false;
    let mut saw_ack = false;
    let max = config.max_user()?.max(wire::CONTROL_MAX);
    loop {
        let input = async {
            let mut prefix = [0; 4];
            if stream.read(&mut prefix[..1]).await? == 0 {
                return Ok::<_, io::Error>(None);
            }
            stream.read_exact(&mut prefix[1..]).await?;
            let length = u32::from_be_bytes(prefix) as usize;
            if !(outer::HEADER_LEN..=outer::HEADER_LEN + max).contains(&length) {
                return Err(invalid("proxy stream length bound"));
            }
            let mut b = vec![0; length];
            stream.read_exact(&mut b).await?;
            Ok(Some(b))
        };
        let Some(input) = timeout(config.timeouts.control_idle, input)
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "proxy retained TLS read deadline")
            })??
        else {
            events
                .send(Event::Eof(direction.index))
                .await
                .map_err(|_| invalid("proxy actor stopped"))?;
            return Ok(());
        };
        let (header, body) = outer::decode(&input, max).map_err(wire_error)?;
        if header.session != direction.session
            || header.epoch != l2tunnel_core::Epoch(1)
            || header.lane != u16::from(direction.lane)
            || header.packet_number != sequence
        {
            return Err(invalid("proxy outer scope/sequence"));
        }
        sequence = sequence
            .checked_add(1)
            .ok_or_else(|| invalid("proxy sequence exhausted"))?;
        match header.kind {
            outer::Kind::Data if direction.bulk && start && ready && !saw_barrier => {
                let user = wire::decode_profile(body, &config, measured)?;
                if saw_quiesce && user.flow != 0 && user.body.get(..6) == Some(b"LTPA\x01\x01") {
                    return Err(invalid("new proxy Open after Quiesce"));
                }
                users
                    .send(body.to_vec())
                    .await
                    .map_err(|_| invalid("proxy actor stopped"))?;
                seen_users = seen_users
                    .checked_add(1)
                    .ok_or_else(|| invalid("proxy reader counter exhausted"))?;
            }
            outer::Kind::Control => {
                // TCP/TLS preserves order, not arrival spacing. Bound decode/actor
                // work at the negotiated rate without rejecting a compliant sender
                // whose flushed records were buffered by the transport or scheduler.
                // Only this already bounded record is retained while backpressured.
                sleep_until(control_due).await;
                control_due = Instant::now()
                    .checked_add(control_interval)
                    .ok_or_else(|| invalid("proxy receive pacing deadline overflow"))?;
                let frame = ControlFrame::decode(body)?;
                match frame {
                    ControlFrame::Start(s) if !start && s == expected => start = true,
                    ControlFrame::Ready(s) if start && !ready && s == expected => ready = true,
                    ControlFrame::Ping(_) | ControlFrame::Pong(_) if start && ready => {}
                    ControlFrame::Credit(_) if direction.bulk && start && ready => {}
                    ControlFrame::Quiesce if direction.bulk && start && ready && !saw_quiesce => {
                        saw_quiesce = true;
                        quiesce.send_replace(Some(Instant::now()));
                    }
                    ControlFrame::Barrier(_) if direction.bulk && saw_quiesce && !saw_barrier => {
                        saw_barrier = true
                    }
                    ControlFrame::Ack(_) if direction.bulk && saw_barrier && !saw_ack => {
                        saw_ack = true
                    }
                    _ => return Err(invalid("proxy control phase or physical lane")),
                }
                events
                    .send(Event::Control(direction.index, frame, seen_users))
                    .await
                    .map_err(|_| invalid("proxy actor stopped"))?;
            }
            _ => return Err(invalid("proxy data phase or physical lane")),
        }
    }
}
/// One noncatching-up physical control slot. Credit admission uses four slots
/// between cumulative updates, retaining headroom for liveness and barriers.
pub(crate) fn control_interval(rate: usize) -> io::Result<Duration> {
    if !(16..=1024).contains(&rate) {
        return Err(invalid("proxy control pacing rate"));
    }
    let rate = u64::try_from(rate).map_err(io::Error::other)?;
    Ok(Duration::from_nanos(1_000_000_000_u64.div_ceil(rate)))
}

#[cfg(test)]
pub(super) async fn writer<W: AsyncWrite + Unpin>(
    stream: W,
    direction: Direction,
    control_rate: usize,
    controls: mpsc::Receiver<Output>,
    users: mpsc::Receiver<Vec<u8>>,
    progress: watch::Sender<Progress>,
    events: mpsc::Sender<Event>,
) -> io::Result<()> {
    writer_selected(
        stream,
        direction,
        control_rate,
        controls,
        users,
        progress,
        events,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn writer_selected<W: AsyncWrite + Unpin>(
    mut stream: W,
    direction: Direction,
    control_rate: usize,
    mut controls: mpsc::Receiver<Output>,
    mut users: mpsc::Receiver<Vec<u8>>,
    progress: watch::Sender<Progress>,
    events: mpsc::Sender<Event>,
    receipts: Option<super::actor::CommonRetirement>,
) -> io::Result<()> {
    let mut sequence = 0u64;
    let mut state = Progress::default();
    let mut burst = 0;
    let mut delayed = None;
    let control_interval = control_interval(control_rate)?;
    let mut control_due = Instant::now();
    loop {
        let item = if delayed.is_some() && Instant::now() < control_due {
            // A paced control frame owns one existing slot, not the user lane.
            // Keep admitted data/measurement records moving while that slot waits.
            tokio::select! {
                _ = sleep_until(control_due) => delayed.take().map(Ok),
                input = users.recv(), if direction.bulk && state.ready => {
                    Some(Err(input.ok_or_else(|| invalid("proxy user producer dropped"))?))
                }
            }
        } else if delayed.is_some() {
            delayed.take().map(Ok)
        } else if burst >= 4 && state.ready {
            match users.try_recv() {
                Ok(user) => Some(Err(user)),
                Err(_) => None,
            }
        } else {
            None
        };
        let item = match item {
            Some(item) => item,
            None => {
                tokio::select! {input=controls.recv()=>Ok(input.ok_or_else(||invalid("proxy control producer dropped"))?),input=users.recv(),if direction.bulk && state.ready=>Err(input.ok_or_else(||invalid("proxy user producer dropped"))?),}
            }
        };
        let (kind, body, control) = match item {
            Err(bytes) => {
                if state.barrier.is_some() {
                    return Err(invalid("proxy writer user after fence"));
                }
                burst = 0;
                (outer::Kind::Data, bytes, None)
            }
            Ok(Output::Close) => {
                if direction.bulk && (state.barrier.is_none() || state.ack.is_none()) {
                    return Err(invalid("proxy premature writer close"));
                }
                stream.shutdown().await?;
                events
                    .send(Event::WriteClosed(direction.index))
                    .await
                    .map_err(|_| invalid("proxy actor stopped"))?;
                return Ok(());
            }
            Ok(Output::Control(frame)) => {
                if Instant::now() < control_due {
                    delayed = Some(Output::Control(frame));
                    continue;
                }
                if matches!(frame, ControlFrame::Quiesce) && !state.ready {
                    return Err(invalid("proxy writer Quiesce before Ready flush"));
                }
                if matches!(frame, ControlFrame::Quiesce)
                    && let Ok(user) = users.try_recv()
                {
                    delayed = Some(Output::Control(frame));
                    burst = 0;
                    let bytes = outer::encode(
                        outer::Header {
                            kind: outer::Kind::Data,
                            epoch: l2tunnel_core::Epoch(1),
                            packet_number: sequence,
                            session: direction.session,
                            lane: u16::from(direction.lane),
                        },
                        &user,
                    )
                    .map_err(wire_error)?;
                    let ordinal = state
                        .users
                        .checked_add(1)
                        .ok_or_else(|| invalid("proxy user counter exhausted"))?;
                    let physical =
                        write_selected_frame(&mut stream, &bytes, receipts.as_ref(), Some(ordinal))
                            .await?;
                    publish_physical(&mut state, ordinal, physical)?;
                    sequence = sequence
                        .checked_add(1)
                        .ok_or_else(|| invalid("proxy sequence exhausted"))?;
                    state.users = state
                        .users
                        .checked_add(1)
                        .ok_or_else(|| invalid("proxy user counter exhausted"))?;
                    progress.send_replace(state);
                    continue;
                }
                if let ControlFrame::Barrier(f) = frame
                    && (f.records != state.users || !users.is_empty())
                {
                    return Err(invalid("proxy writer barrier disagrees with flush"));
                }
                burst = (burst + 1).min(4);
                (outer::Kind::Control, frame.encode(), Some(frame))
            }
        };
        let bytes = outer::encode(
            outer::Header {
                kind,
                epoch: l2tunnel_core::Epoch(1),
                packet_number: sequence,
                session: direction.session,
                lane: u16::from(direction.lane),
            },
            &body,
        )
        .map_err(wire_error)?;
        // Refuse exhaustion before a physical write can consume its Bridge fact.
        let next_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| invalid("proxy sequence exhausted"))?;
        let ordinal = if control.is_none() {
            Some(
                state
                    .users
                    .checked_add(1)
                    .ok_or_else(|| invalid("proxy user counter exhausted"))?,
            )
        } else {
            None
        };
        let physical =
            write_selected_frame(&mut stream, &bytes, receipts.as_ref(), ordinal).await?;
        if let Some(ordinal) = ordinal {
            publish_physical(&mut state, ordinal, physical)?;
        }
        if control.is_some() {
            control_due = Instant::now()
                .checked_add(control_interval)
                .ok_or_else(|| invalid("proxy control pacing deadline overflow"))?;
        }
        sequence = next_sequence;
        match control {
            None => {
                state.users = state
                    .users
                    .checked_add(1)
                    .ok_or_else(|| invalid("proxy user counter exhausted"))?
            }
            Some(ControlFrame::Ready(_)) => state.ready = true,
            Some(ControlFrame::Quiesce) => state.quiesce = true,
            Some(ControlFrame::Barrier(f)) => state.barrier = Some(f),
            Some(ControlFrame::Ack(f)) => state.ack = Some(f),
            Some(ControlFrame::Credit(c)) => state.credit = c,
            Some(ControlFrame::Pong(n)) => state.pong = n,
            _ => {}
        }
        progress.send_replace(state);
    }
}
fn publish_physical(
    state: &mut Progress,
    ordinal: u64,
    receipt: Option<PhysicalWrite>,
) -> io::Result<()> {
    if let Some(receipt) = receipt {
        if receipt.ordinal != Some(ordinal) {
            return Err(invalid("proxy physical user provenance"));
        }
        let index =
            usize::try_from((ordinal - 1) % PHYSICAL_SLOTS as u64).map_err(io::Error::other)?;
        state.physical[index] = Some(receipt);
    }
    Ok(())
}
async fn write_selected_frame<W: AsyncWrite + Unpin>(
    stream: &mut W,
    bytes: &[u8],
    source: Option<&super::actor::CommonRetirement>,
    ordinal: Option<u64>,
) -> io::Result<Option<PhysicalWrite>> {
    if let Some(source) = source
        && let Some(ordinal) = ordinal
    {
        source.prepare_user_receipt(ordinal).await?;
    }
    write_frame(stream, bytes).await?;
    let receipt = source
        .map(|source| source.take_physical_receipt())
        .transpose()?;
    if receipt.is_some_and(|receipt| receipt.ordinal != ordinal) {
        return Err(invalid("proxy frame physical provenance"));
    }
    Ok(receipt)
}
async fn write_frame<W: AsyncWrite + Unpin>(stream: &mut W, bytes: &[u8]) -> io::Result<()> {
    stream
        .write_u32(u32::try_from(bytes.len()).map_err(io::Error::other)?)
        .await?;
    stream.write_all(bytes).await?;
    stream.flush().await
}
