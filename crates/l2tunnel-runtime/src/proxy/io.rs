use super::super::{wire as outer, wire_error};
use super::wire::{ControlFrame, Fence, Start};
use super::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, timeout};

pub(super) enum Event {
    Control(usize, ControlFrame, u64),
    Eof(usize),
    WriteClosed(usize),
}
pub(super) enum Output {
    Control(ControlFrame),
    Close,
}
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Progress {
    pub ready: bool,
    pub users: u64,
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
    let mut control_count = 0;
    let mut control_since = Instant::now();
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
                if control_since.elapsed() >= Duration::from_secs(1) {
                    control_since = Instant::now();
                    control_count = 0;
                }
                control_count += 1;
                if control_count > config.control_rate {
                    return Err(invalid("proxy control rate"));
                }
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
pub(super) async fn writer<W: AsyncWrite + Unpin>(
    mut stream: W,
    direction: Direction,
    mut controls: mpsc::Receiver<Output>,
    mut users: mpsc::Receiver<Vec<u8>>,
    progress: watch::Sender<Progress>,
    events: mpsc::Sender<Event>,
) -> io::Result<()> {
    let mut sequence = 0u64;
    let mut state = Progress::default();
    let mut burst = 0;
    let mut delayed = None;
    loop {
        let item = if delayed.is_some() {
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
                    write_frame(&mut stream, &bytes).await?;
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
        write_frame(&mut stream, &bytes).await?;
        sequence = sequence
            .checked_add(1)
            .ok_or_else(|| invalid("proxy sequence exhausted"))?;
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
async fn write_frame<W: AsyncWrite + Unpin>(stream: &mut W, bytes: &[u8]) -> io::Result<()> {
    stream
        .write_u32(u32::try_from(bytes.len()).map_err(io::Error::other)?)
        .await?;
    stream.write_all(bytes).await?;
    stream.flush().await
}
