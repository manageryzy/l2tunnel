//! Shared retained authenticated-control v1 framing, independent of data recovery.
//!
//! Callers bind magic, feedback length and receipt grammar before reading. This
//! preserves existing fixed-profile wire bytes; it does not negotiate mode
//! transitions or authenticate an untrusted stream by itself.
use crate::invalid;
use std::{io, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::{Instant, timeout};

#[derive(Clone, Default)]
pub(crate) struct Feedback {
    pub ack: Option<Vec<u8>>,
    pub credit: u64,
}
pub(crate) enum ControlEvent {
    Ack(Vec<u8>),
    Credit(u64),
}
/// Exact authenticated native identity receipts for explicit aligned/packed v2.
pub(crate) enum NativeControlEvent {
    Ack(Vec<u8>),
    Delivered { channel: u8, record: u64 },
}
#[cfg(test)]
pub(crate) async fn read_control_bound(
    reader: impl AsyncRead + Unpin,
    lane: usize,
    events: mpsc::Sender<(usize, ControlEvent)>,
    duration: Duration,
    feedback_bytes: usize,
    magic: [u8; 4],
) -> io::Result<()> {
    read_control_bound_inner(
        reader,
        events,
        duration,
        ControlGrammar {
            feedback_bytes,
            magic,
            credit_bytes: 8,
        },
        |bytes| (lane, ControlEvent::Ack(bytes)),
        |[a, b, c, d, e, f, g, h, _]| {
            (
                lane,
                ControlEvent::Credit(u64::from_be_bytes([a, b, c, d, e, f, g, h])),
            )
        },
    )
    .await
}
/// Retain the original authenticated parse receipt before bounded event queueing.
/// The legacy wrapper performs no additional clock reads.
pub(crate) async fn read_control_bound_timed(
    reader: impl AsyncRead + Unpin,
    lane: usize,
    events: mpsc::Sender<(usize, ControlEvent, Instant)>,
    duration: Duration,
    feedback_bytes: usize,
    magic: [u8; 4],
) -> io::Result<()> {
    read_control_bound_inner(
        reader,
        events,
        duration,
        ControlGrammar {
            feedback_bytes,
            magic,
            credit_bytes: 8,
        },
        |bytes| (lane, ControlEvent::Ack(bytes), Instant::now()),
        |[a, b, c, d, e, f, g, h, _]| {
            (
                lane,
                ControlEvent::Credit(u64::from_be_bytes([a, b, c, d, e, f, g, h])),
                Instant::now(),
            )
        },
    )
    .await
}
pub(crate) async fn read_native_control_bound_timed(
    reader: impl AsyncRead + Unpin,
    lane: usize,
    events: mpsc::Sender<(usize, NativeControlEvent, Instant)>,
    duration: Duration,
    feedback_bytes: usize,
    magic: [u8; 4],
) -> io::Result<()> {
    read_control_bound_inner(
        reader,
        events,
        duration,
        ControlGrammar {
            feedback_bytes,
            magic,
            credit_bytes: 9,
        },
        |bytes| (lane, NativeControlEvent::Ack(bytes), Instant::now()),
        |[channel, a, b, c, d, e, f, g, h]| {
            (
                lane,
                NativeControlEvent::Delivered {
                    channel,
                    record: u64::from_be_bytes([a, b, c, d, e, f, g, h]),
                },
                Instant::now(),
            )
        },
    )
    .await
}
struct ControlGrammar {
    feedback_bytes: usize,
    magic: [u8; 4],
    credit_bytes: usize,
}
async fn read_control_bound_inner<E>(
    mut reader: impl AsyncRead + Unpin,
    events: mpsc::Sender<E>,
    duration: Duration,
    grammar: ControlGrammar,
    mut ack: impl FnMut(Vec<u8>) -> E,
    mut credit: impl FnMut([u8; 9]) -> E,
) -> io::Result<()> {
    let ControlGrammar {
        feedback_bytes,
        magic,
        credit_bytes,
    } = grammar;
    if !matches!(credit_bytes, 8 | 9) {
        return Err(invalid("UDP credit grammar"));
    }
    loop {
        let event = timeout(duration, async {
            let mut header = [0; 8];
            reader.read_exact(&mut header).await?;
            if header[..4] != magic || header[4] != 1 {
                return Err(invalid("UDP control header"));
            }
            let length = usize::from(u16::from_be_bytes([header[6], header[7]]));
            match (header[5], length) {
                (1, 0) => Ok(None),
                (2, length) if length == feedback_bytes => {
                    let mut bytes = vec![0; feedback_bytes];
                    reader.read_exact(&mut bytes).await?;
                    Ok(Some(ack(bytes)))
                }
                (3, length) if length == credit_bytes => {
                    let mut bytes = [0; 9];
                    reader.read_exact(&mut bytes[..credit_bytes]).await?;
                    Ok(Some(credit(bytes)))
                }
                _ => Err(invalid("UDP control kind or length")),
            }
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "UDP control read deadline"))??;
        if let Some(event) = event {
            events
                .send(event)
                .await
                .map_err(|_| invalid("UDP control consumer closed"))?;
        }
    }
}
pub(crate) async fn write_control_frame_bound(
    writer: &mut (impl AsyncWrite + Unpin),
    kind: u8,
    body: &[u8],
    magic: [u8; 4],
) -> io::Result<()> {
    let length = u16::try_from(body.len()).map_err(|_| invalid("UDP control length"))?;
    let mut header = *b"L2UC\x01\0\0\0";
    header[..4].copy_from_slice(&magic);
    header[5] = kind;
    header[6..].copy_from_slice(&length.to_be_bytes());
    writer.write_all(&header).await?;
    writer.write_all(body).await?;
    writer.flush().await
}

#[cfg(test)]
mod tests;
