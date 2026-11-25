//! Shared length-delimited local API frames.
use super::COMMON_VERSION;
use serde::{Deserialize, Serialize};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(super) const REQUEST_LIMIT: usize = 4096;
pub(super) const RESPONSE_LIMIT: usize = 8192;
pub(super) const COMMON_RESPONSE_LIMIT: usize = 32768;
pub(super) fn response_limit(version: u16) -> usize {
    if version == COMMON_VERSION {
        COMMON_RESPONSE_LIMIT
    } else {
        RESPONSE_LIMIT
    }
}
pub(super) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
pub(super) async fn read_frame<R: AsyncRead + Unpin>(
    stream: &mut R,
    maximum: usize,
) -> io::Result<Vec<u8>> {
    let count = stream.read_u32().await? as usize;
    if count == 0 || count > maximum {
        return Err(invalid("local API message exceeds bound"));
    }
    let mut bytes = vec![0; count];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}
pub(super) async fn read_json<R: AsyncRead + Unpin, T: for<'a> Deserialize<'a>>(
    stream: &mut R,
    maximum: usize,
) -> io::Result<T> {
    let bytes = read_frame(stream, maximum).await?;
    serde_json::from_slice(&bytes).map_err(|_| invalid("invalid local API JSON"))
}
/// A decoded request of any version this transport understands.
#[cfg_attr(not(any(unix, windows)), allow(dead_code))]
pub(super) enum Incoming {
    Legacy(super::Request),
    Operations(super::OperationRequest),
}
/// Decode the version first, then the strict typed request for that version.
/// Unknown versions and malformed bodies yield None (closed without reply).
#[cfg_attr(not(any(unix, windows)), allow(dead_code))]
pub(super) fn decode_request(bytes: &[u8]) -> Option<Incoming> {
    #[derive(Deserialize)]
    struct Probe {
        version: u16,
    }
    let probe: Probe = serde_json::from_slice(bytes).ok()?;
    if probe.version == super::OPERATIONS_VERSION {
        serde_json::from_slice(bytes).ok().map(Incoming::Operations)
    } else if super::supported_version(probe.version) {
        serde_json::from_slice(bytes).ok().map(Incoming::Legacy)
    } else {
        None
    }
}
pub(super) async fn write_json<W: AsyncWrite + Unpin, T: Serialize>(
    stream: &mut W,
    value: &T,
    maximum: usize,
) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(invalid("local API reply exceeds bound"));
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await
}
