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
pub(super) async fn read_json<R: AsyncRead + Unpin, T: for<'a> Deserialize<'a>>(
    stream: &mut R,
    maximum: usize,
) -> io::Result<T> {
    let count = stream.read_u32().await? as usize;
    if count == 0 || count > maximum {
        return Err(invalid("local API message exceeds bound"));
    }
    let mut bytes = vec![0; count];
    stream.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes).map_err(|_| invalid("invalid local API JSON"))
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
