//! Private stream between the native service host and its sole worker.
use super::{Action, COMMON_VERSION, Request, framing::*};
use crate::service::Handle;
use std::{io, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::time::timeout;

const FRAME_DEADLINE: Duration = Duration::from_secs(5);

/// Serve sequential lifecycle requests over handles inherited from a trusted
/// host. Clean EOF releases the worker. A malformed frame closes the channel.
pub async fn serve_private_common_stream(
    mut input: impl AsyncRead + Unpin,
    mut output: impl AsyncWrite + Unpin,
    handle: &Handle,
) -> io::Result<()> {
    let mut first = [0];
    while input.read(&mut first).await? != 0 {
        let mut frame = io::Cursor::new(first).chain(&mut input);
        let request: Request =
            timeout(FRAME_DEADLINE, read_json(&mut frame, REQUEST_LIMIT)).await??;
        if request.version != COMMON_VERSION
            || !matches!(
                request.action,
                Action::Status {} | Action::Reconnect {} | Action::Disconnect {}
            )
        {
            return Err(invalid("unsupported native host request"));
        }
        let response = handle.lifecycle_request(request).await;
        timeout(
            FRAME_DEADLINE,
            write_json(&mut output, &response, COMMON_RESPONSE_LIMIT),
        )
        .await??;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn long_lived_worker_preserves_frames_and_closes_on_eof() -> io::Result<()> {
        let (handle, _owner) = crate::service::channel();
        let request = Request {
            version: COMMON_VERSION,
            action: Action::Status {},
        };
        let mut input = Vec::new();
        for _ in 0..2 {
            write_json(&mut input, &request, REQUEST_LIMIT).await?;
        }
        let mut output = Vec::new();
        serve_private_common_stream(input.as_slice(), &mut output, &handle).await?;
        let mut frames = output.as_slice();
        for _ in 0..2 {
            let response: crate::local::Response =
                read_json(&mut frames, COMMON_RESPONSE_LIMIT).await?;
            assert_eq!(response.version, COMMON_VERSION);
            assert_eq!(response.code, "unsupported_version");
        }
        assert!(frames.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn malformed_or_truncated_frames_terminate_without_mutation() {
        let (handle, _owner) = crate::service::channel();
        for bytes in [
            &[0_u8][..],
            &[0, 0, 0, 0],
            &[0, 0, 32, 0],
            &[0, 0, 0, 2, b'{', b'}'],
        ] {
            let mut output = Vec::new();
            assert!(
                serve_private_common_stream(bytes, &mut output, &handle)
                    .await
                    .is_err()
            );
            assert!(output.is_empty());
        }
    }
}
