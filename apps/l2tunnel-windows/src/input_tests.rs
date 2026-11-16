//! Bounded stdin parser/worker contracts; no Windows console or device evidence.
use super::*;
use std::{io::Cursor, sync::mpsc as sync, time::Duration};
use tokio::time::timeout;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
const WAIT: Duration = Duration::from_secs(3);

struct Fragmented {
    bytes: Cursor<Vec<u8>>,
    interrupted: bool,
}
impl Read for Fragmented {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if !self.interrupted {
            self.interrupted = true;
            return Err(io::ErrorKind::Interrupted.into());
        }
        assert_eq!(buffer.len(), READ_BYTES);
        self.bytes.read(&mut buffer[..1])
    }
}

#[tokio::test]
async fn fragmented_commands_crlf_and_interrupted_read_preserve_order() -> TestResult {
    let mut input = reader(Fragmented {
        bytes: Cursor::new(b"status\r\ndisconnect\nreconnect\r\n".to_vec()),
        interrupted: false,
    })?;
    assert_eq!(input.max_capacity(), QUEUED_COMMANDS);
    for expected in [Command::Status, Command::Disconnect, Command::Reconnect] {
        let command = timeout(WAIT, input.recv())
            .await?
            .ok_or("missing command")??;
        assert_eq!(command, expected);
    }
    assert!(timeout(WAIT, input.recv()).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn malformed_and_incomplete_input_fail_closed_without_echoing_bytes() -> TestResult {
    for bytes in [
        b"\n".to_vec(),
        b"\r\n".to_vec(),
        b"Status\n".to_vec(),
        b" status\n".to_vec(),
        b"status \n".to_vec(),
        b"status\0\n".to_vec(),
        b"status\r\r\n".to_vec(),
        b"status".to_vec(),
        b"status\r".to_vec(),
        b"secret-not-a-command\nstatus\n".to_vec(),
        vec![0xff, b'\n'],
    ] {
        let mut input = reader(Cursor::new(bytes))?;
        let error = timeout(WAIT, input.recv())
            .await?
            .ok_or("missing error")?
            .err()
            .ok_or("invalid input was accepted")?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(!error.to_string().contains("secret-not-a-command"));
        assert!(timeout(WAIT, input.recv()).await?.is_none());
    }
    let mut empty = reader(Cursor::new(Vec::<u8>::new()))?;
    assert!(timeout(WAIT, empty.recv()).await?.is_none());
    Ok(())
}

struct Counted {
    bytes: Cursor<Vec<u8>>,
    finished: sync::Sender<u64>,
}
impl Read for Counted {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        assert_eq!(buffer.len(), READ_BYTES);
        self.bytes.read(&mut buffer[..1])
    }
}
impl Drop for Counted {
    fn drop(&mut self) {
        let _ = self.finished.send(self.bytes.position());
    }
}

#[tokio::test]
async fn exact_line_bound_has_fixed_storage_and_oversize_stops_at_first_excess() -> TestResult {
    for length in [LINE_BYTES, LINE_BYTES + 1] {
        let (finished, stopped) = sync::channel();
        let mut bytes = vec![b'x'; length];
        bytes.extend_from_slice(b"\nstatus\n");
        let mut input = reader(Counted {
            bytes: Cursor::new(bytes),
            finished,
        })?;
        let error = timeout(WAIT, input.recv())
            .await?
            .ok_or("missing bounded-input error")?
            .err()
            .ok_or("oversized or unknown command accepted")?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(timeout(WAIT, input.recv()).await?.is_none());
        assert_eq!(stopped.recv_timeout(WAIT)?, (LINE_BYTES + 1) as u64);
    }
    Ok(())
}

struct Commands {
    reads: sync::Sender<()>,
    finished: sync::Sender<()>,
}
impl Read for Commands {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.reads.send(()).map_err(io::Error::other)?;
        buffer[..7].copy_from_slice(b"status\n");
        Ok(7)
    }
}
impl Drop for Commands {
    fn drop(&mut self) {
        let _ = self.finished.send(());
    }
}

#[test]
fn full_queue_stops_input_and_dropped_receiver_releases_channel_wait() -> TestResult {
    let (reads, observed) = sync::channel();
    let (finished, stopped) = sync::channel();
    let input = reader(Commands { reads, finished })?;
    // Four accepted commands fill the queue; the fifth is held by the reader.
    for _ in 0..=QUEUED_COMMANDS {
        observed.recv_timeout(WAIT)?;
    }
    assert_eq!(input.capacity(), 0);
    let read_ahead = observed.recv_timeout(Duration::from_millis(50)).is_ok();
    drop(input);
    stopped.recv_timeout(WAIT)?;
    assert!(!read_ahead);
    Ok(())
}

struct Stalled {
    entered: Option<sync::Sender<()>>,
    release: sync::Receiver<()>,
    finished: sync::Sender<()>,
}
impl Read for Stalled {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        if let Some(entered) = self.entered.take() {
            entered.send(()).map_err(io::Error::other)?;
        }
        self.release.recv().map_err(io::Error::other)?;
        Ok(0)
    }
}
impl Drop for Stalled {
    fn drop(&mut self) {
        let _ = self.finished.send(());
    }
}

#[test]
fn dropping_receiver_does_not_wait_for_blocked_input_only_worker() -> TestResult {
    let (entered, started) = sync::channel();
    let (release, resume) = sync::channel();
    let (finished, stopped) = sync::channel();
    let input = reader(Stalled {
        entered: Some(entered),
        release: resume,
        finished,
    })?;
    started.recv_timeout(WAIT)?;
    let (returned, completion) = sync::channel();
    let caller = thread::spawn(move || {
        drop(input);
        let _ = returned.send(());
    });
    completion.recv_timeout(WAIT)?;
    release.send(())?;
    stopped.recv_timeout(WAIT)?;
    caller.join().map_err(|_| "input drop caller panicked")?;
    Ok(())
}

struct Failing;
impl Read for Failing {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private-input-error-fixture",
        ))
    }
}

#[tokio::test]
async fn read_failure_keeps_kind_but_does_not_copy_provider_text() -> TestResult {
    let mut input = reader(Failing)?;
    let error = timeout(WAIT, input.recv())
        .await?
        .ok_or("missing read error")?
        .err()
        .ok_or("read error accepted")?;
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(error.to_string(), "control input could not be read");
    assert!(timeout(WAIT, input.recv()).await?.is_none());
    Ok(())
}
