//! Bounded best-effort text diagnostics, independent of native and service owners.
use std::{
    io::{self, Write},
    sync::mpsc::{self, Receiver, SyncSender},
    thread,
};

const QUEUED_MESSAGES: usize = 8;
const MAX_MESSAGE_BYTES: usize = 2048;

/// Nonblocking admission to a text-only writer with eight bounded pending records.
///
/// The worker can hold one additional record while its output is blocked. It
/// owns only the text receiver and output stream, never a device, service handle,
/// credential or cancellation source. Dropping this sender closes admission;
/// it deliberately does not join a potentially blocked console writer. The
/// detached diagnostics thread therefore cannot delay native owner release.
/// This best-effort sink is not the pending CL-27 Windows event-log facility.
pub struct Diagnostics {
    sender: SyncSender<String>,
}

impl Diagnostics {
    /// Start the dedicated stderr writer without transferring runtime ownership.
    #[cfg(windows)]
    pub fn stderr() -> io::Result<Self> {
        Self::writer(io::stderr())
    }

    /// Start a bounded text-only writer over an explicitly supplied output.
    pub fn writer(writer: impl Write + Send + 'static) -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(QUEUED_MESSAGES);
        let worker = thread::Builder::new()
            .name("l2tunnel-diagnostics".into())
            .spawn(move || write_messages(writer, receiver))?;
        // A blocked output must never become part of device/service shutdown.
        drop(worker);
        Ok(Self { sender })
    }

    /// Try to admit one already-sanitized message without waiting for output.
    ///
    /// Returns false for a full/closed queue or a record over 2048 UTF-8 bytes.
    /// Rejection never prints the record or an output error. The caller must
    /// supply only bounded non-secret status, never credentials or payloads.
    pub fn emit(&self, message: String) -> bool {
        if message.len() > MAX_MESSAGE_BYTES {
            return false;
        }
        self.sender.try_send(message).is_ok()
    }
}

fn write_messages(mut writer: impl Write, receiver: Receiver<String>) {
    while let Ok(message) = receiver.recv() {
        if writer.write_all(message.as_bytes()).is_err()
            || writer.write_all(b"\n").is_err()
            || writer.flush().is_err()
        {
            break;
        }
    }
    // Close admission before dropping the writer, including its test observers.
    drop(receiver);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::mpsc::Sender, time::Duration};

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
    const WAIT: Duration = Duration::from_secs(3);

    struct Capture {
        bytes: Vec<u8>,
        finished: Sender<Vec<u8>>,
    }

    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Drop for Capture {
        fn drop(&mut self) {
            let _ = self.finished.send(std::mem::take(&mut self.bytes));
        }
    }

    struct Stalled {
        entered: Option<Sender<()>>,
        release: Receiver<()>,
        capture: Capture,
    }

    impl Write for Stalled {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if let Some(entered) = self.entered.take() {
                entered.send(()).map_err(io::Error::other)?;
                self.release.recv().map_err(io::Error::other)?;
            }
            self.capture.write(bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.capture.flush()
        }
    }

    #[test]
    fn stalled_writer_bounds_admission_and_never_blocks_sender_drop() -> TestResult {
        let (entered, started) = mpsc::channel();
        let (release, resume) = mpsc::channel();
        let (finished, output) = mpsc::channel();
        let diagnostics = Diagnostics::writer(Stalled {
            entered: Some(entered),
            release: resume,
            capture: Capture {
                bytes: Vec::new(),
                finished,
            },
        })?;
        assert!(diagnostics.emit("active-record".into()));
        started.recv_timeout(WAIT)?;
        // A separate caller makes a regression that joins the stalled worker
        // fail with a finite timeout instead of hanging the test runner.
        let (returned, completion) = mpsc::channel();
        let caller = thread::spawn(move || {
            let accepted = (0..QUEUED_MESSAGES)
                .filter(|index| diagnostics.emit(format!("queued-{index}")))
                .count();
            let overflow = diagnostics.emit("overflow-not-logged".into());
            drop(diagnostics);
            let _ = returned.send((accepted, overflow));
        });
        assert_eq!(completion.recv_timeout(WAIT)?, (QUEUED_MESSAGES, false));
        release.send(())?;
        let bytes = output.recv_timeout(WAIT)?;
        caller
            .join()
            .map_err(|_| io::Error::other("diagnostics test caller failed"))?;
        let expected = std::iter::once("active-record".to_owned())
            .chain((0..QUEUED_MESSAGES).map(|index| format!("queued-{index}")))
            .map(|message| format!("{message}\n"))
            .collect::<String>();
        assert_eq!(bytes, expected.as_bytes());
        Ok(())
    }

    struct Failing {
        on_flush: bool,
        finished: Sender<()>,
    }

    impl Write for Failing {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.on_flush {
                Ok(bytes.len())
            } else {
                Err(io::ErrorKind::BrokenPipe.into())
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
    }

    impl Drop for Failing {
        fn drop(&mut self) {
            let _ = self.finished.send(());
        }
    }

    #[test]
    fn output_errors_close_admission_without_becoming_caller_errors() -> TestResult {
        for on_flush in [false, true] {
            let (finished, stopped) = mpsc::channel();
            let diagnostics = Diagnostics::writer(Failing { on_flush, finished })?;
            assert!(diagnostics.emit("status-fixture".into()));
            stopped.recv_timeout(WAIT)?;
            assert!(!diagnostics.emit("closed-not-logged".into()));
            drop(diagnostics);
        }
        Ok(())
    }

    #[test]
    fn size_limits_count_utf8_bytes_and_reject_without_partial_output() -> TestResult {
        let (finished, output) = mpsc::channel();
        let diagnostics = Diagnostics::writer(Capture {
            bytes: Vec::new(),
            finished,
        })?;
        let ascii = "a".repeat(MAX_MESSAGE_BYTES);
        let unicode = "é".repeat(MAX_MESSAGE_BYTES / 2);
        assert!(diagnostics.emit(ascii.clone()));
        assert!(diagnostics.emit(unicode.clone()));
        assert!(!diagnostics.emit(format!("{ascii}a")));
        assert!(!diagnostics.emit(format!("{unicode}a")));
        drop(diagnostics);
        assert_eq!(
            output.recv_timeout(WAIT)?,
            format!("{ascii}\n{unicode}\n").into_bytes()
        );
        Ok(())
    }
}
