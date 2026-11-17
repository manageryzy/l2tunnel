//! Explicit process-scoped stdin control, isolated from service and native owners.
use std::{
    io::{self, Read},
    thread,
};
use tokio::sync::mpsc;

const QUEUED_COMMANDS: usize = 4;
const READ_BYTES: usize = 256;
const LINE_BYTES: usize = 32;

/// Strict local frontend verbs; no Windows Common service executor is installed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    /// Observe actual service state.
    Status,
    /// Abort the current generation and remain idle.
    Disconnect,
    /// Create a fresh generation using the retained explicit configuration.
    Reconnect,
}

/// Bounded typed commands. Closure means EOF or that the input worker ended.
pub type Receiver = mpsc::Receiver<io::Result<Command>>;

/// Claim standard input once for this process and start its isolated reader.
///
/// Safe standard input reads cannot be forcibly cancelled. The worker owns only
/// stdin, bounded parser buffers and the command sender. Dropping the receiver
/// releases channel backpressure, but a blocked stdin read can remain until new
/// input or process exit. It holds no device, service or credential state and
/// is deliberately never joined by tunnel shutdown. Reusable library callers
/// must inject a receiver instead of creating another process stdin reader.
#[cfg(windows)]
pub fn stdin() -> io::Result<Receiver> {
    use std::sync::atomic::{AtomicBool, Ordering};
    static CLAIMED: AtomicBool = AtomicBool::new(false);
    CLAIMED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "foreground stdin control was already claimed in this process",
            )
        })?;
    match reader(io::stdin()) {
        Ok(receiver) => Ok(receiver),
        Err(error) => {
            // Thread creation failed before any reader could consume stdin.
            CLAIMED.store(false, Ordering::Release);
            Err(error)
        }
    }
}

/// Start a bounded command reader over explicitly supplied input.
/// This parses commands only; the caller must supply a service executor.
pub fn reader(reader: impl Read + Send + 'static) -> io::Result<Receiver> {
    let (sender, receiver) = mpsc::channel(QUEUED_COMMANDS);
    let worker = thread::Builder::new()
        .name("l2tunnel-stdin-control".into())
        .spawn(move || read_commands(reader, sender))?;
    // No tunnel owner or lifecycle future is captured by this input-only task.
    drop(worker);
    Ok(receiver)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn parse(line: &[u8]) -> io::Result<Command> {
    match line.strip_suffix(b"\r").unwrap_or(line) {
        b"status" => Ok(Command::Status),
        b"disconnect" => Ok(Command::Disconnect),
        b"reconnect" => Ok(Command::Reconnect),
        _ => Err(invalid(
            "control input requires status, disconnect or reconnect as an exact LF/CRLF line",
        )),
    }
}

fn read_commands(mut reader: impl Read, sender: mpsc::Sender<io::Result<Command>>) {
    let mut input = [0_u8; READ_BYTES];
    let mut line = [0_u8; LINE_BYTES];
    let mut used = 0;
    while !sender.is_closed() {
        let count = match reader.read(&mut input) {
            Ok(0) => {
                if used != 0 {
                    let _ = sender.blocking_send(Err(invalid(
                        "control input ended before a complete LF/CRLF line",
                    )));
                }
                return;
            }
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                let _ = sender.blocking_send(Err(io::Error::new(
                    error.kind(),
                    "control input could not be read",
                )));
                return;
            }
        };
        let Some(bytes) = input.get(..count) else {
            let _ = sender.blocking_send(Err(invalid("control reader returned an invalid length")));
            return;
        };
        for &byte in bytes {
            if byte == b'\n' {
                let command = parse(&line[..used]);
                let failed = command.is_err();
                if sender.blocking_send(command).is_err() || failed {
                    return;
                }
                used = 0;
            } else {
                if !byte.is_ascii() || used == LINE_BYTES {
                    let _ = sender.blocking_send(Err(invalid(
                        "control input must be ASCII and at most 32 bytes before LF",
                    )));
                    return;
                }
                line[used] = byte;
                used += 1;
            }
        }
    }
}

#[cfg(test)]
#[path = "input_tests.rs"]
mod tests;
