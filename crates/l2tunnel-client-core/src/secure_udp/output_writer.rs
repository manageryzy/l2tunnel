//! One persistent worker for a regular output description. All payload custody
//! (including the current partial line) shares the original four line permits.
use super::output::{MAX_BYTES, MAX_LINE, MAX_LINES, WRITE_BYTES, WRITE_CALLS};
use l2tunnel_runtime::initialization_timing::{Owner, Stage, Timing};
use std::{
    io::{self, Write},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
    },
    thread::{self, JoinHandle},
};

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Snapshot {
    pub pending_lines: usize,
    pub pending_bytes: usize,
    pub queue_bytes_high: u64,
    pub written_bytes: u64,
    pub write_errors: u64,
    pub broken_pipe: u64,
    pub would_block: u64,
    pub dropped_lines: u64,
    pub dropped_bytes: u64,
    pub disabled: bool,
}
#[derive(Default)]
struct Shared {
    lines: AtomicUsize,
    bytes: AtomicUsize,
    high: AtomicU64,
    written: AtomicU64,
    errors: AtomicU64,
    broken: AtomicU64,
    blocked: AtomicU64,
    dropped_lines: AtomicU64,
    dropped_bytes: AtomicU64,
    disabled: AtomicBool,
    closing: AtomicBool,
    stop: AtomicBool,
    grant: AtomicBool,
    exited: AtomicBool,
}
fn add(counter: &AtomicU64, value: u64) {
    let _old = counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
        Some(old.saturating_add(value))
    });
}
impl Shared {
    fn snapshot(&self) -> Snapshot {
        Snapshot {
            pending_lines: self.lines.load(Ordering::Acquire),
            pending_bytes: self.bytes.load(Ordering::Acquire),
            queue_bytes_high: self.high.load(Ordering::Acquire),
            written_bytes: self.written.load(Ordering::Acquire),
            write_errors: self.errors.load(Ordering::Acquire),
            broken_pipe: self.broken.load(Ordering::Acquire),
            would_block: self.blocked.load(Ordering::Acquire),
            dropped_lines: self.dropped_lines.load(Ordering::Acquire),
            dropped_bytes: self.dropped_bytes.load(Ordering::Acquire),
            disabled: self.disabled.load(Ordering::Acquire),
        }
    }
    fn release_line(&self, unwritten: usize) {
        if unwritten != 0 {
            self.bytes.fetch_sub(unwritten, Ordering::AcqRel);
            add(&self.dropped_bytes, unwritten as u64);
            add(&self.dropped_lines, 1);
        }
        self.lines.fetch_sub(1, Ordering::AcqRel);
    }
    fn fail(&self, kind: io::ErrorKind) {
        self.disabled.store(true, Ordering::Release);
        add(&self.errors, 1);
        if kind == io::ErrorKind::BrokenPipe {
            add(&self.broken, 1);
        }
    }
}

// Every reserved line releases its permit even if receiver teardown races
// admission. Rejected local submissions disarm this accounting before returning.
struct Line {
    bytes: Vec<u8>,
    offset: usize,
    shared: Arc<Shared>,
    retained: bool,
}
impl Line {
    fn rejected(mut self) -> Vec<u8> {
        self.shared
            .bytes
            .fetch_sub(self.bytes.len(), Ordering::AcqRel);
        self.shared.lines.fetch_sub(1, Ordering::AcqRel);
        self.retained = false;
        std::mem::take(&mut self.bytes)
    }
}
impl Drop for Line {
    fn drop(&mut self) {
        if self.retained && !thread::panicking() {
            self.shared.release_line(self.bytes.len() - self.offset);
        }
        // An unwinding writer may have made unreported partial progress. Its
        // bounded outstanding permits remain unresolved, never inferred dropped.
        // WorkerExit disables new admission before these destructors run.
    }
}

pub(super) enum Admission {
    Accepted,
    Full(Vec<u8>),
    Closed(Vec<u8>),
}
/// Not a Tokio blocking task: runtime shutdown must not wait for a stuck write.
pub(super) struct Handle {
    sender: SyncSender<Line>,
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}
impl Handle {
    pub(super) fn new<W: Write + Send + 'static>(writer: W) -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(MAX_LINES);
        let shared = Arc::new(Shared::default());
        let worker = Arc::clone(&shared);
        let thread = thread::Builder::new()
            .name("l2tunnel-log-writer".into())
            .spawn(move || run(writer, receiver, &worker))?;
        Ok(Self {
            sender,
            shared,
            thread: Some(thread),
        })
    }
    pub(super) fn snapshot(&self) -> Snapshot {
        // A panic cannot turn unfinished bytes into successful completion. No
        // join (including a supposedly completed join) is needed to observe it.
        if self.thread.as_ref().is_some_and(JoinHandle::is_finished)
            && !self.shared.exited.load(Ordering::Acquire)
            && !self.shared.disabled.swap(true, Ordering::AcqRel)
        {
            add(&self.shared.errors, 1);
        }
        self.shared.snapshot()
    }
    pub(super) fn enqueue(&mut self, line: Vec<u8>) -> Admission {
        if line.is_empty() || line.len() > MAX_LINE {
            return Admission::Full(line);
        }
        if self.shared.closing.load(Ordering::Acquire)
            || self.shared.disabled.load(Ordering::Acquire)
            || self.shared.exited.load(Ordering::Acquire)
        {
            return Admission::Closed(line);
        }
        if self
            .shared
            .lines
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_LINES).then_some(count + 1)
            })
            .is_err()
        {
            return Admission::Full(line);
        }
        let length = line.len();
        let before = self.shared.bytes.fetch_add(length, Ordering::AcqRel);
        if before
            .checked_add(length)
            .is_none_or(|bytes| bytes > MAX_BYTES)
        {
            self.shared.bytes.fetch_sub(length, Ordering::AcqRel);
            self.shared.lines.fetch_sub(1, Ordering::AcqRel);
            return Admission::Full(line);
        }
        self.shared
            .high
            .fetch_max((before + length) as u64, Ordering::AcqRel);
        // The line permit includes worker-owned storage, so the channel cannot
        // be an extra four-line staging queue. No channel lock spans file I/O.
        let line = Line {
            bytes: line,
            offset: 0,
            shared: Arc::clone(&self.shared),
            retained: true,
        };
        match self.sender.try_send(line) {
            Ok(()) => Admission::Accepted,
            Err(TrySendError::Full(line)) => Admission::Full(line.rejected()),
            Err(TrySendError::Disconnected(line)) => {
                self.shared.fail(io::ErrorKind::BrokenPipe);
                Admission::Closed(line.rejected())
            }
        }
    }
    pub(super) fn grant(&self) {
        self.shared.grant.store(true, Ordering::Release);
        if let Some(thread) = &self.thread {
            thread.thread().unpark();
        }
    }
    pub(super) fn close(&self) {
        self.shared.closing.store(true, Ordering::Release);
        if let Some(thread) = &self.thread {
            thread.thread().unpark();
        }
    }
    pub(super) fn stop(&self) {
        self.shared.closing.store(true, Ordering::Release);
        self.shared.stop.store(true, Ordering::Release);
        if let Some(thread) = &self.thread {
            thread.thread().unpark();
        }
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        self.stop();
        // Dropping JoinHandle detaches. A blocked kernel write remains bounded
        // unresolved custody until it returns or the process terminates.
        drop(self.thread.take());
    }
}

struct WorkerExit<'a>(&'a Shared);
impl Drop for WorkerExit<'_> {
    fn drop(&mut self) {
        if thread::panicking() && !self.0.disabled.swap(true, Ordering::AcqRel) {
            add(&self.0.errors, 1);
        }
        self.0.exited.store(true, Ordering::Release);
    }
}

fn run<W: Write>(mut writer: W, receiver: Receiver<Line>, shared: &Shared) {
    let mut timing = Timing::from_environment(Owner::CliWriter, tokio::time::Instant::now());
    let mut current: Option<Line> = None;
    // Declare after payload custody: unwinding marks failure before a Line's
    // destructor could make zero pending bytes appear to be successful drain.
    let _exit = WorkerExit(shared);
    loop {
        if shared.stop.load(Ordering::Acquire) {
            return;
        }
        if shared.closing.load(Ordering::Acquire) && shared.lines.load(Ordering::Acquire) == 0 {
            return;
        }
        if !shared.grant.swap(false, Ordering::AcqRel) {
            thread::park();
            continue;
        }
        let mut budget = WRITE_BYTES;
        for _ in 0..WRITE_CALLS {
            if shared.stop.load(Ordering::Acquire) || budget == 0 {
                break;
            }
            if current.is_none() {
                match receiver.try_recv() {
                    Ok(line) => current = Some(line),
                    Err(_) => break,
                }
            }
            let Some(line) = current.as_mut() else {
                break;
            };
            let end = line.bytes.len().min(line.offset.saturating_add(budget));
            match timing.measure_result(Stage::CliFileWrite, || {
                writer.write(&line.bytes[line.offset..end])
            }) {
                Ok(0) => {
                    shared.fail(io::ErrorKind::WriteZero);
                    return;
                }
                Ok(written) if written <= end - line.offset => {
                    line.offset += written;
                    budget -= written;
                    shared.bytes.fetch_sub(written, Ordering::AcqRel);
                    add(&shared.written, written as u64);
                    if line.offset == line.bytes.len() {
                        current = None;
                    }
                }
                Ok(_) => {
                    shared.fail(io::ErrorKind::InvalidData);
                    return;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    add(&shared.blocked, 1);
                    break;
                }
                Err(error) => {
                    shared.fail(error.kind());
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "output_writer_tests.rs"]
mod tests;
