//! Bounded file diagnostics and Windows Event Log reporter (`CL-27`).
//!
//! Ensures an installed LocalSystem Windows service (which has no console)
//! always records startup, recovery, and error diagnostics in both Windows Event
//! Viewer (`Application` log, source `"l2tunnel"`) and a bounded rotating
//! `<state-dir>/service.log` file (max 2 MiB, never logging private secrets).
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum size of the active service log file before single-backup rotation.
pub const MAX_LOG_BYTES: u64 = 2 * 1024 * 1024;
/// Maximum length of one formatted log line.
const MAX_MESSAGE_CHARS: usize = 512;

/// Severity level for service diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Level {
    /// Informational lifecycle milestone.
    Info,
    /// Recoverable anomaly or warning.
    Warning,
    /// Failure requiring operator attention.
    Error,
}

impl Level {
    fn tag(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Warning => "WARN",
            Self::Error => "ERROR",
        }
    }
}

/// Thread-safe bounded service logger writing to an optional file and Windows Event Log.
pub struct ServiceLogger {
    source: String,
    file: Option<PathBuf>,
    lock: Mutex<()>,
}

impl ServiceLogger {
    /// Create a logger using Windows Event Log `source` and optional rotating log file.
    pub fn new(source: impl Into<String>, file: Option<PathBuf>) -> Self {
        Self {
            source: source.into(),
            file,
            lock: Mutex::new(()),
        }
    }

    /// Record an informational event.
    pub fn info(&self, message: &str) {
        self.log(Level::Info, message);
    }

    /// Record a warning event.
    pub fn warn(&self, message: &str) {
        self.log(Level::Warning, message);
    }

    /// Record an error event.
    pub fn error(&self, message: &str) {
        self.log(Level::Error, message);
    }

    /// Record one bounded message to the rotating log file and (on Windows) Event Log.
    pub fn log(&self, level: Level, message: &str) {
        let bounded = sanitize_message(message);
        if let Some(path) = &self.file {
            let _guard = self.lock.lock();
            let _ = append_bounded_line(path, level, &bounded);
        }
        #[cfg(windows)]
        {
            ffi::report_event(&self.source, level, &bounded);
        }
        #[cfg(not(windows))]
        {
            let _ = &self.source;
        }
    }
}

fn sanitize_message(message: &str) -> String {
    let mut clean: String = message
        .chars()
        .map(|c| {
            if c == '\r' || c == '\n' || c == '\0' {
                ' '
            } else {
                c
            }
        })
        .take(MAX_MESSAGE_CHARS)
        .collect();
    if clean.is_empty() {
        clean.push_str("(empty)");
    }
    clean
}

fn append_bounded_line(path: &Path, level: Level, message: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(meta) = std::fs::metadata(path)
        && meta.len() >= MAX_LOG_BYTES
    {
        let backup = path.with_extension("log.1");
        let _ = std::fs::remove_file(&backup);
        let _ = std::fs::rename(path, &backup);
    }
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "[{ts}] [{}] {message}", level.tag())
}

/// Show a native Windows error dialog (`MessageBoxW`) for GUI startup failures
/// when running under `windows_subsystem = "windows"` without a console.
/// No-op on non-Windows targets.
pub fn show_error_dialog(title: &str, message: &str) {
    #[cfg(windows)]
    {
        ffi::message_box_error(title, message);
    }
    #[cfg(not(windows))]
    {
        let _ = (title, message);
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod ffi {
    #![deny(clippy::undocumented_unsafe_blocks)]

    use super::Level;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::System::EventLog::{
        DeregisterEventSource, EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE,
        EVENTLOG_WARNING_TYPE, RegisterEventSourceW, ReportEventW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};

    pub(super) fn message_box_error(title: &str, message: &str) {
        let wide_title: Vec<u16> = OsStr::new(title).encode_wide().chain(Some(0)).collect();
        let wide_msg: Vec<u16> = OsStr::new(message).encode_wide().chain(Some(0)).collect();
        // SAFETY: `wide_title` and `wide_msg` are NUL-terminated UTF-16 buffers alive
        // for the duration of `MessageBoxW`; null HWND creates a top-level dialog.
        unsafe {
            let _ = MessageBoxW(
                null_mut(),
                wide_msg.as_ptr(),
                wide_title.as_ptr(),
                MB_OK | MB_ICONERROR,
            );
        }
    }

    pub(super) fn report_event(source: &str, level: Level, message: &str) {
        let wide_src: Vec<u16> = OsStr::new(source).encode_wide().chain(Some(0)).collect();
        // SAFETY: `wide_src` is NUL-terminated UTF-16; null server name selects local computer.
        let handle = unsafe { RegisterEventSourceW(null(), wide_src.as_ptr()) };
        if handle.is_null() {
            return;
        }
        let wide_msg: Vec<u16> = OsStr::new(message).encode_wide().chain(Some(0)).collect();
        let strings = [wide_msg.as_ptr()];
        let event_type = match level {
            Level::Info => EVENTLOG_INFORMATION_TYPE,
            Level::Warning => EVENTLOG_WARNING_TYPE,
            Level::Error => EVENTLOG_ERROR_TYPE,
        };
        let event_id = match level {
            Level::Info => 1001,
            Level::Warning => 2001,
            Level::Error => 3001,
        };
        // SAFETY: `handle` is live and `strings` points to one valid NUL-terminated UTF-16 string.
        unsafe {
            let _ = ReportEventW(
                handle,
                event_type,
                0,
                event_id,
                null_mut(),
                1,
                0,
                strings.as_ptr(),
                null(),
            );
            let _ = DeregisterEventSource(handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logger_sanitizes_and_writes_bounded_lines() -> std::io::Result<()> {
        let path = std::env::temp_dir().join(format!("l2t-win-log-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let logger = ServiceLogger::new("l2tunnel", Some(path.clone()));
        logger.info("service started\nwith newline");
        logger.warn("reconnecting");
        logger.error("boom");
        let text = std::fs::read_to_string(&path)?;
        let _ = std::fs::remove_file(&path);
        assert!(text.contains("[INFO] service started with newline"));
        assert!(text.contains("[WARN] reconnecting"));
        assert!(text.contains("[ERROR] boom"));
        Ok(())
    }
}
