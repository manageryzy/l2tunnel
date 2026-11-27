//! Debounced, sliding-window rate-limited Windows network-change and
//! sleep/resume reconnect coordinator (`CL-27`).
//!
//! Mirrors Android's `NetworkChangeCoordinator`: coalesces rapid interface
//! notifications (1.5 s debounce) and caps automatic reconnect triggers at
//! 6 per 5-minute sliding window so flaky Wi-Fi/VPN transitions never spin.
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Default coalesce debounce window.
pub const DEFAULT_DEBOUNCE: Duration = Duration::from_millis(1_500);
/// Default sliding window for trigger rate limiting.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(300);
/// Maximum reconnect triggers emitted inside [`DEFAULT_WINDOW`].
pub const DEFAULT_MAX_TRIGGERS: usize = 6;

/// Pure deterministic rate-limiter for network/power transition triggers.
#[derive(Debug)]
pub struct TransitionLimiter {
    debounce: Duration,
    window: Duration,
    max_triggers: usize,
    last_event: Option<Instant>,
    recent_triggers: VecDeque<Instant>,
}

impl Default for TransitionLimiter {
    fn default() -> Self {
        Self::new(DEFAULT_DEBOUNCE, DEFAULT_WINDOW, DEFAULT_MAX_TRIGGERS)
    }
}

impl TransitionLimiter {
    /// Create a limiter with explicit debounce, sliding window, and cap.
    pub fn new(debounce: Duration, window: Duration, max_triggers: usize) -> Self {
        Self {
            debounce,
            window,
            max_triggers: max_triggers.max(1),
            last_event: None,
            recent_triggers: VecDeque::new(),
        }
    }

    /// Record a raw OS transition notification (interface change or power resume).
    pub fn note_event(&mut self, now: Instant) {
        self.last_event = Some(now);
    }

    /// Returns true once the debounce interval has elapsed since the latest event
    /// and the sliding-window budget permits emitting a reconnect trigger.
    pub fn poll_trigger(&mut self, now: Instant) -> bool {
        let Some(last) = self.last_event else {
            return false;
        };
        if now.saturating_duration_since(last) < self.debounce {
            return false;
        }
        self.last_event = None;
        while let Some(&front) = self.recent_triggers.front() {
            if now.saturating_duration_since(front) >= self.window {
                self.recent_triggers.pop_front();
            } else {
                break;
            }
        }
        if self.recent_triggers.len() >= self.max_triggers {
            return false;
        }
        self.recent_triggers.push_back(now);
        true
    }
}

/// Active Windows IP interface change subscription. Dropping cancels it cleanly.
#[cfg(windows)]
pub struct InterfaceWatcher {
    _inner: ffi::WatchGuard,
}

/// RAII guard requesting 1 ms Windows multimedia timer resolution
/// (`timeBeginPeriod(1)` / `timeEndPeriod(1)`) so Tokio/Wintun polling and
/// protocol ACK/RTO timers are not quantized to Windows' default 15.6 ms tick.
#[cfg(windows)]
pub struct HighResTimerGuard {
    _inner: ffi::TimerGuard,
}

#[cfg(windows)]
impl HighResTimerGuard {
    /// Request 1 ms Windows system timer resolution until this guard is dropped.
    pub fn acquire() -> Self {
        Self {
            _inner: ffi::TimerGuard::acquire(),
        }
    }
}

#[cfg(windows)]
impl InterfaceWatcher {
    /// Start watching IPv4/IPv6 interface changes via `NotifyIpInterfaceChange`.
    /// Each change sends `Some(if_index)` (or `None` when the OS passes a null row)
    /// onto `tx` without blocking, so callers can ignore changes belonging to
    /// their own Wintun tunnel adapter.
    pub fn start(tx: tokio::sync::mpsc::UnboundedSender<Option<u32>>) -> std::io::Result<Self> {
        Ok(Self {
            _inner: ffi::WatchGuard::start(tx)?,
        })
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod ffi {
    #![deny(clippy::undocumented_unsafe_blocks)]

    use std::ffi::c_void;
    use std::io;
    use std::ptr::null_mut;
    use tokio::sync::mpsc::UnboundedSender;
    use windows_sys::Win32::Foundation::{HANDLE, NO_ERROR};
    use windows_sys::Win32::Media::{timeBeginPeriod, timeEndPeriod};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        CancelMibChangeNotify2, MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE, NotifyIpInterfaceChange,
    };
    use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

    pub(super) struct TimerGuard {
        active: bool,
    }

    impl TimerGuard {
        pub(super) fn acquire() -> Self {
            // SAFETY: `timeBeginPeriod(1)` has no pointer arguments and is paired
            // with `timeEndPeriod(1)` in `Drop` when it returns `TIMERR_NOERROR` (0).
            let rc = unsafe { timeBeginPeriod(1) };
            Self { active: rc == 0 }
        }
    }

    impl Drop for TimerGuard {
        fn drop(&mut self) {
            if self.active {
                // SAFETY: matches the preceding successful `timeBeginPeriod(1)`.
                unsafe {
                    let _ = timeEndPeriod(1);
                }
            }
        }
    }

    pub(super) struct WatchGuard {
        handle: HANDLE,
        context: *mut UnboundedSender<Option<u32>>,
    }

    // SAFETY: `WatchGuard` owns both the Win32 notification handle and the
    // heap-allocated `UnboundedSender<Option<u32>>` (which is `Send + Sync`),
    // cancelling the notification before freeing `context` in `Drop`.
    unsafe impl Send for WatchGuard {}

    unsafe extern "system" fn on_change(
        caller_context: *const c_void,
        row: *const MIB_IPINTERFACE_ROW,
        _notification_type: MIB_NOTIFICATION_TYPE,
    ) {
        if !caller_context.is_null() {
            let if_index = if !row.is_null() {
                // SAFETY: when non-null, `row` is provided by Windows IP Helper for
                // the duration of this callback.
                let idx = unsafe { (*row).InterfaceIndex };
                Some(idx)
            } else {
                None
            };
            // SAFETY: `caller_context` is alive until `CancelMibChangeNotify2` returns in `Drop`.
            let tx = unsafe { &*(caller_context.cast::<UnboundedSender<Option<u32>>>()) };
            let _ = tx.send(if_index);
        }
    }

    impl WatchGuard {
        pub(super) fn start(tx: UnboundedSender<Option<u32>>) -> io::Result<Self> {
            let boxed = Box::into_raw(Box::new(tx));
            let mut handle: HANDLE = null_mut();
            // SAFETY: `on_change` matches `PIPINTERFACE_CHANGE_CALLBACK` and `boxed`
            // remains valid until `CancelMibChangeNotify2` completes in `Drop`.
            let rc = unsafe {
                NotifyIpInterfaceChange(
                    AF_UNSPEC,
                    Some(on_change),
                    boxed.cast::<c_void>(),
                    false,
                    &mut handle,
                )
            };
            if rc != NO_ERROR {
                // SAFETY: registration failed so no callback can reference `boxed`.
                unsafe { drop(Box::from_raw(boxed)) };
                return Err(io::Error::from_raw_os_error(rc as i32));
            }
            Ok(Self {
                handle,
                context: boxed,
            })
        }
    }

    impl Drop for WatchGuard {
        fn drop(&mut self) {
            if !self.handle.is_null() {
                // SAFETY: `CancelMibChangeNotify2` waits for any running callback
                // to finish before returning, after which `self.context` is unreferenced.
                unsafe {
                    let _ = CancelMibChangeNotify2(self.handle);
                }
            }
            if !self.context.is_null() {
                // SAFETY: `self.context` was allocated by `Box::into_raw` and is freed once.
                unsafe { drop(Box::from_raw(self.context)) };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debounce_and_sliding_window_cap() {
        let mut lim =
            TransitionLimiter::new(Duration::from_millis(500), Duration::from_secs(60), 2);
        let t0 = Instant::now();
        lim.note_event(t0);
        assert!(!lim.poll_trigger(t0 + Duration::from_millis(200)));
        // A second rapid event resets the debounce timer.
        lim.note_event(t0 + Duration::from_millis(300));
        assert!(!lim.poll_trigger(t0 + Duration::from_millis(600)));
        assert!(lim.poll_trigger(t0 + Duration::from_millis(900)));
        // Second trigger within window succeeds.
        lim.note_event(t0 + Duration::from_secs(2));
        assert!(lim.poll_trigger(t0 + Duration::from_secs(3)));
        // Third trigger within window is capped.
        lim.note_event(t0 + Duration::from_secs(4));
        assert!(!lim.poll_trigger(t0 + Duration::from_secs(5)));
        // After the sliding window expires, triggering resumes.
        lim.note_event(t0 + Duration::from_secs(65));
        assert!(lim.poll_trigger(t0 + Duration::from_secs(66)));
    }
}
