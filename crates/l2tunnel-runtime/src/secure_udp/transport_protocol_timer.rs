//! Runtime actuator for sub-millisecond packing and recovery deadlines.
use tokio::time::{Instant, sleep_until};

#[derive(Default)]
pub(super) struct Timer {
    #[cfg(target_os = "linux")]
    linux: linux::ShortTimer,
}

impl Timer {
    pub(super) async fn wait_until(&mut self, deadline: Instant) {
        #[cfg(target_os = "linux")]
        {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return;
            }
            if remaining <= std::time::Duration::from_millis(1) {
                tokio::select! {
                    result = self.linux.expiry(deadline) => {
                        // A test runtime can suspend its logical clock.
                        if result.is_ok() && Instant::now() >= deadline {
                            return;
                        }
                    }
                    () = sleep_until(deadline) => return,
                }
            }
        }
        sleep_until(deadline).await;
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use rustix::time::{
        Itimerspec, TimerfdClockId, TimerfdFlags, TimerfdTimerFlags, Timespec, timerfd_create,
        timerfd_settime,
    };
    use std::{cell::OnceCell, io, os::fd::OwnedFd};
    use tokio::{
        io::{Interest, unix::AsyncFd},
        time::Instant,
    };

    #[derive(Default)]
    pub(super) struct ShortTimer {
        fd: OnceCell<io::Result<AsyncFd<OwnedFd>>>,
        armed: Option<Instant>,
    }

    impl ShortTimer {
        pub(super) async fn expiry(&mut self, deadline: Instant) -> io::Result<()> {
            let fd = self
                .fd
                .get_or_init(|| {
                    AsyncFd::with_interest(
                        timerfd_create(
                            TimerfdClockId::Monotonic,
                            TimerfdFlags::CLOEXEC | TimerfdFlags::NONBLOCK,
                        )?,
                        Interest::READABLE,
                    )
                })
                .as_ref()
                .map_err(|e| io::Error::from(e.kind()))?;
            if self.armed != Some(deadline) {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Ok(());
                }
                let value = Timespec::try_from(remaining).map_err(io::Error::other)?;
                timerfd_settime(
                    fd.get_ref(),
                    TimerfdTimerFlags::empty(),
                    &Itimerspec {
                        it_interval: Timespec::default(),
                        it_value: value,
                    },
                )?;
                self.armed = Some(deadline);
            }
            // A competing native or carrier event can cancel the wait. Reuse
            // the same armed descriptor if its absolute deadline is unchanged.
            fd.async_io(Interest::READABLE, |timer| {
                rustix::io::read(timer, &mut [0u8; 8][..]).map_err(io::Error::from)
            })
            .await?;
            self.armed = None;
            Ok(())
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{future::Future, task::Context, time::Duration};

    #[tokio::test(start_paused = true)]
    async fn a_cancelled_short_wake_does_not_advance_the_next_deadline() {
        let mut timer = Timer::default();
        let origin = Instant::now();
        let mut cx = Context::from_waker(std::task::Waker::noop());
        {
            let first = timer.wait_until(origin + Duration::from_micros(100));
            let mut first = std::pin::pin!(first);
            assert!(first.as_mut().poll(&mut cx).is_pending());
        }
        let deadline = origin + Duration::from_micros(800);
        let next = timer.wait_until(deadline);
        let mut next = std::pin::pin!(next);
        assert!(next.as_mut().poll(&mut cx).is_pending());
        tokio::time::advance(Duration::from_micros(400)).await;
        assert!(next.as_mut().poll(&mut cx).is_pending());
        next.await;
        assert!(Instant::now() >= deadline);
    }
}
