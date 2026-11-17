//! Runtime-only native readiness: reactor-backed on Unix, bounded polling elsewhere.
use l2tunnel_device::PacketDevice;
use std::io;

/// A nonblocking packet device accepted by the sole transport loop.
/// Unix devices additionally expose the descriptor registered with the reactor.
#[cfg(unix)]
pub trait NativeDevice: PacketDevice<Error = io::Error> + std::os::fd::AsRawFd {}
#[cfg(unix)]
impl<T: PacketDevice<Error = io::Error> + std::os::fd::AsRawFd + ?Sized> NativeDevice for T {}

/// A nonblocking packet device accepted by the portable bounded polling loop.
#[cfg(not(unix))]
pub trait NativeDevice: PacketDevice<Error = io::Error> {}
#[cfg(not(unix))]
impl<T: PacketDevice<Error = io::Error> + ?Sized> NativeDevice for T {}

#[cfg(not(unix))]
pub(super) use polling::{NativeGuard, NativeReady};
#[cfg(unix)]
pub(super) use tokio::io::unix::{AsyncFd as NativeReady, AsyncFdReadyMutGuard as NativeGuard};

// Compile the portable implementation in local tests, independently from the
// host reactor. Passing these tests does not qualify a Windows device driver.
#[cfg(any(not(unix), test))]
mod polling {
    use std::{
        future::Future,
        io,
        pin::Pin,
        task::{Context, Poll},
        time::Duration,
    };
    use tokio::{
        io::{Interest, Ready},
        time::{Instant, Sleep, sleep_until},
    };

    const INTERVAL: Duration = Duration::from_millis(1);

    pub(crate) struct NativeReady<D> {
        device: D,
        read_at: Instant,
        write_at: Instant,
        timer: Pin<Box<Sleep>>,
    }
    pub(crate) struct NativeGuard<'a, D> {
        owner: &'a mut NativeReady<D>,
        ready: Ready,
    }
    impl<D> NativeReady<D> {
        pub(crate) fn with_interest(device: D, _interest: Interest) -> io::Result<Self> {
            let now = Instant::now();
            Ok(Self {
                device,
                read_at: now,
                write_at: now,
                timer: Box::pin(sleep_until(now)),
            })
        }
        fn available(&self, interest: Interest, now: Instant) -> Ready {
            let mut ready = Ready::EMPTY;
            if interest.is_readable() && now >= self.read_at {
                ready |= Ready::READABLE;
            }
            if interest.is_writable() && now >= self.write_at {
                ready |= Ready::WRITABLE;
            }
            ready
        }
        fn guard(&mut self, ready: Ready, now: Instant) -> NativeGuard<'_, D> {
            // Grant one existing bounded batch per interval, including successful
            // batches. A cancelled wait never changes either original poll cap.
            if ready.is_readable() {
                self.read_at = now + INTERVAL;
            }
            if ready.is_writable() {
                self.write_at = now + INTERVAL;
            }
            NativeGuard { owner: self, ready }
        }
        pub(crate) async fn ready_mut(
            &mut self,
            interest: Interest,
        ) -> io::Result<NativeGuard<'_, D>> {
            loop {
                let now = Instant::now();
                let ready = self.available(interest, now);
                if !ready.is_empty() {
                    return Ok(self.guard(ready, now));
                }
                let at = match (interest.is_readable(), interest.is_writable()) {
                    (true, true) => self.read_at.min(self.write_at),
                    (true, false) => self.read_at,
                    (false, true) => self.write_at,
                    (false, false) => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "native readiness interest",
                        ));
                    }
                };
                self.timer.as_mut().reset(at);
                self.timer.as_mut().await;
            }
        }
        pub(crate) fn poll_write_ready_mut(
            &mut self,
            cx: &mut Context<'_>,
        ) -> Poll<io::Result<NativeGuard<'_, D>>> {
            let now = Instant::now();
            if now >= self.write_at {
                return Poll::Ready(Ok(self.guard(Ready::WRITABLE, now)));
            }
            self.timer.as_mut().reset(self.write_at);
            let _ = self.timer.as_mut().poll(cx);
            Poll::Pending
        }
    }
    impl<D> NativeGuard<'_, D> {
        pub(crate) fn ready(&self) -> Ready {
            self.ready
        }
        pub(crate) fn get_inner_mut(&mut self) -> &mut D {
            &mut self.owner.device
        }
        pub(crate) fn clear_ready_matching(&mut self, ready: Ready) {
            let retry = Instant::now() + INTERVAL;
            if ready.is_readable() {
                self.owner.read_at = self.owner.read_at.max(retry);
            }
            if ready.is_writable() {
                self.owner.write_at = self.owner.write_at.max(retry);
            }
            self.ready = self.ready - ready;
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[tokio::test(start_paused = true)]
        async fn portable_native_readiness_retains_retry_caps_and_independent_directions()
        -> io::Result<()> {
            let mut device =
                NativeReady::with_interest(7u8, Interest::READABLE.add(Interest::WRITABLE))?;
            let origin = Instant::now();
            {
                let mut ready = device.ready_mut(Interest::READABLE).await?;
                assert!(ready.ready().is_readable());
                *ready.get_inner_mut() = 9;
                ready.clear_ready_matching(Ready::READABLE);
                assert!(ready.ready().is_empty());
            }
            // A blocked read does not delay the first write. One bounded write
            // grant is followed by Pending, not an immediate busy-poll grant.
            std::future::poll_fn(|cx| {
                let mut ready = match device.poll_write_ready_mut(cx) {
                    Poll::Ready(Ok(ready)) => ready,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => {
                        return Poll::Ready(Err(io::Error::other("initial write readiness")));
                    }
                };
                assert_eq!(*ready.get_inner_mut(), 9);
                ready.clear_ready_matching(Ready::WRITABLE);
                Poll::Ready(Ok(()))
            })
            .await?;
            std::future::poll_fn(|cx| {
                assert!(device.poll_write_ready_mut(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            let original_read = device.read_at;
            // Cancellation by an earlier control/deadline wake does not restart
            // polling and does not consume another native attempt.
            let timer_won = tokio::select! {
                biased;
                () = sleep_until(origin + Duration::from_micros(400)) => true,
                _ = device.ready_mut(Interest::READABLE) => false,
            };
            assert!(timer_won, "read renewed early");
            assert_eq!(device.read_at, original_read);
            let ready = device
                .ready_mut(Interest::READABLE.add(Interest::WRITABLE))
                .await?;
            assert!(ready.ready().is_readable() && ready.ready().is_writable());
            assert!(Instant::now() >= origin + INTERVAL);
            Ok(())
        }
    }
}
