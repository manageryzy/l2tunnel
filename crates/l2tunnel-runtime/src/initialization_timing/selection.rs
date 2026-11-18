//! Selected-wait wall observations, with the original future polled exactly once.
use super::*;
use std::{future::Future, task::Poll};

/// Actual winning branch, never inferred from the planned wake or buffered work.
#[derive(Clone, Copy, Debug)]
#[repr(usize)]
pub(crate) enum SelectionWinner {
    Shutdown,
    Request,
    Carrier,
    Native,
    Timer,
    IoError,
    Work,
}
const WINNERS: [SelectionWinner; 7] = [
    SelectionWinner::Shutdown,
    SelectionWinner::Request,
    SelectionWinner::Carrier,
    SelectionWinner::Native,
    SelectionWinner::Timer,
    SelectionWinner::IoError,
    SelectionWinner::Work,
];

#[derive(Default)]
pub(super) struct Selections {
    pending: Option<Instant>,
    completed: u64,
    winners: [u64; WINNERS.len()],
    maximum: Option<Maximum>,
    interrupted: Option<Interrupted>,
}
struct Maximum {
    planned_wake_us: u64,
    poll_entered_at_us: u64,
    observed_at_us: u64,
    lateness_us: u64,
    winner: SelectionWinner,
}
struct Interrupted {
    planned_wake_us: u64,
    observed_at_us: u64,
}
fn micros(origin: Instant, at: Instant) -> Option<u64> {
    at.checked_duration_since(origin)
        .and_then(|span| u64::try_from(span.as_micros()).ok())
}
impl Selections {
    fn complete(
        &mut self,
        origin: Instant,
        entered: Instant,
        at: Instant,
        winner: SelectionWinner,
    ) -> bool {
        let Some(wake) = self.pending.take() else {
            return true;
        };
        let mut invalid = add(&mut self.completed, 1);
        invalid |= add(&mut self.winners[winner as usize], 1);
        let Some(((planned_wake_us, poll_entered_at_us), observed_at_us)) = micros(origin, wake)
            .zip(micros(origin, entered))
            .zip(micros(origin, at))
        else {
            return true;
        };
        let late = entered.checked_duration_since(wake).unwrap_or_default();
        let Ok(lateness_us) = u64::try_from(late.as_micros()) else {
            return true;
        };
        if self
            .maximum
            .as_ref()
            .is_none_or(|previous| lateness_us > previous.lateness_us)
        {
            self.maximum = Some(Maximum {
                planned_wake_us,
                poll_entered_at_us,
                observed_at_us,
                lateness_us,
                winner,
            });
        }
        invalid
    }
    pub(super) fn censor(&mut self, origin: Instant, at: Instant) -> bool {
        let Some(wake) = self.pending.take() else {
            return false;
        };
        let Some((planned_wake_us, observed_at_us)) = micros(origin, wake).zip(micros(origin, at))
        else {
            return true;
        };
        let repeated = self.interrupted.is_some();
        self.interrupted = Some(Interrupted {
            planned_wake_us,
            observed_at_us,
        });
        repeated
    }
    pub(super) fn write(&self, origin: Instant, output: &mut impl Write) -> io::Result<()> {
        write!(
            output,
            "{{\"definition\":\"selected Pending spans include intentional suspension and scheduling; poll spans include only actual poll calls and descheduling within them; resume lateness is winning poll entry minus planned wake, excluding poll work; not a timer or kernel failure\",\"completed\":{},\"winners\":[",
            self.completed
        )?;
        for (index, winner) in WINNERS.into_iter().enumerate() {
            if index != 0 {
                write!(output, ",")?;
            }
            write!(
                output,
                "{{\"winner\":\"{winner:?}\",\"count\":{}}}",
                self.winners[index]
            )?;
        }
        write!(output, "],\"maximum_lateness\":")?;
        match &self.maximum {
            Some(value) => write!(
                output,
                "{{\"planned_wake_us\":{},\"poll_entered_at_us\":{},\"observed_at_us\":{},\"lateness_us\":{},\"winner\":\"{:?}\"}}",
                value.planned_wake_us,
                value.poll_entered_at_us,
                value.observed_at_us,
                value.lateness_us,
                value.winner
            )?,
            None => write!(output, "null")?,
        }
        write!(output, ",\"interrupted\":")?;
        match &self.interrupted {
            Some(value) => write!(
                output,
                "{{\"planned_wake_us\":{},\"observed_at_us\":{}}}",
                value.planned_wake_us, value.observed_at_us
            )?,
            None => write!(output, "null")?,
        }
        write!(output, ",\"pending_planned_wake_us\":")?;
        optional_us(output, self.pending.and_then(|wake| micros(origin, wake)))?;
        write!(output, "}}")
    }
}
impl Timing {
    /// Observe the existing selection without changing its polling order, waker,
    /// wake instant or result. Pending spans end on the next actual poll entry;
    /// cancellation leaves the original wake and active Pending span for the
    /// existing terminal freeze. Disabled observation adds no clock reads.
    pub(crate) async fn measure_selection<T>(
        &mut self,
        wake: Instant,
        operation: impl Future<Output = T>,
        winner: impl FnOnce(&T) -> SelectionWinner,
    ) -> T {
        let Some(state) = self.state.first_mut() else {
            return operation.await;
        };
        state.invalid |= state.selection.pending.replace(wake).is_some()
            || state.active.is_some()
            || micros(state.origin, wake).is_none();
        tokio::pin!(operation);
        let (result, entered, finished) = std::future::poll_fn(|cx| {
            let entered = Instant::now();
            state.end_at(entered, Outcome::Complete);
            let polled = operation.as_mut().poll(cx);
            let finished = Instant::now();
            state.record_span_at(
                Stage::CommonSelectPoll,
                entered,
                finished,
                Outcome::Complete,
            );
            match polled {
                Poll::Pending => {
                    state.enter_at(Stage::CommonSelectPending, finished);
                    Poll::Pending
                }
                Poll::Ready(result) => Poll::Ready((result, entered, finished)),
            }
        })
        .await;
        state.invalid |= state
            .selection
            .complete(state.origin, entered, finished, winner(&result));
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn timing(origin: Instant) -> Timing {
        Timing {
            state: allocate_state(1, Owner::CommonExecution, origin),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn pending_intervals_end_at_actual_poll_without_changing_poll_order_or_result()
    -> io::Result<()> {
        let origin = Instant::now();
        let mut timing = timing(origin);
        let wake = origin + Duration::from_micros(10);
        let mut order = Vec::new();
        let mut polled = 0;
        let operation = std::future::poll_fn(|_| {
            order.push(polled);
            polled += 1;
            if polled == 1 {
                Poll::Pending
            } else {
                Poll::Ready(Err::<(), _>(io::ErrorKind::BrokenPipe))
            }
        });
        let mut measured =
            Box::pin(timing.measure_selection(wake, operation, |_| SelectionWinner::IoError));
        std::future::poll_fn(|cx| {
            assert!(measured.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        tokio::time::advance(Duration::from_micros(25)).await;
        assert_eq!(measured.await, Err(io::ErrorKind::BrokenPipe));
        assert_eq!(order, [0, 1]);
        let poll = timing
            .snapshot(Stage::CommonSelectPoll)
            .ok_or_else(|| io::Error::other("enabled poll"))?;
        let pending = timing
            .snapshot(Stage::CommonSelectPending)
            .ok_or_else(|| io::Error::other("enabled pending"))?;
        assert_eq!((poll.samples, poll.sum_us), (2, 0));
        assert_eq!(
            (pending.samples, pending.sum_us, pending.censored),
            (1, 25, 0)
        );
        let mut output = Vec::new();
        timing.write_snapshot_at(Instant::now(), &mut output)?;
        let json: serde_json::Value = serde_json::from_slice(&output)?;
        assert_eq!(json["selection"]["completed"], 1);
        assert_eq!(json["selection"]["maximum_lateness"]["lateness_us"], 15);
        assert_eq!(json["selection"]["maximum_lateness"]["winner"], "IoError");
        assert!(json["selection"]["pending_planned_wake_us"].is_null());
        Ok(())
    }

    #[tokio::test]
    async fn successful_poll_work_is_not_counted_as_pending_or_resume_lateness() -> io::Result<()> {
        let origin = Instant::now();
        let mut timing = timing(origin);
        let wake = origin + Duration::from_secs(1);
        let operation = std::future::poll_fn(|_| {
            std::thread::sleep(Duration::from_millis(1));
            Poll::Ready(31)
        });
        assert_eq!(
            timing
                .measure_selection(wake, operation, |_| SelectionWinner::Carrier)
                .await,
            31
        );
        let poll = timing
            .snapshot(Stage::CommonSelectPoll)
            .ok_or_else(|| io::Error::other("poll"))?;
        let pending = timing
            .snapshot(Stage::CommonSelectPending)
            .ok_or_else(|| io::Error::other("pending"))?;
        assert_eq!(poll.samples, 1);
        assert!(poll.sum_us >= 1_000);
        assert_eq!(pending.samples, 0);
        let mut bytes = Vec::new();
        timing.write_snapshot_at(Instant::now(), &mut bytes)?;
        let json: serde_json::Value = serde_json::from_slice(&bytes)?;
        let maximum = &json["selection"]["maximum_lateness"];
        let entered = maximum["poll_entered_at_us"]
            .as_u64()
            .ok_or_else(|| io::Error::other("poll entry"))?;
        let returned = maximum["observed_at_us"]
            .as_u64()
            .ok_or_else(|| io::Error::other("poll return"))?;
        assert!(returned >= entered + 1_000);
        assert_eq!(maximum["lateness_us"], entered.saturating_sub(1_000_000));
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn early_ready_and_disabled_selection_do_not_invent_wait_or_lateness() -> io::Result<()> {
        let origin = Instant::now();
        let mut timing = timing(origin);
        let wake = origin + Duration::from_secs(1);
        assert_eq!(
            timing
                .measure_selection(wake, std::future::ready(17), |_| SelectionWinner::Request)
                .await,
            17
        );
        assert_eq!(
            timing
                .snapshot(Stage::CommonSelectPending)
                .ok_or_else(|| io::Error::other("enabled"))?
                .samples,
            0
        );
        let mut output = Vec::new();
        timing.write_snapshot_at(origin, &mut output)?;
        let json: serde_json::Value = serde_json::from_slice(&output)?;
        assert_eq!(json["selection"]["maximum_lateness"]["lateness_us"], 0);
        assert_eq!(
            json["selection"]["maximum_lateness"]["planned_wake_us"],
            1_000_000
        );
        let mut disabled = Timing::disabled();
        assert_eq!(
            disabled
                .measure_selection(wake, std::future::ready(23), |_| SelectionWinner::Timer)
                .await,
            23
        );
        assert!(disabled.state.is_empty());
        Ok(())
    }
}
