//! Exact immutable ticket custody through maintained QUIC queue acceptance.
use super::*;
use std::sync::Mutex;

/// One complete maintained QUIC DATAGRAM admission, never physical IP emission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendReceipt {
    /// Exact caller record bytes.
    pub record_bytes: usize,
    /// Exact bytes submitted to Quinn, including bootstrap envelope when present.
    pub carrier_bytes: usize,
    /// Explicit conservative configured IP/QUIC admission charge.
    pub charged_bytes: usize,
    /// Local observation after `send_datagram_wait` accepted the complete payload.
    pub accepted_at: Instant,
    /// Original immutable operation cap, never restarted after Pending.
    pub deadline: Instant,
}
/// A failed ticket never rolls back an observed maintained-queue admission.
#[derive(Debug)]
pub enum SendFailure {
    /// Original cap expired; a late successful acceptance remains observable.
    Expired {
        /// Actual acceptance if it occurred before the late observation.
        accepted: Option<SendReceipt>,
    },
    /// Actual maintained transport or owner failure.
    Transport(Error),
    /// This move-only ticket's result was already consumed.
    Consumed,
}
impl fmt::Display for SendFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Common QUIC send: {self:?}")
    }
}
impl std::error::Error for SendFailure {}

/// Named maintained-queue statistics, separate from physical network totals.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AcceptanceStatus {
    /// Complete accepted DATAGRAMs.
    pub accepted_datagrams: u64,
    /// Caller bytes accepted, including all Common records but no private envelope.
    pub accepted_record_bytes: u64,
    /// Exact bytes accepted by Quinn, including retained bootstrap envelopes.
    pub accepted_carrier_bytes: u64,
    /// Conservative admission charges; not actual IP bytes.
    pub accepted_charged_bytes: u64,
    /// Acceptances observed at or beyond their original deadline.
    pub accepted_after_deadline: u64,
}
#[derive(Clone)]
pub(super) struct Ledger(Arc<Mutex<AcceptanceStatus>>);
impl Ledger {
    pub(super) fn new() -> Self {
        Self(Arc::new(Mutex::new(AcceptanceStatus::default())))
    }
    pub(super) fn status(&self) -> Result<AcceptanceStatus, Error> {
        self.0
            .lock()
            .map(|value| *value)
            .map_err(|_| Error::Transport)
    }
    fn accepted(&self, receipt: SendReceipt) -> Result<(), Error> {
        let mut value = self.0.lock().map_err(|_| Error::Transport)?;
        value.accepted_datagrams = value.accepted_datagrams.saturating_add(1);
        value.accepted_record_bytes = value
            .accepted_record_bytes
            .saturating_add(receipt.record_bytes as u64);
        value.accepted_carrier_bytes = value
            .accepted_carrier_bytes
            .saturating_add(receipt.carrier_bytes as u64);
        value.accepted_charged_bytes = value
            .accepted_charged_bytes
            .saturating_add(receipt.charged_bytes as u64);
        if receipt.accepted_at >= receipt.deadline {
            value.accepted_after_deadline = value.accepted_after_deadline.saturating_add(1);
        }
        Ok(())
    }
}

type Completion = Pin<Box<dyn Future<Output = Result<SendReceipt, SendFailure>> + Send>>;
/// Move-only copied record and bounded class reservation. Polling performs the
/// maintained send; dropping a pending future cancels without a new attempt.
pub struct PendingSend {
    completion: Option<Completion>,
    deadline: Instant,
    class: Class,
    record_bytes: usize,
}
impl PendingSend {
    /// Original immutable absolute cap.
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    /// Trusted local class, never peer authority.
    pub fn class(&self) -> Class {
        self.class
    }
    /// Exact retained caller record length.
    pub fn record_bytes(&self) -> usize {
        self.record_bytes
    }
    #[allow(clippy::too_many_arguments)] // Explicit complete ticket custody.
    pub(super) fn new(
        session: Arc<Session>,
        ledger: Ledger,
        permit: OwnedSemaphorePermit,
        class: Class,
        bytes: Bytes,
        record_bytes: usize,
        charged_bytes: usize,
        deadline: Instant,
    ) -> Self {
        let completion = Box::pin(async move {
            let _permit = permit;
            if Instant::now() >= deadline {
                return Err(SendFailure::Expired { accepted: None });
            }
            session.check().map_err(SendFailure::Transport)?;
            let carrier_bytes = bytes.len();
            timeout_at(deadline, session.connection.send_datagram_wait(bytes))
                .await
                .map_err(|_| SendFailure::Expired { accepted: None })?
                .map_err(|_| SendFailure::Transport(Error::Transport))?;
            let receipt = SendReceipt {
                record_bytes,
                carrier_bytes,
                charged_bytes,
                accepted_at: Instant::now(),
                deadline,
            };
            ledger.accepted(receipt).map_err(SendFailure::Transport)?;
            if receipt.accepted_at >= deadline {
                Err(SendFailure::Expired {
                    accepted: Some(receipt),
                })
            } else {
                Ok(receipt)
            }
        });
        Self {
            completion: Some(completion),
            deadline,
            class,
            record_bytes,
        }
    }
}
impl Future for PendingSend {
    type Output = Result<SendReceipt, SendFailure>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(completion) = &mut self.completion else {
            return Poll::Ready(Err(SendFailure::Consumed));
        };
        match completion.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.completion = None;
                Poll::Ready(result)
            }
        }
    }
}
