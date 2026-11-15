//! Physical send custody, separate from admission and peer delivery.

use super::{Class, Error};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, oneshot},
    time::Instant,
};

/// One actual whole UDP socket acceptance, including late physical facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendReceipt {
    /// Caller-provided opaque bytes, without the DataV1 opcode.
    pub record_bytes: usize,
    /// Actual UDP payload, including the single DataV1 opcode.
    pub udp_bytes: usize,
    /// Complete configured IP/UDP plus actual UDP payload bytes.
    pub ip_bytes: usize,
    /// Actual local post-write time; this is not peer delivery.
    pub accepted_at: Instant,
    /// Original immutable caller cap, bounded by the carrier lifetime.
    pub deadline: Instant,
}

/// A failed send never implies that an observed physical write was rolled back.
#[derive(Debug)]
pub enum SendFailure {
    /// The original cap expired; a late whole write is retained if it happened.
    Expired {
        /// Actual physical acceptance, absent when no whole write was observed.
        accepted: Option<SendReceipt>,
    },
    /// The real carrier or socket failed.
    Transport(Error),
    /// This move-only completion has already been consumed.
    Consumed,
}
impl std::fmt::Display for SendFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "OpenVPN send: {self:?}")
    }
}
impl std::error::Error for SendFailure {}

/// Move-only completion of one original datagram, never a queue-admission receipt.
/// Dropping it cancels before a later actor pre-write check; an in-flight write
/// may still complete and remains visible in the carrier's physical counters.
pub struct PendingSend {
    pub(super) response: Option<oneshot::Receiver<Result<SendReceipt, SendFailure>>>,
    pub(super) deadline: Instant,
    pub(super) class: Class,
    pub(super) record_bytes: usize,
}
impl PendingSend {
    /// The immutable original cap, never renewed by polling or WouldBlock.
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    /// Trusted local admission class; no peer authority is inferred.
    pub fn class(&self) -> Class {
        self.class
    }
    /// Exact caller-provided opaque record length.
    pub fn record_bytes(&self) -> usize {
        self.record_bytes
    }
}
impl Future for PendingSend {
    type Output = Result<SendReceipt, SendFailure>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(response) = self.response.as_mut() else {
            return Poll::Ready(Err(SendFailure::Consumed));
        };
        match Pin::new(response).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.response = None;
                Poll::Ready(result.unwrap_or_else(|_| {
                    Err(if Instant::now() >= self.deadline {
                        SendFailure::Expired { accepted: None }
                    } else {
                        SendFailure::Transport(Error::Closed)
                    })
                }))
            }
        }
    }
}

/// Authoritative local whole socket writes; distinct from both policy ledgers.
/// Do not add these bytes to overlapping inner/outer admission counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PhysicalStatus {
    /// Whole UDP writes, including real TLS-control retransmissions.
    pub accepted_datagrams: u64,
    /// Exact configured full-IP bytes of those whole writes.
    pub accepted_ip_bytes: u64,
    /// Whole opaque User writes.
    pub user_datagrams: u64,
    /// Whole opaque common Control writes.
    pub common_control_datagrams: u64,
    /// Whole outer TLS/reset/ACK writes.
    pub tls_control_datagrams: u64,
    /// User physical attempts returning WouldBlock, without a new debit or encoding.
    pub user_would_block: u64,
    /// Common Control physical attempts returning WouldBlock under their own slot.
    pub common_control_would_block: u64,
    /// Raw submissions refused at the original cap before any whole write.
    pub expired_before_write: u64,
    /// Whole writes observed at or beyond their original cap.
    pub accepted_after_deadline: u64,
    /// Raw completions dropped before a subsequent physical write attempt.
    pub cancelled_before_write: u64,
}

#[derive(Clone)]
pub(in super::super) struct Ledger(Arc<Mutex<PhysicalStatus>>);
impl Ledger {
    pub(in super::super) fn new() -> Self {
        Self(Arc::new(Mutex::new(PhysicalStatus::default())))
    }
    pub(in super::super) fn status(&self) -> Result<PhysicalStatus, Error> {
        self.0.lock().map(|value| *value).map_err(|_| Error::Closed)
    }
    pub(in super::super) fn written(
        &self,
        class: Option<Class>,
        bytes: usize,
        late: bool,
    ) -> Result<(), Error> {
        let mut value = self.0.lock().map_err(|_| Error::Closed)?;
        value.accepted_datagrams = value.accepted_datagrams.saturating_add(1);
        value.accepted_ip_bytes = value
            .accepted_ip_bytes
            .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
        let counter = match class {
            Some(Class::User) => &mut value.user_datagrams,
            Some(Class::Control) => &mut value.common_control_datagrams,
            None => &mut value.tls_control_datagrams,
        };
        *counter = counter.saturating_add(1);
        if late {
            value.accepted_after_deadline = value.accepted_after_deadline.saturating_add(1);
        }
        Ok(())
    }
    pub(in super::super) fn refused(&self, cancelled: bool) -> Result<(), Error> {
        let mut value = self.0.lock().map_err(|_| Error::Closed)?;
        if cancelled {
            value.cancelled_before_write = value.cancelled_before_write.saturating_add(1);
        } else {
            value.expired_before_write = value.expired_before_write.saturating_add(1);
        }
        Ok(())
    }
    pub(in super::super) fn blocked(&self, class: Option<Class>) -> Result<(), Error> {
        let Some(class) = class else {
            return Ok(());
        };
        let mut value = self.0.lock().map_err(|_| Error::Closed)?;
        let counter = match class {
            Class::User => &mut value.user_would_block,
            Class::Control => &mut value.common_control_would_block,
        };
        *counter = counter.saturating_add(1);
        Ok(())
    }
}

pub(in super::super) struct Custody {
    pub(in super::super) deadline: Instant,
    pub(in super::super) class: Class,
    pub(in super::super) record_bytes: usize,
    pub(in super::super) response: oneshot::Sender<Result<SendReceipt, SendFailure>>,
    // The actual queue/held/output path retains the class reservation until terminal.
    pub(in super::super) _permit: OwnedSemaphorePermit,
}
pub(in super::super) struct Shared {
    pub(super) user: Arc<Semaphore>,
    pub(super) control: Arc<Semaphore>,
    pub(in super::super) physical: Ledger,
    pub(super) expires: Instant,
    #[cfg(test)]
    pub(super) user_gate: Arc<std::sync::atomic::AtomicBool>,
}
impl Shared {
    pub(super) fn new(slots: usize, expires: Instant) -> Self {
        Self {
            user: Arc::new(Semaphore::new(slots)),
            control: Arc::new(Semaphore::new(slots)),
            physical: Ledger::new(),
            expires,
            #[cfg(test)]
            user_gate: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
    pub(super) fn slots(&self, class: Class) -> Arc<Semaphore> {
        match class {
            Class::User => self.user.clone(),
            Class::Control => self.control.clone(),
        }
    }
}
