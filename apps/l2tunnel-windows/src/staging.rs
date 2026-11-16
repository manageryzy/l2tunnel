//! Refillable, exclusively owned platform handoff to the shared service.
use crate::setup::Setup;
use l2tunnel_client_core::service::Attachment;
use l2tunnel_device::{PacketDevice, PacketLayer};
use std::{
    io,
    sync::{Arc, Mutex},
};

type Device = Box<dyn PacketDevice<Error = io::Error> + Send>;

/// Retains the setup worker and unused device; an attached device belongs to Run.
/// Dropping this guard joins setup and empties the slot even if Prepared survives.
pub(crate) struct Staging {
    slot: Arc<Mutex<Option<Device>>>,
    open: Arc<dyn Fn() -> io::Result<Device> + Send + Sync>,
    worker: tokio::sync::Mutex<Option<Setup<Device>>>,
}

impl Staging {
    pub(crate) fn new(open: impl Fn() -> io::Result<Device> + Send + Sync + 'static) -> Self {
        Self {
            slot: Arc::new(Mutex::new(None)),
            open: Arc::new(open),
            worker: tokio::sync::Mutex::new(None),
        }
    }

    pub(crate) fn attachment(&self, layer: PacketLayer) -> Attachment {
        let slot = self.slot.clone();
        Attachment::new(layer, move || {
            slot.lock()
                .map_err(|_| io::Error::other("device attachment lock failed"))?
                .take()
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotConnected, "no staged foreground device")
                })
        })
    }

    /// Called only after the service has released the previous generation.
    /// Abandoning this future leaves the worker in this guard. The stop request
    /// asynchronously joins it; dropping the guard itself also joins it.
    pub(crate) async fn prepare(&self) -> io::Result<()> {
        self.clear();
        let open = self.open.clone();
        let mut worker = self.worker.lock().await;
        if worker.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "platform setup already owned",
            ));
        }
        *worker = Some(Setup::spawn(move || open())?);
        let result = worker
            .as_mut()
            .ok_or_else(|| io::Error::other("platform setup missing"))?
            .finish()
            .await;
        drop(worker.take());
        let device = result?;
        *self
            .slot
            .lock()
            .map_err(|_| io::Error::other("device attachment lock failed"))? = Some(device);
        Ok(())
    }

    /// Await the original blocking call without blocking the service polling
    /// thread. A late success is dropped, never installed into the handoff slot.
    pub(crate) async fn abandon(&self) {
        let mut worker = self.worker.lock().await;
        if let Some(owned) = worker.as_mut() {
            drop(owned.finish().await);
        }
        drop(worker.take());
        self.clear();
    }

    pub(crate) fn clear(&self) {
        // Poison must never prevent release of a native owner during unwinding.
        let mut slot = self
            .slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        drop(slot.take());
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        // External future abandonment cannot detach a still-running OS call.
        drop(self.worker.get_mut().take());
        self.clear();
    }
}
