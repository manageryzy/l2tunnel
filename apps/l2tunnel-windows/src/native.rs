//! Windows-only startup; all packet forwarding and lifecycle state stay shared.
use crate::{cli::Plan, diagnostics::Diagnostics, foreground, setup::Setup};
use l2tunnel_client_core::service;
use l2tunnel_device::PacketLayer;
use l2tunnel_platform_windows::Device;
use std::{
    io,
    sync::{Arc, Mutex},
};

/// Run one explicitly selected foreground connection. Ctrl+C cancels setup or
/// aborts the connected generation; completion follows release of owned handles.
/// Driver creation runs on a joined blocking worker. Cancellation during that OS
/// call waits for it to return and releases its result, never detaches the worker.
pub async fn execute(plan: Plan) -> io::Result<()> {
    let connection = plan.connection;
    let config = plan.device.clone();
    let slot: Arc<Mutex<Option<Device>>> = Arc::new(Mutex::new(None));
    let offered = slot.clone();
    let attachment = service::Attachment::new(PacketLayer::Ip, move || {
        let device = offered
            .lock()
            .map_err(|_| io::Error::other("device attachment lock failed"))?
            .take()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "foreground device already consumed",
                )
            })?;
        Ok(Box::new(device))
    });
    // Validate credentials and the shared immutable plan before creating a device.
    let prepared = plan.prepare(attachment)?;
    let diagnostics = Diagnostics::stderr()?;
    let mut interrupt = tokio::signal::windows::ctrl_c()?;
    let cancellation = async move {
        interrupt.recv().await.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "console cancellation source closed",
            )
        })
    };
    tokio::pin!(cancellation);
    let mut worker = Setup::spawn(move || Device::open(&config))?;
    let opened = tokio::select! {
        biased;
        cancelled = &mut cancellation => {
            // A blocking native call cannot be safely aborted. Join and drop its
            // owner before acknowledging cancellation, including a late success.
            let result = worker.finish().await;
            drop(result);
            drop(prepared);
            drop(slot);
            cancelled?;
            diagnostics.emit("Cancelled during device setup; setup worker joined and owned handles released".into());
            return Ok(());
        },
        result = worker.finish() => result?,
    };
    diagnostics.emit(format!(
        "Owned Wintun adapter: {}; driver setup complete, authentication pending",
        opened.name()
    ));
    *slot
        .lock()
        .map_err(|_| io::Error::other("device attachment lock failed"))? = Some(opened);
    diagnostics.emit("requested_carrier=tcp-tls requested_udp_cover=not_applicable traffic=system effective_carrier=unknown native_qualification=pending".into());
    let result = foreground::run(prepared, connection, &mut cancellation, |event| {
        // Only bounded copied text reaches the writer. It owns no device,
        // credentials or service handles and cannot block this runtime thread.
        match event {
            foreground::Event::Requested(config) => {
                diagnostics.emit(format!("Requested {config:?}"));
            }
            foreground::Event::Status(status) => {
                let effective = if status
                    .managed
                    .as_ref()
                    .is_some_and(|managed| managed.running)
                {
                    "tcp-tls"
                } else {
                    "none"
                };
                diagnostics.emit(format!(
                    "effective_carrier={effective} udp_cover=not_applicable {status:?}"
                ));
            }
        }
    })
    .await;
    // On failed authentication/cancel-before-attachment the unused owner is here.
    // The live runtime releases a consumed device before returning its result.
    drop(slot);
    diagnostics.emit("Foreground ended; owned device handles released locally".into());
    result.map(|_| ())
}
