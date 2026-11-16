//! Windows-only startup; packet forwarding and lifecycle state stay shared.
use crate::{cli::Plan, diagnostics::Diagnostics, foreground, input, staging::Staging};
use l2tunnel_device::PacketLayer;
use l2tunnel_platform_windows::Device;
use std::{io, sync::Arc};

/// Run the explicit foreground connection with optional bounded stdin control.
/// Ctrl+C and input closure release the actual shared owner and unused devices.
/// Blocking driver creation is joined on cancellation, including a late success.
pub async fn execute(plan: Plan) -> io::Result<()> {
    let connection = plan.connection;
    let control_stdin = plan.control_stdin;
    let config = plan.device.clone();
    let diagnostics = Arc::new(Diagnostics::stderr()?);
    let device_diagnostics = diagnostics.clone();
    let staging = Staging::new(move || {
        let device = Device::open(&config)?;
        device_diagnostics.emit(format!(
            "Owned Wintun adapter: {}; authentication pending",
            device.name()
        ));
        Ok(Box::new(device))
    });
    // Validate credentials and the immutable shared plan before any device work.
    let prepared = plan.prepare(staging.attachment(PacketLayer::Ip))?;
    let mut interrupt = tokio::signal::windows::ctrl_c()?;
    let cancellation = async move {
        interrupt.recv().await.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "console cancellation source closed",
            )
        })
    };
    let controls = if control_stdin {
        Some(input::stdin()?)
    } else {
        None
    };
    diagnostics.emit("requested_carrier=tcp-tls requested_udp_cover=not_applicable traffic=system effective_carrier=unknown native_qualification=pending".into());
    if control_stdin {
        diagnostics.emit("Local stdin control: status, disconnect, reconnect (LF/CRLF). EOF ends foreground ownership; it does not wait for a queued reconnect to finish.".into());
    }
    let result = foreground::controlled(
        prepared,
        connection,
        Some(staging),
        controls,
        cancellation,
        |event| {
            // Bounded copied text only. A blocked diagnostic consumer cannot retain
            // a device, credential, service handle or the thread polling Run.
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
                foreground::Event::Accepted { action, operation } => {
                    diagnostics.emit(format!("Accepted action={action:?} operation={operation}"));
                }
                foreground::Event::Completed { operation, result } => {
                    diagnostics.emit(format!("Completed operation={operation} result={result:?}"));
                }
                foreground::Event::Terminal { generation, result } => {
                    diagnostics.emit(format!(
                        "Released generation={generation} terminal={result:?}"
                    ));
                }
                foreground::Event::DevicePreparing => {
                    diagnostics.emit(
                        "Creating owned Wintun adapter; no new service operation or generation yet"
                            .into(),
                    );
                }
                foreground::Event::DeviceReady => {
                    diagnostics
                        .emit("Device staged; authentication and service readiness pending".into());
                }
                foreground::Event::Failed { kind } => {
                    diagnostics.emit(format!(
                        "Local request failed kind={kind:?}; no automatic retry"
                    ));
                }
                foreground::Event::Rejected { command, reason } => {
                    diagnostics.emit(format!("Rejected command={command:?} reason={reason:?}"));
                }
            }
        },
    )
    .await;
    diagnostics
        .emit("Foreground ended; owned device and transport handles released locally".into());
    result.map(|_| ())
}
