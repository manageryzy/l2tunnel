//! Fixed proxy actor on the original authenticated Common UDP owner.
//!
//! The actor remains the sole TCP Table, per-flow scheduler and drain owner.
//! Its ordered records use an explicit one-channel Common adapter. Common native
//! counters in this composition describe record-port acceptance, not TUN writes;
//! only the proxy Table observes actual native writes and ACKs.
use super::*;
use crate::secure_udp::{member, transport};
use tokio::time::Instant;

/// Validate the finite fixed/full/one-channel composition before native I/O.
/// Measured, multi-channel and live generation/endpoint changes remain unsupported.
pub fn validate(
    config: &Config,
    contract: &transport::CommonTransactionContract,
) -> io::Result<()> {
    config.validate()?;
    if config.duplex != Duplex::Full
        || config.mux.channels != 1
        || contract.proxy_binding() != Some(session_config(config)?.digest)
        || contract.catalog().descriptors().len() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Common proxy requires bound fixed/full/one-channel policy",
        ));
    }
    let maximum = config
        .max_user()?
        .checked_add(48)
        .ok_or_else(|| invalid("proxy frame maximum"))?;
    let initial = contract.initial();
    for role in [
        l2tunnel_management::Role::Client,
        l2tunnel_management::Role::Server,
    ] {
        let direction = initial.descriptor().direction(role);
        if direction.common().traffic().tcp != l2tunnel_core::traffic::TcpControl::SplitTcpProxy
            || direction.max_native() < maximum
        {
            return Err(invalid(
                "Common proxy record capacity differs from actor frames",
            ));
        }
    }
    Ok(())
}

/// Reuse the existing fixed actor and shared Common Driver after actual membership.
/// No socket, authentication, TCP stack or recovery owner is replaced. This entry
/// retains the original setup cap through mutual proxy readiness and joins every
/// actor child before returning failure. The policy digest must have been included
/// in authenticated H0 by the constructing shared client/service Profile.
pub fn run<D>(
    device: D,
    parts: member::Parts,
    contract: transport::CommonTransactionContract,
    config: Config,
    control: Control,
    requests: Option<transport::CommonControlRequests>,
    observe: impl FnMut(&transport::CommonSnapshot) + Send,
) -> impl std::future::Future<Output = io::Result<CloseReport>> + Send
where
    D: PacketDevice<Error = io::Error> + Send,
{
    let prepared = (|| {
        validate(&config, &contract)?;
        if device.layer() != PacketLayer::Ip {
            return Err(invalid("Common proxy requires an IP attachment"));
        }
        if Instant::now() >= parts.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original Common proxy setup cap",
            ));
        }
        let info = parts.info;
        let setup = parts.deadline;
        let logical = info.binding.session.0;
        let maximum = contract
            .initial()
            .descriptor()
            .direction(l2tunnel_management::Role::Client)
            .max_native()
            .max(
                contract
                    .initial()
                    .descriptor()
                    .direction(l2tunnel_management::Role::Server)
                    .max_native(),
            );
        let (port, stream, bridge) =
            super::common_bridge::pair(maximum, contract.resources().native.stall_timeout)?;
        let (reader, writer) = tokio::io::split(stream);
        let link = Link {
            inner: crate::Link {
                managed_metadata: None,
                reader: Box::pin(reader),
                writer: Box::pin(writer),
                reverse_reader: None,
                reverse_writer: None,
                receive_session: logical,
                send_session: logical,
                layer: PacketLayer::Ip,
            },
            binding: session_config(&config)?,
            originator: info.role == l2tunnel_security::Role::Initiator,
            logical,
        };
        let readiness = match &control.status {
            StatusSink::Fixed(sender) => sender.subscribe(),
            StatusSink::Measured(_) => {
                return Err(invalid("measured Common proxy is not installed"));
            }
        };
        Ok((port, bridge, link, readiness, setup))
    })();
    async move {
        let (port, bridge, link, mut readiness, setup) = prepared?;
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let runtime = transport::run_common_proxy_records(
            port,
            bridge.clone(),
            parts,
            contract,
            requests,
            async {
                let _ = stopped.await;
            },
            observe,
        );
        let actor = actor::run_profile_owned(device, link, config, control, None, true);
        tokio::pin!(runtime, actor);
        let ready = async {
            loop {
                if readiness
                    .borrow()
                    .as_ref()
                    .is_some_and(|s| s.phase == Phase::Forwarding)
                {
                    return if Instant::now() < setup {
                        Ok(())
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "original Common proxy readiness cap",
                        ))
                    };
                }
                if readiness.changed().await.is_err() {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "Common proxy readiness owner ended",
                    ));
                }
            }
        };
        tokio::pin!(ready);
        let mut started = false;
        loop {
            tokio::select! {
                result = &mut actor => {
                    let _ = stop.send(());
                    let common = runtime.await;
                    bridge.fail();
                    result?;
                    let stopped = common?;
                    if stopped.reason != transport::StopReason::Cancelled {
                        return Err(io::Error::other(format!("Common proxy ended before local close: {:?}", stopped.reason)));
                    }
                    return Err(io::Error::new(io::ErrorKind::Unsupported,
                        "Common proxy graceful close has no retained reliable retirement owner"));
                }
                result = &mut runtime => {
                    bridge.fail();
                    let _ = actor.await; // Same owner performs abnormal cleanup and actual joins.
                    return Err(match result {
                        Err(error) => error,
                        Ok(stopped) => io::Error::other(format!("Common proxy carrier ended: {:?}", stopped.reason)),
                    });
                }
                result = &mut ready, if !started => {
                    if let Err(error) = result {
                        bridge.fail();
                        let _ = actor.await;
                        let _ = stop.send(());
                        let _ = runtime.await;
                        return Err(error);
                    }
                    if Instant::now() >= setup {
                        bridge.fail();
                        let _ = actor.await;
                        let _ = stop.send(());
                        let _ = runtime.await;
                        return Err(io::Error::new(io::ErrorKind::TimedOut, "original Common proxy readiness cap"));
                    }
                    started = true;
                }
                () = tokio::time::sleep_until(setup), if !started => {
                    bridge.fail();
                    let _ = actor.await;
                    let _ = stop.send(());
                    let _ = runtime.await;
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "original Common proxy readiness cap"));
                }
            }
        }
    }
}
