//! Explicit proxy actors on the original authenticated Common UDP owner.
//!
//! The actor remains the sole TCP Table, per-flow scheduler and drain owner.
//! Its ordered records use an explicit one-channel Common adapter. Common native
//! counters in this composition describe record-port acceptance, not TUN writes;
//! only the proxy Table observes actual native writes and ACKs.
use super::*;
use crate::secure_udp::{member, transport};
use tokio::time::Instant;
#[path = "common_measured.rs"]
mod measured_profile;
pub use measured_profile::{run_measured, validate_measured};
#[path = "common_raw.rs"]
mod raw_profile;
pub use raw_profile::run_on_raw;
#[path = "common_maintained.rs"]
mod maintained_profile;
pub use maintained_profile::{run_measured_on_maintained, run_on_maintained};

/// Validate the fixed Full composition before native I/O. The actor retains its
/// configured user-flow MUX channels; Common supplies one ordered record stream.
pub fn validate(
    config: &Config,
    contract: &transport::CommonTransactionContract,
) -> io::Result<()> {
    config.validate()?;
    validate_binding(config, contract, session_config(config)?.digest)
}

fn validate_binding(
    config: &Config,
    contract: &transport::CommonTransactionContract,
    binding: ConfigDigest,
) -> io::Result<()> {
    if contract.proxy_binding() != Some(binding) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Common proxy lacks its exact bound policy",
        ));
    }
    validate_catalog(config, contract.catalog())
}

/// Validate the exact fixed actor/catalog capacities without creating authority.
/// This pure preflight is shared by requested raw plans before original I/O and
/// effective contracts after genuine member/outer authentication.
pub fn validate_catalog(
    config: &Config,
    catalog: &l2tunnel::record_configuration::Catalog,
) -> io::Result<()> {
    let memory = config.validate()?;
    memory
        .payload_bytes
        .checked_add(memory.common_bridge_metadata_bytes)
        .filter(|bytes| *bytes <= 268_435_456)
        .ok_or_else(|| invalid("Common proxy aggregate memory bound"))?;
    if config.duplex != catalog.initial().duplex() || catalog.descriptors().len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Common proxy requires matching carrier duplex and one immutable record descriptor",
        ));
    }
    let maximum = config
        .max_user()?
        .checked_add(super::record::FRAME_OVERHEAD)
        .ok_or_else(|| invalid("proxy frame maximum"))?;
    let initial = catalog.initial();
    for role in [
        l2tunnel_management::Role::Client,
        l2tunnel_management::Role::Server,
    ] {
        let direction = initial.direction(role);
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
    run_selected(
        device, parts, contract, config, control, None, requests, observe,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_selected<D>(
    device: D,
    parts: member::Parts,
    contract: transport::CommonTransactionContract,
    config: Config,
    control: Control,
    measured_config: Option<measured::Config>,
    requests: Option<transport::CommonControlRequests>,
    observe: impl FnMut(&transport::CommonSnapshot) + Send,
) -> impl std::future::Future<Output = io::Result<CloseReport>> + Send
where
    D: PacketDevice<Error = io::Error> + Send,
{
    let info = parts.info;
    let setup = parts.deadline;
    run_selected_io(
        device,
        info,
        setup,
        contract,
        config,
        control,
        measured_config,
        move |port, bridge, contract, stopped| {
            transport::run_common_proxy_records(
                port,
                bridge,
                parts,
                contract,
                requests,
                async move {
                    let _ = stopped.await;
                },
                observe,
            )
        },
    )
}

// Both call sites still transfer genuine member-owned Parts into the actual
// Driver. Info is copied observation only and cannot create a root or I/O owner.
#[allow(clippy::too_many_arguments)]
fn run_selected_io<D, R>(
    device: D,
    info: member::Info,
    setup: Instant,
    contract: transport::CommonTransactionContract,
    config: Config,
    control: Control,
    measured_config: Option<measured::Config>,
    prepare_runtime: impl FnOnce(
        super::common_bridge::RecordPort,
        super::common_bridge::Bridge,
        transport::CommonTransactionContract,
        tokio::sync::oneshot::Receiver<()>,
    ) -> R,
) -> impl std::future::Future<Output = io::Result<CloseReport>> + Send
where
    D: PacketDevice<Error = io::Error> + Send,
    R: std::future::Future<Output = io::Result<transport::CommonStopped>> + Send,
{
    let prepared = (|| {
        let binding = if let Some(measured) = &measured_config {
            validate_measured(measured, &contract)?;
            measured::session_config(measured)?
        } else {
            validate(&config, &contract)?;
            session_config(&config)?
        };
        if device.layer() != PacketLayer::Ip {
            return Err(invalid("Common proxy requires an IP attachment"));
        }
        if Instant::now() >= setup {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original Common proxy setup cap",
            ));
        }
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
        let retained = contract.proxy_retirement();
        let (port, stream, bridge) = if retained {
            super::common_bridge::pair_retained(maximum, contract.resources().native.stall_timeout)?
        } else {
            super::common_bridge::pair(maximum, contract.resources().native.stall_timeout)?
        };
        if measured_config.is_some() {
            bridge.enable_physical_receipts()?;
        }
        let (reader, writer) = tokio::io::split(stream);
        let link = Link {
            inner: crate::Link {
                reader: Box::pin(reader),
                writer: Box::pin(writer),
                reverse_reader: None,
                reverse_writer: None,
                layer: PacketLayer::Ip,
            },
            binding,
            originator: info.role == l2tunnel_security::Role::Initiator,
            logical,
            common_ordered: true,
        };
        let readiness = measured_profile::Readiness::new(&control, measured_config.is_some())?;
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        // Eager fallible Driver preparation finishes before the returned service
        // future is polled; it starts no child task or physical packet I/O.
        let runtime = prepare_runtime(port, bridge.clone(), contract, stopped);
        Ok((bridge, link, readiness, setup, retained, stop, runtime))
    })();
    async move {
        let (bridge, link, mut readiness, setup, retained, stop, runtime) = prepared?;
        let actor = actor::run_profile_selected(
            device,
            link,
            config,
            control,
            measured_config,
            true,
            retained.then_some(bridge.clone()),
        );
        tokio::pin!(runtime, actor);
        let ready = async {
            loop {
                if readiness.forwarding() {
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
                // Poll ready physical callbacks before another Common work turn.
                // The bounded actor returns Pending; carrier progress still follows.
                biased;
                result = &mut actor => {
                    let _ = stop.send(());
                    let common = runtime.await;
                    let outcome = (|| {
                        let report = match result {
                            Ok(report) => report,
                            Err(error) => return Err(retain_joined_failure(
                                error, common.err(), FailureComponent::Actor,
                            )),
                        };
                        let stopped = common?;
                        if stopped.reason == transport::StopReason::ProxyRetired {
                            require_retired(&bridge)?;
                        } else if stopped.reason != transport::StopReason::Cancelled {
                            return Err(io::Error::other(format!("Common proxy ended before local close: {:?}", stopped.reason)));
                        }
                        if retained {
                            Ok(report)
                        } else {
                            Err(io::Error::new(io::ErrorKind::Unsupported,
                                "Common proxy graceful close has no retained reliable retirement owner"))
                        }
                    })();
                    bridge.fail();
                    return outcome;
                }
                result = &mut runtime => {
                    if matches!(&result, Ok(stopped) if stopped.reason == transport::StopReason::ProxyRetired) {
                        require_retired(&bridge)?;
                        // All child joins precede wait_retired. Its retained gate is
                        // already open, so only synchronous final publication remains.
                        // Never await a stuck actor beyond the original drain cap.
                        let report = finish_joined_actor(actor.as_mut()).await;
                        bridge.fail();
                        return report;
                    }
                    bridge.fail();
                    let joined = actor.await.err(); // Same owner performs abnormal cleanup and actual joins.
                    let error = match result {
                        Err(error) => error,
                        Ok(stopped) => io::Error::other(format!("Common proxy carrier ended: {:?}", stopped.reason)),
                    };
                    return Err(retain_joined_failure(error, joined, FailureComponent::Common));
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

#[derive(Debug)]
enum FailureComponent {
    Common,
    Actor,
}

#[derive(Debug)]
struct JoinedFailure {
    primary: io::Error,
    joined: io::Error,
    component: FailureComponent,
}

impl std::fmt::Display for JoinedFailure {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (common, actor) = match self.component {
            FailureComponent::Common => (&self.primary, &self.joined),
            FailureComponent::Actor => (&self.joined, &self.primary),
        };
        write!(output, "Common runtime: {common}; proxy actor: {actor}")
    }
}

impl std::error::Error for JoinedFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}

/// Preserve the selected branch's error precedence without inferring the order
/// in which the two independently observed failures occurred.
fn retain_joined_failure(
    primary: io::Error,
    joined: Option<io::Error>,
    component: FailureComponent,
) -> io::Error {
    let Some(joined) = joined else {
        return primary;
    };
    io::Error::new(
        primary.kind(),
        JoinedFailure {
            primary,
            joined,
            component,
        },
    )
}

fn require_retired(bridge: &super::common_bridge::Bridge) -> io::Result<()> {
    if bridge.retired()? {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Common proxy retirement result lacks its retained barrier",
        ))
    }
}

async fn finish_joined_actor<T>(
    mut actor: std::pin::Pin<&mut impl std::future::Future<Output = io::Result<T>>>,
) -> io::Result<T> {
    std::future::poll_fn(|cx| {
        std::task::Poll::Ready(match actor.as_mut().poll(cx) {
            std::task::Poll::Ready(result) => result,
            std::task::Poll::Pending => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "joined Common proxy actor did not finish at its original cap",
            )),
        })
    })
    .await
}

#[cfg(test)]
mod close_completion_tests {
    use super::*;

    #[test]
    fn joined_proxy_failures_preserve_both_causes_and_selected_precedence() -> io::Result<()> {
        for component in [FailureComponent::Common, FailureComponent::Actor] {
            let common = io::Error::new(io::ErrorKind::ConnectionRefused, "closed record port");
            let actor = io::Error::other("Record(HandoffExpired)");
            let (primary, joined, expected) = match component {
                FailureComponent::Common => (common, actor, io::ErrorKind::ConnectionRefused),
                FailureComponent::Actor => (actor, common, io::ErrorKind::Other),
            };
            let error = retain_joined_failure(primary, Some(joined), component);
            assert_eq!(error.kind(), expected);
            let details = error
                .get_ref()
                .and_then(|source| source.downcast_ref::<JoinedFailure>())
                .ok_or_else(|| io::Error::other("joined failure was not retained"))?;
            assert_eq!(details.primary.kind(), expected);
            assert!(std::ptr::eq(
                std::error::Error::source(details)
                    .and_then(|source| source.downcast_ref::<io::Error>())
                    .ok_or_else(|| io::Error::other("primary source was not retained"))?,
                &details.primary,
            ));
            assert_eq!(
                error.to_string(),
                "Common runtime: closed record port; proxy actor: Record(HandoffExpired)",
            );
        }
        Ok(())
    }

    #[test]
    fn single_proxy_failure_keeps_original_error_without_wrapper() {
        for component in [FailureComponent::Common, FailureComponent::Actor] {
            let original = io::Error::from(io::ErrorKind::ConnectionRefused);
            let text = original.to_string();
            let error = retain_joined_failure(original, None, component);
            assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
            assert_eq!(error.to_string(), text);
            assert!(error.get_ref().is_none());
        }
    }

    #[tokio::test]
    async fn retired_actor_completion_is_one_poll_and_preserves_failure() -> io::Result<()> {
        let pending = std::future::pending::<io::Result<()>>();
        tokio::pin!(pending);
        assert_eq!(
            finish_joined_actor(pending.as_mut())
                .await
                .err()
                .ok_or_else(|| io::Error::other("pending actor unexpectedly completed"))?
                .kind(),
            io::ErrorKind::TimedOut,
        );
        let failed = std::future::ready(Err::<(), _>(io::Error::new(
            io::ErrorKind::InvalidData,
            "original actor publication failure",
        )));
        tokio::pin!(failed);
        let error = finish_joined_actor(failed.as_mut())
            .await
            .err()
            .ok_or_else(|| io::Error::other("failed actor unexpectedly completed"))?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "original actor publication failure");
        let complete = std::future::ready(Ok(7));
        tokio::pin!(complete);
        assert_eq!(finish_joined_actor(complete.as_mut()).await?, 7);
        Ok(())
    }
}
