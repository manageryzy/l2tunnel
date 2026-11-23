//! Common backend using the original service actor and UDP factory.

use super::*;
use l2tunnel::record_configuration::Configuration;
use l2tunnel_runtime::secure_udp::transport;

#[cfg(unix)]
pub(super) mod carrier;
#[cfg(unix)]
pub(super) mod maintained;
#[cfg(unix)]
pub(super) mod raw;

pub(super) async fn establish(
    shared: &Arc<Shared>,
    plan: &Prepared,
    accepted: Accepted,
    deadline: Instant,
    profile: Arc<crate::secure_udp::common_transaction_profile::Profile>,
) -> io::Result<Active> {
    let session = authenticate_selected_secure_udp(
        shared,
        plan,
        accepted,
        deadline,
        profile.settings(),
        Some(profile.as_ref()),
    )
    .await?;
    let info = session.info();
    setup::stage(shared, accepted.operation, SetupStage::Configuration);
    let contract = profile.runtime_contract(info.role)?;
    if info.peers != profile.peers()
        || info.authenticated.configuration != contract.expected_configuration().0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "actual authentication differs from the complete Common plan",
        ));
    }
    let parts = session.into_parts();
    setup::stage(shared, accepted.operation, SetupStage::Attachment);
    let device = plan.open_common_native().await.inspect_err(|_| {
        setup::reason(shared, accepted.operation, SetupFailureReason::LocalIo);
    })?;
    check(deadline)?;
    let (switcher, requests) = transport::common_channel();
    let backend = Arc::new(SecureUdpCommonBackend {
        requested: profile,
        info,
        counters: Mutex::new(None),
        switcher,
        generation: accepted.operation.value(),
    });
    let sink = backend.clone();
    let changed = shared.clone();
    let runtime = make_runtime(device, parts, contract, requests, sink, changed);
    ready(shared, accepted, deadline, backend, runtime).await
}

async fn ready(
    shared: &Arc<Shared>,
    accepted: Accepted,
    deadline: Instant,
    backend: Arc<SecureUdpCommonBackend>,
    mut runtime: RunFuture,
) -> io::Result<Active> {
    setup::stage(shared, accepted.operation, SetupStage::DriverReadiness);
    use l2tunnel_runtime::initialization_timing::{
        Outcome as TimingOutcome, Owner as TimingOwner, Stage as TimingStage, Timing,
    };
    let mut timing = Timing::from_environment(TimingOwner::CommonReadiness, Instant::now());
    timing.enter_at(TimingStage::FirstRunning, Instant::now());
    let result = std::future::poll_fn(|cx| match runtime.as_mut().poll(cx) {
        Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        Poll::Ready(Ok(())) => Poll::Ready(Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Common secure UDP runtime ended during readiness",
        ))),
        Poll::Pending
            if backend
                .counters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .is_some_and(|snapshot| snapshot.running) =>
        {
            Poll::Ready(Ok(()))
        }
        Poll::Pending => Poll::Pending,
    })
    .await
    .inspect_err(|_| {
        setup::reason(
            shared,
            accepted.operation,
            SetupFailureReason::ReadinessEnded,
        );
    });
    timing.end_at(
        Instant::now(),
        if result.is_ok() {
            TimingOutcome::Complete
        } else {
            TimingOutcome::Failed
        },
    );
    result?;
    check(deadline)?;
    Ok(Active {
        runtime,
        backend: ObservedBackend::SecureUdpCommon(backend),
        generation: accepted.operation,
    })
}

// run_common completes actual fallible runtime construction here, before the
// service readiness poll. The existing boxed service future owns its small
// continuation and the same Driver cell; no independent task is scheduled.
#[inline(never)]
fn make_runtime(
    device: crate::native::Native,
    parts: l2tunnel_runtime::secure_udp::member::Parts,
    contract: transport::CommonTransactionContract,
    requests: transport::CommonControlRequests,
    sink: Arc<SecureUdpCommonBackend>,
    changed: Arc<Shared>,
) -> RunFuture {
    let runtime = transport::run_common(
        device,
        parts,
        contract,
        Some(requests),
        std::future::pending::<()>(),
        move |snapshot| {
            *sink
                .counters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(snapshot.clone());
            changed.changed();
        },
    );
    Box::pin(async move {
        let stopped = runtime.await?;
        Err(secure_udp_termination(stopped.reason))
    })
}

pub(super) async fn apply(
    backend: &SecureUdpCommonBackend,
    configuration: Configuration,
) -> Completed {
    let outcome = backend.switcher.switch(configuration).await;
    match outcome {
        Ok(epoch) => {
            let actual = backend
                .counters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if actual
                .as_ref()
                .is_none_or(|snapshot| snapshot.epoch != epoch || snapshot.current != configuration)
            {
                return Completed::OutcomeUnknown;
            }
        }
        Err(transport::SwitchError::Closed) => return Completed::OutcomeUnknown,
        Err(_) => {}
    }
    Completed::Common {
        configuration,
        outcome,
    }
}
