//! Fixed proxy on the same actual original raw TLS/Noise/member owner.
use super::*;
use crate::raw_packet::common::{PacketOpener, PacketOwner, Settings as RawSettings};
use l2tunnel_runtime::secure_udp::{member, transport};

/// Selected setup only; Run retains Active before starting actor child I/O.
pub(in crate::service::owner) async fn common(
    shared: &Arc<Shared>,
    plan: &Prepared,
    accepted: Accepted,
    deadline: Instant,
    requested: Arc<crate::secure_udp::common_transaction_profile::Profile>,
    raw: Arc<RawSettings>,
    opener: PacketOpener,
) -> io::Result<Active> {
    let super::super::common::raw::Authenticated {
        effective,
        parts,
        contract,
    } = super::super::common::raw::authenticate(
        shared,
        plan,
        accepted,
        deadline,
        requested.clone(),
        raw,
        opener,
    )
    .await?;
    let info = parts.info();
    let config = effective.proxy_config().cloned().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing explicit raw Common proxy policy",
        )
    })?;
    if effective.proxy_measured_config().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "raw Common proxy measured controller is not installed",
        ));
    }
    let digest = runtime::session_config(&config)?.digest;
    let carrier = effective.establish_config(info.role)?.binding.carrier;
    check(deadline)?;
    setup::stage(shared, accepted.operation, SetupStage::Attachment);
    let device = plan.open().inspect_err(|_| {
        setup::reason(shared, accepted.operation, SetupFailureReason::LocalIo);
    })?;
    check(deadline)?;
    let frame = ProxyCommonFrame {
        requested_configuration: requested.requested_configuration()?,
        effective_configuration: contract.expected_configuration(),
        requested_carrier: carrier,
        effective_carrier: info.authenticated.carrier,
        requested_cover: requested.settings().cover.appearance,
        effective_cover: None,
        compact_wire: Some(
            crate::secure_udp::common_status::CompactWireStatus::observe(
                requested.compact_wire(),
                None,
            )?,
        ),
        maintained_request: None,
        maintained: None,
        local_addr: info.local_addr,
        peer_addr: info.peer_addr,
        installed: false,
        running: false,
        epoch: None,
        liveness: Default::default(),
        hot_switch: false,
        socket_accepted_packets: 0,
        socket_accepted_ip_bytes: 0,
        graceful_close: effective.proxy_retirement(),
    };
    let (handle, control) = crate::proxy::control_channel();
    let backend = Arc::new(Backend::common(handle, digest, &config, frame));
    let runtime = make_runtime(
        device,
        parts,
        contract,
        config,
        control,
        backend.clone(),
        shared.clone(),
    );
    Ok(Active {
        runtime,
        backend: ObservedBackend::Proxy(backend),
        generation: accepted.operation,
    })
}

// Keep eager fallible Driver construction outside readiness poll nesting. No
// extra task/FSM or loss of original accepted setup deadline is introduced.
#[inline(never)]
fn make_runtime(
    device: crate::service::prepared::Device,
    parts: member::raw_carrier::RawInitialParts<PacketOwner>,
    contract: transport::CommonTransactionContract,
    config: runtime::Config,
    control: runtime::Control,
    backend: Arc<Backend>,
    changed: Arc<Shared>,
) -> RunFuture {
    let sink = backend.clone();
    let driver = runtime::common::run_on_raw(
        device,
        parts,
        contract,
        config,
        control,
        None,
        move |snapshot| {
            sink.observe_common(snapshot);
            changed.changed();
        },
    );
    Box::pin(async move {
        let result = driver.await;
        backend.finished(&result);
        result.map(|_| ())
    })
}
