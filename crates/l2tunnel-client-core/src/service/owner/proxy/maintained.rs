//! Existing proxy actors using the actual authenticated retained TLS/QUIC owner.
use super::*;

pub(in crate::service::owner) async fn common(
    shared: &Arc<Shared>,
    plan: &Prepared,
    accepted: Accepted,
    deadline: Instant,
    profile: Arc<crate::secure_udp::common_transaction_profile::Profile>,
) -> io::Result<Active> {
    let requested = profile.clone();
    let super::super::common::maintained::Authenticated {
        effective,
        parts,
        contract,
    } = super::super::common::maintained::authenticate(shared, plan, accepted, deadline, profile)
        .await?;
    let info = parts.info;
    let profile = effective;
    let config = profile.proxy_config().cloned().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing maintained Common proxy policy",
        )
    })?;
    let measured = profile.proxy_measured_config().cloned();
    let digest = match &measured {
        Some(config) => runtime::measured::session_config(config)?.digest,
        None => runtime::session_config(&config)?.digest,
    };
    let carrier = profile.establish_config(info.role)?.binding.carrier;
    setup::stage(shared, accepted.operation, SetupStage::Attachment);
    let device = plan.open()?;
    check(deadline)?;
    let frame = ProxyCommonFrame {
        requested_configuration: requested.requested_configuration()?,
        effective_configuration: l2tunnel_security::ConfigDigest(info.authenticated.configuration),
        requested_carrier: carrier,
        effective_carrier: info.authenticated.carrier,
        requested_cover: profile.settings().cover.appearance,
        effective_cover: None,
        compact_wire: Some(
            crate::secure_udp::common_status::CompactWireStatus::observe(
                profile.compact_wire(),
                None,
            )?,
        ),
        maintained_request: profile
            .maintained_settings()
            .map(|settings| settings.request(profile.connection()))
            .transpose()?,
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
        graceful_close: profile.proxy_retirement(),
    };
    let observe = |backend: &Arc<Backend>| {
        let sink = backend.clone();
        let changed = shared.clone();
        move |snapshot: &l2tunnel_runtime::secure_udp::transport::CommonSnapshot| {
            sink.observe_common(snapshot);
            changed.changed();
        }
    };
    type Driver =
        Pin<Box<dyn std::future::Future<Output = io::Result<runtime::CloseReport>> + Send>>;
    let (backend, driver): (Arc<Backend>, Driver) = match measured {
        Some(config) => {
            let (handle, control) = crate::proxy_measured::control_channel();
            let backend = Arc::new(Backend::common_measured(
                handle,
                digest,
                &config.fixed,
                frame,
            ));
            let driver = runtime::common::run_measured_on_maintained(
                device,
                parts,
                contract,
                config,
                control,
                None,
                observe(&backend),
            );
            (backend, Box::pin(driver))
        }
        None => {
            let (handle, control) = crate::proxy::control_channel();
            let backend = Arc::new(Backend::common(handle, digest, &config, frame));
            let driver = runtime::common::run_on_maintained(
                device,
                parts,
                contract,
                config,
                control,
                None,
                observe(&backend),
            );
            (backend, Box::pin(driver))
        }
    };
    let observed = backend.clone();
    let runtime = Box::pin(async move {
        let result = driver.await;
        observed.finished(&result);
        result.map(|_| ())
    });
    Ok(Active {
        runtime,
        backend: ObservedBackend::Proxy(backend),
        generation: accepted.operation,
    })
}
