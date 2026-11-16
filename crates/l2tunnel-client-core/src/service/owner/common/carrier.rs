//! Actual original OpenVPN owner through the shared Common service lifecycle.
use super::*;
use l2tunnel_openvpn::wire_carrier::{self, common as opaque};
use l2tunnel_runtime::secure_udp::{establish as authentication, member};
use l2tunnel_security::Role;

pub(in crate::service::owner) async fn establish(
    shared: &Arc<Shared>,
    plan: &Prepared,
    accepted: Accepted,
    deadline: Instant,
    requested: Arc<crate::secure_udp::common_transaction_profile::Profile>,
    outer_config: opaque::Config,
) -> io::Result<Active> {
    let Authenticated {
        effective,
        parts,
        contract,
    } = authenticate(shared, plan, accepted, deadline, requested, outer_config).await?;
    let info = parts.info;
    setup::stage(shared, accepted.operation, SetupStage::Attachment);
    let device = plan.open_readable().inspect_err(|_| {
        setup::reason(shared, accepted.operation, SetupFailureReason::LocalIo);
    })?;
    check(deadline)?;
    let (switcher, requests) = transport::common_channel();
    let backend = Arc::new(SecureUdpCommonBackend {
        requested: effective,
        info,
        counters: Mutex::new(None),
        switcher,
        generation: accepted.operation.value(),
    });
    let runtime = make_runtime_on_carrier(
        device,
        parts,
        contract,
        requests,
        backend.clone(),
        shared.clone(),
    );
    ready(shared, accepted, deadline, backend, runtime).await
}

// Complete and release authentication polling before eager runtime construction.
// The same opaque Parts cross this boundary; no copied Driver or new I/O task exists.
struct Authenticated {
    effective: Arc<crate::secure_udp::common_transaction_profile::Profile>,
    parts: member::carrier::InitialParts,
    contract: transport::CommonTransactionContract,
}

fn authenticate<'a>(
    shared: &'a Arc<Shared>,
    plan: &'a Prepared,
    accepted: Accepted,
    deadline: Instant,
    requested: Arc<crate::secure_udp::common_transaction_profile::Profile>,
    outer_config: opaque::Config,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<Authenticated>> + Send + 'a>> {
    Box::pin(async move {
        let role = match &plan.data.endpoint {
            Endpoint::CommonCarrierClient { .. } => Role::Initiator,
            Endpoint::CommonCarrierServer(_) => Role::Responder,
            _ => return Err(invalid("missing independent outer/common credentials")),
        };
        let path = requested.settings().gate.path;
        let (local, peer) = match role {
            Role::Initiator => (path.client, path.server),
            Role::Responder => (path.server, path.client),
        };
        check(deadline)?;
        setup::stage(shared, accepted.operation, SetupStage::SocketBind);
        let socket = tokio::net::UdpSocket::bind(local).await.inspect_err(|_| {
            setup::reason(shared, accepted.operation, SetupFailureReason::LocalIo);
        })?;
        setup::stage(shared, accepted.operation, SetupStage::SocketConnect);
        socket.connect(peer).await.inspect_err(|_| {
            setup::reason(shared, accepted.operation, SetupFailureReason::LocalIo);
        })?;
        check(deadline)?;
        if role == Role::Responder {
            shared.lock().snapshot.listening = Some(Listening {
                operation: accepted.operation,
                address: socket.local_addr()?,
            });
            shared.changed();
        }
        setup::stage(shared, accepted.operation, SetupStage::Configuration);
        let outer = match &plan.data.endpoint {
            Endpoint::CommonCarrierClient { outer, .. } => {
                authentication::carrier::Outer::client(
                    socket,
                    outer_config,
                    wire_carrier::ClientCredentials {
                        tls: &outer.tls,
                        server_name: &outer.server_name,
                        member: &outer.member,
                    },
                    deadline,
                )
                .await
            }
            Endpoint::CommonCarrierServer(server) => {
                authentication::carrier::Outer::server(
                    socket,
                    outer_config,
                    wire_carrier::ServerCredentials {
                        tls: &server.outer.tls,
                        members: &server.outer.members,
                    },
                    deadline,
                )
                .await
            }
            _ => return Err(invalid("prepared outer endpoint/backend mismatch")),
        }
        .map_err(authentication_error)?;
        check(deadline)?;
        // Only the real completed TLS owner supplies this proof. The original plan
        // remains immutable; all subsequent validation uses the effective profile.
        let effective = Arc::new(requested.bind_outer(outer.authenticated())?);
        let config = effective.establish_config(role)?;
        let mut entropy = authentication::RuntimeEntropy::new();
        let mut observe = |value| setup::runtime(shared, accepted.operation, value);
        let established = match &plan.data.endpoint {
            Endpoint::CommonCarrierClient { inner, .. } => {
                outer
                    .connect_initial(
                        config,
                        inner.noise().attempt(),
                        inner.admission(),
                        &mut entropy,
                        &mut observe,
                    )
                    .await
            }
            Endpoint::CommonCarrierServer(server) => {
                setup::stage(shared, accepted.operation, SetupStage::AdmissionOwner);
                let mut admission = server.admission.lock().await;
                check(deadline)?;
                // A new actual TLS proof has a different Noise prologue. Retain its
                // quarantine through this attempt; never reuse another proof's gate.
                *admission = Some(
                    authentication::carrier::InitialServerAdmission::new(
                        &outer,
                        config,
                        server.inner.noise().peers(role),
                        server.inner.admission(),
                        server.inner.cookie(),
                        Instant::now(),
                    )
                    .map_err(authentication_error)?,
                );
                outer
                    .accept_initial(
                        server.inner.noise().attempt(),
                        admission.as_mut().ok_or_else(|| {
                            io::Error::other("missing outer-bound admission owner")
                        })?,
                        &mut entropy,
                        &mut observe,
                    )
                    .await
            }
            _ => return Err(invalid("prepared inner endpoint/backend mismatch")),
        }
        .map_err(authentication_error)?;
        let binding = established.binding();
        let authenticated = established.authenticated();
        let peers = established.peers();
        let policy = effective.settings().membership;
        let settings = member::Settings {
            context: l2tunnel_identity::Context {
                session: binding.session,
                transcript: binding.transcript,
                configuration: authenticated.configuration,
                carrier: authenticated.carrier,
                outer: authenticated.outer,
                initiator_noise: l2tunnel_identity::NoisePublicKey(peers.initiator.0),
                responder_noise: l2tunnel_identity::NoisePublicKey(peers.responder.0),
            },
            retry_interval: policy.retry_interval,
            max_attempts: policy.max_attempts,
            receive_interval: policy.receive_interval,
            receive_packets_per_interval: policy.receive_packets_per_interval,
        };
        let session = match &plan.data.endpoint {
            Endpoint::CommonCarrierClient { inner, .. } => {
                member::carrier::connect_initial(
                    established,
                    inner.member(),
                    settings,
                    &mut observe,
                )
                .await?
            }
            Endpoint::CommonCarrierServer(_) => {
                let members = l2tunnel_identity::Allowlist::new(&[effective.settings().member])
                    .map_err(io::Error::other)?;
                member::carrier::accept_initial(established, members, settings, &mut observe)
                    .await?
            }
            _ => return Err(invalid("prepared member endpoint/backend mismatch")),
        };
        check(deadline)?;
        let info = session.info();
        setup::stage(shared, accepted.operation, SetupStage::Configuration);
        let contract = effective.runtime_contract(role)?;
        if info.role != role
            || info.peers != effective.peers()
            || info.authenticated.configuration != contract.expected_configuration().0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "actual carrier authentication differs from effective common plan",
            ));
        }
        let parts = session.into_parts();
        Ok(Authenticated {
            effective,
            parts,
            contract,
        })
    })
}

// Perform eager fallible Driver construction before readiness polling, keeping
// its constructor frames outside the selected service future's poll nesting.
#[inline(never)]
fn make_runtime_on_carrier(
    device: crate::swift::Native,
    parts: member::carrier::InitialParts,
    contract: transport::CommonTransactionContract,
    requests: transport::CommonControlRequests,
    sink: Arc<SecureUdpCommonBackend>,
    changed: Arc<Shared>,
) -> RunFuture {
    let runtime = transport::run_common_on_carrier(
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

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn authentication_error(error: authentication::Error) -> io::Error {
    let kind = match &error {
        authentication::Error::Deadline => io::ErrorKind::TimedOut,
        authentication::Error::Configuration(_) => io::ErrorKind::InvalidInput,
        authentication::Error::Io(error) => error.kind(),
        _ => io::ErrorKind::PermissionDenied,
    };
    io::Error::new(kind, error)
}
