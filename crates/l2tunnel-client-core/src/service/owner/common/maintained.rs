//! Actual original maintained TLS/QUIC owners through the shared Common lifecycle.
use super::*;
use crate::secure_udp::maintained::{
    Client as OuterClient, Server as OuterServer, Settings, Transport,
};
use l2tunnel_runtime::secure_udp::{establish as authentication, member};
use l2tunnel_runtime::{retained_tls, secure_udp::maintained_io};
use l2tunnel_security::Role;
use tokio::net::TcpListener;

#[cfg(all(test, target_os = "linux"))]
#[path = "maintained_socket_tests.rs"]
mod socket_tests;

fn tls_client_socket(local: std::net::SocketAddr) -> io::Result<tokio::net::TcpSocket> {
    let socket = if local.is_ipv6() {
        tokio::net::TcpSocket::new_v6()?
    } else {
        tokio::net::TcpSocket::new_v4()?
    };
    // Fixed client ports can remain in TIME_WAIT after an orderly close. Linux
    // requires reuse on both the original socket and its replacement, before bind.
    // Windows gives this option different active-address ownership semantics.
    #[cfg(unix)]
    socket.set_reuseaddr(true)?;
    Ok(socket)
}

pub(in crate::service::owner) async fn establish(
    shared: &Arc<Shared>,
    plan: &Prepared,
    accepted: Accepted,
    deadline: Instant,
    requested: Arc<crate::secure_udp::common_transaction_profile::Profile>,
) -> io::Result<Active> {
    #[cfg(windows)]
    let device = {
        setup::stage(shared, accepted.operation, SetupStage::Attachment);
        let dev = plan.open_common_native().await.inspect_err(|_| {
            setup::reason(shared, accepted.operation, SetupFailureReason::LocalIo);
        })?;
        check(deadline)?;
        dev
    };
    let Authenticated {
        effective,
        parts,
        contract,
    } = authenticate(shared, plan, accepted, deadline, requested).await?;
    let info = parts.info;
    #[cfg(not(windows))]
    let device = {
        setup::stage(shared, accepted.operation, SetupStage::Attachment);
        plan.open_common_native().await.inspect_err(|_| {
            setup::reason(shared, accepted.operation, SetupFailureReason::LocalIo);
        })?
    };
    check(deadline)?;
    let (switcher, requests) = transport::common_channel();
    let requests = crate::service::device_mtu::tune(&plan.data.attachment, &effective, requests);
    let backend = Arc::new(SecureUdpCommonBackend {
        requested: effective,
        info,
        counters: Mutex::new(None),
        observed: Mutex::new(None),
        switcher,
        generation: accepted.operation.value(),
    });
    let runtime = make_runtime_on_maintained(
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
pub(in crate::service::owner) struct Authenticated {
    pub(in crate::service::owner) effective:
        Arc<crate::secure_udp::common_transaction_profile::Profile>,
    pub(in crate::service::owner) parts: member::maintained::InitialParts,
    pub(in crate::service::owner) contract: transport::CommonTransactionContract,
}

pub(in crate::service::owner) fn authenticate<'a>(
    shared: &'a Arc<Shared>,
    plan: &'a Prepared,
    accepted: Accepted,
    deadline: Instant,
    requested: Arc<crate::secure_udp::common_transaction_profile::Profile>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<Authenticated>> + Send + 'a>> {
    Box::pin(async move {
        let role = match &plan.data.endpoint {
            Endpoint::CommonMaintainedClient { .. } => Role::Initiator,
            Endpoint::CommonMaintainedServer(_) => Role::Responder,
            _ => return Err(invalid("missing independent outer/common credentials")),
        };
        let outer = establish_outer(shared, plan, accepted, deadline, &requested).await?;
        check(deadline)?;
        // Only the real completed TLS/QUIC owner supplies this proof. The original plan
        // remains immutable; all subsequent validation uses the effective profile.
        let effective = Arc::new(requested.bind_maintained(outer.authenticated())?);
        let config = effective.establish_config(role)?;
        // Live tuning (docs/modules/live-tuning.md): a client proposes its
        // choices in Noise message 1; a server judges them against its limits.
        let proposal = crate::secure_udp::live_tuning::proposal(&effective)?;
        let mut live_catalog = proposal.as_ref().map(|proposal| proposal.catalog.clone());
        let mut judge = |carried: &[u8]| {
            let (catalog, root) = crate::secure_udp::live_tuning::judge(&effective, role, carried)?;
            live_catalog = Some(catalog);
            Ok(root)
        };
        let mut entropy = authentication::RuntimeEntropy::new();
        let mut observe = |value| setup::runtime(shared, accepted.operation, value);
        let established = match &plan.data.endpoint {
            Endpoint::CommonMaintainedClient { inner, .. } => {
                outer
                    .connect_initial(
                        config,
                        inner.noise().attempt(),
                        inner.admission(),
                        &mut entropy,
                        &mut observe,
                        match &proposal {
                            Some(proposal) => authentication::Tuning::Propose {
                                proposal: &proposal.bytes,
                                context: proposal.root,
                            },
                            None => authentication::Tuning::Off,
                        },
                    )
                    .await
            }
            Endpoint::CommonMaintainedServer(server) => {
                setup::stage(shared, accepted.operation, SetupStage::AdmissionOwner);
                let mut admission = server.admission.lock().await;
                check(deadline)?;
                // A new actual maintained proof has a different Noise prologue. Retain its
                // quarantine through this attempt; never reuse another proof's gate.
                *admission = Some(
                    authentication::maintained::InitialServerAdmission::new(
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
                        authentication::Tuning::Judge(&mut judge),
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
            Endpoint::CommonMaintainedClient { inner, .. } => {
                member::maintained::connect_initial(
                    established,
                    inner.member(),
                    settings,
                    &mut observe,
                )
                .await?
            }
            Endpoint::CommonMaintainedServer(_) => {
                let members = l2tunnel_identity::Allowlist::new(&[effective.settings().member])
                    .map_err(io::Error::other)?;
                member::maintained::accept_initial(established, members, settings, &mut observe)
                    .await?
            }
            _ => return Err(invalid("prepared member endpoint/backend mismatch")),
        };
        check(deadline)?;
        let info = session.info();
        setup::stage(shared, accepted.operation, SetupStage::Configuration);
        // A tuned session switches within the catalog both ends generated.
        let effective = match live_catalog {
            Some(catalog) => Arc::new(effective.with_live_catalog(catalog)?),
            None => effective,
        };
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
fn make_runtime_on_maintained(
    device: crate::native::Native,
    parts: member::maintained::InitialParts,
    contract: transport::CommonTransactionContract,
    requests: transport::CommonControlRequests,
    sink: Arc<SecureUdpCommonBackend>,
    changed: Arc<Shared>,
) -> RunFuture {
    let runtime = transport::run_common_on_maintained(
        device,
        parts,
        contract,
        Some(requests),
        std::future::pending::<()>(),
        move |snapshot| {
            sink.store(snapshot);
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

fn remaining(deadline: Instant) -> io::Result<std::time::Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or_else(expired)
}
async fn establish_outer(
    shared: &Arc<Shared>,
    plan: &Prepared,
    accepted: Accepted,
    deadline: Instant,
    profile: &crate::secure_udp::common_transaction_profile::Profile,
) -> io::Result<authentication::maintained::Outer> {
    let settings = profile
        .maintained_settings()
        .ok_or_else(|| invalid("maintained selection absent"))?;
    let request = settings.request(profile.connection())?;
    let base = profile.maintained_session()?;
    let capacity = profile.parameters().retained_bytes;
    setup::stage(shared, accepted.operation, SetupStage::SocketBind);
    let owner = match settings.transport {
        Transport::Tls(limits) => {
            let link = tls_lanes(shared, plan, accepted, deadline, settings, base).await?;
            maintained_io::Carrier::tls(link, limits, request, base, capacity)?
        }
        Transport::Quic(profiles) => {
            let values =
                quic_lanes(shared, plan, accepted, deadline, settings, profiles, base).await?;
            maintained_io::Carrier::quic(values, request, base, capacity)?
        }
    };
    authentication::maintained::Outer::from_carrier(owner).map_err(authentication_error)
}
async fn tls_lanes(
    shared: &Arc<Shared>,
    plan: &Prepared,
    accepted: Accepted,
    deadline: Instant,
    settings: Settings,
    base: l2tunnel_auth::SessionConfig,
) -> io::Result<retained_tls::Link> {
    let Transport::Tls(limits) = settings.transport else {
        return Err(invalid("TLS framing limits absent"));
    };
    let trace_socket_error = |stage: &str,
                              local: std::net::SocketAddr,
                              peer: std::net::SocketAddr,
                              error: &io::Error| {
        if std::env::var_os("L2TUNNEL_TRACE_FAILURE").is_some() {
            eprintln!(
                "Common TLS socket failure: operation={:?} stage={stage} local={local} peer={peer} kind={:?} errno={:?}",
                accepted.operation,
                error.kind(),
                error.raw_os_error(),
            );
        }
    };
    let paths = [Some(settings.first), settings.second];
    let mut lanes = Vec::with_capacity(if settings.second.is_some() { 2 } else { 1 });
    match &plan.data.endpoint {
        Endpoint::CommonMaintainedClient {
            outer: OuterClient::Tls(credentials),
            ..
        } => {
            for path in paths.into_iter().flatten() {
                check(deadline)?;
                let socket = tls_client_socket(path.client)?;
                setup::stage(shared, accepted.operation, SetupStage::SocketBind);
                socket.bind(path.client).inspect_err(|error| {
                    trace_socket_error("client-bind", path.client, path.server, error);
                })?;
                setup::stage(shared, accepted.operation, SetupStage::SocketConnect);
                let stream = socket.connect(path.server).await.inspect_err(|error| {
                    trace_socket_error("client-connect", path.client, path.server, error);
                })?;
                check(deadline)?;
                if stream.local_addr()? != path.client || stream.peer_addr()? != path.server {
                    return Err(invalid("actual TLS client endpoints differ"));
                }
                stream.set_nodelay(true)?;
                let connection = l2tunnel_auth::client_connect(
                    stream,
                    &credentials.tls,
                    &credentials.server_name,
                    &credentials.member,
                    base,
                    remaining(deadline)?,
                )
                .await
                .map_err(io::Error::other)?;
                check(deadline)?;
                lanes.push(connection);
            }
        }
        Endpoint::CommonMaintainedServer(server) => {
            let OuterServer::Tls(credentials) = &server.outer else {
                return Err(invalid("TLS server credentials absent"));
            };
            let mut listeners = Vec::with_capacity(lanes.capacity());
            for path in paths.into_iter().flatten() {
                let listener = TcpListener::bind(path.server).await.inspect_err(|error| {
                    trace_socket_error("server-bind", path.server, path.client, error);
                })?;
                listeners.push((listener, path));
                check(deadline)?;
            }
            shared.lock().snapshot.listening = Some(Listening {
                operation: accepted.operation,
                address: listeners
                    .first()
                    .ok_or_else(|| invalid("missing first TLS listener"))?
                    .0
                    .local_addr()?,
            });
            shared.changed();
            for (listener, path) in listeners {
                let (stream, peer) = listener.accept().await.inspect_err(|error| {
                    trace_socket_error("server-accept", path.server, path.client, error);
                })?;
                check(deadline)?;
                if peer != path.client || stream.local_addr()? != path.server {
                    return Err(invalid("actual TLS server endpoints differ"));
                }
                stream.set_nodelay(true)?;
                let connection = l2tunnel_auth::server_accept(
                    stream,
                    &credentials.tls,
                    &credentials.members,
                    base,
                    remaining(deadline)?,
                )
                .await
                .map_err(io::Error::other)?;
                check(deadline)?;
                lanes.push(connection);
            }
        }
        _ => return Err(invalid("maintained TLS credentials absent")),
    }
    let mut lanes = lanes.into_iter();
    let first = lanes
        .next()
        .ok_or_else(|| invalid("missing first TLS lane"))?;
    match lanes.next() {
        None => retained_tls::Link::full(first, deadline, limits),
        Some(second) => {
            if matches!(&plan.data.endpoint, Endpoint::CommonMaintainedClient { .. }) {
                retained_tls::client_pair(first, second, deadline, limits).await
            } else {
                retained_tls::server_pair(first, second, deadline, limits).await
            }
        }
    }
}
async fn quic_lanes(
    shared: &Arc<Shared>,
    plan: &Prepared,
    accepted: Accepted,
    deadline: Instant,
    settings: Settings,
    profiles: [Option<l2tunnel_quic::Profile>; 2],
    base: l2tunnel_auth::SessionConfig,
) -> io::Result<Vec<l2tunnel_quic::common::Carrier>> {
    let first_profile = profiles[0].ok_or_else(|| invalid("missing QUIC profile"))?;
    let expected = [first_profile, profiles[1].unwrap_or(first_profile)];
    let count = if settings.second.is_some() { 2 } else { 1 };
    let limits = l2tunnel_quic::EndpointLimits {
        max_connections: 1,
        pending_connections: 4,
        handshake_timeout: remaining(deadline)?,
    };
    let paths = [Some(settings.first), settings.second];
    let mut values = Vec::with_capacity(count);
    match &plan.data.endpoint {
        Endpoint::CommonMaintainedClient {
            outer:
                OuterClient::Quic {
                    roots,
                    server_name,
                    member,
                },
            ..
        } => {
            let mut endpoints = Vec::with_capacity(count);
            for (path, profile) in paths.into_iter().flatten().zip(expected) {
                let config = l2tunnel_quic::ClientConfig::from_der_roots(roots, profile, limits)
                    .map_err(io::Error::other)?;
                endpoints.push((
                    l2tunnel_quic::ClientEndpoint::bind(path.client, &config)
                        .map_err(io::Error::other)?,
                    path,
                ));
                check(deadline)?;
            }
            for (endpoint, path) in endpoints {
                let value = endpoint
                    .connect(path.server, server_name, member, base)
                    .await
                    .map_err(io::Error::other)?;
                check(deadline)?;
                if value.local_addr().map_err(io::Error::other)? != path.client
                    || value.peer_addr() != path.server
                {
                    return Err(invalid("actual QUIC client endpoints differ"));
                }
                values.push(value);
            }
        }
        Endpoint::CommonMaintainedServer(server) => {
            let OuterServer::Quic {
                certs,
                key,
                members,
            } = &server.outer
            else {
                return Err(invalid("QUIC server credentials absent"));
            };
            let mut endpoints = Vec::with_capacity(count);
            for (path, profile) in paths.into_iter().flatten().zip(expected) {
                let config = l2tunnel_quic::ServerConfig::from_der(certs, key, profile, limits)
                    .map_err(io::Error::other)?;
                endpoints.push((
                    l2tunnel_quic::ServerEndpoint::bind(path.server, &config)
                        .map_err(io::Error::other)?,
                    path,
                ));
                check(deadline)?;
            }
            shared.lock().snapshot.listening = Some(Listening {
                operation: accepted.operation,
                address: endpoints
                    .first()
                    .ok_or_else(|| invalid("missing first QUIC listener"))?
                    .0
                    .local_addr()
                    .map_err(io::Error::other)?,
            });
            shared.changed();
            for (endpoint, path) in endpoints {
                let value = endpoint
                    .accept(members, base)
                    .await
                    .map_err(io::Error::other)?;
                check(deadline)?;
                if value.local_addr().map_err(io::Error::other)? != path.server
                    || value.peer_addr() != path.client
                {
                    return Err(invalid("actual QUIC server endpoints differ"));
                }
                values.push(value);
            }
        }
        _ => return Err(invalid("maintained QUIC credentials absent")),
    }
    let mut values = values.into_iter();
    let first = values
        .next()
        .ok_or_else(|| invalid("missing QUIC first lane"))?;
    match values.next() {
        None => Ok(vec![
            l2tunnel_quic::common::Carrier::new(first, expected[0], base, deadline)
                .map_err(io::Error::other)?,
        ]),
        Some(second) => {
            let paired =
                if matches!(&plan.data.endpoint, Endpoint::CommonMaintainedClient { .. }) {
                    l2tunnel_quic::common::client_pair(first, second, expected, base, deadline)
                        .await
                } else {
                    l2tunnel_quic::common::server_pair(first, second, expected, base, deadline)
                        .await
                }
                .map_err(io::Error::other)?;
            Ok(Vec::from(paired))
        }
    }
}
