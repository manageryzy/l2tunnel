//! Actual original raw Full/Half owners through the existing Common service actor.
use super::*;
use crate::raw_packet::common::{PacketOpener, PacketOwner, Settings as RawSettings};
use l2tunnel_raw_io::handoff::pairing::packet;
use l2tunnel_raw_tcp::Role as RawRole;
use l2tunnel_runtime::secure_udp::{establish as authentication, member};
use l2tunnel_security::Role;

pub(in crate::service::owner) async fn establish(
    shared: &Arc<Shared>,
    plan: &Prepared,
    accepted: Accepted,
    deadline: Instant,
    requested: Arc<crate::secure_udp::common_transaction_profile::Profile>,
    raw: Arc<RawSettings>,
    opener: PacketOpener,
) -> io::Result<Active> {
    let Authenticated {
        effective,
        parts,
        contract,
    } = authenticate(shared, plan, accepted, deadline, requested, raw, opener).await?;
    let info = parts.info();
    setup::stage(shared, accepted.operation, SetupStage::Attachment);
    let device = plan.open_native().inspect_err(|_| {
        setup::reason(shared, accepted.operation, SetupFailureReason::LocalIo);
    })?;
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
    let runtime = make_runtime_on_raw(
        device,
        parts,
        contract,
        requests,
        backend.clone(),
        shared.clone(),
    );
    ready(shared, accepted, deadline, backend, runtime).await
}

// Separate authentication polling from runtime construction. Their large owned
// setup/Engine scratch values must not occupy the same service poll stack.
pub(in crate::service::owner) struct Authenticated {
    pub(in crate::service::owner) effective:
        Arc<crate::secure_udp::common_transaction_profile::Profile>,
    pub(in crate::service::owner) parts: member::raw_carrier::RawInitialParts<PacketOwner>,
    pub(in crate::service::owner) contract: transport::CommonTransactionContract,
}

pub(in crate::service::owner) fn authenticate<'a>(
    shared: &'a Arc<Shared>,
    plan: &'a Prepared,
    accepted: Accepted,
    deadline: Instant,
    requested: Arc<crate::secure_udp::common_transaction_profile::Profile>,
    raw: Arc<RawSettings>,
    opener: PacketOpener,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<Authenticated>> + Send + 'a>> {
    Box::pin(async move {
        let role = match &plan.data.endpoint {
            Endpoint::CommonRawClient { .. } => Role::Initiator,
            Endpoint::CommonRawServer(_) => Role::Responder,
            _ => return Err(invalid("missing independent outer/common credentials")),
        };
        check(deadline)?;
        setup::stage(shared, accepted.operation, SetupStage::SocketBind);
        let original = raw
            .open(
                if role == Role::Initiator {
                    RawRole::Client
                } else {
                    RawRole::Server
                },
                deadline,
                &opener,
            )
            .inspect_err(|_| {
                setup::reason(shared, accepted.operation, SetupFailureReason::LocalIo)
            })?;
        if role == Role::Responder {
            shared.lock().snapshot.listening = Some(Listening {
                operation: accepted.operation,
                address: raw.forward().0.into(),
            });
            shared.changed();
        }
        check(deadline)?;
        setup::stage(shared, accepted.operation, SetupStage::Configuration);
        let phase = raw.phase(&requested)?;
        let factory = match &plan.data.endpoint {
            Endpoint::CommonRawClient { outer, .. } => packet::begin_packet_client(
                original,
                &outer.tls,
                &outer.server_name,
                &outer.member,
                phase,
            ),
            Endpoint::CommonRawServer(server) => packet::begin_packet_server(
                original,
                &server.outer.tls,
                &server.outer.members,
                phase,
            ),
            _ => return Err(invalid("prepared raw outer endpoint mismatch")),
        }
        .map_err(|failure| raw_setup_error("factory", failure.error))?;
        let mut factory = ObservedRawSetup {
            factory,
            operation: accepted.operation,
            trace: std::env::var_os("L2TUNNEL_TRACE_FAILURE").is_some(),
            finished: false,
        };
        // timeout_at polls its inner future before its timer. The original service
        // cap must forbid another actual PacketIo poll even when the factory began
        // later and therefore retains a later internal setup deadline.
        let carrier = std::future::poll_fn(|cx| factory.poll(cx, deadline)).await?;
        drop(factory);
        check(deadline)?;
        let outer = authentication::raw_carrier::RawOuter::from_packet(carrier)
            .and_then(|owner| owner.restrict_setup_deadline(deadline))
            .map_err(authentication_error)?;
        // Only the real completed TLS owner supplies this proof. The original plan
        // remains immutable; all subsequent validation uses the effective profile.
        let effective = Arc::new(requested.bind_raw(outer.authenticated())?);
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
            Endpoint::CommonRawClient { inner, .. } => {
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
            Endpoint::CommonRawServer(server) => {
                setup::stage(shared, accepted.operation, SetupStage::AdmissionOwner);
                let mut admission = server.admission.lock().await;
                check(deadline)?;
                // A new actual TLS proof has a different Noise prologue. Retain its
                // quarantine through this attempt; never reuse another proof's gate.
                *admission = Some(
                    authentication::raw_carrier::RawInitialServerAdmission::new(
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
            Endpoint::CommonRawClient { inner, .. } => {
                member::raw_carrier::connect_initial(
                    established,
                    inner.member(),
                    settings,
                    &mut observe,
                )
                .await?
            }
            Endpoint::CommonRawServer(_) => {
                let members = l2tunnel_identity::Allowlist::new(&[effective.settings().member])
                    .map_err(io::Error::other)?;
                member::raw_carrier::accept_initial(established, members, settings, &mut observe)
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
fn make_runtime_on_raw(
    device: crate::native::Native,
    parts: member::raw_carrier::RawInitialParts<PacketOwner>,
    contract: transport::CommonTransactionContract,
    requests: transport::CommonControlRequests,
    sink: Arc<SecureUdpCommonBackend>,
    changed: Arc<Shared>,
) -> RunFuture {
    let runtime = transport::run_common_on_raw(
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

fn raw_setup_error(boundary: &'static str, error: packet::Error) -> io::Error {
    if std::env::var_os("L2TUNNEL_TRACE_FAILURE").is_some() {
        eprintln!(
            "Common raw setup failure: boundary={boundary} cause={}",
            RawSetupCause(&error)
        );
    }
    raw_error(error)
}

// Retain the actual factory until its one terminal observation. The surrounding
// service can cancel before PacketSetup's later internal deadline; Drop observes
// the still-owned progress before that cancellation destroys original I/O.
struct ObservedRawSetup<'a> {
    factory: packet::PacketSetup<'a, PacketOwner>,
    operation: OperationId,
    trace: bool,
    finished: bool,
}
impl ObservedRawSetup<'_> {
    fn observe_terminal(&mut self, boundary: &'static str) {
        if !self.finished && self.trace {
            eprintln!(
                "Common raw setup snapshot: operation={} boundary={boundary} snapshot={:?}",
                self.operation.value(),
                self.factory.diagnostic_snapshot(),
            );
        }
        self.finished = true;
    }

    fn poll(
        &mut self,
        cx: &mut std::task::Context<'_>,
        deadline: Instant,
    ) -> Poll<io::Result<packet::PacketCarrier<PacketOwner>>> {
        if let Err(error) = check(deadline) {
            self.observe_terminal("service-deadline");
            return Poll::Ready(Err(error));
        }
        match std::future::Future::poll(std::pin::Pin::new(&mut self.factory), cx) {
            Poll::Ready(Err(error)) => {
                self.observe_terminal("handoff");
                Poll::Ready(Err(raw_setup_error("handoff", error)))
            }
            Poll::Ready(Ok(carrier)) => {
                self.finished = true;
                Poll::Ready(Ok(carrier))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
impl Drop for ObservedRawSetup<'_> {
    fn drop(&mut self) {
        if !self.finished {
            // Cancellation is a boundary observation, not a claim about its cause.
            self.observe_terminal("cancelled-before-completion");
        }
    }
}

struct RawSetupCause<'a>(&'a packet::Error);

impl std::fmt::Display for RawSetupCause<'_> {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use l2tunnel_raw_io::handoff::{SetupFailure, pairing::PairError};
        match self.0 {
            packet::Error::Pair(PairError::Setup(failure)) => match failure.as_ref() {
                SetupFailure::Authentication(l2tunnel_auth::Error::Io(error)) => write!(
                    output,
                    "Pair(Setup(Authentication(Io {{ kind: {:?}, errno: {:?} }})))",
                    error.kind(),
                    error.raw_os_error()
                ),
                // Authentication Display excludes provider text and certificate/key bytes.
                SetupFailure::Authentication(error) => {
                    write!(output, "Pair(Setup(Authentication({error})))")
                }
                other => write!(output, "Pair(Setup({other:?}))"),
            },
            other => write!(output, "{other:?}"),
        }
    }
}

fn raw_error(error: packet::Error) -> io::Error {
    use l2tunnel_raw_io::handoff::pairing::PairError;
    let kind = match &error {
        packet::Error::Io { kind, .. } | packet::Error::Pair(PairError::Driver { kind, .. }) => {
            *kind
        }
        packet::Error::Expired | packet::Error::Pair(PairError::Expired) => io::ErrorKind::TimedOut,
        packet::Error::Busy => io::ErrorKind::WouldBlock,
        packet::Error::Configuration | packet::Error::Pair(PairError::Configuration) => {
            io::ErrorKind::InvalidInput
        }
        _ => io::ErrorKind::InvalidData,
    };
    match error {
        packet::Error::Io {
            raw_os_error: Some(errno),
            ..
        }
        | packet::Error::Pair(PairError::Driver {
            raw_os_error: Some(errno),
            ..
        }) => io::Error::from_raw_os_error(errno),
        _ => io::Error::new(kind, error),
    }
}

#[cfg(test)]
mod failure_tests {
    use super::*;
    use l2tunnel_raw_io::handoff::{SetupFailure, pairing::PairError};

    #[test]
    fn raw_setup_cause_retains_original_variant_without_provider_body() {
        let error = packet::Error::Pair(PairError::Setup(Arc::new(SetupFailure::Authentication(
            l2tunnel_auth::Error::Io(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "provider body must remain private",
            )),
        ))));
        assert_eq!(
            RawSetupCause(&error).to_string(),
            "Pair(Setup(Authentication(Io { kind: ConnectionReset, errno: None })))"
        );
        assert_eq!(raw_error(error).kind(), io::ErrorKind::InvalidData);
        let error = packet::Error::Pair(PairError::Message(
            l2tunnel_raw_io::handoff::MessageError::Eof,
        ));
        assert_eq!(RawSetupCause(&error).to_string(), "Pair(Message(Eof))");
        assert_eq!(raw_error(error).kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            raw_error(packet::Error::Expired).kind(),
            io::ErrorKind::TimedOut
        );
    }
}
