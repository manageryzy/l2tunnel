//! Version-5 local operations: an adapter of the existing actor, never a
//! second lifecycle owner. Submissions return acceptance without waiting;
//! only the explicit long-poll actions wait, and for a bounded time.
use super::*;
use crate::local::{
    self, EventBatch, EventBody, EventState, OperationAction, OperationReply, OperationRequest,
    OperationResult, OperationState, ServiceId, ServiceStatus, SetupState, TerminalState,
};
use std::time::Duration;

/// Convert a Debug variant name such as `SocketBind` to `socket_bind`.
fn snake(value: impl std::fmt::Debug) -> String {
    let text = format!("{value:?}");
    let name = text.split(['(', ' ', '{']).next().unwrap_or_default();
    let mut out = String::with_capacity(name.len() + 4);
    for (index, character) in name.chars().enumerate() {
        if character.is_ascii_uppercase() {
            if index > 0 {
                out.push('_');
            }
            out.push(character.to_ascii_lowercase());
        } else {
            out.push(character);
        }
    }
    out
}
fn bounded(text: String) -> String {
    text.chars().take(128).collect()
}
fn phase_name(phase: Phase) -> String {
    snake(phase)
}
fn terminal_state(terminal: Terminal) -> TerminalState {
    match terminal {
        Terminal::Aborted => TerminalState::Aborted,
        Terminal::Closed => TerminalState::Closed,
        Terminal::Failed(failure) => TerminalState::Failed {
            error_kind: snake(failure.kind),
        },
    }
}
fn kind_name(kind: OperationKind) -> String {
    snake(kind)
}
fn result_state(completed: &Completed) -> Option<OperationResult> {
    Some(match completed {
        Completed::Connected { generation } => OperationResult::Connected {
            generation: generation.value(),
        },
        Completed::Aborted => OperationResult::Aborted,
        Completed::Applied(response) => OperationResult::Applied {
            code: bounded(response.code.clone()),
        },
        Completed::Rejected(response) => OperationResult::Rejected {
            code: bounded(response.code.clone()),
        },
        Completed::Common {
            configuration,
            outcome,
        } => {
            let configuration =
                crate::secure_udp::common_status::CanonicalConfiguration::from_configuration(
                    *configuration,
                )
                .ok()?;
            match outcome {
                Ok(epoch) => OperationResult::CommonCommitted {
                    epoch: epoch.0,
                    configuration,
                },
                Err(error) => OperationResult::CommonRefused {
                    reason: bounded(format!("{error:?}")),
                    configuration,
                },
            }
        }
        Completed::ConnectionReuse {
            generation,
            outcome,
            ..
        } => match outcome {
            Ok(_) => OperationResult::ReuseConfirmed {
                generation: *generation,
            },
            Err(error) => OperationResult::ReuseRefused {
                generation: *generation,
                reason: bounded(format!("{error:?}")),
            },
        },
        Completed::Cancelled => OperationResult::Cancelled,
        Completed::OutcomeUnknown => OperationResult::OutcomeUnknown,
        Completed::Failed(failure) => OperationResult::Failed {
            error_kind: snake(failure.kind),
        },
        Completed::Host(Ok(summary)) => OperationResult::HostApplied {
            summary: bounded(summary.clone()),
        },
        Completed::Host(Err(reason)) => OperationResult::HostRefused {
            reason: bounded(reason.clone()),
        },
        Completed::Profile(Ok(summary)) => OperationResult::ProfileApplied {
            summary: bounded(summary.clone()),
        },
        Completed::Profile(Err(reason)) => OperationResult::ProfileRefused {
            reason: bounded(reason.clone()),
        },
    })
}
fn operation_state(view: &OperationView) -> OperationState {
    let now = Instant::now();
    OperationState {
        id: view.accepted.operation.value(),
        kind: kind_name(view.kind),
        state: if view.result.is_some() {
            "completed"
        } else {
            "pending"
        }
        .into(),
        deadline_ms: view.accepted.deadline.map(|deadline| {
            u64::try_from(deadline.saturating_duration_since(now).as_millis()).unwrap_or(u64::MAX)
        }),
        cancel_requested: view.cancel_requested,
        setup: view.setup.map(|setup| SetupState {
            stage: snake(setup.stage),
            outcome: snake(setup.outcome),
            failure: setup
                .failure
                .map(|failure| bounded(format!("{}:{:?}", snake(failure.kind), failure.reason))),
            elapsed_micros: setup.elapsed_micros,
        }),
        // A Common result whose configuration cannot be re-encoded is reported
        // as unknown rather than fabricated.
        result: view
            .result
            .as_ref()
            .map(|result| result_state(result).unwrap_or(OperationResult::OutcomeUnknown)),
    }
}
fn event_state(event: &Event) -> EventState {
    let event_body = match event.kind {
        EventKind::OperationAccepted { operation, kind } => EventBody::OperationAccepted {
            operation: operation.value(),
            kind: kind_name(kind),
        },
        EventKind::OperationProgress { operation, stage } => EventBody::OperationProgress {
            operation: operation.value(),
            stage: snake(stage),
        },
        EventKind::OperationCompleted { operation, outcome } => EventBody::OperationCompleted {
            operation: operation.value(),
            outcome: snake(outcome),
        },
        EventKind::Lifecycle {
            phase,
            operation,
            generation,
            terminal,
        } => EventBody::Lifecycle {
            phase: phase_name(phase),
            operation: operation.map(OperationId::value),
            generation: generation.map(OperationId::value),
            terminal: terminal.map(terminal_state),
        },
    };
    EventState {
        sequence: event.sequence,
        event: event_body,
    }
}
fn submit_code(error: SubmitError) -> &'static str {
    match error {
        SubmitError::Busy => "busy",
        SubmitError::Conflict => "conflict",
        SubmitError::Expired => "expired_key",
        SubmitError::FutureKey => "future_key",
        SubmitError::Closed => "closed",
        SubmitError::State => "state",
        SubmitError::Unsupported => "unsupported",
        SubmitError::InvalidConfiguration => "invalid_configuration",
    }
}
fn lookup_code(error: SubmitError) -> &'static str {
    match error {
        SubmitError::Expired => "expired",
        SubmitError::Closed => "closed",
        _ => "unknown_operation",
    }
}

impl Handle {
    pub(super) fn service_id(&self) -> Option<ServiceId> {
        Some(ServiceId(self.instance()))
    }
    fn reply(&self, ok: bool, code: &str) -> OperationReply {
        OperationReply::code(ok, code, self.service_id())
    }
    /// Existing backend projection of the latest observation, unchanged.
    pub(super) fn observation(&self, snapshot: &Snapshot) -> Option<local::Snapshot> {
        let mut response = match snapshot.runtime.as_ref()? {
            Observation::Proxy(_) => Self::proxy_status_from(snapshot.clone(), true, "ok"),
            Observation::SecureUdpCommon(_) => {
                Self::common_status_from(snapshot.clone(), true, "ok")
            }
        };
        self.common_reply_key(&mut response);
        response.state
    }
    fn service_status(&self) -> ServiceStatus {
        let (snapshot, cursor, profile, connected_at) = {
            let state = self.0.lock();
            (
                Self::snapshot_locked(&state),
                state.events.last(),
                state.profile.clone(),
                state.connected_at,
            )
        };
        let connected_ms = connected_at
            .filter(|_| matches!(snapshot.phase, Phase::Connected))
            .map(|at| u64::try_from(at.elapsed().as_millis()).unwrap_or(u64::MAX));
        ServiceStatus {
            phase: phase_name(snapshot.phase),
            operation: snapshot.operation.map(OperationId::value),
            generation: snapshot.generation.map(OperationId::value),
            terminal: snapshot.terminal.map(terminal_state),
            next_request_key: self.next_key().ok().map(RequestKey::value),
            event_cursor: cursor,
            listening: snapshot
                .listening
                .map(|listening| listening.address.to_string()),
            observation: self.observation(&snapshot),
            profile,
            connected_ms,
        }
    }
    fn operation_reply(&self, ok: bool, code: &str, id: OperationId) -> OperationReply {
        match self.operation(id) {
            Ok(view) => OperationReply {
                operation: Some(operation_state(&view)),
                ..self.reply(ok, code)
            },
            Err(error) => self.reply(false, lookup_code(error)),
        }
    }
    fn accepted(&self, result: Result<Accepted, SubmitError>) -> OperationReply {
        match result {
            Ok(accepted) => self.operation_reply(true, "accepted", accepted.operation),
            Err(error) => self.reply(false, submit_code(error)),
        }
    }
    /// Serve one version-5 request. Submissions never wait for completion;
    /// waits are bounded by the request's own timeout.
    pub async fn operations_request(&self, request: OperationRequest) -> OperationReply {
        let key = |value: u64| RequestKey::new(value);
        let operation_id = |value: u64| OperationId::new(value);
        match request.action {
            OperationAction::Status {} => OperationReply {
                status: Some(self.service_status()),
                ..self.reply(true, "ok")
            },
            OperationAction::Metrics {} => match self.metrics() {
                Some(metrics) => OperationReply {
                    metrics: Some(Box::new(metrics)),
                    ..self.reply(true, "ok")
                },
                None => self.reply(false, "not_running"),
            },
            OperationAction::MetersRead {
                side,
                prefix,
                cursor,
                limit,
            } => {
                let result = match side {
                    crate::local::MeterSide::Local => {
                        self.meters_local(&prefix, cursor.as_deref(), limit)
                    }
                    crate::local::MeterSide::Remote => {
                        self.meters_remote(&prefix, cursor.as_deref(), limit).await
                    }
                };
                match result {
                    Ok(page) => OperationReply {
                        meters: Some(Box::new(page)),
                        ..self.reply(true, "ok")
                    },
                    Err(code) => self.reply(false, code),
                }
            }
            OperationAction::MetersCatalog {
                prefix,
                cursor,
                limit,
            } => match self.meters_catalog(&prefix, cursor, limit) {
                Ok(page) => OperationReply {
                    meter_catalog: Some(Box::new(page)),
                    ..self.reply(true, "ok")
                },
                Err(code) => self.reply(false, code),
            },
            OperationAction::SessionList {} => match self.sessions() {
                Ok(sessions) => OperationReply {
                    sessions: Some(sessions),
                    ..self.reply(true, "ok")
                },
                Err(error) => self.reply(false, submit_code(error)),
            },
            OperationAction::SessionKick { request_key } => match key(request_key) {
                Some(key) => self.accepted(self.kick(key)),
                None => self.reply(false, "invalid_request_key"),
            },
            OperationAction::ServiceStop { request_key } => match key(request_key) {
                Some(key) => self.accepted(self.stop(key)),
                None => self.reply(false, "invalid_request_key"),
            },
            OperationAction::ProfileList {} => match self.profiles().map(|store| store.list()) {
                Some(Ok(profiles)) => OperationReply {
                    profiles: Some(profiles),
                    ..self.reply(true, "ok")
                },
                Some(Err(error)) => self.reply(false, &format!("store_{}", snake(error.kind()))),
                None => self.reply(false, "unsupported"),
            },
            OperationAction::ProfileGet { name } => {
                match self.profiles().map(|store| store.get(&name)) {
                    Some(Ok(Some(profile))) => OperationReply {
                        profile: Some(profile),
                        ..self.reply(true, "ok")
                    },
                    Some(Ok(None)) => self.reply(false, "unknown_profile"),
                    Some(Err(error)) => {
                        self.reply(false, &format!("store_{}", snake(error.kind())))
                    }
                    None => self.reply(false, "unsupported"),
                }
            }
            OperationAction::ProfileKeys { name } => {
                match self.profiles().map(|store| store.get(&name)) {
                    Some(Ok(Some(entry))) => OperationReply {
                        keys: Some(
                            entry
                                .document
                                .options
                                .iter()
                                .filter_map(|(option, path)| {
                                    crate::local::keys::inspect(option, path)
                                })
                                .take(crate::local::keys::KEY_REFERENCE_LIMIT)
                                .collect(),
                        ),
                        ..self.reply(true, "ok")
                    },
                    Some(Ok(None)) => self.reply(false, "unknown_profile"),
                    Some(Err(error)) => {
                        self.reply(false, &format!("store_{}", snake(error.kind())))
                    }
                    None => self.reply(false, "unsupported"),
                }
            }
            OperationAction::ProfileValidate { name } => match self.profile_check(&name) {
                Ok(Some(check)) => OperationReply {
                    check: Some(check),
                    ..self.reply(true, "ok")
                },
                Ok(None) => self.reply(false, "unknown_profile"),
                Err(error) if error.kind() == io::ErrorKind::Unsupported => {
                    self.reply(false, "unsupported")
                }
                Err(error) => self.reply(false, &format!("store_{}", snake(error.kind()))),
            },
            OperationAction::Profile {
                request_key,
                change,
            } => match (key(request_key), change.validate()) {
                (None, _) => self.reply(false, "invalid_request_key"),
                (_, Err(_)) => self.reply(false, "invalid_change"),
                (Some(key), Ok(())) => self.accepted(self.profile_change(change, key)),
            },
            OperationAction::ProfileConnect {
                request_key,
                name,
                replace,
            } => match (key(request_key), crate::local::validate_profile_name(&name)) {
                (None, _) => self.reply(false, "invalid_request_key"),
                (_, Err(_)) => self.reply(false, "unknown_profile"),
                (Some(key), Ok(())) => match self.connect_profile(&name, replace, key) {
                    Ok(accepted) => self.accepted(Ok(accepted)),
                    Err(super::profiles::ProfileConnectError::Submit(error)) => {
                        self.accepted(Err(error))
                    }
                    Err(super::profiles::ProfileConnectError::Invalid(reason)) => OperationReply {
                        check: Some(crate::local::ProfileCheck {
                            valid: false,
                            summary: name.clone(),
                            reason: Some(crate::local::bounded_text(&reason)),
                        }),
                        ..self.reply(false, "invalid_profile")
                    },
                },
            },
            OperationAction::DeviceList {} => match self.host() {
                Some(host) => match host.devices().await {
                    Ok(mut devices) => {
                        devices.truncate(local::HOST_LIST_LIMIT);
                        OperationReply {
                            devices: Some(devices),
                            ..self.reply(true, "ok")
                        }
                    }
                    Err(error) => self.reply(false, &format!("host_{}", snake(error.kind()))),
                },
                None => self.reply(false, "unsupported"),
            },
            OperationAction::RouteList {} => match self.host() {
                Some(host) => match host.routes().await {
                    Ok(mut routes) => {
                        routes.truncate(local::HOST_LIST_LIMIT);
                        OperationReply {
                            routes: Some(routes),
                            ..self.reply(true, "ok")
                        }
                    }
                    Err(error) => self.reply(false, &format!("host_{}", snake(error.kind()))),
                },
                None => self.reply(false, "unsupported"),
            },
            OperationAction::Device {
                request_key,
                change,
            } => match (key(request_key), change.validate()) {
                (None, _) => self.reply(false, "invalid_request_key"),
                (_, Err(_)) => self.reply(false, "invalid_change"),
                (Some(key), Ok(())) => self.accepted(self.device(change, key)),
            },
            OperationAction::Route {
                request_key,
                change,
            } => match (key(request_key), change.validate()) {
                (None, _) => self.reply(false, "invalid_request_key"),
                (_, Err(_)) => self.reply(false, "invalid_change"),
                (Some(key), Ok(())) => self.accepted(self.route(change, key)),
            },
            OperationAction::TuningGet {} => match self.tuning_view() {
                Ok(view) => OperationReply {
                    tuning: Some(Box::new(view)),
                    ..self.reply(true, "ok")
                },
                Err(code) => self.reply(false, code),
            },
            OperationAction::TuningSwitch {
                request_key,
                setting,
            } => {
                let Some(key) = key(request_key) else {
                    return self.reply(false, "invalid_request_key");
                };
                match self.tuning_target(&setting) {
                    Ok(configuration) => self.accepted(self.apply_common(configuration, key)),
                    Err(code) => self.reply(false, code),
                }
            }
            OperationAction::TestStart { test } => self.test_start(&test),
            OperationAction::TestGet { id, timeout_ms } => self.test_get(id, timeout_ms).await,
            OperationAction::TestCancel { id } => self.test_cancel(id),
            OperationAction::RateBudgetSet {
                send_rate,
                receive_rate,
            } => {
                use l2tunnel_runtime::secure_udp::transport::RateBudgetError;
                let switcher = {
                    let state = self.0.lock();
                    match &state.backend {
                        Some(ObservedBackend::SecureUdpCommon(backend)) => {
                            Ok(backend.switcher.clone())
                        }
                        Some(ObservedBackend::Proxy(_)) => Err("unsupported"),
                        None => Err("not_running"),
                    }
                };
                match switcher {
                    Err(code) => self.reply(false, code),
                    Ok(switcher) => match switcher.set_rate_budget(send_rate, receive_rate).await {
                        Ok(_) => OperationReply {
                            status: Some(self.service_status()),
                            ..self.reply(true, "ok")
                        },
                        Err(error) => {
                            let code = match error {
                                RateBudgetError::InvalidRate => "invalid_rate",
                                RateBudgetError::Busy => "busy",
                                RateBudgetError::Timeout => "peer_timeout",
                                RateBudgetError::PeerRefused => "peer_refused",
                                RateBudgetError::Malformed => "peer_malformed",
                                RateBudgetError::Closed => "not_running",
                            };
                            self.reply(false, code)
                        }
                    },
                }
            }
            OperationAction::ServiceInfo {} => OperationReply {
                info: Some(self.service_info()),
                ..self.reply(true, "ok")
            },
            OperationAction::SocksGet {} => OperationReply {
                socks: Some(Box::new(self.socks_status())),
                ..self.reply(true, "ok")
            },
            OperationAction::SocksSet { settings } => match self.socks_set(settings).await {
                Ok(status) => OperationReply {
                    socks: Some(Box::new(status)),
                    ..self.reply(true, "ok")
                },
                Err((code, status)) => OperationReply {
                    socks: Some(Box::new(status)),
                    ..self.reply(false, code)
                },
            },
            OperationAction::SocksFlows {} => OperationReply {
                socks_flows: Some(Box::new(self.socks_flows())),
                ..self.reply(true, "ok")
            },
            OperationAction::CarrierSwitchGet {} => match self.carrier_switch_view() {
                Ok(view) => OperationReply {
                    carrier_switch: Some(Box::new(view)),
                    ..self.reply(true, "ok")
                },
                Err(code) => self.reply(false, code),
            },
            OperationAction::CarrierSwitch { target } => {
                use l2tunnel_runtime::secure_udp::transport::{CarrierSwitchError, CarrierTarget};
                let Some(parsed) = CarrierTarget::parse(&target) else {
                    return self.reply(false, "invalid_target");
                };
                let switcher = {
                    let state = self.0.lock();
                    match &state.backend {
                        Some(ObservedBackend::SecureUdpCommon(backend)) => {
                            Ok(backend.switcher.clone())
                        }
                        Some(ObservedBackend::Proxy(_)) => Err("unsupported"),
                        None => Err("not_running"),
                    }
                };
                match switcher {
                    Err(code) => self.reply(false, code),
                    Ok(switcher) => match switcher.switch_carrier(parsed).await {
                        Ok(_) => OperationReply {
                            status: Some(self.service_status()),
                            carrier_switch: self.carrier_switch_view().ok().map(Box::new),
                            ..self.reply(true, "ok")
                        },
                        Err(error) => {
                            let code = match error {
                                CarrierSwitchError::UnsupportedCarrier => "unsupported_carrier",
                                CarrierSwitchError::NotCoordinator => "not_coordinator",
                                CarrierSwitchError::Busy => "busy",
                                CarrierSwitchError::BindFailed => "bind_failed",
                                CarrierSwitchError::ProbeFailed => "probe_failed",
                                CarrierSwitchError::Timeout => "peer_timeout",
                                CarrierSwitchError::PeerRefused => "peer_refused",
                                CarrierSwitchError::Malformed => "peer_malformed",
                                CarrierSwitchError::Closed => "not_running",
                            };
                            self.reply(false, code)
                        }
                    },
                }
            }
            OperationAction::Connect { request_key } => match key(request_key) {
                Some(key) => self.accepted(self.connect_retained(key)),
                None => self.reply(false, "invalid_request_key"),
            },
            OperationAction::Reconnect { request_key } => match key(request_key) {
                Some(key) => self.accepted(self.reconnect_retained(key)),
                None => self.reply(false, "invalid_request_key"),
            },
            OperationAction::Disconnect { request_key } => match key(request_key) {
                Some(key) => self.accepted(self.disconnect(key)),
                None => self.reply(false, "invalid_request_key"),
            },
            OperationAction::DrainProxy { request_key } => match key(request_key) {
                Some(key) => self.accepted(self.apply(
                    local::Request {
                        version: local::VERSION,
                        action: local::Action::DrainProxy {},
                    },
                    key,
                )),
                None => self.reply(false, "invalid_request_key"),
            },
            OperationAction::SwitchCommonConfiguration {
                configuration,
                request_key,
            } => {
                let Some(key) = key(request_key) else {
                    return self.reply(false, "invalid_request_key");
                };
                match configuration.configuration() {
                    Ok(configuration) => self.accepted(self.apply_common(configuration, key)),
                    Err(_) => self.reply(false, "invalid_configuration"),
                }
            }
            OperationAction::ReuseConnection {
                request,
                request_key,
            } => match key(request_key) {
                Some(key) => self.accepted(self.reuse_connection(
                    request.owner,
                    request.old_key.key(),
                    request.next_key.key(),
                    key,
                )),
                None => self.reply(false, "invalid_request_key"),
            },
            OperationAction::OperationGet { operation, service } => {
                if let Some(refusal) = self.restarted(service) {
                    return refusal;
                }
                match operation_id(operation) {
                    Some(id) => self.operation_reply(true, "ok", id),
                    None => self.reply(false, "unknown_operation"),
                }
            }
            OperationAction::OperationWait {
                operation,
                timeout_ms,
                service,
            } => {
                if let Some(refusal) = self.restarted(service) {
                    return refusal;
                }
                if !(1..=local::WAIT_LIMIT_MS).contains(&timeout_ms) {
                    return self.reply(false, "invalid_timeout");
                }
                let Some(id) = operation_id(operation) else {
                    return self.reply(false, "unknown_operation");
                };
                let limit = Duration::from_millis(u64::from(timeout_ms));
                match tokio::time::timeout(limit, self.wait(id)).await {
                    Ok(Ok(_)) => self.operation_reply(true, "completed", id),
                    // Closed while waiting: report the retained entry as it is.
                    Ok(Err(SubmitError::Closed)) => self.operation_reply(true, "closed", id),
                    Ok(Err(error)) => self.reply(false, lookup_code(error)),
                    Err(_) => self.operation_reply(true, "running", id),
                }
            }
            OperationAction::OperationCancel { operation, service } => {
                if let Some(refusal) = self.restarted(service) {
                    return refusal;
                }
                let Some(id) = operation_id(operation) else {
                    return self.reply(false, "unknown_operation");
                };
                match self.cancel(id) {
                    Ok(()) => self.operation_reply(true, "cancel_requested", id),
                    Err(SubmitError::Unsupported) => {
                        self.operation_reply(false, "cancel_unsupported", id)
                    }
                    Err(SubmitError::State) if self.operation(id).is_ok() => {
                        self.operation_reply(false, "completed", id)
                    }
                    Err(error) => self.reply(false, lookup_code(error)),
                }
            }
            OperationAction::Events {
                after,
                limit,
                timeout_ms,
                service,
            } => {
                if let Some(refusal) = self.restarted(service) {
                    return refusal;
                }
                if !(1..=local::EVENTS_LIMIT).contains(&limit) || timeout_ms > local::WAIT_LIMIT_MS
                {
                    return self.reply(false, "invalid_page");
                }
                let mut page = self.events(after, usize::from(limit));
                if page.events.is_empty() && !page.gap && timeout_ms > 0 {
                    let limit_time = Duration::from_millis(u64::from(timeout_ms));
                    let _woken = tokio::time::timeout(limit_time, self.wait_event(after)).await;
                    page = self.events(after, usize::from(limit));
                }
                OperationReply {
                    status: page.gap.then(|| self.service_status()),
                    events: Some(EventBatch {
                        events: page.events.iter().map(event_state).collect(),
                        next: page.next,
                        gap: page.gap,
                    }),
                    ..self.reply(true, if page.gap { "gap" } else { "ok" })
                }
            }
            OperationAction::Catalog {
                generation,
                catalog,
                offset,
                limit,
            } => {
                let response = self
                    .common_request(local::Request {
                        version: local::COMMON_VERSION,
                        action: local::Action::CommonCatalog {
                            generation,
                            catalog: catalog.0,
                            offset,
                            limit,
                        },
                    })
                    .await;
                OperationReply {
                    observation: response.state,
                    ..self.reply(response.ok, &response.code)
                }
            }
        }
    }
    fn restarted(&self, service: Option<ServiceId>) -> Option<OperationReply> {
        service
            .filter(|service| service.0 != self.instance())
            .map(|_| self.reply(false, "service_restarted"))
    }
}

#[cfg(test)]
impl Handle {
    /// Retain one pending setup entry exactly as submit_locked would, for
    /// frontend tests that need a running operation without real I/O.
    pub(crate) fn seed_pending_setup_for_test(&self) -> OperationId {
        let mut state = self.0.lock();
        let operation = OperationId(state.last_key + 1);
        state.entries.push_back(Entry {
            accepted: Accepted {
                operation,
                deadline: Instant::now().checked_add(Duration::from_secs(60)),
            },
            fingerprint: Fingerprint::Connect(Arc::new(())),
            result: None,
            cancel: false,
            setup: None,
            reported: events::Reported::default(),
        });
        state.last_key = operation.0;
        state.snapshot.operation = Some(operation);
        state.snapshot.phase = Phase::Preparing;
        operation
    }
    /// Complete a seeded operation through the actor's own finish path.
    pub(crate) fn finish_for_test(&self, operation: OperationId, result: Completed) {
        owner::finish(&self.0, operation, result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(action: OperationAction) -> OperationRequest {
        OperationRequest::new(action)
    }

    #[test]
    fn names_are_snake_case() {
        assert_eq!(snake(SetupStage::SocketBind), "socket_bind");
        assert_eq!(snake(Phase::Disconnected), "disconnected");
        assert_eq!(snake(OutcomeName::OutcomeUnknown), "outcome_unknown");
        assert_eq!(snake(io::ErrorKind::TimedOut), "timed_out");
        assert_eq!(snake(OperationKind::CommonSwitch), "common_switch");
    }

    #[tokio::test]
    async fn operations_report_acceptance_waits_and_restarts() {
        let (handle, run) = channel();
        let service = Some(ServiceId(handle.instance()));
        let status = handle
            .operations_request(request(OperationAction::Status {}))
            .await;
        assert!(status.ok);
        let current = status.status.as_ref().map(|status| status.phase.as_str());
        assert_eq!(current, Some("disconnected"));
        assert_eq!(
            status
                .status
                .as_ref()
                .and_then(|status| status.next_request_key),
            Some(1)
        );
        // No retained plan: refused before any state change.
        let reply = handle
            .operations_request(request(OperationAction::Reconnect { request_key: 1 }))
            .await;
        assert_eq!((reply.ok, reply.code.as_str()), (false, "state"));
        let reply = handle
            .operations_request(request(OperationAction::Disconnect { request_key: 0 }))
            .await;
        assert_eq!(reply.code, "invalid_request_key");
        let operation = handle.seed_pending_setup_for_test();
        let reply = handle
            .operations_request(request(OperationAction::OperationWait {
                operation: 1,
                timeout_ms: 20,
                service,
            }))
            .await;
        assert_eq!((reply.ok, reply.code.as_str()), (true, "running"));
        let pending = reply.operation.as_ref();
        assert_eq!(pending.map(|state| state.state.as_str()), Some("pending"));
        assert!(
            pending
                .and_then(|state| state.deadline_ms)
                .is_some_and(|ms| ms > 50_000)
        );
        let reply = handle
            .operations_request(request(OperationAction::OperationCancel {
                operation: 1,
                service,
            }))
            .await;
        assert_eq!(reply.code, "cancel_requested");
        assert_eq!(
            reply.operation.map(|state| state.cancel_requested),
            Some(true)
        );
        let reply = handle
            .operations_request(request(OperationAction::OperationGet {
                operation: 1,
                service: Some(ServiceId(handle.instance() ^ 1)),
            }))
            .await;
        assert_eq!(reply.code, "service_restarted");
        let waiter = {
            let handle = handle.clone();
            tokio::spawn(async move {
                handle
                    .operations_request(request(OperationAction::OperationWait {
                        operation: 1,
                        timeout_ms: 5_000,
                        service,
                    }))
                    .await
            })
        };
        tokio::task::yield_now().await;
        owner::finish(&handle.0, operation, Completed::Cancelled);
        let reply = waiter.await.ok();
        assert_eq!(
            reply.as_ref().map(|reply| reply.code.as_str()),
            Some("completed")
        );
        assert_eq!(
            reply
                .and_then(|reply| reply.operation)
                .and_then(|state| state.result),
            Some(OperationResult::Cancelled)
        );
        // Cancelling a completed operation is refused with its actual view.
        let reply = handle
            .operations_request(request(OperationAction::OperationCancel {
                operation: 1,
                service,
            }))
            .await;
        assert_eq!((reply.ok, reply.code.as_str()), (false, "completed"));
        let reply = handle
            .operations_request(request(OperationAction::OperationGet {
                operation: 7,
                service,
            }))
            .await;
        assert_eq!(reply.code, "unknown_operation");

        // Events: full page from zero, then a bounded long-poll that times out.
        let reply = handle
            .operations_request(request(OperationAction::Events {
                after: 0,
                limit: 32,
                timeout_ms: 0,
                service,
            }))
            .await;
        let batch = reply.events.unwrap_or(EventBatch {
            events: vec![],
            next: 0,
            gap: true,
        });
        assert!(!batch.gap);
        assert!(matches!(
            batch.events.first().map(|event| &event.event),
            Some(EventBody::Lifecycle { phase, .. }) if phase == "disconnected"
        ));
        assert!(batch.events.iter().any(|event| matches!(
            &event.event,
            EventBody::OperationCompleted { operation: 1, outcome } if outcome == "cancelled"
        )));
        let started = Instant::now();
        let reply = handle
            .operations_request(request(OperationAction::Events {
                after: batch.next,
                limit: 4,
                timeout_ms: 30,
                service,
            }))
            .await;
        assert!(started.elapsed() >= Duration::from_millis(30));
        assert_eq!(reply.events.map(|batch| batch.events.len()), Some(0));
        let reply = handle
            .operations_request(request(OperationAction::Events {
                after: 0,
                limit: 33,
                timeout_ms: 0,
                service,
            }))
            .await;
        assert_eq!(reply.code, "invalid_page");
        drop(run);
        let reply = handle
            .operations_request(request(OperationAction::Status {}))
            .await;
        assert_eq!(
            reply.status.map(|status| status.phase),
            Some("closed".to_owned())
        );
    }

    #[tokio::test]
    async fn applied_cancel_is_refused_and_evicted_cursor_reports_gap_with_status() {
        let (handle, _run) = channel();
        {
            let mut state = handle.0.lock();
            let operation = OperationId(1);
            state.entries.push_back(Entry {
                accepted: Accepted {
                    operation,
                    deadline: None,
                },
                fingerprint: Fingerprint::Apply(local::Request {
                    version: local::VERSION,
                    action: local::Action::DrainProxy {},
                }),
                result: None,
                cancel: false,
                setup: None,
                reported: events::Reported::default(),
            });
            state.last_key = 1;
            state.snapshot.operation = Some(operation);
            state.snapshot.phase = Phase::Applying;
        }
        let reply = handle
            .operations_request(request(OperationAction::OperationCancel {
                operation: 1,
                service: None,
            }))
            .await;
        assert_eq!(
            (reply.ok, reply.code.as_str()),
            (false, "cancel_unsupported")
        );
        assert_eq!(
            reply
                .operation
                .map(|state| (state.state, state.cancel_requested)),
            Some(("pending".to_owned(), false))
        );
        // Publish more transitions than the ring retains.
        for index in 0..events::EVENT_CAPACITY + 8 {
            handle.0.lock().snapshot.phase = if index % 2 == 0 {
                Phase::Stopping
            } else {
                Phase::Applying
            };
        }
        let reply = handle
            .operations_request(request(OperationAction::Events {
                after: 1,
                limit: 4,
                timeout_ms: 0,
                service: None,
            }))
            .await;
        assert_eq!((reply.ok, reply.code.as_str()), (true, "gap"));
        let batch = reply.events.unwrap_or(EventBatch {
            events: vec![],
            next: 0,
            gap: false,
        });
        assert!(batch.gap);
        assert_eq!(batch.events.len(), 4);
        assert!(reply.status.is_some(), "a gap carries a full status");
        assert_eq!(
            reply.status.map(|status| status.event_cursor),
            Some(handle.event_cursor())
        );
    }
}
