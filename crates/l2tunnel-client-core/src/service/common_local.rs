//! APIv4 is an adapter of the existing Common actor, not a second control owner.
use super::*;
use crate::secure_udp::common_status::{self, CanonicalConfiguration, CatalogPage, SwitchResult};

impl Handle {
    pub(super) fn common_reply_key(&self, response: &mut local::Response) {
        if let Some(status) = response
            .state
            .as_mut()
            .and_then(|value| value.common.as_mut())
        {
            status.next_request_key = self.next_key().ok().map(RequestKey::value);
        }
    }
    pub(super) fn common_status_from(snapshot: Snapshot, ok: bool, code: &str) -> local::Response {
        let status = snapshot
            .runtime
            .as_ref()
            .and_then(Observation::secure_udp_common)
            .map(SecureUdpCommonFrame::status)
            .transpose();
        let status = match status {
            Ok(value) => value,
            Err(_) => {
                return local::Response {
                    version: local::COMMON_VERSION,
                    ok: false,
                    code: "status_unavailable".into(),
                    state: None,
                };
            }
        };
        let phase = match snapshot.phase {
            Phase::Connected => "forwarding",
            Phase::Disconnected => "disconnected",
            Phase::Preparing | Phase::Authenticating => "connecting",
            Phase::Applying => "applying",
            Phase::Stopping => "stopping",
            Phase::Failed => "failed",
            Phase::Closed => "closed",
        };
        local::Response {
            version: local::COMMON_VERSION,
            ok,
            code: code.into(),
            state: Some(local::Snapshot {
                epoch: status.as_ref().and_then(|value| value.epoch).unwrap_or(0),
                phase: phase.into(),
                compression: local::Compression::Off,
                active: None,
                proxy: None,
                openvpn_drain: None,
                raw_packet: None,
                rolling: None,
                swift: None,
                secure_udp: None,
                transaction: None,
                common: status,
            }),
        }
    }
    pub(super) async fn common_request(&self, request: local::Request) -> local::Response {
        let refusal = |code| Self::common_status_from(self.snapshot(), false, code);
        match request.action {
            local::Action::ReuseConnection {
                request,
                request_key,
            } => {
                return self.common_reuse_request(request, request_key).await;
            }
            local::Action::CommonCatalog {
                generation,
                catalog,
                offset,
                limit,
            } => {
                let snapshot = self.snapshot();
                let Some(frame) = snapshot
                    .runtime
                    .as_ref()
                    .and_then(Observation::secure_udp_common)
                else {
                    return refusal("closed");
                };
                if generation != frame.generation
                    || catalog != *frame.requested.catalog().root().as_bytes()
                {
                    return refusal("stale_catalog");
                }
                let descriptors = frame.requested.catalog().descriptors();
                if !(1..=common_status::CATALOG_PAGE_LIMIT).contains(&limit)
                    || usize::from(offset) >= descriptors.len()
                {
                    return refusal("invalid_page");
                }
                let end = (usize::from(offset) + usize::from(limit)).min(descriptors.len());
                let values = descriptors[usize::from(offset)..end]
                    .iter()
                    .map(|descriptor| {
                        l2tunnel::record_configuration::Configuration::new(
                            frame.requested.envelope(),
                            *descriptor,
                        )
                        .map_err(io::Error::other)
                        .and_then(CanonicalConfiguration::from_configuration)
                    })
                    .collect::<io::Result<Vec<_>>>();
                let Ok(configurations) = values else {
                    return refusal("status_unavailable");
                };
                let total = descriptors.len() as u16; // Catalog bounds are checked at construction (at most64).
                let mut response = Self::common_status_from(snapshot, true, "ok");
                if let Some(status) = response
                    .state
                    .as_mut()
                    .and_then(|value| value.common.as_mut())
                {
                    status.catalog_page = Some(CatalogPage {
                        offset,
                        total,
                        next: (usize::from(total) > end).then_some(end as u16),
                        configurations,
                    });
                }
                response
            }
            local::Action::SwitchCommonConfiguration {
                configuration,
                request_key,
            } => {
                let Some(key) = RequestKey::new(request_key) else {
                    return refusal("invalid_request_key");
                };
                let Ok(configuration) = configuration.configuration() else {
                    return refusal("invalid_configuration");
                };
                let accepted = match self.apply_common(configuration, key) {
                    Ok(value) => value,
                    Err(error) => {
                        return refusal(match error {
                            SubmitError::InvalidConfiguration => "invalid_configuration",
                            SubmitError::Unsupported => "unsupported",
                            SubmitError::Busy => "busy",
                            SubmitError::Conflict => "conflict",
                            SubmitError::FutureKey => "future_key",
                            SubmitError::Expired => "expired_key",
                            _ => "closed",
                        });
                    }
                };
                match self.wait(accepted.operation).await {
                    Ok(Completed::Common {
                        configuration,
                        outcome,
                    }) => {
                        let (ok, epoch, code) = match outcome {
                            Ok(epoch) => (true, Some(epoch.0), "ok".to_owned()),
                            Err(error) => (false, None, format!("{error:?}")),
                        };
                        let mut response = Self::common_status_from(
                            self.snapshot(),
                            ok,
                            if ok { "ok" } else { "rejected" },
                        );
                        if let Some(status) = response
                            .state
                            .as_mut()
                            .and_then(|value| value.common.as_mut())
                        {
                            if let Ok(configuration) =
                                CanonicalConfiguration::from_configuration(configuration)
                            {
                                status.result = Some(SwitchResult {
                                    configuration,
                                    epoch,
                                    outcome: code,
                                    operation: accepted.operation.value(),
                                    request_key,
                                });
                            } else {
                                return refusal("status_unavailable");
                            }
                        }
                        response
                    }
                    Ok(Completed::OutcomeUnknown) => refusal("outcome_unknown"),
                    Ok(Completed::Cancelled) => refusal("cancelled"),
                    _ => refusal("closed"),
                }
            }
            _ => refusal("unsupported"),
        }
    }
}
