//! Explicit opaque record-port installation into the existing Common Driver.
use super::*;
use crate::proxy::common_bridge::{Bridge, RecordPort};

/// Consume the genuine retained TLS/QUIC member owner into the same record port.
pub(crate) fn run_common_proxy_records_on_maintained(
    device: RecordPort,
    bridge: Bridge,
    parts: member::maintained::InitialParts,
    contract: CommonTransactionContract,
    requests: Option<CommonControlRequests>,
    shutdown: impl Future<Output = ()> + Send,
    observe: impl FnMut(&CommonSnapshot) + Send,
) -> impl Future<Output = io::Result<CommonStopped>> + Send {
    let prepared = (|| {
        if contract.proxy_binding().is_none() {
            return Err(invalid(
                "maintained Common record port lacks explicit proxy binding",
            ));
        }
        let setup_deadline = parts.deadline;
        if Instant::now() >= setup_deadline {
            return Err(common_setup_expired());
        }
        let (socket, mut driver) = Driver::new_common_on_maintained(parts, contract)?;
        driver
            .common
            .as_deref_mut()
            .ok_or_else(|| invalid("maintained Common proxy owner absent"))?
            .proxy_bridge = Some(bridge);
        if Instant::now() >= setup_deadline {
            return Err(common_setup_expired());
        }
        Ok(PreparedRuntime {
            device,
            socket,
            driver,
            setup_deadline,
        })
    })();
    run_prepared_common(prepared, requests, shutdown, observe)
}

pub(crate) fn run_common_proxy_records(
    device: RecordPort,
    bridge: Bridge,
    parts: member::Parts,
    contract: CommonTransactionContract,
    requests: Option<CommonControlRequests>,
    shutdown: impl Future<Output = ()> + Send,
    observe: impl FnMut(&CommonSnapshot) + Send,
) -> impl Future<Output = io::Result<CommonStopped>> + Send {
    let prepared = (|| {
        if contract.proxy_binding().is_none() {
            return Err(invalid(
                "opaque Common record port lacks explicit proxy binding",
            ));
        }
        let setup_deadline = parts.deadline;
        let origin = Instant::now();
        if origin >= setup_deadline {
            return Err(common_setup_expired());
        }
        let (socket, mut driver) =
            Driver::new_common(parts, contract, origin, |socket, driver| {
                Ok((socket, owner::StateCell::new(driver)?))
            })?;
        driver
            .common
            .as_deref_mut()
            .ok_or_else(|| invalid("Common proxy owner absent"))?
            .proxy_bridge = Some(bridge);
        if Instant::now() >= setup_deadline {
            return Err(common_setup_expired());
        }
        Ok(PreparedRuntime {
            device,
            socket: socket.into(),
            driver,
            setup_deadline,
        })
    })();
    run_prepared_common(prepared, requests, shutdown, observe)
}

/// The same opaque record adapter on an actual original raw member handoff.
/// No public observation can construct Parts or substitute a UDP socket owner.
pub(crate) fn run_common_proxy_records_on_raw<I>(
    device: RecordPort,
    bridge: Bridge,
    parts: member::raw_carrier::RawInitialParts<I>,
    contract: CommonTransactionContract,
    requests: Option<CommonControlRequests>,
    shutdown: impl Future<Output = ()> + Send,
    observe: impl FnMut(&CommonSnapshot) + Send,
) -> impl Future<Output = io::Result<CommonStopped>> + Send
where
    I: l2tunnel_raw_io::PacketIo + Send + 'static,
{
    let prepared = (|| {
        if contract.proxy_binding().is_none() {
            return Err(invalid(
                "opaque raw Common record port lacks explicit proxy binding",
            ));
        }
        let setup_deadline = parts.deadline();
        if Instant::now() >= setup_deadline {
            return Err(common_setup_expired());
        }
        let (socket, mut driver) = Driver::new_common_on_raw(parts, contract)?;
        driver
            .common
            .as_deref_mut()
            .ok_or_else(|| invalid("raw Common proxy owner absent"))?
            .proxy_bridge = Some(bridge);
        if Instant::now() >= setup_deadline {
            return Err(common_setup_expired());
        }
        Ok(PreparedRuntime {
            device,
            socket,
            driver,
            setup_deadline,
        })
    })();
    run_prepared_common(prepared, requests, shutdown, observe)
}

impl Driver {
    pub(in super::super) fn observe_proxy_retirement(
        &self,
        runtime: &common::Runtime,
    ) -> io::Result<()> {
        let Some(bridge) = &runtime.proxy_bridge else {
            return Ok(());
        };
        let (source, retired, drained) = self.proxy_retirement_facts(runtime, bridge)?;
        bridge.advance_retirement(
            source,
            retired,
            drained,
            self.proxy_control_drained(runtime)?,
        )
    }

    pub(in super::super) fn proved_proxy_peer_close_cap(&self) -> io::Result<Option<Instant>> {
        let Some(runtime) = self.common.as_deref() else {
            return Ok(None);
        };
        let Some(bridge) = &runtime.proxy_bridge else {
            return Ok(None);
        };
        if self.terminal.is_some() || !self.proxy_control_drained(runtime)? {
            return Ok(None);
        }
        let (source, retired, drained) = self.proxy_retirement_facts(runtime, bridge)?;
        let cap = bridge.proved_peer_close_cap(source, retired, drained)?;
        Ok(cap.filter(|cap| {
            self.origin
                .checked_add(duration(self.lease))
                .is_some_and(|lease| *cap <= lease)
        }))
    }

    fn proxy_control_drained(&self, runtime: &common::Runtime) -> io::Result<bool> {
        Ok(self.challenge.is_none()
            && self.pong.is_none()
            && self.control.retained_close_drained()
            && self.common_state()?.operation_deadline().is_none()
            && runtime.request.is_none()
            && runtime.action.is_none()
            && runtime.outcome.is_none()
            && runtime.completion.is_none())
    }

    #[cfg(debug_assertions)]
    pub(in super::super) fn trace_proxy_peer_close_refusal(
        &self,
        terminal_facts_clear: bool,
        retained_peer_close: bool,
    ) {
        let Some(runtime) = self.common.as_deref() else {
            return;
        };
        let Some(bridge) = &runtime.proxy_bridge else {
            return;
        };
        let facts = self.proxy_retirement_facts(runtime, bridge);
        let facts_ok = facts.is_ok();
        let (source, retired, drained) = facts.unwrap_or((None, false, false));
        eprintln!(
            "PROXY_CLOSE_GATE facts_clear={} typed_idle_close={} terminal={:?} challenge={} pong={} control_drained={} operation={} request={} action={} outcome={} completion={} facts_ok={} source={} source_retired={} custody_drained={} sealed={} unsealed={} raw_control={} feedback={} ingress={} native={} eligible={:?}",
            terminal_facts_clear,
            retained_peer_close,
            self.terminal,
            self.challenge.is_some(),
            self.pong.is_some(),
            self.control.retained_close_drained(),
            self.common_state()
                .is_ok_and(|state| state.operation_deadline().is_some()),
            runtime.request.is_some(),
            runtime.action.is_some(),
            runtime.outcome.is_some(),
            runtime.completion.is_some(),
            facts_ok,
            source.is_some(),
            retired,
            drained,
            runtime.sealed.is_some(),
            runtime.unsealed.is_some(),
            runtime.raw_control.is_some(),
            runtime.pending_feedback.is_some(),
            runtime.pending_ingress.is_some(),
            self.native.len(),
            self.proved_proxy_peer_close_cap().ok().flatten(),
        );
        self.control.trace_retained_close();
        bridge.trace_retirement_failure();
    }

    fn proxy_retirement_facts(
        &self,
        runtime: &common::Runtime,
        bridge: &crate::proxy::common_bridge::Bridge,
    ) -> io::Result<(Option<l2tunnel_recovery::SourceId>, bool, bool)> {
        let source = bridge.final_source()?;
        let engine = self
            .common_state()?
            .engine(core::Epoch(self.source_scope.epoch.0))?;
        let retired = source
            .map(|source| engine.proxy_source_retired(source).map_err(protocol))
            .transpose()?
            .unwrap_or(false);
        let drained = runtime.sealed.is_none()
            && runtime.unsealed.is_none()
            && runtime.raw_control.is_none()
            && runtime.pending_feedback.is_none()
            && runtime.pending_ingress.is_none()
            && self.native.is_empty()
            && engine.drained().map_err(protocol)?;
        Ok((source, retired, drained))
    }
}
