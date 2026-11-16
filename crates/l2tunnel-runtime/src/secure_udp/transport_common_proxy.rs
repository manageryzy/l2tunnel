//! Explicit opaque record-port installation into the existing Common Driver.
use super::*;
use crate::proxy::common_bridge::{Bridge, RecordPort};

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
            .as_mut()
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
            .as_mut()
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
        let source = bridge.final_source()?;
        let engine = self
            .common_state()?
            .engine(core::Epoch(self.source_scope.epoch.0))?;
        let retired = source
            .map(|source| engine.proxy_source_retired(source).map_err(protocol))
            .transpose()?
            .unwrap_or(false);
        let drained = runtime.sealed.is_none()
            && runtime.pending_feedback.is_none()
            && runtime.pending_ingress.is_none()
            && self.native.is_empty()
            && engine.drained().map_err(protocol)?;
        bridge.advance_retirement(source, retired, drained)
    }
}
