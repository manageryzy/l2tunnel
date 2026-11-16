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
