//! Consume original maintained connections into the sole existing Common loop.
use super::*;

/// Run native Common records and authenticated management on the same genuine
/// TLS/QUIC owner(s). Maintained encryption and transport behavior remain active.
pub fn run_common_on_maintained<D>(
    device: D,
    parts: member::maintained::InitialParts,
    contract: CommonTransactionContract,
    requests: Option<CommonControlRequests>,
    shutdown: impl Future<Output = ()> + Send,
    observe: impl FnMut(&CommonSnapshot) + Send,
) -> impl Future<Output = io::Result<CommonStopped>> + Send
where
    D: NativeDevice + Send,
{
    run_prepared_common(
        prepare(device, parts, contract),
        requests,
        shutdown,
        observe,
    )
}
#[inline(never)]
fn prepare<D>(
    device: D,
    parts: member::maintained::InitialParts,
    contract: CommonTransactionContract,
) -> io::Result<PreparedRuntime<D>>
where
    D: NativeDevice + Send,
{
    contract.require_native_adapter()?;
    if device.layer() != contract.native_layer() {
        return Err(invalid("maintained Common actual native layer differs"));
    }
    let setup_deadline = parts.deadline;
    if Instant::now() >= setup_deadline {
        return Err(common_setup_expired());
    }
    let (socket, driver) = Driver::new_common_on_maintained(parts, contract)?;
    if Instant::now() >= setup_deadline {
        return Err(common_setup_expired());
    }
    Ok(PreparedRuntime {
        device,
        socket,
        driver,
        setup_deadline,
    })
}
impl Driver {
    pub(in super::super) fn new_common_on_maintained(
        mut parts: member::maintained::InitialParts,
        contract: CommonTransactionContract,
    ) -> io::Result<(carrier::IoOwner, owner::StateCell<Self>)> {
        contract.validate_maintained(parts.outer())?;
        if parts.carrier.authenticated() != parts.outer()
            || parts.info.authenticated.configuration != contract.expected_configuration().0
            || parts.carrier.setup_deadline() != parts.deadline
        {
            return Err(invalid("maintained actual owner and Common handoff differ"));
        }
        parts.carrier.select_final_records(parts.deadline)?;
        let origin = parts.clock_origin();
        let geometry = parts.carrier.geometry();
        let capacity =
            super::super::maintained_carrier::MaintainedIo::capacity_for(&parts.carrier)?;
        let input = CommonInput {
            material: establish::InitialMaterial::Legacy(parts.root),
            cover: parts.cover,
            bootstrap: parts.bootstrap,
            joining: parts.joining,
            next_outer: parts.next_outer,
            info: parts.info,
            deadline: parts.deadline,
            addresses: parts.carrier.addresses(),
            io_capacity: capacity,
        };
        Self::new_common_input(
            input,
            contract,
            origin,
            parts.carrier,
            |original, driver| {
                if driver
                    .records
                    .capacity(driver.config.security.max_body_bytes)
                    .map_err(invalid)?
                    .packet_bytes
                    > geometry.max_record_bytes
                {
                    return Err(invalid(
                        "selected Common record exceeds maintained carrier capacity",
                    ));
                }
                let socket = carrier::IoOwner::from_maintained(original)?;
                if socket.adapter_capacity_bytes()? != capacity
                    || socket.addresses()? != (driver.info.local_addr, driver.info.peer_addr)
                    || socket.ip_wire_bytes()? != driver.ip
                    || socket.maximum_datagram_bytes() != Some(geometry.max_record_bytes)
                {
                    return Err(protocol(
                        "maintained carrier differs from admitted Common plan",
                    ));
                }
                Ok((socket, owner::StateCell::new(driver)?))
            },
        )
    }
}
