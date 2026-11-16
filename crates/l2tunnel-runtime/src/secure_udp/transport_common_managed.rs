//! Consume actual carrier membership into the existing Common runtime.
use super::*;

/// Run the shared Common protocol after an initial-only carrier handshake.
/// The actual original carrier/socket, authenticated member, clock and retained
/// confirmation tails are transferred once. This enables no periodic rekeying.
pub fn run_common_on_carrier<D>(
    device: D,
    parts: member::carrier::InitialParts,
    contract: CommonTransactionContract,
    requests: Option<CommonControlRequests>,
    shutdown: impl Future<Output = ()> + Send,
    observe: impl FnMut(&CommonSnapshot) + Send,
) -> impl Future<Output = io::Result<CommonStopped>> + Send
where
    D: PacketDevice<Error = io::Error> + AsRawFd + Send,
{
    run_prepared_common(
        prepare_carrier_runtime(device, parts, contract),
        requests,
        shutdown,
        observe,
    )
}

#[inline(never)]
fn prepare_carrier_runtime<D>(
    device: D,
    parts: member::carrier::InitialParts,
    contract: CommonTransactionContract,
) -> io::Result<PreparedRuntime<D>>
where
    D: PacketDevice<Error = io::Error> + AsRawFd + Send,
{
    contract.require_native_adapter()?;
    if device.layer() != contract.native_layer() {
        return Err(invalid(
            "carrier Common native layer differs from actual device",
        ));
    }
    let setup_deadline = parts.deadline;
    if Instant::now() >= setup_deadline {
        return Err(common_setup_expired());
    }
    let (socket, driver) = Driver::new_common_on_carrier(parts, contract)?;
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
    pub(in super::super) fn new_common_on_carrier(
        mut parts: member::carrier::InitialParts,
        contract: CommonTransactionContract,
    ) -> io::Result<(carrier::IoOwner, owner::StateCell<Self>)> {
        let selected = contract.compact_wire().is_some();
        if contract.refresh_selection().is_some()
            || contract.extra_wire_bytes() != usize::from(!selected)
        {
            return Err(invalid(
                "initial-only carrier requires its exact untimed contract",
            ));
        }
        contract.validate_outer(Some(parts.outer()))?;
        if selected {
            if parts.info.authenticated.configuration != contract.expected_configuration().0 {
                return Err(invalid(
                    "compact carrier selection differs from actual member proof",
                ));
            }
            parts.datagram.select_final_records(parts.deadline)?;
        }
        let origin = parts.clock_origin();
        let geometry = parts.datagram.geometry();
        if parts.datagram.outer_info() != Some(&parts.outer().info())
            || geometry.extra_wire_bytes != contract.extra_wire_bytes()
            || geometry.ip_udp_bytes != if contract.ipv6() { 48 } else { 28 }
        {
            return Err(invalid(
                "carrier owner differs from actual authenticated outer geometry",
            ));
        }
        let plan = carrier::Plan::for_original(&parts.datagram)?;
        let input = CommonInput {
            material: establish::InitialMaterial::Legacy(parts.root),
            cover: parts.cover,
            bootstrap: parts.bootstrap,
            joining: parts.joining,
            next_outer: parts.next_outer,
            info: parts.info,
            deadline: parts.deadline,
            addresses: parts.datagram.addresses(),
            io_capacity: plan.capacity_bytes(),
        };
        // Preflight the shared Bank limit before allocating the new I/O adapter.
        Self::new_common_input(
            input,
            contract,
            origin,
            parts.datagram,
            |datagram, driver| {
                if driver
                    .records
                    .capacity(driver.config.security.max_body_bytes)
                    .map_err(invalid)?
                    .packet_bytes
                    > geometry.max_datagram_bytes
                {
                    return Err(invalid(
                        "actual selected record exceeds original carrier capacity",
                    ));
                }
                let socket = carrier::IoOwner::from_original(datagram)?;
                let usage = socket.adapter_usage()?;
                if usage.capacity_bytes != plan.capacity_bytes()
                    || usage.allocations != 3
                    || socket.addresses()? != (driver.info.local_addr, driver.info.peer_addr)
                    || socket.ip_wire_bytes()? != driver.ip
                    || socket.extra_wire_bytes() != geometry.extra_wire_bytes
                    || socket.maximum_datagram_bytes() != Some(geometry.max_datagram_bytes)
                {
                    return Err(protocol("carrier adapter usage differs from admitted plan"));
                }
                Ok((socket, owner::StateCell::new(driver)?))
            },
        )
    }
}
