//! Consume actual original raw membership into the existing single Common loop.
use super::*;
use crate::secure_udp::raw_carrier_io::{RawAdapter, RawBacking};
use l2tunnel_raw_io::PacketIo;

/// Run Common on the same genuine original raw TCP/TLS/packet owners.
/// Construction is eager and fallible, as with run_common: no second loop/task,
/// no new socket or SYN, no periodic rekey, no renewed initial setup cap. The
/// returned future reports construction failure when awaited; drop releases all
/// exact original owners and does not claim maintained clean TCP close.
pub fn run_common_on_raw<D, I>(
    device: D,
    parts: member::raw_carrier::RawInitialParts<I>,
    contract: CommonTransactionContract,
    requests: Option<CommonControlRequests>,
    shutdown: impl Future<Output = ()> + Send,
    observe: impl FnMut(&CommonSnapshot) + Send,
) -> impl Future<Output = io::Result<CommonStopped>> + Send
where
    D: PacketDevice<Error = io::Error> + AsRawFd + Send,
    I: PacketIo + Send + 'static,
{
    run_prepared_common(
        prepare_raw_runtime(device, parts, contract),
        requests,
        shutdown,
        observe,
    )
}
#[inline(never)]
fn prepare_raw_runtime<D, I>(
    device: D,
    parts: member::raw_carrier::RawInitialParts<I>,
    contract: CommonTransactionContract,
) -> io::Result<PreparedRuntime<D, RawAdapter<I>>>
where
    D: PacketDevice<Error = io::Error> + AsRawFd + Send,
    I: PacketIo + Send + 'static,
{
    contract.require_native_adapter()?;
    if device.layer() != contract.native_layer() {
        return Err(invalid("raw Common actual native layer differs"));
    }
    let setup_deadline = parts.deadline();
    if Instant::now() >= setup_deadline {
        return Err(common_setup_expired());
    }
    let (socket, driver) = Driver::new_common_on_raw(parts, contract)?;
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
    pub(super) fn new_common_on_raw<I: PacketIo + Send + 'static>(
        parts: member::raw_carrier::RawInitialParts<I>,
        contract: CommonTransactionContract,
    ) -> io::Result<(carrier::IoOwner<RawAdapter<I>>, owner::StateCell<Self>)> {
        contract.validate_raw(parts.outer())?;
        let geometry = parts.io.geometry();
        if geometry != parts.outer().geometry() {
            return Err(invalid(
                "actual raw owner geometry differs from genuine handoff",
            ));
        }
        let origin = parts.clock_origin();
        let io_capacity = parts
            .io
            .capacity_bytes()?
            .checked_add(std::mem::size_of::<carrier::IoOwner<RawAdapter<I>>>())
            .ok_or_else(exhausted)?;
        let input = CommonInput {
            material: establish::InitialMaterial::Legacy(parts.root),
            cover: parts.cover,
            bootstrap: parts.bootstrap,
            joining: parts.joining,
            next_outer: parts.next_outer,
            info: parts.info,
            deadline: parts.deadline,
            addresses: parts.io.addresses(),
            io_capacity,
        };
        // Check the complete known Bank subtotal before allocating the raw singleton
        // or moving this same initialized Driver into its existing fallible cell.
        Self::new_common_input(input, contract, origin, parts.io, |raw, driver| {
            if driver
                .records
                .capacity(driver.config.security.max_body_bytes)
                .map_err(invalid)?
                .packet_bytes
                > geometry.max_record_bytes
            {
                return Err(invalid(
                    "actual selected record exceeds original raw body capacity",
                ));
            }
            let socket = carrier::IoOwner::from_raw(raw)?;
            let usage = socket.adapter_usage()?;
            if usage.capacity_bytes != io_capacity
                || usage.allocations != 3
                || socket.addresses()? != (driver.info.local_addr, driver.info.peer_addr)
                || socket.ip_wire_bytes()? != driver.ip
                || socket.maximum_datagram_bytes() != Some(geometry.max_record_bytes)
            {
                return Err(protocol(
                    "actual raw adapter differs from admitted layout/geometry",
                ));
            }
            Ok((socket, owner::StateCell::new(driver)?))
        })
    }
}
