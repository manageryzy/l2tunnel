//! Existing proxy actors on genuine retained TLS/QUIC Common owners.
use super::*;

/// Preserve the fixed actor and its retained close on the authenticated carrier.
#[allow(clippy::too_many_arguments)]
pub fn run_on_maintained<D>(
    device: D,
    parts: member::maintained::InitialParts,
    contract: transport::CommonTransactionContract,
    config: Config,
    control: Control,
    requests: Option<transport::CommonControlRequests>,
    observe: impl FnMut(&transport::CommonSnapshot) + Send,
) -> impl std::future::Future<Output = io::Result<CloseReport>> + Send
where
    D: PacketDevice<Error = io::Error> + Send,
{
    run_selected_on_maintained(
        device, parts, contract, config, control, None, requests, observe,
    )
}

/// Preserve measured admission using actual maintained acceptance receipts.
/// TLS flush and Quinn DATAGRAM acceptance are not physical NIC transmission.
#[allow(clippy::too_many_arguments)]
pub fn run_measured_on_maintained<D>(
    device: D,
    parts: member::maintained::InitialParts,
    contract: transport::CommonTransactionContract,
    config: measured::Config,
    control: measured::Control,
    requests: Option<transport::CommonControlRequests>,
    observe: impl FnMut(&transport::CommonSnapshot) + Send,
) -> impl std::future::Future<Output = io::Result<CloseReport>> + Send
where
    D: PacketDevice<Error = io::Error> + Send,
{
    run_selected_on_maintained(
        device,
        parts,
        contract,
        config.fixed.clone(),
        control.into_control(),
        Some(config),
        requests,
        observe,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_selected_on_maintained<D>(
    device: D,
    parts: member::maintained::InitialParts,
    contract: transport::CommonTransactionContract,
    config: Config,
    control: Control,
    measured: Option<measured::Config>,
    requests: Option<transport::CommonControlRequests>,
    observe: impl FnMut(&transport::CommonSnapshot) + Send,
) -> impl std::future::Future<Output = io::Result<CloseReport>> + Send
where
    D: PacketDevice<Error = io::Error> + Send,
{
    let info = parts.info;
    let setup = parts.deadline;
    run_selected_io(
        device,
        info,
        setup,
        contract,
        config,
        control,
        measured,
        move |port, bridge, contract, stopped| {
            transport::run_common_proxy_records_on_maintained(
                port,
                bridge,
                parts,
                contract,
                requests,
                async move {
                    let _ = stopped.await;
                },
                observe,
            )
        },
    )
}
