//! Genuine original raw TCP owner consumed by the same fixed proxy actor.
use super::*;
use l2tunnel_raw_io::PacketIo;

/// Run the fixed/full proxy on the same TLS-to-raw/Noise/member accepted owner.
/// Original raw sequence/authentication, physical receipts and setup/drain caps
/// remain in the same Driver and Bridge. This adds no TCP/recovery/controller.
#[allow(clippy::too_many_arguments)]
pub fn run_on_raw<D, I>(
    device: D,
    parts: member::raw_carrier::RawInitialParts<I>,
    contract: transport::CommonTransactionContract,
    config: Config,
    control: Control,
    requests: Option<transport::CommonControlRequests>,
    observe: impl FnMut(&transport::CommonSnapshot) + Send,
) -> impl std::future::Future<Output = io::Result<CloseReport>> + Send
where
    D: PacketDevice<Error = io::Error> + Send,
    I: PacketIo + Send + 'static,
{
    let info = parts.info();
    let setup = parts.deadline();
    run_selected_io(
        device,
        info,
        setup,
        contract,
        config,
        control,
        None,
        move |port, bridge, contract, stopped| {
            transport::run_common_proxy_records_on_raw(
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
