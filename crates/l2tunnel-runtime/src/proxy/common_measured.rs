//! Selection of the existing measured actor on the retained Common record port.
use super::*;

/// Validate an explicit measured/full/one-channel retained Common composition.
/// The complete measured policy must already be bound into authenticated H0.
pub fn validate_measured(
    config: &measured::Config,
    contract: &transport::CommonTransactionContract,
) -> io::Result<()> {
    config.validate()?;
    if !contract.proxy_retirement() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "measured Common proxy requires explicit retained retirement",
        ));
    }
    validate_binding(
        &config.fixed,
        contract,
        measured::session_config(config)?.digest,
    )
}

/// Run the existing measured controller, Table, scheduler and feedback owner on
/// the original authenticated Common member. The record bridge completes writes
/// only after whole protected datagrams are accepted by the physical socket.
/// Measurement admission, immutable ledger tokens and callback deadlines remain
/// owned by the same actor; Common does not supply replacement measurement time.
pub fn run_measured<D>(
    device: D,
    parts: member::Parts,
    contract: transport::CommonTransactionContract,
    config: measured::Config,
    control: measured::Control,
    requests: Option<transport::CommonControlRequests>,
    observe: impl FnMut(&transport::CommonSnapshot) + Send,
) -> impl std::future::Future<Output = io::Result<CloseReport>> + Send
where
    D: PacketDevice<Error = io::Error> + Send,
{
    run_selected(
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

pub(super) enum Readiness {
    Fixed(tokio::sync::watch::Receiver<Option<Status>>),
    Measured(tokio::sync::watch::Receiver<Option<measured::Status>>),
}
impl Readiness {
    pub(super) fn new(control: &Control, measured: bool) -> io::Result<Self> {
        match (&control.status, measured) {
            (StatusSink::Fixed(sender), false) => Ok(Self::Fixed(sender.subscribe())),
            (StatusSink::Measured(sender), true) => Ok(Self::Measured(sender.subscribe())),
            _ => Err(invalid("Common proxy control and policy differ")),
        }
    }

    pub(super) fn forwarding(&self) -> bool {
        match self {
            Self::Fixed(receiver) => receiver
                .borrow()
                .as_ref()
                .is_some_and(|s| s.phase == Phase::Forwarding),
            Self::Measured(receiver) => receiver
                .borrow()
                .as_ref()
                .is_some_and(|s| s.runtime.phase == Phase::Forwarding),
        }
    }

    pub(super) async fn changed(&mut self) -> Result<(), tokio::sync::watch::error::RecvError> {
        match self {
            Self::Fixed(receiver) => receiver.changed().await,
            Self::Measured(receiver) => receiver.changed().await,
        }
    }
}
