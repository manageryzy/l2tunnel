use super::*;
use l2tunnel_runtime::proxy as runtime;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Exact installed proxy policy family, independent of Common record profiles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyProfile {
    /// Fixed buffer-backed relay credit and maintained native TCP legs.
    FixedCredit,
    /// Measured relay targets over the same maintained native TCP legs.
    MeasuredRelay,
}
/// Copied facts from the actual fixed/measured owner; no control sender escapes.
#[derive(Clone, Debug)]
pub struct ProxyFrame {
    /// Exact prepared family; no automatic fallback is implemented.
    pub requested_profile: ProxyProfile,
    /// Family installed by the actual authenticated Session.
    pub effective_profile: ProxyProfile,
    /// Complete prepared policy binding, including actual native/route limits.
    pub requested_digest: l2tunnel_core::ConfigDigest,
    /// Binding read from the authenticated Session's exact retained policy.
    pub effective_digest: l2tunnel_core::ConfigDigest,
    /// Actual latest actor observation; absence is not readiness.
    pub runtime: Option<runtime::Status>,
    /// Existing bounded aggregate; never native RTT/cwnd or exact rwnd control.
    #[cfg(unix)]
    pub measured: Option<crate::proxy_measured::LocalSnapshot>,
    /// A local drain was admitted; this is not completed closure.
    pub drain_accepted: bool,
    /// An original-deadline abort is still releasing actual child ownership.
    pub releasing: bool,
    /// Exact retained local abort cap; retries never replace it.
    pub release_deadline: Option<Instant>,
    /// The owned runtime returned after observing all actual child joins.
    pub released: bool,
    /// Only the real runtime result can provide Closed and its exact report.
    pub terminal: Option<local::ProxyTerminal>,
    /// Shared lifecycle result, separate from the runtime's clean-close proof.
    pub service_terminal: Option<Terminal>,
    /// False: the maintained stack, not measured relay targets, chooses rwnd.
    pub exact_tcp_rwnd_control: bool,
    /// False: this backend does not install a Common proxy record adapter.
    pub common_record_composition: bool,
}

enum Control {
    Fixed(crate::proxy::Handle),
    Measured(crate::proxy_measured::Handle),
}
pub(super) struct Backend {
    control: Control,
    profile: ProxyProfile,
    requested_digest: l2tunnel_core::ConfigDigest,
    effective_digest: l2tunnel_core::ConfigDigest,
    duplex: l2tunnel_core::Duplex,
    stop_timeout: Duration,
    release_deadline: Mutex<Option<Instant>>,
    abort_enqueued: AtomicBool,
    releasing: AtomicBool,
    released: AtomicBool,
    drain_accepted: AtomicBool,
    terminal: Mutex<Option<local::ProxyTerminal>>,
}
impl Backend {
    pub(super) fn fixed(
        handle: crate::proxy::Handle,
        requested_digest: l2tunnel_core::ConfigDigest,
        effective_digest: l2tunnel_core::ConfigDigest,
        config: &runtime::Config,
    ) -> Self {
        Self::new(
            Control::Fixed(handle),
            ProxyProfile::FixedCredit,
            requested_digest,
            effective_digest,
            config,
        )
    }
    pub(super) fn measured(
        handle: crate::proxy_measured::Handle,
        requested_digest: l2tunnel_core::ConfigDigest,
        effective_digest: l2tunnel_core::ConfigDigest,
        config: &runtime::Config,
    ) -> Self {
        Self::new(
            Control::Measured(handle),
            ProxyProfile::MeasuredRelay,
            requested_digest,
            effective_digest,
            config,
        )
    }
    fn new(
        control: Control,
        profile: ProxyProfile,
        requested_digest: l2tunnel_core::ConfigDigest,
        effective_digest: l2tunnel_core::ConfigDigest,
        config: &runtime::Config,
    ) -> Self {
        Self {
            control,
            profile,
            requested_digest,
            effective_digest,
            duplex: config.duplex,
            stop_timeout: config.timeouts.shutdown,
            release_deadline: Mutex::new(None),
            abort_enqueued: AtomicBool::new(false),
            releasing: AtomicBool::new(false),
            released: AtomicBool::new(false),
            drain_accepted: AtomicBool::new(false),
            terminal: Mutex::new(None),
        }
    }
    pub(super) fn observe(&self) -> ProxyFrame {
        let (runtime, measured) = match &self.control {
            Control::Fixed(handle) => (handle.status(), None),
            Control::Measured(handle) => {
                let value = handle.status();
                #[cfg(unix)]
                let measured = Some(crate::proxy_measured::LocalSnapshot::observed(
                    self.duplex,
                    value.as_ref().map(|s| &s.measurement),
                ));
                #[cfg(not(unix))]
                let measured: Option<()> = None;
                (value.map(|s| s.runtime), measured)
            }
        };
        #[cfg(not(unix))]
        let _ = (measured, self.duplex);
        ProxyFrame {
            requested_profile: self.profile,
            effective_profile: self.profile,
            requested_digest: self.requested_digest,
            effective_digest: self.effective_digest,
            runtime,
            #[cfg(unix)]
            measured,
            drain_accepted: self.drain_accepted.load(Ordering::Acquire),
            releasing: self.awaiting_release(),
            release_deadline: *self
                .release_deadline
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            released: self.released.load(Ordering::Acquire),
            terminal: self
                .terminal
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
            service_terminal: None,
            exact_tcp_rwnd_control: false,
            common_record_composition: false,
        }
    }
    pub(super) fn ready(&self) -> bool {
        !self.released.load(Ordering::Acquire)
            && self
                .observe()
                .runtime
                .is_some_and(|s| s.phase == runtime::Phase::Forwarding)
    }
    pub(super) fn awaiting_release(&self) -> bool {
        self.releasing.load(Ordering::Acquire) && !self.released.load(Ordering::Acquire)
    }
    pub(super) fn released(&self) -> bool {
        self.released.load(Ordering::Acquire)
    }
    pub(super) fn clean_closed(&self) -> bool {
        self.released.load(Ordering::Acquire)
            && matches!(
                *self
                    .terminal
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
                Some(local::ProxyTerminal::Closed { .. })
            )
    }
    pub(super) fn begin_release(&self, accepted: Option<Instant>) -> io::Result<Instant> {
        let mut retained = self
            .release_deadline
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(deadline) = *retained {
            return Ok(deadline);
        }
        let now = Instant::now();
        let deadline = now.checked_add(self.stop_timeout).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "proxy release deadline overflow",
            )
        })?;
        let deadline = accepted.map_or(deadline, |accepted| accepted.min(deadline));
        *retained = Some(deadline);
        self.releasing.store(true, Ordering::Release);
        Ok(deadline)
    }
    pub(super) fn stop_timeout(&self) -> Duration {
        self.stop_timeout
    }
    pub(super) fn drive_abort(&self) -> io::Result<()> {
        if self.abort_enqueued.load(Ordering::Acquire) || !self.awaiting_release() {
            return Ok(());
        }
        let deadline = self
            .release_deadline
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .ok_or_else(|| io::Error::other("proxy release lacks original deadline"))?;
        let waiter = match &self.control {
            Control::Fixed(handle) => handle.request_abort(deadline),
            Control::Measured(handle) => handle.request_abort(deadline),
        }?;
        self.abort_enqueued.store(true, Ordering::Release);
        // Release is proven by the same owned runtime returning after all joins.
        // Queue admission and dropping this acknowledgement are never that proof.
        drop(waiter);
        Ok(())
    }
    pub(super) fn request_drain(&self) -> io::Result<&'static str> {
        if self.releasing.load(Ordering::Acquire) || self.released.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "proxy owner is releasing",
            ));
        }
        if self.drain_accepted.load(Ordering::Acquire) {
            return Ok("already_accepted");
        }
        let waiter = match &self.control {
            Control::Fixed(handle) => handle.request_drain()?,
            Control::Measured(handle) => handle.request_drain()?,
        };
        self.drain_accepted.store(true, Ordering::Release);
        // Actual completion is observed from the same owned runtime result.
        drop(waiter);
        Ok("accepted")
    }
    pub(super) fn finished(&self, result: &io::Result<runtime::CloseReport>) {
        let terminal = match result {
            Ok(report) => local::ProxyTerminal::Closed {
                report: local::ProxyCloseReport {
                    local_user_records: report.local_user_records,
                    peer_user_records: report.peer_user_records,
                    local_transparent_packets: report.local_transparent_packets,
                    native_confirmed_packets: report.native_confirmed_packets,
                    clean_flows: report.clean_flows,
                    stopped_flows: report.stopped_flows,
                    tls_lanes_closed: report.tls_lanes_closed,
                },
            },
            Err(error) => local::ProxyTerminal::Failed {
                error: format!("{:?}", error.kind()),
            },
        };
        *self
            .terminal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(terminal);
        self.released.store(true, Ordering::Release);
    }
}

impl Handle {
    pub(super) fn proxy_status_from(snapshot: Snapshot, ok: bool, code: &str) -> local::Response {
        let proxy = snapshot.runtime.as_ref().and_then(Observation::proxy);
        local::Response {
            version: local::VERSION,
            ok,
            code: code.into(),
            state: Some(local::Snapshot {
                epoch: 1,
                // Preserve v1 proxy CLI/native parser semantics. Service phase
                // remains separately available on the typed lifecycle Snapshot.
                phase: proxy
                    .and_then(|frame| frame.runtime.as_ref())
                    .map_or_else(|| "Starting".into(), |status| format!("{:?}", status.phase)),
                compression: local::Compression::Off,
                active: None,
                openvpn_drain: None,
                raw_packet: None,
                rolling: None,
                #[cfg(unix)]
                swift: None,
                #[cfg(unix)]
                secure_udp: None,
                transaction: None,
                common: None,
                proxy: proxy.map(|frame| local::ProxySnapshot {
                    digest: frame
                        .effective_digest
                        .0
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect(),
                    drain_accepted: frame.drain_accepted,
                    runtime: frame.runtime.as_ref().map(|status| local::ProxyStatus {
                        phase: format!("{:?}", status.phase),
                        flows: status.flows,
                        active: status.active,
                        stopped: status.stopped,
                        retired: status.retired,
                        queued_bytes: status.queued_bytes,
                        queued_records: status.queued_records,
                        transparent_admitted_bytes: status.transparent_admitted_bytes,
                        transparent_admitted_packets: status.transparent_admitted_packets,
                        native_confirmed_packets: status.native_confirmed_packets,
                    }),
                    terminal: frame.terminal.clone(),
                    #[cfg(unix)]
                    measured: frame.measured.clone(),
                    #[cfg(not(unix))]
                    measured: None,
                }),
            }),
        }
    }
}
