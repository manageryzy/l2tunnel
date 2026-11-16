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
/// Bounded copied facts for the explicit proxy Common composition. No Common
/// control sender, credential, packet buffer or lifecycle authority escapes.
#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
pub struct ProxyCommonFrame {
    /// Full requested authenticated Common plan, including the proxy policy.
    pub requested_configuration: l2tunnel_security::ConfigDigest,
    /// Configuration read from actual completed Noise/member authentication.
    pub effective_configuration: l2tunnel_security::ConfigDigest,
    /// Exact requested carrier binding and actual authenticated binding.
    pub requested_carrier: [u8; 32],
    /// Actual authenticated carrier binding, without a fallback selection.
    pub effective_carrier: [u8; 32],
    /// Explicit selected UDP appearance.
    pub requested_cover: l2tunnel_cover::Appearance,
    /// Absent until the actual Common runtime publishes its installed selection.
    pub effective_cover: Option<l2tunnel_cover::Appearance>,
    /// Original authenticated connected socket endpoints.
    pub local_addr: std::net::SocketAddr,
    /// Original fixed peer endpoint.
    pub peer_addr: std::net::SocketAddr,
    /// True only after actual Common Driver readiness publication.
    pub installed: bool,
    /// Last observed Common running state, distinct from proxy drain state.
    pub running: bool,
    /// Actual current Common generation.
    pub epoch: Option<l2tunnel_core::Epoch>,
    /// Actual authenticated Common liveness observations.
    pub liveness: l2tunnel_runtime::secure_udp::transport::Liveness,
    /// False for the initial immutable single-descriptor composition.
    pub hot_switch: bool,
    /// Cumulative original-carrier whole-packet acceptance across Common scopes.
    /// This is not a measurement-token callback, peer ACK or network-delivery count.
    pub socket_accepted_packets: u64,
    /// Cumulative IP bytes accepted by the original carrier, not application delivery.
    pub socket_accepted_ip_bytes: u64,
    /// True only for an explicitly authenticated retained-retirement selection.
    pub graceful_close: bool,
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
    /// True only after the actual Common adapter publishes installation.
    pub common_record_composition: bool,
    /// Exact bounded Common facts; absent for retained TLS proxy selections.
    #[cfg(unix)]
    pub common: Option<ProxyCommonFrame>,
}

impl ProxyFrame {
    /// One maintained portable proxy observation; Common is absent for legacy TLS.
    pub fn status(&self) -> local::ProxySnapshot {
        local::ProxySnapshot {
            common: self.common_status().map(Box::new),
            digest: self
                .effective_digest
                .0
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            drain_accepted: self.drain_accepted,
            runtime: self.runtime.as_ref().map(|status| local::ProxyStatus {
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
            terminal: self.terminal.clone(),
            #[cfg(unix)]
            measured: self.measured.clone(),
            #[cfg(not(unix))]
            measured: None,
        }
    }
    /// Bounded copied facts from the actual backend, without handles or credentials.
    #[cfg(unix)]
    pub fn common_status(&self) -> Option<local::ProxyCommonStatus> {
        let frame = self.common?;
        let cover = |appearance| match appearance {
            l2tunnel_cover::Appearance::QuicLike => local::ProxyCommonCover::QuicLike,
            l2tunnel_cover::Appearance::MediaLike => local::ProxyCommonCover::MediaLike,
        };
        Some(local::ProxyCommonStatus {
            requested_proxy_digest: self.requested_digest.0,
            effective_proxy_digest: self.effective_digest.0,
            requested_configuration: frame.requested_configuration.0,
            effective_configuration: frame.effective_configuration.0,
            requested_carrier: frame.requested_carrier,
            effective_carrier: frame.effective_carrier,
            requested_cover: cover(frame.requested_cover),
            effective_cover: frame.effective_cover.map(cover),
            local_addr: frame.local_addr,
            peer_addr: frame.peer_addr,
            installed: frame.installed,
            running: frame.running,
            epoch: frame.epoch.map(|epoch| epoch.0),
            outstanding_ping: frame.liveness.outstanding,
            original_ping_deadline_micros: frame.liveness.deadline_micros,
            last_verified_micros: frame.liveness.last_verified_micros,
            last_pong_micros: frame.liveness.last_pong_micros,
            hot_switch: frame.hot_switch,
            graceful_close: frame.graceful_close,
            exact_tcp_rwnd_control: self.exact_tcp_rwnd_control,
            releasing: self.releasing,
            released: self.released,
        })
    }
    /// No Common proxy backend is installed on non-Unix targets.
    #[cfg(not(unix))]
    pub fn common_status(&self) -> Option<local::ProxyCommonStatus> {
        None
    }
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
    #[cfg(unix)]
    common: Mutex<Option<ProxyCommonFrame>>,
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
    #[cfg(unix)]
    pub(super) fn common(
        handle: crate::proxy::Handle,
        digest: l2tunnel_core::ConfigDigest,
        config: &runtime::Config,
        frame: ProxyCommonFrame,
    ) -> Self {
        let mut backend = Self::fixed(handle, digest, digest, config);
        backend.common = Mutex::new(Some(frame));
        backend
    }
    #[cfg(unix)]
    pub(super) fn common_measured(
        handle: crate::proxy_measured::Handle,
        digest: l2tunnel_core::ConfigDigest,
        config: &runtime::Config,
        frame: ProxyCommonFrame,
    ) -> Self {
        let mut backend = Self::measured(handle, digest, digest, config);
        backend.common = Mutex::new(Some(frame));
        backend
    }
    #[cfg(unix)]
    pub(super) fn observe_common(
        &self,
        snapshot: &l2tunnel_runtime::secure_udp::transport::CommonSnapshot,
    ) {
        if let Some(frame) = &mut *self
            .common
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            frame.installed |= snapshot.running;
            frame.running = snapshot.running;
            frame.epoch = Some(snapshot.epoch);
            frame.liveness = snapshot.liveness;
            frame.socket_accepted_packets = snapshot.counters.socket_accepted_packets;
            frame.socket_accepted_ip_bytes = snapshot.counters.socket_accepted_ip_bytes;
            if snapshot.running {
                frame.effective_cover = Some(frame.requested_cover);
            }
        }
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
            #[cfg(unix)]
            common: Mutex::new(None),
        }
    }
    pub(super) fn observe(&self) -> ProxyFrame {
        #[cfg(unix)]
        let common = *self
            .common
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (runtime, measured) = match &self.control {
            Control::Fixed(handle) => (handle.status(), None),
            Control::Measured(handle) => {
                let value = handle.status();
                #[cfg(unix)]
                let measured = Some(match common {
                    Some(frame) => crate::proxy_measured::LocalSnapshot::observed_common(
                        self.duplex,
                        value.as_ref().map(|s| &s.measurement),
                        frame.requested_cover,
                        frame.effective_cover,
                    ),
                    None => crate::proxy_measured::LocalSnapshot::observed(
                        self.duplex,
                        value.as_ref().map(|s| &s.measurement),
                    ),
                });
                #[cfg(not(unix))]
                let measured: Option<()> = None;
                (value.map(|s| s.runtime), measured)
            }
        };
        #[cfg(not(unix))]
        let _ = (measured, self.duplex);
        #[cfg(unix)]
        let common_record_composition = common.is_some_and(|frame| frame.installed);
        #[cfg(not(unix))]
        let common_record_composition = false;
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
            common_record_composition,
            #[cfg(unix)]
            common,
        }
    }
    pub(super) fn ready(&self) -> bool {
        #[cfg(unix)]
        if self
            .common
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some_and(|frame| !frame.running)
        {
            return false;
        }
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
        #[cfg(unix)]
        if let Some(frame) = &mut *self
            .common
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            frame.running = false;
        }
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
                proxy: proxy.map(ProxyFrame::status),
            }),
        }
    }
}
