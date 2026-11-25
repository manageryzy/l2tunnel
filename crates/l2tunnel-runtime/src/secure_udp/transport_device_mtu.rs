//! Device MTU ordering for live inner-size switches (live tuning, owner
//! decisions 2, 8 and 9 in docs/modules/live-tuning.md).
//!
//! The service injects a setter for the session's TUN/TAP device. Before an
//! end takes part in a switch to a smaller inner packet size, it lowers its
//! device MTU: the leader before it proposes, the follower before it
//! acknowledges the proposal. Both ends raise the MTU only after a switch
//! to a larger size has completed, and return to the current entry's size
//! after an aborted switch. The protocol library stays free of OS handles:
//! the loop awaits the setter between turns.
use super::{Driver, common_contract, owner};
use l2tunnel::record_configuration::Configuration;
use l2tunnel_device::PacketLayer;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

/// How long one MTU change may take before it counts as failed.
pub(super) const SET_WAIT: Duration = Duration::from_secs(2);
/// Ethernet header bytes a TAP device's MTU excludes.
const ETHERNET_HEADER: usize = 14;

/// Sets the MTU of the session's device. Implemented by the service, which
/// owns the device and the privilege to configure it.
pub trait DeviceMtu: Send + Sync {
    /// Set the device MTU to `mtu` bytes.
    fn set(&self, mtu: u32) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>>;
}

/// Device MTU state reported with the session.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeviceMtuSnapshot {
    /// MTU last set on the device by this session; `None` before the first.
    pub applied: Option<u32>,
    /// MTU the current protocol entry needs.
    pub wanted: Option<u32>,
    /// Changes that failed or timed out.
    pub failures: u64,
    /// Kind of the last failure.
    pub last_error: Option<io::ErrorKind>,
}

/// Whether an end may take part in a switch to a target now.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Readiness {
    /// The device already fits the target.
    Ready,
    /// A lowering was requested; try again after it.
    Wait,
    /// Lowering to the target failed.
    Failed,
}

pub(super) struct Gate {
    setter: Arc<dyn DeviceMtu>,
    layer: PacketLayer,
    role: l2tunnel_management::Role,
    applied: Option<u32>,
    wanted: Option<u32>,
    // The last value whose change failed; not retried automatically.
    failed: Option<u32>,
    current: Option<u32>,
    failures: u64,
    last_error: Option<io::ErrorKind>,
}
impl Gate {
    pub(super) fn new(
        setter: Arc<dyn DeviceMtu>,
        layer: PacketLayer,
        role: l2tunnel_management::Role,
    ) -> Self {
        Self {
            setter,
            layer,
            role,
            applied: None,
            wanted: None,
            failed: None,
            current: None,
            failures: 0,
            last_error: None,
        }
    }
    /// The device MTU an entry needs: its largest local inner packet, less
    /// the Ethernet header on a TAP device.
    pub(super) fn mtu_of(&self, configuration: &Configuration) -> Option<u32> {
        let native = configuration.descriptor().direction(self.role).max_native();
        let mtu = match self.layer {
            PacketLayer::Ip => native,
            PacketLayer::Ethernet => native.checked_sub(ETHERNET_HEADER)?,
        };
        u32::try_from(mtu).ok()
    }
    /// Before taking part in a switch to `target`: lower first when the
    /// device is larger (decision 9).
    pub(super) fn ready_for(&mut self, target: &Configuration) -> Readiness {
        let Some(mtu) = self.mtu_of(target) else {
            return Readiness::Ready;
        };
        if self.applied.is_some_and(|applied| applied <= mtu) {
            return Readiness::Ready;
        }
        if self.failed == Some(mtu) {
            return Readiness::Failed;
        }
        self.wanted = Some(mtu);
        Readiness::Wait
    }
    /// With no switch in flight, follow the current entry: the first
    /// setting, a raise after a completed switch up, or a return after an
    /// aborted switch down.
    pub(super) fn reconcile(&mut self, current: &Configuration, busy: bool) {
        self.current = self.mtu_of(current);
        if busy || self.wanted.is_some() {
            return;
        }
        if let Some(mtu) = self.current
            && self.applied != Some(mtu)
            && self.failed != Some(mtu)
        {
            self.wanted = Some(mtu);
        }
    }
    pub(super) fn take_wanted(&mut self) -> Option<(Arc<dyn DeviceMtu>, u32)> {
        let mtu = self.wanted.take()?;
        (self.applied != Some(mtu)).then(|| (self.setter.clone(), mtu))
    }
    pub(super) fn done(&mut self, mtu: u32, result: io::Result<()>) {
        match result {
            Ok(()) => {
                self.applied = Some(mtu);
                self.failed = None;
            }
            Err(error) => {
                self.failures = self.failures.saturating_add(1);
                self.last_error = Some(error.kind());
                self.failed = Some(mtu);
            }
        }
    }
    pub(super) fn snapshot(&self) -> DeviceMtuSnapshot {
        DeviceMtuSnapshot {
            applied: self.applied,
            wanted: self.current,
            failures: self.failures,
            last_error: self.last_error,
        }
    }
}

impl Driver {
    /// Take the setter from the service's requests when the loop starts.
    pub(super) fn install_device_mtu(&mut self, layer: PacketLayer, requests: &super::Requests) {
        let super::Requests::Common(Some(requests)) = requests else {
            return;
        };
        let (Some(setter), Some(_)) = (&requests.2, &self.common) else {
            return;
        };
        let role = common_contract::mg_role(self.info.role);
        self.device_mtu = Some(Box::new(Gate::new(setter.clone(), layer, role)));
    }
    /// The MTU change the loop should make now, if any.
    pub(super) fn device_mtu_due(&mut self) -> Option<(Arc<dyn DeviceMtu>, u32)> {
        let gate = self.device_mtu.as_deref_mut()?;
        let runtime = self.common.as_deref()?;
        let owner::DataOwner::Common(state) = &self.owner;
        let busy = state.peer().operation().is_some()
            || runtime.request.is_some()
            || state.awaiting_admission();
        gate.reconcile(state.current(), busy);
        gate.take_wanted()
    }
    /// Record the result of a change the loop made.
    pub(super) fn device_mtu_done(&mut self, mtu: u32, result: io::Result<()>) {
        if let Some(gate) = self.device_mtu.as_deref_mut() {
            gate.done(mtu, result);
            if let Some(runtime) = self.common.as_deref_mut() {
                runtime.observation_dirty = true;
            }
        }
    }
}
