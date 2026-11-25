//! Service-owned device and route changes (CL-22, CL-23). The platform host
//! does the privileged work and keeps the ownership record; the service
//! actor sequences each change as one keyed operation.
use super::*;
use crate::local::{DeviceChange, DeviceState, RouteChange, RouteState};
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;

/// Boxed host future.
pub type HostFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One requested host change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostChange {
    /// Device change.
    Device(DeviceChange),
    /// Route change.
    Route(RouteChange),
}

/// What the running session tells the host.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HostContext {
    /// Outer address of the connected peer, for the default-route exception.
    pub peer: Option<IpAddr>,
}

/// Platform side of device and route management. Implementations never
/// remove configuration they did not create.
pub trait Host: Send + Sync + 'static {
    /// Devices visible to the service, with ownership.
    fn devices(&self) -> HostFuture<'_, io::Result<Vec<DeviceState>>>;
    /// Main-table routes, with ownership.
    fn routes(&self) -> HostFuture<'_, io::Result<Vec<RouteState>>>;
    /// Apply one validated change; `Err` is a bounded refusal reason after
    /// any partial step was undone.
    fn apply(
        &self,
        change: HostChange,
        context: HostContext,
    ) -> HostFuture<'_, Result<String, String>>;
    /// The session ended: remove every route the service added for it.
    /// Must not block; the host schedules its own release.
    fn session_ended(&self);
    /// Remove the session's routes now (before the service process exits).
    fn release(&self) -> HostFuture<'_, ()>;
}

/// Attach the platform host when the service was started with
/// `--state-dir DIR`; without it devices and routes stay unavailable.
pub async fn attach_state_dir(handle: &Handle, directory: Option<&String>) -> io::Result<()> {
    let Some(directory) = directory else {
        return Ok(());
    };
    #[cfg(target_os = "linux")]
    {
        let host = super::host_linux::LinuxHost::open(std::path::Path::new(directory)).await?;
        handle
            .attach_host(host)
            .map_err(|_| io::Error::other("a device/route host is already attached"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (handle, directory);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "--state-dir device/route management is implemented on Linux only",
        ))
    }
}

impl Handle {
    /// Attach the platform host once; later attachments are refused.
    pub fn attach_host(&self, host: Arc<dyn Host>) -> Result<(), Arc<dyn Host>> {
        self.0.host.set(host)
    }
    /// The attached host, if any.
    pub(crate) fn host(&self) -> Option<Arc<dyn Host>> {
        self.0.host.get().cloned()
    }
    /// Submit one device change as a keyed operation.
    pub fn device(&self, change: DeviceChange, key: RequestKey) -> Result<Accepted, SubmitError> {
        let change = HostChange::Device(change);
        self.submit(
            Fingerprint::Host(change.clone()),
            Command::Host(change),
            key,
        )
    }
    /// Submit one route change as a keyed operation.
    pub fn route(&self, change: RouteChange, key: RequestKey) -> Result<Accepted, SubmitError> {
        let change = HostChange::Route(change);
        self.submit(
            Fingerprint::Host(change.clone()),
            Command::Host(change),
            key,
        )
    }
    /// Outer address of the connected peer from the latest observation.
    pub(super) fn peer_address(&self) -> Option<IpAddr> {
        let snapshot = {
            let state = self.0.lock();
            Self::snapshot_locked(&state)
        };
        let observation = self.observation(&snapshot)?;
        let peer = &observation.common.as_ref()?.peer;
        peer.parse::<std::net::SocketAddr>()
            .map(|address| address.ip())
            .or_else(|_| peer.parse::<IpAddr>())
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::{
        DeviceLayer, Feature, OperationAction, OperationReply, OperationRequest, OperationResult,
    };
    use std::sync::Mutex;

    /// Records every change; refuses deleting `busy0`.
    #[derive(Default)]
    struct FakeHost {
        applied: Mutex<Vec<HostChange>>,
        released: Mutex<u32>,
    }
    impl Host for FakeHost {
        fn devices(&self) -> HostFuture<'_, io::Result<Vec<DeviceState>>> {
            Box::pin(async {
                Ok(vec![DeviceState {
                    name: "l2t0".into(),
                    layer: Some(DeviceLayer::Tun),
                    mtu: Some(1400),
                    up: true,
                    addresses: vec!["10.88.0.2/24".into()],
                    owned: true,
                }])
            })
        }
        fn routes(&self) -> HostFuture<'_, io::Result<Vec<RouteState>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn apply(
            &self,
            change: HostChange,
            _context: HostContext,
        ) -> HostFuture<'_, Result<String, String>> {
            Box::pin(async move {
                if let HostChange::Device(DeviceChange::Delete { name }) = &change
                    && name == "busy0"
                {
                    return Err("busy0 is not owned by this service".into());
                }
                let summary = format!("{change:?}");
                self.applied
                    .lock()
                    .map_err(|_| "poisoned".to_owned())?
                    .push(change);
                Ok(summary)
            })
        }
        fn session_ended(&self) {
            if let Ok(mut released) = self.released.lock() {
                *released += 1;
            }
        }
        fn release(&self) -> HostFuture<'_, ()> {
            Box::pin(async {})
        }
    }
    fn request(action: OperationAction) -> OperationRequest {
        OperationRequest::new(action)
    }
    fn create(name: &str) -> DeviceChange {
        DeviceChange::Create {
            name: name.into(),
            layer: DeviceLayer::Tun,
            mtu: Some(1400),
            addresses: vec!["10.88.0.2/24".into()],
            up: true,
        }
    }
    async fn wait(handle: &Handle, id: u64) -> OperationReply {
        handle
            .operations_request(request(OperationAction::OperationWait {
                operation: id,
                timeout_ms: 5_000,
                service: None,
            }))
            .await
    }

    #[tokio::test]
    async fn device_changes_are_keyed_operations_executed_by_the_host() -> io::Result<()> {
        let (handle, run) = channel();
        let owner = tokio::spawn(run);
        // Without a host the features are unavailable and changes are refused.
        let info = handle.service_info();
        assert!(
            info.capability(Feature::Devices)
                .is_some_and(|c| !c.available)
        );
        let refused = handle
            .operations_request(request(OperationAction::Device {
                request_key: 1,
                change: create("l2t0"),
            }))
            .await;
        assert_eq!((refused.ok, refused.code.as_str()), (false, "unsupported"));

        let host = Arc::new(FakeHost::default());
        assert!(handle.attach_host(host.clone()).is_ok());
        assert!(handle.attach_host(host.clone()).is_err(), "attached once");
        assert!(
            handle
                .service_info()
                .capability(Feature::Devices)
                .is_some_and(|c| c.available)
        );
        let listed = handle
            .operations_request(request(OperationAction::DeviceList {}))
            .await;
        assert_eq!(listed.devices.map(|devices| devices.len()), Some(1));

        // An invalid change never consumes the key.
        let invalid = handle
            .operations_request(request(OperationAction::Device {
                request_key: 1,
                change: create("bad/name"),
            }))
            .await;
        assert_eq!(invalid.code, "invalid_change");
        let accepted = handle
            .operations_request(request(OperationAction::Device {
                request_key: 1,
                change: create("l2t0"),
            }))
            .await;
        assert_eq!((accepted.ok, accepted.code.as_str()), (true, "accepted"));
        let done = wait(&handle, 1).await;
        let state = done
            .operation
            .ok_or_else(|| io::Error::other("no operation"))?;
        assert_eq!(state.kind, "device");
        assert!(matches!(
            state.result,
            Some(OperationResult::HostApplied { .. })
        ));
        // Exact replay returns the same acceptance; a different change conflicts.
        let replay = handle
            .operations_request(request(OperationAction::Device {
                request_key: 1,
                change: create("l2t0"),
            }))
            .await;
        assert_eq!(replay.code, "accepted");
        let conflict = handle
            .operations_request(request(OperationAction::Device {
                request_key: 1,
                change: create("l2t1"),
            }))
            .await;
        assert_eq!(conflict.code, "conflict");
        assert_eq!(host.applied.lock().map(|list| list.len()).unwrap_or(0), 1);

        // A host refusal is a completed operation with the reason.
        handle
            .operations_request(request(OperationAction::Device {
                request_key: 2,
                change: DeviceChange::Delete {
                    name: "busy0".into(),
                },
            }))
            .await;
        let refused = wait(&handle, 2)
            .await
            .operation
            .and_then(|state| state.result);
        assert!(matches!(refused, Some(OperationResult::HostRefused { .. })));
        // Routes need a running session.
        let route = handle
            .operations_request(request(OperationAction::Route {
                request_key: 3,
                change: RouteChange::Default {
                    enabled: true,
                    device: "l2t0".into(),
                },
            }))
            .await;
        assert_eq!(route.code, "state");
        // The phase never changed.
        assert_eq!(handle.snapshot().phase, Phase::Disconnected);
        owner.abort();
        Ok(())
    }
}
