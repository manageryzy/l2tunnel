//! The service sets the session's device MTU (live tuning, owner decisions
//! 2 and 9 in docs/modules/live-tuning.md). A live-tuned session follows its
//! protocol entry: lowered before a switch to smaller inner packets, raised
//! after a switch to larger ones. The device's MTU from before the session
//! is restored when the session ends, for created and preexisting devices.
use l2tunnel_runtime::secure_udp::transport;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};

/// Boxed future of a device MTU operation.
pub type MtuFuture<'a, T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send + 'a>>;

/// Reads and sets one device's MTU; needs the privilege to configure it.
pub trait DeviceMtuHost: Send + Sync {
    /// Current MTU.
    fn get(&self) -> MtuFuture<'_, u32>;
    /// Set the MTU.
    fn set(&self, mtu: u32) -> MtuFuture<'_, ()>;
}

/// One session's use of a device: remembers the MTU before its first
/// change and puts it back when the session's runtime is dropped.
struct SessionMtu {
    host: Arc<dyn DeviceMtuHost>,
    original: Mutex<Option<u32>>,
}
impl transport::DeviceMtu for SessionMtu {
    fn set(&self, mtu: u32) -> MtuFuture<'_, ()> {
        Box::pin(async move {
            let known = self
                .original
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_some();
            if !known {
                let before = self.host.get().await?;
                *self.original.lock().unwrap_or_else(PoisonError::into_inner) = Some(before);
            }
            self.host.set(mtu).await
        })
    }
}
impl Drop for SessionMtu {
    fn drop(&mut self) {
        let Some(original) = self
            .original
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        else {
            return;
        };
        // The runtime is dropped from inside the service; the restore runs
        // as its own short task so dropping never blocks.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let host = self.host.clone();
            runtime.spawn(async move {
                let _restored = host.set(original).await;
            });
        }
    }
}

/// Give a live-tuned session the device MTU setter of its attachment.
pub(super) fn tune(
    attachment: &super::Attachment,
    profile: &crate::secure_udp::common_transaction_profile::Profile,
    requests: transport::CommonControlRequests,
) -> transport::CommonControlRequests {
    match (attachment.device_mtu(), profile.live_catalog()) {
        (Some(host), Some(_)) => requests.with_device_mtu(Arc::new(SessionMtu {
            host: host.clone(),
            original: Mutex::new(None),
        })),
        _ => requests,
    }
}

/// A Linux TUN/TAP device by name, configured over rtnetlink.
#[cfg(target_os = "linux")]
pub struct LinuxDevice {
    name: String,
}
#[cfg(target_os = "linux")]
impl LinuxDevice {
    /// The device named `name`.
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
    async fn link(
        &self,
    ) -> io::Result<(
        l2tunnel_platform_linux::netconf::Netconf,
        l2tunnel_platform_linux::netconf::Link,
    )> {
        let netconf = l2tunnel_platform_linux::netconf::Netconf::open()?;
        let link = netconf
            .link(&self.name)
            .await?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "device no longer exists"))?;
        Ok((netconf, link))
    }
}
#[cfg(target_os = "linux")]
impl DeviceMtuHost for LinuxDevice {
    fn get(&self) -> MtuFuture<'_, u32> {
        Box::pin(async move {
            self.link()
                .await?
                .1
                .mtu
                .ok_or_else(|| io::Error::other("device reports no MTU"))
        })
    }
    fn set(&self, mtu: u32) -> MtuFuture<'_, ()> {
        Box::pin(async move {
            let (netconf, link) = self.link().await?;
            netconf.set_link(link.index, Some(mtu), None).await
        })
    }
}

#[cfg(test)]
#[path = "device_mtu_tests.rs"]
mod tests;
