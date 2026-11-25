//! Version-5 `service_info`: identity, role, uptime and capabilities.
use super::*;
use crate::local::{Capability, Feature, OPERATIONS_VERSION, Role, ServiceInfo};

/// Reason for a feature this service build does not serve yet.
const NOT_IMPLEMENTED: &str = "not implemented by this service version";

impl Handle {
    /// Current identity and per-feature capabilities. Reading never waits.
    pub fn service_info(&self) -> ServiceInfo {
        let (role, common) = {
            let state = self.0.lock();
            let snapshot = Self::snapshot_locked(&state);
            (
                state
                    .plan
                    .as_ref()
                    .map_or(Role::Unconfigured, Prepared::role),
                matches!(snapshot.runtime, Some(Observation::SecureUdpCommon(_))),
            )
        };
        let lifecycle = if role == Role::Unconfigured && self.profiles().is_none() {
            Capability::unavailable(Feature::Lifecycle, "no retained plan and no profile store")
        } else {
            Capability::available(Feature::Lifecycle)
        };
        let catalog = if common {
            Capability::available(Feature::Catalog)
        } else {
            Capability::unavailable(Feature::Catalog, "needs a running Common profile")
        };
        let metrics = if common {
            Capability::available(Feature::Metrics)
        } else {
            Capability::unavailable(Feature::Metrics, "needs a running Common profile")
        };
        let meters = if common {
            Capability::available(Feature::Meters)
        } else {
            Capability::unavailable(Feature::Meters, "needs a running Common profile")
        };
        let host = self.host().is_some();
        let mut capabilities = vec![lifecycle, catalog, metrics, meters];
        for feature in [Feature::Devices, Feature::Routes] {
            capabilities.push(if host {
                Capability::available(feature)
            } else {
                Capability::unavailable(
                    feature,
                    "the service runs without device/route management (no --state-dir)",
                )
            });
        }
        capabilities.push(if self.profiles().is_some() {
            Capability::available(Feature::Profiles)
        } else {
            Capability::unavailable(
                Feature::Profiles,
                "the service runs one fixed option set; start it as `daemon --state-dir DIR` for stored profiles",
            )
        });
        // Keys stay files (owner decision): the service reports the key files
        // a stored profile references; generation is local to the frontends.
        capabilities.push(if self.profiles().is_some() {
            Capability::available(Feature::Keys)
        } else {
            Capability::unavailable(
                Feature::Keys,
                "key references are read from stored profiles; start the service as `daemon`",
            )
        });
        capabilities.push(Capability::unavailable(Feature::Socks5, NOT_IMPLEMENTED));
        capabilities.push(if self.0.stop.get().is_some() {
            Capability::available(Feature::Stop)
        } else {
            Capability::unavailable(
                Feature::Stop,
                "this service runs in the foreground; stop it from its terminal or service manager",
            )
        });
        capabilities.push(if role == Role::Server {
            Capability::available(Feature::Sessions)
        } else {
            Capability::unavailable(Feature::Sessions, "server role only")
        });
        capabilities.push(match super::tunnel_tests_local::unavailable(self) {
            None => Capability::available(Feature::Tests),
            Some(reason) => Capability::unavailable(Feature::Tests, &reason),
        });
        ServiceInfo {
            version: env!("CARGO_PKG_VERSION").into(),
            role,
            api: OPERATIONS_VERSION,
            uptime_ms: u64::try_from(self.0.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            capabilities,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unconfigured_service_reports_every_feature_with_reasons() {
        let (handle, _run) = channel();
        let info = handle.service_info();
        assert_eq!(info.role, Role::Unconfigured);
        assert_eq!(info.api, OPERATIONS_VERSION);
        assert!(info.capabilities.len() <= crate::local::CAPABILITY_LIMIT);
        for feature in [
            Feature::Lifecycle,
            Feature::Catalog,
            Feature::Metrics,
            Feature::Meters,
            Feature::Devices,
            Feature::Routes,
            Feature::Socks5,
            Feature::Profiles,
            Feature::Keys,
            Feature::Sessions,
        ] {
            let capability = info.capability(feature);
            assert!(
                capability
                    .is_some_and(|capability| !capability.available && capability.reason.is_some()),
                "{feature:?}"
            );
        }
    }
}
