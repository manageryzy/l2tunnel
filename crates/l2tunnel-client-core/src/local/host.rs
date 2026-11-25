//! Version-5 service-owned device and route changes (CL-22, CL-23). Reads are
//! queries; every change is a keyed operation executed by the service, which
//! records what it owns and never removes configuration it did not create.
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Longest Linux interface name (IFNAMSIZ - 1).
pub const DEVICE_NAME_LIMIT: usize = 15;
/// Most addresses in one device change.
pub const ADDRESS_LIMIT: usize = 8;
/// Most devices or routes in one listing reply.
pub const HOST_LIST_LIMIT: usize = 256;

/// Device packet layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceLayer {
    /// IP packets (TUN).
    Tun,
    /// Ethernet frames (TAP).
    Tap,
}

/// One device change.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum DeviceChange {
    /// Create a persistent service-owned device.
    Create {
        /// Interface name.
        name: String,
        /// Packet layer.
        layer: DeviceLayer,
        /// MTU, kernel default when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mtu: Option<u32>,
        /// Addresses as `ADDRESS/LENGTH`.
        #[serde(default)]
        addresses: Vec<String>,
        /// Bring the device up.
        up: bool,
    },
    /// Change a service-owned device.
    Configure {
        /// Interface name.
        name: String,
        /// New MTU.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mtu: Option<u32>,
        /// Addresses to add.
        #[serde(default)]
        add: Vec<String>,
        /// Addresses to remove.
        #[serde(default)]
        remove: Vec<String>,
        /// New administrative state.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        up: Option<bool>,
    },
    /// Delete a service-owned device.
    Delete {
        /// Interface name.
        name: String,
    },
}
impl DeviceChange {
    /// Device name the change targets.
    pub fn name(&self) -> &str {
        match self {
            Self::Create { name, .. } | Self::Configure { name, .. } | Self::Delete { name } => {
                name
            }
        }
    }
    /// Check names, prefixes and bounds before anything is submitted.
    pub fn validate(&self) -> Result<(), &'static str> {
        validate_name(self.name())?;
        let (mtu, lists): (Option<u32>, Vec<&Vec<String>>) = match self {
            Self::Create { mtu, addresses, .. } => (*mtu, vec![addresses]),
            Self::Configure {
                mtu, add, remove, ..
            } => (*mtu, vec![add, remove]),
            Self::Delete { .. } => (None, Vec::new()),
        };
        if mtu.is_some_and(|mtu| !(68..=65_535).contains(&mtu)) {
            return Err("mtu must be 68..65535");
        }
        for list in lists {
            if list.len() > ADDRESS_LIMIT {
                return Err("too many addresses");
            }
            for address in list {
                parse_prefix(address).ok_or("address must be ADDRESS/LENGTH")?;
            }
        }
        Ok(())
    }
}

/// One route change. Routes are tied to the running session: the service
/// removes every route it added when the session ends or the service stops.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum RouteChange {
    /// Route `destination` through `device`.
    Add {
        /// Destination `ADDRESS/LENGTH`.
        destination: String,
        /// Output device.
        device: String,
        /// Gateway inside the tunnel, if any.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        gateway: Option<String>,
        /// Metric.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        metric: Option<u32>,
    },
    /// Remove a service-owned route.
    Remove {
        /// Destination `ADDRESS/LENGTH`.
        destination: String,
        /// Output device.
        device: String,
    },
    /// Send all traffic of the peer's address family through `device`: two
    /// half-default routes plus an exception route for the peer's outer
    /// address over its current path. Existing routes are never replaced.
    Default {
        /// Enable or remove.
        enabled: bool,
        /// Tunnel device.
        device: String,
    },
}
impl RouteChange {
    /// Check names and prefixes before anything is submitted.
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Add {
                destination,
                device,
                gateway,
                ..
            } => {
                validate_name(device)?;
                let prefix =
                    parse_prefix(destination).ok_or("destination must be ADDRESS/LENGTH")?;
                if let Some(gateway) = gateway {
                    let gateway: IpAddr = gateway.parse().map_err(|_| "invalid gateway")?;
                    if gateway.is_ipv4() != prefix.0.is_ipv4() {
                        return Err("gateway and destination families differ");
                    }
                }
                Ok(())
            }
            Self::Remove {
                destination,
                device,
            } => {
                validate_name(device)?;
                parse_prefix(destination)
                    .map(|_| ())
                    .ok_or("destination must be ADDRESS/LENGTH")
            }
            Self::Default { device, .. } => validate_name(device),
        }
    }
}

/// Interface name rule shared by every frontend.
pub fn validate_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty()
        || name.len() > DEVICE_NAME_LIMIT
        || name == "."
        || name == ".."
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err("device name must be 1..15 of [A-Za-z0-9._-]");
    }
    Ok(())
}

/// Parse `ADDRESS/LENGTH` with a length valid for the family.
pub fn parse_prefix(text: &str) -> Option<(IpAddr, u8)> {
    let (address, length) = text.split_once('/')?;
    let address: IpAddr = address.parse().ok()?;
    let length: u8 = length.parse().ok()?;
    (length <= if address.is_ipv4() { 32 } else { 128 }).then_some((address, length))
}

/// One device as listed by the service.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceState {
    /// Interface name.
    pub name: String,
    /// TUN or TAP; absent for other interfaces.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layer: Option<DeviceLayer>,
    /// MTU.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    /// Administratively up.
    pub up: bool,
    /// Addresses as `ADDRESS/LENGTH`.
    pub addresses: Vec<String>,
    /// Created by this service (only these can be changed or deleted).
    pub owned: bool,
}

/// One main-table route as listed by the service.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteState {
    /// Destination `ADDRESS/LENGTH`.
    pub destination: String,
    /// Gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    /// Output device name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// Metric.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metric: Option<u32>,
    /// Added by this service.
    pub owned: bool,
    /// Why the service added it: `route`, `default` or `peer_exception`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changes_validate_names_prefixes_and_bounds() {
        let create = |name: &str, address: &str, mtu: Option<u32>| DeviceChange::Create {
            name: name.into(),
            layer: DeviceLayer::Tun,
            mtu,
            addresses: vec![address.into()],
            up: true,
        };
        assert_eq!(
            create("l2t0", "10.88.0.2/24", Some(1400)).validate(),
            Ok(())
        );
        assert!(create("", "10.0.0.1/24", None).validate().is_err());
        assert!(
            create("way-too-long-name0", "10.0.0.1/24", None)
                .validate()
                .is_err()
        );
        assert!(create("bad/name", "10.0.0.1/24", None).validate().is_err());
        assert!(create("..", "10.0.0.1/24", None).validate().is_err());
        assert!(create("l2t0", "10.0.0.1/33", None).validate().is_err());
        assert!(create("l2t0", "10.0.0.1", None).validate().is_err());
        assert!(create("l2t0", "fd00::1/64", Some(67)).validate().is_err());
        let route = RouteChange::Add {
            destination: "10.20.0.0/16".into(),
            device: "l2t0".into(),
            gateway: Some("fd00::1".into()),
            metric: None,
        };
        assert_eq!(
            route.validate(),
            Err("gateway and destination families differ")
        );
        assert_eq!(
            RouteChange::Default {
                enabled: true,
                device: "l2t0".into()
            }
            .validate(),
            Ok(())
        );
    }

    #[test]
    fn changes_round_trip_strictly() -> serde_json::Result<()> {
        let text = r#"{"op":"create","name":"l2t0","layer":"tap","addresses":[],"up":false}"#;
        let change: DeviceChange = serde_json::from_str(text)?;
        assert_eq!(change.name(), "l2t0");
        assert!(
            serde_json::from_str::<DeviceChange>(r#"{"op":"delete","name":"x","extra":1}"#)
                .is_err()
        );
        let route: RouteChange =
            serde_json::from_str(r#"{"op":"default","enabled":true,"device":"l2t0"}"#)?;
        assert!(matches!(route, RouteChange::Default { enabled: true, .. }));
        Ok(())
    }
}
