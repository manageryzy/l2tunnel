//! Linux device and route host (CL-22, CL-23). Devices are persistent TUN/TAP
//! interfaces created by this service; routes belong to the running session.
//! The ownership record lives in `<state-dir>/host-state.json`, so a restarted
//! service still knows what it owns and removes routes a crash left behind.
//! Nothing this service did not create is changed or removed.
use super::host::{Host, HostChange, HostContext, HostFuture};
use crate::local::{DeviceChange, DeviceLayer, DeviceState, RouteChange, RouteState};
use l2tunnel_device::PacketLayer;
use l2tunnel_platform_linux::{
    TunTap,
    netconf::{self, Netconf, Prefix, Route},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const STATE_FILE: &str = "host-state.json";
/// Largest accepted ownership record.
const STATE_LIMIT: u64 = 256 * 1024;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedRoute {
    destination: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gateway: Option<IpAddr>,
    device: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    metric: Option<u32>,
    purpose: String,
}
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    /// Owned devices by name.
    devices: BTreeMap<String, DeviceLayer>,
    /// Owned session routes.
    routes: Vec<OwnedRoute>,
}

/// The Linux host.
pub struct LinuxHost {
    path: PathBuf,
    record: Mutex<Record>,
    runtime: tokio::runtime::Handle,
    /// Self reference for the asynchronous session-end release.
    me: std::sync::Weak<LinuxHost>,
}

fn refusal(context: &str, error: io::Error) -> String {
    format!("{context}: {error}")
}
fn layer_of(name: &str) -> Option<DeviceLayer> {
    // tun_flags exists only for TUN/TAP devices; IFF_TUN = 1, IFF_TAP = 2.
    let text = std::fs::read_to_string(format!("/sys/class/net/{name}/tun_flags")).ok()?;
    let flags = u32::from_str_radix(text.trim().trim_start_matches("0x"), 16).ok()?;
    match flags & 0x3 {
        1 => Some(DeviceLayer::Tun),
        2 => Some(DeviceLayer::Tap),
        _ => None,
    }
}

/// Check that `directory` exists, is a directory owned by this process's
/// user (via a probe file) and is not writable by group or others.
fn check_directory(directory: &Path) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(directory)?;
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--state-dir must be a directory (not a symlink)",
        ));
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "--state-dir must not be group- or world-writable",
        ));
    }
    let probe = directory.join(".owner-probe");
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&probe)?;
    let owner = file.metadata()?.uid();
    drop(file);
    std::fs::remove_file(&probe)?;
    if owner != metadata.uid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "--state-dir must be owned by the service user",
        ));
    }
    Ok(())
}

impl LinuxHost {
    /// Open the ownership record in `directory` and remove routes a previous
    /// run left behind. Runs on the service's Tokio runtime.
    pub async fn open(directory: &Path) -> io::Result<Arc<Self>> {
        check_directory(directory)?;
        let path = directory.join(STATE_FILE);
        let record = match std::fs::metadata(&path) {
            Ok(metadata) if metadata.len() > STATE_LIMIT => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "host ownership record is too large",
                ));
            }
            Ok(_) => serde_json::from_slice(&std::fs::read(&path)?)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Record::default(),
            Err(error) => return Err(error),
        };
        let host = Arc::new_cyclic(|me| Self {
            path,
            record: Mutex::new(record),
            runtime: tokio::runtime::Handle::current(),
            me: me.clone(),
        });
        host.release_routes().await?;
        Ok(host)
    }
    fn record(&self) -> io::Result<std::sync::MutexGuard<'_, Record>> {
        self.record
            .lock()
            .map_err(|_| io::Error::other("host ownership record lock poisoned"))
    }
    fn save(&self, record: &Record) -> io::Result<()> {
        let text = serde_json::to_vec_pretty(record).map_err(io::Error::other)?;
        let temporary = self.path.with_extension("tmp");
        {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&temporary)?;
            file.write_all(&text)?;
            file.sync_all()?;
        }
        std::fs::rename(&temporary, &self.path)
    }
    fn update(&self, change: impl FnOnce(&mut Record)) -> io::Result<()> {
        let mut record = self.record()?;
        let mut next = record.clone();
        change(&mut next);
        self.save(&next)?;
        *record = next;
        Ok(())
    }
    /// Remove every recorded route (missing routes are already gone).
    async fn release_routes(&self) -> io::Result<()> {
        let routes = self.record()?.routes.clone();
        if routes.is_empty() {
            return Ok(());
        }
        let netconf = Netconf::open()?;
        let links = netconf.links().await?;
        for owned in routes.iter().rev() {
            if let Ok(route) = resolve(&links, owned) {
                match netconf.delete_route(&route).await {
                    Ok(()) => {}
                    Err(error) if error.raw_os_error() == Some(ROUTE_MISSING) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        self.update(|record| record.routes.clear())
    }
    async fn create_device(
        &self,
        name: String,
        layer: DeviceLayer,
        mtu: Option<u32>,
        addresses: Vec<String>,
        up: bool,
    ) -> Result<String, String> {
        let netconf = Netconf::open().map_err(|error| refusal("netlink", error))?;
        if netconf
            .link(&name)
            .await
            .map_err(|error| refusal("netlink", error))?
            .is_some()
        {
            return Err(format!("{name} already exists"));
        }
        let packet = match layer {
            DeviceLayer::Tun => PacketLayer::Ip,
            DeviceLayer::Tap => PacketLayer::Ethernet,
        };
        let created = TunTap::create_persistent(&name, packet, None)
            .map_err(|error| refusal("create", error))?;
        self.update(|record| {
            record.devices.insert(created.clone(), layer);
        })
        .map_err(|error| refusal("record", error))?;
        let configured = async {
            let link = netconf
                .link(&created)
                .await?
                .ok_or_else(|| io::Error::other("created device disappeared"))?;
            for address in &addresses {
                netconf.add_address(link.index, parse(address)?).await?;
            }
            netconf.set_link(link.index, mtu, Some(up)).await
        }
        .await;
        if let Err(error) = configured {
            // Undo the partial create: the device and its record.
            if let Ok(Some(link)) = netconf.link(&created).await {
                let _deleted = netconf.delete_link(link.index).await;
            }
            let _forgotten = self.update(|record| {
                record.devices.remove(&created);
            });
            return Err(refusal("configure", error));
        }
        Ok(format!("created {} {created}", layer_name(layer)))
    }
    fn owned_device(&self, name: &str) -> Result<(), String> {
        let owned = self
            .record()
            .map_err(|error| refusal("record", error))?
            .devices
            .contains_key(name);
        if owned {
            Ok(())
        } else {
            Err(format!("{name} is not owned by this service"))
        }
    }
    async fn change_device(&self, change: DeviceChange) -> Result<String, String> {
        match change {
            DeviceChange::Create {
                name,
                layer,
                mtu,
                addresses,
                up,
            } => self.create_device(name, layer, mtu, addresses, up).await,
            DeviceChange::Configure {
                name,
                mtu,
                add,
                remove,
                up,
            } => {
                self.owned_device(&name)?;
                let netconf = Netconf::open().map_err(|error| refusal("netlink", error))?;
                let link = netconf
                    .link(&name)
                    .await
                    .map_err(|error| refusal("netlink", error))?
                    .ok_or_else(|| format!("{name} no longer exists"))?;
                for address in &remove {
                    let prefix = parse(address).map_err(|error| refusal("address", error))?;
                    netconf
                        .delete_address(link.index, prefix)
                        .await
                        .map_err(|error| refusal("remove address", error))?;
                }
                for address in &add {
                    let prefix = parse(address).map_err(|error| refusal("address", error))?;
                    netconf
                        .add_address(link.index, prefix)
                        .await
                        .map_err(|error| refusal("add address", error))?;
                }
                netconf
                    .set_link(link.index, mtu, up)
                    .await
                    .map_err(|error| refusal("set link", error))?;
                Ok(format!("configured {name}"))
            }
            DeviceChange::Delete { name } => {
                self.owned_device(&name)?;
                let netconf = Netconf::open().map_err(|error| refusal("netlink", error))?;
                if let Some(link) = netconf
                    .link(&name)
                    .await
                    .map_err(|error| refusal("netlink", error))?
                {
                    netconf
                        .delete_link(link.index)
                        .await
                        .map_err(|error| refusal("delete", error))?;
                }
                // The kernel dropped its routes with the device.
                self.update(|record| {
                    record.devices.remove(&name);
                    record.routes.retain(|route| route.device != name);
                })
                .map_err(|error| refusal("record", error))?;
                Ok(format!("deleted {name}"))
            }
        }
    }
    async fn add_owned(&self, netconf: &Netconf, owned: OwnedRoute) -> io::Result<()> {
        let links = netconf.links().await?;
        let route = resolve(&links, &owned)?;
        netconf.add_route(&route).await?;
        self.update(|record| record.routes.push(owned))
    }
    /// Remove every owned route for which `keep(position, route)` is false.
    async fn remove_owned(
        &self,
        netconf: &Netconf,
        keep: impl Fn(usize, &OwnedRoute) -> bool,
    ) -> io::Result<usize> {
        let links = netconf.links().await?;
        let remove: Vec<OwnedRoute> = self
            .record()?
            .routes
            .iter()
            .enumerate()
            .filter(|(position, route)| !keep(*position, route))
            .map(|(_, route)| route.clone())
            .collect();
        for owned in remove.iter().rev() {
            if let Ok(route) = resolve(&links, owned) {
                match netconf.delete_route(&route).await {
                    Ok(()) => {}
                    Err(error) if error.raw_os_error() == Some(ROUTE_MISSING) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        self.update(|record| {
            let mut position = 0;
            record.routes.retain(|route| {
                let kept = keep(position, route);
                position += 1;
                kept
            });
        })?;
        Ok(remove.len())
    }
    async fn change_route(
        &self,
        change: RouteChange,
        context: HostContext,
    ) -> Result<String, String> {
        let netconf = Netconf::open().map_err(|error| refusal("netlink", error))?;
        match change {
            RouteChange::Add {
                destination,
                device,
                gateway,
                metric,
            } => {
                let gateway = gateway
                    .map(|text| text.parse::<IpAddr>())
                    .transpose()
                    .map_err(|_| "invalid gateway".to_owned())?;
                let owned = OwnedRoute {
                    destination: destination.clone(),
                    gateway,
                    device: device.clone(),
                    metric,
                    purpose: "route".into(),
                };
                self.add_owned(&netconf, owned)
                    .await
                    .map_err(|error| refusal("add route", error))?;
                Ok(format!("route {destination} via {device}"))
            }
            RouteChange::Remove {
                destination,
                device,
            } => {
                let owned = self
                    .record()
                    .map_err(|error| refusal("record", error))?
                    .routes
                    .iter()
                    .any(|route| route.destination == destination && route.device == device);
                if !owned {
                    return Err(format!(
                        "{destination} via {device} is not owned by this service"
                    ));
                }
                self.remove_owned(&netconf, |_, route| {
                    !(route.destination == destination && route.device == device)
                })
                .await
                .map_err(|error| refusal("remove route", error))?;
                Ok(format!("removed {destination} via {device}"))
            }
            RouteChange::Default {
                enabled: false,
                device,
            } => {
                let removed = self
                    .remove_owned(&netconf, |_, route| {
                        !(matches!(route.purpose.as_str(), "default" | "peer_exception")
                            && (route.device == device || route.purpose == "peer_exception"))
                    })
                    .await
                    .map_err(|error| refusal("remove default", error))?;
                Ok(format!("removed {removed} default-route entries"))
            }
            RouteChange::Default {
                enabled: true,
                device,
            } => {
                let peer = context
                    .peer
                    .ok_or_else(|| "the peer's outer address is not known yet".to_owned())?;
                self.route_everything(&netconf, peer, device).await
            }
        }
    }
    async fn route_everything(
        &self,
        netconf: &Netconf,
        peer: IpAddr,
        device: String,
    ) -> Result<String, String> {
        let links = netconf
            .links()
            .await
            .map_err(|error| refusal("netlink", error))?;
        let tunnel = links
            .iter()
            .find(|link| link.name == device)
            .ok_or_else(|| format!("{device} does not exist"))?;
        let routes = netconf
            .routes()
            .await
            .map_err(|error| refusal("netlink", error))?;
        let path = netconf::best_route(&routes, peer, Some(tunnel.index))
            .ok_or_else(|| format!("no existing route toward the peer {peer}"))?;
        let path_device = path
            .device
            .and_then(|index| links.iter().find(|link| link.index == index))
            .map(|link| link.name.clone())
            .ok_or_else(|| "the peer's current route has no device".to_owned())?;
        let host_length = if peer.is_ipv4() { 32 } else { 128 };
        let halves: [String; 2] = if peer.is_ipv4() {
            ["0.0.0.0/1".into(), "128.0.0.0/1".into()]
        } else {
            ["::/1".into(), "8000::/1".into()]
        };
        let mut wanted = vec![OwnedRoute {
            destination: format!("{peer}/{host_length}"),
            gateway: path.gateway,
            device: path_device,
            metric: None,
            purpose: "peer_exception".into(),
        }];
        wanted.extend(halves.iter().map(|destination| OwnedRoute {
            destination: destination.clone(),
            gateway: None,
            device: device.clone(),
            metric: None,
            purpose: "default".into(),
        }));
        let before = self
            .record()
            .map_err(|error| refusal("record", error))?
            .routes
            .len();
        for owned in wanted {
            if let Err(error) = self.add_owned(netconf, owned).await {
                // Undo the routes this request added (those after `before`).
                let _undone = self
                    .remove_owned(netconf, |position, _| position < before)
                    .await;
                return Err(refusal("route everything", error));
            }
        }
        Ok(format!(
            "all traffic through {device}; peer {peer} stays on its current path"
        ))
    }
}

fn layer_name(layer: DeviceLayer) -> &'static str {
    match layer {
        DeviceLayer::Tun => "TUN",
        DeviceLayer::Tap => "TAP",
    }
}
fn parse(text: &str) -> io::Result<Prefix> {
    Prefix::parse(text)
}
/// ESRCH: netlink's answer for deleting a route that no longer exists.
const ROUTE_MISSING: i32 = 3;
fn resolve(links: &[netconf::Link], owned: &OwnedRoute) -> io::Result<Route> {
    let device = links
        .iter()
        .find(|link| link.name == owned.device)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "route device does not exist"))?;
    Ok(Route {
        destination: parse(&owned.destination)?,
        gateway: owned.gateway,
        device: Some(device.index),
        metric: owned.metric,
    })
}
fn unspecified(route: &Route) -> bool {
    match route.destination.address {
        IpAddr::V4(address) => address == Ipv4Addr::UNSPECIFIED && route.destination.length == 0,
        IpAddr::V6(address) => address == Ipv6Addr::UNSPECIFIED && route.destination.length == 0,
    }
}

impl Host for LinuxHost {
    fn devices(&self) -> HostFuture<'_, io::Result<Vec<DeviceState>>> {
        Box::pin(async move {
            let netconf = Netconf::open()?;
            let owned = self.record()?.devices.clone();
            let mut devices = Vec::new();
            for link in netconf.links().await? {
                let layer = layer_of(&link.name);
                if layer.is_none() && !owned.contains_key(&link.name) {
                    continue;
                }
                let addresses = netconf
                    .addresses(link.index)
                    .await?
                    .iter()
                    .map(ToString::to_string)
                    .collect();
                devices.push(DeviceState {
                    owned: owned.contains_key(&link.name),
                    name: link.name,
                    layer,
                    mtu: link.mtu,
                    up: link.up,
                    addresses,
                });
            }
            Ok(devices)
        })
    }
    fn routes(&self) -> HostFuture<'_, io::Result<Vec<RouteState>>> {
        Box::pin(async move {
            let netconf = Netconf::open()?;
            let links = netconf.links().await?;
            let owned = self.record()?.routes.clone();
            let name = |index: Option<u32>| {
                index.and_then(|index| {
                    links
                        .iter()
                        .find(|link| link.index == index)
                        .map(|link| link.name.clone())
                })
            };
            Ok(netconf
                .routes()
                .await?
                .into_iter()
                .map(|route| {
                    let device = name(route.device);
                    let destination = if unspecified(&route) {
                        format!("{}/0", route.destination.address)
                    } else {
                        route.destination.to_string()
                    };
                    let record = owned.iter().find(|owned| {
                        Some(&owned.device) == device.as_ref()
                            && parse(&owned.destination).ok() == Some(route.destination)
                    });
                    RouteState {
                        destination,
                        gateway: route.gateway.map(|gateway| gateway.to_string()),
                        device,
                        metric: route.metric,
                        owned: record.is_some(),
                        purpose: record.map(|record| record.purpose.clone()),
                    }
                })
                .collect())
        })
    }
    fn apply(
        &self,
        change: HostChange,
        context: HostContext,
    ) -> HostFuture<'_, Result<String, String>> {
        Box::pin(async move {
            match change {
                HostChange::Device(change) => self.change_device(change).await,
                HostChange::Route(change) => self.change_route(change, context).await,
            }
        })
    }
    fn release(&self) -> HostFuture<'_, ()> {
        Box::pin(async move {
            if let Err(error) = self.release_routes().await {
                eprintln!("l2tunnel: releasing session routes failed: {error}");
            }
        })
    }
    fn session_ended(&self) {
        let pending = self.record().is_ok_and(|record| !record.routes.is_empty());
        if let (true, Some(host)) = (pending, self.me.upgrade()) {
            self.runtime.spawn(async move {
                if let Err(error) = host.release_routes().await {
                    eprintln!("l2tunnel: releasing session routes failed: {error}");
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_round_trip_strictly_and_directories_are_checked() -> io::Result<()> {
        let record = Record {
            devices: BTreeMap::from([("l2t0".to_owned(), DeviceLayer::Tun)]),
            routes: vec![OwnedRoute {
                destination: "0.0.0.0/1".into(),
                gateway: None,
                device: "l2t0".into(),
                metric: None,
                purpose: "default".into(),
            }],
        };
        let text = serde_json::to_string(&record).map_err(io::Error::other)?;
        let back: Record = serde_json::from_str(&text).map_err(io::Error::other)?;
        assert_eq!(back, record);
        assert!(serde_json::from_str::<Record>(r#"{"devices":{},"routes":[],"x":1}"#).is_err());

        let directory = std::env::temp_dir().join(format!("l2t-host-{}", std::process::id()));
        std::fs::create_dir_all(&directory)?;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o777))?;
        assert!(check_directory(&directory).is_err(), "world-writable");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
        check_directory(&directory)?;
        let file = directory.join("file");
        std::fs::write(&file, b"")?;
        assert!(check_directory(&file).is_err(), "not a directory");
        std::fs::remove_dir_all(&directory)?;
        Ok(())
    }

    #[test]
    fn routes_resolve_only_through_existing_devices() -> io::Result<()> {
        let links = [netconf::Link {
            index: 7,
            name: "l2t0".into(),
            mtu: Some(1400),
            up: true,
        }];
        let owned = OwnedRoute {
            destination: "10.20.0.0/16".into(),
            gateway: None,
            device: "l2t0".into(),
            metric: Some(5),
            purpose: "route".into(),
        };
        let route = resolve(&links, &owned)?;
        assert_eq!((route.device, route.metric), (Some(7), Some(5)));
        let missing = OwnedRoute {
            device: "gone0".into(),
            ..owned
        };
        assert!(resolve(&links, &missing).is_err());
        Ok(())
    }

    /// Real netlink run. Needs CAP_NET_ADMIN, so run it only inside a
    /// throwaway network namespace, never against the host's own network:
    /// `sudo unshare -n <test binary> --ignored --exact
    /// service::host_linux::tests::owned_devices_and_session_routes_in_a_private_namespace`
    #[tokio::test]
    #[ignore = "needs CAP_NET_ADMIN inside a private network namespace"]
    async fn owned_devices_and_session_routes_in_a_private_namespace() -> io::Result<()> {
        // Refuse to run where the host's real interfaces are visible.
        let netconf = Netconf::open()?;
        let foreign: Vec<String> = netconf
            .links()
            .await?
            .into_iter()
            .map(|link| link.name)
            .filter(|name| name != "lo")
            .collect();
        assert!(
            foreign.is_empty(),
            "not a fresh network namespace: {foreign:?}"
        );
        let directory = std::env::temp_dir().join(format!("l2t-host-lab-{}", std::process::id()));
        std::fs::create_dir_all(&directory)?;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
        let host = LinuxHost::open(&directory).await?;
        let create = |name: &str, address: &str| {
            HostChange::Device(DeviceChange::Create {
                name: name.into(),
                layer: DeviceLayer::Tun,
                mtu: Some(1400),
                addresses: vec![address.into()],
                up: true,
            })
        };
        let none = HostContext::default();
        let apply = |change| host.apply(change, none);
        apply(create("l2tlab0", "10.77.0.1/24"))
            .await
            .map_err(io::Error::other)?;
        apply(create("l2tlab1", "10.88.0.2/24"))
            .await
            .map_err(io::Error::other)?;
        assert!(
            apply(create("l2tlab1", "10.88.0.3/24")).await.is_err(),
            "exists"
        );
        assert!(
            apply(HostChange::Device(DeviceChange::Delete {
                name: "lo".into()
            }))
            .await
            .is_err(),
            "preexisting devices are never removed"
        );
        let devices = host.devices().await?;
        assert!(
            devices
                .iter()
                .any(|d| d.name == "l2tlab1" && d.owned && d.mtu == Some(1400))
        );
        apply(HostChange::Route(RouteChange::Add {
            destination: "10.20.0.0/16".into(),
            device: "l2tlab1".into(),
            gateway: None,
            metric: Some(5),
        }))
        .await
        .map_err(io::Error::other)?;
        let peer = HostContext {
            peer: Some("10.77.0.9".parse().map_err(io::Error::other)?),
        };
        host.apply(
            HostChange::Route(RouteChange::Default {
                enabled: true,
                device: "l2tlab1".into(),
            }),
            peer,
        )
        .await
        .map_err(io::Error::other)?;
        let owned: Vec<(String, Option<String>)> = host
            .routes()
            .await?
            .into_iter()
            .filter(|route| route.owned)
            .map(|route| (route.destination, route.purpose))
            .collect();
        assert_eq!(owned.len(), 4, "{owned:?}");
        assert!(owned.contains(&("10.77.0.9/32".into(), Some("peer_exception".into()))));
        // A restarted service finds the record and releases the session routes.
        drop(host);
        let host = LinuxHost::open(&directory).await?;
        assert!(host.routes().await?.iter().all(|route| !route.owned));
        for name in ["l2tlab0", "l2tlab1"] {
            host.apply(
                HostChange::Device(DeviceChange::Delete { name: name.into() }),
                none,
            )
            .await
            .map_err(io::Error::other)?;
        }
        assert!(host.devices().await?.is_empty());
        std::fs::remove_dir_all(&directory)?;
        Ok(())
    }
}
