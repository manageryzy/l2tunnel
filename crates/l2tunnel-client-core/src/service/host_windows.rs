//! Windows device and route host (CL-22, CL-23, CL-25).
//!
//! Tracks every route installed by this service in `<state-dir>/host-state.json`
//! so session end, service stop, and crash recovery remove ONLY service-created
//! routes without disturbing pre-existing Windows interfaces or routing tables.
//! Default routes automatically install a host bypass route for the outer tunnel
//! peer over its original gateway/interface before directing traffic to Wintun.
use super::host::{Host, HostChange, HostContext, HostFuture};
use crate::local::{DeviceChange, DeviceLayer, DeviceState, RouteChange, RouteState};
use l2tunnel_platform_windows::{MtuController, routes as win_routes};
use serde::{Deserialize, Serialize};
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const STATE_FILE: &str = "host-state.json";
const STATE_LIMIT: u64 = 256 * 1024;
/// Low metric for tunnel routes so they win over default LAN routes without
/// deleting or modifying the host's original default gateway.
const TUNNEL_ROUTE_METRIC: u32 = 5;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedRoute {
    destination: IpAddr,
    prefix: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gateway: Option<IpAddr>,
    interface_index: u32,
    device: String,
    metric: u32,
    purpose: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    routes: Vec<OwnedRoute>,
}

/// Windows device/route host implementing the shared [`Host`] trait.
pub struct WindowsHost {
    path: PathBuf,
    record: Mutex<Record>,
    mtu: MtuController,
    runtime: tokio::runtime::Handle,
    me: std::sync::Weak<WindowsHost>,
}

fn parse_cidr(text: &str) -> Result<(IpAddr, u8), String> {
    let (addr, len) = text
        .split_once('/')
        .ok_or_else(|| format!("route destination {text:?} must be IP/PREFIX"))?;
    let ip: IpAddr = addr
        .parse()
        .map_err(|_| format!("invalid route IP address {addr:?}"))?;
    let prefix: u8 = len
        .parse()
        .map_err(|_| format!("invalid route prefix {len:?}"))?;
    let normalized =
        win_routes::normalize_prefix(ip, prefix).map_err(|e| format!("invalid route: {e}"))?;
    Ok((normalized, prefix))
}

impl WindowsHost {
    /// Open the Windows host state directory and clean up any leftover routes
    /// recorded by a previous crashed service run.
    pub async fn open(directory: &Path, mtu: MtuController) -> io::Result<Arc<Self>> {
        std::fs::create_dir_all(directory)?;
        let path = directory.join(STATE_FILE);
        let prior = load_record(&path)?;
        let host = Arc::new_cyclic(|me| Self {
            path,
            record: Mutex::new(prior),
            mtu,
            runtime: tokio::runtime::Handle::current(),
            me: me.clone(),
        });
        host.release_all_routes().await;
        Ok(host)
    }

    fn save_locked(&self, record: &Record) -> io::Result<()> {
        let bytes = serde_json::to_vec_pretty(record).map_err(io::Error::other)?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, bytes)?;
        if self.path.exists() {
            let _ = std::fs::remove_file(&self.path);
        }
        std::fs::rename(&tmp, &self.path)
    }

    fn resolve_interface_index(&self, device: &str) -> Result<u32, String> {
        if let (Some(active_name), Some(idx)) = (self.mtu.name(), self.mtu.if_index())
            && active_name.eq_ignore_ascii_case(device)
        {
            return Ok(idx);
        }
        if device.eq_ignore_ascii_case("wintun") || device.eq_ignore_ascii_case("active") {
            if let Some(idx) = self.mtu.if_index() {
                return Ok(idx);
            }
            return Err("no active Wintun adapter is open".to_owned());
        }
        win_routes::interface_index_by_alias(device)
            .map_err(|e| format!("unknown Windows interface {device:?}: {e}"))
    }

    async fn release_all_routes(&self) {
        let owned = match self.record.lock() {
            Ok(mut guard) => {
                let taken = std::mem::take(&mut guard.routes);
                let _ = self.save_locked(&guard);
                taken
            }
            Err(_) => return,
        };
        if owned.is_empty() {
            return;
        }
        let _ = tokio::task::spawn_blocking(move || {
            for route in owned.into_iter().rev() {
                let _ = win_routes::delete_route(
                    route.destination,
                    route.prefix,
                    route.gateway,
                    route.interface_index,
                );
            }
        })
        .await;
    }

    fn install_route_entry(&self, entry: OwnedRoute) -> Result<(), String> {
        win_routes::add_route(
            entry.destination,
            entry.prefix,
            entry.gateway,
            entry.interface_index,
            entry.metric,
        )
        .map_err(|e| format!("add route {}/{}: {e}", entry.destination, entry.prefix))?;
        let mut guard = self
            .record
            .lock()
            .map_err(|_| "windows host lock poisoned".to_owned())?;
        if !guard.routes.iter().any(|r| {
            r.destination == entry.destination
                && r.prefix == entry.prefix
                && r.interface_index == entry.interface_index
        }) {
            guard.routes.push(entry);
            self.save_locked(&guard)
                .map_err(|e| format!("persist host state: {e}"))?;
        }
        Ok(())
    }

    fn apply_blocking(&self, change: HostChange, context: HostContext) -> Result<String, String> {
        match change {
            HostChange::Device(DeviceChange::Create { .. })
            | HostChange::Device(DeviceChange::Delete { .. }) => Err(
                "Windows Wintun adapters are owned per session; connect a profile to create the adapter"
                    .to_owned(),
            ),
            HostChange::Device(DeviceChange::Configure { name, mtu, .. }) => {
                if let Some(mtu) = mtu {
                    if let Some(active) = self.mtu.name()
                        && active.eq_ignore_ascii_case(&name)
                    {
                        self.mtu
                            .set_mtu(mtu)
                            .map_err(|e| format!("set Wintun MTU: {e}"))?;
                        return Ok(format!("set {name} MTU to {mtu}"));
                    }
                    return Err(format!("device {name} is not the active owned Wintun adapter"));
                }
                Err("Windows device configure currently supports --mtu on the active Wintun adapter".to_owned())
            }
            HostChange::Route(RouteChange::Add {
                destination,
                gateway,
                device,
                metric,
            }) => {
                let (ip, prefix) = parse_cidr(&destination)?;
                let gw_ip = gateway
                    .as_deref()
                    .map(|s| {
                        s.parse::<IpAddr>()
                            .map_err(|_| format!("invalid gateway IP {s:?}"))
                    })
                    .transpose()?;
                let if_index = self.resolve_interface_index(&device)?;
                let metric = metric.unwrap_or(TUNNEL_ROUTE_METRIC);
                self.install_route_entry(OwnedRoute {
                    destination: ip,
                    prefix,
                    gateway: gw_ip,
                    interface_index: if_index,
                    device: device.clone(),
                    metric,
                    purpose: "session".to_owned(),
                })?;
                Ok(format!("added route {ip}/{prefix} via {device}"))
            }
            HostChange::Route(RouteChange::Remove {
                destination,
                device,
            }) => {
                let (ip, prefix) = parse_cidr(&destination)?;
                let mut guard = self
                    .record
                    .lock()
                    .map_err(|_| "windows host lock poisoned".to_owned())?;
                let pos = guard
                    .routes
                    .iter()
                    .position(|r| {
                        r.destination == ip
                            && r.prefix == prefix
                            && r.device.eq_ignore_ascii_case(&device)
                    })
                    .ok_or_else(|| format!("route {ip}/{prefix} on {device} is not owned by this service"))?;
                let removed = guard.routes.remove(pos);
                let _ = self.save_locked(&guard);
                drop(guard);
                win_routes::delete_route(
                    removed.destination,
                    removed.prefix,
                    removed.gateway,
                    removed.interface_index,
                )
                .map_err(|e| format!("delete route {ip}/{prefix}: {e}"))?;
                Ok(format!("removed route {ip}/{prefix} on {device}"))
            }
            HostChange::Route(RouteChange::Default { enabled, device }) => {
                if !enabled {
                    let removed_entries: Vec<OwnedRoute> = {
                        let mut guard = self
                            .record
                            .lock()
                            .map_err(|_| "windows host lock poisoned".to_owned())?;
                        let mut keep = Vec::new();
                        let mut remove = Vec::new();
                        for r in guard.routes.drain(..) {
                            if r.purpose == "default" || r.purpose == "peer_bypass" {
                                remove.push(r);
                            } else {
                                keep.push(r);
                            }
                        }
                        guard.routes = keep;
                        let _ = self.save_locked(&guard);
                        remove
                    };
                    for r in removed_entries {
                        let _ = win_routes::delete_route(
                            r.destination,
                            r.prefix,
                            r.gateway,
                            r.interface_index,
                        );
                    }
                    return Ok("removed default tunnel routes".to_owned());
                }
                let peer = context.peer.ok_or_else(|| {
                    "default route requires a connected session with a known peer IP".to_owned()
                })?;
                let tun_index = self.resolve_interface_index(&device)?;
                // 1. Install peer anti-loop bypass route over the original path BEFORE adding tunnel halves.
                let best = win_routes::best_route(peer)
                    .map_err(|e| format!("lookup original route to peer {peer}: {e}"))?;
                if best.interface_index != tun_index {
                    let host_prefix = if peer.is_ipv4() { 32 } else { 128 };
                    self.install_route_entry(OwnedRoute {
                        destination: peer,
                        prefix: host_prefix,
                        gateway: best.gateway,
                        interface_index: best.interface_index,
                        device: best.interface_alias,
                        metric: 1,
                        purpose: "peer_bypass".to_owned(),
                    })?;
                }
                // 2. Install two /1 split-default routes so the host's original 0.0.0.0/0 is never touched.
                for (cidr, prefix) in [
                    (IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 1u8),
                    (IpAddr::V4(std::net::Ipv4Addr::new(128, 0, 0, 0)), 1u8),
                ] {
                    self.install_route_entry(OwnedRoute {
                        destination: cidr,
                        prefix,
                        gateway: None,
                        interface_index: tun_index,
                        device: device.clone(),
                        metric: TUNNEL_ROUTE_METRIC,
                        purpose: "default".to_owned(),
                    })?;
                }
                Ok(format!(
                    "enabled default IPv4 route via {device} with peer bypass for {peer}"
                ))
            }
        }
    }
}

fn load_record(path: &Path) -> io::Result<Record> {
    match std::fs::metadata(path) {
        Ok(meta) if meta.len() > STATE_LIMIT => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "host-state.json exceeds size bound",
        )),
        Ok(_) => {
            let bytes = std::fs::read(path)?;
            serde_json::from_slice(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Record::default()),
        Err(e) => Err(e),
    }
}

impl Host for WindowsHost {
    fn devices(&self) -> HostFuture<'_, io::Result<Vec<DeviceState>>> {
        let mtu_ctrl = self.mtu.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let mut out = Vec::new();
                if let Some(name) = mtu_ctrl.name() {
                    let mtu = mtu_ctrl.get_mtu().ok();
                    out.push(DeviceState {
                        name,
                        layer: Some(DeviceLayer::Tun),
                        mtu,
                        up: true,
                        addresses: Vec::new(),
                        owned: true,
                    });
                }
                Ok(out)
            })
            .await
            .map_err(io::Error::other)?
        })
    }

    fn routes(&self) -> HostFuture<'_, io::Result<Vec<RouteState>>> {
        let owned = self
            .record
            .lock()
            .map(|r| r.routes.clone())
            .unwrap_or_default();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let table = win_routes::list_routes()?;
                let mut out = Vec::with_capacity(table.len());
                for r in table {
                    let matched = owned.iter().find(|o| {
                        o.destination == r.destination
                            && o.prefix == r.prefix
                            && o.interface_index == r.interface_index
                    });
                    out.push(RouteState {
                        destination: format!("{}/{}", r.destination, r.prefix),
                        gateway: r.gateway.map(|ip| ip.to_string()),
                        device: Some(r.interface_alias),
                        metric: Some(r.metric),
                        owned: matched.is_some(),
                        purpose: matched.map(|o| o.purpose.clone()),
                    });
                }
                Ok(out)
            })
            .await
            .map_err(io::Error::other)?
        })
    }

    fn apply(
        &self,
        change: HostChange,
        context: HostContext,
    ) -> HostFuture<'_, Result<String, String>> {
        let me = self.me.upgrade();
        Box::pin(async move {
            let Some(host) = me else {
                return Err("windows host stopped".to_owned());
            };
            tokio::task::spawn_blocking(move || host.apply_blocking(change, context))
                .await
                .map_err(|e| format!("windows host worker failed: {e}"))?
        })
    }

    fn session_ended(&self) {
        if let Some(host) = self.me.upgrade() {
            self.runtime.spawn(async move {
                host.release_all_routes().await;
            });
        }
    }

    fn release(&self) -> HostFuture<'_, ()> {
        Box::pin(async move {
            self.release_all_routes().await;
        })
    }
}
