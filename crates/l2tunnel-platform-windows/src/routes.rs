//! Windows IPv4/IPv6 routing table access via IP Helper API (`iphlpapi.dll`).
//!
//! Portable route types and validation run on every host; native Win32 calls
//! live in the narrow documented `ffi` submodule on Windows targets.
//! No shell-out to `route.exe` or `netsh.exe` is used.
use std::io;
use std::net::IpAddr;

/// One IPv4 or IPv6 route entry in the Windows routing table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WinRoute {
    /// Destination network address.
    pub destination: IpAddr,
    /// Prefix length (`0..=32` for IPv4, `0..=128` for IPv6).
    pub prefix: u8,
    /// Optional next-hop gateway (on-link when `None` or unspecified).
    pub gateway: Option<IpAddr>,
    /// Windows interface index (`IF_INDEX`).
    pub interface_index: u32,
    /// Resolved Windows interface alias/name when available.
    pub interface_alias: String,
    /// Route metric offset.
    pub metric: u32,
}

/// Validate destination address, prefix length, and gateway family agreement.
pub fn validate_route(destination: IpAddr, prefix: u8, gateway: Option<IpAddr>) -> io::Result<()> {
    let max = match destination {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "route prefix length exceeds address width",
        ));
    }
    if let Some(gw) = gateway
        && gw.is_ipv4() != destination.is_ipv4()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "route gateway and destination address families must match",
        ));
    }
    Ok(())
}

/// Normalize a destination IP by masking off host bits beyond `prefix`.
pub fn normalize_prefix(ip: IpAddr, prefix: u8) -> io::Result<IpAddr> {
    validate_route(ip, prefix, None)?;
    Ok(match ip {
        IpAddr::V4(v4) => {
            let mask = if prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - u32::from(prefix))
            };
            IpAddr::V4(std::net::Ipv4Addr::from(u32::from(v4) & mask))
        }
        IpAddr::V6(v6) => {
            let mask = if prefix == 0 {
                0u128
            } else {
                u128::MAX << (128 - u32::from(prefix))
            };
            IpAddr::V6(std::net::Ipv6Addr::from(u128::from(v6) & mask))
        }
    })
}

/// List IPv4 and IPv6 routes from the Windows routing table.
pub fn list_routes() -> io::Result<Vec<WinRoute>> {
    #[cfg(windows)]
    {
        ffi::list_routes()
    }
    #[cfg(not(windows))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows route table queries require Windows",
        ))
    }
}

/// Find the current best Windows route to `destination` (used for mandatory peer
/// anti-loop bypass routes before installing default/redirect tunnel routes).
pub fn best_route(destination: IpAddr) -> io::Result<WinRoute> {
    #[cfg(windows)]
    {
        ffi::best_route(destination)
    }
    #[cfg(not(windows))]
    {
        let _ = destination;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows best-route lookup requires Windows",
        ))
    }
}

/// Resolve a Windows interface alias (adapter name) to its interface index.
pub fn interface_index_by_alias(alias: &str) -> io::Result<u32> {
    if alias.is_empty() || alias.len() > 256 || alias.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Windows interface alias",
        ));
    }
    #[cfg(windows)]
    {
        ffi::interface_index_by_alias(alias)
    }
    #[cfg(not(windows))]
    {
        let _ = alias;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows interface resolution requires Windows",
        ))
    }
}

/// Add a route to the Windows IP forwarding table via `CreateIpForwardEntry2`.
pub fn add_route(
    destination: IpAddr,
    prefix: u8,
    gateway: Option<IpAddr>,
    interface_index: u32,
    metric: u32,
) -> io::Result<()> {
    let dest = normalize_prefix(destination, prefix)?;
    validate_route(dest, prefix, gateway)?;
    #[cfg(windows)]
    {
        ffi::add_route(dest, prefix, gateway, interface_index, metric)
    }
    #[cfg(not(windows))]
    {
        let _ = (interface_index, metric);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows route modification requires Windows",
        ))
    }
}

/// Delete a route from the Windows IP forwarding table via `DeleteIpForwardEntry2`.
pub fn delete_route(
    destination: IpAddr,
    prefix: u8,
    gateway: Option<IpAddr>,
    interface_index: u32,
) -> io::Result<()> {
    let dest = normalize_prefix(destination, prefix)?;
    validate_route(dest, prefix, gateway)?;
    #[cfg(windows)]
    {
        ffi::delete_route(dest, prefix, gateway, interface_index)
    }
    #[cfg(not(windows))]
    {
        let _ = interface_index;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows route modification requires Windows",
        ))
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod ffi {
    #![deny(clippy::undocumented_unsafe_blocks)]

    use super::WinRoute;
    use std::ffi::OsStr;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceAliasToLuid, ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToAlias,
        ConvertInterfaceLuidToIndex, CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable,
        GetBestRoute2, GetIpForwardTable2, InitializeIpForwardEntry, MIB_IPFORWARD_ROW2,
        MIB_IPFORWARD_TABLE2,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN,
        SOCKADDR_IN6, SOCKADDR_INET,
    };

    const MAX_ALIAS_WCHARS: usize = 257;

    struct MibTableGuard(*mut MIB_IPFORWARD_TABLE2);

    impl Drop for MibTableGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: pointer was allocated by `GetIpForwardTable2` and freed once here.
                unsafe { FreeMibTable(self.0.cast()) };
            }
        }
    }

    fn to_sockaddr_inet(ip: IpAddr) -> SOCKADDR_INET {
        match ip {
            IpAddr::V4(v4) => SOCKADDR_INET {
                Ipv4: SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_port: 0,
                    sin_addr: IN_ADDR {
                        S_un: IN_ADDR_0 {
                            S_addr: u32::from_ne_bytes(v4.octets()),
                        },
                    },
                    sin_zero: [0; 8],
                },
            },
            IpAddr::V6(v6) => SOCKADDR_INET {
                Ipv6: SOCKADDR_IN6 {
                    sin6_family: AF_INET6,
                    sin6_port: 0,
                    sin6_flowinfo: 0,
                    sin6_addr: IN6_ADDR {
                        u: IN6_ADDR_0 { Byte: v6.octets() },
                    },
                    Anonymous: Default::default(),
                },
            },
        }
    }

    fn from_sockaddr_inet(sa: &SOCKADDR_INET) -> Option<IpAddr> {
        // SAFETY: `si_family` is the common leading field of every union variant.
        let family = unsafe { sa.si_family };
        if family == AF_INET {
            // SAFETY: `family == AF_INET` selects the `Ipv4` variant.
            let raw = unsafe { sa.Ipv4.sin_addr.S_un.S_addr };
            Some(IpAddr::V4(Ipv4Addr::from(raw.to_ne_bytes())))
        } else if family == AF_INET6 {
            // SAFETY: `family == AF_INET6` selects the `Ipv6` variant.
            let octets = unsafe { sa.Ipv6.sin6_addr.u.Byte };
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        } else {
            None
        }
    }

    fn alias_from_luid(luid: &NET_LUID_LH, index: u32) -> String {
        let mut buf = [0u16; MAX_ALIAS_WCHARS];
        // SAFETY: `luid` is a valid pointer and `buf` holds `MAX_ALIAS_WCHARS` UTF-16 code units.
        let rc = unsafe { ConvertInterfaceLuidToAlias(luid, buf.as_mut_ptr(), buf.len()) };
        if rc == NO_ERROR {
            let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            String::from_utf16_lossy(&buf[..end])
        } else {
            format!("if#{index}")
        }
    }

    fn row_to_win_route(row: &MIB_IPFORWARD_ROW2) -> Option<WinRoute> {
        let destination = from_sockaddr_inet(&row.DestinationPrefix.Prefix)?;
        let gateway = from_sockaddr_inet(&row.NextHop).filter(|ip| !ip.is_unspecified());
        let alias = alias_from_luid(&row.InterfaceLuid, row.InterfaceIndex);
        Some(WinRoute {
            destination,
            prefix: row.DestinationPrefix.PrefixLength,
            gateway,
            interface_index: row.InterfaceIndex,
            interface_alias: alias,
            metric: row.Metric,
        })
    }

    pub(super) fn interface_index_by_alias(alias: &str) -> io::Result<u32> {
        let wide: Vec<u16> = OsStr::new(alias).encode_wide().chain(Some(0)).collect();
        let mut luid = NET_LUID_LH::default();
        // SAFETY: `wide` is NUL-terminated UTF-16 and `luid` is a valid out pointer.
        let rc = unsafe { ConvertInterfaceAliasToLuid(wide.as_ptr(), &mut luid) };
        if rc != NO_ERROR {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        let mut index = 0u32;
        // SAFETY: `luid` and `index` are valid pointers.
        let rc = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) };
        if rc != NO_ERROR {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        Ok(index)
    }

    pub(super) fn list_routes() -> io::Result<Vec<WinRoute>> {
        let mut table_ptr: *mut MIB_IPFORWARD_TABLE2 = null_mut();
        // SAFETY: `table_ptr` is a valid out pointer freed by `MibTableGuard`.
        let rc = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table_ptr) };
        if rc != NO_ERROR {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        let guard = MibTableGuard(table_ptr);
        if guard.0.is_null() {
            return Ok(Vec::new());
        }
        // SAFETY: `guard.0` is non-null and holds `NumEntries` contiguous `MIB_IPFORWARD_ROW2` items.
        let rows = unsafe {
            let count = (*guard.0).NumEntries as usize;
            let first = std::ptr::addr_of!((*guard.0).Table).cast::<MIB_IPFORWARD_ROW2>();
            std::slice::from_raw_parts(first, count)
        };
        Ok(rows.iter().filter_map(row_to_win_route).collect())
    }

    pub(super) fn best_route(destination: IpAddr) -> io::Result<WinRoute> {
        let dest_sa = to_sockaddr_inet(destination);
        let mut best = MIB_IPFORWARD_ROW2::default();
        let mut src = SOCKADDR_INET::default();
        // SAFETY: all pointers are valid stack locals; optional `interfaceluid` and
        // `sourceaddress` are documented to accept null.
        let rc = unsafe { GetBestRoute2(null(), 0, null(), &dest_sa, 0, &mut best, &mut src) };
        if rc != NO_ERROR {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        row_to_win_route(&best).ok_or_else(|| io::Error::other("invalid best route family"))
    }

    fn build_row(
        destination: IpAddr,
        prefix: u8,
        gateway: Option<IpAddr>,
        interface_index: u32,
        metric: u32,
    ) -> io::Result<MIB_IPFORWARD_ROW2> {
        let mut row = MIB_IPFORWARD_ROW2::default();
        // SAFETY: `row` is a valid stack struct.
        unsafe { InitializeIpForwardEntry(&mut row) };
        let mut luid = NET_LUID_LH::default();
        // SAFETY: `luid` is a valid out pointer.
        let rc = unsafe { ConvertInterfaceIndexToLuid(interface_index, &mut luid) };
        if rc != NO_ERROR {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        row.InterfaceLuid = luid;
        row.InterfaceIndex = interface_index;
        row.DestinationPrefix.Prefix = to_sockaddr_inet(destination);
        row.DestinationPrefix.PrefixLength = prefix;
        row.NextHop = match gateway {
            Some(gw) => to_sockaddr_inet(gw),
            None => match destination {
                IpAddr::V4(_) => to_sockaddr_inet(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                IpAddr::V6(_) => to_sockaddr_inet(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
            },
        };
        row.Metric = metric;
        Ok(row)
    }

    pub(super) fn add_route(
        destination: IpAddr,
        prefix: u8,
        gateway: Option<IpAddr>,
        interface_index: u32,
        metric: u32,
    ) -> io::Result<()> {
        let row = build_row(destination, prefix, gateway, interface_index, metric)?;
        // SAFETY: `row` is fully initialized by `InitializeIpForwardEntry` and our fields.
        let rc = unsafe { CreateIpForwardEntry2(&row) };
        if rc == NO_ERROR || rc == ERROR_OBJECT_ALREADY_EXISTS {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(rc as i32))
        }
    }

    pub(super) fn delete_route(
        destination: IpAddr,
        prefix: u8,
        gateway: Option<IpAddr>,
        interface_index: u32,
    ) -> io::Result<()> {
        let row = build_row(destination, prefix, gateway, interface_index, 0)?;
        // SAFETY: `row` is fully initialized.
        let rc = unsafe { DeleteIpForwardEntry2(&row) };
        if rc == NO_ERROR || rc == ERROR_NOT_FOUND {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(rc as i32))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn route_validation_and_normalization() -> io::Result<()> {
        assert_eq!(
            normalize_prefix(IpAddr::V4(Ipv4Addr::new(10, 81, 0, 42)), 24)?,
            IpAddr::V4(Ipv4Addr::new(10, 81, 0, 0))
        );
        assert_eq!(
            normalize_prefix(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 0)?,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        );
        assert!(validate_route(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 33, None).is_err());
        assert!(
            validate_route(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                8,
                Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
            )
            .is_err()
        );
        assert!(interface_index_by_alias("").is_err());
        assert!(interface_index_by_alias("bad\0name").is_err());
        Ok(())
    }
}
