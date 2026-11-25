//! Service-side Linux network configuration over rtnetlink: links, addresses
//! and main-table routes. Every call needs CAP_NET_ADMIN in the caller's
//! network namespace; nothing here decides ownership (the service does).
use futures_util::TryStreamExt;
use rtnetlink::packet_route::{
    AddressFamily,
    address::{AddressAttribute, AddressMessage},
    link::{LinkAttribute, LinkFlags, LinkMessage},
    route::{RouteAddress, RouteAttribute, RouteMessage, RouteProtocol},
};
use rtnetlink::{Handle, LinkUnspec, RouteMessageBuilder};
use std::io;
use std::net::IpAddr;

/// Most links, addresses or routes read in one listing.
pub const LIST_LIMIT: usize = 1024;
/// Linux main routing table.
pub const MAIN_TABLE: u32 = 254;

fn netlink(error: rtnetlink::Error) -> io::Error {
    match error {
        rtnetlink::Error::NetlinkError(message) => message.code.map_or_else(
            || io::Error::other("netlink error"),
            |code| io::Error::from_raw_os_error(-code.get()),
        ),
        other => io::Error::other(other.to_string()),
    }
}

/// One network interface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Link {
    /// Kernel interface index.
    pub index: u32,
    /// Interface name.
    pub name: String,
    /// Current MTU.
    pub mtu: Option<u32>,
    /// Administratively up.
    pub up: bool,
}

/// One interface address with its prefix length.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Prefix {
    /// Address (or network for routes).
    pub address: IpAddr,
    /// Prefix length.
    pub length: u8,
}
impl Prefix {
    /// A checked prefix: at most 32 bits for IPv4 and 128 for IPv6.
    pub fn new(address: IpAddr, length: u8) -> io::Result<Self> {
        let maximum = if address.is_ipv4() { 32 } else { 128 };
        if length > maximum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "prefix length exceeds the address size",
            ));
        }
        Ok(Self { address, length })
    }
    /// Parse `ADDRESS/LENGTH`.
    pub fn parse(text: &str) -> io::Result<Self> {
        let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "expected ADDRESS/LENGTH");
        let (address, length) = text.split_once('/').ok_or_else(invalid)?;
        Self::new(
            address.parse().map_err(|_| invalid())?,
            length.parse().map_err(|_| invalid())?,
        )
    }
    /// Whether `address` lies inside this prefix (never across families).
    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.address, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let shift = 32_u32.saturating_sub(u32::from(self.length));
                let mask = u32::MAX.checked_shl(shift).unwrap_or(0);
                u32::from(network) & mask == u32::from(address) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let shift = 128_u32.saturating_sub(u32::from(self.length));
                let mask = u128::MAX.checked_shl(shift).unwrap_or(0);
                u128::from(network) & mask == u128::from(address) & mask
            }
            _ => false,
        }
    }
}
impl std::fmt::Display for Prefix {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}/{}", self.address, self.length)
    }
}

/// One main-table unicast route.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Route {
    /// Destination prefix.
    pub destination: Prefix,
    /// Next-hop gateway, if any.
    pub gateway: Option<IpAddr>,
    /// Output interface index.
    pub device: Option<u32>,
    /// Route priority (metric).
    pub metric: Option<u32>,
}

/// A netlink session bound to the current Tokio runtime.
pub struct Netconf {
    handle: Handle,
}
impl Netconf {
    /// Open a netlink socket; its connection task runs on the current runtime.
    pub fn open() -> io::Result<Self> {
        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);
        Ok(Self { handle })
    }

    fn link_of(message: &LinkMessage) -> Option<Link> {
        let mut name = None;
        let mut mtu = None;
        for attribute in &message.attributes {
            match attribute {
                LinkAttribute::IfName(value) => name = Some(value.clone()),
                LinkAttribute::Mtu(value) => mtu = Some(*value),
                _ => {}
            }
        }
        Some(Link {
            index: message.header.index,
            name: name?,
            mtu,
            up: message.header.flags.contains(LinkFlags::Up),
        })
    }
    /// Every interface, at most [`LIST_LIMIT`].
    pub async fn links(&self) -> io::Result<Vec<Link>> {
        let mut stream = self.handle.link().get().execute();
        let mut links = Vec::new();
        while let Some(message) = stream.try_next().await.map_err(netlink)? {
            if links.len() == LIST_LIMIT {
                return Err(io::Error::other("too many interfaces"));
            }
            links.extend(Self::link_of(&message));
        }
        Ok(links)
    }
    /// One interface by name.
    pub async fn link(&self, name: &str) -> io::Result<Option<Link>> {
        Ok(self
            .links()
            .await?
            .into_iter()
            .find(|link| link.name == name))
    }
    /// Set MTU and/or administrative state.
    pub async fn set_link(&self, index: u32, mtu: Option<u32>, up: Option<bool>) -> io::Result<()> {
        let mut builder = LinkUnspec::new_with_index(index);
        if let Some(mtu) = mtu {
            builder = builder.mtu(mtu);
        }
        builder = match up {
            Some(true) => builder.up(),
            Some(false) => builder.down(),
            None => builder,
        };
        self.handle
            .link()
            .set(builder.build())
            .execute()
            .await
            .map_err(netlink)
    }
    /// Delete an interface (a persistent TUN/TAP device included).
    pub async fn delete_link(&self, index: u32) -> io::Result<()> {
        self.handle
            .link()
            .del(index)
            .execute()
            .await
            .map_err(netlink)
    }

    fn address_of(message: &AddressMessage) -> Option<Prefix> {
        message
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                AddressAttribute::Address(address) => Some(Prefix {
                    address: *address,
                    length: message.header.prefix_len,
                }),
                _ => None,
            })
    }
    /// Addresses of one interface.
    pub async fn addresses(&self, index: u32) -> io::Result<Vec<Prefix>> {
        let mut stream = self
            .handle
            .address()
            .get()
            .set_link_index_filter(index)
            .execute();
        let mut addresses = Vec::new();
        while let Some(message) = stream.try_next().await.map_err(netlink)? {
            if addresses.len() == LIST_LIMIT {
                return Err(io::Error::other("too many addresses"));
            }
            addresses.extend(Self::address_of(&message));
        }
        Ok(addresses)
    }
    /// Add one address.
    pub async fn add_address(&self, index: u32, prefix: Prefix) -> io::Result<()> {
        self.handle
            .address()
            .add(index, prefix.address, prefix.length)
            .execute()
            .await
            .map_err(netlink)
    }
    /// Remove one address.
    pub async fn delete_address(&self, index: u32, prefix: Prefix) -> io::Result<()> {
        let mut stream = self
            .handle
            .address()
            .get()
            .set_link_index_filter(index)
            .set_address_filter(prefix.address)
            .set_prefix_length_filter(prefix.length)
            .execute();
        while let Some(message) = stream.try_next().await.map_err(netlink)? {
            self.handle
                .address()
                .del(message)
                .execute()
                .await
                .map_err(netlink)?;
        }
        Ok(())
    }

    fn route_of(message: &RouteMessage) -> Option<Route> {
        let header = &message.header;
        let mut destination = None;
        let mut gateway = None;
        let mut device = None;
        let mut metric = None;
        let mut table = u32::from(header.table);
        for attribute in &message.attributes {
            match attribute {
                RouteAttribute::Destination(RouteAddress::Inet(value)) => {
                    destination = Some(IpAddr::V4(*value));
                }
                RouteAttribute::Destination(RouteAddress::Inet6(value)) => {
                    destination = Some(IpAddr::V6(*value));
                }
                RouteAttribute::Gateway(RouteAddress::Inet(value)) => {
                    gateway = Some(IpAddr::V4(*value));
                }
                RouteAttribute::Gateway(RouteAddress::Inet6(value)) => {
                    gateway = Some(IpAddr::V6(*value));
                }
                RouteAttribute::Oif(value) => device = Some(*value),
                RouteAttribute::Priority(value) => metric = Some(*value),
                RouteAttribute::Table(value) => table = *value,
                _ => {}
            }
        }
        if table != MAIN_TABLE {
            return None;
        }
        let unspecified = match header.address_family {
            AddressFamily::Inet => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            AddressFamily::Inet6 => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            _ => return None,
        };
        Some(Route {
            destination: Prefix {
                address: destination.unwrap_or(unspecified),
                length: header.destination_prefix_length,
            },
            gateway,
            device,
            metric,
        })
    }
    /// Main-table routes of both families, at most [`LIST_LIMIT`].
    pub async fn routes(&self) -> io::Result<Vec<Route>> {
        let mut routes = Vec::new();
        for request in [
            RouteMessageBuilder::<std::net::Ipv4Addr>::new().build(),
            RouteMessageBuilder::<std::net::Ipv6Addr>::new().build(),
        ] {
            let mut stream = self.handle.route().get(request).execute();
            while let Some(message) = stream.try_next().await.map_err(netlink)? {
                if routes.len() == LIST_LIMIT {
                    return Err(io::Error::other("too many routes"));
                }
                routes.extend(Self::route_of(&message));
            }
        }
        Ok(routes)
    }
    fn message(route: &Route) -> io::Result<RouteMessage> {
        let mut builder = RouteMessageBuilder::<IpAddr>::new()
            .destination_prefix(route.destination.address, route.destination.length)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?
            .table_id(MAIN_TABLE)
            .protocol(RouteProtocol::Static);
        if let Some(gateway) = route.gateway {
            builder = builder
                .gateway(gateway)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        }
        if let Some(device) = route.device {
            builder = builder.output_interface(device);
        }
        if let Some(metric) = route.metric {
            builder = builder.priority(metric);
        }
        Ok(builder.build())
    }
    /// Add one route; an existing identical route fails with `AlreadyExists`.
    pub async fn add_route(&self, route: &Route) -> io::Result<()> {
        self.handle
            .route()
            .add(Self::message(route)?)
            .execute()
            .await
            .map_err(netlink)
    }
    /// Delete one route.
    pub async fn delete_route(&self, route: &Route) -> io::Result<()> {
        self.handle
            .route()
            .del(Self::message(route)?)
            .execute()
            .await
            .map_err(netlink)
    }
}

/// Longest-prefix main-table route toward `address`, ignoring `exclude`
/// (the tunnel device), as the peer-exception route needs.
pub fn best_route(routes: &[Route], address: IpAddr, exclude: Option<u32>) -> Option<Route> {
    routes
        .iter()
        .filter(|route| route.device.is_none() || route.device != exclude)
        .filter(|route| route.destination.contains(address))
        .max_by_key(|route| (route.destination.length, std::cmp::Reverse(route.metric)))
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(text: &str, device: u32, metric: u32) -> io::Result<Route> {
        Ok(Route {
            destination: Prefix::parse(text)?,
            gateway: None,
            device: Some(device),
            metric: Some(metric),
        })
    }

    #[test]
    fn prefixes_parse_and_contain_strictly() -> io::Result<()> {
        let net = Prefix::parse("10.20.0.0/16")?;
        assert!(net.contains("10.20.9.1".parse().map_err(io::Error::other)?));
        assert!(!net.contains("10.21.0.1".parse().map_err(io::Error::other)?));
        assert!(!net.contains("::1".parse().map_err(io::Error::other)?));
        let all = Prefix::parse("0.0.0.0/0")?;
        assert!(all.contains("203.0.113.7".parse().map_err(io::Error::other)?));
        let host = Prefix::parse("203.0.113.7/32")?;
        assert!(host.contains("203.0.113.7".parse().map_err(io::Error::other)?));
        assert!(!host.contains("203.0.113.8".parse().map_err(io::Error::other)?));
        let v6 = Prefix::parse("2001:db8::/32")?;
        assert!(v6.contains("2001:db8:1::5".parse().map_err(io::Error::other)?));
        for bad in ["10.0.0.0/33", "::/129", "10.0.0.0", "x/8", "10.0.0.0/-1"] {
            assert!(Prefix::parse(bad).is_err(), "{bad}");
        }
        assert_eq!(net.to_string(), "10.20.0.0/16");
        Ok(())
    }

    #[test]
    fn best_route_prefers_longest_prefix_outside_the_tunnel() -> io::Result<()> {
        let routes = [
            route("0.0.0.0/0", 2, 100)?,
            route("0.0.0.0/1", 9, 50)?,
            route("203.0.113.0/24", 3, 10)?,
        ];
        let peer = "203.0.113.7".parse().map_err(io::Error::other)?;
        assert_eq!(
            best_route(&routes, peer, Some(9)).map(|r| r.device),
            Some(Some(3))
        );
        let other = "8.8.8.8".parse().map_err(io::Error::other)?;
        // The tunnel's own half-default is ignored for the exception route.
        assert_eq!(
            best_route(&routes, other, Some(9)).map(|r| r.device),
            Some(Some(2))
        );
        Ok(())
    }
}
