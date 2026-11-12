use crate::{
    Address, ArpMetadata, Classification, Domain, Endpoint, EthernetMetadata, FlowKey,
    FragmentMetadata, Header, IpMetadata, MAX_IPV6_EXTENSION_BYTES, MAX_IPV6_EXTENSIONS,
    MAX_VLAN_TAGS, OpaqueReason, PacketKind, PacketLayer, ParseError, ParseLimits,
    TransportMetadata, Tuple, VlanTag, ordered,
};

/// Classify one complete captured TAP frame or TUN packet without allocation.
///
/// Unknown protocols and bounded-inspection exhaustion retain opaque keys. An
/// error concerns malformed/truncated supported structure, not packet authority.
pub fn classify(
    layer: PacketLayer,
    packet: &[u8],
    limits: ParseLimits,
) -> Result<Classification, ParseError> {
    if limits.max_packet_bytes == 0
        || usize::from(limits.max_vlan_tags) > MAX_VLAN_TAGS
        || limits.max_ipv6_extensions > MAX_IPV6_EXTENSIONS
        || limits.max_ipv6_extension_bytes > MAX_IPV6_EXTENSION_BYTES
    {
        return Err(ParseError::InvalidLimits);
    }
    if packet.len() > limits.max_packet_bytes {
        return Err(ParseError::PacketTooLarge);
    }
    let mut domain = Domain::default();
    let mut ethernet = None;
    let (offset, ether_type) = match layer {
        PacketLayer::Ethernet => {
            need(packet, 14, Header::Ethernet)?;
            let mut meta = EthernetMetadata {
                source: array(packet, 6, Header::Ethernet)?,
                destination: array(packet, 0, Header::Ethernet)?,
                ether_type: u16_at(packet, 12, Header::Ethernet)?,
                vlans: [VlanTag::default(); MAX_VLAN_TAGS],
                vlan_count: 0,
                header_bytes: 14,
            };
            while matches!(meta.ether_type, 0x8100 | 0x88a8 | 0x9100) {
                if meta.vlan_count == limits.max_vlan_tags {
                    return Ok(opaque_ethernet(
                        packet.len(),
                        domain,
                        meta,
                        OpaqueReason::VlanDepth,
                    ));
                }
                let offset = meta.header_bytes;
                need(packet, offset + 4, Header::Vlan)?;
                let index = usize::from(meta.vlan_count);
                let tag = VlanTag {
                    tpid: meta.ether_type,
                    tci: u16_at(packet, offset, Header::Vlan)?,
                };
                meta.vlans[index] = tag;
                domain.tags[index] = (tag.tpid, tag.tci & 0x0fff);
                meta.vlan_count += 1;
                domain.count = meta.vlan_count;
                meta.ether_type = u16_at(packet, offset + 2, Header::Vlan)?;
                meta.header_bytes += 4;
            }
            let result = (meta.header_bytes, meta.ether_type);
            ethernet = Some(meta);
            result
        }
        PacketLayer::Ip => match packet.first().map(|first| first >> 4) {
            Some(4) => (0, 0x0800),
            Some(6) => (0, 0x86dd),
            None => return Err(ParseError::Truncated(Header::Ipv4)),
            _ => return Err(ParseError::UnknownIpVersion),
        },
    };
    let body = &packet[offset..];
    let (key, kind, ip, transport, arp) = match ether_type {
        0x0800 => {
            let (tuple, kind, ip, transport) = ipv4(body)?;
            (FlowKey { domain, tuple }, kind, Some(ip), transport, None)
        }
        0x86dd => {
            let (tuple, kind, ip, transport) = ipv6(body, limits)?;
            (FlowKey { domain, tuple }, kind, Some(ip), transport, None)
        }
        0x0806 => {
            let Some(meta) = ethernet else {
                return Err(ParseError::UnknownIpVersion);
            };
            let (tuple, kind, arp) = arp(body, meta)?;
            (FlowKey { domain, tuple }, kind, None, None, Some(arp))
        }
        value => {
            let Some(meta) = ethernet else {
                return Err(ParseError::UnknownIpVersion);
            };
            let reason = if value <= 1500 {
                need(body, usize::from(value), Header::Ethernet)?;
                OpaqueReason::Llc
            } else {
                OpaqueReason::EtherType(value)
            };
            return Ok(opaque_ethernet(packet.len(), domain, meta, reason));
        }
    };
    Ok(Classification {
        key,
        kind,
        observed_bytes: packet.len(),
        ethernet,
        ip,
        transport,
        arp,
    })
}

fn ethernet_tuple(meta: EthernetMetadata) -> Tuple {
    let (low, high) = ordered(meta.source, meta.destination);
    // The IEEE 802.3 length varies per packet; it is not a protocol identity.
    let protocol = if meta.ether_type <= 1500 {
        0
    } else {
        meta.ether_type
    };
    Tuple::Ethernet(protocol, low, high)
}

fn opaque_ethernet(
    length: usize,
    domain: Domain,
    meta: EthernetMetadata,
    reason: OpaqueReason,
) -> Classification {
    Classification {
        key: FlowKey {
            domain,
            tuple: ethernet_tuple(meta),
        },
        kind: PacketKind::Opaque(reason),
        observed_bytes: length,
        ethernet: Some(meta),
        ip: None,
        transport: None,
        arp: None,
    }
}

fn arp(
    body: &[u8],
    ethernet: EthernetMetadata,
) -> Result<(Tuple, PacketKind, ArpMetadata), ParseError> {
    need(body, 8, Header::Arp)?;
    let hlen = body[4];
    let plen = body[5];
    let length = 8 + 2 * (usize::from(hlen) + usize::from(plen));
    need(body, length, Header::Arp)?;
    let meta = ArpMetadata {
        hardware_type: u16_at(body, 0, Header::Arp)?,
        protocol_type: u16_at(body, 2, Header::Arp)?,
        hardware_bytes: hlen,
        protocol_bytes: plen,
        operation: u16_at(body, 6, Header::Arp)?,
        packet_bytes: length,
    };
    if (meta.hardware_type, meta.protocol_type, hlen, plen) == (1, 0x0800, 6, 4) {
        let (low, high) = ordered(array(body, 14, Header::Arp)?, array(body, 24, Header::Arp)?);
        Ok((Tuple::Arp(low, high), PacketKind::Arp, meta))
    } else {
        Ok((
            ethernet_tuple(ethernet),
            PacketKind::Opaque(OpaqueReason::ArpAddressFormat),
            meta,
        ))
    }
}

type IpResult = (Tuple, PacketKind, IpMetadata, Option<TransportMetadata>);

fn ipv4(body: &[u8]) -> Result<IpResult, ParseError> {
    need(body, 20, Header::Ipv4)?;
    let ihl = usize::from(body[0] & 15) * 4;
    let length = usize::from(u16_at(body, 2, Header::Ipv4)?);
    if body[0] >> 4 != 4 || ihl < 20 || length < ihl {
        return Err(ParseError::Malformed(Header::Ipv4));
    }
    need(body, length, Header::Ipv4)?;
    let mut ip = IpMetadata {
        source: Address::V4(array(body, 12, Header::Ipv4)?),
        destination: Address::V4(array(body, 16, Header::Ipv4)?),
        protocol: body[9],
        dscp: body[1] >> 2,
        ecn: body[1] & 3,
        packet_bytes: Some(length),
        header_bytes: ihl,
        fragment: None,
    };
    let bits = u16_at(body, 6, Header::Ipv4)?;
    if bits & 0x3fff != 0 {
        let fragment = FragmentMetadata {
            id: u32::from(u16_at(body, 4, Header::Ipv4)?),
            offset_bytes: u32::from(bits & 0x1fff) * 8,
            more: bits & 0x2000 != 0,
            atomic: false,
        };
        ip.fragment = Some(fragment);
        return Ok((
            fragment_tuple(ip, fragment.id),
            PacketKind::Fragment,
            ip,
            None,
        ));
    }
    transport(&body[ihl..length], ip)
}

fn ipv6(body: &[u8], limits: ParseLimits) -> Result<IpResult, ParseError> {
    need(body, 40, Header::Ipv6)?;
    if body[0] >> 4 != 6 {
        return Err(ParseError::Malformed(Header::Ipv6));
    }
    let payload = usize::from(u16_at(body, 4, Header::Ipv6)?);
    let length = 40 + payload;
    let traffic = ((body[0] & 15) << 4) | (body[1] >> 4);
    let mut ip = IpMetadata {
        source: Address::V6(array(body, 8, Header::Ipv6)?),
        destination: Address::V6(array(body, 24, Header::Ipv6)?),
        protocol: body[6],
        dscp: traffic >> 2,
        ecn: traffic & 3,
        packet_bytes: Some(length),
        header_bytes: 40,
        fragment: None,
    };
    if payload == 0 && ip.protocol == 0 {
        ip.packet_bytes = None;
        return Ok(opaque_ip(ip, OpaqueReason::Ipv6JumbogramUnsupported));
    }
    need(body, length, Header::Ipv6)?;
    let body = &body[..length];
    let mut count = 0;
    let mut extension_bytes = 0;
    while matches!(ip.protocol, 0 | 43 | 44 | 51 | 60) {
        if count == limits.max_ipv6_extensions
            || limits.max_ipv6_extension_bytes - extension_bytes < 2
        {
            return Ok(opaque_ip(ip, OpaqueReason::ExtensionLimit));
        }
        let offset = ip.header_bytes;
        need(body, offset + 2, Header::Ipv6Extension)?;
        let size = match ip.protocol {
            44 => 8,
            51 => {
                let size = (usize::from(body[offset + 1]) + 2) * 4;
                if size < 12 {
                    return Err(ParseError::Malformed(Header::Ipv6Extension));
                }
                size
            }
            _ => (usize::from(body[offset + 1]) + 1) * 8,
        };
        if size > limits.max_ipv6_extension_bytes - extension_bytes {
            return Ok(opaque_ip(ip, OpaqueReason::ExtensionLimit));
        }
        need(body, offset + size, Header::Ipv6Extension)?;
        let is_fragment = ip.protocol == 44;
        ip.protocol = body[offset];
        ip.header_bytes += size;
        extension_bytes += size;
        count += 1;
        if is_fragment {
            let bits = u16_at(body, offset + 2, Header::Ipv6Extension)?;
            let fragment = FragmentMetadata {
                id: u32::from_be_bytes(array(body, offset + 4, Header::Ipv6Extension)?),
                offset_bytes: u32::from(bits & 0xfff8),
                more: bits & 1 != 0,
                atomic: bits & 0xfff9 == 0,
            };
            ip.fragment = Some(fragment);
            return Ok((
                fragment_tuple(ip, fragment.id),
                PacketKind::Fragment,
                ip,
                None,
            ));
        }
    }
    transport(&body[ip.header_bytes..], ip)
}

fn fragment_tuple(ip: IpMetadata, id: u32) -> Tuple {
    // Identification belongs to the originating host, not a bidirectional pair.
    Tuple::Fragment(ip.protocol, id, ip.source, ip.destination)
}

fn opaque_ip(ip: IpMetadata, reason: OpaqueReason) -> IpResult {
    let (low, high) = ordered(ip.source, ip.destination);
    (
        Tuple::Ip(ip.protocol, low, high),
        PacketKind::Opaque(reason),
        ip,
        None,
    )
}

fn transport(body: &[u8], ip: IpMetadata) -> Result<IpResult, ParseError> {
    let (kind, meta) = match ip.protocol {
        6 => {
            need(body, 20, Header::Tcp)?;
            let size = usize::from(body[12] >> 4) * 4;
            if size < 20 || size > body.len() {
                return Err(ParseError::Malformed(Header::Tcp));
            }
            (
                PacketKind::Tcp,
                TransportMetadata {
                    source_port: u16_at(body, 0, Header::Tcp)?,
                    destination_port: u16_at(body, 2, Header::Tcp)?,
                    header_bytes: size,
                    payload_bytes: body.len() - size,
                    tcp_flags: Some((u16::from(body[12] & 1) << 8) | u16::from(body[13])),
                    tcp_window: Some(u16_at(body, 14, Header::Tcp)?),
                },
            )
        }
        17 => {
            need(body, 8, Header::Udp)?;
            let size = usize::from(u16_at(body, 4, Header::Udp)?);
            if size < 8 || size > body.len() {
                return Err(ParseError::Malformed(Header::Udp));
            }
            (
                PacketKind::Udp,
                TransportMetadata {
                    source_port: u16_at(body, 0, Header::Udp)?,
                    destination_port: u16_at(body, 2, Header::Udp)?,
                    header_bytes: 8,
                    payload_bytes: size - 8,
                    tcp_flags: None,
                    tcp_window: None,
                },
            )
        }
        59 if matches!(ip.source, Address::V6(_)) => {
            return Ok(opaque_ip(ip, OpaqueReason::NoNextHeader));
        }
        protocol => return Ok(opaque_ip(ip, OpaqueReason::IpProtocol(protocol))),
    };
    let (low, high) = ordered(
        Endpoint {
            address: ip.source,
            port: meta.source_port,
        },
        Endpoint {
            address: ip.destination,
            port: meta.destination_port,
        },
    );
    Ok((
        Tuple::Transport(ip.protocol, low, high),
        kind,
        ip,
        Some(meta),
    ))
}

fn need(bytes: &[u8], length: usize, header: Header) -> Result<(), ParseError> {
    if bytes.len() < length {
        Err(ParseError::Truncated(header))
    } else {
        Ok(())
    }
}

fn array<const N: usize>(
    bytes: &[u8],
    offset: usize,
    header: Header,
) -> Result<[u8; N], ParseError> {
    let end = offset.checked_add(N).ok_or(ParseError::Malformed(header))?;
    bytes
        .get(offset..end)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(ParseError::Truncated(header))
}

fn u16_at(bytes: &[u8], offset: usize, header: Header) -> Result<u16, ParseError> {
    Ok(u16::from_be_bytes(array(bytes, offset, header)?))
}
