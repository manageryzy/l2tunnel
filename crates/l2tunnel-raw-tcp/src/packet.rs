//! Packet framing only; this module grants no authenticated transition authority.
use super::{Config, Error, IpConfig};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    IpAddress, IpProtocol, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
};

/// Borrowed complete packet after tuple, length and checksum validation.
#[derive(Clone, Copy, Debug)]
pub struct Packet<'a> {
    /// Original sequence field; no inferred logical acceptance.
    pub sequence: u32,
    /// Original acknowledgment field.
    pub acknowledgment: u32,
    /// Unscaled original advertised window.
    pub window: u16,
    /// Complete TCP flags, including ECN and reserved high bits.
    pub flags: u16,
    /// Actual TCP header length including options.
    pub header_bytes: usize,
    /// Exact complete TCP payload.
    pub payload: &'a [u8],
}
impl Packet<'_> {
    /// Whether this has the experimental profile's exact ACK|PSH/no-option shape.
    pub fn phase_shape(&self) -> bool {
        self.flags == 0x18 && self.header_bytes == 20 && !self.payload.is_empty()
    }
    /// Whether this is a plain ACK or ACK|PSH data segment without any options.
    pub fn old_data_shape(&self) -> bool {
        matches!(self.flags, 0x10 | 0x18) && self.header_bytes == 20 && !self.payload.is_empty()
    }
}

/// Validate one complete incoming IPv4/TCP packet, without allocation or state changes.
pub fn inspect(config: Config, bytes: &[u8]) -> Result<Packet<'_>, Error> {
    IpConfig::from(config).validate_packet(bytes)?;
    let tcp = TcpPacket::new_checked(&bytes[20..]).map_err(|_| Error::Malformed)?;
    let header_bytes = usize::from(tcp.header_len());
    Ok(Packet {
        sequence: tcp.seq_number().0 as u32,
        acknowledgment: tcp.ack_number().0 as u32,
        window: tcp.window_len(),
        flags: u16::from_be_bytes([bytes[32] & 0x0f, bytes[33]]),
        header_bytes,
        payload: &bytes[20 + header_bytes..],
    })
}

/// Emit one exact no-option IPv4/TCP ACK or ACK|PSH packet into caller storage.
///
/// All configuration/length checks precede output changes. Checksums use smoltcp.
pub fn encode(
    config: Config,
    sequence: u32,
    acknowledgment: u32,
    window: u16,
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, Error> {
    IpConfig::from(config).validate()?;
    let length = payload.len().checked_add(40).ok_or(Error::Mtu)?;
    if length > config.mtu || length > usize::from(u16::MAX) || output.len() < length {
        return Err(Error::Mtu);
    }
    let source = IpAddress::Ipv4(*config.local.ip());
    let destination = IpAddress::Ipv4(*config.peer.ip());
    let checksum = ChecksumCapabilities::default();
    output[..length].fill(0);
    Ipv4Repr {
        src_addr: *config.local.ip(),
        dst_addr: *config.peer.ip(),
        next_header: IpProtocol::Tcp,
        payload_len: length - 20,
        hop_limit: 64,
    }
    .emit(&mut Ipv4Packet::new_unchecked(&mut output[..20]), &checksum);
    TcpRepr {
        src_port: config.local.port(),
        dst_port: config.peer.port(),
        control: if payload.is_empty() {
            TcpControl::None
        } else {
            TcpControl::Psh
        },
        seq_number: TcpSeqNumber(sequence as i32),
        ack_number: Some(TcpSeqNumber(acknowledgment as i32)),
        window_len: window,
        max_seg_size: None,
        window_scale: None,
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload,
    }
    .emit(
        &mut TcpPacket::new_unchecked(&mut output[20..length]),
        &source,
        &destination,
        &checksum,
    );
    Ok(length)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn configs() -> (Config, Config) {
        let a = Config {
            local: std::net::SocketAddrV4::new([192, 0, 2, 1].into(), 1001),
            peer: std::net::SocketAddrV4::new([192, 0, 2, 2].into(), 1002),
            mtu: 576,
            send_bytes: 4096,
            receive_bytes: 4096,
            packet_slots: 4,
            random_seed: 1,
            ack_delay_millis: 1,
            keepalive_millis: 1000,
            idle_timeout_millis: 10_000,
        };
        (
            a,
            Config {
                local: a.peer,
                peer: a.local,
                ..a
            },
        )
    }
    #[test]
    fn exact_payload_headers_and_checksum() -> Result<(), Error> {
        let (a, b) = configs();
        for length in [0, 1, 280, 536] {
            let payload = vec![0xa5; length];
            let mut output = [0; 576];
            let n = encode(a, u32::MAX - 7, 12, 8192, &payload, &mut output)?;
            let p = inspect(b, &output[..n])?;
            assert_eq!(p.payload, payload);
            assert_eq!(
                (p.sequence, p.acknowledgment, p.window),
                (u32::MAX - 7, 12, 8192)
            );
            assert_eq!(p.phase_shape(), length > 0);
            assert_eq!(p.flags, if length == 0 { 0x10 } else { 0x18 });
            output[n - 1] ^= 1;
            assert!(inspect(b, &output[..n]).is_err());
        }
        Ok(())
    }
    #[test]
    fn rejected_lengths_preserve_output() {
        let (a, b) = configs();
        let mut output = [0x73; 576];
        assert!(encode(a, 0, 0, 0, &[0; 537], &mut output).is_err());
        assert_eq!(output, [0x73; 576]);
        for n in 0..40 {
            assert!(inspect(b, &output[..n]).is_err());
        }
    }
}
