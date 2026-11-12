//! Explicit ignored syscall probe; only the owned diagnostic harness invokes it.
use super::*;
const MARK: u32 = 0x12aa0001;
fn checksum(bytes: &[u8]) -> u16 {
    let mut total: u32 = bytes
        .chunks(2)
        .map(|part| {
            u32::from(u16::from_be_bytes([
                part[0],
                part.get(1).copied().unwrap_or(0),
            ]))
        })
        .sum();
    while total >> 16 != 0 {
        total = (total & 65535) + (total >> 16);
    }
    !(total as u16)
}
fn packet(id: u16, flags: u8) -> Vec<u8> {
    let mut bytes = vec![0; 40];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&40u16.to_be_bytes());
    bytes[4..6].copy_from_slice(&id.to_be_bytes());
    bytes[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 6;
    bytes[12..16].copy_from_slice(&[192, 0, 2, 2]);
    bytes[16..20].copy_from_slice(&[192, 0, 2, 6]);
    bytes[20..22].copy_from_slice(&24440u16.to_be_bytes());
    bytes[22..24].copy_from_slice(&24441u16.to_be_bytes());
    bytes[24..28].copy_from_slice(&123u32.to_be_bytes());
    bytes[28..32].copy_from_slice(&456u32.to_be_bytes());
    bytes[32] = 0x50;
    bytes[33] = flags;
    bytes[34..36].copy_from_slice(&4096u16.to_be_bytes());
    let mut pseudo = bytes[12..20].to_vec();
    pseudo.extend_from_slice(&[0, 6, 0, 20]);
    pseudo.extend_from_slice(&bytes[20..]);
    bytes[36..38].copy_from_slice(&checksum(&pseudo).to_be_bytes());
    let ip = checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&ip.to_be_bytes());
    bytes
}
#[test]
fn diagnostic_packets_have_independent_ip_and_tcp_checksums() {
    for (id, flags) in [(0x5101, 0x10), (0x5102, 4), (0x5103, 4)] {
        let bytes = packet(id, flags);
        assert_eq!(bytes.len(), 40);
        assert_eq!(checksum(&bytes[..20]), 0);
        let mut pseudo = bytes[12..20].to_vec();
        pseudo.extend_from_slice(&[0, 6, 0, 20]);
        pseudo.extend_from_slice(&bytes[20..]);
        assert_eq!(checksum(&pseudo), 0);
    }
}
#[tokio::test]
#[ignore = "requires explicit owned network namespace and marked exact-tuple policy"]
async fn marked_descriptor_policy() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if std::env::var("L2T_RAW_DIAG_ALLOWED").as_deref() != Ok("owned-policy-v1") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "owned diagnostic harness required",
        )
        .into());
    }
    let config = Config {
        local: "192.0.2.2:24440".parse()?,
        peer: "192.0.2.6:24441".parse()?,
        mtu: 1200,
        send_bytes: 65536,
        receive_bytes: 65536,
        packet_slots: 64,
        random_seed: 1,
        ack_delay_millis: 10,
        keepalive_millis: 1000,
        idle_timeout_millis: 30000,
    };
    assert_eq!(
        open_marked(config, Role::Client, 0)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
    assert_eq!(
        open_marked(config, Role::Client, MARK ^ 1)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    assert_eq!(
        open(config, Role::Client).err().map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    let (_caller, mut driver) = open_marked(config, Role::Client, MARK)?;
    assert_eq!(driver.io.raw.mark()?, MARK);
    assert_eq!(driver.io._reservation.mark()?, 0);
    driver.io.send(&packet(0x5101, 0x10))?;
    driver.io.send(&packet(0x5102, 4))?;
    // A separate descriptor isolates the unmarked control without changing the
    // verified production descriptor's mark or the owned firewall rules.
    let unmarked = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))?;
    unmarked.set_header_included_v4(true)?;
    unmarked.set_nonblocking(true)?;
    unmarked.bind(&SockAddr::from(SocketAddr::V4(SocketAddrV4::new(
        *config.local.ip(),
        0,
    ))))?;
    assert_eq!(unmarked.mark()?, 0);
    let error = unmarked
        .send_to(&packet(0x5103, 4), &driver.io.peer)
        .err()
        .ok_or_else(|| io::Error::other("unmarked RST was not rejected"))?;
    assert_eq!(error.raw_os_error(), Some(1));
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(driver.io.raw.mark()?, MARK);
    assert_eq!(driver.io._reservation.mark()?, 0);
    // No maintained TCP driver ran: direct diagnostic sends are deliberately
    // not reported as Driver counters or a clean TCP/session close.
    assert_eq!(driver.counters.sent_packets, 0);
    println!(
        "{}",
        serde_json::json!({"kind":"marked_raw_descriptor_diagnostic","status":"passed",
        "raw_mark":MARK,"reservation_mark":0,"zero_mark_rejected":true,"wrong_mark_rejected":true,"legacy_policy_rejected":true,
        "marked_ack":{"packet_id":0x5101,"flags":16,"bytes":40,"send_succeeded":true},
        "marked_rst":{"packet_id":0x5102,"flags":4,"bytes":40,"send_succeeded":true},
        "unmarked_rst":{"packet_id":0x5103,"flags":4,"bytes":40,"send_succeeded":false,
            "raw_os_error":error.raw_os_error(),"error_kind":format!("{:?}",error.kind())},
        "driver_ran":false,"driver_sent_packets":0})
    );
    Ok(())
}
