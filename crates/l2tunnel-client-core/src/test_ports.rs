//! Test-only loopback port reservations outside the ephemeral range.
//!
//! Public client factories bind their own UDP sockets, so a test must release a
//! reserved address before the factory binds it. An address taken from the
//! kernel's ephemeral range can be handed to any other test's automatic bind
//! during that gap, which fails an unrelated test with `AddrInUse`. Ports
//! issued here come from one process-wide counter below the default ephemeral
//! ranges (Linux 32768+, Windows and macOS 49152+), so no automatic bind can
//! select them and no two tests in this process receive the same one. Maintained
//! TLS fixtures also use these addresses, so candidates must permit an ordinary
//! TCP bind without address reuse, including after earlier subprocess teardown.
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU32, Ordering};

const FIRST: u32 = 20_000;
const COUNT: u32 = 12_000;
static NEXT: AtomicU32 = AtomicU32::new(u32::MAX);

fn shard(value: Option<&str>) -> io::Result<Option<(u32, u32)>> {
    match value {
        None => Ok(None),
        Some("0") => Ok(Some((0, COUNT / 4))),
        Some("1") => Ok(Some((COUNT / 4, COUNT / 4))),
        Some("2") => Ok(Some((COUNT / 2, COUNT / 4))),
        Some("3") => Ok(Some((COUNT * 3 / 4, COUNT / 4))),
        Some(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "L2TUNNEL_TEST_PORT_SHARD must be one of 0, 1, 2, 3",
        )),
    }
}

fn reserve_address(address: SocketAddr) -> io::Result<UdpSocket> {
    let tcp = if address.is_ipv6() {
        tokio::net::TcpSocket::new_v6()?
    } else {
        tokio::net::TcpSocket::new_v4()?
    };
    // Match the actual TLS client's bind semantics. A listener may enable
    // address reuse and miss a TCP TIME_WAIT conflict even while UDP is free.
    tcp.bind(address)?;
    UdpSocket::bind(address)
}

/// Bind the next unused process-unique loopback UDP port and return its owner.
/// TCP or UDP occupancy is skipped; only `AddrInUse` is retried.
pub(crate) fn reserve(ipv6: bool) -> io::Result<UdpSocket> {
    let selected = std::env::var("L2TUNNEL_TEST_PORT_SHARD")
        .map(Some)
        .or_else(|error| match error {
            std::env::VarError::NotPresent => Ok(None),
            std::env::VarError::NotUnicode(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "L2TUNNEL_TEST_PORT_SHARD is not Unicode",
            )),
        })?;
    let partition = shard(selected.as_deref())?;
    // Start each test process at a different offset so two concurrent test
    // binaries rarely probe the same ports. The four-process continuation
    // harness supplies disjoint partitions held until each child exits.
    let _ = NEXT.compare_exchange(
        u32::MAX,
        if partition.is_some() {
            0
        } else {
            std::process::id() % COUNT
        },
        Ordering::SeqCst,
        Ordering::SeqCst,
    );
    for _ in 0..256 {
        let offset = NEXT
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                if let Some((_, count)) = partition {
                    (value < count).then_some(value + 1)
                } else {
                    Some((value + 1) % COUNT)
                }
            })
            .map_err(|_| io::Error::other("test port partition exhausted"))?;
        let offset = offset + partition.map_or(0, |(first, _)| first);
        let port = u16::try_from(FIRST + offset).map_err(io::Error::other)?;
        let address = if ipv6 {
            SocketAddr::from((Ipv6Addr::LOCALHOST, port))
        } else {
            SocketAddr::from((Ipv4Addr::LOCALHOST, port))
        };
        match reserve_address(address) {
            Ok(socket) => return Ok(socket),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => (),
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "no free test UDP port below the ephemeral range",
    ))
}

#[test]
fn tcp_occupied_candidates_are_rejected_without_leaking_udp_reservations() -> io::Result<()> {
    let occupied = tokio::net::TcpSocket::new_v4()?;
    occupied.bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let candidate = occupied.local_addr()?;
    assert_eq!(
        reserve_address(candidate).err().map(|error| error.kind()),
        Some(io::ErrorKind::AddrInUse)
    );
    let udp = UdpSocket::bind(candidate)?;
    drop(udp);
    drop(occupied);
    assert_eq!(reserve_address(candidate)?.local_addr()?, candidate);
    Ok(())
}

#[test]
fn worker_partitions_are_strict_disjoint_and_bounded() -> io::Result<()> {
    assert_eq!(shard(None)?, None);
    let mut previous_end = 0;
    for value in ["0", "1", "2", "3"] {
        let (first, count) =
            shard(Some(value))?.ok_or_else(|| io::Error::other("missing shard"))?;
        assert_eq!(first, previous_end);
        assert_eq!(count, 3000);
        previous_end = first + count;
    }
    assert_eq!(previous_end, COUNT);
    for value in ["", "4", "-1", "00", " 1", "1 ", "4294967295"] {
        assert_eq!(
            shard(Some(value)).err().map(|error| error.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
    }
    Ok(())
}

#[test]
fn reservations_are_distinct_and_below_the_ephemeral_range() -> io::Result<()> {
    let held = (0..8)
        .map(|index| reserve(index % 2 == 1))
        .collect::<io::Result<Vec<_>>>()?;
    let mut ports = held
        .iter()
        .map(|socket| socket.local_addr().map(|address| address.port()))
        .collect::<io::Result<Vec<_>>>()?;
    assert!(ports.iter().all(|port| (20_000..32_000).contains(port)));
    ports.sort_unstable();
    ports.dedup();
    assert_eq!(ports.len(), 8);
    Ok(())
}
