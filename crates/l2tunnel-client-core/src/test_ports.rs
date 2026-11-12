//! Test-only loopback UDP port reservations outside the ephemeral range.
//!
//! Public client factories bind their own UDP sockets, so a test must release a
//! reserved address before the factory binds it. An address taken from the
//! kernel's ephemeral range can be handed to any other test's automatic bind
//! during that gap, which fails an unrelated test with `AddrInUse`. Ports
//! issued here come from one process-wide counter below the default ephemeral
//! ranges (Linux 32768+, Windows and macOS 49152+), so no automatic bind can
//! select them and no two tests in this process receive the same one.
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU32, Ordering};

const FIRST: u32 = 20_000;
const COUNT: u32 = 12_000;
static NEXT: AtomicU32 = AtomicU32::new(u32::MAX);

/// Bind the next unused process-unique loopback UDP port and return its owner.
/// A port held by another process is skipped; only `AddrInUse` is retried.
pub(crate) fn reserve(ipv6: bool) -> io::Result<UdpSocket> {
    // Start each test process at a different offset so two concurrent test
    // binaries rarely probe the same ports.
    let _ = NEXT.compare_exchange(
        u32::MAX,
        std::process::id() % COUNT,
        Ordering::SeqCst,
        Ordering::SeqCst,
    );
    for _ in 0..256 {
        let offset = NEXT
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                Some((value + 1) % COUNT)
            })
            .map_err(|_| io::Error::other("test port counter"))?;
        let port = u16::try_from(FIRST + offset).map_err(io::Error::other)?;
        let address = if ipv6 {
            SocketAddr::from((Ipv6Addr::LOCALHOST, port))
        } else {
            SocketAddr::from((Ipv4Addr::LOCALHOST, port))
        };
        match UdpSocket::bind(address) {
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
