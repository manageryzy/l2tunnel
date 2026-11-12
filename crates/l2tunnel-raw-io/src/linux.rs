use super::{Driver, PacketIo, bridge};
use l2tunnel_raw_tcp::{Config, Millis, Role, TcpEngine};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, SocketAddrV4};
use std::num::NonZeroU32;
use std::os::unix::fs::MetadataExt;
use std::process::{Command, Stdio};
use tokio::io::DuplexStream;

/// Owned raw descriptor plus a bound, non-listening TCP port reservation.
pub struct RawSocket {
    raw: Socket,
    peer: SockAddr,
    ports: (u16, u16),
    _reservation: Socket,
}

/// Open only in a non-initial namespace with an existing exact-tuple RST rule.
///
/// Requires CAP_NET_RAW and read access to the namespace's iptables rules. The
/// embedding lab owns the rule for this entire driver's lifetime. This function
/// never installs rules or connects/listens on a kernel TCP socket.
pub fn open(config: Config, role: Role) -> io::Result<(DuplexStream, Driver<RawSocket>)> {
    open_socket(config, role, None)
}

/// Open with an explicit nonzero mark that distinguishes owned TCP from kernel RST.
///
/// Requires an existing finite canonical OUTPUT policy containing only ACCEPT
/// policy plus exact-tuple RST drops for packets whose mark differs. The adapter
/// validates that policy, sets/reads back the raw descriptor mark and never changes
/// firewall state. The kernel port reservation stays unmarked. The embedding
/// namespace owner must preserve this policy for the descriptor's full lifetime.
pub fn open_marked(
    config: Config,
    role: Role,
    mark: u32,
) -> io::Result<(DuplexStream, Driver<RawSocket>)> {
    let mark = NonZeroU32::new(mark).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "owned raw mark must be nonzero",
        )
    })?;
    open_socket(config, role, Some(mark))
}

fn open_socket(
    config: Config,
    role: Role,
    mark: Option<NonZeroU32>,
) -> io::Result<(DuplexStream, Driver<RawSocket>)> {
    // Validate all capacities before any socket or external inspection.
    let _validated = TcpEngine::new(config, role, Millis(0)).map_err(io::Error::other)?;
    let current = std::fs::metadata("/proc/self/ns/net")?.ino();
    let initial = std::fs::metadata("/proc/1/ns/net")?.ino();
    if current == initial {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "raw profile requires a separate owned network namespace",
        ));
    }
    if let Some(mark) = mark {
        let output = read_marked_policy()?;
        let text = std::str::from_utf8(&output).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "non-UTF8 marked OUTPUT policy")
        })?;
        let target = format!(
            "-A OUTPUT -s {}/32 -d {}/32 -p tcp -m tcp --sport {} --dport {} --tcp-flags RST RST -m mark ! --mark {:#x} -j DROP",
            config.local.ip(),
            config.peer.ip(),
            config.local.port(),
            config.peer.port(),
            mark.get()
        );
        validate_marked_policy(text, &target, mark)?;
    } else {
        let policy = Command::new("/usr/sbin/iptables")
            .args([
                "-w",
                "1",
                "-C",
                "OUTPUT",
                "-p",
                "tcp",
                "-s",
                &config.local.ip().to_string(),
                "--sport",
                &config.local.port().to_string(),
                "-d",
                &config.peer.ip().to_string(),
                "--dport",
                &config.peer.port().to_string(),
                "--tcp-flags",
                "RST",
                "RST",
                "-j",
                "DROP",
            ])
            .output()?;
        if !policy.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "missing owned exact-tuple RST suppression rule",
            ));
        }
    }
    let reservation = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    reservation.bind(&SockAddr::from(SocketAddr::V4(config.local)))?;
    let raw = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))?;
    if let Some(mark) = mark {
        raw.set_mark(mark.get())?;
        if raw.mark()? != mark.get() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "owned raw mark readback differs",
            ));
        }
    }
    raw.set_header_included_v4(true)?;
    raw.set_nonblocking(true)?;
    raw.set_recv_buffer_size((config.mtu * config.packet_slots).min(4_194_304))?;
    raw.set_send_buffer_size((config.mtu * config.packet_slots).min(4_194_304))?;
    raw.bind(&SockAddr::from(SocketAddr::V4(SocketAddrV4::new(
        *config.local.ip(),
        0,
    ))))?;
    let peer = SockAddr::from(SocketAddr::V4(SocketAddrV4::new(*config.peer.ip(), 0)));
    bridge(
        config,
        role,
        RawSocket {
            raw,
            peer,
            ports: (config.local.port(), config.peer.port()),
            _reservation: reservation,
        },
    )
}

fn read_marked_policy() -> io::Result<Vec<u8>> {
    let mut child = Command::new("/usr/sbin/iptables")
        .args(["-w", "1", "-S", "OUTPUT"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut output = Vec::new();
    let read = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("missing policy inspection pipe"))
        .and_then(|stdout| stdout.take(65_537).read_to_end(&mut output));
    if read.is_err() || output.len() > 65_536 {
        let _ = child.kill();
        let _ = child.wait();
        read?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "marked OUTPUT policy exceeds read bound",
        ));
    }
    if !child.wait()?.success() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "cannot read owned marked OUTPUT policy",
        ));
    }
    Ok(output)
}

fn validate_marked_policy(text: &str, target: &str, mark: NonZeroU32) -> io::Result<()> {
    let denied = || {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unexpected owned marked OUTPUT policy",
        )
    };
    if text.len() > 65_536 {
        return Err(denied());
    }
    let mut lines = text.lines();
    if lines.next() != Some("-P OUTPUT ACCEPT") {
        return Err(denied());
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut found = false;
    let expected_mark = format!("{:#x}", mark.get());
    for line in lines {
        if seen.len() == 64 || !seen.insert(line) {
            return Err(denied());
        }
        let words: Vec<_> = line.split_ascii_whitespace().collect();
        if words.len() != 24 {
            return Err(denied());
        }
        for (index, expected) in [
            (0, "-A"),
            (1, "OUTPUT"),
            (2, "-s"),
            (4, "-d"),
            (6, "-p"),
            (7, "tcp"),
            (8, "-m"),
            (9, "tcp"),
            (10, "--sport"),
            (12, "--dport"),
            (14, "--tcp-flags"),
            (15, "RST"),
            (16, "RST"),
            (17, "-m"),
            (18, "mark"),
            (19, "!"),
            (20, "--mark"),
            (22, "-j"),
            (23, "DROP"),
        ] {
            if words[index] != expected {
                return Err(denied());
            }
        }
        for index in [3, 5] {
            if words[index]
                .strip_suffix("/32")
                .and_then(|value| value.parse::<std::net::Ipv4Addr>().ok())
                .is_none()
            {
                return Err(denied());
            }
        }
        for index in [11, 13] {
            if words[index]
                .parse::<u16>()
                .ok()
                .is_none_or(|port| port == 0)
            {
                return Err(denied());
            }
        }
        if words[21] != expected_mark {
            return Err(denied());
        }
        found |= line == target;
    }
    if !found {
        return Err(denied());
    }
    Ok(())
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    const RULE: &str = "-A OUTPUT -s 192.0.2.2/32 -d 192.0.2.6/32 -p tcp -m tcp --sport 24440 --dport 24441 --tcp-flags RST RST -m mark ! --mark 0x12aa0001 -j DROP";
    fn check(text: &str) -> io::Result<()> {
        let mark = NonZeroU32::new(0x12aa0001).ok_or_else(|| io::Error::other("test mark"))?;
        validate_marked_policy(text, RULE, mark)
    }
    #[test]
    fn exact_marked_policy_accepts_bounded_distinct_tuples() -> io::Result<()> {
        let mut text = format!("-P OUTPUT ACCEPT\n{RULE}\n");
        check(&text)?;
        for port in 24442..24505 {
            text.push_str(&RULE.replace("24440", &port.to_string()));
            text.push('\n');
        }
        check(&text)?;
        text.push_str(&RULE.replace("24440", "24506"));
        assert!(check(&text).is_err());
        Ok(())
    }
    #[test]
    fn marked_policy_rejects_bypass_broad_unknown_and_duplicate_rules() {
        let text = format!("-P OUTPUT ACCEPT\n{RULE}\n");
        for changed in [
            text.replace("0x12aa0001", "0x12aa0002"),
            text.replace("0x12aa0001", "0x12aa0001/0xff"),
            text.replace("/32", "/24"),
            text.replace("--sport 24440", "--sport 0"),
            text.replace("--dport 24441", "--dport 65536"),
            text.replace("! --mark", "--mark"),
            text.replace("-j DROP", "-j ACCEPT"),
            text.replace("-j DROP", "-j OTHER"),
            text.replace("--tcp-flags RST RST", "--tcp-flags SYN SYN"),
            text.replace("-P OUTPUT ACCEPT", "-P OUTPUT DROP"),
            format!("{text}{RULE}\n"),
            format!("{text}-A OUTPUT -j ACCEPT\n"),
            format!("-P OUTPUT ACCEPT\n-A OUTPUT -j ACCEPT\n{RULE}\n"),
            "-P OUTPUT ACCEPT\n".to_string(),
            String::new(),
            "x".repeat(65537),
        ] {
            assert!(check(&changed).is_err(), "accepted {changed}");
        }
    }
}

// Emit one bounded diagnostic immediately before returning the original error.
// The error itself is never wrapped, so kind/raw_os_error remain authoritative.
fn report_error(
    operation: &str,
    error: &io::Error,
    bytes: usize,
    flags: Option<u8>,
    ports: (u16, u16),
) {
    let errno = error
        .raw_os_error()
        .map_or_else(|| "null".to_owned(), |value| value.to_string());
    let flags = flags.map_or_else(|| "null".to_owned(), |value| value.to_string());
    let _ = writeln!(
        io::stderr(),
        "{{\"kind\":\"raw_socket_error\",\"operation\":\"{operation}\",\"error_kind\":\"{:?}\",\"raw_os_error\":{errno},\"packet_bytes\":{bytes},\"tcp_flags\":{flags},\"local_port\":{},\"peer_port\":{}}}",
        error.kind(),
        ports.0,
        ports.1
    );
}

impl PacketIo for RawSocket {
    fn receive(&mut self, output: &mut [u8]) -> io::Result<Option<usize>> {
        match self.raw.read(output) {
            Ok(size) => Ok(Some(size)),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => {
                report_error("read", &error, 0, None, self.ports);
                Err(error)
            }
        }
    }
    fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        let size = match self.raw.send_to(packet, &self.peer) {
            Ok(size) => size,
            Err(error) => {
                if error.kind() != io::ErrorKind::WouldBlock {
                    let flags = packet
                        .first()
                        .and_then(|first| packet.get(usize::from(first & 15) * 4 + 13))
                        .copied();
                    report_error("send_to", &error, packet.len(), flags, self.ports);
                }
                return Err(error);
            }
        };
        if size != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial raw packet send",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "linux_native_tests.rs"]
mod native_policy_tests;
