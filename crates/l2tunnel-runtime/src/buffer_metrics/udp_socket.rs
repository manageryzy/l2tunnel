//! One readback of actual original UDP socket options, not queue occupancy.
use std::{
    fmt::Display,
    io::{self, Write},
    net::SocketAddr,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Failure {
    kind: io::ErrorKind,
    raw_os_error: Option<i32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Readback<T>(Result<T, Failure>);

impl<T> From<io::Result<T>> for Readback<T> {
    fn from(result: io::Result<T>) -> Self {
        Self(result.map_err(|error| Failure {
            kind: error.kind(),
            raw_os_error: error.raw_os_error(),
        }))
    }
}

impl<T: Display> Readback<T> {
    fn write(&self, writer: &mut impl Write, field: &str, quoted: bool) -> io::Result<()> {
        match &self.0 {
            Ok(value) => {
                write!(writer, "{{\"availability\":\"observed\",\"{field}\":")?;
                if quoted {
                    // Only SocketAddr uses quoted formatting; its Display has no
                    // JSON escape characters or caller-provided address labels.
                    write!(writer, "\"{value}\"")?;
                } else {
                    write!(writer, "{value}")?;
                }
                write!(writer, ",\"error_kind\":null,\"raw_os_error\":null}}")
            }
            Err(error) => {
                write!(
                    writer,
                    "{{\"availability\":\"unavailable\",\"{field}\":null,\"error_kind\":\"{:?}\",\"raw_os_error\":",
                    error.kind
                )?;
                if let Some(code) = error.raw_os_error {
                    write!(writer, "{code}")?;
                } else {
                    write!(writer, "null")?;
                }
                write!(writer, "}}")
            }
        }
    }
}

/// Fixed scalar metadata; neither payload storage nor a source of flow authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Snapshot {
    local: Readback<SocketAddr>,
    peer: Readback<SocketAddr>,
    receive: Readback<usize>,
    send: Readback<usize>,
    requested_receive: Option<u64>,
}

impl Snapshot {
    pub(super) fn read(socket: &tokio::net::UdpSocket, requested_receive: Option<u64>) -> Self {
        #[cfg(any(unix, windows))]
        let (receive, send) = {
            let socket = socket2::SockRef::from(socket);
            (
                socket.recv_buffer_size().into(),
                socket.send_buffer_size().into(),
            )
        };
        #[cfg(not(any(unix, windows)))]
        let (receive, send) = {
            let unavailable = Readback(Err(Failure {
                kind: io::ErrorKind::Unsupported,
                raw_os_error: None,
            }));
            (unavailable, unavailable)
        };
        Self {
            local: socket.local_addr().into(),
            peer: socket.peer_addr().into(),
            receive,
            send,
            requested_receive,
        }
    }

    pub(super) fn write(&self, writer: &mut impl Write) -> io::Result<()> {
        write!(
            writer,
            "{{\"availability\":\"attempted\",\"lane\":\"Shared\",\"sampling\":\"runtime_entry_once\",\"readback_attempted\":true,\"requested_receive_bytes\":{},\"requested_send_bytes\":null,\"socket_options_changed\":{},\"definition\":\"SO_RCVBUF and SO_SNDBUF getsockopt readback; accounting limits, not UDP payload capacity, occupancy, drops or blocked duration\",\"reporting_convention\":\"{}\",\"local\":",
            self.requested_receive
                .map_or_else(|| "null".to_owned(), |bytes| bytes.to_string()),
            self.requested_receive.is_some(),
            if cfg!(target_os = "linux") {
                "Linux kernel accounting byte limits include bookkeeping; Linux doubles user-set values; raw readback is preserved without halving or inferring a requested value"
            } else {
                "Native platform getsockopt byte values; no payload-capacity conversion is assumed"
            }
        )?;
        self.local.write(writer, "address", true)?;
        write!(writer, ",\"peer\":")?;
        self.peer.write(writer, "address", true)?;
        write!(writer, ",\"receive\":")?;
        self.receive.write(writer, "kernel_reported_bytes", false)?;
        write!(writer, ",\"send\":")?;
        self.send.write(writer, "kernel_reported_bytes", false)?;
        write!(writer, "}}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(unix, windows))]
    #[tokio::test]
    async fn original_udp_readback_matches_actual_socket_without_setting_options()
    -> Result<(), Box<dyn std::error::Error>> {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        socket.connect(peer.local_addr()?).await?;
        peer.connect(socket.local_addr()?).await?;
        let actual = socket2::SockRef::from(&socket);
        let before = (actual.recv_buffer_size()?, actual.send_buffer_size()?);
        let snapshot = Snapshot::read(&socket, None);
        assert_eq!(snapshot.local.0, Ok(socket.local_addr()?));
        assert_eq!(snapshot.peer.0, Ok(peer.local_addr()?));
        assert_eq!(snapshot.receive.0, Ok(before.0));
        assert_eq!(snapshot.send.0, Ok(before.1));
        let mut bytes = Vec::new();
        snapshot.write(&mut bytes)?;
        let report: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(report["receive"]["kernel_reported_bytes"], before.0);
        assert_eq!(report["send"]["kernel_reported_bytes"], before.1);
        assert_eq!(report["local"]["address"], socket.local_addr()?.to_string());
        assert_eq!(report["lane"], "Shared");
        assert!(report["requested_receive_bytes"].is_null());
        assert_eq!(report["socket_options_changed"], false);
        assert_eq!(
            before,
            (actual.recv_buffer_size()?, actual.send_buffer_size()?)
        );

        // The readback borrows the existing owner without replacing or closing it.
        socket.send(b"original-socket").await?;
        let mut payload = [0; 32];
        let count =
            tokio::time::timeout(std::time::Duration::from_secs(1), peer.recv(&mut payload))
                .await??;
        assert_eq!(&payload[..count], b"original-socket");
        Ok(())
    }

    #[test]
    fn option_failure_stays_unavailable_without_erasing_independent_readback()
    -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = Snapshot {
            local: Ok("127.0.0.1:24440".parse()?).into(),
            peer: Err(io::Error::new(io::ErrorKind::NotConnected, "not exported")).into(),
            receive: Err(io::Error::from_raw_os_error(22)).into(),
            send: Ok(12345).into(),
            requested_receive: Some(16 << 20),
        };
        let mut bytes = Vec::new();
        snapshot.write(&mut bytes)?;
        let report: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(report["receive"]["availability"], "unavailable");
        assert!(report["receive"]["kernel_reported_bytes"].is_null());
        assert_eq!(report["receive"]["raw_os_error"], 22);
        assert_eq!(report["send"]["availability"], "observed");
        assert_eq!(report["send"]["kernel_reported_bytes"], 12345);
        assert_eq!(report["peer"]["error_kind"], "NotConnected");
        assert_eq!(report["requested_receive_bytes"], 16 << 20);
        assert_eq!(report["socket_options_changed"], true);
        assert!(!String::from_utf8(bytes)?.contains("not exported"));
        Ok(())
    }
}
