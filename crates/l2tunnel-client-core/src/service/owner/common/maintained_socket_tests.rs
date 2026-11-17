//! Linux socket lifecycle evidence, separate from same-four-tuple TLS reconnection.
use super::tls_client_socket;
use std::io::{self, BufRead};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket};

fn proc_address(address: SocketAddr) -> io::Result<String> {
    let SocketAddr::V4(address) = address else {
        return Err(io::Error::other("TIME_WAIT fixture requires IPv4"));
    };
    Ok(format!(
        "{:08X}:{:04X}",
        u32::from_ne_bytes(address.ip().octets()),
        address.port(),
    ))
}

fn exact_tuple_state(local: SocketAddr, peer: SocketAddr) -> io::Result<Option<String>> {
    let local = proc_address(local)?;
    let peer = proc_address(peer)?;
    let table = std::io::BufReader::new(std::fs::File::open("/proc/net/tcp")?);
    for line in table.lines() {
        let line = line?;
        let mut fields = line.split_ascii_whitespace();
        let _ = fields.next();
        if fields.next() == Some(local.as_str()) && fields.next() == Some(peer.as_str()) {
            return Ok(fields.next().map(str::to_owned));
        }
    }
    Ok(None)
}

#[tokio::test]
async fn tls_client_socket_rebinds_proven_time_wait_without_claiming_same_tuple_connect()
-> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let peer = listener.local_addr()?;
        let socket = tls_client_socket(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        socket.bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        let local = socket.local_addr()?;
        let mut client = socket.connect(peer).await?;
        let (mut server, observed_client) = listener.accept().await?;
        assert_eq!(observed_client, local);

        // Client FIN is observed before the server sends its FIN. Both reads
        // consume EOF, so dropping these owners does not discard unread data.
        client.shutdown().await?;
        assert_eq!(server.read(&mut [0; 1]).await?, 0);
        server.shutdown().await?;
        assert_eq!(client.read(&mut [0; 1]).await?, 0);
        drop(client);
        drop(server);
        assert_eq!(exact_tuple_state(local, peer)?.as_deref(), Some("06"));

        // This comparison isolates bind reuse while the exact original tuple
        // remains in TIME_WAIT. No sleep, retry, or kernel policy change is used.
        let no_reuse = TcpSocket::new_v4()?;
        assert_eq!(
            no_reuse.bind(local).err().map(|error| error.kind()),
            Some(io::ErrorKind::AddrInUse),
        );
        let replacement = tls_client_socket(local)?;
        replacement.bind(local)?;
        assert_eq!(replacement.local_addr()?, local);
        assert_eq!(exact_tuple_state(local, peer)?.as_deref(), Some("06"));

        // Reusing a bound client port does not permit taking a live listener's
        // address. An actual same-four-tuple connect/TLS result remains covered
        // separately by the shared-service reconnect fixture.
        let occupied = tls_client_socket(peer)?;
        assert_eq!(
            occupied.bind(peer).err().map(|error| error.kind()),
            Some(io::ErrorKind::AddrInUse),
        );
        Ok(())
    })
    .await
    .map_err(|error| io::Error::new(io::ErrorKind::TimedOut, error))?
}
