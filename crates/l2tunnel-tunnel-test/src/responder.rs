//! The answering side: TCP discard/source on the internal responder address;
//! the interface answers ICMP echo itself.
use crate::{
    Addresses, CONNECTION_LIFETIME, Direction, Error, HEADER_BYTES, MAX_STREAMS, PING_IDENT,
    RESPONDER_PORT, Stack, echo_answer, icmp_socket, parse_header, tcp_socket,
};
use smoltcp::iface::SocketHandle;
use smoltcp::socket::icmp;
use smoltcp::socket::tcp::{self, State};
use smoltcp::wire::Ipv4Address;
use std::time::Duration;

enum Work {
    /// Listening or reading the header.
    Header {
        bytes: [u8; HEADER_BYTES],
        filled: usize,
    },
    /// Counting an upload until the tester's FIN.
    Upload { count: u64 },
    /// Writing the 8-byte count, then closing.
    Confirm { count: [u8; 8], written: usize },
    /// Sending zeros until `until`.
    Download { until: Duration },
    /// Closing; listen again once closed.
    Closing,
}

struct Connection {
    handle: SocketHandle,
    work: Work,
    since: Option<Duration>,
}

/// The always-on responder of a connected session (owner 2026-11-24).
pub struct Responder {
    address: Ipv4Address,
    stack: Stack,
    connections: Vec<Connection>,
    echo: SocketHandle,
    refused: u64,
}
impl Responder {
    /// A responder on the agreed `addresses` for test packets up to `mtu`
    /// bytes; `seed` seeds the stack's sequence numbers.
    pub fn new(addresses: Addresses, mtu: usize, seed: u64, now: Duration) -> Result<Self, Error> {
        addresses.validate()?;
        let address = addresses.responder;
        let mut stack = Stack::new(address, addresses.tester, mtu, seed, now)?;
        let mut connections = Vec::with_capacity(usize::from(MAX_STREAMS));
        for _ in 0..MAX_STREAMS {
            let mut socket = tcp_socket();
            socket
                .listen((address, RESPONDER_PORT))
                .map_err(|_| Error::Stack)?;
            connections.push(Connection {
                handle: stack.sockets.add(socket),
                work: header(),
                since: None,
            });
        }
        let mut echo = icmp_socket();
        echo.bind(icmp::Endpoint::Ident(PING_IDENT))
            .map_err(|_| Error::Stack)?;
        let echo = stack.sockets.add(echo);
        Ok(Self {
            address,
            stack,
            connections,
            echo,
            refused: 0,
        })
    }
    /// Queue one flagged test packet from the peer.
    pub fn deliver(&mut self, packet: &[u8]) {
        self.stack.queues.deliver(packet);
    }
    /// Run the stack and the connections at `now`.
    pub fn poll(&mut self, now: Duration) -> Result<(), Error> {
        self.stack.advance(now)?;
        for connection in &mut self.connections {
            let socket = self.stack.sockets.get_mut::<tcp::Socket>(connection.handle);
            self.refused += u64::from(serve(socket, connection, self.address, now));
        }
        let echo = self.stack.sockets.get_mut::<icmp::Socket>(self.echo);
        while echo.can_send() {
            let Ok((request, source)) = echo.recv() else {
                break;
            };
            if let Some(reply) = echo_answer(PING_IDENT, request) {
                let _ = echo.send_slice(&reply, source);
            }
        }
        self.stack.advance(now)
    }
    /// Next packet to send to the peer, flagged.
    pub fn next_outbound(&mut self) -> Option<Vec<u8>> {
        self.stack.queues.outgoing.pop_front()
    }
    /// When to call [`Responder::poll`] next.
    pub fn poll_at(&mut self, now: Duration) -> Option<Duration> {
        let active = self.connections.iter().any(|connection| {
            matches!(
                connection.work,
                Work::Download { .. } | Work::Confirm { .. }
            )
        });
        let stack = self.stack.poll_at(now);
        if active {
            // Keep sources filling their send buffers.
            let soon = now + Duration::from_millis(1);
            return Some(stack.map_or(soon, |at| at.min(soon)));
        }
        stack
    }
    /// Open test connections.
    pub fn connections(&self) -> usize {
        self.connections
            .iter()
            .filter(|connection| connection.since.is_some())
            .count()
    }
    /// Connections reset for a bad header or the lifetime bound.
    pub fn refused(&self) -> u64 {
        self.refused
    }
    /// Peer packets dropped (queue full or oversized).
    pub fn dropped(&self) -> u64 {
        self.stack.queues.dropped
    }
}

fn header() -> Work {
    Work::Header {
        bytes: [0; HEADER_BYTES],
        filled: 0,
    }
}

/// Serve one socket; returns whether a connection was refused.
fn serve(
    socket: &mut tcp::Socket<'static>,
    connection: &mut Connection,
    address: Ipv4Address,
    now: Duration,
) -> bool {
    match socket.state() {
        State::Closed => {
            // Listen again for the next test.
            connection.work = header();
            connection.since = None;
            let _ = socket.listen((address, RESPONDER_PORT));
            return false;
        }
        State::Listen | State::SynReceived => return false,
        _ => {}
    }
    let since = *connection.since.get_or_insert(now);
    if now.saturating_sub(since) > CONNECTION_LIFETIME {
        socket.abort();
        connection.work = Work::Closing;
        return true;
    }
    match &mut connection.work {
        Work::Header { bytes, filled } => {
            if let Ok(read) = socket.recv_slice(&mut bytes[*filled..]) {
                *filled += read;
            }
            if *filled < HEADER_BYTES {
                if !socket.may_recv() {
                    socket.abort();
                    connection.work = Work::Closing;
                    return true;
                }
                return false;
            }
            connection.work = match parse_header(bytes) {
                Some((Direction::Upload, _)) => Work::Upload { count: 0 },
                Some((Direction::Download, duration)) => Work::Download {
                    until: now + duration,
                },
                None => {
                    socket.abort();
                    connection.work = Work::Closing;
                    return true;
                }
            };
            serve(socket, connection, address, now)
        }
        Work::Upload { count } => {
            while let Ok(read) = socket.recv(|buffer| (buffer.len(), buffer.len())) {
                if read == 0 {
                    break;
                }
                *count = count.saturating_add(read as u64);
            }
            if !socket.may_recv() {
                connection.work = Work::Confirm {
                    count: count.to_be_bytes(),
                    written: 0,
                };
                return serve(socket, connection, address, now);
            }
            false
        }
        Work::Confirm { count, written } => {
            if let Ok(sent) = socket.send_slice(&count[*written..]) {
                *written += sent;
            }
            if *written == count.len() {
                socket.close();
                connection.work = Work::Closing;
            }
            false
        }
        Work::Download { until } => {
            // Discard anything the tester sends after its header.
            while let Ok(read) = socket.recv(|buffer| (buffer.len(), buffer.len())) {
                if read == 0 {
                    break;
                }
            }
            if now >= *until || !socket.may_send() {
                socket.close();
                connection.work = Work::Closing;
                return false;
            }
            while socket.can_send() {
                let sent = socket
                    .send(|buffer| {
                        buffer.fill(0);
                        (buffer.len(), buffer.len())
                    })
                    .unwrap_or(0);
                if sent == 0 {
                    break;
                }
            }
            false
        }
        Work::Closing => {
            while let Ok(read) = socket.recv(|buffer| (buffer.len(), buffer.len())) {
                if read == 0 {
                    break;
                }
            }
            false
        }
    }
}
