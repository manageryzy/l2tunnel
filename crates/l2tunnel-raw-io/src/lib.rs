//! Bounded asynchronous userspace-TCP bridge and isolated Linux raw socket adapter.
//!
//! The caller supervises the returned driver with its TLS/application future.
//! No firewall, interface, route or namespace is ever created or changed here.
use l2tunnel_raw_tcp::{CloseReason, Config, Error, Millis, ReadOutcome, Role, State, TcpEngine};
use std::io::{self, Write};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

/// Opt-in counted bridge freeze and original packet-owner handoff.
pub mod handoff;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{RawSocket, open, open_marked, open_packet_marked};

/// Atomic nonblocking packet I/O; used by the driver and finite test links.
pub trait PacketIo {
    /// Read at most one complete IP packet. Buffer has a 65536-byte sentinel bound.
    fn receive(&mut self, output: &mut [u8]) -> io::Result<Option<usize>>;
    /// Send exactly one packet or return WouldBlock without consuming it.
    fn send(&mut self, packet: &[u8]) -> io::Result<()>;
}

/// Finite driver counters, not a claim of authentication or native qualification.
#[derive(Clone, Copy, Debug, Default)]
pub struct Counters {
    /// Packets accepted into the maintained TCP owner.
    pub received_packets: u64,
    /// Packets successfully handed to atomic packet I/O.
    pub sent_packets: u64,
    /// Malformed, foreign or excess incoming packets discarded before state mutation.
    pub discarded_packets: u64,
    /// Caller bytes admitted to the maintained TCP send ring.
    pub sent_bytes: u64,
    /// Ordered original bytes delivered into the finite caller bridge.
    pub received_bytes: u64,
}

/// Explicitly supervised raw-owned TCP driver. Dropping it closes all owned I/O.
pub struct Driver<I: PacketIo> {
    io: I,
    engine: TcpEngine,
    bridge: DuplexStream,
    chunk_bytes: usize,
    drain_timeout_millis: u64,
    counters: Counters,
    handshake_timeout: Duration,
}

/// Build finite bridge/engine state; no task is spawned and no clock is read yet.
pub fn bridge<I: PacketIo>(
    config: Config,
    role: Role,
    io: I,
) -> io::Result<(DuplexStream, Driver<I>)> {
    let engine = TcpEngine::new(config, role, Millis(0)).map_err(io::Error::other)?;
    let (stream, bridge) = tokio::io::duplex(config.mtu);
    Ok((
        stream,
        Driver {
            io,
            engine,
            bridge,
            chunk_bytes: config.mtu,
            drain_timeout_millis: config.idle_timeout_millis,
            counters: Counters::default(),
            handshake_timeout: Duration::from_millis(config.idle_timeout_millis),
        },
    ))
}

impl<I: PacketIo> Driver<I> {
    /// Drive bounded packet/stream progress until orderly close or failure.
    /// The caller must drop this future when its associated application is dropped.
    pub async fn run(mut self) -> io::Result<Counters> {
        let started = tokio::time::Instant::now();
        let mut tick = tokio::time::interval(Duration::from_millis(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut raw_input = vec![0; 65_536];
        let mut caller_input = vec![0; self.chunk_bytes];
        let mut caller_output = vec![0; self.chunk_bytes];
        let mut input_len = 0;
        let mut input_offset = 0;
        let mut output_len = 0;
        let mut output_offset = 0;
        let mut pending_packet: Option<Vec<u8>> = None;
        let mut caller_eof = false;
        let mut peer_eof = false;
        let mut closed_send = false;
        let mut close_started = None::<Millis>;
        loop {
            if !self.engine.status().established && started.elapsed() >= self.handshake_timeout {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "raw TCP handshake deadline",
                ));
            }
            let now =
                Millis(u64::try_from(started.elapsed().as_millis()).map_err(io::Error::other)?);
            for _ in 0..32 {
                let Some(size) = self.io.receive(&mut raw_input)? else {
                    break;
                };
                if size > raw_input.len() {
                    return Err(io::Error::other("packet adapter exceeded buffer"));
                }
                match self.engine.ingest(&raw_input[..size]) {
                    Ok(()) => {
                        self.counters.received_packets =
                            self.counters.received_packets.saturating_add(1)
                    }
                    Err(
                        Error::Malformed
                        | Error::Checksum
                        | Error::Tuple
                        | Error::Mtu
                        | Error::QueueFull,
                    ) => {
                        self.counters.discarded_packets =
                            self.counters.discarded_packets.saturating_add(1);
                    }
                    Err(error) => return Err(io::Error::other(error)),
                }
            }
            self.engine.poll(now, 32).map_err(io::Error::other)?;
            for _ in 0..32 {
                if pending_packet.is_none() {
                    pending_packet = self.engine.pop_packet();
                }
                let Some(packet) = pending_packet.as_ref() else {
                    break;
                };
                match self.io.send(packet) {
                    Ok(()) => {
                        self.counters.sent_packets = self.counters.sent_packets.saturating_add(1);
                        pending_packet = None;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => {
                        let status = self.engine.status();
                        let errno = error
                            .raw_os_error()
                            .map_or_else(|| "null".to_owned(), |value| value.to_string());
                        let _ = writeln!(
                            io::stderr(),
                            "{{\"kind\":\"raw_driver_packet_error\",\"operation\":\"send\",\"raw_os_error\":{errno},\"state\":\"{:?}\",\"close_reason\":\"{:?}\",\"caller_eof\":{caller_eof},\"peer_eof\":{peer_eof},\"input_remaining\":{},\"output_remaining\":{},\"send_bytes\":{},\"receive_bytes\":{},\"outgoing_packets\":{},\"pending_packet_bytes\":{}}}",
                            status.state,
                            status.close_reason,
                            input_len - input_offset,
                            output_len - output_offset,
                            status.send_bytes,
                            status.receive_bytes,
                            status.outgoing_packets,
                            packet.len()
                        );
                        return Err(error);
                    }
                }
            }
            let status = self.engine.status();
            if input_offset < input_len
                && matches!(status.state, State::Established | State::CloseWait)
            {
                let size = self
                    .engine
                    .write(&caller_input[input_offset..input_len])
                    .map_err(io::Error::other)?;
                input_offset += size;
                self.counters.sent_bytes = self.counters.sent_bytes.saturating_add(size as u64);
            }
            if caller_eof && input_offset == input_len && status.established && !closed_send {
                self.engine.close();
                closed_send = true;
            }
            if output_offset == output_len && !peer_eof {
                match self.engine.read(&mut caller_output).map_err(engine_error)? {
                    ReadOutcome::Data(size) => {
                        output_len = size;
                        output_offset = 0;
                    }
                    ReadOutcome::Pending => {}
                    ReadOutcome::Eof => {
                        peer_eof = true;
                        self.bridge.shutdown().await?;
                    }
                }
            }
            let status = self.engine.status();
            if status.state == State::Closed {
                if status.close_reason != Some(CloseReason::Clean) {
                    return Err(engine_error(Error::Terminated(
                        status.close_reason.unwrap_or(CloseReason::Unexpected),
                    )));
                }
                if status.established
                    && caller_eof
                    && peer_eof
                    && output_offset == output_len
                    && input_offset == input_len
                    && status.send_bytes == 0
                    && status.receive_bytes == 0
                    && status.outgoing_packets == 0
                    && pending_packet.is_none()
                {
                    return Ok(self.counters);
                }
                let since = *close_started.get_or_insert(now);
                if now.0 - since.0 >= self.drain_timeout_millis {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "raw-owned TCP final bridge/packet drain deadline",
                    ));
                }
            }
            let (mut reader, mut writer) = tokio::io::split(&mut self.bridge);
            tokio::select! {
                result = reader.read(&mut caller_input), if !caller_eof && input_offset == input_len && status.established => {
                    input_len = result?; input_offset = 0; caller_eof = input_len == 0;
                }
                result = writer.write(&caller_output[output_offset..output_len]), if output_offset < output_len => {
                    let size = result?;
                    if size == 0 { return Err(io::Error::new(io::ErrorKind::WriteZero, "caller bridge closed")); }
                    output_offset += size;
                    self.counters.received_bytes = self.counters.received_bytes.saturating_add(size as u64);
                }
                _ = tick.tick() => {}
            }
        }
    }
}

fn engine_error(error: Error) -> io::Error {
    let kind = match error {
        Error::Terminated(CloseReason::Timeout) => io::ErrorKind::TimedOut,
        Error::Terminated(CloseReason::PeerReset) => io::ErrorKind::ConnectionReset,
        Error::Terminated(CloseReason::UndrainedReceive) => io::ErrorKind::UnexpectedEof,
        Error::Terminated(_) => io::ErrorKind::ConnectionAborted,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, error)
}

#[cfg(test)]
mod tests;
