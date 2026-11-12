use super::*;
use crate::{
    PacketIo,
    handoff::{SwitchLimits, bridge_switchable},
};
use l2tunnel_raw_tcp::{Config, Role};
use std::{
    collections::VecDeque,
    net::{Ipv4Addr, SocketAddrV4},
    task::Waker,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
type R = Result<(), Box<dyn std::error::Error>>;

struct Mock {
    input: VecDeque<u8>,
    output: Vec<u8>,
    chunk: usize,
    calls: [usize; 4],
    offered: Vec<usize>,
    pending: [bool; 4],
    errno: [Option<i32>; 4],
    zero_write: bool,
}
impl Mock {
    fn new(input: Vec<u8>, chunk: usize) -> Self {
        Self {
            input: input.into(),
            output: vec![],
            chunk,
            calls: [0; 4],
            offered: vec![],
            pending: [false; 4],
            errno: [None; 4],
            zero_write: false,
        }
    }
    fn begin(&mut self, op: usize) -> Poll<io::Result<()>> {
        self.calls[op] += 1;
        if self.pending[op] {
            return Poll::Pending;
        }
        if let Some(errno) = self.errno[op] {
            return Poll::Ready(Err(io::Error::from_raw_os_error(errno)));
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncRead for Mock {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.offered.push(out.remaining());
        match this.begin(0) {
            Poll::Ready(Ok(())) => (),
            v => return v,
        }
        let n = this.input.len().min(out.remaining()).min(this.chunk);
        for _ in 0..n {
            if let Some(b) = this.input.pop_front() {
                out.put_slice(&[b]);
            }
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Mock {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.offered.push(bytes.len());
        match this.begin(1) {
            Poll::Ready(Ok(())) => (),
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        }
        let n = if this.zero_write {
            0
        } else {
            bytes.len().min(this.chunk)
        };
        this.output.extend_from_slice(&bytes[..n]);
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().begin(2)
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().begin(3)
    }
}
fn record(n: u16) -> Vec<u8> {
    let [hi, lo] = n.to_be_bytes();
    let mut v = vec![23, 3, 3, hi, lo];
    v.extend((0..n).map(|x| (x % 251) as u8));
    v
}
fn observer(input: Vec<u8>, chunk: usize) -> RecordIo<Mock> {
    RecordIo::new(Mock::new(input, chunk), RecordLimits::default())
}
fn read_once(io: &mut RecordIo<Mock>, out: &mut [u8]) -> (Poll<io::Result<()>>, usize) {
    let mut buf = ReadBuf::new(out);
    let result = Pin::new(io).poll_read(&mut Context::from_waker(Waker::noop()), &mut buf);
    (result, buf.filled().len())
}
fn write_once(io: &mut RecordIo<Mock>, bytes: &[u8]) -> Poll<io::Result<usize>> {
    Pin::new(io).poll_write(&mut Context::from_waker(Waker::noop()), bytes)
}
fn ready<T>(value: Poll<io::Result<T>>) -> io::Result<T> {
    match value {
        Poll::Ready(v) => v,
        Poll::Pending => Err(io::Error::other("unexpected Pending")),
    }
}
fn fault(io: &RecordIo<Mock>, direction: RecordDirection, kind: RecordFaultKind) {
    assert_eq!(io.status().fault, Some(RecordFault { direction, kind }));
}

#[tokio::test]
async fn all_header_splits_zero_and_maximum_payload_roundtrip_without_prefetch() -> R {
    for n in [0, 1, 7, 4096, MAX_RECORD_PAYLOAD] {
        for chunk in 1..=6 {
            let original = record(n);
            let mut input = original.clone();
            input.extend(record(1));
            let mut io = observer(input, chunk);
            let mut out = vec![0; original.len()];
            io.read_exact(&mut out).await?;
            assert_eq!(out, original);
            assert_eq!(io.inner.input.len(), 6);
            assert_eq!(io.status().incoming.wire_bytes, original.len() as u64);
            assert_eq!(io.status().incoming.started_records, 1);
            assert_eq!(io.status().incoming.completed_records, 1);
            assert!(io.status().incoming.at_boundary());
            io.write_all(&original).await?;
            assert_eq!(io.inner.output, original);
            assert_eq!(io.status().incoming, io.status().outgoing);
            assert!(io.inner.offered.iter().all(|n| *n <= MAX_POLL_BYTES));
        }
    }
    Ok(())
}
#[test]
fn one_call_returns_only_current_header_or_body_and_charges_started_once() -> R {
    let mut io = observer([record(6), record(0)].concat(), usize::MAX);
    let mut bytes = [0; 64];
    for (expected, header, body, completed) in [(5, 5, 6, 0), (6, 0, 0, 1), (5, 0, 0, 2)] {
        let calls = io.inner.calls[0];
        let (result, n) = read_once(&mut io, &mut bytes);
        ready(result)?;
        assert_eq!(n, expected);
        assert_eq!(io.inner.calls[0], calls + 1);
        let p = io.status().incoming;
        assert_eq!(
            (p.header_bytes, p.body_remaining, p.completed_records),
            (header, body, completed)
        );
    }
    assert_eq!(io.status().incoming.started_records, 2);
    Ok(())
}
#[test]
fn invalid_incoming_header_reports_real_progress_then_stops_both_directions() -> R {
    for split in 1..=5 {
        let mut io = observer(record(9), split);
        io.limits.max_payload = 8;
        let mut got = vec![];
        while io.status().fault.is_none() {
            let mut b = [0; 30];
            let (result, n) = read_once(&mut io, &mut b);
            ready(result)?;
            got.extend_from_slice(&b[..n]);
        }
        assert_eq!(got, record(9)[..5]);
        assert_eq!(io.status().incoming.wire_bytes, 5);
        assert_eq!(io.inner.input.len(), 9);
        fault(
            &io,
            RecordDirection::Incoming,
            RecordFaultKind::RecordLength,
        );
        let calls = io.inner.calls;
        assert!(ready(read_once(&mut io, &mut [0; 2]).0).is_err());
        assert!(ready(write_once(&mut io, &[])).is_err());
        assert!(
            ready(Pin::new(&mut io).poll_flush(&mut Context::from_waker(Waker::noop()))).is_err()
        );
        assert_eq!(io.inner.calls, calls);
    }
    Ok(())
}
#[test]
fn outgoing_invalid_header_is_previewed_before_any_new_endpoint_bytes() -> R {
    for split in 0..5 {
        let mut io = observer(vec![], 99);
        io.limits.max_payload = 8;
        if split > 0 {
            assert_eq!(ready(write_once(&mut io, &record(9)[..split]))?, split);
        }
        let before = io.status().outgoing;
        let calls = io.inner.calls;
        assert!(ready(write_once(&mut io, &record(9)[split..])).is_err());
        fault(
            &io,
            RecordDirection::Outgoing,
            RecordFaultKind::RecordLength,
        );
        assert_eq!(io.status().outgoing, before);
        assert_eq!(io.inner.output, record(9)[..split]);
        assert_eq!(io.inner.calls, calls);
    }
    Ok(())
}
#[tokio::test]
async fn record_and_byte_caps_complete_final_record_then_reject_before_io() -> R {
    for use_record_limit in [false, true] {
        let data = record(3);
        let mut io = observer([data.clone(), record(0)].concat(), 2);
        let limits = DirectionLimits {
            wire_bytes: if use_record_limit { 99 } else { 8 },
            records: if use_record_limit { 1 } else { 99 },
        };
        io.limits.incoming = limits;
        io.limits.outgoing = limits;
        let mut out = [0; 8];
        io.read_exact(&mut out).await?;
        io.write_all(&data).await?;
        assert!(io.status().fault.is_none());
        io.flush().await?;
        let before = io.status();
        let calls = io.inner.calls;
        assert!(ready(read_once(&mut io, &mut [7; 10]).0).is_err());
        assert_eq!(io.status().incoming, before.incoming);
        assert_eq!(io.inner.calls, calls);
        fault(
            &io,
            RecordDirection::Incoming,
            if use_record_limit {
                RecordFaultKind::RecordLimit
            } else {
                RecordFaultKind::ByteLimit
            },
        );
    }
    Ok(())
}
#[test]
fn full_body_budget_is_reserved_on_header_without_charging_untransferred_bytes() -> R {
    let mut input = observer(record(5), 99);
    input.limits.incoming.wire_bytes = 9;
    let (result, n) = read_once(&mut input, &mut [0; 50]);
    ready(result)?;
    assert_eq!(n, 5);
    assert_eq!(input.status().incoming.wire_bytes, 5);
    assert_eq!(input.inner.input.len(), 5);
    fault(
        &input,
        RecordDirection::Incoming,
        RecordFaultKind::ByteLimit,
    );
    let mut output = observer(vec![], 99);
    output.limits.outgoing.wire_bytes = 9;
    assert!(ready(write_once(&mut output, &record(5))).is_err());
    assert_eq!(output.inner.calls, [0; 4]);
    assert_eq!(output.status().outgoing, RecordProgress::default());
    fault(
        &output,
        RecordDirection::Outgoing,
        RecordFaultKind::ByteLimit,
    );
    Ok(())
}
#[test]
fn checked_counter_exhaustion_rejects_before_side_effects() {
    for field in 0..3 {
        for incoming in [false, true] {
            let mut io = observer(record(0), 99);
            let parser = if incoming {
                &mut io.incoming
            } else {
                &mut io.outgoing
            };
            match field {
                0 => parser.progress.wire_bytes = u64::MAX,
                1 => parser.progress.started_records = u64::MAX,
                _ => parser.progress.completed_records = u64::MAX,
            }
            let before = io.status();
            let rejected = if incoming {
                ready(read_once(&mut io, &mut [0; 5]).0).is_err()
            } else {
                ready(write_once(&mut io, &record(0))).is_err()
            };
            assert!(rejected);
            assert_eq!(io.inner.calls, [0; 4]);
            assert_eq!(io.status().incoming, before.incoming);
            assert_eq!(io.status().outgoing, before.outgoing);
            fault(
                &io,
                if incoming {
                    RecordDirection::Incoming
                } else {
                    RecordDirection::Outgoing
                },
                RecordFaultKind::Arithmetic,
            );
        }
    }
}
#[test]
fn pending_cancellation_and_partial_acceptance_preserve_exact_suffix() -> R {
    let data = record(4);
    let mut io = observer(data.clone(), 2);
    io.inner.pending[0] = true;
    io.inner.pending[1] = true;
    let before = io.status();
    assert!(read_once(&mut io, &mut [0; 99]).0.is_pending());
    assert!(write_once(&mut io, &data).is_pending());
    assert_eq!(io.status(), before);
    io.inner.pending = [false; 4];
    assert_eq!(ready(write_once(&mut io, &data))?, 2);
    assert_eq!(io.status().outgoing.header_bytes, 2);
    assert_eq!(io.status().outgoing.started_records, 1);
    io.inner.pending[1] = true;
    let before = io.status();
    assert!(write_once(&mut io, &data[2..]).is_pending());
    assert_eq!(io.status(), before);
    io.inner.pending[1] = false;
    let mut offset = 2;
    while offset < data.len() {
        offset += ready(write_once(&mut io, &data[offset..]))?;
    }
    assert_eq!(io.inner.output, data);
    assert_eq!(io.status().outgoing.completed_records, 1);
    Ok(())
}
#[tokio::test]
async fn eof_at_every_incomplete_phase_is_sticky_but_boundary_eof_is_half_close() -> R {
    let data = record(4);
    for n in 0..data.len() {
        let mut io = observer(data[..n].to_vec(), 2);
        let mut bytes = vec![0; n];
        io.read_exact(&mut bytes).await?;
        let (result, got) = read_once(&mut io, &mut [0; 3]);
        assert_eq!(got, 0);
        if n == 0 {
            ready(result)?;
            assert!(io.status().read_eof);
            assert!(io.status().fault.is_none());
            let calls = io.inner.calls[0];
            ready(read_once(&mut io, &mut [0; 2]).0)?;
            assert_eq!(io.inner.calls[0], calls);
            io.write_all(&data).await?;
        } else {
            assert_eq!(
                ready(result).err().ok_or("missing EOF")?.kind(),
                io::ErrorKind::UnexpectedEof
            );
            fault(
                &io,
                RecordDirection::Incoming,
                RecordFaultKind::TruncatedRecord,
            );
            assert!(!io.status().read_eof);
        }
    }
    Ok(())
}
#[test]
fn first_io_error_preserves_errno_and_prevents_all_further_io() -> R {
    for op in 0..4 {
        let mut io = observer(record(0), 99);
        io.inner.errno[op] = Some(13);
        let mut cx = Context::from_waker(Waker::noop());
        let error = match op {
            0 => ready(read_once(&mut io, &mut [0; 5]).0).err(),
            1 => ready(write_once(&mut io, &record(0))).err(),
            2 => ready(Pin::new(&mut io).poll_flush(&mut cx)).err(),
            _ => ready(Pin::new(&mut io).poll_shutdown(&mut cx)).err(),
        }
        .ok_or("missing I/O error")?;
        assert_eq!(error.raw_os_error(), Some(13));
        let status = io.status();
        let calls = io.inner.calls;
        assert!(ready(read_once(&mut io, &mut []).0).is_err());
        assert!(ready(write_once(&mut io, &[])).is_err());
        assert!(ready(Pin::new(&mut io).poll_shutdown(&mut cx)).is_err());
        assert_eq!(io.status(), status);
        assert_eq!(io.inner.calls, calls);
    }
    Ok(())
}
#[test]
fn write_zero_is_terminal_and_no_record_is_started() -> R {
    let mut io = observer(vec![], 99);
    io.inner.zero_write = true;
    assert_eq!(
        ready(write_once(&mut io, &record(0)))
            .err()
            .ok_or("missing zero error")?
            .kind(),
        io::ErrorKind::WriteZero
    );
    fault(&io, RecordDirection::Outgoing, RecordFaultKind::WriteZero);
    assert_eq!(io.status().outgoing, RecordProgress::default());
    Ok(())
}
#[test]
fn shutdown_pending_is_irreversible_while_read_side_remains_usable() -> R {
    let mut io = observer(record(0), 99);
    io.inner.pending[3] = true;
    let mut cx = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut io).poll_shutdown(&mut cx).is_pending());
    assert!(io.status().shutdown_started);
    assert!(!io.status().shutdown_completed);
    assert_eq!(
        ready(write_once(&mut io, &[]))
            .err()
            .ok_or("write after shutdown")?
            .kind(),
        io::ErrorKind::BrokenPipe
    );
    assert_eq!(io.inner.calls[1], 0);
    ready(read_once(&mut io, &mut [0; 5]).0)?;
    io.inner.pending[3] = false;
    ready(Pin::new(&mut io).poll_shutdown(&mut cx))?;
    assert!(io.status().shutdown_completed);
    let calls = io.inner.calls;
    ready(Pin::new(&mut io).poll_shutdown(&mut cx))?;
    assert_eq!(calls, io.inner.calls);
    Ok(())
}
#[test]
fn empty_and_bounded_vectored_operations_never_prefetch_or_scan_unbounded_input() -> R {
    let mut io = observer(record(0), 99);
    let mut cx = Context::from_waker(Waker::noop());
    ready(read_once(&mut io, &mut []).0)?;
    assert_eq!(ready(write_once(&mut io, &[]))?, 0);
    let empty = [io::IoSlice::new(&[]); MAX_IO_SLICES];
    assert_eq!(
        ready(Pin::new(&mut io).poll_write_vectored(&mut cx, &empty))?,
        0
    );
    assert_eq!(io.inner.calls, [0; 4]);
    assert!(!io.status().read_eof);
    let oversized = [io::IoSlice::new(&[]); MAX_IO_SLICES + 1];
    assert!(ready(Pin::new(&mut io).poll_write_vectored(&mut cx, &oversized)).is_err());
    assert_eq!(io.inner.calls, [0; 4]);
    assert!(io.status().fault.is_none());
    let data = record(0);
    let buffers = [
        io::IoSlice::new(&[]),
        io::IoSlice::new(&data[..2]),
        io::IoSlice::new(&data[2..]),
    ];
    assert_eq!(
        ready(Pin::new(&mut io).poll_write_vectored(&mut cx, &buffers))?,
        2
    );
    assert_eq!(io.inner.output, data[..2]);
    assert!(!io.is_write_vectored());
    Ok(())
}

struct NoPackets;
impl PacketIo for NoPackets {
    fn receive(&mut self, _: &mut [u8]) -> io::Result<Option<usize>> {
        Ok(None)
    }
    fn send(&mut self, _: &[u8]) -> io::Result<()> {
        Err(io::ErrorKind::WouldBlock.into())
    }
}
fn tracked() -> io::Result<(
    TrackedStream,
    SwitchHandle,
    super::super::SwitchDriver<NoPackets>,
)> {
    bridge_switchable(
        Config {
            local: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 4001),
            peer: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 2), 4002),
            mtu: 576,
            send_bytes: 4096,
            receive_bytes: 4096,
            packet_slots: 8,
            random_seed: 123,
            ack_delay_millis: 1,
            keepalive_millis: 1000,
            idle_timeout_millis: 30000,
        },
        Role::Client,
        NoPackets,
        SwitchLimits::default(),
    )
}
#[test]
fn limits_rejection_returns_original_owner_without_gate_mutation() -> R {
    let invalid = [
        RecordLimits {
            max_payload: 0,
            ..RecordLimits::default()
        },
        RecordLimits {
            max_payload: MAX_RECORD_PAYLOAD + 1,
            ..RecordLimits::default()
        },
        RecordLimits {
            incoming: DirectionLimits {
                wire_bytes: 4,
                records: 1,
            },
            ..RecordLimits::default()
        },
        RecordLimits {
            outgoing: DirectionLimits {
                wire_bytes: MAX_DIRECTION_BYTES + 1,
                records: 1,
            },
            ..RecordLimits::default()
        },
        RecordLimits {
            incoming: DirectionLimits {
                wire_bytes: 5,
                records: 0,
            },
            ..RecordLimits::default()
        },
        RecordLimits {
            outgoing: DirectionLimits {
                wire_bytes: 5,
                records: MAX_DIRECTION_RECORDS + 1,
            },
            ..RecordLimits::default()
        },
    ];
    for limits in invalid {
        let (stream, handle, _driver) = tracked()?;
        let shared = stream.shared.clone();
        let before = handle.status();
        let (returned, reason) = RecordIo::attach(stream, limits)
            .err()
            .ok_or("accepted invalid limits")?;
        assert_eq!(reason, AttachError::InvalidLimits);
        assert!(Arc::ptr_eq(&returned.shared, &shared));
        assert_eq!(handle.status(), before);
    }
    Ok(())
}
#[test]
fn freshness_rejects_used_or_terminal_endpoints_even_if_record_aligned() -> R {
    for case in 0..9 {
        let (stream, handle, _driver) = tracked()?;
        let shared = stream.shared.clone();
        {
            let mut gate = shared.lock().map_err(|_| "gate")?;
            match case {
                0 => gate.status.endpoint.read = 5,
                1 => gate.status.endpoint.written = 5,
                2 => gate.eof = true,
                3 => gate.shutdown = true,
                4 => gate.handle_alive = false,
                5 => gate.status.state = SwitchState::Failed,
                6 => gate.status.state = SwitchState::Frozen,
                7 => gate.status.state = SwitchState::Clean,
                _ => gate.status.state = SwitchState::Handoff,
            }
        }
        let before = handle.status();
        let (returned, reason) = RecordIo::attach(stream, RecordLimits::default())
            .err()
            .ok_or("accepted stale endpoint")?;
        assert_eq!(reason, AttachError::NotFresh);
        assert!(Arc::ptr_eq(&returned.shared, &shared));
        assert_eq!(handle.status(), before);
    }
    Ok(())
}
#[test]
fn fresh_identity_is_exact_and_permits_running_driver_without_endpoint_use() -> R {
    for running in [false, true] {
        let (stream, handle, _driver) = tracked()?;
        let (_other, other_handle, _other_driver) = tracked()?;
        if running {
            stream.shared.lock().map_err(|_| "gate")?.status.state = SwitchState::Running;
        }
        let io = RecordIo::attach(stream, RecordLimits::default()).map_err(|(_, e)| e)?;
        assert!(io.belongs_to(&handle));
        assert!(!io.belongs_to(&other_handle));
        assert_eq!(io.status(), RecordStatus::default());
    }
    Ok(())
}

#[test]
fn every_small_body_boundary_cancellation_retains_progress_and_never_next_record() -> R {
    for split in 1..=31 {
        let data = record(32);
        let mut io = observer([data.clone(), record(0)].concat(), 99);
        ready(read_once(&mut io, &mut [0; 5]).0)?;
        let mut body = [0; 32];
        assert_eq!(read_once(&mut io, &mut body[..split]).1, split);
        assert_eq!(io.status().incoming.body_remaining, (32 - split) as u16);
        io.inner.pending[0] = true;
        let status = io.status();
        let (polled, n) = read_once(&mut io, &mut body[split..]);
        assert!(polled.is_pending());
        assert_eq!(n, 0);
        assert_eq!(io.status(), status);
        io.inner.pending[0] = false;
        let (result, n) = read_once(&mut io, &mut body[split..]);
        ready(result)?;
        assert_eq!(n, 32 - split);
        assert_eq!(body, data[5..]);
        assert_eq!(io.inner.input.len(), 5);
        assert!(io.status().incoming.at_boundary());
    }
    Ok(())
}
#[test]
fn incoming_lengths_cover_backend_exclusive_ceiling_and_u16_maximum() -> R {
    for length in [MAX_RECORD_PAYLOAD + 1, u16::MAX] {
        let [hi, lo] = length.to_be_bytes();
        let header = [23, 3, 3, hi, lo];
        let mut io = observer(header.to_vec(), 99);
        let (result, n) = read_once(&mut io, &mut [0; 5]);
        ready(result)?;
        assert_eq!(n, 5);
        fault(
            &io,
            RecordDirection::Incoming,
            RecordFaultKind::RecordLength,
        );
        assert_eq!(io.status().incoming.completed_records, 0);
        let mut io = observer(vec![], 99);
        assert!(ready(write_once(&mut io, &header)).is_err());
        assert_eq!(io.inner.calls, [0; 4]);
    }
    Ok(())
}
#[test]
fn insufficient_next_header_space_is_rejected_without_reading_eof() -> R {
    for spare in 0..5 {
        let mut io = observer(record(0), 99);
        io.limits.incoming.wire_bytes = 5 + spare;
        ready(read_once(&mut io, &mut [0; 5]).0)?;
        let before = io.status();
        let calls = io.inner.calls;
        assert!(ready(read_once(&mut io, &mut [0; 1]).0).is_err());
        assert_eq!(io.status().incoming, before.incoming);
        assert_eq!(io.inner.calls, calls);
        assert!(!io.status().read_eof);
        fault(&io, RecordDirection::Incoming, RecordFaultKind::ByteLimit);
    }
    Ok(())
}
