use crate::native::{Attachment, FENCE, NATIVE_ACK, NativeFence, REQUEST};
use crate::runtime::{Shared, increment};
use crate::{Config, Error};
use l2tunnel_auth::AuthenticatedIo;
use std::{collections::VecDeque, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    time::{Instant, MissedTickBehavior, interval},
};

const PING: u8 = 1;
const PONG: u8 = 2;
const CLOSE: u8 = 3;
const DRAINED: u8 = 4;
const ACK: u8 = 5;

struct Writer<const BYTES: usize> {
    native: bool,
    flushed_kind: u8,
    queue: VecDeque<[u8; BYTES]>,
    current: Option<[u8; BYTES]>,
    offset: usize,
    flush: bool,
    sequence: u64,
    session: [u8; 16],
    digest: [u8; 32],
    role: u8,
}
impl<const BYTES: usize> Writer<BYTES> {
    fn enqueue(&mut self, kind: u8, token: u64) -> Result<(), Error> {
        self.enqueue_fence(kind, token, NativeFence::default())
    }
    fn enqueue_fence(&mut self, kind: u8, token: u64, fence: NativeFence) -> Result<(), Error> {
        if self.queue.len() + usize::from(self.current.is_some()) + usize::from(self.flush)
            >= if self.native { 8 } else { 4 }
        {
            return Err(Error::Configuration("TLS control queue bound"));
        }
        let next = self
            .sequence
            .checked_add(1)
            .ok_or(Error::Configuration("TLS control sequence exhausted"))?;
        let mut bytes = [0; BYTES];
        bytes[..4].copy_from_slice(if self.native { b"OVC2" } else { b"OVC1" });
        bytes[4] = kind;
        bytes[5] = self.role;
        bytes[8..24].copy_from_slice(&self.session);
        bytes[24..32].copy_from_slice(&self.sequence.to_be_bytes());
        bytes[32..40].copy_from_slice(&token.to_be_bytes());
        bytes[40..72].copy_from_slice(&self.digest);
        if self.native {
            for (chunk, value) in bytes[72..104].chunks_exact_mut(8).zip(fence.fields()) {
                chunk.copy_from_slice(&value.to_be_bytes());
            }
        }
        self.queue.push_back(bytes);
        self.sequence = next;
        Ok(())
    }
    fn empty(&self) -> bool {
        self.queue.is_empty() && self.current.is_none() && !self.flush
    }
}
enum WriteEvent {
    Bytes(usize),
    Flushed,
    Shutdown,
}

pub(crate) async fn run(
    connection: AuthenticatedIo<DuplexStream>,
    config: Config,
    server: bool,
    shared: Arc<Shared>,
    native: Option<Attachment>,
) -> Result<(), Error> {
    if native.is_some() {
        run_profile::<112>(connection, config, server, shared, native).await
    } else {
        run_profile::<80>(connection, config, server, shared, None).await
    }
}
async fn run_profile<const BYTES: usize>(
    connection: AuthenticatedIo<DuplexStream>,
    config: Config,
    server: bool,
    shared: Arc<Shared>,
    native: Option<Attachment>,
) -> Result<(), Error> {
    let info = *connection.info();
    let (mut reader, mut writer) = tokio::io::split(connection);
    let mut output = Writer::<BYTES> {
        native: native.is_some(),
        flushed_kind: 0,
        queue: VecDeque::with_capacity(if native.is_some() { 8 } else { 4 }),
        current: None,
        offset: 0,
        flush: false,
        sequence: 0,
        session: info.session_id,
        digest: native
            .as_ref()
            .map_or(info.config.digest.0, |n| n.domain.scope),
        role: if server { 2 } else { 1 },
    };
    let mut input = [0; BYTES];
    let mut used = 0;
    let mut expected_sequence = 0_u64;
    let mut ping = None::<u64>;
    let mut next_ping = 0_u64;
    let mut peer_ping = None::<u64>;
    let mut last_fresh = Instant::now();
    let mut ping_at = Instant::now();
    let (
        mut close_sent,
        mut close_received,
        mut drained_sent,
        mut drained_received,
        mut ack_sent,
        mut ack_received,
    ) = (false, false, false, false, false, false);
    let (mut request_sent, mut fence_sent, mut native_ack_sent) = (false, false, false);
    let (mut shutdown, mut eof) = (false, false);
    let mut deferred_close = false;
    let mut terminal = shared.terminal.subscribe();
    let mut timer = interval(config.poll_interval);
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        shared.check()?;
        if deferred_close
            && let Some(n) = &native
            && n.domain.proof()?
        {
            // An independent secondary lane may overtake the ordered native ACK.
            // Only the completed logical proof activates its retained Close.
            n.domain.secondary_close(false)?;
            shared.begin_close()?;
            close_received = true;
            deferred_close = false;
        }
        let (closing, close_started, data_drained) =
            shared.modify(|s| Ok((s.status.closing, s.close_started, s.data_drained)))?;
        let now = Instant::now();
        if close_started.is_some_and(|start| now.duration_since(start) >= config.close_timeout) {
            #[cfg(test)]
            eprintln!(
                "CLOSE_TLS_TIMEOUT lane={} server={server} shared={:p} elapsed={:?} close=({close_sent},{close_received}) drained=({drained_sent},{drained_received},{data_drained}) ack=({ack_sent},{ack_received}) shutdown={shutdown} eof={eof} output=({},{},{}) used={used}",
                config.profile.lane.0,
                std::sync::Arc::as_ptr(&shared),
                close_started.map(|t| t.elapsed()),
                output.queue.len(),
                output.current.is_some(),
                output.flush
            );
            return Err(Error::IncompleteClose);
        }
        if !closing && now.duration_since(last_fresh) >= config.inactivity_timeout {
            return Err(Error::Timeout);
        }
        if let Some(attachment) = &native {
            let state = attachment.domain.state()?;
            if state.deadline.is_some_and(|end| now >= end) {
                return Err(Error::IncompleteClose);
            }
            if attachment.management {
                if state.requested_at.is_some() && !request_sent {
                    output.enqueue(REQUEST, 0)?;
                    request_sent = true;
                }
                if let Some(fence) = state.local
                    && !fence_sent
                {
                    output.enqueue_fence(FENCE, 0, fence)?;
                    fence_sent = true;
                }
                if state.peer_acknowledged && !native_ack_sent {
                    let peer = state
                        .peer
                        .ok_or(Error::Configuration("native ack missing fence"))?;
                    output.enqueue_fence(NATIVE_ACK, 0, peer.fence())?;
                    native_ack_sent = true;
                }
            }
            if closing && !attachment.domain.proof()? {
                return Err(Error::Configuration("carrier close before native proof"));
            }
        }
        if closing && !close_sent {
            output.enqueue(CLOSE, 0)?;
            close_sent = true;
        }
        if close_received && data_drained && !drained_sent {
            output.enqueue(DRAINED, 0)?;
            drained_sent = true;
        }
        if drained_sent && drained_received && !ack_sent {
            output.enqueue(ACK, 0)?;
            ack_sent = true;
        }
        if !closing && ping.is_none() && now >= ping_at {
            output.enqueue(PING, next_ping)?;
            ping = Some(next_ping);
            next_ping = next_ping
                .checked_add(1)
                .ok_or(Error::Configuration("heartbeat nonce exhausted"))?;
            ping_at = now + config.heartbeat_interval;
        }
        if output.current.is_none() && !output.flush {
            output.current = output.queue.pop_front();
            output.offset = 0;
        }
        let may_shutdown = ack_sent && ack_received && output.empty() && data_drained;
        if shutdown && eof {
            shared.modify(|s| {
                s.tls_finished = true;
                Ok(())
            })?;
            return Ok(());
        }
        tokio::select! {
            _ = terminal.changed() => { shared.check()?; return Err(Error::Closed); }
            _ = timer.tick() => {}
            written = async {
                if output.flush { writer.flush().await.map(|()| WriteEvent::Flushed) }
                else if let Some(bytes) = &output.current { writer.write(&bytes[output.offset..]).await.map(WriteEvent::Bytes) }
                else if may_shutdown && !shutdown { writer.shutdown().await.map(|()| WriteEvent::Shutdown) }
                else { std::future::pending().await }
            } => match written? {
                WriteEvent::Bytes(0) => return Err(Error::Closed),
                WriteEvent::Bytes(count) => { output.offset += count; if output.offset == BYTES { output.flushed_kind=output.current.as_ref().ok_or(Error::Closed)?[4]; output.current = None; output.flush = true; } }
                WriteEvent::Flushed => { output.flush = false; if let Some(n)=&native { n.domain.flushed(output.flushed_kind)?; } },
                WriteEvent::Shutdown => shutdown = true,
            },
            read = reader.read(&mut input[used..]), if !eof => {
                let count = read?;
                if count == 0 {
                    if !ack_received || !ack_sent || used != 0 { return Err(Error::Closed); }
                    eof = true; continue;
                }
                used += count;
                if used != BYTES { continue; }
                used = 0;
                let (kind,sequence,token,fence)=decode(&input, info.session_id, output.digest, 3-output.role, native.is_some())?;
                if sequence < expected_sequence { continue; }
                if sequence != expected_sequence { return Err(Error::Configuration("internal TLS sequence gap")); }
                expected_sequence = expected_sequence.checked_add(1).ok_or(Error::Configuration("internal TLS sequence exhausted"))?;
                match kind {
                    PING => {
                        if peer_ping.is_some_and(|old| token <= old) { continue; }
                        peer_ping = Some(token); output.enqueue(PONG, token)?;
                    }
                    PONG if ping == Some(token) => ping = None,
                    CLOSE if token == 0 && !close_received => {
                        if let Some(n)=&native && !n.domain.proof()? {
                            if n.management {return Err(Error::Configuration("peer management close before native proof"));}
                            if deferred_close {continue;}
                            n.domain.secondary_close(true)?;deferred_close=true;
                        } else {close_received = true; shared.begin_close()?;}
                    }
                    DRAINED if token == 0 && close_received && !drained_received => drained_received = true,
                    ACK if token == 0 && drained_sent && drained_received && !ack_received => ack_received = true,
                    CLOSE | DRAINED | ACK if token == 0 => continue,
                    REQUEST | FENCE | NATIVE_ACK if token == 0 => {
                        let attachment=native.as_ref().filter(|n| n.management).ok_or(Error::Configuration("native kind on inactive profile/lane"))?;
                        if !attachment.domain.accept(kind,fence)? { continue; }
                    }
                    _ => return Err(Error::Configuration("internal TLS kind/state/nonce")),
                }
                last_fresh = Instant::now();
                shared.modify(|s| increment(&mut s.status.tls_messages))?;
            }
        }
    }
}
fn number(bytes: &[u8]) -> Result<u64, Error> {
    Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| {
        Error::Configuration("internal integer length")
    })?))
}

fn decode(
    input: &[u8],
    session: [u8; 16],
    scope: [u8; 32],
    role: u8,
    native: bool,
) -> Result<(u8, u64, u64, NativeFence), Error> {
    let length = if native { 112 } else { 80 };
    if input.len() != length
        || input[..4] != *if native { b"OVC2" } else { b"OVC1" }
        || input[5] != role
        || !(1..=2).contains(&role)
        || input[6..8] != [0; 2]
        || input[8..24] != session
        || input[40..72] != scope
        || input[length - 8..] != [0; 8]
    {
        return Err(Error::Configuration("internal TLS scope or format"));
    }
    let kind = input[4];
    let token = number(&input[32..40])?;
    if !(PING..=if native { NATIVE_ACK } else { ACK }).contains(&kind)
        || (kind >= CLOSE && token != 0)
    {
        return Err(Error::Configuration("internal TLS kind or nonce"));
    }
    let fence = if native {
        NativeFence::from_fields([
            number(&input[72..80])?,
            number(&input[80..88])?,
            number(&input[88..96])?,
            number(&input[96..104])?,
        ])
    } else {
        NativeFence::default()
    };
    if kind <= REQUEST && fence != NativeFence::default() {
        return Err(Error::Configuration("unexpected native fence fields"));
    }
    Ok((kind, number(&input[24..32])?, token, fence))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn writer<const N: usize>(native: bool) -> Writer<N> {
        Writer {
            native,
            flushed_kind: 0,
            queue: VecDeque::new(),
            current: None,
            offset: 0,
            flush: false,
            sequence: 0,
            session: [3; 16],
            digest: [4; 32],
            role: 1,
        }
    }
    #[test]
    fn legacy_ovc1_bytes_stay_exact_and_native_is_a_distinct_strict_frame() -> Result<(), Error> {
        let mut old = writer::<80>(false);
        old.enqueue(PING, 9)?;
        let bytes = old.queue.pop_front().ok_or(Error::Closed)?;
        let mut expected = [0; 80];
        expected[..4].copy_from_slice(b"OVC1");
        expected[4] = 1;
        expected[5] = 1;
        expected[8..24].fill(3);
        expected[39] = 9;
        expected[40..72].fill(4);
        assert_eq!(bytes, expected);
        assert_eq!(decode(&bytes, [3; 16], [4; 32], 1, false)?.2, 9);
        let mut new = writer::<112>(true);
        new.enqueue_fence(
            FENCE,
            0,
            NativeFence {
                packets: 1,
                native_bytes: 9,
                sources: 2,
                source_bytes: 15,
            },
        )?;
        let bytes = new.queue.pop_front().ok_or(Error::Closed)?;
        assert_eq!(decode(&bytes, [3; 16], [4; 32], 1, true)?.3.sources, 2);
        for length in 0..112 {
            assert!(decode(&bytes[..length], [3; 16], [4; 32], 1, true).is_err());
        }
        for offset in [0, 4, 5, 6, 7, 8, 40, 104, 111] {
            let mut bad = bytes;
            bad[offset] ^= 0xff;
            assert!(
                decode(&bad, [3; 16], [4; 32], 1, true).is_err(),
                "offset {offset}"
            );
        }
        let mut bad = bytes;
        bad[39] = 1;
        assert!(decode(&bad, [3; 16], [4; 32], 1, true).is_err());
        bad = bytes;
        bad[4] = REQUEST;
        assert!(decode(&bad, [3; 16], [4; 32], 1, true).is_err());
        assert!(decode(&bytes, [3; 16], [4; 32], 1, false).is_err());
        Ok(())
    }
    #[test]
    fn output_limit_includes_unflushed_record_and_sequence_overflow_is_atomic() -> Result<(), Error>
    {
        let mut out = writer::<112>(true);
        out.flush = true;
        for _ in 0..7 {
            out.enqueue(PING, 0)?;
        }
        assert!(out.enqueue(PING, 0).is_err());
        assert_eq!(out.queue.len(), 7);
        let mut exhausted = writer::<112>(true);
        exhausted.sequence = u64::MAX;
        assert!(exhausted.enqueue(REQUEST, 0).is_err());
        assert!(exhausted.queue.is_empty());
        assert_eq!(exhausted.sequence, u64::MAX);
        Ok(())
    }
}
