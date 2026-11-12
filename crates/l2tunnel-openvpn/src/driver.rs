use crate::budget::Budget;
use crate::runtime::{Activation, DataState, Received, Shared, Submission, Terminal, increment};
use crate::{Config, Error};
use l2tunnel_recovery::{BufferSide, PacketView, RecoveryEngine, RecoveryError, inspect_packet};
use l2tunnel_udp_control::{ClientGate, ControlEngine, ReceiveOutcome};
use std::{io, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    net::UdpSocket,
    sync::mpsc,
    time::{Instant, MissedTickBehavior, interval},
};

#[allow(clippy::too_many_arguments)] // One private actor owns all bounded channels and the sole socket reader.
pub(crate) async fn run(
    socket: UdpSocket,
    config: Config,
    server: bool,
    mut control: ControlEngine,
    mut gate: Option<ClientGate>,
    started: Instant,
    port: DuplexStream,
    mut activation: mpsc::Receiver<Activation>,
    mut input: mpsc::Receiver<Submission>,
    output: mpsc::Sender<Received>,
    shared: Arc<Shared>,
    budget: Budget,
) -> Result<(), Error> {
    let peer = if server {
        config.bootstrap.path.client
    } else {
        config.bootstrap.path.server
    };
    let (mut stream_read, mut stream_write) = tokio::io::split(port);
    let mut terminal = shared.terminal.subscribe();
    let mut timer = interval(config.poll_interval);
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut data = None::<DataState>;
    let mut activation_closed = false;
    let mut submission = None::<Submission>;
    let mut input_closed = false;
    let mut stream_closed = false;
    let mut receive = vec![0; config.bootstrap.path_mtu - config.bootstrap.outer_overhead + 1];
    let mut control_buffer = vec![0; control.max_datagram_bytes()];
    let mut data_buffer = Vec::new();
    let mut sealed = Vec::new();
    let mut native = Vec::new();
    let mut from_tls = vec![0; config.bootstrap.arq.max_source_bytes];
    let mut to_tls = vec![0; config.bootstrap.arq.max_source_bytes];
    let (mut from_start, mut from_end, mut to_start, mut to_end) = (0, 0, 0, 0);
    let (mut control_output, mut data_output) = (None::<Vec<u8>>, None::<Vec<u8>>);
    let mut prefer_tls = true;
    let mut quiet = CloseQuiet::new(
        config
            .bootstrap
            .arq
            .maximum_rto
            .checked_add(config.bootstrap.arq.ack_delay)
            .and_then(|v| v.checked_add(config.poll_interval.checked_mul(2)?))
            .ok_or(Error::Configuration("close quiet overflow"))?,
    );
    #[cfg(test)]
    let mut test_path = super::test_wire::Path::take(socket.local_addr()?)?;
    loop {
        shared.check()?;
        tokio::select! {
            _ = terminal.changed() => { shared.check()?; return Err(Error::Closed); }
            _ = timer.tick() => {}
            _ = socket.writable(), if control_output.is_some() || data_output.is_some() => {}
            value = activation.recv(), if !activation_closed => {
                let Some(value) = value else { activation_closed = true; if data.is_none() { return Err(Error::Closed); } continue; };
                match value {
                    Activation::Promote(reply) => {
                        let promoted = control.promote_authenticated(config.authenticated_lease, started.elapsed());
                        if let Err(error) = promoted { let _ = reply.send(Err(Error::Control(error))); return Err(Error::Control(error)); }
                        reply.send(Ok(())).map_err(|_| Error::Closed)?;
                    }
                    Activation::Enable { data: value, reply } => {
                        if data.is_some() { return Err(Error::Configuration("duplicate data activation")); }
                        data = Some(*value);
                        data_buffer.resize(config.profile.max_payload_bytes, 0);
                        sealed.resize(receive.len() - 1, 0);
                        native.resize(config.arq.max_source_bytes, 0);
                        shared.modify(|state| { state.status.authenticated = true; Ok(()) })?;
                        reply.send(Ok(())).map_err(|_| Error::Closed)?;
                    }
                }
            }
            value = input.recv(), if !input_closed && submission.is_none() => {
                match value { Some(value) => submission = Some(value), None => input_closed = true }
            }
            read = stream_read.read(&mut from_tls), if !stream_closed && from_start == from_end => {
                from_end = read?; from_start = 0;
                if from_end == 0 {
                    stream_closed = true;
                    if !shared.modify(|s| Ok(s.status.closing))? { return Err(Error::Closed); }
                }
            }
            written = stream_write.write(&to_tls[to_start..to_end]), if to_start != to_end => {
                let written = written?; if written == 0 { return Err(Error::Closed); } to_start += written;
            }
            received = socket.recv_from(&mut receive) => {
                let (length, source) = received?;
                let bytes = &receive[..length]; let now = started.elapsed();
                let mut discarded = source != peer;
                if !discarded {
                    match bytes.first() {
                        Some(32 | 40) => match control.receive(source, bytes, now) {
                            Ok(ReceiveOutcome::Fresh) => {
                                #[cfg(test)]
                                if let Some(close) = shared.modify(|s| Ok(s.close_started))? {
                                    eprintln!("CLOSE_ACTIVITY lane={} server={server} reason=fresh_control opcode={} packet={:?} driver_at={now:?} close_elapsed={:?} quiet_since={:?}", config.profile.lane.0, bytes[0], bytes.get(20..28).and_then(|b| <[u8;8]>::try_from(b).ok()).map(u64::from_be_bytes), close.elapsed(),quiet.since);
                                }
                                quiet.activity(); if let Some(gate) = &mut gate { gate.confirm_peer_control(now)?; } gate = None; }
                            Ok(ReceiveOutcome::Replay) => discarded = true,
                            Err(l2tunnel_udp_control::Error::Malformed | l2tunnel_udp_control::Error::Authentication) => discarded = true,
                            Err(l2tunnel_udp_control::Error::Recovery(RecoveryError::Capacity(BufferSide::Receive) | RecoveryError::SequenceWindow)) => discarded = true,
                            Err(error) => return Err(error.into()),
                        },
                        Some(0x48) => {
                            if let Some(data) = &mut data {
                                match data.protected.open(bytes) {
                                    Ok(payload) => {
                                        let source=match inspect_packet(payload, data.context, config.arq.max_source_bytes)? {
                                            PacketView::Data { source, .. } => { if !data.may_receive { return Err(Error::DirectionDisabled); } Some(source.0) },
                                            _=>None,
                                        };
                                        // Serialize the accepted-source boundary against an authenticated
                                        // native ceiling, including reordered sources. A future restoration
                                        // engine must use this same boundary before admitting restored IDs.
                                        let received=shared.modify(|s| {
                                            let next=source.map(|id| id.checked_add(1).ok_or(Error::Configuration("source ID exhausted"))).transpose()?;
                                            if let Some(next)=next && s.sources.ceiling.is_some_and(|(n,_)| next>n) { return Err(Error::Configuration("source beyond native ceiling")); }
                                            match data.recovery.receive(payload,now) {
                                                Ok(())=> { if let Some(next)=next { s.sources.accepted_prefix=s.sources.accepted_prefix.max(next); } Ok(Ok(())) },
                                                Err(error)=>Ok(Err(error)),
                                            }
                                        })?;
                                        match received {
                                            Ok(()) => {}
                                            Err(RecoveryError::Capacity(BufferSide::Receive) | RecoveryError::SequenceWindow) => discarded = true,
                                            Err(error) => return Err(error.into()),
                                        }
                                    }
                                    Err(l2tunnel_datagram::Error::KeyUsageExhausted) => return Err(Error::Datagram(l2tunnel_datagram::Error::KeyUsageExhausted)),
                                    Err(_) => discarded = true,
                                }
                            } else { discarded = true; }
                        }
                        _ => discarded = true, // Gate duplicates never allocate or renew a retained lease.
                    }
                }
                if discarded { shared.modify(|s| increment(&mut s.status.discarded_datagrams))?; }
            }
        }
        let now = started.elapsed();
        #[cfg(test)]
        {
            let sent = test_path.flush(&socket, peer, now)?;
            shared.modify(|s| {
                s.status.transmitted_datagrams = s
                    .status
                    .transmitted_datagrams
                    .checked_add(sent)
                    .ok_or(Error::Configuration("socket count"))?;
                Ok(())
            })?;
        }
        if now >= control.absolute_deadline() {
            return Err(Error::Timeout);
        }
        if from_start != from_end {
            from_start += control.write(&from_tls[from_start..from_end], now)?;
        }
        if to_start == to_end {
            to_start = 0;
            to_end = control.read(&mut to_tls, now)?;
        }
        if let Some(data) = &mut data {
            if let Some(pending) = &submission {
                if !data.may_send {
                    return Err(Error::DirectionDisabled);
                }
                let submitted = shared.modify(|s| {
                    if s.sources.sealed {
                        return Err(Error::Configuration("retained submission after seal"));
                    }
                    let count = s
                        .status
                        .admitted_packets
                        .checked_add(1)
                        .ok_or(Error::Configuration("source count exhausted"))?;
                    let bytes = s
                        .sources
                        .admitted_bytes
                        .checked_add(pending.bytes.len() as u64)
                        .ok_or(Error::Configuration("source bytes exhausted"))?;
                    match data.recovery.submit(&pending.bytes, now) {
                        Ok(id) => {
                            if id != s.status.admitted_packets {
                                return Err(Error::Configuration("source prefix mismatch"));
                            }
                            s.status.admitted_packets = count;
                            s.sources.admitted_bytes = bytes;
                            Ok(Ok(id))
                        }
                        Err(error) => Ok(Err(error)),
                    }
                })?;
                match submitted {
                    Ok(_) => {
                        let value = submission.take().ok_or(Error::Closed)?;
                        let _ = value.reply.send(Ok(()));
                    }
                    Err(
                        RecoveryError::Capacity(BufferSide::Send) | RecoveryError::SequenceWindow,
                    ) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            for _ in 0..config.work_limit {
                let Ok(slot) = shared.receive_slots.clone().try_acquire_owned() else {
                    break;
                };
                let permit = match output.try_reserve() {
                    Ok(permit) => permit,
                    Err(mpsc::error::TrySendError::Full(_)) => break,
                    Err(mpsc::error::TrySendError::Closed(_)) => return Err(Error::Closed),
                };
                let delivered = shared.modify(|s| {
                    let result = data.recovery.poll_delivered(&mut native)?;
                    if let Some((source, _)) = result
                        && s.sources.ceiling.is_some_and(|(n, _)| source >= n)
                    {
                        return Err(Error::Configuration(
                            "restored/delivered source beyond native ceiling",
                        ));
                    }
                    Ok(result)
                })?;
                let Some((_, length)) = delivered else {
                    break;
                };
                permit.send(Received {
                    bytes: native[..length].to_vec(),
                    _slot: slot,
                });
            }
        }
        budget.transaction(|budget| {
            // Each class owns a separate retained slot, but both debit the same ledger.
            if control_output.is_none() && budget.permits(true, config.bootstrap.path_mtu) {
                if let Some(client) = &mut gate
                    && let Some(bytes) = client.poll(now)?
                {
                    budget.charge(
                        true,
                        bytes.len() + config.bootstrap.outer_overhead,
                        Some(&shared),
                    )?;
                    control_output = Some(bytes.to_vec());
                }
                // A continuous data-ACK stream must not starve authenticated TLS liveness.
                for tls in [prefer_tls, !prefer_tls] {
                    if control_output.is_some() {
                        break;
                    }
                    if tls {
                        if let Some(length) = control.poll(now, &mut control_buffer)? {
                            budget.charge(
                                true,
                                length + config.bootstrap.outer_overhead,
                                Some(&shared),
                            )?;
                            control_output = Some(control_buffer[..length].to_vec());
                        }
                    } else if let Some(data) = &mut data {
                        data.protected.reserve_maximum_send()?;
                        if let Some(length) = data.recovery.poll_feedback(now, &mut data_buffer)? {
                            let packet =
                                data.protected.seal(&data_buffer[..length], &mut sealed)?;
                            budget.charge(
                                true,
                                packet.wire_len + config.bootstrap.outer_overhead,
                                Some(&shared),
                            )?;
                            control_output = Some(sealed[..packet.wire_len].to_vec());
                        }
                    }
                    if control_output.is_some() {
                        prefer_tls = !tls;
                    }
                }
            }
            if data_output.is_none()
                && budget.permits(false, config.bootstrap.path_mtu)
                && let Some(data) = &mut data
            {
                data.protected.reserve_maximum_send()?;
                if let Some(length) = data.recovery.poll_source(now, &mut data_buffer)? {
                    let packet = data.protected.seal(&data_buffer[..length], &mut sealed)?;
                    budget.charge(
                        false,
                        packet.wire_len + config.bootstrap.outer_overhead,
                        Some(&shared),
                    )?;
                    data_output = Some(sealed[..packet.wire_len].to_vec());
                }
            }
            Ok(())
        })?;
        for pending in [&mut control_output, &mut data_output] {
            if let Some(bytes) = pending {
                #[cfg(test)]
                let sent = test_path.send(
                    &socket,
                    bytes,
                    peer,
                    now,
                    shared.modify(|s| Ok(s.status.closing))?,
                );
                #[cfg(not(test))]
                let sent = socket.try_send_to(bytes, peer).and_then(|length| {
                    if length == bytes.len() {
                        Ok(1)
                    } else {
                        Err(io::Error::other("partial UDP write"))
                    }
                });
                match sent {
                    Ok(sent) => {
                        #[cfg(test)]
                        if let Some(close) = shared.modify(|s| Ok(s.close_started))? {
                            eprintln!(
                                "CLOSE_ACTIVITY lane={} server={server} reason=send opcode={:?} control_packet={:?} physical_count={sent} driver_at={now:?} close_elapsed={:?} quiet_since={:?}",
                                config.profile.lane.0,
                                bytes.first(),
                                bytes
                                    .get(20..28)
                                    .and_then(|b| <[u8; 8]>::try_from(b).ok())
                                    .map(u64::from_be_bytes),
                                close.elapsed(),
                                quiet.since
                            );
                        }
                        quiet.activity();
                        *pending = None;
                        shared.modify(|s| {
                            s.status.transmitted_datagrams = s
                                .status
                                .transmitted_datagrams
                                .checked_add(sent)
                                .ok_or(Error::Configuration("socket count"))?;
                            Ok(())
                        })?;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        let data_drained = data.as_ref().is_some_and(|data| data.recovery.drained())
            && submission.is_none()
            && input.is_empty()
            && shared.receive_slots.available_permits() == config.packet_slots
            && data_output.is_none();
        let (tls_finished, closing, close_started) = shared.modify(|s| {
            s.data_drained = data_drained;
            Ok((s.tls_finished, s.status.closing, s.close_started))
        })?;
        #[cfg(test)]
        test_path.observe_recovery_drain(
            data_drained
                && control.drained()
                && control_output.is_none()
                && data_output.is_none()
                && from_start == from_end
                && to_start == to_end
                && test_path.drained(),
        );
        if close_started.is_some_and(|at| at.elapsed() >= config.close_timeout) {
            #[cfg(test)]
            eprintln!(
                "CLOSE_DRIVER_TIMEOUT lane={} server={server} shared={:p} elapsed={:?} tls_finished={tls_finished} data_drained={data_drained} control_drained={} control={:?} data={:?} stream_closed={stream_closed} from=({from_start},{from_end}) to=({to_start},{to_end}) output=({},{}) quiet={:?}/{:?}",
                config.profile.lane.0,
                std::sync::Arc::as_ptr(&shared),
                close_started.map(|t| t.elapsed()),
                control.drained(),
                control.statistics(),
                data.as_ref().map(|d| d.recovery.retained()),
                control_output.is_some(),
                data_output.is_some(),
                quiet.since,
                quiet.interval
            );
            return Err(Error::IncompleteClose);
        }
        #[cfg(test)]
        let path_drained = test_path.drained();
        #[cfg(not(test))]
        let path_drained = true;
        let locally_drained = closing
            && tls_finished
            && data_drained
            && control.drained()
            && control_output.is_none()
            && from_start == from_end
            && to_start == to_end
            && stream_closed
            && path_drained;
        if quiet.poll(now, locally_drained) {
            shared.finish(Terminal::Clean);
            return Ok(());
        }
    }
}

// A fixed quiet interval keeps the same owner available for the peer's final
// source retries. It never changes the original absolute close deadline.
struct CloseQuiet {
    interval: std::time::Duration,
    since: Option<std::time::Duration>,
}
impl CloseQuiet {
    fn new(interval: std::time::Duration) -> Self {
        Self {
            interval,
            since: None,
        }
    }
    fn activity(&mut self) {
        self.since = None;
    }
    fn poll(&mut self, now: std::time::Duration, drained: bool) -> bool {
        if !drained {
            self.since = None;
            return false;
        }
        let since = *self.since.get_or_insert(now);
        now.checked_sub(since)
            .is_some_and(|age| age >= self.interval)
    }
}

#[cfg(test)]
mod close_tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn late_final_activity_cannot_fit_default_quiet_inside_original_five_seconds() {
        let interval = Duration::from_secs(3) + Duration::from_millis(5 + 2 * 2);
        let mut quiet = CloseQuiet::new(interval);
        assert!(!quiet.poll(Duration::ZERO, true));
        // A genuine late retry is serviceable but cannot renew the close owner.
        // Its required quiet endpoint is 5.209s, beyond the original 5s bound.
        quiet.activity();
        assert!(!quiet.poll(Duration::from_millis(2_200), true));
        assert!(!quiet.poll(Duration::from_secs(5), true));
        assert!(quiet.poll(Duration::from_millis(5_209), true));
    }
    #[test]
    fn repeated_final_retries_reset_quiet_but_never_the_absolute_close_bound() {
        let mut quiet = CloseQuiet::new(Duration::from_millis(50));
        let absolute = Duration::from_millis(120);
        assert!(!quiet.poll(Duration::ZERO, true));
        assert!(!quiet.poll(Duration::from_millis(49), true));
        quiet.activity();
        assert!(!quiet.poll(Duration::from_millis(49), true));
        assert!(!quiet.poll(Duration::from_millis(98), true));
        quiet.activity();
        assert!(!quiet.poll(Duration::from_millis(98), true));
        assert!(!quiet.poll(absolute, true)); // The driver reports IncompleteClose here.
        assert!(quiet.poll(Duration::from_millis(148), true));
        assert!(!quiet.poll(Duration::from_millis(149), false));
        assert!(!quiet.poll(Duration::from_millis(150), true));
    }
}
