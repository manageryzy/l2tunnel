//! Explicit, bounded scalar diagnostics; never protocol custody or retry policy.
use l2tunnel::{record_configuration::DirectionProfile, record_engine::Engine};
use l2tunnel_management::Role;
use l2tunnel_recovery::{CompactArqConfig, CompactPacketKind, CompactPacketView};
use std::{
    fs::OpenOptions,
    io::{self, BufWriter, Write},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

const MAX_EVENTS: usize = 512;
static NEXT_TRACE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
enum Selection {
    Compact,
    RollingGap,
}

impl Selection {
    fn limit(self) -> usize {
        match self {
            Self::Compact => MAX_EVENTS,
            Self::RollingGap => 65_536,
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::Compact => {
                "source0 and all feedback of unfragmented AlignedCompact/PackedCompact"
            }
            Self::RollingGap => "named feedback of unfragmented targeted Packed/Rolling",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::secure_udp) enum Packet {
    Gap {
        serial: u64,
        prefix: u32,
        start: u32,
        mask: u32,
    },
    Source {
        serial: u64,
    },
    Feedback {
        prefix: u64,
        start: u64,
        count: u16,
        echo: u64,
        receiver_delay_us: u64,
        serial: u64,
        acknowledges_zero: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::secure_udp) enum Outcome {
    Selected,
    CarrierAccepted,
    AuthenticatedInput,
    Applied,
    RetainedInputBlocked,
    Rejected(l2tunnel::record_bank::Error),
}

#[derive(Clone, Copy)]
struct Event {
    stage: &'static str,
    epoch: u64,
    number: u64,
    observed: u64,
    original: Option<u64>,
    packet: Packet,
    outcome: Outcome,
    boundary: Option<crate::secure_udp::SendBoundary>,
}

/// The optional allocation is diagnostic heap outside authenticated protocol
/// quota. It has no packet payload, clock, queue or completion authority.
pub(in crate::secure_udp) struct Observer {
    path: PathBuf,
    selection: Selection,
    events: Vec<Event>,
    dropped: u64,
    parse_errors: u64,
    acceptance_mismatches: u64,
    pending: Option<(u64, u64, Packet)>,
}

impl Observer {
    pub(in crate::secure_udp) fn from_environment() -> io::Result<Option<Self>> {
        let (mut prefix, selection) =
            if let Some(path) = std::env::var_os("L2TUNNEL_COMPACT_ARQ_TRACE") {
                (path, Selection::Compact)
            } else if let Some(path) = std::env::var_os("L2TUNNEL_ROLLING_GAP_TRACE") {
                (path, Selection::RollingGap)
            } else {
                return Ok(None);
            };
        if prefix.is_empty() || prefix.as_encoded_bytes().len() > 4096 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "recovery trace path",
            ));
        }
        let id = NEXT_TRACE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| io::Error::other("Compact ARQ trace owner exhausted"))?;
        prefix.push(format!(".{}.{}.json", std::process::id(), id));
        Self::new(PathBuf::from(prefix), selection).map(Some)
    }

    fn new(path: PathBuf, selection: Selection) -> io::Result<Self> {
        let mut events = Vec::new();
        events
            .try_reserve_exact(selection.limit())
            .map_err(io::Error::other)?;
        Ok(Self {
            path,
            selection,
            events,
            dropped: 0,
            parse_errors: 0,
            acceptance_mismatches: 0,
            pending: None,
        })
    }

    /// Decode diagnostic fields with the negotiated family's own parser.
    pub(in crate::secure_udp) fn inspect(
        &mut self,
        engine: &Engine,
        role: Role,
        outgoing: bool,
        bytes: &[u8],
    ) -> Option<Packet> {
        let kind = bytes.first().copied()?;
        if let Selection::RollingGap = self.selection {
            if kind != 5 {
                return None;
            }
            return match engine.inspect_rolling_gap(outgoing, bytes) {
                Ok(request) => request.map(|r| Packet::Gap {
                    serial: r.id.0,
                    prefix: r.prefix,
                    start: r.start,
                    mask: r.mask,
                }),
                Err(_) => {
                    self.parse_errors = self.parse_errors.saturating_add(1);
                    None
                }
            };
        }
        let local = engine.configuration().descriptor().local(role);
        let direction = if (kind == 1) == outgoing {
            local.send()
        } else {
            local.receive()
        };
        let policy = match direction.profile() {
            DirectionProfile::AlignedCompact(config) => config.recovery.arq(),
            DirectionProfile::PackedCompact(config) => config.base.recovery.arq(),
            _ => return None,
        };
        match inspect(policy, bytes) {
            Ok(packet) => packet,
            Err(_) => {
                self.parse_errors = self.parse_errors.saturating_add(1);
                None
            }
        }
    }

    pub(in crate::secure_udp) fn selected(
        &mut self,
        epoch: u64,
        number: u64,
        now: u64,
        packet: Option<Packet>,
    ) {
        self.pending = packet.map(|packet| (epoch, number, packet));
        if let Some(packet) = packet {
            self.input(
                "selected",
                epoch,
                number,
                now,
                None,
                packet,
                Outcome::Selected,
            );
        }
    }

    pub(in crate::secure_udp) fn accepted(
        &mut self,
        epoch: u64,
        number: u64,
        observed: u64,
        accepted: Option<u64>,
        boundary: crate::secure_udp::SendBoundary,
    ) {
        let Some((expected_epoch, expected_number, packet)) = self.pending.take() else {
            return;
        };
        if (expected_epoch, expected_number) != (epoch, number) {
            self.acceptance_mismatches = self.acceptance_mismatches.saturating_add(1);
            return;
        }
        self.push(Event {
            stage: "accepted",
            epoch,
            number,
            observed,
            original: accepted,
            packet,
            outcome: Outcome::CarrierAccepted,
            boundary: Some(boundary),
        });
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::secure_udp) fn input(
        &mut self,
        stage: &'static str,
        epoch: u64,
        number: u64,
        observed: u64,
        received: Option<u64>,
        packet: Packet,
        outcome: Outcome,
    ) {
        self.push(Event {
            stage,
            epoch,
            number,
            observed,
            original: received,
            packet,
            outcome,
            boundary: None,
        });
    }

    fn push(&mut self, event: Event) {
        if self.events.len() == self.selection.limit() {
            self.dropped = self.dropped.saturating_add(1);
        } else {
            self.events.push(event);
        }
    }

    fn write_report(&self, writer: &mut impl Write) -> io::Result<()> {
        write!(
            writer,
            "{{\"schema\":1,\"scope\":\"{}\",\"time_unit\":\"runtime-relative microseconds\",\"original_time_definition\":\"accepted stage uses carrier acceptance; input/apply/retry use original authenticated arrival\",\"acceptance_definition\":\"local carrier boundary only; never peer delivery\",\"storage_definition\":\"opt-in diagnostic allocation outside protocol quota; no packet payload or per-event IO\",\"max_events\":{},\"diagnostic_heap_bytes\":{},\"dropped_events\":{},\"parse_errors\":{},\"acceptance_mismatches\":{},\"pending_selection\":{},\"events\":[",
            self.selection.description(),
            self.selection.limit(),
            self.events.capacity() * std::mem::size_of::<Event>() + self.path.as_os_str().len(),
            self.dropped,
            self.parse_errors,
            self.acceptance_mismatches,
            self.pending.is_some()
        )?;
        for (index, event) in self.events.iter().enumerate() {
            if index != 0 {
                write!(writer, ",")?;
            }
            write!(
                writer,
                "{{\"stage\":\"{}\",\"epoch\":{},\"packet_number\":{},\"observed_us\":{},\"original_us\":",
                event.stage, event.epoch, event.number, event.observed
            )?;
            match event.original {
                Some(value) => write!(writer, "{value}")?,
                None => write!(writer, "null")?,
            }
            write!(writer, ",\"outcome\":")?;
            json_string(writer, &format!("{:?}", event.outcome))?;
            write!(writer, ",\"boundary\":")?;
            match event.boundary {
                Some(value) => write!(writer, "\"{value:?}\"")?,
                None => write!(writer, "null")?,
            }
            match event.packet {
                Packet::Gap {
                    serial,
                    prefix,
                    start,
                    mask,
                } => write!(
                    writer,
                    ",\"kind\":\"gap\",\"feedback_serial\":{serial},\"prefix\":{prefix},\"start\":{start},\"mask\":{mask}}}"
                )?,
                Packet::Source { serial } => write!(
                    writer,
                    ",\"kind\":\"source\",\"source\":0,\"attempt_serial\":{serial}}}"
                )?,
                Packet::Feedback {
                    prefix,
                    start,
                    count,
                    echo,
                    receiver_delay_us,
                    serial,
                    acknowledges_zero,
                } => write!(
                    writer,
                    ",\"kind\":\"feedback\",\"prefix\":{prefix},\"start\":{start},\"count\":{count},\"echo\":{echo},\"receiver_delay_us\":{receiver_delay_us},\"feedback_serial\":{serial},\"acknowledges_source0\":{acknowledges_zero}}}"
                )?,
            }
        }
        writeln!(writer, "]}}")
    }

    fn persist(&self) -> io::Result<()> {
        let mut temporary = self.path.as_os_str().to_owned();
        temporary.push(".tmp");
        let temporary = PathBuf::from(temporary);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        let result = (|| {
            let mut writer = BufWriter::new(file);
            self.write_report(&mut writer)?;
            writer.flush()?;
            writer.get_ref().sync_all()?;
            std::fs::rename(&temporary, &self.path)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }
}

fn json_string(writer: &mut impl Write, value: &str) -> io::Result<()> {
    write!(writer, "\"")?;
    for character in value.chars() {
        match character {
            '"' => write!(writer, "\\\"")?,
            '\\' => write!(writer, "\\\\")?,
            character if character.is_control() => {
                write!(writer, "\\u{:04x}", u32::from(character))?
            }
            character => write!(writer, "{character}")?,
        }
    }
    write!(writer, "\"")
}

impl Drop for Observer {
    fn drop(&mut self) {
        if let Err(error) = self.persist() {
            let _ = writeln!(
                io::stderr().lock(),
                "Common Compact ARQ trace report failed: {error}"
            );
        }
    }
}

fn inspect(
    policy: CompactArqConfig,
    bytes: &[u8],
) -> Result<Option<Packet>, l2tunnel_recovery::RecoveryError> {
    let Some((&kind, body)) = bytes.split_first() else {
        return Err(l2tunnel_recovery::RecoveryError::MalformedPacket);
    };
    let kind = match kind {
        1 => CompactPacketKind::Data,
        2 => CompactPacketKind::Feedback,
        _ => return Err(l2tunnel_recovery::RecoveryError::MalformedPacket),
    };
    Ok(
        match l2tunnel_recovery::inspect_compact_body(kind, body, policy)? {
            CompactPacketView::Data { source, serial, .. } => {
                (source.0 == 0).then_some(Packet::Source { serial })
            }
            CompactPacketView::Feedback(feedback) => Some(Packet::Feedback {
                prefix: feedback.prefix,
                start: feedback.start,
                count: feedback.count,
                echo: feedback.echo,
                receiver_delay_us: feedback.receiver_delay_us,
                serial: feedback.serial,
                acknowledges_zero: feedback.prefix > 0
                    || (feedback.start == 0
                        && feedback.count != 0
                        && feedback.bitmap.first().is_some_and(|byte| byte & 1 != 0)),
            }),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use l2tunnel_recovery::{
        CompactBounds, CompactFeedback, CompactRecovery, CompactTiming, SourceId,
    };
    use std::time::Duration;
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

    fn policy() -> Result<CompactArqConfig> {
        Ok(CompactArqConfig::new(
            CompactBounds {
                max_source_bytes: 128,
                send_bytes: 512,
                receive_bytes: 512,
                send_records: 4,
                receive_records: 4,
            },
            CompactTiming {
                nominal_rtt: Duration::from_millis(70),
                feedback_interval: Duration::from_millis(1),
                feedback_packets: 16,
            },
            77,
            16,
            9,
            CompactRecovery::Guarded,
        )?)
    }

    #[test]
    fn compact_arq_trace_uses_canonical_parser_and_retains_only_source_zero_scalars() -> Result {
        let policy = policy()?;
        let mut body = [0; 256];
        body[0] = 1;
        let n = CompactPacketView::Data {
            source: SourceId(0),
            serial: 129,
            payload: b"private payload never retained",
        }
        .encode_compact_into(&mut body[1..])?
            + 1;
        assert_eq!(
            inspect(policy, &body[..n])?,
            Some(Packet::Source { serial: 129 })
        );
        body[1] = 1;
        assert_eq!(inspect(policy, &body[..n])?, None);
        body[0] = 2;
        for (prefix, start, count, bitmap, acknowledges_zero) in [
            (0, 0, 1, &[0][..], false),
            (0, 1, 1, &[1][..], false),
            (1, 1, 0, &[][..], true),
            (1, 2, 1, &[1][..], true),
        ] {
            let n = CompactPacketView::Feedback(CompactFeedback {
                prefix,
                start,
                count,
                echo: 129,
                receiver_delay_us: 1000,
                serial: 4,
                bitmap,
            })
            .encode_compact_into(&mut body[1..])?
                + 1;
            assert_eq!(
                inspect(policy, &body[..n])?,
                Some(Packet::Feedback {
                    prefix,
                    start,
                    count,
                    echo: 129,
                    receiver_delay_us: 1000,
                    serial: 4,
                    acknowledges_zero,
                })
            );
            assert!(inspect(policy, &body[..n - 1]).is_err());
            if prefix == 0 && start == 0 {
                // A positive first bit must already have advanced the prefix.
                // Mutating a valid packet exercises the canonical decoder's
                // refusal rather than asking its encoder to emit invalid bytes.
                body[n - 1] = 1;
                assert!(matches!(
                    inspect(policy, &body[..n]),
                    Err(l2tunnel_recovery::RecoveryError::MalformedPacket)
                ));
            }
        }
        assert!(inspect(policy, &[]).is_err());
        assert!(inspect(policy, &[3]).is_err());
        Ok(())
    }

    #[test]
    fn rolling_gap_trace_retains_feedback_identity_across_physical_acceptance() -> Result {
        let id = NEXT_TRACE.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("l2t-rolling-gap-{}-{id}.json", std::process::id()));
        let mut trace = Observer::new(path.clone(), Selection::RollingGap)?;
        let gap = Packet::Gap {
            serial: 19,
            prefix: 41,
            start: 51,
            mask: 9,
        };
        trace.selected(2, 113, 501, Some(gap));
        trace.accepted(
            2,
            113,
            534,
            Some(530),
            crate::secure_udp::SendBoundary::SocketAccepted,
        );
        let mut bytes = Vec::new();
        trace.write_report(&mut bytes)?;
        let report = String::from_utf8(bytes)?;
        assert!(report.contains("\"max_events\":65536"));
        assert!(report.contains("\"acceptance_mismatches\":0"));
        assert!(report.contains("\"observed_us\":534,\"original_us\":530"));
        let fields =
            "\"kind\":\"gap\",\"feedback_serial\":19,\"prefix\":41,\"start\":51,\"mask\":9";
        assert_eq!(report.matches(fields).count(), 2);
        drop(trace);
        std::fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn compact_arq_trace_bounds_events_and_separates_selection_from_acceptance() -> Result {
        let id = NEXT_TRACE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "l2t-compact-arq-trace-{}-{id}.json",
            std::process::id()
        ));
        let mut observer = Observer::new(path.clone(), Selection::Compact)?;
        let packet = Packet::Source { serial: 2 };
        observer.selected(7, 4, 100, Some(packet));
        assert_eq!(observer.events.len(), 1);
        assert!(observer.events[0].boundary.is_none());
        observer.accepted(
            7,
            4,
            150,
            Some(120),
            crate::secure_udp::SendBoundary::TlsStreamFlushed,
        );
        assert_eq!(observer.events[1].original, Some(120));
        assert_eq!(observer.events[1].observed, 150);
        assert!(observer.pending.is_none());
        // A repeated completion without a retained selected identity adds no fact.
        observer.accepted(
            7,
            4,
            200,
            Some(120),
            crate::secure_udp::SendBoundary::TlsStreamFlushed,
        );
        assert_eq!(observer.events.len(), 2);
        for number in 0..=MAX_EVENTS as u64 {
            observer.input(
                "retry",
                7,
                number,
                210,
                Some(160),
                packet,
                Outcome::Rejected(l2tunnel::record_bank::Error::Engine(
                    l2tunnel::record_engine::Error::Aligned(l2tunnel_aligned::Error::Recovery(
                        l2tunnel_reliable::Error::Arq(
                            l2tunnel_recovery::RecoveryError::FeedbackAwaitingPhysical,
                        ),
                    )),
                )),
            );
        }
        assert_eq!(observer.events.len(), MAX_EVENTS);
        assert_eq!(observer.dropped, 3);
        drop(observer);
        let report = std::fs::read_to_string(&path)?;
        std::fs::remove_file(path)?;
        assert!(report.contains("\"dropped_events\":3"));
        assert!(report.contains("FeedbackAwaitingPhysical"));
        assert!(report.contains("\"stage\":\"selected\""));
        assert!(report.contains("\"boundary\":\"TlsStreamFlushed\""));
        assert!(!report.contains("private payload never retained"));
        Ok(())
    }
}
