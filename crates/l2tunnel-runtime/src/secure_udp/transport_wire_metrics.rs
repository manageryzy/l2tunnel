//! Opt-in bounded observations of accepted Common records, never admission credit.
use l2tunnel::record_engine::{CodecCoverage, EmissionKind, OutputExtent, SourceForm};
use std::{
    fs::OpenOptions,
    io::{self, BufWriter, Write},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::secure_udp::SendBoundary;

static NEXT_OBSERVER: AtomicU64 = AtomicU64::new(1);
const NAMES: [&str; 11] = [
    "algorithm_bytes",
    "final_record_bytes",
    "record_overhead_bytes",
    "route_header_bytes",
    "fragment_header_bytes",
    "recovery_header_bytes",
    "systematic_coded_fill_bytes",
    "codec_envelope_bytes",
    "codec_container_bytes",
    "codec_unit_header_bytes",
    "codec_body_bytes",
];
const METRICS: usize = NAMES.len();

#[derive(Clone, Copy)]
pub(in crate::secure_udp) struct Sample {
    pub(in crate::secure_udp) algorithm_bytes: usize,
    pub(in crate::secure_udp) kind: EmissionKind,
    pub(in crate::secure_udp) fragmented: bool,
    pub(in crate::secure_udp) extent: Option<OutputExtent>,
}

/// One explicitly requested diagnostic allocation, outside protocol retained-byte
/// admission. No packet bytes, keys, native payload or unbounded event list exists.
pub(in crate::secure_udp) struct Observer {
    path: PathBuf,
    bins: Vec<[u64; METRICS]>,
    classes: [u64; 6],
    boundaries: [u64; 3],
    fragments: u64,
    invalid: u64,
    overflow: u64,
    extent_errors: u64,
    coverage: [u64; 6],
}

impl Observer {
    #[cfg(test)]
    pub(in crate::secure_udp) fn for_test(path: PathBuf, maximum: usize) -> io::Result<Self> {
        Self::new(path, maximum)
    }

    #[cfg(test)]
    pub(in crate::secure_udp) fn accepted_record_totals_for_test(&self) -> (u128, u128) {
        let records = self.classes.iter().map(|count| u128::from(*count)).sum();
        let bytes = self
            .bins
            .iter()
            .enumerate()
            .map(|(size, bin)| (size as u128) * u128::from(bin[1]))
            .sum();
        (records, bytes)
    }

    pub(in crate::secure_udp) fn from_environment(maximum: usize) -> io::Result<Option<Self>> {
        let Some(prefix) = std::env::var_os("L2TUNNEL_WIRE_METRICS") else {
            return Ok(None);
        };
        if prefix.is_empty() || prefix.as_encoded_bytes().len() > 4096 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "wire metrics path length",
            ));
        }
        let id = NEXT_OBSERVER
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| io::Error::other("wire metrics owner exhausted"))?;
        let mut path = prefix;
        path.push(format!(".{}.{}.json", std::process::id(), id));
        Self::new(PathBuf::from(path), maximum).map(Some)
    }

    fn new(path: PathBuf, maximum: usize) -> io::Result<Self> {
        if maximum == 0 || maximum > 65_535 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "wire metrics packet ceiling",
            ));
        }
        let count = maximum + 1;
        let mut bins = Vec::new();
        bins.try_reserve_exact(count).map_err(io::Error::other)?;
        if bins.capacity() != count {
            return Err(io::Error::other("wire metrics histogram capacity differs"));
        }
        bins.resize(count, [0; METRICS]);
        Ok(Self {
            path,
            bins,
            classes: [0; 6],
            boundaries: [0; 3],
            fragments: 0,
            invalid: 0,
            overflow: 0,
            extent_errors: 0,
            coverage: [0; 6],
        })
    }

    pub(in crate::secure_udp) fn accepted(
        &mut self,
        sample: Sample,
        record_bytes: usize,
        boundary: SendBoundary,
    ) {
        let class = match sample.kind {
            EmissionKind::Source(SourceForm::Swift) => 0,
            EmissionKind::Source(SourceForm::DirectArq) => 1,
            EmissionKind::Source(SourceForm::SystematicFec) => 2,
            EmissionKind::Repair => 3,
            EmissionKind::Feedback => 4,
            EmissionKind::UnreliableNative => 5,
        };
        increment(&mut self.classes[class], &mut self.overflow);
        let boundary = match boundary {
            SendBoundary::SocketAccepted => 0,
            SendBoundary::TlsStreamFlushed => 1,
            SendBoundary::QuicDatagramAccepted => 2,
        };
        increment(&mut self.boundaries[boundary], &mut self.overflow);
        if sample.fragmented {
            increment(&mut self.fragments, &mut self.overflow);
        }
        let Some(overhead) = record_bytes.checked_sub(sample.algorithm_bytes) else {
            increment(&mut self.invalid, &mut self.overflow);
            return;
        };
        let lengths = [sample.algorithm_bytes, record_bytes, overhead];
        if lengths.iter().any(|length| *length >= self.bins.len()) {
            increment(&mut self.invalid, &mut self.overflow);
            return;
        }
        for (metric, length) in lengths.into_iter().enumerate() {
            increment(&mut self.bins[length][metric], &mut self.overflow);
        }
        let Some(extent) = sample
            .extent
            .filter(|extent| extent.bytes == sample.algorithm_bytes && extent.kind == sample.kind)
        else {
            increment(&mut self.extent_errors, &mut self.overflow);
            return;
        };
        let coverage = match extent.codec_coverage {
            CodecCoverage::EnvelopeOnly => 0,
            CodecCoverage::FragmentedUnits => 1,
            CodecCoverage::SwiftStream => 2,
            CodecCoverage::FragmentedRecord => 3,
            CodecCoverage::NotApplicable => 4,
            CodecCoverage::UnencodedNative => 5,
        };
        increment(&mut self.coverage[coverage], &mut self.overflow);
        let lengths = [
            Some(extent.route_header_bytes),
            Some(extent.fragment_header_bytes),
            extent.recovery.map(|value| value.header_bytes),
            extent
                .recovery
                .map(|value| value.systematic_coded_fill_bytes),
            extent.codec.map(|value| value.envelope_bytes),
            extent.codec.map(|value| value.container_bytes),
            extent.codec.map(|value| value.unit_header_bytes),
            extent.codec.map(|value| value.body_bytes),
        ];
        for (metric, length) in lengths.into_iter().enumerate() {
            if let Some(length) = length {
                if let Some(bin) = self.bins.get_mut(length) {
                    increment(&mut bin[metric + 3], &mut self.overflow);
                } else {
                    increment(&mut self.extent_errors, &mut self.overflow);
                }
            }
        }
    }

    fn quantile(&self, metric: usize, percentile: u128) -> Option<usize> {
        if self.overflow != 0 {
            return None;
        }
        let count: u128 = self.bins.iter().map(|bin| u128::from(bin[metric])).sum();
        if count == 0 {
            return None;
        }
        let rank = (count * percentile).div_ceil(100);
        let mut cumulative = 0u128;
        for (size, bin) in self.bins.iter().enumerate() {
            cumulative += u128::from(bin[metric]);
            if cumulative >= rank {
                return Some(size);
            }
        }
        None
    }

    fn write_report(&self, writer: &mut impl Write) -> io::Result<()> {
        writeln!(
            writer,
            "{{\"schema\":2,\"scope\":\"accepted Common user, repair and recovery-feedback records; excludes bootstrap, management and raw carrier control\","
        )?;
        writeln!(
            writer,
            "\"definition\":\"algorithm_bytes is the exact selected body, including any outer fragmentation header; final_record_bytes is the accepted inner Records length; record_overhead_bytes is their difference, never total network overhead; source includes retransmission and configured copies\","
        )?;
        writeln!(
            writer,
            "\"receipt_definition\":\"socket acceptance, TLS stream flush and Quinn DATAGRAM acceptance are distinct; none establishes peer delivery; late accepted facts remain counted\","
        )?;
        writeln!(
            writer,
            "\"quantile_definition\":\"nearest-rank by accepted Common record count; exact integer bytes; null for no samples or counter overflow; not IP-packet or total-encapsulation percentiles\","
        )?;
        writeln!(
            writer,
            "\"codec_framing_bytes\":null,\"padding_bytes\":null,\"retry_attribution\":null,\"native_compression_gain\":null,\"physical_carrier_overhead_quantiles\":null,"
        )?;
        writeln!(
            writer,
            "\"unsupported_definition\":\"null means unmeasured, not zero; no duplicate codec decoder, plaintext, encryption key or payload capture\","
        )?;
        writeln!(
            writer,
            "\"extent_definition\":\"exact canonical outgoing parser extents, counted only on actual acceptance; each histogram has its own sample population; absent repair/feedback codec and incomplete Swift stream or outer-fragment attribution are excluded, not zero-filled; codec body includes unmeasured compression/context/fragment fields; coded fill is distinct from repair redundancy and genuine zero payload\","
        )?;
        writeln!(
            writer,
            "\"extent_errors\":{},\"codec_coverage\":{{\"envelope_only\":{},\"fragmented_units\":{},\"swift_stream\":{},\"fragmented_record\":{},\"not_applicable\":{},\"unencoded_native\":{}}},",
            self.extent_errors,
            self.coverage[0],
            self.coverage[1],
            self.coverage[2],
            self.coverage[3],
            self.coverage[4],
            self.coverage[5]
        )?;
        writeln!(
            writer,
            "\"diagnostic_heap_bytes\":{},\"diagnostic_histogram_heap_bytes\":{},\"diagnostic_path_heap_bytes\":{},\"diagnostic_storage_definition\":\"explicit opt-in retained allocation outside protocol quota; excludes allocator overhead and transient report writer; no per-record allocation or I/O\",",
            self.bins.capacity() * std::mem::size_of::<[u64; METRICS]>() + self.path.capacity(),
            self.bins.capacity() * std::mem::size_of::<[u64; METRICS]>(),
            self.path.capacity()
        )?;
        writeln!(
            writer,
            "\"accepted_classes\":{{\"swift_source\":{},\"direct_arq_source\":{},\"systematic_fec_source\":{},\"repair\":{},\"recovery_feedback\":{},\"unreliable_native\":{}}},",
            self.classes[0],
            self.classes[1],
            self.classes[2],
            self.classes[3],
            self.classes[4],
            self.classes[5]
        )?;
        writeln!(
            writer,
            "\"accepted_boundaries\":{{\"socket_accepted\":{},\"tls_stream_flushed\":{},\"quic_datagram_accepted\":{}}},\"fragmented_records\":{},\"invalid_samples\":{},\"counter_overflow\":{},",
            self.boundaries[0],
            self.boundaries[1],
            self.boundaries[2],
            self.fragments,
            self.invalid,
            self.overflow
        )?;
        for (metric, name) in NAMES.into_iter().enumerate() {
            write!(writer, "\"{name}\":{{\"p50\":")?;
            write_optional(writer, self.quantile(metric, 50))?;
            write!(writer, ",\"p95\":")?;
            write_optional(writer, self.quantile(metric, 95))?;
            write!(writer, ",\"p99\":")?;
            write_optional(writer, self.quantile(metric, 99))?;
            let samples: u128 = self.bins.iter().map(|bin| u128::from(bin[metric])).sum();
            let bytes: u128 = self
                .bins
                .iter()
                .enumerate()
                .map(|(size, bin)| (size as u128) * u128::from(bin[metric]))
                .sum();
            write!(
                writer,
                ",\"samples\":{samples},\"total_bytes\":{bytes},\"histogram\":["
            )?;
            let mut first = true;
            for (size, bin) in self
                .bins
                .iter()
                .enumerate()
                .filter(|(_, bin)| bin[metric] != 0)
            {
                if !first {
                    write!(writer, ",")?;
                }
                first = false;
                write!(writer, "[{size},{}]", bin[metric])?;
            }
            writeln!(
                writer,
                "]}}{}",
                if metric + 1 == METRICS { "" } else { "," }
            )?;
        }
        writeln!(writer, "}}")
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

impl Drop for Observer {
    fn drop(&mut self) {
        if let Err(error) = self.persist() {
            let _ = writeln!(
                io::stderr().lock(),
                "Common wire metrics report failed: {error}"
            );
        }
    }
}

fn increment(value: &mut u64, overflow: &mut u64) {
    if let Some(next) = value.checked_add(1) {
        *value = next;
    } else {
        *overflow = overflow.saturating_add(1);
    }
}
fn write_optional(writer: &mut impl Write, value: Option<usize>) -> io::Result<()> {
    match value {
        Some(value) => write!(writer, "{value}"),
        None => write!(writer, "null"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepted_record_histograms_separate_lengths_overhead_and_receipt_boundaries()
    -> io::Result<()> {
        let path = std::env::temp_dir().join(format!(
            "l2tunnel-wire-metrics-test-{}.json",
            std::process::id()
        ));
        let mut observer = Observer::new(path.clone(), 256)?;
        let sample = Sample {
            algorithm_bytes: 100,
            kind: EmissionKind::Repair,
            fragmented: false,
            extent: None,
        };
        observer.accepted(sample, 121, SendBoundary::TlsStreamFlushed);
        observer.accepted(
            Sample {
                algorithm_bytes: 200,
                kind: EmissionKind::Feedback,
                fragmented: true,
                extent: None,
            },
            221,
            SendBoundary::QuicDatagramAccepted,
        );
        assert_eq!(observer.quantile(0, 50), Some(100));
        assert_eq!(observer.quantile(1, 99), Some(221));
        assert_eq!(observer.quantile(2, 99), Some(21));
        assert_eq!(observer.boundaries, [0, 1, 1]);
        assert_eq!(observer.classes, [0, 0, 0, 1, 1, 0]);
        observer.accepted(sample, 99, SendBoundary::SocketAccepted);
        assert_eq!(observer.invalid, 1);
        assert_eq!(observer.quantile(2, 99), Some(21));
        drop(observer);
        let report = std::fs::read_to_string(&path)?;
        assert!(report.contains("\"record_overhead_bytes\":{\"p50\":21"));
        assert!(report.contains("\"padding_bytes\":null"));
        std::fs::remove_file(path)
    }

    #[test]
    fn extent_populations_exclude_unknown_codec_and_count_real_fill_only() -> io::Result<()> {
        let path = std::env::temp_dir().join(format!(
            "l2tunnel-wire-extent-test-{}.json",
            std::process::id()
        ));
        let mut observer = Observer::new(path.clone(), 256)?;
        let source = EmissionKind::Source(SourceForm::Swift);
        let extent = OutputExtent {
            bytes: 100,
            kind: source,
            route_header_bytes: 0,
            fragment_header_bytes: 0,
            recovery: Some(l2tunnel::reliable::RecoveryExtent {
                kind: l2tunnel::reliable::RecordKind::Source,
                bytes: 100,
                header_bytes: 5,
                payload_bytes: 95,
                systematic_coded_fill_bytes: 0,
            }),
            codec: None,
            codec_coverage: CodecCoverage::SwiftStream,
        };
        let sample = Sample {
            algorithm_bytes: 100,
            kind: source,
            fragmented: false,
            extent: Some(extent),
        };
        observer.accepted(sample, 121, SendBoundary::SocketAccepted);
        assert_eq!(observer.quantile(5, 99), Some(5));
        assert_eq!(observer.quantile(6, 99), Some(0));
        assert_eq!(observer.quantile(7, 99), None);
        assert_eq!(observer.coverage, [0, 0, 1, 0, 0, 0]);
        assert_eq!(observer.extent_errors, 0);
        observer.accepted(
            Sample {
                extent: None,
                ..sample
            },
            121,
            SendBoundary::SocketAccepted,
        );
        assert_eq!(observer.extent_errors, 1);
        assert_eq!(observer.bins[5][5], 1);
        drop(observer);
        let report = std::fs::read_to_string(&path)?;
        assert!(report.contains("\"recovery_header_bytes\":{\"p50\":5"));
        assert!(report.contains("\"codec_envelope_bytes\":{\"p50\":null"));
        std::fs::remove_file(path)
    }
}
