//! Once-per-admission codec facts; emitted retries never enter these totals.
use l2tunnel::record_engine::{NativeEncodingKind, NativeEncodingObservation};
use std::io::{self, Write};

const KINDS: [&str; 11] = [
    "aligned_timestamp",
    "aligned_raw",
    "aligned_lz4",
    "aligned_delta",
    "aligned_elided",
    "aligned_predictive",
    "aligned_timestamp_pair",
    "swift_literal",
    "swift_literal_context",
    "swift_delta",
    "unencoded",
];

#[derive(Clone, Copy, Default)]
struct Totals {
    packets: u64,
    original: u64,
    context: u64,
    body: u64,
    framing: u64,
}

#[derive(Default)]
pub(super) struct Native {
    inputs: [[Totals; KINDS.len()]; 2],
    overflow: u64,
}

impl Native {
    pub(super) fn admitted(&mut self, value: NativeEncodingObservation, proxy: bool) {
        use l2tunnel::{codec::aligned_body::BodyKind as A, swift::header::EncodingKind as S};
        let kind = match value.kind {
            NativeEncodingKind::Aligned(A::Timestamp) => 0,
            NativeEncodingKind::Aligned(A::Raw) => 1,
            NativeEncodingKind::Aligned(A::Lz4) => 2,
            NativeEncodingKind::Aligned(A::Delta) => 3,
            NativeEncodingKind::Aligned(A::Elided) => 4,
            NativeEncodingKind::Aligned(A::Predictive) => 5,
            NativeEncodingKind::Aligned(A::TimestampPair) => 6,
            NativeEncodingKind::Swift(S::Literal) => 7,
            NativeEncodingKind::Swift(S::LiteralContext) => 8,
            NativeEncodingKind::Swift(S::Delta) => 9,
            NativeEncodingKind::Unencoded => 10,
        };
        let old = self.inputs[usize::from(proxy)][kind];
        let next = (|| {
            Some(Totals {
                packets: old.packets.checked_add(1)?,
                original: old
                    .original
                    .checked_add(u64::try_from(value.original_native_bytes).ok()?)?,
                context: old
                    .context
                    .checked_add(u64::try_from(value.context_bytes).ok()?)?,
                body: old
                    .body
                    .checked_add(u64::try_from(value.encoded_body_bytes).ok()?)?,
                framing: old
                    .framing
                    .checked_add(u64::try_from(value.framing_bytes).ok()?)?,
            })
        })();
        if let Some(next) = next {
            self.inputs[usize::from(proxy)][kind] = next;
        } else {
            self.overflow = self.overflow.saturating_add(1);
        }
    }

    pub(super) fn write_report(&self, writer: &mut impl Write) -> io::Result<()> {
        write!(
            writer,
            "\"native_encoding\":{{\"counter_overflow\":{},\"definition\":\"one successful codec admission per original input, including context and generated unit/fragment or Swift stream framing; excludes packing containers, recovery, Records, carrier and retransmissions. Native packets and proxy records have separate populations. Signed gains retain literal/context expansion; LZ4 gain is whole-input compression, not header compression. These totals do not establish per-emission or physical overhead percentiles\"",
            self.overflow
        )?;
        for (input, totals) in ["native_packet", "proxy_record"]
            .into_iter()
            .zip(&self.inputs)
        {
            write!(writer, ",\"{input}\":{{")?;
            for (index, (name, value)) in KINDS.into_iter().zip(totals).enumerate() {
                let codec_gain =
                    i128::from(value.original) - i128::from(value.context) - i128::from(value.body);
                let gain = codec_gain - i128::from(value.framing);
                write!(
                    writer,
                    "{}\"{name}\":{{\"inputs\":{},\"original_bytes\":{},\"context_bytes\":{},\"encoded_body_bytes\":{},\"framing_bytes\":{},\"codec_net_gain_bytes\":{},\"net_gain_bytes\":{}}}",
                    if index == 0 { "" } else { "," },
                    value.packets,
                    value.original,
                    value.context,
                    value.body,
                    value.framing,
                    codec_gain,
                    gain
                )?;
            }
            write!(writer, "}}")?;
        }
        writeln!(writer, "}},")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_expansion_and_proxy_inputs_keep_separate_signed_totals() -> io::Result<()> {
        let mut counts = Native::default();
        let literal = NativeEncodingObservation {
            original_native_bytes: 100,
            context_bytes: 0,
            encoded_body_bytes: 101,
            framing_bytes: 2,
            kind: NativeEncodingKind::Swift(l2tunnel::swift::header::EncodingKind::Literal),
        };
        counts.admitted(literal, false);
        counts.admitted(literal, true);
        assert_eq!(counts.inputs[0][7].packets, 1);
        assert_eq!(counts.inputs[1][7].packets, 1);
        let mut report = Vec::new();
        counts.write_report(&mut report)?;
        let report = String::from_utf8(report).map_err(io::Error::other)?;
        assert_eq!(
            report
                .matches("\"codec_net_gain_bytes\":-1,\"net_gain_bytes\":-3")
                .count(),
            2
        );
        counts.inputs[0][7].original = u64::MAX;
        counts.admitted(literal, false);
        assert_eq!(counts.overflow, 1);
        assert_eq!(counts.inputs[0][7].packets, 1);
        Ok(())
    }
}
