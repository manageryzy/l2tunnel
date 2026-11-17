//! Return-only facts from the actual successful native admission.
use super::ProfileIdentity;

/// Actual successful encoding, without attributing recovery or carrier bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeEncodingKind {
    /// Aligned body grammar, including actual LZ4-or-raw selection.
    Aligned(l2tunnel_codec::aligned_body::BodyKind),
    /// Swift literal/context/delta record before its stream prefix.
    Swift(l2tunnel_swift::header::EncodingKind),
    /// Explicit source-free native bypass; no codec or stream framing exists.
    Unencoded,
}

/// One admitted native input, counted once rather than once per emitted copy.
/// Body bytes include their own codec syntax. Framing is the complete frame's
/// generated unit/fragment headers, or Swift's two-byte stream prefix. Packing
/// containers, recovery, Records, carrier bytes and physical delivery are absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeEncodingObservation {
    /// Exact original input length; proxy-profile inputs remain proxy records.
    pub original_native_bytes: usize,
    /// Separate context body bytes caused by this input.
    pub context_bytes: usize,
    /// Actual encoded native body, including its internal tag/length syntax.
    pub encoded_body_bytes: usize,
    /// Complete generated unit/fragment or stream framing for this input.
    pub framing_bytes: usize,
    /// Actual encoder result, not the requested policy label.
    pub kind: NativeEncodingKind,
}
impl NativeEncodingObservation {
    /// Signed gain before unit/fragment or stream framing; expansion is negative.
    pub fn codec_net_gain_bytes(self) -> i128 {
        self.original_native_bytes as i128
            - self.context_bytes as i128
            - self.encoded_body_bytes as i128
    }
    /// Signed gain including the observed framing, before packing and recovery.
    pub fn net_gain_bytes(self) -> i128 {
        self.codec_net_gain_bytes() - self.framing_bytes as i128
    }
    pub(super) fn unencoded(bytes: usize) -> Self {
        Self {
            original_native_bytes: bytes,
            context_bytes: 0,
            encoded_body_bytes: bytes,
            framing_bytes: 0,
            kind: NativeEncodingKind::Unencoded,
        }
    }
}
impl From<l2tunnel_codec::aligned_body::NativeEncodingObservation> for NativeEncodingObservation {
    fn from(value: l2tunnel_codec::aligned_body::NativeEncodingObservation) -> Self {
        Self {
            original_native_bytes: value.original_native_bytes,
            context_bytes: value.context_bytes,
            encoded_body_bytes: value.encoded_body_bytes,
            framing_bytes: value.framing_bytes,
            kind: NativeEncodingKind::Aligned(value.kind),
        }
    }
}
impl From<l2tunnel_swift::records::NativeEncodingObservation> for NativeEncodingObservation {
    fn from(value: l2tunnel_swift::records::NativeEncodingObservation) -> Self {
        Self {
            original_native_bytes: value.original_native_bytes,
            context_bytes: value.context_bytes,
            encoded_body_bytes: value.encoded_body_bytes,
            framing_bytes: value.framing_bytes,
            kind: NativeEncodingKind::Swift(value.kind),
        }
    }
}

/// Exact successful identity and its return-only encoding observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedProfileIdentity {
    /// Unchanged admission identity, without physical send/delivery authority.
    pub identity: ProfileIdentity,
    /// Facts from the successful encoder, never reconstructed from a retry.
    pub encoding: NativeEncodingObservation,
}
