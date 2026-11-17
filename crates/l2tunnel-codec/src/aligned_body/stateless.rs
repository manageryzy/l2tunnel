//! Stateless native compression in the existing body/fragment grammar.
use super::*;

/// Independent LZ4 body; tags 8/9 remain native-IP context/delta records.
pub const LZ4_TAG: u8 = 10;
/// Whether the maintained bounded LZ4 provider was enabled in this build.
pub const fn lz4_available() -> bool {
    cfg!(feature = "lz4")
}

impl Encoder {
    /// Encode one independent LZ4 body, falling back to raw unless total bytes shrink.
    /// Reuses the reserved scratch slab and preserves context and output on failure.
    pub fn encode_lz4(&mut self, frame: &[u8], output: &mut [u8]) -> Result<EncodedBodies, Error> {
        if !lz4_available() {
            return Err(Error::CompressionUnavailable);
        }
        if frame.is_empty() || frame.len() > self.config.max_frame_bytes {
            return Err(tcp_header::Error::FrameTooLarge.into());
        }
        #[cfg(feature = "lz4")]
        if frame.len() > 2 {
            // The provider requires its full worst-case destination capacity,
            // even when the actual block shrinks. That slab is reserved up front.
            // The extra original-length field costs two bytes over kind 2.
            let maximum = frame.len() - 2;
            if let Ok(encoded) = lz4_flex::block::compress_into(frame, &mut self.scratch[5..])
                && encoded < maximum
                && encoded + 5 <= usize::from(u16::MAX)
            {
                let total = encoded + 5;
                require_output(output, total)?;
                self.scratch[0] = LZ4_TAG;
                self.scratch[1..3].copy_from_slice(&(encoded as u16).to_be_bytes());
                self.scratch[3..5].copy_from_slice(&(frame.len() as u16).to_be_bytes());
                output[..total].copy_from_slice(&self.scratch[..total]);
                return Ok(EncodedBodies {
                    context_len: 0,
                    body_len: total,
                    kind: BodyKind::Lz4,
                });
            }
        }
        self.encode_raw(frame, output)
    }
}

impl Decoder {
    pub(super) fn decode_lz4(
        &mut self,
        input: &[u8],
        padding: Padding,
        output: &mut [u8],
    ) -> Result<Decoded, Error> {
        if !lz4_available() {
            return Err(Error::CompressionUnavailable);
        }
        if input.len() < 5 {
            return Err(Error::Compression);
        }
        let encoded = usize::from(word16(input, 1));
        let original = usize::from(word16(input, 3));
        let consumed = encoded + 5;
        if original == 0
            || original > self.config.max_frame_bytes
            || encoded == 0
            || encoded + 2 >= original
            || consumed > input.len()
        {
            return Err(Error::Compression);
        }
        match padding {
            Padding::Exact if consumed != input.len() => return Err(Error::Padding),
            Padding::ZeroExtended if input[consumed..].iter().any(|byte| *byte != 0) => {
                return Err(Error::Padding);
            }
            _ => {}
        }
        require_output(output, original)?;
        #[cfg(feature = "lz4")]
        {
            let written =
                lz4_flex::block::decompress_into(&input[5..consumed], &mut self.native[..original])
                    .map_err(|_| Error::Compression)?;
            if written != original {
                return Err(Error::Compression);
            }
            output[..written].copy_from_slice(&self.native[..written]);
            Ok(Decoded::Frame {
                consumed,
                written,
                kind: BodyKind::Lz4,
            })
        }
        #[cfg(not(feature = "lz4"))]
        Err(Error::CompressionUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
    fn config() -> Config {
        Config {
            max_frame_bytes: 2048,
            symbol_bytes: 1460,
            elide_payload_length: false,
            predictive: false,
            timestamp_pair_dictionary: false,
            independent_short_frame_bytes: 64,
        }
    }

    #[cfg(feature = "lz4")]
    #[test]
    fn native_lz4_uses_only_smaller_bodies_and_preserves_exact_meaningful_zero_tails() -> Result {
        let mut encoder = Encoder::new(config())?;
        let mut decoder = Decoder::new(config())?;
        for original in [
            vec![0; 1200],
            (0u8..=255).collect(),
            vec![1, 7, 0],
            vec![0; 64],
        ] {
            let mut encoded = [0xa5; 2100];
            let result = encoder.encode_lz4(&original, &mut encoded)?;
            assert_eq!(result.context_len, 0);
            assert_eq!(
                result.kind == BodyKind::Lz4,
                result.body_len < original.len() + 3
            );
            assert!(result.body_len <= original.len() + 3);
            assert!(encoded[result.body_len..].iter().all(|byte| *byte == 0xa5));
            if result.kind == BodyKind::Lz4 {
                assert_eq!(encoded[0], 10);
                assert_eq!(usize::from(word16(&encoded, 3)), original.len());
            } else {
                assert_eq!(encoded[0], 2);
            }
            let mut native = [0x5a; 2048];
            let decoded =
                decoder.decode_body(&encoded[..result.body_len], Padding::Exact, &mut native)?;
            assert_eq!(
                decoded,
                Decoded::Frame {
                    consumed: result.body_len,
                    written: original.len(),
                    kind: result.kind
                }
            );
            assert_eq!(&native[..original.len()], original);
            assert!(native[original.len()..].iter().all(|byte| *byte == 0x5a));
            assert!(!encoder.has_context() && !decoder.has_context());
        }
        Ok(())
    }

    #[cfg(feature = "lz4")]
    #[test]
    fn native_lz4_rejects_lengths_corruption_padding_and_output_shortage_atomically() -> Result {
        let mut encoder = Encoder::new(config())?;
        let mut decoder = Decoder::new(config())?;
        let mut encoded = [0; 2100];
        let length = encoder.encode_lz4(&[0; 1200], &mut encoded)?.body_len;
        assert_eq!(encoded[0], LZ4_TAG);
        let mut cases: Vec<Vec<u8>> = (0..length).map(|end| encoded[..end].to_vec()).collect();
        for original in [0u16, 1199, 1201, 2049, 65535] {
            let mut bad = encoded[..length].to_vec();
            bad[3..5].copy_from_slice(&original.to_be_bytes());
            cases.push(bad);
        }
        let mut corrupt = encoded[..length].to_vec();
        corrupt[5..].fill(0xff);
        cases.push(corrupt);
        let mut trailing = encoded[..length].to_vec();
        trailing.push(0);
        cases.push(trailing);
        for bad in cases {
            let mut output = [0xa5; 2048];
            assert!(
                decoder
                    .decode_body(&bad, Padding::Exact, &mut output)
                    .is_err()
            );
            assert!(output.iter().all(|byte| *byte == 0xa5));
            assert!(!decoder.has_context());
        }
        let mut short = [0x5a; 1199];
        assert_eq!(
            decoder.decode_body(&encoded[..length], Padding::Exact, &mut short),
            Err(Error::OutputTooSmall { needed: 1200 })
        );
        assert_eq!(short, [0x5a; 1199]);
        let mut padded = vec![0; config().symbol_bytes - 3];
        padded[..length].copy_from_slice(&encoded[..length]);
        let mut output = [0xa5; 2048];
        assert!(
            decoder
                .decode_body(&padded, Padding::ZeroExtended, &mut output)
                .is_ok()
        );
        padded[length] = 1;
        output.fill(0xa5);
        assert!(
            decoder
                .decode_body(&padded, Padding::ZeroExtended, &mut output)
                .is_err()
        );
        assert!(output.iter().all(|byte| *byte == 0xa5));
        let mut short_encoded = [0xa5; 2];
        assert!(encoder.encode_lz4(&[0; 1200], &mut short_encoded).is_err());
        assert_eq!(short_encoded, [0xa5; 2]);
        Ok(())
    }

    #[cfg(not(feature = "lz4"))]
    #[test]
    fn native_lz4_unavailable_is_explicit_before_output() -> Result {
        assert!(!lz4_available());
        let mut encoder = Encoder::new(config())?;
        let mut output = [0xa5; 32];
        assert_eq!(
            encoder.encode_lz4(&[0; 16], &mut output),
            Err(Error::CompressionUnavailable)
        );
        assert_eq!(output, [0xa5; 32]);
        Ok(())
    }
}
