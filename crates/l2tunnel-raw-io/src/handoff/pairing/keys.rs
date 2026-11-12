use super::*;
use zeroize::Zeroizing;
pub(super) type Roots = [l2tunnel_auth::Secret; 6];
pub(super) struct Keys {
    // Kept private for the later reviewed manager; no packet/freeze capability.
    pub(super) _values: Zeroizing<Box<[[u8; 32]]>>,
}
impl Keys {
    pub(super) fn derive(
        roots: &[Option<Roots>; 2],
        count: usize,
        digest: [u8; 32],
    ) -> Result<Self, PairError> {
        if !(1..=2).contains(&count) {
            return Err(PairError::Keys);
        }
        // Exactly six or twelve keys, matching the authenticated payload charge.
        let mut values = Zeroizing::new(vec![[0u8; 32]; count * 6].into_boxed_slice());
        for purpose in 0..3 {
            for direction in 0..2 {
                let index = purpose * 2 + direction;
                let mut material = Zeroizing::new([0u8; 64]);
                for (lane, root) in roots.iter().enumerate().take(count) {
                    material[lane * 32..lane * 32 + 32].copy_from_slice(
                        root.as_ref().ok_or(PairError::Keys)?[index].expose_bytes(),
                    );
                }
                let salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &digest);
                let key = salt.extract(&material[..count * 32]);
                for lane in 0..count {
                    let version = 1u16.to_be_bytes();
                    let labels = [purpose as u8 + 1, direction as u8 + 1];
                    let lane_bytes = (lane as u32).to_be_bytes();
                    let info: [&[u8]; 5] = [
                        b"l2tunnel/raw-owned-pair-key/v1\0",
                        &version,
                        &labels,
                        &lane_bytes,
                        &digest,
                    ];
                    key.expand(&info, ring::hkdf::HKDF_SHA256)
                        .map_err(|_| PairError::Keys)?
                        .fill(&mut values[lane * 6 + index])
                        .map_err(|_| PairError::Keys)?;
                }
            }
        }
        Ok(Self { _values: values })
    }
}
