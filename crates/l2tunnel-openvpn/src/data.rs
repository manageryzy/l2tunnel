//! Private authenticated USER-datagram boundary, independent of recovery framing.
//!
//! Only the verified factory creates this owner. Bootstrap/TLS reliability stays
//! in the socket driver's control engine; the current USER selective-repeat
//! adapter consumes plaintext returned here, outside this module.

use l2tunnel_datagram::{DatagramConfig, Error, PacketOpener, PacketSealer, SealedPacket};

pub(crate) struct ProtectedDatagrams {
    sealer: PacketSealer,
    opener: PacketOpener,
    send_config: DatagramConfig,
    received: Vec<u8>,
}
impl ProtectedDatagrams {
    // Caller must derive these keys from the actual authenticated connection and
    // bind both configs before activation. This private constructor grants no
    // authority from an asserted session ID or caller-provided exporter.
    pub(crate) fn new(
        send_config: DatagramConfig,
        outbound: &[u8; 32],
        receive_config: DatagramConfig,
        inbound: &[u8; 32],
    ) -> Result<Self, Error> {
        let sealer = PacketSealer::new(send_config, outbound)?;
        let opener = PacketOpener::new(receive_config, inbound)?;
        Ok(Self {
            sealer,
            opener,
            send_config,
            received: vec![0; receive_config.max_payload_bytes],
        })
    }

    /// Authenticate/replay-check one datagram before exposing its exact payload.
    /// No USER recovery header, source ID, ACK or ordering policy is interpreted.
    pub(crate) fn open(&mut self, wire: &[u8]) -> Result<&[u8], Error> {
        let packet = self.opener.open(wire, &mut self.received)?;
        Ok(&self.received[..packet.payload_len])
    }

    /// Keep the existing conservative maximum-payload key reservation before a
    /// recovery poll can consume an attempt. This does not allocate a nonce.
    pub(crate) fn reserve_maximum_send(&self) -> Result<(), Error> {
        let usage = self.sealer.usage();
        if usage.packets >= self.send_config.max_packets_per_key
            || usage
                .payload_bytes
                .checked_add(self.send_config.max_payload_bytes as u64)
                .is_none_or(|bytes| bytes > self.send_config.max_payload_bytes_per_key)
        {
            return Err(Error::KeyUsageExhausted);
        }
        Ok(())
    }

    /// Seal one opaque USER payload into the driver's retained output slot.
    /// The driver remains responsible for the shared exact wire ledger and I/O.
    pub(crate) fn seal(
        &mut self,
        payload: &[u8],
        output: &mut [u8],
    ) -> Result<SealedPacket, Error> {
        self.sealer.seal_into(payload, output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use l2tunnel_datagram::{
        CoverProfile, Direction, KeyContext, KeyGeneration, LaneId, Protection, SessionId,
    };

    fn config(direction: Direction, protection: Protection) -> DatagramConfig {
        DatagramConfig {
            context: KeyContext {
                session: SessionId([0x73; 16]),
                direction,
                lane: LaneId(7),
                generation: KeyGeneration(1),
            },
            cover: CoverProfile::OpenVpnLike,
            protection,
            path_mtu: 1280,
            outer_overhead_bytes: 28,
            max_payload_bytes: 256,
            max_packets_per_key: 8,
            max_payload_bytes_per_key: 2048,
        }
    }
    fn pair(protection: Protection) -> Result<(ProtectedDatagrams, ProtectedDatagrams), Error> {
        let forward = config(Direction::ClientToServer, protection);
        let reverse = config(Direction::ServerToClient, protection);
        Ok((
            ProtectedDatagrams::new(forward, &[0x21; 32], reverse, &[0x42; 32])?,
            ProtectedDatagrams::new(reverse, &[0x42; 32], forward, &[0x21; 32])?,
        ))
    }
    fn seal(owner: &mut ProtectedDatagrams, payload: &[u8]) -> Result<Vec<u8>, Error> {
        owner.reserve_maximum_send()?;
        let mut wire = vec![0; 1280];
        let length = owner.seal(payload, &mut wire)?.wire_len;
        wire.truncate(length);
        Ok(wire)
    }

    #[test]
    fn arbitrary_non_arq_payloads_remain_loss_visible_and_reordered() -> Result<(), Error> {
        for protection in [Protection::ChaCha20Poly1305, Protection::HmacSha256] {
            let (mut a, mut b) = pair(protection)?;
            // Deliberately not a recovery source or feedback frame. Missing wire
            // packet 1 cannot prevent later packet 2 or 0 from being exposed.
            let payloads: [&[u8]; 3] = [b"\0\xffraw\0", b"lost", b"rolling-or-packed\0\0"];
            let recovery_context = l2tunnel_recovery::RecoveryContext {
                session: u128::from_be_bytes([0x73; 16]),
                epoch: 1,
                role: l2tunnel_recovery::EndpointRole::Responder,
            };
            for payload in payloads {
                assert!(l2tunnel_recovery::inspect_packet(payload, recovery_context, 256).is_err());
            }
            let wires = payloads
                .iter()
                .map(|payload| seal(&mut a, payload))
                .collect::<Result<Vec<_>, _>>()?;
            assert_eq!(b.open(&wires[2])?, payloads[2]);
            assert_eq!(b.open(&wires[0])?, payloads[0]);
            assert!(matches!(b.open(&wires[2]), Err(Error::Replay)));
            assert_eq!(
                a.open(&seal(&mut b, b"reverse feedback")?)?,
                b"reverse feedback"
            );
        }
        Ok(())
    }

    #[test]
    fn bad_auth_and_short_output_do_not_consume_packet_identity() -> Result<(), Error> {
        let (mut a, mut b) = pair(Protection::ChaCha20Poly1305)?;
        let mut short = [0xa5; 1];
        assert!(matches!(
            a.seal(b"opaque", &mut short),
            Err(Error::OutputTooSmall)
        ));
        assert_eq!(short, [0xa5]);
        let mut wire = vec![0; 1280];
        let packet = a.seal(b"opaque", &mut wire)?;
        assert_eq!(packet.packet.0, 0);
        wire.truncate(packet.wire_len);
        // A failed short-output attempt did not allocate packet zero.
        assert_eq!(a.sealer.usage().packets, 1);
        let mut forged = wire.clone();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert!(b.open(&forged).is_err());
        assert_eq!(b.open(&wire)?, b"opaque");
        assert!(matches!(b.open(&wire), Err(Error::Replay)));
        Ok(())
    }

    #[test]
    fn extraction_preserves_existing_protected_wire_bytes() -> Result<(), Error> {
        for protection in [Protection::ChaCha20Poly1305, Protection::HmacSha256] {
            let forward = config(Direction::ClientToServer, protection);
            let mut legacy = PacketSealer::new(forward, &[0x21; 32])?;
            let (mut extracted, mut receiver) = pair(protection)?;
            for payload in [b"first source".as_slice(), b"feedback", b"retry"] {
                let mut expected = vec![0; 1280];
                let packet = legacy.seal_into(payload, &mut expected)?;
                expected.truncate(packet.wire_len);
                let actual = seal(&mut extracted, payload)?;
                assert_eq!(actual, expected);
                assert_eq!(receiver.open(&actual)?, payload);
            }
        }
        Ok(())
    }

    #[test]
    fn fixed_receive_storage_and_key_preflight_remain_bounded() -> Result<(), Error> {
        let forward = config(Direction::ClientToServer, Protection::HmacSha256);
        let reverse = config(Direction::ServerToClient, Protection::HmacSha256);
        let mut limited = forward;
        limited.max_payload_bytes_per_key = 256;
        let mut a = ProtectedDatagrams::new(limited, &[0x21; 32], reverse, &[0x42; 32])?;
        assert_eq!(a.received.len(), reverse.max_payload_bytes);
        a.reserve_maximum_send()?;
        let _ = seal(&mut a, b"x")?;
        assert!(matches!(
            a.reserve_maximum_send(),
            Err(Error::KeyUsageExhausted)
        ));
        assert_eq!(a.sealer.usage().packets, 1);
        let mut invalid = reverse;
        invalid.max_payload_bytes = usize::MAX;
        assert!(matches!(
            ProtectedDatagrams::new(forward, &[0x21; 32], invalid, &[0x42; 32]),
            Err(Error::InvalidConfig)
        ));
        Ok(())
    }
}
