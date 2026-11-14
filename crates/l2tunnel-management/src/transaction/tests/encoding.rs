//! Explicit complete encodings use the same actual transaction and request gate.

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Probe<const N: usize, const COMPLETE: bool, const DOMAIN: usize = 32>;
impl<const N: usize, const COMPLETE: bool, const DOMAIN: usize> Configuration
    for Probe<N, COMPLETE, DOMAIN>
{
    const ENCODING: ConfigurationEncoding = if COMPLETE {
        ConfigurationEncoding::CompleteV2
    } else {
        ConfigurationEncoding::LegacyV1
    };
    const ENCODED_LEN: usize = N;
    const DIGEST_DOMAIN: &'static [u8] = &[b'x'; DOMAIN];
    fn validate(&self) -> Result<(), Error> {
        Err(Error::Unexpected)
    }
    fn encode_into(&self, _: &mut [u8]) -> Result<(), Error> {
        Err(Error::Unexpected)
    }
    fn decode(_: &[u8]) -> Result<Self, Error> {
        Err(Error::Unexpected)
    }
    fn channels(&self) -> u16 {
        1
    }
    fn duplex(&self) -> l2tunnel_core::Duplex {
        l2tunnel_core::Duplex::Full
    }
}

#[test]
fn selected_static_bounds_refuse_before_local_callbacks() -> Result<(), Error> {
    assert_eq!(ConfigurationEncoding::LegacyV1.maximum_bytes(), 512);
    assert_eq!(ConfigurationEncoding::CompleteV2.maximum_bytes(), 4096);
    assert_eq!(
        configuration_digest(&Probe::<512, false>),
        Err(Error::Unexpected)
    );
    assert_eq!(
        configuration_digest(&Probe::<513, true>),
        Err(Error::Unexpected)
    );
    assert_eq!(
        configuration_digest(&Probe::<4096, true>),
        Err(Error::Unexpected)
    );
    assert!(matches!(
        configuration_digest(&Probe::<513, false>),
        Err(Error::Configuration(_))
    ));
    assert!(matches!(
        configuration_digest(&Probe::<4097, true>),
        Err(Error::Configuration(_))
    ));
    assert!(matches!(
        configuration_digest(&Probe::<0, true>),
        Err(Error::Configuration(_))
    ));
    assert!(matches!(
        configuration_digest(&Probe::<{ usize::MAX }, true>),
        Err(Error::Configuration(_))
    ));
    assert!(matches!(
        config::decode_configuration::<Probe<513, false>>(&[]),
        Err(Error::Configuration(_))
    ));
    assert!(matches!(
        config::decode_configuration::<Probe<4097, true>>(&[]),
        Err(Error::Configuration(_))
    ));
    assert!(matches!(
        config::decode_configuration::<Probe<{ usize::MAX }, true>>(&[]),
        Err(Error::Configuration(_))
    ));
    assert_eq!(
        config::decode_configuration::<Probe<4096, true>>(&vec![0; 4096]),
        Err(Error::Unexpected)
    );
    assert_eq!(configuration_limits::<Probe<512, false>>()?, limits());
    assert_eq!(configuration_limits::<Probe<1304, true>>()?, limits());
    assert_eq!(configuration_limits::<Probe<1926, true>>()?, limits());
    let first_extension = configuration_limits::<Probe<1927, true>>()?;
    assert_eq!(first_extension.max_frame_bytes, 4097);
    assert_eq!(first_extension.max_retained_bytes, 16388);
    let extended = configuration_limits::<Probe<4096, true>>()?;
    assert_eq!(extended.max_frame_bytes, 6266);
    assert_eq!(extended.max_requests, 4);
    assert_eq!(extended.max_retained_bytes, 25064);
    assert_eq!(maximum_prepare_bytes::<Probe<4096, true>>(256)?, 6266);
    assert_eq!(
        maximum_prepare_bytes::<Probe<1304, true>>(1)?,
        HEADER_LEN + 8 + 1304 + 2 + 8
    );
    for width in [0, 257, u16::MAX] {
        assert!(matches!(
            maximum_prepare_bytes::<Probe<1304, true>>(width),
            Err(Error::Configuration(_))
        ));
    }
    assert!(matches!(
        configuration_limits::<Probe<4097, true>>(),
        Err(Error::Configuration(_))
    ));
    assert_eq!(
        configuration_digest(&Probe::<1, true, 128>),
        Err(Error::Unexpected)
    );
    assert_eq!(
        config::decode_configuration::<Probe<1, true, 128>>(&[0]),
        Err(Error::Unexpected)
    );
    assert!(matches!(
        configuration_digest(&Probe::<1, true, 0>),
        Err(Error::Configuration(_))
    ));
    assert!(matches!(
        configuration_digest(&Probe::<1, true, 129>),
        Err(Error::Configuration(_))
    ));
    assert!(matches!(
        config::decode_configuration::<Probe<1, true, 0>>(&[0]),
        Err(Error::Configuration(_))
    ));
    assert!(matches!(
        config::decode_configuration::<Probe<1, true, 129>>(&[0]),
        Err(Error::Configuration(_))
    ));
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CompletePolicy<const N: usize> {
    forward: u16,
    reverse: u16,
    value: u8,
}
impl<const N: usize> Configuration for CompletePolicy<N> {
    const ENCODING: ConfigurationEncoding = ConfigurationEncoding::CompleteV2;
    const ENCODED_LEN: usize = N;
    const DIGEST_DOMAIN: &'static [u8] = b"test/complete-policy/v2\0";
    fn validate(&self) -> Result<(), Error> {
        if N < 6
            || !(1..=256).contains(&self.forward)
            || !(1..=256).contains(&self.reverse)
            || self.value == 0
        {
            return Err(Error::Configuration("test complete policy"));
        }
        Ok(())
    }
    fn encode_into(&self, output: &mut [u8]) -> Result<(), Error> {
        self.validate()?;
        if output.len() != N {
            return Err(Error::Malformed);
        }
        output[..2].copy_from_slice(&[2, self.value]);
        output[2..4].copy_from_slice(&self.forward.to_be_bytes());
        output[4..6].copy_from_slice(&self.reverse.to_be_bytes());
        for (i, byte) in output[6..].iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(13) ^ self.value;
        }
        Ok(())
    }
    fn decode(input: &[u8]) -> Result<Self, Error> {
        if input.len() != N || N < 6 || input[0] != 2 {
            return Err(Error::Malformed);
        }
        // Intentionally ignore tail here: the central re-encoding gate must
        // reject a permissive trusted local decoder's noncanonical peer bytes.
        Ok(Self {
            forward: u16::from_be_bytes([input[2], input[3]]),
            reverse: u16::from_be_bytes([input[4], input[5]]),
            value: input[1],
        })
    }
    fn channels(&self) -> u16 {
        self.forward
    }
    fn sender_channels(&self, sender: Role) -> u16 {
        if sender == Role::Client {
            self.forward
        } else {
            self.reverse
        }
    }
    fn duplex(&self) -> l2tunnel_core::Duplex {
        l2tunnel_core::Duplex::Full
    }
}

#[test]
fn complete_canonical_tail_length_and_legacy_contract_remain_exact() -> Result<(), Error> {
    let c = CompletePolicy::<1304> {
        forward: 2,
        reverse: 3,
        value: 7,
    };
    let encoded = config::encode_configuration(&c)?;
    assert_eq!(encoded.len(), 1304);
    assert_eq!(
        config::decode_configuration::<CompletePolicy<1304>>(&encoded)?,
        c
    );
    let mut wrong = encoded.clone();
    wrong[1303] ^= 1;
    assert_eq!(
        config::decode_configuration::<CompletePolicy<1304>>(&wrong),
        Err(Error::Malformed)
    );
    assert!(config::decode_configuration::<CompletePolicy<1304>>(&encoded[..1303]).is_err());
    wrong = encoded.clone();
    wrong.push(0);
    assert!(config::decode_configuration::<CompletePolicy<1304>>(&wrong).is_err());
    assert_ne!(
        configuration_digest(&c)?,
        configuration_digest(&CompletePolicy::<1304> { value: 8, ..c })?
    );
    assert_eq!(
        <ModeConfig as Configuration>::ENCODING,
        ConfigurationEncoding::LegacyV1
    );
    assert_eq!(configuration_limits::<ModeConfig>()?, limits());
    for mode in [modes().0, modes().1] {
        assert_eq!(configuration_digest(&mode)?, mode_digest(&mode)?);
        assert_eq!(config::encode_configuration(&mode)?, encode_mode(&mode)?);
    }
    Ok(())
}

fn receive<const N: usize>(
    peer: &mut Peer<CompletePolicy<N>>,
    sender: Role,
    bytes: &[u8],
    leased: bool,
    now: Tick,
) -> Result<Effects<CompletePolicy<N>>, Error> {
    if leased {
        peer.receive_until(origin(sender), bytes, now, Tick(900))
    } else {
        peer.receive(origin(sender), bytes, now)
    }
}
fn wire<const N: usize>(effects: Effects<CompletePolicy<N>>) -> Result<Vec<u8>, Error> {
    effects.outbound.ok_or(Error::Unexpected)
}

fn actual_exchange<const N: usize>(leased: bool) -> Result<(), Error> {
    let initial = CompletePolicy::<N> {
        forward: 256,
        reverse: 255,
        value: 3,
    };
    let target = CompletePolicy::<N> {
        forward: 2,
        reverse: 3,
        value: 7,
    };
    let catalog = [initial.clone(), target.clone()];
    let settings = Settings {
        retry_ms: 3,
        phase_timeout_ms: 100,
        reconcile_timeout_ms: 500,
    };
    let make = |role| {
        if leased {
            Peer::new_leased_directional(
                identity(role, 3),
                Epoch(1),
                initial.clone(),
                &catalog,
                settings,
                LeaseSettings {
                    session_expires: Tick(10_000),
                    max_operation_ms: 5_000,
                    transaction_epoch: 1,
                },
                Tick(0),
            )
        } else {
            Peer::new_directional(
                identity(role, 3),
                Epoch(1),
                initial.clone(),
                &catalog,
                settings,
                Tick(0),
            )
        }
    };
    let mut client = make(Role::Client)?;
    let mut server = make(Role::Server)?;
    if leased {
        client.propose_until(target.clone(), Tick(0), Tick(900))?;
    } else {
        client.propose(target.clone(), Tick(0))?;
    }
    let local = Fence::new(&(1..=256).collect::<Vec<u64>>())?;
    let remote = Fence::new(&(1..=255).collect::<Vec<u64>>())?;
    let prepare = wire(client.staged(local.clone(), Tick(1))?)?;
    if leased {
        let context = client.outbound_context(&prepare)?;
        assert_eq!(context.origin().digest, configuration_digest(&initial)?);
        assert_eq!(context.expires(), Tick(900));
    }
    assert_eq!(
        prepare.len(),
        maximum_prepare_bytes::<CompletePolicy<N>>(256)?
    );
    let frame = Frame::decode(&prepare, configuration_limits::<CompletePolicy<N>>()?)
        .map_err(Error::Admission)?;
    assert_eq!(
        &frame.body[8..8 + N],
        config::encode_configuration(&target)?
    );
    assert!(matches!(
        receive(&mut server, Role::Client, &prepare, leased, Tick(2))?.event,
        Some(Event::Stage { .. })
    ));
    let ready = wire(server.staged(remote.clone(), Tick(3))?)?;
    let retry = wire(client.poll(Tick(4))?)?;
    let retry_frame = Frame::decode(&retry, configuration_limits::<CompletePolicy<N>>()?)
        .map_err(Error::Admission)?;
    assert_eq!(retry_frame.header.request, frame.header.request);
    assert_eq!(retry_frame.body, frame.body);
    assert_ne!(retry_frame.header.packet, frame.header.packet);
    let repeated = wire(receive(&mut server, Role::Client, &retry, leased, Tick(4))?)?;
    let a = Frame::decode(&ready, configuration_limits::<CompletePolicy<N>>()?)
        .map_err(Error::Admission)?;
    let b = Frame::decode(&repeated, configuration_limits::<CompletePolicy<N>>()?)
        .map_err(Error::Admission)?;
    assert_eq!(a.header.request, b.header.request);
    assert_eq!(a.body, b.body);
    receive(&mut client, Role::Server, &repeated, leased, Tick(5))?;
    server.confirm_drained(&remote, &local, Tick(6))?;
    let mut command = wire(client.confirm_drained(&local, &remote, Tick(6))?)?;
    for tick in 7..10 {
        let reply = wire(receive(
            &mut server,
            Role::Client,
            &command,
            leased,
            Tick(tick),
        )?)?;
        let effect = receive(&mut client, Role::Server, &reply, leased, Tick(tick))?;
        if let Some(next) = effect.outbound {
            command = next;
        }
    }
    for peer in [&mut client, &mut server] {
        assert_eq!(peer.phase(), Phase::Idle);
        assert_eq!(peer.active_config(), &target);
        assert_eq!(peer.active_epoch(), Epoch(2));
        assert!(peer.reader(Epoch(1)).is_none());
        assert_eq!(peer.sender_channels(Role::Client), 2);
        assert_eq!(peer.sender_channels(Role::Server), 3);
        if leased {
            let operation = peer.operation().ok_or(Error::Unexpected)?;
            assert_eq!(operation.expires(), Tick(900));
            assert_eq!(operation.origin().digest, configuration_digest(&initial)?);
            assert!(
                !peer.can_admit_data(),
                "terminal message custody still owns the operation"
            );
            assert_eq!(peer.poll(Tick(900)), Err(Error::LeaseExpired));
            assert_eq!(peer.active_config(), &target);
        }
    }
    Ok(())
}

#[test]
fn actual_complete_value_uses_existing_directional_peer_and_retry_phases() -> Result<(), Error> {
    actual_exchange::<1304>(false)?;
    actual_exchange::<4096>(false)
}
#[test]
fn actual_complete_value_preserves_original_lease_and_terminal_custody() -> Result<(), Error> {
    actual_exchange::<1304>(true)?;
    actual_exchange::<4096>(true)
}
