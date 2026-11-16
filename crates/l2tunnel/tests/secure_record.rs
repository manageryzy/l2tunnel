//! Finite secure-record contracts and same-socket local UDP composition checks.

use l2tunnel::{
    cover,
    secure_record::{
        Capacity, Class, DataReader, Error, Opened, ReaderState, Records, Scope, Sealed,
    },
    security,
};
use std::{error::Error as StdError, net::UdpSocket, time::Duration};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn StdError>>;

#[path = "secure_record/compact.rs"]
mod compact;
#[path = "secure_record/compact_arq.rs"]
mod compact_arq;
#[path = "secure_record/compact_carrier.rs"]
mod compact_carrier;

fn scope(epoch: u64, digest: u8) -> Scope {
    Scope {
        epoch: security::Epoch(epoch),
        configuration: security::ConfigDigest([digest; 32]),
    }
}

fn control() -> Scope {
    scope(1, 0xc0)
}

fn data() -> Scope {
    scope(10, 0xd0)
}

fn limits() -> security::Limits {
    security::Limits {
        max_body_bytes: 1024,
        packets_per_key: 8,
        max_body_bytes_per_key: 8192,
    }
}

fn root(role: security::Role) -> Result<security::SessionRoot> {
    Ok(security::SessionRoot::from_split_keys(
        Zeroizing::new([1; 32]),
        Zeroizing::new([2; 32]),
        security::SessionBinding {
            session: security::SessionId([3; 16]),
            transcript: [4; 32],
        },
        role,
    )?)
}

fn covers(appearance: cover::Appearance) -> Result<(cover::Config, cover::Config)> {
    let configuration = |local, peer, local_ssrc, peer_ssrc| {
        cover::Config::new(
            appearance,
            cover::ConnectionIds {
                local: cover::ConnectionId([local; 8]),
                peer: cover::ConnectionId([peer; 8]),
            },
            cover::MediaConfig {
                local_ssrc: cover::Ssrc(local_ssrc),
                peer_ssrc: cover::Ssrc(peer_ssrc),
                payload_type: 96,
            },
            cover::Limits {
                max_packet_bytes: 1536,
                max_protected_bytes: 1450,
            },
        )
    };
    Ok((
        configuration(0x11, 0x22, 11, 22)?,
        configuration(0x22, 0x11, 22, 11)?,
    ))
}

fn peers(
    appearance: cover::Appearance,
    protection: security::Protection,
) -> Result<(Records, Records)> {
    let (a_cover, b_cover) = covers(appearance)?;
    Ok((
        Records::new(
            root(security::Role::Initiator)?,
            security::LaneId(7),
            limits(),
            protection,
            a_cover,
            control(),
            data(),
        )?,
        Records::new(
            root(security::Role::Responder)?,
            security::LaneId(7),
            limits(),
            protection,
            b_cover,
            control(),
            data(),
        )?,
    ))
}

fn outer(number: u32) -> cover::PacketMeta {
    cover::PacketMeta {
        phase: cover::Phase::Established,
        packet_number: cover::PacketNumber(number),
        media_timestamp: cover::MediaTimestamp(u32::MAX),
    }
}

fn seal(records: &mut Records, class: Class, body: &[u8]) -> Result<(Sealed, Vec<u8>)> {
    let capacity = records.capacity(body.len())?;
    let mut workspace = vec![0; capacity.seal_workspace_bytes];
    let mut packet = vec![0; capacity.packet_bytes];
    let sealed = records.seal(class, outer(0x1234_5678), body, &mut workspace, &mut packet)?;
    assert_eq!(sealed.bytes, packet.len());
    Ok((sealed, packet))
}

fn open(records: &mut Records, packet: &[u8]) -> Result<(Opened, Vec<u8>)> {
    let mut workspace = [0; 1600];
    let mut plaintext = [0; 1024];
    let opened = records.open(packet, &mut workspace, &mut plaintext)?;
    Ok((opened, plaintext[..opened.bytes].to_vec()))
}

fn repack(
    sender: cover::Config,
    receiver: cover::Config,
    packet: &[u8],
    change: impl FnOnce(&mut Vec<u8>),
) -> Result<Vec<u8>> {
    let mut protected = receiver.decode(packet)?.protected.to_vec();
    change(&mut protected);
    let mut output = [0; 1536];
    let length = sender.encode(outer(1), &protected, &mut output)?;
    Ok(output[..length].to_vec())
}

fn seal_registered_scope(
    sender: &mut security::Sender,
    cover: cover::Config,
    scope: Scope,
    body: &[u8],
    legacy_route: bool,
) -> Result<Vec<u8>> {
    let mut route = vec![1];
    route.extend_from_slice(&scope.epoch.0.to_be_bytes());
    if legacy_route {
        route.extend_from_slice(&scope.configuration.0);
    }
    let mut workspace = [0; 1536];
    let sealed = sender.seal(
        security::Metadata {
            epoch: scope.epoch,
            configuration: scope.configuration,
            extra: &route,
        },
        body,
        &mut workspace[route.len()..],
    )?;
    workspace[..route.len()].copy_from_slice(&route);
    let mut output = [0; 1536];
    let length = cover.encode(
        outer(0),
        &workspace[..route.len() + sealed.bytes],
        &mut output,
    )?;
    Ok(output[..length].to_vec())
}

fn selections() -> impl Iterator<Item = (cover::Appearance, security::Protection)> {
    [cover::Appearance::QuicLike, cover::Appearance::MediaLike]
        .into_iter()
        .flat_map(|appearance| {
            [
                security::Protection::ChaCha20Poly1305,
                security::Protection::HmacSha256,
            ]
            .into_iter()
            .map(move |protection| (appearance, protection))
        })
}

#[test]
fn both_covers_protections_classes_and_directions_preserve_exact_records() -> Result<()> {
    for (appearance, protection) in selections() {
        let (mut a, mut b) = peers(appearance, protection)?;
        let bodies = [vec![], vec![0], vec![0xff, 0, 1, 0, 0], vec![0; 1024]];
        for reverse in [false, true] {
            let (sender, receiver) = if reverse {
                (&mut b, &mut a)
            } else {
                (&mut a, &mut b)
            };
            for class in [Class::User, Class::Control] {
                for (number, body) in bodies.iter().enumerate() {
                    let capacity = sender.capacity(body.len())?;
                    let overhead = protection.overhead_bytes();
                    let outer_bytes = match appearance {
                        cover::Appearance::QuicLike => cover::QUIC_ESTABLISHED_OVERHEAD,
                        cover::Appearance::MediaLike => cover::MEDIA_OVERHEAD,
                    };
                    assert_eq!(
                        capacity,
                        Capacity {
                            plaintext_bytes: body.len(),
                            seal_workspace_bytes: 9 + overhead + body.len(),
                            open_workspace_bytes: protection.tag_bytes() + body.len(),
                            packet_bytes: outer_bytes + 9 + overhead + body.len(),
                        }
                    );
                    let (sealed, packet) = seal(sender, class, body)?;
                    assert_eq!(sealed.number, security::PacketNumber(number as u64));
                    let (opened, plaintext) = open(receiver, &packet)?;
                    assert_eq!(plaintext, *body);
                    assert_eq!(opened.class, class);
                    assert_eq!(
                        opened.scope,
                        if class == Class::User {
                            data()
                        } else {
                            control()
                        }
                    );
                    assert_eq!(opened.number, sealed.number);
                    assert_eq!(opened.generation, security::KeyGeneration(0));
                    assert_eq!(opened.bytes, body.len());
                }
            }
        }
    }
    Ok(())
}

#[test]
fn exact_route_is_public_but_management_looking_user_bytes_keep_user_authority() -> Result<()> {
    for (appearance, protection) in selections() {
        let (mut a, mut b) = peers(appearance, protection)?;
        let (_, b_cover) = covers(appearance)?;
        let ethernet = b"\xff\xff\xff\xff\xff\xff\x02\0\0\0\0\x01\x88\xb5L2MC\0\0";
        let (_, packet) = seal(&mut a, Class::User, ethernet)?;
        let protected = b_cover.decode(&packet)?.protected;
        assert_eq!(protected[0], 1);
        assert_eq!(&protected[1..9], &data().epoch.0.to_be_bytes());
        assert_eq!(protected[9], security::VERSION);
        assert_eq!(protected[10], protection as u8);
        assert_eq!(&protected[11..19], &[0; 8]);
        let (opened, bytes) = open(&mut b, &packet)?;
        assert_eq!(opened.class, Class::User);
        assert_eq!(bytes, ethernet);
    }
    Ok(())
}

#[test]
fn every_protected_byte_tamper_fails_without_plaintext_or_replay_adoption() -> Result<()> {
    for (appearance, protection) in selections() {
        let (mut a, mut b) = peers(appearance, protection)?;
        let (a_cover, b_cover) = covers(appearance)?;
        let (_, packet) = seal(&mut a, Class::User, b"exact protected body\0\0")?;
        let protected_length = b_cover.decode(&packet)?.protected.len();
        for index in 0..protected_length {
            let forged = repack(a_cover, b_cover, &packet, |body| body[index] ^= 1)?;
            let mut workspace = [0x6b; 1600];
            let mut plaintext = [0xa5; 1024];
            assert!(
                b.open(&forged, &mut workspace, &mut plaintext).is_err(),
                "byte {index}"
            );
            assert!(plaintext.iter().all(|value| *value == 0xa5));
        }
        let (opened, body) = open(&mut b, &packet)?;
        assert_eq!(opened.number, security::PacketNumber(0));
        assert_eq!(body, b"exact protected body\0\0");
        assert_eq!(
            b.open(&packet, &mut [0; 1600], &mut [0; 1024]),
            Err(Error::Security(security::Error::Replay))
        );
    }
    Ok(())
}

#[test]
fn relabeling_a_user_record_as_a_valid_control_route_cannot_grant_authority() -> Result<()> {
    for (appearance, protection) in selections() {
        let (mut a, mut b) = peers(appearance, protection)?;
        let (a_cover, b_cover) = covers(appearance)?;
        let (_, user) = seal(&mut a, Class::User, b"L2MC fake control")?;
        let forged = repack(a_cover, b_cover, &user, |body| {
            body[0] = 2;
            body[1..9].copy_from_slice(&control().epoch.0.to_be_bytes());
        })?;
        assert_eq!(
            b.open(&forged, &mut [0; 1600], &mut [0; 1024]),
            Err(Error::Security(security::Error::Authentication))
        );
        let (_, real_control) = seal(&mut a, Class::Control, b"authenticated management")?;
        let (opened, body) = open(&mut b, &real_control)?;
        assert_eq!(opened.class, Class::Control);
        assert_eq!(opened.number, security::PacketNumber(0));
        assert_eq!(body, b"authenticated management");
        assert_eq!(open(&mut b, &user)?.0.class, Class::User);
    }
    Ok(())
}

#[test]
fn control_and_shared_data_replay_survive_staging_activation_and_retirement() -> Result<()> {
    for (appearance, protection) in selections() {
        let (mut a, mut b) = peers(appearance, protection)?;
        let next = scope(11, 0xd1);
        let (_, accepted_old) = seal(&mut a, Class::User, b"already accepted old")?;
        open(&mut b, &accepted_old)?;
        let (_, draining_old) = seal(&mut a, Class::User, b"delayed old\0\0")?;
        let (_, retired_old) = seal(&mut a, Class::User, b"too late old")?;

        for endpoint in [&mut a, &mut b] {
            endpoint.stage_data(next)?;
            assert_eq!(endpoint.active_data(), data());
            assert_eq!(
                endpoint.additional_data(),
                Some(DataReader {
                    scope: next,
                    state: ReaderState::Staged
                })
            );
        }
        let (_, management) = seal(&mut a, Class::Control, b"prepare")?;
        assert_eq!(open(&mut b, &management)?.0.scope, control());
        a.activate_data(next)?;
        let (sealed_new, new) = seal(&mut a, Class::User, b"staged new\0\0")?;
        assert_eq!(sealed_new.number, security::PacketNumber(3));
        assert_eq!(open(&mut b, &new)?.0.scope, next);
        assert_eq!(b.active_data(), data());
        b.activate_data(next)?;
        assert_eq!(
            b.additional_data(),
            Some(DataReader {
                scope: data(),
                state: ReaderState::Draining
            })
        );
        let (opened, body) = open(&mut b, &draining_old)?;
        assert_eq!(opened.scope, data());
        assert_eq!(opened.number, security::PacketNumber(1));
        assert_eq!(body, b"delayed old\0\0");
        assert_eq!(
            b.open(&accepted_old, &mut [0; 1600], &mut [0; 1024]),
            Err(Error::Security(security::Error::Replay))
        );

        let (_, reply) = seal(&mut b, Class::Control, b"commit acknowledgement")?;
        assert_eq!(open(&mut a, &reply)?.0.scope, control());
        a.retire_data(data())?;
        b.retire_data(data())?;
        assert_eq!(
            b.open(&retired_old, &mut [0; 1600], &mut [0; 1024]),
            Err(Error::Scope)
        );
        assert_eq!(
            b.open(&new, &mut [0; 1600], &mut [0; 1024]),
            Err(Error::Security(security::Error::Replay))
        );
        assert_eq!(a.next_number(Class::User), security::PacketNumber(4));
        assert_eq!(a.next_number(Class::Control), security::PacketNumber(1));
        let (_, steady_control) = seal(&mut a, Class::Control, b"still live")?;
        assert_eq!(open(&mut b, &steady_control)?.0.scope, control());
    }
    Ok(())
}

#[test]
fn changing_a_late_route_to_another_registered_scope_does_not_consume_it() -> Result<()> {
    for (appearance, protection) in selections() {
        let (mut a, mut b) = peers(appearance, protection)?;
        let (a_cover, b_cover) = covers(appearance)?;
        let (_, old) = seal(&mut a, Class::User, b"old scope")?;
        let next = scope(11, 0xd1);
        b.stage_data(next)?;
        let forged = repack(a_cover, b_cover, &old, |body| {
            body[1..9].copy_from_slice(&next.epoch.0.to_be_bytes());
        })?;
        assert_eq!(
            b.open(&forged, &mut [0; 1600], &mut [0; 1024]),
            Err(Error::Security(security::Error::Authentication))
        );
        assert_eq!(open(&mut b, &old)?.0.scope, data());
    }
    Ok(())
}

#[test]
fn canceled_epoch_can_change_digest_without_accepting_old_ciphertext_or_resetting_replay()
-> Result<()> {
    for (appearance, protection) in selections() {
        let (a_cover, b_cover) = covers(appearance)?;
        let mut sender = root(security::Role::Initiator)?.sender(
            security::Purpose::Data,
            security::LaneId(7),
            limits(),
            protection,
        )?;
        let mut receiver = Records::new(
            root(security::Role::Responder)?,
            security::LaneId(7),
            limits(),
            protection,
            b_cover,
            control(),
            data(),
        )?;
        let canceled = scope(11, 0xa1);
        let replacement = scope(11, 0xb1);
        let accepted = seal_registered_scope(&mut sender, a_cover, data(), b"active scope", false)?;
        open(&mut receiver, &accepted)?;
        receiver.stage_data(canceled)?;
        let old =
            seal_registered_scope(&mut sender, a_cover, canceled, b"canceled attempt", false)?;
        receiver.cancel_staged_data(canceled)?;
        receiver.stage_data(replacement)?;
        let mut plaintext = [0xa5; 1024];
        assert_eq!(
            receiver.open(&old, &mut [0; 1600], &mut plaintext),
            Err(Error::Security(security::Error::Authentication))
        );
        assert!(plaintext.iter().all(|byte| *byte == 0xa5));
        assert_eq!(
            receiver.open(&accepted, &mut [0; 1600], &mut plaintext),
            Err(Error::Security(security::Error::Replay))
        );
        let new =
            seal_registered_scope(&mut sender, a_cover, replacement, b"replacement\0\0", false)?;
        let (opened, bytes) = open(&mut receiver, &new)?;
        assert_eq!(opened.scope, replacement);
        assert_eq!(opened.number, security::PacketNumber(2));
        assert_eq!(bytes, b"replacement\0\0");
        assert_eq!(
            receiver.open(&new, &mut [0; 1600], &mut [0; 1024]),
            Err(Error::Security(security::Error::Replay))
        );
        assert_eq!(sender.next_number(), security::PacketNumber(3));
        assert_eq!(receiver.next_number(Class::User), security::PacketNumber(0));
    }
    Ok(())
}

#[test]
fn prior_41_byte_route_is_not_autodetected_or_accepted() -> Result<()> {
    for (appearance, protection) in selections() {
        let (a_cover, b_cover) = covers(appearance)?;
        let mut sender = root(security::Role::Initiator)?.sender(
            security::Purpose::Data,
            security::LaneId(7),
            limits(),
            protection,
        )?;
        let mut receiver = Records::new(
            root(security::Role::Responder)?,
            security::LaneId(7),
            limits(),
            protection,
            b_cover,
            control(),
            data(),
        )?;
        let legacy = seal_registered_scope(&mut sender, a_cover, data(), b"legacy draft", true)?;
        assert!(
            receiver
                .open(&legacy, &mut [0; 1600], &mut [0; 1024])
                .is_err()
        );
        let compact = seal_registered_scope(&mut sender, a_cover, data(), b"compact draft", false)?;
        let (opened, bytes) = open(&mut receiver, &compact)?;
        assert_eq!(opened.number, security::PacketNumber(1));
        assert_eq!(bytes, b"compact draft");
    }
    Ok(())
}

#[test]
fn local_reader_changes_are_bounded_exact_and_do_not_reset_senders() -> Result<()> {
    let (mut a, _) = peers(
        cover::Appearance::QuicLike,
        security::Protection::ChaCha20Poly1305,
    )?;
    let next = scope(11, 0xd1);
    let later = scope(12, 0xd2);
    assert_eq!(a.activate_data(next), Err(Error::ScopeState));
    assert_eq!(a.cancel_staged_data(next), Err(Error::ScopeState));
    assert_eq!(a.retire_data(data()), Err(Error::ScopeState));
    for invalid in [scope(9, 0xd1), scope(10, 0xff), data()] {
        assert_eq!(a.stage_data(invalid), Err(Error::ScopeState));
    }
    a.stage_data(next)?;
    a.stage_data(next)?;
    assert_eq!(a.stage_data(later), Err(Error::ScopeState));
    assert_eq!(a.activate_data(scope(11, 0xff)), Err(Error::ScopeState));
    assert_eq!(a.cancel_staged_data(later), Err(Error::ScopeState));
    assert_eq!(a.retire_data(next), Err(Error::ScopeState));
    a.cancel_staged_data(next)?;
    a.stage_data(next)?;
    a.activate_data(next)?;
    a.activate_data(next)?;
    assert_eq!(a.stage_data(later), Err(Error::ScopeState));
    assert_eq!(a.cancel_staged_data(data()), Err(Error::ScopeState));
    assert_eq!(a.retire_data(next), Err(Error::ScopeState));
    a.retire_data(data())?;
    a.stage_data(later)?;
    assert_eq!(a.control_scope(), control());
    assert_eq!(a.next_number(Class::User), security::PacketNumber(0));
    assert_eq!(a.next_number(Class::Control), security::PacketNumber(0));
    Ok(())
}

#[test]
fn seal_preflight_errors_preserve_both_buffers_and_unique_numbers() -> Result<()> {
    for (appearance, protection) in selections() {
        let (mut a, _) = peers(appearance, protection)?;
        for class in [Class::User, Class::Control] {
            let capacity = a.capacity(100)?;
            for failure in 0..4 {
                let mut workspace = [0x6b; 1600];
                let mut packet = [0xa5; 1600];
                let result = match failure {
                    0 => a.seal(class, outer(0), &[0; 1025], &mut workspace, &mut packet),
                    1 => a.seal(
                        class,
                        cover::PacketMeta {
                            phase: cover::Phase::Handshake,
                            ..outer(0)
                        },
                        &[0; 100],
                        &mut workspace,
                        &mut packet,
                    ),
                    2 => a.seal(
                        class,
                        outer(0),
                        &[0; 100],
                        &mut workspace[..capacity.seal_workspace_bytes - 1],
                        &mut packet,
                    ),
                    _ => a.seal(
                        class,
                        outer(0),
                        &[0; 100],
                        &mut workspace,
                        &mut packet[..capacity.packet_bytes - 1],
                    ),
                };
                assert!(result.is_err());
                assert!(workspace.iter().all(|value| *value == 0x6b));
                assert!(packet.iter().all(|value| *value == 0xa5));
                assert_eq!(a.next_number(class), security::PacketNumber(0));
            }
            assert_eq!(
                seal(&mut a, class, &[0; 100])?.0.number,
                security::PacketNumber(0)
            );
        }
    }
    Ok(())
}

#[test]
fn receive_capacity_errors_do_not_expose_plaintext_or_consume_replay_credit() -> Result<()> {
    for (appearance, protection) in selections() {
        let (mut a, mut b) = peers(appearance, protection)?;
        let capacity = a.capacity(100)?;
        let (_, packet) = seal(&mut a, Class::User, &[0; 100])?;
        let mut workspace = [0x6b; 1600];
        let mut plaintext = [0xa5; 1024];
        assert_eq!(
            b.open(
                &packet,
                &mut workspace[..capacity.open_workspace_bytes - 1],
                &mut plaintext
            ),
            Err(Error::OutputTooSmall)
        );
        assert_eq!(
            b.open(&packet, &mut workspace, &mut plaintext[..99]),
            Err(Error::OutputTooSmall)
        );
        assert!(workspace.iter().all(|value| *value == 0x6b));
        assert!(plaintext.iter().all(|value| *value == 0xa5));
        assert_eq!(open(&mut b, &packet)?.1, &[0; 100]);
    }
    Ok(())
}

#[test]
fn truncation_trailing_bytes_unknown_classes_and_scopes_are_bounded() -> Result<()> {
    for (appearance, protection) in selections() {
        let (mut a, mut b) = peers(appearance, protection)?;
        let (a_cover, b_cover) = covers(appearance)?;
        let (_, packet) = seal(&mut a, Class::User, b"truncation\0\0")?;
        for end in 0..packet.len() {
            assert!(
                b.open(&packet[..end], &mut [0; 1600], &mut [0; 1024])
                    .is_err(),
                "prefix {end}"
            );
        }
        let mut appended = packet.clone();
        appended.push(0);
        assert!(b.open(&appended, &mut [0; 1600], &mut [0; 1024]).is_err());
        for class in [0, 3, 255] {
            let forged = repack(a_cover, b_cover, &packet, |body| body[0] = class)?;
            assert_eq!(
                b.open(&forged, &mut [0; 1600], &mut [0; 1024]),
                Err(Error::Malformed)
            );
        }
        let unknown_epoch = repack(a_cover, b_cover, &packet, |body| body[1] ^= 1)?;
        assert_eq!(
            b.open(&unknown_epoch, &mut [0; 1600], &mut [0; 1024]),
            Err(Error::Scope)
        );
        let no_security = repack(a_cover, b_cover, &packet, |body| body.truncate(9))?;
        assert_eq!(
            b.open(&no_security, &mut [0; 1600], &mut [0; 1024]),
            Err(Error::Malformed)
        );
        assert_eq!(open(&mut b, &packet)?.1, b"truncation\0\0");
    }
    Ok(())
}

#[test]
fn outer_numbers_are_not_authenticated_packet_identities_or_handshake_authority() -> Result<()> {
    for (appearance, protection) in selections() {
        let (mut a, mut b) = peers(appearance, protection)?;
        let (a_cover, b_cover) = covers(appearance)?;
        let (_, packet) = seal(&mut a, Class::User, &[1, 0])?;
        let protected = b_cover.decode(&packet)?.protected;
        let mut changed_outer = [0; 1536];
        let length = a_cover.encode(outer(u32::MAX), protected, &mut changed_outer)?;
        let (opened, body) = open(&mut b, &changed_outer[..length])?;
        assert_eq!(opened.number, security::PacketNumber(0));
        assert_eq!(body, &[1, 0]);
        assert_eq!(
            b.open(&packet, &mut [0; 1600], &mut [0; 1024]),
            Err(Error::Security(security::Error::Replay))
        );
        let length = a_cover.encode(
            cover::PacketMeta {
                phase: cover::Phase::Handshake,
                ..outer(0)
            },
            protected,
            &mut changed_outer,
        )?;
        assert_eq!(
            b.open(&changed_outer[..length], &mut [0; 1600], &mut [0; 1024]),
            Err(Error::Phase)
        );
    }
    Ok(())
}

#[test]
fn security_counter_and_generation_continue_across_many_data_scope_changes() -> Result<()> {
    for (appearance, protection) in selections() {
        let (mut a, mut b) = peers(appearance, protection)?;
        let mut active = data();
        for number in 0..20_u64 {
            if number % 3 == 2 {
                let next = scope(active.epoch.0 + 1, number as u8);
                for endpoint in [&mut a, &mut b] {
                    endpoint.stage_data(next)?;
                    endpoint.activate_data(next)?;
                    endpoint.retire_data(active)?;
                }
                active = next;
            }
            let (sealed, packet) = seal(&mut a, Class::User, &[number as u8, 0, 0])?;
            let (opened, bytes) = open(&mut b, &packet)?;
            assert_eq!(sealed.number, security::PacketNumber(number));
            assert_eq!(opened.number, security::PacketNumber(number));
            assert_eq!(opened.generation, security::KeyGeneration(number / 8));
            assert_eq!(opened.scope, active);
            assert_eq!(bytes, &[number as u8, 0, 0]);
        }
    }
    Ok(())
}

#[test]
fn different_lanes_and_protection_selections_cannot_open_the_record() -> Result<()> {
    for (appearance, protection) in selections() {
        let (mut a, _) = peers(appearance, protection)?;
        let (_, b_cover) = covers(appearance)?;
        let (_, packet) = seal(&mut a, Class::User, &[0; 100])?;
        let mut wrong_lane = Records::new(
            root(security::Role::Responder)?,
            security::LaneId(8),
            limits(),
            protection,
            b_cover,
            control(),
            data(),
        )?;
        assert_eq!(
            wrong_lane.open(&packet, &mut [0; 1600], &mut [0; 1024]),
            Err(Error::Security(security::Error::Authentication))
        );
        let other_protection = match protection {
            security::Protection::ChaCha20Poly1305 => security::Protection::HmacSha256,
            security::Protection::HmacSha256 => security::Protection::ChaCha20Poly1305,
        };
        let mut wrong_protection = Records::new(
            root(security::Role::Responder)?,
            security::LaneId(7),
            limits(),
            other_protection,
            b_cover,
            control(),
            data(),
        )?;
        assert_eq!(
            wrong_protection.open(&packet, &mut [0; 1600], &mut [0; 1024]),
            Err(Error::Security(security::Error::ContextMismatch))
        );
    }
    Ok(())
}

#[test]
fn construction_rejects_incompatible_security_and_cover_bounds() -> Result<()> {
    for (appearance, protection) in selections() {
        let (a_cover, _) = covers(appearance)?;
        let maximum = a_cover.limits().max_protected_bytes
            - l2tunnel::secure_record::ROUTE_BYTES
            - protection.overhead_bytes();
        assert_eq!(
            maximum,
            match protection {
                security::Protection::ChaCha20Poly1305 => 1415,
                security::Protection::HmacSha256 => 1399,
            }
        );
        let valid = Records::new(
            root(security::Role::Initiator)?,
            security::LaneId(7),
            security::Limits {
                max_body_bytes: maximum,
                ..limits()
            },
            protection,
            a_cover,
            control(),
            data(),
        )?;
        assert_eq!(valid.capacity(maximum)?.seal_workspace_bytes, 1450);
        for max_body_bytes in [0, usize::MAX, maximum + 1] {
            assert!(
                Records::new(
                    root(security::Role::Initiator)?,
                    security::LaneId(7),
                    security::Limits {
                        max_body_bytes,
                        ..limits()
                    },
                    protection,
                    a_cover,
                    control(),
                    data()
                )
                .is_err()
            );
        }
    }
    Ok(())
}

#[test]
fn protected_user_and_control_use_the_same_two_real_udp_sockets() -> Result<()> {
    for (appearance, protection) in selections() {
        let (mut a, mut b) = peers(appearance, protection)?;
        let left = UdpSocket::bind("127.0.0.1:0")?;
        let right = UdpSocket::bind("127.0.0.1:0")?;
        let left_address = left.local_addr()?;
        let right_address = right.local_addr()?;
        left.connect(right_address)?;
        right.connect(left_address)?;
        left.set_read_timeout(Some(Duration::from_secs(1)))?;
        right.set_read_timeout(Some(Duration::from_secs(1)))?;
        for reverse in [false, true] {
            let (sender, receiver, tx, rx, expected_source) = if reverse {
                (&mut b, &mut a, &right, &left, right_address)
            } else {
                (&mut a, &mut b, &left, &right, left_address)
            };
            for class in [Class::User, Class::Control] {
                let body = if class == Class::User {
                    b"user frames\0\0".as_slice()
                } else {
                    b"management\0\0".as_slice()
                };
                let (_, packet) = seal(sender, class, body)?;
                assert_eq!(tx.send(&packet)?, packet.len());
                let mut input = [0; 1536];
                let (received, source) = rx.recv_from(&mut input)?;
                assert_eq!(source, expected_source);
                let (opened, bytes) = open(receiver, &input[..received])?;
                assert_eq!(opened.class, class);
                assert_eq!(bytes, body);
            }
        }
        assert_eq!(left.local_addr()?, left_address);
        assert_eq!(left.peer_addr()?, right_address);
        assert_eq!(right.local_addr()?, right_address);
        assert_eq!(right.peer_addr()?, left_address);
    }
    Ok(())
}

#[test]
fn explicit_directional_scopes_share_user_numbers_replay_and_generations() -> Result<()> {
    for appearance in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        for protection in [
            security::Protection::ChaCha20Poly1305,
            security::Protection::HmacSha256,
        ] {
            let (mut left, mut right) = peers(appearance, protection)?;
            let next = scope(11, 0xe1);
            left.stage_data(next)?;
            right.stage_data(next)?;
            let mut old_packet = None;
            let mut new_packet = None;
            for index in 0..20_u64 {
                // Old-policy sources coexist with new receiver-policy feedback.
                let selected = if index % 2 == 0 { data() } else { next };
                let body = [index as u8, 0x81, 0xff, 0, 0];
                let capacity = left.capacity(body.len())?;
                let mut workspace = vec![0; capacity.seal_workspace_bytes];
                let mut packet = vec![0; capacity.packet_bytes];
                let sealed = left.seal_user_in(
                    selected,
                    outer(index as u32),
                    &body,
                    &mut workspace,
                    &mut packet,
                )?;
                assert_eq!(sealed.number.0, index);
                assert_eq!(sealed.generation.0, index / 8);
                if index == 0 {
                    old_packet = Some(packet.clone());
                }
                if index == 1 {
                    new_packet = Some(packet.clone());
                }
                let (opened, actual) = open(&mut right, &packet)?;
                assert_eq!(opened.scope, selected);
                assert_eq!(opened.number, sealed.number);
                assert_eq!(opened.generation, sealed.generation);
                assert_eq!(actual, body);
                if index == 7 {
                    left.activate_data(next)?;
                    right.activate_data(next)?;
                    let (_, management) = seal(&mut left, Class::Control, b"fixed control\0")?;
                    assert_eq!(open(&mut right, &management)?.0.scope, control());
                    for replay in [&old_packet, &new_packet] {
                        let replay = replay.as_ref().ok_or("missing replay fixture")?;
                        assert!(open(&mut right, replay).is_err());
                    }
                }
            }
            assert_eq!(left.next_number(Class::User).0, 20);
            left.retire_data(data())?;
            right.retire_data(data())?;
            let mut workspace = [0xa5; 64];
            let mut packet = [0xa5; 128];
            assert_eq!(
                left.seal_user_in(data(), outer(22), b"old", &mut workspace, &mut packet),
                Err(Error::Scope)
            );
            assert_eq!(left.next_number(Class::User).0, 20);
            assert_eq!(workspace, [0xa5; 64]);
            assert_eq!(packet, [0xa5; 128]);
        }
    }
    Ok(())
}

#[test]
fn explicit_scope_preflight_cannot_substitute_digest_or_burn_a_number() -> Result<()> {
    let (mut left, _) = peers(
        cover::Appearance::MediaLike,
        security::Protection::ChaCha20Poly1305,
    )?;
    let staged = scope(11, 0xe1);
    left.stage_data(staged)?;
    let mut workspace = [0xa5; 128];
    let mut packet = [0xa5; 256];
    for rejected in [scope(11, 0xe2), scope(12, 0xe1), scope(1, 0xc0)] {
        assert_eq!(
            left.seal_user_in(rejected, outer(1), b"x", &mut workspace, &mut packet),
            Err(Error::Scope)
        );
        assert_eq!(left.next_number(Class::User).0, 0);
        assert_eq!(workspace, [0xa5; 128]);
        assert_eq!(packet, [0xa5; 256]);
    }
    assert_eq!(
        left.seal_user_in(staged, outer(1), b"x", &mut [], &mut packet),
        Err(Error::OutputTooSmall)
    );
    assert_eq!(left.next_number(Class::User).0, 0);
    left.cancel_staged_data(staged)?;
    assert_eq!(
        left.seal_user_in(staged, outer(1), b"x", &mut workspace, &mut packet),
        Err(Error::Scope)
    );
    assert_eq!(left.next_number(Class::User).0, 0);
    Ok(())
}
