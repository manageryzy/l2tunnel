//! Finite denial/ownership checks; privileged packet opening is a separate probe.
use super::*;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;

const MARK: u32 = 0x12aa0001;

fn config() -> Config {
    Config {
        local: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 2), 24440),
        peer: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 6), 24441),
        mtu: 1200,
        send_bytes: 65536,
        receive_bytes: 65536,
        packet_slots: 64,
        random_seed: 1,
        ack_delay_millis: 10,
        keepalive_millis: 1000,
        idle_timeout_millis: 30000,
    }
}

#[test]
fn packet_open_zero_mark_rejects_before_config_or_external_inspection() {
    let mut invalid = config();
    invalid.mtu = usize::MAX;
    for role in [Role::Client, Role::Server] {
        for config in [config(), invalid] {
            let error = crate::open_packet_marked(config, role, 0).err();
            assert_eq!(
                error.as_ref().map(io::Error::kind),
                Some(io::ErrorKind::InvalidInput)
            );
            assert_eq!(
                error.as_ref().map(ToString::to_string).as_deref(),
                Some("owned raw mark must be nonzero")
            );
        }
    }
}

#[test]
fn all_openers_reject_invalid_bounds_before_namespace_policy_or_socket_io() {
    let valid = config();
    let mut cases = Vec::new();
    for local in [true, false] {
        for address in [
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 24440),
            SocketAddrV4::new(Ipv4Addr::BROADCAST, 24440),
            SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 1), 24440),
            SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 2), 0),
        ] {
            let mut changed = valid;
            if local {
                changed.local = address;
            } else {
                changed.peer = address;
            }
            cases.push(changed);
        }
    }
    cases.push(Config {
        peer: valid.local,
        ..valid
    });
    for mtu in [0, 575, 65536, usize::MAX] {
        cases.push(Config { mtu, ..valid });
    }
    for bytes in [0, 1199, 4_194_305, usize::MAX] {
        cases.push(Config {
            send_bytes: bytes,
            ..valid
        });
        cases.push(Config {
            receive_bytes: bytes,
            ..valid
        });
    }
    for packet_slots in [0, 1025, usize::MAX] {
        cases.push(Config {
            packet_slots,
            ..valid
        });
    }
    cases.push(Config {
        random_seed: 0,
        ..valid
    });
    cases.push(Config {
        ack_delay_millis: 201,
        ..valid
    });
    for keepalive_millis in [0, 30000, u64::MAX] {
        cases.push(Config {
            keepalive_millis,
            ..valid
        });
    }
    for idle_timeout_millis in [999, 120001, u64::MAX] {
        cases.push(Config {
            idle_timeout_millis,
            ..valid
        });
    }
    for role in [Role::Client, Role::Server] {
        for invalid in &cases {
            // The original typed error proves config validation won before any
            // namespace, subprocess or descriptor error could replace it.
            for error in [
                crate::open_packet_marked(*invalid, role, MARK).err(),
                open_marked(*invalid, role, MARK).err(),
                open(*invalid, role).err(),
            ] {
                assert_eq!(
                    error
                        .as_ref()
                        .and_then(io::Error::get_ref)
                        .and_then(|inner| inner.downcast_ref::<l2tunnel_raw_tcp::Error>()),
                    Some(&l2tunnel_raw_tcp::Error::InvalidConfig),
                    "config: {invalid:?}, error: {error:?}"
                );
            }
        }
    }
}

#[test]
fn namespace_denial_and_exact_tuple_policy_do_not_admit_neighbors() -> io::Result<()> {
    assert_eq!(
        validate_namespace(42, 42).err().map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    validate_namespace(43, 42)?;
    let mark = owned_mark(MARK)?;
    let valid = config();
    let target = marked_target(valid, mark);
    let policy = format!("-P OUTPUT ACCEPT\n{target}\n");
    validate_marked_policy(&policy, &target, mark)?;
    for changed in [
        Config {
            local: valid.peer,
            peer: valid.local,
            ..valid
        },
        Config {
            local: SocketAddrV4::new(*valid.local.ip(), 24442),
            ..valid
        },
        Config {
            peer: SocketAddrV4::new(*valid.peer.ip(), 24442),
            ..valid
        },
        Config {
            local: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 3), valid.local.port()),
            ..valid
        },
        Config {
            peer: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 7), valid.peer.port()),
            ..valid
        },
    ] {
        assert_eq!(
            validate_marked_policy(&policy, &marked_target(changed, mark), mark)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
    }
    let wrong_mark = owned_mark(MARK ^ 1)?;
    assert!(validate_marked_policy(&policy, &target, wrong_mark).is_err());
    Ok(())
}

#[test]
fn original_unmarked_port_reservation_survives_move_and_releases_on_drop() -> io::Result<()> {
    // A loopback ephemeral port tests the actual shared reservation helper
    // without a raw descriptor, namespace change or elevated capability.
    let reservation = reserve_port(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
    let local = reservation
        .local_addr()?
        .as_socket_ipv4()
        .ok_or_else(|| io::Error::other("missing reservation tuple"))?;
    let original = reservation.as_raw_fd();
    assert_eq!(reservation.mark()?, 0);
    let moved = Some(reservation);
    assert_eq!(moved.as_ref().map(AsRawFd::as_raw_fd), Some(original));
    assert_eq!(
        reserve_port(local).err().map(|error| error.kind()),
        Some(io::ErrorKind::AddrInUse)
    );
    drop(moved);
    let replacement = reserve_port(local)?;
    assert_eq!(replacement.local_addr()?.as_socket_ipv4(), Some(local));
    Ok(())
}

#[test]
#[ignore = "requires explicit owned network namespace and marked exact-tuple policy"]
fn packet_descriptor_from_birth() -> io::Result<()> {
    if std::env::var("L2T_RAW_DIAG_ALLOWED").as_deref() != Ok("owned-policy-v1") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "owned diagnostic harness required",
        ));
    }
    let config = config();
    let original: crate::RawSocket = crate::open_packet_marked(config, Role::Client, MARK)?;
    let descriptor = original.raw.as_raw_fd();
    let reservation = original._reservation.as_raw_fd();
    assert_eq!(original.raw.mark()?, MARK);
    assert_eq!(original._reservation.mark()?, 0);
    assert_eq!(
        original._reservation.local_addr()?.as_socket_ipv4(),
        Some(config.local)
    );
    assert_eq!(
        original
            .raw
            .local_addr()?
            .as_socket_ipv4()
            .map(|addr| *addr.ip()),
        Some(*config.local.ip())
    );
    let input = crate::handoff::pairing::RawInput {
        config,
        io: original,
    };
    assert_eq!(input.io.raw.as_raw_fd(), descriptor);
    assert_eq!(input.io._reservation.as_raw_fd(), reservation);
    assert_eq!(input.io.ports, (config.local.port(), config.peer.port()));
    assert_eq!(
        input.io.peer.as_socket_ipv4(),
        Some(SocketAddrV4::new(*config.peer.ip(), 0))
    );
    assert_eq!(
        reserve_port(config.local).err().map(|error| error.kind()),
        Some(io::ErrorKind::AddrInUse)
    );
    drop(input);
    let released = reserve_port(config.local)?;
    assert_eq!(released.mark()?, 0);
    // No PacketIo call, TCP poll, TLS setup or background driver ran. Captured
    // full/half startup qualification is intentionally a separate native gate.
    Ok(())
}
