//! Live-tuning proposal and judgment on a real common profile
//! (docs/modules/live-tuning.md, LT-03).
use super::*;
use crate::secure_udp::live_tuning::{self as tuning, Policy};
use l2tunnel::live_tuning::{Choices, Limits, Refusal, Repair};
use l2tunnel_security::Role as Side;

fn requested() -> Result<Profile> {
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    profile(
        l2tunnel_udp_control::Path {
            client: "127.0.0.1:41000".parse()?,
            server: "127.0.0.1:41001".parse()?,
        },
        l2tunnel_cover::Appearance::QuicLike,
        member.public_key(),
    )
}

fn choices() -> Choices {
    Choices {
        repair: vec![Repair::Off],
        device_mtu: vec![1280],
        path_mtu: vec![],
    }
}

#[test]
fn server_derives_the_client_catalog_and_both_keep_the_base_identity() -> Result {
    let base = requested()?;
    let client = base.clone().with_tuning(Policy {
        choices: Some(choices()),
        ..Policy::default()
    });
    let proposal = tuning::proposal(&client)?.ok_or("no proposal")?;
    // The plan's three entries plus FEC off and inner size 1280 around the
    // Swift initial entry: {1/3, off} x {1500, 1280} adds three.
    assert_eq!(proposal.catalog.descriptors().len(), 3 + 3);
    let (catalog, root) = tuning::judge(&base, Side::Responder, &proposal.bytes)?;
    assert_eq!(catalog, proposal.catalog);
    assert_eq!(root, proposal.root);
    for role in [Side::Initiator, Side::Responder] {
        let tuned = base.with_live_catalog(catalog.clone())?;
        let contract = tuned.runtime_contract(role)?;
        assert_eq!(contract.catalog(), &catalog);
        assert_eq!(
            contract.expected_configuration(),
            base.runtime_contract(role)?.expected_configuration()
        );
        assert_eq!(tuned.establish_config(role)?, base.establish_config(role)?);
    }
    // No choices, no proposal.
    assert!(tuning::proposal(&base)?.is_none());
    Ok(())
}

#[test]
fn server_limits_refuse_with_the_exact_reason() -> Result {
    let base = requested()?;
    let bytes = choices().encode()?;
    let with = |policy: Policy| base.clone().with_tuning(policy);
    let refused =
        |profile: &Profile, bytes: &[u8]| tuning::judge(profile, Side::Responder, bytes).err();
    let narrow = with(Policy {
        limits: Limits {
            device_mtu: (1400, 1500),
            ..Limits::PROTOCOL
        },
        ..Policy::default()
    });
    assert_eq!(refused(&narrow, &bytes), Some(Refusal::DeviceMtuLimit));
    let few = with(Policy {
        limits: Limits {
            max_entries: 4,
            ..Limits::PROTOCOL
        },
        ..Policy::default()
    });
    assert_eq!(refused(&few, &bytes), Some(Refusal::Entries));
    let small = with(Policy {
        memory_cap: Some(1),
        ..Policy::default()
    });
    assert_eq!(refused(&small, &bytes), Some(Refusal::Memory));
    assert_eq!(refused(&base, b"garbage"), Some(Refusal::Encoding));
    let rate = Choices {
        repair: vec![Repair::Rate {
            numerator: 1,
            denominator: 2,
        }],
        ..Choices::default()
    }
    .encode()?;
    let capped = with(Policy {
        limits: Limits {
            max_repair: (1, 3),
            ..Limits::PROTOCOL
        },
        ..Policy::default()
    });
    assert_eq!(refused(&capped, &rate), Some(Refusal::RepairLimit));
    // Inner size 60 is below what any packet needs.
    let tiny = Choices {
        device_mtu: vec![60],
        ..Choices::default()
    }
    .encode()?;
    assert_eq!(refused(&base, &tiny), Some(Refusal::DeviceMtuLimit));
    Ok(())
}
