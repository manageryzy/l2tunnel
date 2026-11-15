use super::*;
use crate::{fec::rolling, management::Role};
use l2tunnel_codec::aligned_receiver as receiver;
use l2tunnel_reliable::OutboundBudget;

#[test]
fn actual_rolling_carrier_tokens_bind_bank_before_time_and_never_ack_on_poll()
-> Result<(), Box<dyn std::error::Error>> {
    let config =
        crate::record_engine::rolling_tests::fixture(false, rolling::wire::SourceWire::Exact)?;
    let plan = engine::storage::Plan::for_engine(
        config,
        engine::Context {
            session: 0x1234_5678_9012_3456,
            epoch: 7,
            role: Role::Client,
        },
        engine::Geometry {
            forward_overhead_bytes: 17,
            reverse_overhead_bytes: 73,
        },
        engine::NativeLimits {
            stall_micros: 50_000,
        },
    )?;
    let mut bank = tests::bank(plan, 0)?;
    let mut foreign = tests::bank(plan, 0)?;
    let id = bank.initial();
    let other = foreign.initial();
    let original_usage = bank.usage();
    let work = rolling::WorkBudget {
        field: 65_536,
        copies: 65_536,
        metadata: 65_536,
    };
    let mut output = [0; 1500];
    let mut witnesses = [receiver::UnitWitness {
        identity: receiver::RecordIdentity {
            channel: receiver::ChannelId(0),
            record: receiver::RecordId(0),
        },
        index: 0,
        count: 1,
    }; 4];
    let packet = tests::packet(0x5b);
    for (owner, generation) in [(&mut bank, id), (&mut foreign, other)] {
        let mut entry = owner.entry(generation)?;
        entry.enqueue_borrowed(engine::Tick(0), &packet)?;
        entry
            .admit_borrowed(engine::Tick(0))?
            .ok_or("actual rolling admission")?;
        assert!(entry.step(engine::Tick(1000), work)?.is_some());
        let mut budget = OutboundBudget {
            packets: 1,
            wire_bytes: 1500,
        };
        let emitted = entry
            .poll(
                engine::Tick(1000),
                (1u64 << 59) + 7,
                true,
                &mut output,
                &mut budget,
                &mut witnesses,
            )?
            .ok_or("actual rolling emission")?;
        assert_eq!(
            entry
                .pending_carrier_output()
                .ok_or("actual rolling token")?
                .emission(),
            emitted
        );
        assert_eq!(budget.packets, 0);
    }
    let foreign_token = foreign
        .entry(other)?
        .pending_carrier_output()
        .ok_or("foreign token")?;
    assert_eq!(
        bank.entry(id)?
            .confirm_carrier_output(engine::Tick(u64::MAX), foreign_token),
        Err(Error::Stale)
    );
    bank.entry(id)?.tick(engine::Tick(1000))?;
    let mut entry = bank.entry(id)?;
    let token = entry.pending_carrier_output().ok_or("original token")?;
    let duplicate = entry.pending_carrier_output().ok_or("retained token")?;
    assert_eq!(token.generation(), id);
    let mut untouched = [0x87; 1500];
    let mut budget = OutboundBudget {
        packets: 0,
        wire_bytes: 0,
    };
    assert_eq!(
        entry.poll(
            engine::Tick(1000),
            u64::MAX,
            false,
            &mut untouched,
            &mut budget,
            &mut witnesses
        )?,
        Some(token.emission())
    );
    assert_eq!(untouched, [0x87; 1500]);
    assert_eq!(
        budget,
        OutboundBudget {
            packets: 0,
            wire_bytes: 0
        }
    );
    entry.confirm_carrier_output(engine::Tick(1000), token)?;
    assert!(entry.pending_carrier_output().is_none());
    assert_eq!(
        entry.confirm_carrier_output(engine::Tick(1000), duplicate),
        Err(Error::Engine(engine::Error::Token))
    );
    assert_eq!(bank.usage(), original_usage);
    assert!(matches!(bank.retire(id), Err(Error::NotDrained)));
    Ok(())
}
