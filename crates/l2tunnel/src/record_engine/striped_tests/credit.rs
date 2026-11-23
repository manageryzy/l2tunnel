use super::*;

#[test]
fn prepared_member_quotes_its_exact_wire_credit_until_physical_reservation() -> TestResult {
    let mut client = Engine::new_functional(
        fixture()?,
        context(Role::Client),
        geometry(),
        NativeLimits {
            stall_micros: 50_000,
        },
    )?;
    client.enable_compact_wire(31)?;
    client.enqueue_borrowed(Tick(0), &packet(true, 5100, 54, 1))?;
    client.admit_borrowed(Tick(0))?;
    let mut bytes = [0xd7; 1500];
    let mut witnesses = [receiver::UnitWitness {
        identity: receiver::RecordIdentity {
            channel: receiver::ChannelId(0),
            record: receiver::RecordId(0),
        },
        index: 0,
        count: 1,
    }; 4];
    let mut now = Tick(0);
    let mut quote = None;
    for _ in 0..16 {
        let mut empty = OutboundBudget {
            packets: 1,
            wire_bytes: 0,
        };
        assert_eq!(
            client.poll(now, 7, true, &mut bytes, &mut empty, &mut witnesses)?,
            None
        );
        quote = client.ready_rolling_data_wire_bytes()?;
        if quote.is_some() {
            break;
        }
        now = client
            .wake_at()?
            .ok_or("no first packing or seal deadline")?;
        assert!(now.0 <= 20_000);
    }
    let cost = quote.ok_or("a sealed member must expose a price while credit is short")?;
    assert!(cost > geometry().forward_overhead_bytes);
    let before = OutboundBudget {
        packets: 1,
        wire_bytes: cost - 1,
    };
    let mut short = before;
    assert_eq!(
        client.poll(now, 8, true, &mut bytes, &mut short, &mut witnesses)?,
        None
    );
    assert_eq!(short, before);
    assert_eq!(bytes, [0xd7; 1500]);
    assert!(client.pending_carrier_output().is_none());
    assert_eq!(client.ready_rolling_data_wire_bytes()?, Some(cost));
    // Eligibility now depends on the external bucket. No timer may spin on
    // the already prepared member while it waits for the last byte.
    assert!(client.wake_at()?.is_none_or(|at| at > now));
    let mut enough = OutboundBudget {
        packets: 1,
        wire_bytes: cost,
    };
    let at = Tick(now.0 + 1);
    let output = client
        .poll(at, 9, true, &mut bytes, &mut enough, &mut witnesses)?
        .ok_or("payable mixed member")?;
    assert_eq!(output.wire_bytes, cost);
    assert_eq!(output.bytes + geometry().forward_overhead_bytes, cost);
    assert_eq!(
        enough,
        OutboundBudget {
            packets: 0,
            wire_bytes: 0
        }
    );
    assert_eq!(client.ready_rolling_data_wire_bytes()?, None);
    let token = client
        .pending_carrier_output()
        .ok_or("retained physical token")?;
    client.confirm_carrier_output(at, token)?;
    Ok(())
}
