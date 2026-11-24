//! RRP-06: receiver hole-abandonment triggers over real research output.
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn config(profile: Profile, abandon_ticks: u64) -> Result<Config, Error> {
    let window = profile.minimum_window()?.max(64);
    Ok(Config {
        recovery: rolling::Config {
            window,
            local_window: window,
            global_every: 16,
            max_payload: 8,
            max_rows: 64,
            repair_history: 64,
            handoff_sources: window,
            job_ticks: 1_000,
            debt_ticks: 10_000,
            handoff_ticks: 5_000,
            memory_bytes: rolling::MAX_MEMORY,
        },
        profile,
        feedback_ticks: 5,
        memory_bytes: rolling::MAX_MEMORY,
        abandon_ticks,
    })
}

fn scope() -> Scope {
    Scope {
        session: [43; 16],
        epoch: 4,
        stream: 1,
        direction: 0,
    }
}

fn budget() -> WorkBudget {
    WorkBudget {
        field: 65_536,
        copies: 65_536,
        metadata: 65_536,
    }
}

fn payload(id: u32) -> [u8; 3] {
    [id as u8, 0x5a, (id >> 8) as u8 + 1]
}

/// Every output of `sources` originals, in send order, all created at zero.
fn outputs(config: Config, sources: u32) -> Result<Vec<(OutputId, Vec<u8>)>, Error> {
    let mut sender = Sender::new(config, scope(), Tick(0))?;
    let mut list = Vec::new();
    let drain = |sender: &mut Sender, list: &mut Vec<_>| -> Result<(), Error> {
        for _ in 0..10_000 {
            if let Some(output) = sender.pending_output() {
                let id = output.id();
                let mut bytes = vec![0; output.encoded_len()];
                let written = sender.encode_pending(&mut bytes)?;
                bytes.truncate(written);
                sender.confirm_output(id, Tick(0))?;
                list.push((id, bytes));
            } else if sender.step(Tick(0), budget())? == WorkUsed::default() {
                return Ok(());
            }
        }
        Err(Error::WorkLimit)
    };
    for id in 0..sources {
        sender.admit_source(&payload(id), Tick(0), Tick(0))?;
        drain(&mut sender, &mut list)?;
    }
    Ok(list)
}

fn deliver(receiver: &mut Receiver, bytes: &[u8], now: Tick) -> Result<(), Error> {
    receiver.receive_wire(bytes, now)?;
    settle(receiver, now)
}

fn settle(receiver: &mut Receiver, now: Tick) -> Result<(), Error> {
    for _ in 0..1_000 {
        receiver.step(now, budget())?;
        if !receiver.status().decoder.pending_job {
            receiver.step(now, budget())?;
            return Ok(());
        }
    }
    Err(Error::WorkLimit)
}

fn hand_off(receiver: &mut Receiver, now: Tick) -> Result<Vec<u32>, Error> {
    let mut handed = Vec::new();
    while let Some((id, bytes)) = receiver.pending_source() {
        assert_eq!(bytes, payload(id.0));
        handed.push(id.0);
        receiver.confirm_handoff(id, now)?;
    }
    Ok(handed)
}

fn is_source(id: OutputId, wanted: impl Fn(u32) -> bool) -> bool {
    matches!(id, OutputId::Source(SourceId(source)) if wanted(source))
}

fn accumulator() -> Profile {
    Profile::Accumulator {
        lanes: 2,
        window: 8,
    }
}

#[test]
fn cap_abandons_an_unrepaired_hole_and_the_rest_is_handed_off() -> TestResult {
    let config = config(accumulator(), 100)?;
    let mut receiver = Receiver::new(config, scope(), Tick(0))?;
    // Source 0 and every repair are lost.
    for (id, bytes) in outputs(config, 10)? {
        if is_source(id, |source| source != 0) {
            deliver(&mut receiver, &bytes, Tick(0))?;
        }
    }
    assert_eq!(hand_off(&mut receiver, Tick(0))?, Vec::<u32>::new());
    // The reverse path took the earlier receipt (prefix 0).
    let earlier = receiver.pending_feedback().ok_or("no receipt")?;
    assert_eq!(earlier.prefix, 0);
    receiver.confirm_feedback(earlier.id, Tick(0))?;
    assert_eq!(receiver.abandon_wake(), Some(Tick(100)));
    settle(&mut receiver, Tick(99))?;
    assert_eq!(receiver.status().abandoned_by, AbandonReasons::default());
    // The quiet receiver repeated the prefix-0 receipt meanwhile.
    let repeat = receiver.pending_feedback().ok_or("no repeat")?;
    assert_eq!(repeat.prefix, 0);
    receiver.confirm_feedback(repeat.id, Tick(99))?;
    assert!(receiver.abandon_due(Tick(100)));
    settle(&mut receiver, Tick(100))?;
    let status = receiver.status();
    assert_eq!(status.abandoned_by.cap, 1);
    assert_eq!(status.abandon.abandoned, 1);
    assert_eq!(status.hole, None);
    assert_eq!(
        hand_off(&mut receiver, Tick(100))?,
        (1..10).collect::<Vec<_>>()
    );
    // The sender learns the new prefix from the next receipt, one
    // feedback_ticks interval after the repeat taken at 99.
    settle(&mut receiver, Tick(104))?;
    let feedback = receiver.pending_feedback().ok_or("no receipt")?;
    assert_eq!(feedback.prefix, 10);
    assert_eq!(status.terminal, None);
    Ok(())
}

#[test]
fn repairable_loss_is_recovered_and_never_abandoned() -> TestResult {
    let config = config(accumulator(), 100)?;
    let mut receiver = Receiver::new(config, scope(), Tick(0))?;
    for (id, bytes) in outputs(config, 20)? {
        if !is_source(id, |source| source == 3) {
            deliver(&mut receiver, &bytes, Tick(0))?;
        }
    }
    settle(&mut receiver, Tick(500))?;
    assert_eq!(
        hand_off(&mut receiver, Tick(500))?,
        (0..20).collect::<Vec<_>>()
    );
    let status = receiver.status();
    assert_eq!(status.abandon, rolling::AbandonStatus::default());
    assert_eq!(status.abandoned_by, AbandonReasons::default());
    Ok(())
}

#[test]
fn definite_abandons_once_recursive_spans_pass_the_hole() -> TestResult {
    let profile = Profile::Recursive {
        taps: 1,
        width: 2,
        reset: 2,
        fresh_interval: 0,
    };
    // A cap far beyond the test: only the definite trigger can fire.
    let config = config(profile, 9_000)?;
    let mut receiver = Receiver::new(config, scope(), Tick(0))?;
    let mut definite_seen = false;
    for (id, bytes) in outputs(config, 40)? {
        match id {
            OutputId::Source(SourceId(0)) => {}
            // Every repair whose span still includes source 0 is lost.
            OutputId::Repair(RepairId(serial))
                if profile.support(40, 0, serial as u32)?.start == 0 => {}
            _ => {
                deliver(&mut receiver, &bytes, Tick(1))?;
                definite_seen |= receiver.status().abandoned_by.definite > 0;
            }
        }
    }
    assert!(definite_seen);
    let status = receiver.status();
    assert_eq!(status.abandoned_by.definite, 1);
    assert_eq!(
        (status.abandoned_by.cap, status.abandoned_by.projected),
        (0, 0)
    );
    assert_eq!(
        hand_off(&mut receiver, Tick(1))?,
        (1..40).collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
fn projected_abandons_when_the_deficit_cannot_close_in_time() -> TestResult {
    let config = config(accumulator(), 50)?;
    let mut receiver = Receiver::new(config, scope(), Tick(0))?;
    let list = outputs(config, 10)?;
    // Sources 0..5 are lost; 5..10 arrive at once.
    for (id, bytes) in &list {
        if is_source(*id, |source| source >= 5) {
            deliver(&mut receiver, bytes, Tick(0))?;
        }
    }
    // The first repair covers [0, 5) and arrives ten ticks later: one rank
    // per ten ticks against a remaining deficit of four exceeds the cap.
    let (_, repair) = list
        .iter()
        .find(|(id, _)| matches!(id, OutputId::Repair(RepairId(1))))
        .ok_or("no first repair")?;
    deliver(&mut receiver, repair, Tick(10))?;
    let status = receiver.status();
    assert_eq!(status.abandoned_by.projected, 1);
    assert_eq!(status.abandoned_by.cap, 0);
    assert_eq!(status.abandon.dropped_rows, 1);
    // The remaining holes of the same cohort keep its age and reach the cap.
    assert_eq!(receiver.abandon_wake(), Some(Tick(50)));
    settle(&mut receiver, Tick(50))?;
    assert_eq!(receiver.status().abandoned_by.cap, 4);
    assert_eq!(
        hand_off(&mut receiver, Tick(50))?,
        (5..10).collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
fn zero_abandon_ticks_disables_abandonment() -> TestResult {
    let config = config(accumulator(), 0)?;
    let mut receiver = Receiver::new(config, scope(), Tick(0))?;
    for (id, bytes) in outputs(config, 10)? {
        if is_source(id, |source| source != 0) {
            deliver(&mut receiver, &bytes, Tick(0))?;
        }
    }
    assert_eq!(receiver.abandon_wake(), None);
    // Within the unconfirmed receipt's own output deadline (job_ticks).
    settle(&mut receiver, Tick(900))?;
    assert!(!receiver.abandon_due(Tick(900)));
    assert_eq!(receiver.status().abandon.abandoned, 0);
    Ok(())
}

/// Owner decision 2026-11-24: after input goes quiet the receiver repeats its
/// latest receipt a bounded number of times at doubling intervals, so a lost
/// final receipt cannot leave a window-blocked sender waiting forever.
#[test]
fn quiet_receiver_repeats_its_last_receipt_a_bounded_number_of_times() -> TestResult {
    let config = config(accumulator(), 0)?;
    let mut receiver = Receiver::new(config, scope(), Tick(0))?;
    for (id, bytes) in outputs(config, 10)? {
        if is_source(id, |_| true) {
            deliver(&mut receiver, &bytes, Tick(0))?;
        }
    }
    assert_eq!(hand_off(&mut receiver, Tick(0))?.len(), 10);
    // Drain receipts (rate-limited by feedback_ticks) until the final one.
    let mut now = 0;
    let first = loop {
        settle(&mut receiver, Tick(now))?;
        if let Some(feedback) = receiver.pending_feedback() {
            receiver.confirm_feedback(feedback.id, Tick(now))?;
            if feedback.prefix == 10 {
                break feedback;
            }
        }
        now += 5;
        assert!(now < 100, "final receipt never sent");
    };
    let repeats = receiver.status().receipt_repeats;
    let mut times = Vec::new();
    while let Some(wake) = receiver.service_wake() {
        // Nothing is repeated before the wake.
        settle(&mut receiver, Tick(wake.0 - 1))?;
        assert!(receiver.pending_feedback().is_none());
        assert!(!receiver.service_due(Tick(wake.0 - 1)));
        assert!(receiver.service_due(wake));
        settle(&mut receiver, wake)?;
        let repeat = receiver.pending_feedback().ok_or("no repeat")?;
        assert_eq!(
            (repeat.prefix, repeat.observed_end),
            (first.prefix, first.observed_end)
        );
        assert!(repeat.id > first.id);
        receiver.confirm_feedback(repeat.id, wake)?;
        times.push(wake.0 - now);
        now = wake.0;
        assert!(times.len() <= 8, "{times:?}");
    }
    // 4x, 8x, 16x, then 64x feedback_ticks (5) until eight repeats.
    assert_eq!(times, [20, 40, 80, 160, 320, 320, 320, 320]);
    assert_eq!(receiver.status().receipt_repeats - repeats, 8);
    settle(&mut receiver, Tick(now + 10_000))?;
    assert!(receiver.pending_feedback().is_none());
    assert_eq!(receiver.status().terminal, None);
    Ok(())
}
