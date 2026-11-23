use super::*;

fn message(kind: u8, slot: u8, value: u8) -> Message {
    Message {
        kind,
        slot,
        challenge: [value; 16],
    }
}

fn send(state: &mut State, slot: u8, now: u64, kind: u8) -> Result<Message> {
    let msg = state.due(slot, now)?.ok_or(Error::Payment)?;
    assert_eq!(msg.kind, kind);
    state.paid(slot, msg, now)?;
    Ok(msg)
}

#[test]
fn wire_is_exact_and_path_challenge_and_first_payment_bind_each_echo() -> Result<()> {
    let mut state = State::new(vec![[7; 16], [9; 16]], 10)?;
    let wire = message(ECHO, 0, 7).encode();
    assert_eq!(wire.len(), 18);
    assert_eq!(&wire[..2], &[0xa5, 0]);
    assert_eq!(&wire[2..], &[7; 16]);
    for n in 0..wire.len() {
        assert_eq!(
            state.receive_authenticated(0, &wire[..n], 10),
            Err(Error::Packet)
        );
    }
    assert_eq!(
        state.receive_authenticated(0, &[0xa1; 18], 10),
        Err(Error::Packet)
    );
    assert_eq!(
        state.receive_authenticated(0, &[0xa4; 19], 10),
        Err(Error::Packet)
    );
    assert_eq!(state.receive_authenticated(1, &wire, 10), Err(Error::Path));
    assert_eq!(
        state.receive_authenticated(2, &message(ECHO, 2, 7).encode(), 10),
        Err(Error::Path)
    );
    state.receive_authenticated(0, &wire, 10)?;
    assert_eq!(state.verified, 0);
    send(&mut state, 0, 11, REQUEST)?;
    state.receive_authenticated(0, &message(ECHO, 0, 9).encode(), 12)?;
    assert_eq!(state.verified, 0);
    state.receive_authenticated(0, &wire, 13)?;
    state.receive_authenticated(0, &wire, 14)?;
    assert_eq!(state.verified, 1);
    assert!(!state.ready());
    assert_eq!(state.lanes[0].duplicate_echoes, 1);
    assert_eq!(state.lanes[0].unmatched_echoes, 2);
    assert_eq!(state.check(13), Err(Error::Clock));
    Ok(())
}

#[test]
fn a_lost_reply_is_served_after_the_peer_is_ready() -> Result<()> {
    let mut a = State::new(vec![[1; 16], [2; 16]], 0)?;
    let mut b = State::new(vec![[3; 16], [4; 16]], 0)?;
    // Deliver the requests in reverse lane order while every path is still unverified.
    for slot in [1, 0] {
        let ar = send(&mut a, slot, 0, REQUEST)?;
        let br = send(&mut b, slot, 0, REQUEST)?;
        a.receive_authenticated(slot, &br.encode(), 0)?;
        b.receive_authenticated(slot, &ar.encode(), 0)?;
    }
    assert_eq!((a.verified, b.verified), (0, 0));
    for slot in [0, 1] {
        let ae = send(&mut a, slot, 10, ECHO)?;
        let be = send(&mut b, slot, 10, ECHO)?;
        b.receive_authenticated(slot, &ae.encode(), 10)?;
        if slot == 0 {
            a.receive_authenticated(slot, &be.encode(), 10)?;
        }
    }
    assert!(b.ready());
    assert!(!a.ready());
    assert_eq!(a.path_wake(1, 20)?, Some(RETRY_US));
    assert_eq!(b.path_wake(1, 20)?, None);
    let ar = send(&mut a, 1, RETRY_US, REQUEST)?;
    b.receive_authenticated(1, &ar.encode(), RETRY_US + 10)?;
    let reply = send(&mut b, 1, RETRY_US + 10, ECHO)?;
    a.receive_authenticated(1, &reply.encode(), RETRY_US + 20)?;
    assert!(a.ready());
    assert_eq!(a.setup_deadline(), None);
    assert!(a.status()["paths"][1]["rtt_us"].is_null());
    assert_eq!(b.lanes[1].echoes_paid, 2);
    Ok(())
}

#[test]
fn blocked_output_never_starts_a_timer_and_overtaken_frozen_retries_stay_accountable() -> Result<()>
{
    let mut s = State::new(vec![[1; 16]], 100)?;
    let original = s.due(0, 100)?.ok_or(Error::Payment)?;
    assert_eq!(s.due(0, 40_100)?, Some(original));
    assert_eq!(s.lanes[0].requests_paid, 0);
    s.paid(0, original, 40_100)?;
    assert_eq!(s.path_wake(0, 40_100)?, Some(130_100));
    assert_eq!(s.setup_deadline(), Some(SETUP_TIMEOUT_US + 100));
    assert_eq!(s.paid(0, original, 40_101), Err(Error::Payment));
    let frozen = s.due(0, 130_100)?.ok_or(Error::Payment)?;
    s.receive_authenticated(0, &message(ECHO, 0, 1).encode(), 130_105)?;
    s.paid(0, frozen, 130_110)?;
    assert!(s.ready());
    assert_eq!(s.lanes[0].requests_paid, 2);
    assert_eq!(s.status()["paths"][0]["rtt_us"], 90_005);
    assert_eq!(s.path_wake(0, 130_110)?, None);
    Ok(())
}

#[test]
fn original_deadline_and_payment_caps_survive_duplicates_and_changed_peer_challenges() -> Result<()>
{
    let mut silent = State::new(vec![[1; 16]], 0)?;
    for i in 0..MAX_REQUESTS {
        send(&mut silent, 0, u64::from(i) * RETRY_US, REQUEST)?;
    }
    assert_eq!(silent.path_wake(0, SETUP_TIMEOUT_US - 1)?, None);
    assert_eq!(silent.check(SETUP_TIMEOUT_US), Err(Error::Deadline));
    assert_eq!(
        silent.receive_authenticated(0, &message(ECHO, 0, 1).encode(), SETUP_TIMEOUT_US),
        Err(Error::Deadline)
    );
    assert!(!silent.ready());

    let mut s = State::new(vec![[1; 16]], 0)?;
    send(&mut s, 0, 0, REQUEST)?;
    s.receive_authenticated(0, &message(ECHO, 0, 1).encode(), 1)?;
    let request = message(REQUEST, 0, 8).encode();
    for i in 0..MAX_ECHOES {
        let now = SETUP_TIMEOUT_US + u64::from(i) * ECHO_INTERVAL_US;
        s.receive_authenticated(0, &request, now)?;
        s.receive_authenticated(0, &request, now)?;
        s.receive_authenticated(0, &message(REQUEST, 0, 9).encode(), now)?;
        let reply = send(&mut s, 0, now, ECHO)?;
        assert_eq!(reply.challenge, [8; 16]);
        assert_eq!(s.due(0, now)?, None);
    }
    let after = SETUP_TIMEOUT_US + u64::from(MAX_ECHOES) * ECHO_INTERVAL_US;
    s.receive_authenticated(0, &request, after)?;
    assert_eq!(s.path_wake(0, after)?, None);
    assert_eq!(s.lanes[0].changed_challenges, u64::from(MAX_ECHOES));
    assert_eq!(s.lanes[0].echoes_paid, MAX_ECHOES);
    Ok(())
}

#[test]
fn duplicate_requests_during_an_unpaid_echo_coalesce_and_both_directions_get_service() -> Result<()>
{
    let mut state = State::new(vec![[1; 16]], 0)?;
    let peer_request = message(REQUEST, 0, 2).encode();
    state.receive_authenticated(0, &peer_request, 0)?;
    let echo = state.due(0, 0)?.ok_or(Error::Payment)?;
    assert!(echo.is_echo());
    state.receive_authenticated(0, &peer_request, 1)?;
    assert_eq!(state.due(0, 1)?, Some(echo));
    state.paid(0, echo, 2)?;
    state.receive_authenticated(0, &peer_request, 3)?;
    send(&mut state, 0, 3, REQUEST)?;
    assert_eq!(state.path_wake(0, 3)?, Some(2 + ECHO_INTERVAL_US));
    assert_eq!(state.due(0, 1 + ECHO_INTERVAL_US)?, None);
    assert_eq!(send(&mut state, 0, 2 + ECHO_INTERVAL_US, ECHO)?, echo);
    assert_eq!(state.lanes[0].echoes_paid, 2);
    assert_eq!(state.lanes[0].requests_paid, 1);
    assert_eq!(
        state.path_wake(0, 2 + ECHO_INTERVAL_US)?,
        Some(3 + RETRY_US)
    );
    Ok(())
}

#[test]
fn invalid_configuration_and_time_are_rejected_before_egress() {
    assert!(matches!(
        State::new(Vec::new(), 0),
        Err(Error::Configuration)
    ));
    assert!(matches!(
        State::new(vec![[0; 16]; 256], 0),
        Err(Error::Configuration)
    ));
    assert!(matches!(
        State::new(vec![[0; 16]; 2], 0),
        Err(Error::Configuration)
    ));
    assert!(matches!(
        State::new(vec![[0; 16]], u64::MAX),
        Err(Error::Clock)
    ));
}
