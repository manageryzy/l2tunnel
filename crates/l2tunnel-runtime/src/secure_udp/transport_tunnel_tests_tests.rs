use super::*;

const MTU: usize = 1500;

/// Two ports joined directly: control messages and test packets pass
/// unchanged, as the tunnel would carry them.
struct Pair {
    client: Port,
    server: Port,
    client_shared: Arc<Shared>,
    server_shared: Arc<Shared>,
    now: Duration,
}
impl Pair {
    fn new() -> Self {
        let client_shared = Arc::new(Shared::default());
        let server_shared = Arc::new(Shared::default());
        let mut client = Port::new(PacketLayer::Ip, 1);
        let mut server = Port::new(PacketLayer::Ip, 2);
        client.attach(client_shared.clone());
        server.attach(server_shared.clone());
        Self {
            client,
            server,
            client_shared,
            server_shared,
            now: Duration::ZERO,
        }
    }
    /// One millisecond of both loops; returns packets that reached a device.
    fn step(&mut self) -> usize {
        let now = self.now;
        let mut leaked = 0;
        self.client.poll(now, MTU);
        self.server.poll(now, MTU);
        while let Some(message) = self.client.take_message() {
            self.server.receive(&message.encode(), now, MTU);
        }
        while let Some(message) = self.server.take_message() {
            self.client.receive(&message.encode(), now, MTU);
        }
        for _ in 0..INJECT_PER_TURN {
            match self.client.next_packet() {
                Some(packet) => leaked += usize::from(!self.server.capture(&packet, now)),
                None => break,
            }
        }
        for _ in 0..INJECT_PER_TURN {
            match self.server.next_packet() {
                Some(packet) => leaked += usize::from(!self.client.capture(&packet, now)),
                None => break,
            }
        }
        self.now += Duration::from_millis(1);
        leaked
    }
    fn run_until_done(&mut self, limit: Duration) -> Result<TunnelTestReport, String> {
        while self.now < limit {
            assert_eq!(self.step(), 0, "a test packet reached a device");
            if let Some(report) = self.client_shared.report()
                && !report.active()
            {
                return Ok(report);
            }
        }
        Err(format!("still running: {:?}", self.client_shared.report()))
    }
}

#[test]
fn speed_and_ping_tests_negotiate_addresses_and_complete() -> Result<(), String> {
    let mut pair = Pair::new();
    let id = pair
        .client_shared
        .start(TunnelTestRequest::Speed {
            direction: Direction::Download,
            streams: 2,
            duration: Duration::from_secs(2),
        })
        .map_err(|error| format!("{error:?}"))?;
    assert_eq!(
        pair.client_shared.start(TunnelTestRequest::Ping {
            count: 1,
            interval: Duration::from_millis(100)
        }),
        Err(TunnelTestRefusal::Busy)
    );
    let report = pair.run_until_done(Duration::from_secs(10))?;
    assert_eq!(report.id, id);
    assert_eq!(report.phase, TunnelTestPhase::Completed, "{report:?}");
    let addresses = report.addresses.ok_or("agreed addresses")?;
    assert!(l2tunnel_tunnel_test::usable(addresses.tester));
    assert!(l2tunnel_tunnel_test::usable(addresses.responder));
    let progress = report.progress.ok_or("progress")?;
    assert!(progress.bits_per_second() > 0, "{progress:?}");
    // The responder is released by the End message.
    for _ in 0..5 {
        pair.step();
    }
    assert!(pair.server.responder.is_none());
    // Late packets of the ended test are discarded for a while on both
    // ends, never delivered to the device; after that nothing is captured.
    let stray = |address: std::net::Ipv4Addr| {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[16..20].copy_from_slice(&address.octets());
        packet
    };
    assert!(pair.client.capture(&stray(addresses.tester), pair.now));
    assert!(pair.server.capture(&stray(addresses.responder), pair.now));
    let later = pair.now + super::LINGER;
    assert!(!pair.client.capture(&stray(addresses.tester), later));
    assert!(!pair.server.capture(&stray(addresses.responder), later));

    pair.client_shared
        .start(TunnelTestRequest::Ping {
            count: 5,
            interval: Duration::from_millis(100),
        })
        .map_err(|error| format!("{error:?}"))?;
    let report = pair.run_until_done(Duration::from_secs(20))?;
    assert_eq!(report.phase, TunnelTestPhase::Completed, "{report:?}");
    let Some(l2tunnel_tunnel_test::Measurement::Ping(ping)) =
        report.progress.map(|progress| progress.measurement)
    else {
        return Err("ping measurement".into());
    };
    assert_eq!(ping.sent, 5);
    assert!(ping.rtts.iter().all(Option::is_some), "{ping:?}");
    Ok(())
}

#[test]
fn addresses_the_peer_uses_are_refused_and_replaced() -> Result<(), String> {
    let mut pair = Pair::new();
    // The server's host uses every address of the first offers.
    let refused = Arc::new(Mutex::new(Vec::<Ipv4Addr>::new()));
    let seen = refused.clone();
    pair.server_shared.set_check(Arc::new(move |address| {
        let mut seen = seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if seen.len() < 4 {
            seen.push(address);
            true
        } else {
            false
        }
    }));
    pair.client_shared
        .start(TunnelTestRequest::Ping {
            count: 2,
            interval: Duration::from_millis(100),
        })
        .map_err(|error| format!("{error:?}"))?;
    let report = pair.run_until_done(Duration::from_secs(10))?;
    assert_eq!(report.phase, TunnelTestPhase::Completed, "{report:?}");
    let addresses = report.addresses.ok_or("addresses")?;
    let refused = refused.lock().map_err(|_| "lock")?.clone();
    assert!(
        !refused.contains(&addresses.responder),
        "a refused pair was reused"
    );
    Ok(())
}

#[test]
fn unanswered_offers_cancel_and_session_end_fail_cleanly() -> Result<(), String> {
    // A peer that never answers (an older build): the offer times out.
    let shared = Arc::new(Shared::default());
    let mut lonely = Port::new(PacketLayer::Ip, 3);
    lonely.attach(shared.clone());
    shared
        .start(TunnelTestRequest::Ping {
            count: 1,
            interval: Duration::from_millis(100),
        })
        .map_err(|error| format!("{error:?}"))?;
    lonely.poll(Duration::ZERO, MTU);
    assert!(matches!(lonely.take_message(), Some(Message::Offer { .. })));
    lonely.poll(ANSWER_WAIT, MTU);
    let report = shared.report().ok_or("report")?;
    assert_eq!(report.phase, TunnelTestPhase::Failed);
    assert!(report.error.unwrap_or_default().contains("did not answer"));

    // Cancel while running.
    let mut pair = Pair::new();
    let id = pair
        .client_shared
        .start(TunnelTestRequest::Speed {
            direction: Direction::Upload,
            streams: 1,
            duration: Duration::from_secs(5),
        })
        .map_err(|error| format!("{error:?}"))?;
    for _ in 0..200 {
        pair.step();
    }
    assert!(pair.client_shared.cancel(id));
    for _ in 0..5 {
        pair.step();
    }
    let report = pair.client_shared.report().ok_or("report")?;
    assert_eq!(report.phase, TunnelTestPhase::Cancelled);
    assert!(!pair.client_shared.cancel(id), "already over");

    // The session ends during a test: the report fails, new starts refuse.
    pair.client_shared
        .start(TunnelTestRequest::Ping {
            count: 50,
            interval: Duration::from_millis(100),
        })
        .map_err(|error| format!("{error:?}"))?;
    for _ in 0..50 {
        pair.step();
    }
    let Pair {
        client,
        client_shared,
        ..
    } = pair;
    drop(client);
    let report = client_shared.report().ok_or("report")?;
    assert_eq!(report.phase, TunnelTestPhase::Failed);
    assert!(matches!(
        client_shared.start(TunnelTestRequest::Ping {
            count: 1,
            interval: Duration::from_millis(100)
        }),
        Err(TunnelTestRefusal::Unavailable(_))
    ));
    Ok(())
}

#[test]
fn tap_sessions_and_malformed_control_are_refused_without_failure() -> Result<(), String> {
    let shared = Arc::new(Shared::default());
    let mut tap = Port::new(PacketLayer::Ethernet, 4);
    tap.attach(shared.clone());
    assert!(matches!(
        shared.start(TunnelTestRequest::Ping {
            count: 1,
            interval: Duration::from_millis(100)
        }),
        Err(TunnelTestRefusal::Unavailable(_))
    ));
    let offer = Message::Offer {
        id: 9,
        addresses: Addresses {
            tester: Ipv4Addr::new(10, 9, 9, 1),
            responder: Ipv4Addr::new(10, 9, 9, 2),
        },
    };
    tap.receive(&offer.encode(), Duration::ZERO, MTU);
    assert_eq!(
        tap.take_message(),
        Some(Message::Refuse {
            id: 9,
            reason: Refusal::Unavailable
        })
    );
    tap.receive(b"garbage", Duration::ZERO, MTU);
    assert_eq!(tap.malformed(), 1);
    assert!(tap.take_message().is_none());
    Ok(())
}
