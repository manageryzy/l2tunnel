//! Local API tunnel tests (TT-03, docs/modules/tunnel-tests.md) on the
//! running Common session's runtime handle.
use super::{Handle, ObservedBackend};
use crate::local::OperationReply;
use crate::local::tunnel_test::{
    Direction, PingResult, SAMPLE_LIMIT, TestPhase, TestReply, TestRequest, TestState,
};
use l2tunnel_runtime::secure_udp::transport::{
    CommonControlHandle, TunnelTestPhase, TunnelTestRefusal, TunnelTestReport, TunnelTestRequest,
};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Why tests cannot run, when they cannot.
pub(super) fn unavailable(handle: &Handle) -> Option<String> {
    match tests_handle(handle) {
        Ok(tests) => tests.tunnel_test_unavailable(),
        Err(reason) => Some(reason.into()),
    }
}

fn tests_handle(handle: &Handle) -> Result<CommonControlHandle, &'static str> {
    let state = handle.0.lock();
    match &state.backend {
        Some(ObservedBackend::SecureUdpCommon(backend)) => {
            let tests = backend.switcher.clone();
            tests.tunnel_test_address_check(Arc::new(host_uses));
            Ok(tests)
        }
        Some(ObservedBackend::Proxy(_)) => {
            Err("tunnel tests run on Common sessions; this session uses the TCP proxy backend")
        }
        None => Err("connect first: tunnel tests run on a connected session"),
    }
}

fn request(test: &TestRequest) -> TunnelTestRequest {
    match *test {
        TestRequest::Speed {
            direction,
            streams,
            duration_ms,
        } => TunnelTestRequest::Speed {
            direction: match direction {
                Direction::Upload => l2tunnel_tunnel_test::Direction::Upload,
                Direction::Download => l2tunnel_tunnel_test::Direction::Download,
            },
            streams,
            duration: Duration::from_millis(u64::from(duration_ms)),
        },
        TestRequest::Ping { count, interval_ms } => TunnelTestRequest::Ping {
            count,
            interval: Duration::from_millis(u64::from(interval_ms)),
        },
    }
}

fn micros(duration: Duration) -> u32 {
    u32::try_from(duration.as_micros()).unwrap_or(u32::MAX)
}

/// Local API view of a runtime report.
pub(crate) fn state(report: &TunnelTestReport) -> TestState {
    let progress = report.progress.as_ref();
    let mut state = TestState {
        id: report.id,
        kind: match report.request {
            TunnelTestRequest::Speed { .. } => "speed",
            TunnelTestRequest::Ping { .. } => "ping",
        }
        .into(),
        state: match report.phase {
            TunnelTestPhase::Negotiating | TunnelTestPhase::Running => TestPhase::Running,
            TunnelTestPhase::Completed => TestPhase::Completed,
            TunnelTestPhase::Failed => TestPhase::Failed,
            TunnelTestPhase::Cancelled => TestPhase::Cancelled,
        },
        direction: None,
        streams: None,
        duration_ms: None,
        elapsed_ms: progress.map_or(0, |p| {
            u64::try_from(p.elapsed.as_millis()).unwrap_or(u64::MAX)
        }),
        bytes: 0,
        bits_per_second: progress.map_or(0, l2tunnel_tunnel_test::Progress::bits_per_second),
        samples: Vec::new(),
        ping: None,
        error: report.error.clone(),
    };
    match report.request {
        TunnelTestRequest::Speed {
            direction,
            streams,
            duration,
        } => {
            state.direction = Some(match direction {
                l2tunnel_tunnel_test::Direction::Upload => Direction::Upload,
                l2tunnel_tunnel_test::Direction::Download => Direction::Download,
            });
            state.streams = Some(streams);
            state.duration_ms = Some(u32::try_from(duration.as_millis()).unwrap_or(u32::MAX));
        }
        TunnelTestRequest::Ping { .. } => state.ping = Some(PingResult::default()),
    }
    match progress.map(|p| &p.measurement) {
        Some(l2tunnel_tunnel_test::Measurement::Speed { bytes, samples, .. }) => {
            state.bytes = *bytes;
            state.samples = samples.iter().copied().take(SAMPLE_LIMIT).collect();
        }
        Some(l2tunnel_tunnel_test::Measurement::Ping(ping)) => {
            let mut result = PingResult {
                sent: ping.sent,
                rtts_us: ping.rtts.iter().map(|rtt| rtt.map(micros)).collect(),
                ..PingResult::default()
            };
            result.summarize();
            state.ping = Some(result);
        }
        None => {}
    }
    state
}

impl Handle {
    fn test_reply(&self, report: Option<TunnelTestReport>, ok: bool, code: &str) -> OperationReply {
        OperationReply {
            test: Some(Box::new(TestReply {
                test: report.as_ref().map(state),
            })),
            ..OperationReply::code(ok, code, self.service_id())
        }
    }
    pub(super) fn test_start(&self, test: &TestRequest) -> OperationReply {
        if test.validate().is_err() {
            return OperationReply::code(false, "invalid_test", self.service_id());
        }
        let tests = match tests_handle(self) {
            Ok(tests) => tests,
            Err(_) => return OperationReply::code(false, "not_connected", self.service_id()),
        };
        match tests.tunnel_test_start(request(test)) {
            Ok(_) => self.test_reply(tests.tunnel_test_report(), true, "accepted"),
            Err(TunnelTestRefusal::Busy) => {
                self.test_reply(tests.tunnel_test_report(), false, "busy")
            }
            Err(TunnelTestRefusal::Unavailable(_)) => {
                OperationReply::code(false, "unsupported", self.service_id())
            }
        }
    }
    pub(super) async fn test_get(&self, id: Option<u64>, timeout_ms: u32) -> OperationReply {
        let Ok(tests) = tests_handle(self) else {
            return self.test_reply(None, false, "not_connected");
        };
        let until = Instant::now() + Duration::from_millis(u64::from(timeout_ms.min(30_000)));
        loop {
            let report = tests.tunnel_test_report();
            if let Some(id) = id
                && report.as_ref().is_none_or(|report| report.id != id)
            {
                return self.test_reply(None, false, "unknown_test");
            }
            if report.as_ref().is_none_or(|report| !report.active()) || Instant::now() >= until {
                return self.test_reply(report, true, "ok");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    pub(super) fn test_cancel(&self, id: u64) -> OperationReply {
        let Ok(tests) = tests_handle(self) else {
            return self.test_reply(None, false, "not_connected");
        };
        if tests.tunnel_test_cancel(id) {
            self.test_reply(tests.tunnel_test_report(), true, "ok")
        } else {
            self.test_reply(tests.tunnel_test_report(), false, "unknown_test")
        }
    }
}

/// Whether an interface address or a main-table route on this host covers
/// `address`; agreed test addresses must not shadow real ones.
#[cfg(target_os = "linux")]
fn host_uses(address: Ipv4Addr) -> bool {
    let local = std::fs::read_to_string("/proc/net/fib_trie").unwrap_or_default();
    let routes = std::fs::read_to_string("/proc/net/route").unwrap_or_default();
    local_addresses(&local).contains(&address) || routed(&routes, address)
}
#[cfg(not(target_os = "linux"))]
fn host_uses(_address: Ipv4Addr) -> bool {
    false
}

/// Host addresses (`/32 host LOCAL` leaves) in `/proc/net/fib_trie`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn local_addresses(fib_trie: &str) -> Vec<Ipv4Addr> {
    let mut found = Vec::new();
    let mut last = None;
    for line in fib_trie.lines() {
        let line = line.trim();
        if let Some(address) = line.strip_prefix("|-- ") {
            last = address.parse::<Ipv4Addr>().ok();
        } else if line.starts_with("/32 host LOCAL")
            && let Some(address) = last
            && !found.contains(&address)
        {
            found.push(address);
        }
    }
    found
}

/// Whether a non-default route in `/proc/net/route` covers `address`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn routed(table: &str, address: Ipv4Addr) -> bool {
    let target = u32::from(address);
    table.lines().skip(1).any(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (Some(destination), Some(mask)) = (fields.get(1), fields.get(7)) else {
            return false;
        };
        let (Ok(destination), Ok(mask)) = (
            u32::from_str_radix(destination, 16),
            u32::from_str_radix(mask, 16),
        ) else {
            return false;
        };
        // The kernel prints network-order words in host order.
        let destination = u32::from(Ipv4Addr::from(destination.to_ne_bytes()));
        let mask = u32::from(Ipv4Addr::from(mask.to_ne_bytes()));
        mask != 0 && target & mask == destination & mask
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_tables_are_parsed() {
        let trie = "Main:\n  +-- 0.0.0.0/0 3 0 5\n     |-- 0.0.0.0\n        /0 universe UNICAST\n  \
                    +-- 10.231.255.0/30 2 0 2\n     |-- 10.231.255.1\n        /32 host LOCAL\n";
        assert_eq!(local_addresses(trie), vec![Ipv4Addr::new(10, 231, 255, 1)]);
        let word = |a: Ipv4Addr| format!("{:08X}", u32::from_ne_bytes(a.octets()));
        let table = format!(
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
             eth0\t{}\t{}\t0003\t0\t0\t0\t{}\n\
             tun0\t{}\t00000000\t0001\t0\t0\t0\t{}\n",
            word(Ipv4Addr::UNSPECIFIED),
            word(Ipv4Addr::new(192, 168, 1, 1)),
            word(Ipv4Addr::UNSPECIFIED),
            word(Ipv4Addr::new(10, 231, 255, 0)),
            word(Ipv4Addr::new(255, 255, 255, 252)),
        );
        assert!(routed(&table, Ipv4Addr::new(10, 231, 255, 2)));
        assert!(
            !routed(&table, Ipv4Addr::new(10, 1, 2, 3)),
            "default route is ignored"
        );
        let state = state(&TunnelTestReport {
            id: 3,
            request: TunnelTestRequest::Ping {
                count: 2,
                interval: Duration::from_millis(100),
            },
            phase: TunnelTestPhase::Negotiating,
            addresses: None,
            progress: None,
            error: None,
        });
        assert_eq!(state.state, TestPhase::Running);
        assert_eq!(state.kind, "ping");
    }

    #[tokio::test]
    async fn tunnel_test_actions_report_expected_refusals_when_idle() {
        let (handle, _run) = crate::service::channel();
        assert!(unavailable(&handle).is_some());

        // Invalid test parameters are rejected before backend lookup.
        let bad_speed = handle.test_start(&TestRequest::Speed {
            direction: Direction::Upload,
            streams: 0,
            duration_ms: 1_000,
        });
        assert!(
            (!bad_speed.ok) && bad_speed.code == "invalid_test",
            "{bad_speed:?}"
        );

        let bad_ping = handle.test_start(&TestRequest::Ping {
            count: 0,
            interval_ms: 200,
        });
        assert!(
            (!bad_ping.ok) && bad_ping.code == "invalid_test",
            "{bad_ping:?}"
        );

        // Valid start/get/cancel while disconnected all return `not_connected`.
        let valid_speed = handle.test_start(&TestRequest::Speed {
            direction: Direction::Upload,
            streams: 1,
            duration_ms: 1_000,
        });
        assert!(
            (!valid_speed.ok) && valid_speed.code == "not_connected",
            "{valid_speed:?}"
        );

        let got = handle.test_get(None, 0).await;
        assert!((!got.ok) && got.code == "not_connected", "{got:?}");

        let cancelled = handle.test_cancel(1);
        assert!(
            (!cancelled.ok) && cancelled.code == "not_connected",
            "{cancelled:?}"
        );
    }
}
