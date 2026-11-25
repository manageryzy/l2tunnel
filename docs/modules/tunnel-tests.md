# Tunnel speed and ping tests

Status: in design and implementation. The pure endpoint crate and the
service/API/CLI/GUI belong to the GUI/CLI session. The framing flag and
runtime hook (TT-02) were the protocol-core session's; with no protocol
session running, the owner had the GUI/CLI session take them (2026-11-24).

## Owner decisions (2026-11-24)

The owner asked: "add speedtest (specify tcp streaming) / ping test button on
gui and service first, then add a merge step".

1. The answering side's responder is always on while a session is connected,
   with no setting.
2. The test uses the tunnel's own components, never the host network stack.
   Owner: "you should use internal tun compoments to simulate tcp rather than
   using host network stack". This supersedes an earlier answer for real
   kernel TCP to the peer's tunnel address. That design would also have
   bypassed the tunnel on a single machine, because Linux delivers traffic to
   any local address over loopback.
3. Hook: the runtime's native path. Test packets enter where TUN/TAP
   packets enter, pass the same queue and MUX admission, and are taken out
   on the peer before its TUN/TAP. Chosen over a service-side device
   wrapper, which would need an epoll descriptor and would work on Unix only.
4. Recognition: a flag in the tunnel framing, outside the IP packet. Chosen
   over a reserved benchmark range and over an address advertised on the
   control channel. No IP address is reserved or exchanged, and test packets
   never reach either side's TUN/TAP device or the host stack.

5. Flag placement (owner, 2026-11-24, after the protocol-core session handed
   TT-02 back): a "test" tag in each protocol's own per-packet record form
   (swift beside literal/delta, and the aligned, packed and other forms'
   equivalents), so test packets take exactly the same queue, MUX admission,
   ARQ and FEC as user traffic and measure the selected protocol. Chosen
   over a third secure-record class (would skip the protocol's ARQ/FEC) and
   over a prefix byte on every packet (grows every user packet and breaks
   header compression). User packets are unchanged in size; each wire change
   carries Python simulator parity and golden vectors. TT-02 is now this
   session's work, protocol by protocol, swift first.
   **Withdrawn the same day.** The owner objected to changing a protocol's
   wire format for a speed test ("why you direct change swift protocol.
   It's just a speed test."). A swift edit was started and reverted to the
   committed file. Above the protocol codecs nothing writes per-packet
   bytes, so decision 4 (a framing flag) cannot be met without protocol
   changes; recognition is being decided again.
6. Recognition, replacing decision 4 (owner, 2026-11-24): the test lives in
   the upper layers (runtime and record engine) on both ends, and the
   protocols carry test packets unchanged. "talk with each other before
   test, negotiate a testing blackhole address for ping and bw testing":
   before each test the two sides agree on the test addresses over the
   authenticated control channel; while the test runs, the responder's
   runtime takes packets to the agreed address before its TUN/TAP device
   (a blackhole for user traffic), and nothing is captured outside a test.
7. Addresses (owner, 2026-11-24): "select random private address nobody
   use". The tester draws a fresh random pair from private (RFC 1918)
   space that no interface or route on its host uses, and proposes it; the
   responder refuses a pair that its host uses, and the tester retries with
   a new pair (bounded). A new pair for every test.

## Design

The test lives in the upper layers of both ends. The data protocols (swift,
aligned, packed, rolling, ...) carry its packets unchanged, as ordinary
native packets.

- **Pure endpoint crate** `l2tunnel-tunnel-test` (tier 1: no Tokio, clocks
  or OS handles; time is injected). Each side runs one smoltcp interface
  (`medium-ip`) on the test's agreed [`Addresses`](../../crates/l2tunnel-tunnel-test/src/addresses.rs).
  - Tester: TCP streams for the speed test, ICMP echo for ping.
  - Responder: TCP listeners on port 5201 (discard or source) and an ICMP
    socket that answers the tester's echo identifier. smoltcp's
    `auto-icmp-echo-reply` stays off: Cargo feature unification would make
    every smoltcp interface in the binary (TCP proxy, raw TCP, pipeline)
    answer pings. TCP uses Reno; enabling CUBIC would change the TCP-proxy
    engines' default controller the same way.
  - [`control::Message`](../../crates/l2tunnel-tunnel-test/src/control.rs):
    the 24-byte pre-test exchange (Offer, Accept, Refuse, End).
- **Pre-test exchange** on the authenticated control channel: session
  control `ProfileControl` tag `TunnelTestV1` (4), carried on the Liveness
  stream in Control scope next to Ping/Pong, never on the Transaction
  stream. The tester draws a random private (RFC 1918) pair that no
  interface or main-table route on its host uses, and offers it; the
  responder refuses a pair its host uses (`AddressInUse`), and the tester
  offers a new pair, at most 8 times. An offer unanswered for 3 s fails the
  test. Either side sends End when the test is over.
- **Runtime test port** (`l2tunnel-runtime`,
  [transport_tunnel_tests.rs](../../crates/l2tunnel-runtime/src/secure_udp/transport_tunnel_tests.rs)),
  one per Common session loop:
  - outgoing test packets are admitted through the same bank entry as
    device reads (`enqueue_borrowed`, or `ingest_borrowed_at` for
    connection-record scopes), so they share MUX admission, the channel
    budget and the protocol's ARQ/FEC; at most 64 per loop turn, and a
    refused packet is offered again first;
  - at the device write, a packet for this end's active test address goes
    to the endpoint instead of the TUN device; nothing is captured outside a
    test, and a responder with no traffic for 40 s is released;
  - the loop wakes at the endpoints' next timer.
  - The test MTU is the current protocol's native packet bound.
  - TUN (IP) sessions only for now; a TAP session reports the capability
    unavailable and refuses offers.
- **Service, API, CLI, GUI**: `test_start`, `test_get`, `test_cancel` on the
  running Common session's `CommonControlHandle`; `l2tunnelctl test`; the
  GUI panel. The service installs the host address check (Linux:
  `/proc/net/fib_trie` local addresses and `/proc/net/route`).

Compatibility: both ends need a build with tunnel tests. An older peer
does not know the `TunnelTestV1` tag; it rejects the control envelope, which
ends its session. Start tests only against peers on a build with this
feature.

## Test wire (inside the internal TCP connection)

- Request header, 16 bytes: `L2TS`, version `1`, mode (`1` upload, `2`
  download), two reserved zero bytes, `duration_ms` (u32 big-endian,
  1000..=30000), and four reserved zero bytes. Any other header resets the
  connection.
- Upload: the responder discards until the tester's FIN, then sends the
  received byte count (u64 big-endian) and closes. The result counts what
  arrived.
- Download: the responder sends zero bytes for the duration, then closes.
  The tester counts what arrived.
- Ping: ICMP echo between the internal addresses.

## Bounds

- Responder: 8 TCP sockets; each connection lives at most 32 s; 256 KiB
  buffers per socket; at most 256 queued outbound packets per endpoint.
- Tests: one at a time per service. Speed: 1..=8 streams, 1..=30 s, at most
  30 one-second samples. Ping: 1..=100 probes, 100..=1000 ms apart, 1 s
  timeout each. A test fails when its session ends. The last test stays
  readable until the next one starts.

## Local API (version 5 additions)

These are new actions. Existing replies gain only the optional `test`
field, which older clients never request.

- `test_start {test}`: `test` is `{kind:"speed", direction:"upload"|
  "download", streams, duration_ms}` or `{kind:"ping", count,
  interval_ms}`. Replies `accepted` with the test state. It is refused with
  `busy`, `not_connected`, `invalid_test` or `unsupported`.
- `test_get {id?, timeout_ms}`: the latest test, or test `id`. It waits at
  most `timeout_ms` (≤ the wait limit) for completion.
- `test_cancel {id}`.

The reply field `test` holds `{test?}`:
- `test` is `{id, kind, state (running|completed|failed|cancelled),
  direction?, streams?, duration_ms?, elapsed_ms, bytes, bits_per_second,
  samples (bit/s per second), ping?, error?}`.
- `ping` is `{sent, received, min_us?, avg_us?, max_us?, rtts_us[]}`.

The capability is `tests`. It stays unavailable, with a reason, until the
runtime hook exists.

CLI: `l2tunnelctl test speed [--download] [--streams N] [--seconds S]
[--watch]`, `l2tunnelctl test ping [--count N] [--interval-ms MS] [--watch]`,
`l2tunnelctl test status [ID]` and `l2tunnelctl test cancel ID`.

GUI: a "Test the tunnel" panel on the Connection page. It has a speed test
(direction, streams, seconds, Start, live chart and result) and a ping test
(count, Start, round-trip times and loss).

## Tasks

- [x] [TT-01] Pure endpoint crate: smoltcp tester and responder on internal addresses, test wire, bounds; unit-tested back to back with loss. Evidence: [crate](../../crates/l2tunnel-tunnel-test/src/lib.rs), [back-to-back tests](../../crates/l2tunnel-tunnel-test/src/tests.rs) (`cargo test -p l2tunnel-tunnel-test`: 6 passed on 2026-11-24, simulated 120 Mbit/s link measured within bounds for upload and download, 2% loss, 20 ms ping round trips, total loss, no responder, cancel, bad headers and garbage packets); Clippy clean.
- [x] [TT-02] Pre-test address exchange on the control channel and runtime test port through native admission (owner decisions 6 and 7 replaced the framing flag). Evidence: [port](../../crates/l2tunnel-runtime/src/secure_udp/transport_tunnel_tests.rs) and its [back-to-back tests](../../crates/l2tunnel-runtime/src/secure_udp/transport_tunnel_tests_tests.rs) (`cargo test -p l2tunnel-runtime --lib tunnel_tests`: 4 passed on 2026-11-24: speed and ping complete on negotiated addresses, a pair the peer uses is refused and replaced, an unanswered offer times out, cancel, session end, TAP refusal, malformed control ignored), [control grammar](../../crates/l2tunnel-tunnel-test/src/control.rs) and [addresses](../../crates/l2tunnel-tunnel-test/src/addresses.rs) (`cargo test -p l2tunnel-tunnel-test`: 9 passed), `cargo test -p l2tunnel-management`: 146 passed; Clippy clean.
- [ ] [TT-03] Local API `test_start`/`test_get`/`test_cancel`, capability `tests`, CLI `l2tunnelctl test`, fake-service parity. Status: API types ([tunnel_test.rs](../../crates/l2tunnel-client-core/src/local/tunnel_test.rs)), CLI ([cli_groups_test.rs](../../crates/l2tunnel-client-core/src/cli_groups_test.rs)) and fake-service simulation are implemented and contract-tested (`tools.test_fake_local_service`: start, follow, busy, cancel, usage). The real service now maps them onto the running Common session ([tunnel_tests_local.rs](../../crates/l2tunnel-client-core/src/service/tunnel_tests_local.rs)) and reports the capability with the session's reason when unavailable.
- [ ] [TT-04] GUI panel on the Connection page. Status: [implemented](../../crates/l2tunnel-desktop-ui/src/test_panel.rs) and checked by screenshots against the fake service (live progress and chart, ping round trips with lost probes, cancel); real-service use waits for TT-02.
- [ ] [TT-05] Real run through a connected session. Status: unprivileged end to end passed: two real services joined by real loopback UDP with in-memory devices (`tunnel_tests_cross_the_real_session_and_never_reach_a_device`, 2026-11-24, debug build, fixture plan): upload 6.9 Mbit/s and download 3.6 Mbit/s over 2 streams, ping 5/5 at 8.1-9.3 ms, and no test packet reached either device. The installed system service still runs the earlier binary; a run through it needs the owner to reinstall the service.

## Executed checks (2026-11-24, local Linux, unprivileged)

- `cargo test -p l2tunnel-tunnel-test`: 9 passed. `-p l2tunnel-management`:
  146 passed. `-p l2tunnel-runtime --lib`: 394 passed.
  `-p l2tunnel-desktop-ui`: 24 passed.
- `cargo test -p l2tunnel-client-core --lib`: 262 passed, 1 ignored, with
  `RUST_MIN_STACK=4194304`. At the default 2 MiB test stack,
  `generic_apply_waiter_replay_catalog_and_replacement_preserve_one_actual_switch`
  overflows. Its body is documented as a ~400 KB debug future held just
  under that limit. It still overflowed with every tunnel-test hook removed
  from the loop and the service (bisected by hand), so the cause was not
  isolated; it is recorded here, not fixed.
- Clippy (`--no-deps`, `-D warnings`) clean on tunnel-test, management,
  runtime, client-core and desktop-ui; rustfmt clean on the edited files.
- Not run: the installed system service still runs the earlier binary, and
  replacing it was not permitted in this session, so no test has crossed
  the owner's real TUN pair yet.

## Late test packets (fix, 2026-11-24)

Under load the service test `tunnel_tests_cross_the_real_session_and_never_reach_a_device`
failed with a test packet on the native device: retransmissions arriving
after a test ended were no longer captured and went to the TUN device. Each
end now keeps discarding packets for an ended test's address for 10 s
(`LINGER`, at most 4 ended addresses), on the tester and the responder side;
after that nothing is captured, as before. Evidence:
[port](../../crates/l2tunnel-runtime/src/secure_udp/transport_tunnel_tests.rs)
and [unit test](../../crates/l2tunnel-runtime/src/secure_udp/transport_tunnel_tests_tests.rs)
(late packets discarded on both ends, passed through after the linger);
`RUST_MIN_STACK=4194304 cargo test -p l2tunnel-client-core --lib` three
clean runs after the fix.
