# Standalone OpenVPN-like retained runtime

Status: implemented and loopback integration-tested. The retained standalone UDP
runtime carries actual verified TLS/member control and protected recovered user
packets over full or authenticated paired half lanes, without TCP sockets.
Native TAP/TUN, client selection, production qualification and FEC integration
remain separate open gates. The pure gate is described in
[the bootstrap module](standalone-openvpn.md).

A separately negotiated [native-fence capability](openvpn-native-drain.md) adds
strict OVC2 control and source admission/consumption seals. Its full/paired
factories use actual verified sessions and preserve all legacy OVC1 factories and
configuration domains. Its [client/CLI selection](openvpn-drain-client.md) has
local integration evidence; privileged native clean-close qualification remains open.

## Ownership and public API

`l2tunnel-openvpn` is a Tokio/OS runtime crate distinct from the pure protocol
libraries. The existing `l2tunnel-udp` retains a concrete TLS/TCP connection and its
own API; changing that object would conflate two different carrier capabilities.
The new crate reuses `l2tunnel-udp-control`, maintained auth factories, protected
datagrams and existing bounded selective repeat. It creates no new cipher,
handshake primitive or ARQ wire format. Initial data recovery is selective repeat;
existing Cauchy FEC profiles need an explicit later adapter and parity gate.

Implemented bounded API:

```rust
pub struct ClientCredentials<'a> {
    pub tls: &'a ClientTls,
    pub server_name: &'a str,
    pub member: &'a MemberKey,
    pub admission: udp_control::Secret,
}
pub struct ServerCredentials<'a> {
    pub tls: &'a ServerTls,
    pub members: &'a MemberAllowlist,
    pub admission: udp_control::Secret,
    pub cookie: udp_control::Secret,
}
pub async fn client_connect(socket: UdpSocket, config: Config,
    credentials: ClientCredentials<'_>) -> Result<Carrier, Error>;
pub async fn server_accept(socket: UdpSocket, config: Config,
    credentials: ServerCredentials<'_>) -> Result<Carrier, Error>;
Carrier::info() -> &SessionInfo;
Carrier::split(self) -> (Control, PacketSender, PacketReceiver);
PacketSender::send(&self, packet: &[u8]) -> Result<(), Error>;
PacketReceiver::receive(&mut self, output: &mut [u8]) -> Result<usize, Error>;
Control::status() -> Result<Status, Error>;
Control::close(self) -> Result<CloseReceipt, Error>;
```

Factories consume the caller's exact fixed-tuple socket and complete the actual
admission and TLS/member exchange before returning packet handles. No API accepts
arbitrary exporter bytes or an asserted authenticated session. Config includes
the upper `SessionConfig`, fixed client/server tuple, gate bounds, data profile,
data ARQ bounds, positive auth deadline, absolute authenticated lease, heartbeat
and inactivity durations, finite stream/application/datagram slots and bytes,
poll interval/work limit, and aggregate transmission allowance/control reserve.
All values enter one canonical digest before gate or TLS exchange. The gate's
base profile hashes that runtime policy and the upper digest; TLS then binds the
complete gate digest. Key bytes never enter public configuration metadata.

One supervised driver exclusively calls `recv_from` and owns the socket, control
engine, protected packet sealer/opener, data recovery and bounded retained output.
A bounded duplex stream connects that driver to the same actual TLS object.
The auth factory performs TLS on one end; its private success path verifies the
immutable `OpenVpnLikeTls` profile and exact config, derives purpose/direction/
lane keys from that object, and sends one private activation command. After
activation a supervised TLS task owns the same authenticated stream for internal
heartbeat/close/control frames. Public handles cannot issue activation commands.
Task guards cancel/abort owned tasks when factories fail or Control is dropped;
plain detached Tokio tasks are forbidden.

## USER recovery separation (FIX-10)

The current public `Carrier` supplies ordered recovered packets, not loss-visible
USER datagrams. This is a composition limitation, not a property of UDP or a
requirement of reliable bootstrap TLS. In the running path,
`runtime::enable_native` constructs `SelectiveRepeat`; `PacketSender::send`
queues originals for `driver::run` to submit to that engine. The sole socket
reader authenticates each data packet, then applies `inspect_packet` and
`SelectiveRepeat::receive`. Only `poll_delivered` reaches `PacketReceiver`.
`l2tunnel-runtime::openvpn` places FrameCodec/Fragmenter above this recovered
packet service. Consequently these handles cannot implement the loss-visible
`DatagramSend`/`DatagramReceive` boundary used by the UDP/QUIC aligned, packed and
rolling owners. Passing their frames through this public API would add forced
Selective Repeat underneath the selected recovery.

The private `data::ProtectedDatagrams` owner separates maintained packet
protection from USER recovery in that actual driver path. It owns the sealer,
opener and one maximum-payload receive buffer, separate from the driver's existing
fixed send scratch. This adds one bounded payload buffer and no packet queue. Its
interface is:

```text
new(send_config, actual_outbound_key, receive_config, actual_inbound_key)
open(authenticated_wire) -> borrowed exact opaque payload
reserve_maximum_send() -> checked key-use headroom, without a nonce allocation
seal(opaque_payload, caller_output) -> exact sealed packet metadata
```

Only the existing verified factory constructs it from the actual directional
Data exporters. It authenticates context and payload and commits replay state
before exposing plaintext; it does not parse recovery headers or maintain USER
source IDs, ACKs, retries or ordering. The current `DataState` still explicitly
owns a Selective Repeat adapter above that boundary. Bootstrap control reliability,
private post-pair activation, retained output slots, exact wire charging and the
original deadlines remain in their existing owners. This extraction is a private
implementation stage: it does not enable a public datagram factory or complete
FIX-10. Existing factories and their authenticated policy/wire bytes remain the
recovered-packet service.

The minimal remaining interface is an additive, explicitly selected authenticated
USER-datagram factory returning the existing control owner plus bounded sender
and receiver handles. Its sender completion must mean transfer into a retained
wire-output slot, not delivery or USER-recovery admission. Its receiver must expose
accepted datagrams independently despite loss/reordering, retaining an exact packet
on small output. Reuse the runtime's existing `DatagramParts` adapter boundary and
`l2tunnel-transport::Requirement::Datagrams`; do not add a parallel carrier enum or
claim a cover name proves those semantics. A datagram adapter must validate its
actual factory/config before satisfying that requirement. Unsupported recovery
combinations remain errors before authentication and cannot silently fall back
to the legacy recovered-packet factory.

- [ ] [MOD-OVPNRT-10] Complete FIX-10: expose a genuinely loss-visible authenticated USER-datagram service and compose selected user recovery above it, preserving reliable bootstrap control. The private extraction alone does not satisfy this parent gate.
- [x] [MOD-OVPNRT-10A] Extract the protected USER-datagram owner into the running driver and verify arbitrary non-ARQ payloads, independent loss/reordering, replay/authentication rejection, fixed storage and unchanged legacy runtime behavior. Evidence: [private owner and four boundary tests](../../crates/l2tunnel-openvpn/src/data.rs), [running driver integration](../../crates/l2tunnel-openvpn/src/driver.rs), [53-case focused crate checks and exact source receipt](../../work/openvpn-data-boundary27/validation.json). This private stage does not expose the public datagram capability required by FIX-10.
- [ ] [MOD-OVPNRT-10B] Add an explicit versioned pre-auth configuration/factory domain for USER datagrams. Bind full selected recovery, payload/feedback limits, layer, duplex, queues and shared allowance before authentication; preserve the legacy canonical domain. Do not discard the legacy `Config::arq` fields or reinterpret its source limit as a raw payload limit.
- [ ] [MOD-OVPNRT-10C] Implement bounded datagram admission/delivery and runtime adapters using the same sole socket owner. Preserve control reservation, physical-lane direction, authentic replay protection, original deadlines and immutable held output across WouldBlock; charge selected-recovery feedback and retries to the common allowance exactly once.
- [ ] [MOD-OVPNRT-10D] Move legacy Selective Repeat to an explicit upper adapter and qualify selected aligned/packed/rolling recovery over the new service with independent exact bytes, loss/reorder, feedback loss and backpressure. Sender recovery state must never be available to the receiver. Do not count a capability flag, enum or compile as integration evidence.
- [ ] [MOD-OVPNRT-10E] Bind native close fences to the selected upper recovery's actual accepted/consumed source identity. Current native fence counters are Selective Repeat source counters; draining raw datagram queues does not establish native delivery or recovered-source completion. Qualify original-deadline full/paired close before enabling that combination.

## Lease and uninterrupted state

Bootstrap has its original immutable gate deadline. Actual TLS/member completion
must occur before that deadline and within the separately bound auth timeout.
Only the runtime's private authenticated success path calls
`ControlEngine::promote_authenticated(lease, now)`. The pure method documents a
trusted-caller precondition; it does not pretend to inspect TLS membership.

The authenticated lease defaults to one hour and is positive and at most 24 hours.
Promotion is allowed once, checked before bootstrap expiry. It updates only the
absolute expiry and time watermark. The original bootstrap deadline remains
observable. Control keys, bootstrap session, outer packet sequence/replay bitmap,
ARQ source IDs/retry attempts/retained bytes and interval quotas remain intact.
Late/double/backward-time/overflow promotion fails without resetting anything.
There is no later absolute renewal or in-place rekey; exhaustion ends the session.

A second, shorter TLS inactivity deadline limits dead peers. The default heartbeat
interval must be at most one third of that timeout. Only a fresh valid internal
message actually decrypted/read from the retained TLS object renews inactivity.
Outer admission MACs, ARQ feedback, data traffic, malformed/repeated heartbeat
messages and old outer replay cannot renew it. Heartbeat frames bind session,
message kind, role and nonwrapping sequence; one outstanding request and one
bounded response slot are allowed. Absolute expiry always takes precedence.
TLS EOF/error or either supervised task failure revokes both packet handles.

## One socket, common allowance and bounded delivery

Demultiplex by the strict disjoint gate/control/data prefixes, then validate full
length, configured source tuple, role/profile/session and MAC/AEAD before recovery.
Before private activation, data datagrams are discarded without payload retention.
After activation, both cryptographic directions exist even for a one-direction
bulk lane: reverse recovery feedback is internal control. User admission checks
the lane's configured bulk direction. The initial profile fixes endpoints and
does not learn NAT rebinding, allow QUIC-like relabeling, or fall back to TCP.

All outgoing datagrams share one bounded packet/complete-IP-byte allowance per
interval, including TLS sources, control ACKs, data sources, data ACKs and every
retry. Data cannot spend a configured mandatory-control reservation. Control also
has a finite ceiling so a cooperative steady control stream cannot consume every
data slot. Reserve capacity and verify key-use headroom before polling recovery;
do not burn a recovery attempt while waiting for allowance or an output slot.
Seal a retransmission with a fresh packet number while retaining its recovery
source identity. Exact cost includes cover, common header, tag and IP/UDP bytes.
Accounting is admission to retained caller output; actual successful socket sends
are tracked separately. At most a configured fixed number of complete datagrams
may be held after admission across WouldBlock. A single blocked data output must
leave room for mandatory control.

Finite packet queues are configured by count and bytes. Admission acquires queue
capacity before cloning user bytes. The driver keeps an original packet until
recovery admission succeeds. Recovery delivery is transferred into a bounded
receiver queue only after its slot is reserved. A too-small receive output keeps
the same queued packet. `send` completion means bounded recovery admission;
`receive` transfers packet ownership, not native device acceptance. Higher layers
must separately account for native delivery. All user TCP control/probe packets
follow this same data path and configured MUX policy.

The first packet slice enforces a negotiated maximum source that fits the complete
data datagram after recovery/protection overhead. Oversize packets are explicit
errors; a production TAP/TUN adapter must compose reviewed fragmentation rather
than silently truncating a native frame. Kernel offload and path MTU qualification
remain native gates.

## Close, paired lanes and validation gates

Explicit close first freezes new user admission, then drains queued originals,
recovery obligations, receiver handoffs and retained socket output. Only then may
session-bound TLS Close/CloseAck finish. Deadline expiry or an unread application
queue is a reported failed/incomplete close, not silent successful disposal.
Dropping the control owner cancels ownership and is not a clean-drain receipt.
After local TLS EOF/shutdown, data/application drain and control-ARQ drain, the
same socket/control engine remains alive for a fixed quiet interval equal to the
negotiated control maximum RTO plus ACK delay plus two driver poll intervals.
Fresh accepted control input and newly emitted output restart quiet, never the
original absolute close deadline. `Control::close` applies that same retained
start/deadline to terminal waiting and every supervised task join; awaiting a join
never moves its handle out of the owner. Explicit checks before waiting, after
each ready join and before the final receipt also reject completion at/after the
original deadline: Tokio timeout wrappers may poll a ready child before an
already-expired timer. Cancellation or an earlier failed join
therefore aborts both the current and all not-yet-joined tasks. A peer-triggered
earlier close does not acquire a fresh timeout when the caller later closes.
This services final source retries after an
ACK was lost. A short remaining lease or close deadline can still end with an
explicit failure. This is finite retry/delay protection, not proof of remote
shutdown under arbitrary packet loss or unbounded network delay.

Implement one full-duplex lane first. Paired half duplex then joins two separately
authenticated physical lanes using actual exporter-bound member/server/config
identity and complementary direction, with finite pairing time and no cross-lane
source/key reuse. Existing UDP pairing helpers can be studied but cannot prove a
standalone capability while still containing a TCP stream. CLI selection remains disabled pending the native, TLS-allocation and provisioning
audits below.

### Paired implementation contract

`client_pair([UdpSocket; 2], [Config; 2], ClientPairCredentials)` and
`server_pair(..., ServerPairCredentials)` accept lanes in canonical order:
client-to-server bulk first, server-to-client bulk second. Each lane has a distinct
lane ID, fixed tuple, bootstrap admission key and actual TLS session. Base policy,
protection, aggregate allowance and final authenticated identities must agree.
`PairedCarrier::split()` returns a `PairControl`, the locally permitted packet
sender and the opposite lane's packet receiver. PairControl retains the inactive
handles and owns both original controls; dropping it cancels both lanes. A bounded
supervisor propagates any failed lane terminal state to its sibling. Clean close
waits for both owners and never cancels the sibling merely because one finishes
its quiet interval first.

One shared monotonic origin and one locked wire ledger are created before either
gate runs. Every gate or recovery emission checks capacity, polls and charges in
one synchronous critical section; no socket await holds the ledger lock. The
pair's aggregate counters are read from that ledger rather than adding duplicate
per-lane snapshots. Each lane also exposes its own counters; snapshots across
actors are not instantaneous. Each lane retains at most its two bounded output slots.

After genuine member authentication each private factory promotes its retained
control lease only. It does not construct data recovery, data keys or payload
scratch buffers. Both actual TLS capabilities stay private until a fixed-frame
join over the first TLS stream completes within the canonically bound pairing
deadline. The join hashes both actual session IDs, lane IDs/directions, exact
accepted configs and member/server identities. Each side contributes a fresh
16-byte random challenge. Maintained HMAC under the reverse lane's directional
LaneJoin exporter authenticates that digest, both ordered challenges and a
domain-separated HMAC under the forward lane's actual exporter. Thus another
valid forward session cannot transplant a reverse proof. Hello, Proof and Accept
have strict roles/order/length/reserved fields and phase-separated proofs; each
factory consumes the join once. Only mutual acceptance releases private data
activation and starts normal retained TLS heartbeat tasks. Failure, cancellation,
wrong identity/config/proof, replay or timeout drops both owned drivers. The
join is a project protocol over actual TLS, not an OpenVPN interoperability claim.

- [x] [MOD-OVPNRT-01] Implement approved one-shot pure lease promotion preserving transport state and rejecting late/double/time/overflow changes. Evidence: [promotion implementation](../../crates/l2tunnel-udp-control/src/control.rs), [continuity/absolute-expiry tests](../../crates/l2tunnel-udp-control/src/tests.rs).
- [x] [MOD-OVPNRT-02] Finalize canonical runtime config and private verified-auth activation API, including every queue/lease/pacing bound. Evidence: [canonical config](../../crates/l2tunnel-openvpn/src/config.rs), [private actual-auth preparation/enable](../../crates/l2tunnel-openvpn/src/runtime.rs).
- [x] [MOD-OVPNRT-03] Implement one supervised fixed-tuple socket owner and bounded duplex control IO with authenticated TLS inactivity and terminal task/error propagation. Evidence: [single reader driver](../../crates/l2tunnel-openvpn/src/driver.rs), [retained TLS heartbeat](../../crates/l2tunnel-openvpn/src/heartbeat.rs), [stale traffic/cancellation tests](../../crates/l2tunnel-openvpn/src/tests.rs).
- [x] [MOD-OVPNRT-04] Compose exporter-protected user datagrams and existing selective repeat with a common exact allowance and mandatory-control reservation. Evidence: [atomic shared ledger and reserve test](../../crates/l2tunnel-openvpn/src/budget.rs), [protected recovery driver](../../crates/l2tunnel-openvpn/src/driver.rs).
- [x] [MOD-OVPNRT-05] Prove bounded application packet ownership before native handoff, oversize/backpressure atomicity and explicit bounded close outcomes. Evidence: [retained sender/receiver permits](../../crates/l2tunnel-openvpn/src/runtime.rs), [blocked consumer, small output and final-ACK loss tests](../../crates/l2tunnel-openvpn/src/tests.rs), [quiet versus absolute expiry test](../../crates/l2tunnel-openvpn/src/driver.rs).
- [x] [MOD-OVPNRT-06] Add authenticated complementary paired half lanes without TCP, then test full/half actual payloads under loss/reorder/replay and stalled consumers. Evidence: [actual two-exporter join and paired owners](../../crates/l2tunnel-openvpn/src/pair.rs), [IPv4 impairment/IPv6 integrity and invalid joins](../../crates/l2tunnel-openvpn/src/pair/tests.rs), [full and half blocked consumer tests](../../crates/l2tunnel-openvpn/src/tests.rs).
- [x] [MOD-OVPNRT-07] Qualify fixed IPv4/IPv6 tuples, admission/certificate/member failures, timeout/cancellation, wrong-profile demux, stale outer traffic, lease/key exhaustion and strict aggregate checks. Evidence: [configuration/profile rejection](../../crates/l2tunnel-openvpn/src/config.rs), [runtime failures and deadlines](../../crates/l2tunnel-openvpn/src/tests.rs), [IPv4/IPv6 paired tests](../../crates/l2tunnel-openvpn/src/pair/tests.rs), [wave 6 aggregate](../../work/implementation-wave6/validation.json).
- [ ] [MOD-OVPNRT-08] Integrate reviewed runtime/device/client selection and owned native TAP/TUN capture/MTU tests; keep FEC and mode-parity claims separate.
- [x] [MOD-OVPNRT-09] Bound terminal waiting and all task joins by the original close deadline while preserving abort ownership during cancellation. Evidence: [close implementation and deadline/cancellation regressions](../../crates/l2tunnel-openvpn/src/runtime.rs).
- [x] [MOD-OVPNRT-09A] Reject already-ready clean state and ready task joins at/after the original close deadline, without widening the bound or changing retry/fault policy. Evidence: [close deadline investigation](../../work/openvpn-close15-review/REPORT.md), deterministic old-code failures and focused current checks. The earlier paired impairment timeout is preserved separately and is not attributed to this fix.


## Focused verification and remaining limits

The current local Linux checkpoint ran `cargo test --offline -p l2tunnel-openvpn`
(29 passing cases), targeted `cargo fmt`, `cargo clippy --offline -p
l2tunnel-openvpn --all-targets -- -D warnings`, and strict no-dependency rustdoc.
The first 24-case runtime checkpoint was included in the stable
[wave 6 aggregate](../../work/implementation-wave6/validation.json): 492 Rust cases
including doctests, 36 Python cases, full `tools/check.py`, matching source hashes.
That receipt predates the narrow close-join ownership/deadline fix and its three
new regression cases; those subsequently passed the complete 27-case crate suite,
strict Clippy and rustdoc. The stable [wave-7 aggregate](../../work/implementation-wave7/validation.json)
now includes the complete subsequent source: 549 Rust cases including doctests,
39 Python cases and matching source hashes. Auth
and pure control earlier passed 14 and 10 cases.

The subsequent MTU helper and close-ACK fixture regression bring the current
crate suite to 29 cases. A parallel 28-case run first failed the persistent
ACK-loss assertion; an isolated diagnostic rerun passed with unchanged criteria.
Static review identified a test-only trigger gap: an ACK could leave after close
initiation but before `tls_finished` activated loss. The fixture now drops ACKs
from close initiation, with a direct regression for that interval. Production
close deadlines and clean-drain criteria were not relaxed. The original failure
is retained as an observation, not claimed to be conclusively attributed.

Actual paired tests use four UDP sockets and independent payloads, with IPv4 AEAD
under deterministic loss/reordering/duplicates and IPv6 integrity-only packet
protection. TLS remains encrypted in either mode. Fault injection is test-only,
bounded to one delayed packet per actor, and does not qualify native network or
throughput behavior. Separate cases cover real wrong admission/name/member,
post-cookie cancellation and rebind proof, second-lane failure releasing all four
socket owners, stale outer traffic with fresh data, absolute lease/key exhaustion,
invalid/swapped identities/config/roles, forward-exporter transplantation, wrong
reverse proof, phase replay and join timeout. Small-buffer and stalled-consumer
cases retain exact packet bytes/permits. One and three lost final ACKs still
complete cleanly; persistent final ACK loss returns incomplete within the original
deadline. The latter behavior corrects the initially observed paired close race.

The runtime fixes one peer tuple per physical lane. It has no wildcard listener,
NAT rebinding, reconnect or in-place rekey. The separate [device adapter](openvpn-device.md)
now supplies reviewed frame fragmentation and bounded native ownership; the
[shared client](openvpn-client.md) supplies explicit CLI selection, private key
provisioning and the pinned TLS resource review. Platform checks, native
captures/MTU and FEC/mode-parity gates remain open.

## Snapshot15 close investigation

The [close investigation](../../work/openvpn-close15-review/REPORT.md) preserves
the snapshot15 paired impairment failure: data and TLS were drained, but the
socket driver had not published clean before the original owner deadline. Four
instrumented baseline reproductions passed under unchanged deadline/impairment
settings; the original receipt lacks the final control/quiet timestamps needed
for conclusive attribution. A 3.009-second quiet interval inside a five-second
close bound cannot promise clean completion if final activity occurs after
1.991 seconds. A pure regression pins that finite exhaustion rather than
resetting or enlarging the close deadline.

The investigation separately proved and fixed a ready-future deadline bypass:
an already-Clean state or completed child could return success at/after the
original deadline because the timeout wrapper polled the ready child first.
Two deterministic regressions reject both an already-expired owner and a child
made ready after an executor stall. This correction does not claim to fix the
preserved snapshot15 `IncompleteClose` observation. That snapshot
passed 49 tests; strict validation details are recorded in its focused receipt.

The later [snapshot27d finite failure](../../work/implementation-wave27d/local-check.log)
again reported `IncompleteClose` with drained ownership, while the whole quiet
interval had not completed. Its trace does not identify a specific lost final ACK;
driver-origin quiet times and close-relative ages must not be subtracted directly.
The [current scoped follow-up](../../work/openvpn-close28/RECEIPT.md) preserves that
failure and qualifies the positive paired test as impaired exact transfer followed
by witnessed recovery/held-path drain and no-new-loss close. Only those four test
paths are quiesced, within the original transfer budget; the five-second production
close and complete quiet requirement are unchanged. A separate actual final-ACK
loss table retains its 160ms profile and additionally requires explicit failure at
the default five-second bound. Neither the positive fixture nor isolated passing
runs explain away the historical failures or promise clean shutdown under arbitrary
continuing loss.
