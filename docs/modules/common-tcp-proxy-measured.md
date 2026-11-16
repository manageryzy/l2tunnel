# Explicit measured TCP proxy through Common records

Status: implemented finite composition with current root integration evidence
(PCOM-02a) in [Batch15](../../work/parallel-features-20261115/parallel-batch15-scoped-validation.json).
External results below remain separately source-bound. Full
PCOM-02 remains open for exact per-token physical timestamp retention, native
ACK/window qualification and the remaining complete acceptance requirements.
The earlier fixed Common and measured TLS results are separate evidence.

## Selection and actual call chain

The additive selection is
`common_transaction_profile::Profile::new_proxy_measured_retained`. It requires
the existing complete `proxy::measured::Config`, including its fixed base policy.
Its measured policy digest enters a separate application domain before the
existing fixed-proxy and retained-retirement domains, Common configuration,
admission, Noise and member authentication. Both role-specific runtime contracts
bind the measured digest and validate the same finite geometry. Fixed and TLS
constructors keep their existing selections.

The production path is:

1. [Profile construction](../../crates/l2tunnel-client-core/src/secure_udp/common_transaction_profile.rs)
   -> existing `Prepared::proxy_common_client/server` ->
   [shared service owner](../../crates/l2tunnel-client-core/src/service/owner/proxy.rs)
   -> existing `authenticate_secure_udp`. The service verifies the actual peers,
   authenticated configuration and carrier before opening its native attachment.
2. The service selects the existing measured control channel and backend, then
   calls [common::run_measured](../../crates/l2tunnel-runtime/src/proxy/common_measured.rs).
   [run_selected](../../crates/l2tunnel-runtime/src/proxy/common.rs) consumes the
   original authenticated `member::Parts`, installs the same bounded record bridge
   and observes `measured::Status.runtime.phase` under the original setup cap.
3. `actor::run_profile_selected` receives `Some(measured_config)` and the existing
   retained-retirement bridge. The same actor constructs one maintained TCP
   `session::Table`, one measured Controller, the existing token ledger and the
   existing original-flow MUX/DRR. It owns route checks, native I/O, quiesce,
   fences, original deadlines and actual child cleanup.
4. The actor's version-two user envelopes carry transparent packets, proxy
   records and canonical measurement records through the same writer. The bridge
   presents opaque ordered records to the existing Common Driver, then
   `record_bank::Entry::enqueue_proxy_borrowed`, the reserved Pipeline,
   Aligned/direct ARQ, existing Common protection and the original UDP socket.
5. The reverse path uses the same authenticated Common receiver and record port.
   The existing proxy reader validates session, sequence and envelope; the actor
   dispatches measurement records only after actual lifetime-flow and channel
   checks to `Controller::receive_authenticated`. Native payload bytes cannot
   acquire measurement or Common management authority.

The finite selection is full duplex, TUN, one actor/Common channel, one immutable
catalog descriptor and uncompressed Aligned raw bodies with direct ARQ and one
coding unit per record. Native header codecs, independent short paths, FEC repairs
and fragments remain unsupported. Common uses the existing typed aggregate
ordered-record flow; the actor still arbitrates original flows. It does not wrap
the records in fabricated native IP/Ethernet packets or install another TCP,
measurement, authentication or recovery state machine.

## Admission, physical completion and ACK provenance

Measurement admission stays at the successful actor `Arbiter::push`, immediately
followed by `Controller::confirm_admission` and `Ledger::admit` with the same
actor time. Failed MUX admission leaves the Controller's pending owner intact.
Later writer custody, Common Pipeline admission and carrier acceptance cannot
replace that original admission time or renew its handoff deadline. Demand and
echo work retain their existing report/probe budgets, producer admission cursor,
flow weight and framed-byte charges; they have no free or reserved probe channel.

The [existing ledger](../../crates/l2tunnel-runtime/src/proxy/measured/ledger.rs)
retains each opaque `OutputId`, immutable canonical body, channel and all-user
ordinal. The single bulk writer advances cumulative `Progress.users` only after
complete framing and flush, including the branch that drains queued users ahead
of Quiesce. Common bridge flush requires the admitted record's exact
`UnitWitness` identity, index zero and count one, followed by the actual whole
retained-ciphertext receipt. Enqueue, sealing, partial writes, WouldBlock and ARQ
retries cannot advance that writer ordinal.

The actor validates cumulative progress against handed ordinals, invokes each
retained token's callback once and frees it only after Controller success.
Coalesced writer notifications do not lose immutable token ownership. The
[callback phase](../../crates/l2tunnel-runtime/src/proxy/measured/state.rs)
checks original expiry first and supplies fresh actor time to
`Controller::confirm_written`. A receipt observed too late remains a failure;
backdating the callback to socket acceptance must not bypass that watermark.

The physical receipt carries independent acceptance and observation times, which
the bridge checks against its original first-write cap. Those exact times are
currently discarded after completion; they are not retained for each measurement
token. `ProxyCommonFrame.socket_accepted_packets` and
`socket_accepted_ip_bytes` are bounded cumulative facts from the actual Common
carrier counters across scopes. They include more than measurement traffic and
are neither per-token receipts nor peer ACK, native delivery or application
consumption. These aggregates do not close the timestamp requirement in PCOM-02.

ACK-rate observations still come from the maintained Table's actual acknowledged
byte prefixes. Peer Demand reports, writer completion and Common ARQ ACKs do not
substitute for native TCP ACK evidence. Service latency remains original
measurement-MUX-admission to the first accepted authenticated echo reply,
including local queue/write and peer service delay. A reply received before its
write callback retains that original reply time. This is not native TCP RTT.

Queue pressure still uses actual actor MUX age and retained writer handoff age;
the latter includes waiting on Common. Native receiver pressure comes from
actual native I/O and pending native sends blocked by the maintained peer receive
window. The same Controller prepares and applies future relay credit targets.
This neither promises an exact advertised-window value nor turns a measured
relay target into an endpoint cwnd actuator. Transparent TUN owns no endpoint
cwnd, and native-window qualification remains separate.

## Lifecycle and observations

The original membership/setup cap remains active through mutual proxy readiness.
The bridge preserves its first-write deadline across backpressure; Common caps
can shorten it. Controller handoff/probe expiry, Table/Open, heartbeat and actor
startup/drain deadlines retain their existing owners. Terminal failure wakes the
same actor and waits for its actual children; the shared service retains release
and reconnect authority.

Measured selection requires explicit retained retirement. After existing
measurement quiesce/drain, native completion, fences and child joins, the actor
waits on the same retained Common EOF source/feedback owner under its original
minimum drain cap. Physical acceptance and `Engine::drained()` alone cannot
produce clean closure. See the [retained-close contract](common-tcp-proxy.md#selected-retained-close-implementation-finite-integration-evidence)
for separate source-retirement, peer-EOF and custody conditions. Its imported
implementation has the finite component/service evidence below; complete PCOM-09
acceptance remains open.

The shared projection reports `MeasuredRelay`, the measured policy digest,
requested/effective Common carrier and UDP cover, original endpoints, Common
liveness, carrier acceptance counters and the existing measured aggregate.
Effective carrier/cover require actual runtime observation. `hot_switch=false`,
exact native rwnd control, native RTT/cwnd reporting and native-window
qualification remain false; `graceful_close=true` identifies the explicitly
authenticated retained-retirement selection, not a completed close result.
The actual terminal result and observed release remain separate. The dependent
[explicit measured CLI](common-tcp-proxy.md#explicit-measured-common-cli-consumer)
uses this same shared API1 presenter; no default changes. The optional measured
configuration is boxed in the shared Profile so its absence does not enlarge
every carrier setup future. Authentication and serialized policy remain exact.

## Retained complete requirements

PCOM-02a is only the finite installed composition above. It does not reduce
[PCOM-02 or PCOM-03 through PCOM-09](common-tcp-proxy.md#acceptance-and-complete-retained-follow-up):

- Preserve exact physical timestamps with their immutable token/ordinal
  provenance, and complete measured growth/shrink, ACK and native window effects.
- Support every required Common family, codec, FEC/repair/short/packed/rolling
  shape, configured multi-channel MUX and independent recovery owner, mapping all
  physical fragments/copies without premature completion or duplicate charging.
- Complete paired-half and every required original carrier, including genuine
  QUIC, OpenVPN-like and raw TCP/HTTPS-like paths, with original authentication,
  connection/five-tuple custody and platform constraints. Appearance parsing,
  interoperability and network behavior remain separate claims.
- Preserve full SW-11: authenticated epoch/digest transactions, idempotent drain
  barriers, retained old flows/grants/readers and explicitly permitted new-flow
  ownership transitions. No local reload may seize existing TCP ownership.
- Complete shared CLI/GUI selection, inspection, measured paging, switching,
  lifecycle failure/cancellation/reconnect and requested/effective capability
  matrices through the existing API.
- Qualify malformed/replayed input, policy/authentication mismatch, source,
  feedback and control loss/reordering, blocked native output, every original
  deadline boundary, peer failure, reconciliation and full resource/release
  matrices. Complete reliable retirement loss/cap outcomes for both peers.
- Complete owned Linux IPv4/IPv6 TUN captures, SYN/options/scaling, advertised
  window pressure/reopening, TIME-WAIT and 1/2/4/16/64-flow demand/fairness;
  qualify memory/CPU, Windows/Android and real devices. Preserve all 47 mode
  definitions and unchanged performance gates, including the 80 Mbit/s gate.

DATA-02, FC-*, MG-*, CL-*, P-*, MOD-PROXYRT-*, MOD-PROXY-MEASURED-*, SEC-* and the
complete shared-session requirements remain in scope. Finite unprivileged socket
fixtures cannot establish kernel TUN, full resources, platform or throughput
acceptance. Simulator results and historical experiment receipts are unchanged.

## Preserved external finite verification

The measured patch is based on `3583e3af1bd67bdae1eb6be2ea6f81f49e7e8090`:
prior fixed integration `1e8190cb8af55a1b19236b8ff2f3b0c2fb6ea477`, the root's
hash-bound retirement staging import `43cc6a8b0183ebd85f54fd05074ce23f9a44d524`,
a one-line retirement-helper visibility repair `e78e776`, and test assertion lint
repair `3583e3a`. The original retirement interface, source hashes, measured file
hashes, patches and command logs are recorded in the
[handoff](../../work/tcp-proxy-measured-common-20261116/HANDOFF.md).
Do not replace concurrent shared files with these snapshots.

All Cargo commands used `--offline` and the isolated
`CARGO_TARGET_DIR=/tmp/l2tunnel-proxy-measured-common-target`.

| Actual command after `cargo` | Observed result |
| --- | --- |
| `check -p l2tunnel-runtime -p l2tunnel-client-core --tests` | Passed after the imported retirement method's visibility repair |
| `test -p l2tunnel-client-core proxy_common --lib -- --nocapture` | 7 passed: real measured pressure/qualified growth/retained close, policy separation, actual capabilities, fixed v1 refusal, fixed retained close and abnormal release |
| `test -p l2tunnel-runtime common_bridge:: --lib -- --nocapture` | 7 passed: exact physical receipt, first-write cap, failure, old close refusal, retained source/feedback loss and held retry |
| `test -p l2tunnel-runtime measured_cases:: --lib -- --nocapture` | 13 passed: original admission and deadlines, immutable tokens, partial/pending flush, budget/replay/channel checks, source demand versus downstream pressure |
| `clippy -p l2tunnel-runtime -p l2tunnel-client-core --lib --tests -- -W clippy::all` | Completed; only inherited `raw_carrier_io.rs:375,382` collapsible-if and `secure_udp_common_raw.rs:44` type-complexity warnings remain; no authored-line diagnostics |

The service fixture used actual protected loopback UDP, existing Noise/member
authentication and maintained TCP endpoints with 4096-byte rings. It withheld the
destination application's reads while continuing native packet/ACK processing,
Common management and measurement service, then resumed exact 32769/16387-byte
bidirectional delivery and FIN. In the recorded qualified-growth run
(`service-delivery.log`), downstream `Backpressure` selected 512 bytes at
revision 53; after pressure cleared, actual `Probing` selected 1024 bytes at
revision 201. Both sides observed positive maintained ACK bins, fresh authenticated
Echo samples and all three admitted measurement kinds. Observed carrier totals
were 1812/1786 whole packets and 1145953/1065536 IP bytes; these are aggregate
acceptance facts, not per-token receipts or throughput.

The original two-second fixture drain cap stayed active after physical EOF
acceptance. Both actual owners then published clean close, zero queued/awaiting
measurement callbacks, quiescing Controller state, observed attachment release
and reusable original socket addresses. The fixture claimed zero TLS lane closes.

Retained failed attempts include the imported visibility compile error, a new
policy fixture's use of nonexistent/private accessors (fixed using existing
`resources()`/`cover()`), and a source-filename test filter that matched zero
tests. That zero-test invocation is not evidence. Clippy initially also caught
two denied unwraps in imported retirement tests and two new style warnings;
those were repaired without weakening lint settings. No full-workspace check,
`tools/check.py`, kernel TUN lab, Windows/Android build, device or performance
qualification was run; those gates remain with the coordinator.
