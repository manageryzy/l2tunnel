# Explicit fixed TCP proxy through Common records

Status: implemented finite slice with current root Linux component and shared-service
integration evidence in the [Batch13 receipt](../../work/parallel-features-20261115/parallel-batch13-scoped-validation.json).
The receipt separately preserves the two failed existing runtime cases, their
same-binary passing rechecks, and successful remaining required stages.
The complete proxy/Common mode remains open. This does not qualify kernel TUN,
Windows/Android, native advertised-window control, or throughput.

## Installed composition

`common_transaction_profile::Profile::new_proxy` binds the complete existing
fixed proxy `session_config` digest into the application input before the existing
Common configuration, admission, Noise and member authentication. Explicit
`service::Prepared::proxy_common_client/server` use the existing shared service
owner, readiness, keyed operations, abort, release and reconnect machinery.
The preexisting TLS fixed/measured constructors and CLI keep their original
selections. Their external checkpoint did not include the explicit Common CLI
slice staged below.

The actual call chain is:

1. `Profile::new_proxy` -> `Prepared::proxy_common_client/server` ->
   `service::owner::proxy::common` -> existing `authenticate_secure_udp`.
2. `proxy::common::run` consumes the original authenticated `member::Parts`,
   creates a bounded local record port and reuses `proxy::actor::run_profile_owned`.
3. The same actor owns the maintained TCP `session::Table`, route checks,
   fixed credit, original-flow DRR/MUX, actual native I/O, quiesce and fences.
4. The existing Common Driver reads the explicit opaque record port ->
   `record_bank::Entry::enqueue_proxy_borrowed` -> the same reserved Pipeline ->
   Aligned/direct ARQ -> existing Common security and original UDP socket.
5. Actual admission returns an Aligned record identity. The emitted original
   `UnitWitness` must match that identity, index zero and count one. Only the
   existing whole-carrier confirmation of that retained ciphertext can complete
   the bridge writer. Enqueue, sealing, partial writes and WouldBlock do not flush.
6. Common's existing authenticated management/liveness owners continue independently
   of the bounded user stream. Peer data traverses the existing Common receiver,
   then the record port and the same proxy reader/Table. A user record never
   acquires Common management authority.

The narrow selection requires full duplex, TUN, fixed credit, one actor/Common
channel, one immutable catalog descriptor, Aligned raw bodies, no native header
coding, no independent short path, no FEC repairs and exactly one coding unit per
proxy frame. The actor already arbitrates original flows; Common supplies one
bounded aggregate ordered-record queue and actual wire accounting. A typed flow
namespace distinguishes this queue from native IP/Ethernet classification. No
synthetic IP header or privileged Ethernet identifier is used.

Every proxy envelope and TCP control record remains in user-data admission.
Proxy session framing is reused unchanged inside this stream; it does not create
another TCP, authentication, recovery or service state machine. Existing Common
control has its own already established authenticated bounded service.

## Custody, deadlines and observations

The bridge retains one outbound frame and a bounded receive frame. Its physical-write
stall cap starts at the first stream write and survives local port backpressure,
Pipeline admission, carrier WouldBlock and physical completion. This cap ends after
the exact whole-carrier receipt; it is not a whole-ARQ lifetime. Existing Common
recovery starts its own configured lifetime at real admission and retains that
owner across retries. The actor keeps its existing queue age, Table/Open, heartbeat,
startup and shutdown semantics; fixed mode does not gain a new pre-stream queue-age
cap. Common's lease and physical output caps can only shorten the write cap. Startup remains bounded by the original
membership/setup deadline through actual mutual proxy readiness. Terminal carrier
failure wakes the same actor and awaits its owned child cleanup. Graceful stream
shutdown waits any pending physical completion, then explicitly fails with
`Unsupported`: no reliable session-close retirement owner is installed. It emits
no synthetic EOF and cannot produce a clean `CloseReport`. The existing actor
performs its original failure cleanup and the shared service observes actual release.

Common's historical `native_*` counters describe record-port acceptance in this
composition. They do not certify a TUN write or native application consumption.
The proxy Table separately confirms actual device writes and maintained ACKs.
Its existing `confirm_record_sent` records reliable writer admission; it does not
become a physical-send receipt. Writer progress and proxy fences advance only
after the bridge receives the exact whole-carrier completion.
No successful TLS-lane close is claimed for Common. Status exposes explicit requested/effective configuration,
carrier, cover, original endpoints, actual Common liveness, `hot_switch=false` and `graceful_close=false`.
`common_record_composition` becomes true only after actual Common observation.
Transparent TUN still owns no endpoint cwnd; `exact_tcp_rwnd_control` remains false.

## Acceptance and complete retained follow-up

- [x] [PCOM-01] Integrate and execute the fixed/full/one-channel Aligned direct-ARQ slice through actual authenticated original UDP, shared service, maintained native TCP endpoints, exact bidirectional opaque bytes/FIN, transparent bypass, management liveness and owned cleanup. Include admission refusal and original physical-completion cap evidence. Evidence: [actual shared-service fixture](../../crates/l2tunnel-client-core/src/service/tests/proxy_common.rs), [typed record tests](../../crates/l2tunnel/src/record_engine/proxy_records_tests.rs), [physical bridge tests](../../crates/l2tunnel-runtime/src/proxy/common_bridge.rs), and [executed checks](#preserved-external-verification). Graceful close is explicitly refused and remains PCOM-09.
- [ ] [PCOM-02] Integrate the existing measured controller without a second controller: preserve original measurement admission times, exact physical completion times and immutable token/ordinal callbacks; retain probe/report budgets, ACK provenance, growth/shrink and quiesce/drain semantics. Verify real ACK/window effects separately.
- [ ] [PCOM-03] Extend all required Common record families, codecs, FEC/repair/short/packed/rolling variants, configured multi-channel MUX and independent recovery owners. Map one logical proxy record to every actual physical fragment/copy and completion without early flush or duplicate debit; qualify mixed traffic/backpressure and finite resources.
- [ ] [PCOM-04] Install paired-half and every required original carrier (including actual OpenVPN-like and raw TCP/HTTPS-like paths), retaining complete authentication/connection/five-tuple custody and platform constraints. Separate appearance parsing, interoperability and ISP behavior claims.
- [ ] [PCOM-05] Implement authenticated epoch/digest transactions and idempotent drain barriers for proxy record changes while retaining old TCP flows, grants and readers. Define and implement explicitly permitted new-flow ownership transitions; no transparent-to-proxy local switch or config reload may seize existing TCP ownership. Preserve complete SW-11.
- [ ] [PCOM-06] Extend the same shared CLI/GUI/service API for explicit Common proxy selection, inspection, measured paging, supported switching, requested/effective capability status and every lifecycle failure/reconnect path. The existing TLS CLI is not evidence of a new Common CLI command.
- [ ] [PCOM-07] Qualify malformed/replayed input, authentication/policy mismatch, source/feedback/control loss, reordering, blocked real native outputs, every original deadline boundary, cancellation during each setup phase, peer failure, retained-session reconciliation and full release/resource matrices. No new recovery state machine or new timeout is implied.
- [ ] [PCOM-08] Complete owned Linux TUN captures with IPv4/IPv6, both directions, native SYN/options/scaling, actual advertised-window pressure/reopening, maintained TIME-WAIT, 1/2/4/16/64-flow demand/fairness, memory/CPU and unchanged performance gates; independently qualify Windows/Android and real devices. Finite local socket tests do not close these gates.

- [ ] [PCOM-09] Implement reliable graceful session retirement using the existing Common recovery/feedback owners and the actor's original drain cap. Preserve own final-record ARQ debt and duplicate-triggered final feedback until the retained owner can be released. Qualify loss of the terminal record and final feedback, original cap expiry and both peer outcomes. Never equate physical acceptance or `Engine::drained()` with a completed peer session close; add no parallel TCP/recovery state machine.

These child tasks retain DATA-02, FC-*, MG-*, CL-*, all P-* parity requirements,
MOD-PROXYRT-*, MOD-PROXY-MEASURED-* and the complete shared-session/SEC-* requirements.
No parent completion definition is reduced by the narrow runnable composition.
Local switch requests return `Invalid`; a validated fresh peer PREPARE terminates
with `Unsupported` before new storage or epoch admission. Existing management has
no follower policy-rejection response for that case; this slice does not add one.


## Selected retained-close implementation (finite integration evidence)

An additive `Profile::new_proxy_retained` binds an explicit application/H0 domain
before the existing immutable proxy commitment. `Profile::new_proxy` and its old
wire/default selection remain unchanged and still refuse graceful close. No new
CLI default or periodic key exchange is selected. The [Batch14 receipt](../../work/parallel-features-20261115/parallel-batch14-scoped-validation.json)
records two actual protocol/Bridge cases and the protected-UDP shared-service case;
full PCOM-09 acceptance remains open.

The existing actor passes its original minimum drain cap to the same bounded
Bridge. Its single-byte EOF uses the same Pipeline and Aligned/direct ARQ. The
maintained Reliable parser identifies the actual EOF `SourceId`; the code never
converts a native record or physical packet ID into that source. A real peer ACK
must retire the final source, including any exact physically held retry. Actual
peer EOF, actor native/fence completion and child joins remain separate mandatory
conditions. The same Driver retains duplicate-triggered feedback until the cap,
then checks relevant user/record custody before waking the actor. Only afterward
may the actor publish Closed or complete its administrative drain waiter.
`Engine::drained()` is one local custody conjunct, never a peer-close proof, and
unrelated periodic management/liveness output need not become globally empty.

At the original cap, incomplete relevant output fails. Physical acceptance alone,
ACK receipt with a still-held retry, local timeout, or cancelling ciphertext
cannot produce clean closure. An explicit terminal failure wakes the actor and
performs owned cleanup. Each peer's result is local; loss through the entire cap
can yield different honest outcomes. Common reports no fabricated closed TLS lane.

Two passing component cases use actual reserved Reliable senders/receivers and
real Bridge EOF ports for final-source loss, first-final-feedback loss,
duplicate-triggered ACKs, held retries, original-cap expiry and late receipt. A
third passing case uses the actual shared service/original UDP/Noise/member path,
maintained native TCP endpoints and existing quiesce/fence/join machinery. This is finite local Linux integration evidence. End-to-end final-record/final-feedback loss, full selection,
native/platform/resource/performance and complete PCOM-09 remain required.

## Explicit fixed CLI and portable observations

The implemented CLI slice passes its strict-selection, portable-projection and
actual shared-service presentation cases in the Batch14 receipt. The original
[source-bound handoff](../../work/parallel-features-20261115/common-proxy-cli-v0/handoff.json)
remains preserved.
It explicitly selects --traffic proxy --proxy-policy JSON_FILE together with
--record-profile common --common-transaction-plan PATH and original
--carrier quic-like|media-like. It reads the maintained strict fixed policy,
uses runtime_config/Profile::new_proxy/Prepared::proxy_common_client/server,
and reuses the sole existing proxy shared-service presenter. No proxy, TCP,
recovery, authentication or lifecycle state machine is duplicated.

The finite selection remains full/TUN/no compression, fixed one channel and one
immutable compatible Aligned/direct-ARQ descriptor. Measured, raw/OpenVPN, Half,
multiple channels/catalog members and incompatible record geometry are rejected
before network/device startup. Settings and trust file reads are ordinary bounded
preflight; native attachment remains deferred until the actual service owns it.
There is no silent catalog/body clamp, family conversion, policy fallback or
retained-close default.

inspect-common-transaction-plan includes requested-only fixed proxy policy and
complete bounded route pages with the authenticated policy digest. Actual setup
uses Observation::Proxy with embedded Common facts, not native-Common API4 event
projection. The maintained proxy local API1 exposes status, drain-proxy,
disconnect and explicit fresh reconnect. It does not enable native-Common API4
catalog/switch operations. Omitting --proxy-close preserves the existing v1
graceful_close=false selection. Explicit --proxy-close retained uses
Profile::new_proxy_retained and binds that selection into authenticated H0;
both peers must select it. Inspection names common_proxy_fixed_retained_v1,
and effective observations copy the actual selected close capability. Closure
keeps the original actor drain cap and the same reliable EOF/feedback owners.

Portable ProxySnapshot.common is optional and omitted for legacy TLS proxy
observations, preserving their old serialized bytes. For the explicit Common
selection it carries bounded actual requested/effective policy/configuration,
carrier/cover/original endpoints, liveness, installation/capability and release
facts from ProxyCommonFrame. It carries no credentials or packet bytes. Older
strict clients may reject this explicit-mode field instead of silently reporting
a different backend. Requested inspection is not an effective runtime observation.
Common record-port counters remain distinct from actual native TCP/TUN writes.

Focused parser, legacy omission, bounded requested/effective projection and one
genuine shared-service presentation regression pass. The optional Common status
is boxed in-process to bound legacy async frames; its serialized representation
and omission remain unchanged. Full
PCOM-06 (including measured paging, supported switching and every lifecycle
failure/reconnect path), PCOM-02..05/07..09, native/platform/performance and all
other original mode requirements remain unchanged and open.

## Preserved external verification

The isolated branch is based on source HEAD
`99f45488f01f0f215e7b6c3bbb58b3c9a7d74360`, plus the coordinator's 122-file
uncommitted dependency snapshot `106c931707b1a16ccb5c922f7406cdef3fcb71e1`
(captured 2026-11-16 03:53:56 UTC). Separate prerequisite repairs are
`b0b75a6d94ac9dd45566b53af274c654f56dbe21`,
`dc3b25eca5ccb4b1c7ffa3018aed82efd2cf43c3` and
`d0f5ad76f407384fbcb693369cb253ac383c32cc`. They fix captured incomplete
imports/moves/conversion and exhaustive fixture matches; they are not proxy work.
Merge the integration delta above that last commit, not the dependency snapshot
onto the concurrently changing coordinator checkout. The handoff manifest records
SHA-256 of the captured dependency files, each authored file and current source drift.

All commands below used
`CARGO_TARGET_DIR=/tmp/l2tunnel-proxy-common-target` and `--offline`.

| Command (after `cargo`) | Observed result |
| --- | --- |
| `test -p l2tunnel record_engine:: --lib` | 30 passed; typed opaque ingress, parser/shape refusal and preserved custody |
| `test -p l2tunnel-runtime common_bridge:: --lib` | 5 passed; partial writes, exact receipts, immutable write cap, truncation, failure wakeup and explicit close refusal |
| `test -p l2tunnel-runtime proxy_guard --lib` | 2 passed; generic native catalog refusal and no local same-configuration epoch change |
| `test -p l2tunnel-runtime immutable_dispatch_refuses_same_configuration_prepare_before_admission --lib` | 1 passed; authenticated PREPARE does not allocate or change epoch |
| `test -p l2tunnel-runtime common_sealed_user_wouldblock_retains_exact_bytes_number_scope_and_single_debit --lib` | 1 passed with `RUST_MIN_STACK=16777216`; first attempt overflowed the default test thread stack |
| `test -p l2tunnel-runtime common_original_operation_cap_guards_physical_write_and_preserves_late_success_facts --lib` | 1 passed with `RUST_MIN_STACK=16777216` |
| `test -p l2tunnel-client-core proxy_common --lib` | 3 passed; actual original-socket authentication, 7001/4099 bidirectional bytes, native FIN, transparent bypass, authenticated liveness, truthful failed drain and observed release |

The byte test uses maintained TCP engines on unprivileged Unix packet attachments
and real UDP sockets. It does not establish Linux kernel TUN performance, real
network loss behavior, native advertised-window control, Windows or Android.
Physical completion means complete acceptance by the original socket/carrier,
not delivery over a physical network or application consumption.

Strict affected-package Clippy (`--lib --tests -- -D warnings`) is blocked by
two preexisting `clippy::collapsible_if` diagnostics in unchanged
`secure_udp/raw_carrier_io.rs:375,382`; this checkpoint does not repair unrelated
raw-carrier code. A complete diagnostic run with `-W clippy::all` finished
successfully and additionally reported one preexisting `type_complexity` warning
in unchanged `service/tests/secure_udp_common_raw.rs:44`; no new-file or changed-line
diagnostics were reported. No lint defaults were modified.

Affected-file `cargo fmt` output was used while preserving unrelated inherited
formatting hunks in shared files; `git diff --check` passed. The ledger checker
currently fails at preexisting `RWI-02` (missing evidence link), reproduced against
the unmodified dependency baseline. The new PCOM entries retain stable IDs and
link their finite evidence. Per the parallel-work instruction, `tools/check.py`
and full-workspace checks remain with the coordinator. Simulator and historical
experiment receipts were not modified.
