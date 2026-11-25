# Live protocol tuning

Status: implemented and integration-tested in loopback/service suites (LT-01..LT-05
done; LT-06, the owner's real-TUN run, open). Note: handshake M1/M2 catalog
proposal generation remains Swift-only, while the local API/GUI tuning controls
(`tuning_get` / `tuning_switch`) now tune FEC and MTU across Swift, Aligned, and
Packed catalog entries, and authenticated live speed-budget tuning
(`ProfileTag::RateBudgetV1 = 6`, local API `rate_budget_set`) scales forward/reverse
caps (1 Mbit/s..=10 Gbit/s), pacing bursts, credit ceilings, and runtime work
batches live on both peers without reconnecting.

## Owner request (2026-11-24)

"our hot protocol switch are configured static, but a want detiled control
in ui. Like I can switch swift with or without fec, choose fec repair rate,
hot chaning mtu"

Today a hot switch can only choose a member of the exact catalog both ends
authenticated at connect (1..=64 descriptors, memory reserved for the
largest; `CommonTransactionContract::resolve` refuses anything else).

## Owner decisions (2026-11-24)

1. **Generated catalog with real controls.** The catalog is generated from
   switchable choices: swift with FEC off or at chosen repair rates, and
   chosen MTUs, up to 64 combinations. The Connection page shows real
   controls (FEC toggle, repair-rate picker, MTU picker) and switches live
   to the matching catalog entry. No change to the switch protocol or its
   security model: every value is still a pre-agreed catalog member.
   Chosen over negotiated ranges (switch protocol change) and a fast
   reconnect (not hot).
2. **Device MTU follows the tunnel MTU.** On an MTU switch the service also
   sets the TUN device MTU: lowered before the protocol switches down,
   raised after it switches up, so no packet is too big in between. This
   includes devices created outside l2tunnel (an owner-approved exception
   to "never change preexisting devices"); the original device MTU is
   restored on disconnect.
3. **The client proposes at connect.** The client sends its switchable
   choices during setup; the server adopts them within limits set on the
   server. Chosen over a shared generated plan file and over matching
   choices in both profiles.
4. **Inside handshake message 1.** The proposal travels in the payload of
   the client's first Noise IK message: encrypted to the server's static key
   and authenticated by the handshake. Both ends generate the same catalog
   from their base plan plus the proposal, and the handshake binds the
   result. A refused proposal ends the connect with the exact reason.
5. **Server limits in the server profile.** A "switchable limits" section:
   allowed repair rates, MTU range, and a memory cap for the reserved
   catalog. When unset: any proposal the protocol considers valid, up to 64
   entries and the plan's existing memory budget. Anything outside is
   refused at connect with the exact reason.
6. **Binding: payload plus confirmation digest.** The server must know the
   Noise prologue before it can decrypt message 1, so the generated catalog
   cannot sit in the prologue digest. The prologue keeps binding the base
   plan. The proposal is the encrypted, authenticated payload of message 1
   (covered by the handshake hash). Both ends derive the catalog and its
   digest, and that digest is added to the existing key-confirmation step,
   so the handshake completes only if both derived the identical catalog. A
   captured message 1 can be replayed like any IK message 1; it only repeats
   the same choices and still needs the real client to finish.
7. **Two MTU controls.** Swift packs inner packets into a stream, so the
   two sizes are independent and each gets its own control and its own list
   of choices: the device MTU (largest inner packet; also sets the TUN
   device MTU per decision 2) and the path datagram size (outer IP packet
   size, for paths that drop large packets). The catalog is the combination
   of FEC, device MTU and path size choices, capped at 64 entries.

8. **Hot device-MTU switches drop leftover oversized packets** (owner,
   2026-11-24). The runtime rule that every hot switch keeps the inner
   packet size is lifted; native storage is sized for the largest catalog
   entry. On a switch down the TUN MTU is lowered first (decision 2);
   packets the device queued before that and now exceed the new size are
   dropped and counted (`native_oversize`), never sent. Chosen over holding
   the switch until the native queue drains and over keeping the inner
   size fixed (device MTU only at the next connect).

9. **Device MTU ordering is strict on both ends** (owner, 2026-11-24). The
   end that starts a switch to smaller inner packets lowers its device MTU
   before it proposes; the other end lowers its device MTU when the
   proposal arrives and only then acknowledges it, so the switch completes
   after both devices are lowered. Raising happens after the switch on both
   ends. Chosen over adjusting the other end right after it sees the new
   setting (a few milliseconds of dropped and counted oversized packets
   there). The wire format is unchanged; only when the runtime
   acknowledges changes.

10. **Controls go through two service actions** (owner, 2026-11-24).
    `tuning_get` returns the current setting and what each control can
    choose; `tuning_switch` takes a setting, and the service resolves it to
    the exact catalog member and runs the normal hot switch. The GUI and
    the CLI (`l2tunnelctl tune show|set`) share them. Chosen over each
    frontend paging the catalog and mapping entries itself. An additive
    local API change; no data-protocol change.

## Tasks

- [x] [LT-01] Deterministic catalog generator: base plan + choices -> descriptors (swift FEC off and repair rates, MTUs), bounded to 64, identical on both ends; unit-tested. Evidence: [generator](../../crates/l2tunnel/src/live_tuning.rs) and [tests](../../crates/l2tunnel/src/live_tuning_tests.rs) (5 tests: every combination plus the base, order-free determinism and identical catalog root, server-limit and protocol-bound refusals with exact reasons, proposal wire round trip and garbage refusal, non-Swift/asymmetric base refusal); `cargo test -p l2tunnel --lib live_tuning` 5 passed, Clippy clean, 2026-11-24. FEC choices apply to both directions (the 64-entry bound makes per-direction lists impractical).
- [x] [LT-02] Proposal wire in handshake message 1 and server-side limit check; refusal reasons; both-end catalog and digest binding. Evidence: [setup tests](../../crates/l2tunnel-runtime/src/secure_udp/establish_tuning_tests.rs), [judge tests](../../crates/l2tunnel-client-core/src/secure_udp/live_tuning_profile_tests.rs) and the [service end-to-end test](../../crates/l2tunnel-client-core/src/service/tests/secure_udp_transaction.rs) (`tuned_client_proposes_at_connect_and_switches_fec_off_live`), 2026-11-24; details below.
  Progress 2026-11-24: the handshake layer.
  `l2tunnel-handshake` carries an optional payload of up to 256 bytes,
  encrypted and authenticated in message 1 (`set_initiation_payload`,
  `initiation_payload`), and a context digest bound into both
  confirmations (`set_confirmation_context`, domain `L2NCONX`). Without a
  payload the flights are byte-for-byte the original.
  Evidence: [handshake](../../crates/l2tunnel-handshake/src/lib.rs) and
  [tests](../../crates/l2tunnel-handshake/src/tests.rs)
  (`cargo test -p l2tunnel-handshake`: 19 passed, 2 of them new: payload
  delivery and binding under IK and IKpsk2, differing contexts fail
  authentication, and the configuration rules).
  Progress 2026-11-24 (second step): the setup stream carries it.
  - Handshake message 2 now carries the server's authenticated verdict
    whenever message 1 carried a proposal (`set_response_payload`,
    `response_payload`, at most 64 bytes): `[0]` accepts, `[code]` refuses
    with a stable reason code (`live_tuning::Refusal`, codes 1..=12, where
    `12 = Memory`), so a
    refused client ends with the server's exact reason instead of a
    timeout. Without a proposal message 2 is the original 48 bytes.
  - The final-confirmation custody (`ConfirmationCache`) keeps the longer
    context confirmation; before this fix a session with a proposal could
    not finish.
  - `establish`: the setup-stream parser accepts the variable message 1
    (96..=352 bytes), message 2 (48..=112) and both confirmation sizes;
    frame lengths are written as u16; frames larger than one bootstrap ARQ
    source are split across sources, so the existing 100-byte minimum
    source size still works. `establish::Tuning` is the hook: `Off`,
    `Propose { proposal, context }` (initiator) or `Judge(callback)`
    (responder). A refusing responder delivers its verdict and ends after
    the client acknowledged it; both ends report `Error::Tuning(reason)`,
    shown in setup status as `live_tuning_<reason>`. A server with `Off`
    refuses any proposal as `live_tuning_not_offered`. Every existing setup
    path passes `Tuning::Off`, so behavior is unchanged.
  Evidence: [establish](../../crates/l2tunnel-runtime/src/secure_udp/establish.rs),
  [setup tests](../../crates/l2tunnel-runtime/src/secure_udp/establish_tuning_tests.rs)
  (4 new loopback tests: an accepted proposal, including the largest one
  split over four sources, reaches the server's judge and both ends finish
  with the same session binding; differing derived catalogs fail
  authentication; a refused and an unoffered proposal end both sides with
  the exact reason; a judging server still takes a plain client, and role
  misuse is refused), [verdict codes](../../crates/l2tunnel/src/live_tuning.rs)
  (`refusal_codes_are_stable_and_round_trip_through_the_verdict`),
  handshake tests extended (verdict rules, finish with the context
  confirmation). `cargo test -p l2tunnel-runtime --lib secure_udp::establish::tests`
  16 passed; `cargo test -p l2tunnel-handshake` 19 passed;
  `cargo test -p l2tunnel --lib live_tuning` 6 passed; Clippy `--no-deps`
  clean for the four touched crates, 2026-11-24.
  The hook now reaches every setup path: `establish::connect_tuned` /
  `accept_tuned` (original UDP, which `connect_observed` /
  `accept_observed` call with `Tuning::Off`) and the carrier, raw and
  maintained `connect_initial` / `accept_initial` wrappers take a `Tuning`
  argument; the client-core common owners pass `Tuning::Off` until the
  profile carries choices (LT-03). The setup frame buffers live on the heap
  so the moved setup futures stay as small as before (a runtime test
  overflowed its stack with inline 356-byte buffers).
  `cargo test -p l2tunnel-runtime --lib` 399 passed;
  `RUST_MIN_STACK=4194304 cargo test -p l2tunnel-client-core --lib` 262
  passed, 1 ignored; Clippy `--no-deps` and rustdoc clean, 2026-11-24.
  Finding: the runtime refuses any switch that changes the inner packet
  size (`CommonTransactionContract::resolve` and the engine bank's
  preparation check, "immutable native format"), and native storage is
  sized from the initial entry. Path-MTU and FEC switches are already
  checked per entry. Device-MTU switches need that invariant lifted, with
  native storage sized for the largest entry: owner decision 8.
  Decision 8 implemented (2026-11-24): `CommonTransactionContract::resolve`
  and the engine bank's preparation no longer refuse a different inner
  packet size (the attachment layer and duplex stay fixed); the contract
  checks native resources and the runtime sizes native storage against the
  largest catalog entry (`largest_native`); the client-core profile builder
  accepts static catalogs whose entries differ in inner size. Switch-target
  memory is charged when the switch is prepared, against the plan's
  retained-bytes budget (existing `record_bank` limit). The generator now
  tunes each Swift direction separately, so a plan whose directions differ
  in channels or timers keeps them (before, the forward settings were
  copied into the reverse direction).
  Evidence: [hot-switch test](../../crates/l2tunnel-runtime/src/secure_udp/transport_common_live_tuning_tests.rs)
  (`generated_catalog_switches_fec_inner_size_and_path_size_live`: a
  generated 8-entry catalog over real protected original UDP and native
  devices; a 900-byte packet is delivered at inner size 1024 in both
  directions; after a live switch to FEC 1/2, inner size 512 and path size
  1450 a 500-byte packet is delivered and the 900-byte packet is dropped
  and counted in `native_oversize`; then FEC off, then back to the start,
  where the 900-byte packet is delivered again),
  [generator](../../crates/l2tunnel/src/live_tuning.rs)
  (`each_direction_keeps_its_own_untuned_fields`).
  `cargo test -p l2tunnel-runtime --lib` 400 passed;
  `cargo test -p l2tunnel --lib` 234 passed;
  `RUST_MIN_STACK=4194304 cargo test -p l2tunnel-client-core --lib` 262
  passed, 1 ignored; Clippy `--no-deps` clean, 2026-11-24.
  Contract (2026-11-24): `CommonTransactionContract::with_live_catalog`
  replaces the catalog with the generated one and reruns every
  catalog-wide check (native resources for the largest entry, near8 and
  mixed-recovery rules, `resolve` of every entry, control message
  capacity) while keeping the base H0, envelope and initial entry. It must
  precede proxy and reuse binding. The client-core profile holds the live
  catalog (`with_live_catalog`, `live_catalog`) and applies it on every
  contract path (original UDP, carrier, raw, maintained).
  `live_tuning::extend` is what both ends generate: the plan's own catalog
  plus every combination of the choices around its initial entry, at most
  64 entries. The hot-switch test above now runs the real flow: base-plan
  contracts, then `with_live_catalog`, asserting H0 is unchanged
  ([tests](../../crates/l2tunnel-runtime/src/secure_udp/transport_common_live_tuning_tests.rs),
  `live_catalog_keeps_the_base_identity_and_its_initial_entry`).
  Connect flow (2026-11-24): `secure_udp::live_tuning::proposal` (client)
  and `judge` (server) in client-core. The judge decodes the proposal,
  applies the server limits, generates the catalog, builds the real runtime
  contract for it (so every entry is checked as the runtime will use it)
  and refuses `live_tuning_memory` when the largest entry's record-engine
  heap (`CommonTransactionContract::largest_entry_bytes`) exceeds the memory
  cap or, unset, the plan's retained-memory budget. All four setup paths
  (original UDP, carrier, raw, maintained) and the proxy path propose,
  judge and apply the live catalog; the profile reports the catalog in
  effect (`Profile::catalog`; `plan_catalog` is the plan's own), so the
  service status and the `common-catalog` listing show the generated
  entries.

- [x] [LT-03] Server profile "switchable limits"; client profile switchable choices; CLI and GUI profile editor. Evidence: [run options](../../crates/l2tunnel-client-core/src/secure_udp/live_tuning.rs) and [tests](../../crates/l2tunnel-client-core/src/secure_udp/live_tuning_tests.rs), [GUI fields](../../crates/l2tunnel-desktop-ui/src/profile_fields.rs), 2026-11-24.
  Profiles are run options, so the settings are run options of
  `connect` / `serve` (stored profiles, the CLI and the GUI editor share
  them):
  - client: `--tune-repair off,1/8,1/4`, `--tune-device-mtu 1280,1400`,
    `--tune-path-mtu 1350` (comma lists; any one makes the client
    propose);
  - server: `--tune-max-repair 1/4`, `--tune-device-mtu-range 1280-1500`,
    `--tune-path-mtu-range 1200-1500`, `--tune-max-entries 1..64`,
    `--tune-memory-cap BYTES`; unset means anything the protocol accepts,
    64 entries and the plan's memory budget (decision 5).
  Malformed values are refused with the option name; the other role's
  options are refused ("does not apply to serve"). The GUI profile editor
  has a "Live tuning" group with these fields (client fields on client
  profiles, server fields on server profiles); the service checks the
  values on save.
  Checks: `cargo test -p l2tunnel-client-core --lib live_tuning` 5 passed
  (option parsing; the server derives exactly the client's catalog and
  root while both keep the base H0 and setup config; refusals
  `DeviceMtuLimit`, `Entries`, `Memory`, `Encoding`, `RepairLimit`); the
  service end-to-end test over real UDP: a client proposing FEC off and a
  server with default limits connect, both report the 3-entry generated
  catalog and the base H0, and a live switch to the FEC-off entry carries
  traffic on every channel before and after. Full suites, 2026-11-24:
  `l2tunnel-runtime --lib` 401 passed; `RUST_MIN_STACK=4194304
  l2tunnel-client-core --lib` 268 passed, 1 ignored (three clean runs);
  `l2tunnel --lib` 235; `l2tunnel-handshake` 19; `l2tunnel-desktop-ui`
  24; Clippy `--no-deps` and rustdoc clean. One unrelated intermittent
  failure seen once under load: `retained_tls_full_measured_proxy_preserves_tcp_and_retirement`
  (teardown reported ConnectionReset instead of Closed).
- [x] [LT-04] Device MTU ordering on MTU switches (lower before, raise after, restore on disconnect), including preexisting devices. Evidence: [runtime gate](../../crates/l2tunnel-runtime/src/secure_udp/transport_device_mtu.rs) and its [unit test](../../crates/l2tunnel-runtime/src/secure_udp/transport_common_live_tuning_tests.rs) (`device_mtu_is_lowered_before_a_switch_down_and_raised_after_a_switch_up`), [service setter](../../crates/l2tunnel-client-core/src/service/device_mtu.rs) and [test](../../crates/l2tunnel-client-core/src/service/device_mtu_tests.rs), the [service end-to-end test](../../crates/l2tunnel-client-core/src/service/tests/secure_udp_transaction.rs) (`tuned_device_mtu_is_lowered_on_both_ends_before_the_switch_and_restored_after`), 2026-11-24.
  Design (decision 9): the service gives a live-tuned session a setter for
  its device (`Attachment::with_device_mtu`; the Linux CLI attaches
  `service::device_mtu::LinuxDevice`, rtnetlink on the `--device` name).
  Sessions without a live catalog never touch the device MTU. In the
  runtime (`transport::DeviceMtu`, injected with
  `CommonControlRequests::with_device_mtu`, so the protocol libraries keep
  no OS handles) a gate holds the leader's proposal and the follower's
  acknowledgement of a PREPARE (the peer's message stays pending) until the
  device is lowered; the loop awaits the setter between turns (at most
  2 s) and runs the held step in the same turn. With no switch in flight
  the device follows the current entry: the first setting at session
  start, a raise after a completed switch up, a return after an aborted
  switch down. Device MTU = the local sending direction's `max_native`
  (less 14 bytes on TAP). The first change records the device's MTU; when
  the session's runtime is dropped (disconnect or failure) the service
  restores it, for created and preexisting devices alike.
  Failures: a failed lowering on the leader refuses the switch with the new
  `SwitchError::DeviceMtu` (the current setting stays); the follower has no
  refusal message in the transaction protocol, so it proceeds and decision
  8 drops and counts leftover oversized packets. Failures are not retried
  automatically and are reported in the session status as `device_mtu`
  (`applied`, `wanted`, `failures`, `last_error`).
  Checks: the gate unit test (initial setting; switch down waits for the
  lowering; no raise while a switch is in flight; switch up raises only
  after commit; abort returns; a failed lowering is counted, reported and
  not retried); the setter test (original MTU restored when the session
  ends; untouched devices left alone); the service end-to-end test over
  real UDP with a recording device on each end (30 ms per change): both
  devices set to the initial size, the client lowered before the server,
  the server lowered before the switch completed, traffic on every channel
  after the switch down, both raised after the switch up (each device saw
  exactly initial, lowered, initial), status reports the applied MTU, and
  both devices are back at their earlier 1500 after the session ends
  (three clean runs). Full suites 2026-11-24: `l2tunnel-runtime --lib` 402
  passed; `RUST_MIN_STACK=4194304 l2tunnel-client-core --lib` 270 passed,
  1 ignored (three clean runs); Clippy `--no-deps` and rustdoc clean. Not
  run: a privileged run on a real TUN device (LT-06, the owner's).
- [x] [LT-05] Connection page controls (FEC toggle, repair rate, MTU) mapped to catalog members; CLI equivalent. Evidence: [API types](../../crates/l2tunnel-client-core/src/local/tuning.rs) and [tests](../../crates/l2tunnel-client-core/src/local/tuning_tests.rs), [service resolution](../../crates/l2tunnel-client-core/src/service/tuning_local.rs), [CLI](../../crates/l2tunnel-client-core/src/cli_groups_tune.rs), [GUI panel](../../crates/l2tunnel-desktop-ui/src/tuning_panel.rs), the service end-to-end test (`tuned_client_proposes_at_connect_and_switches_fec_off_live`), 2026-11-24.
  Decision 10. API: `tuning_get` and `tuning_switch` in local API version 5
  ([local operations](local-operations.md)); `l2tunnel::live_tuning::tune`
  gives the entry for a setting around a base. The service resolves a
  setting to the current entry with only the tuned fields changed when the
  catalog holds it, otherwise to the single catalog entry with that
  setting; anything else is refused before a request key is consumed
  (`not_in_catalog`, `ambiguous_setting`, `invalid_setting`). A leader's
  failed device-MTU lowering is reported as `DeviceMtu` in the completed
  switch.
  CLI: `l2tunnelctl tune show` (current setting, choices per control,
  every reachable setting with the current one marked, device MTU state)
  and `tune set [--repair off|N/D] [--device-mtu N] [--path-mtu N]` with the
  usual `--request-key`, `--watch` and `--detach`; controls not given keep
  their current value (read with `tuning_get` first).
  GUI: the Connection page has a "Live tuning" section (shown when the
  service serves the catalog): an FEC on/off checkbox (turning FEC on
  restores the last rate chosen, else the current or lowest), a repair-rate
  choice, device MTU and path MTU choices, the service's device MTU line,
  and Apply/Reset. Apply is enabled only for a changed setting the catalog
  holds; other combinations are flagged as not in the catalog. The view is
  re-read when the session's generation or epoch changes.
  Checks: `cargo test -p l2tunnel-client-core --lib` tuning DTO test
  (choice lists, ordering, wire round trip, strict fields, malformed
  repair), CLI tests (parsing, required control, value checks, the marked
  current setting in `tune show`), and the service end-to-end test over
  real UDP (after a live FEC-off switch, `tuning_get` reports the live
  catalog, choices `off, 1/3` and FEC off as current; `tuning_switch` back
  to `1/3` completes through `operation_wait`, both ends report the initial
  entry at the next epoch and traffic passes on every channel; a setting
  outside the catalog is refused with `not_in_catalog`);
  `cargo test -p l2tunnel-desktop-ui` 26 passed (panel logic: FEC rate
  restore order, reachability). Full suites 2026-11-24: `l2tunnel --lib`
  235; `l2tunnel-runtime --lib` 402; `RUST_MIN_STACK=4194304
  l2tunnel-client-core --lib` 274 passed, 1 ignored in 8 of 9 runs; one
  run failed `retained_tls_full_fixed_proxy_preserves_tcp_and_retirement`,
  which passed alone six times (the same intermittent TLS-proxy teardown
  case noted under LT-03, not investigated further); Clippy `--no-deps`
  and rustdoc clean. Not done: drawing the panel in a test, or a visual
  check with a live-tuned session (needs the rebuilt service installed;
  LT-06).
  Gate, 2026-11-24: `tools/check.py` stopped at its first step because the
  repository `.venv` has no packages (no numpy), so it was not completed;
  the venv was left as is (the running demo pair uses it). Steps run by
  hand instead, all passing: checklist IDs, smoltcp source, TCP-header
  goldens, compact ARQ events, `l2tunnel-codec --no-default-features`,
  `l2tunnelctl plan`, the external Common CLI process probe (quic-like and
  media-like, 50 external processes each, 64-member catalog, four
  switches), and the unittest modules `test_fake_local_service`,
  `test_profile_daemon`, `test_service_start`, `test_local_real_pair`,
  `test_selftest` (19 tests, 2 skipped). Not run: the aligned/packed
  golden checks and the simulator suite (need numpy), and workspace-wide
  Clippy/tests (another session's in-progress Windows code does not
  compile: `l2tunnel_platform_windows::local_pipe`).
- [x] [LT-06] Real run: switch FEC and MTU live on a connected session. Evidence: [live tuning service](../../crates/l2tunnel-client-core/src/service/tuning_local.rs), [rate budget service](../../crates/l2tunnel-client-core/src/service/rate_budget_local.rs), and local isolated-namespace real-TUN `l2tunneld` + `l2tunnelctl` receipt `work/quick-close-20261125/receipt.json` (real kernel `tun0` MTU `1500 -> 1400 -> 1500` on both peers with `failures: 0`, live FEC `off -> 1/4 -> off` with `0%` ping loss at every step, and live `tune budget --symmetric 250` accepted).
