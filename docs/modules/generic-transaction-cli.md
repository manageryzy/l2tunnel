# Explicit generic transaction CLI, implementation contract v0

Status: **complete-plan frontend implemented, with finite construction and
external CLI/shared-service integration tests**. The source-stable combined batch
passes. Successful production CLI TAP/TUN startup and the complete frontend
negative/lifecycle matrix remain open. This additive frontend exposes the existing
shared service/APIv3 under the active implementation goal; it is not an owner
scope decision, a new default or completion of a parent gate. The complete schema
and acceptance below are retained. Root owns validation and Git. Performance
workloads remain deferred.

## Current path and required seam

`cli.rs` registers `secure_udp/cli.rs` as `secure_udp_frontend`. Its selection
runs before the other carrier frontends. For explicitly selected quic-like or
media-like, the current path requires Swift/full/no-compression, manually supplied
Noise/member/admission/cookie credentials, fixed endpoint addresses and a readable
packet attachment. It builds the existing `secure_udp::profile::Profile`, then
submits `Prepared::secure_udp_client/server` to the shared service. The Linux
execution path does not call a runtime directly.

Actual shared `Prepared::secure_udp_transaction_client/server`, typed transaction
commands, portable complete-C/status DTOs and local API version3 exist in source.
Before this checkpoint the CLI had no generic plan selector or command arm for
the complete-C action, and its help/event projection described only the legacy
profile. The additive Selected sum and explicit plan now route directly to the
existing transaction Prepared/service path, with separate bounded event/inspection
projections. The original path remains available without the flag. External
command evidence below is separate from successful production CLI device startup.

The legacy builder is not a valid generic-plan intermediate. It produces
`streams=None`, kilobit/permille policy fields and startup directions accepted by
legacy `Profile::new`, which intentionally requires exact125-byte rate units,
symmetric channel/window/repair representation and its old digest graph. Building
that Profile first would reject valid generic odd rates, exact fractions and
asymmetric widths. Extract shared raw physical/session inputs before the legacy
Profile constructor; legacy then calls exactly its old constructor, while the
explicit new branch constructs the real transaction Profile.

## Frozen additive flags and authority

Add exactly one startup selector:

    --swift-transaction-plan PATH

Its presence explicitly selects `generic_swift_v1`. Its absence preserves the
current selection, defaults, wire bytes and old flags. Keep explicit
`--carrier quic-like|media-like --record-profile swift --duplex full` and no
compression. Swift remains the algorithm inside the selected carrier. This slice
does not implement or relabel another carrier, authenticate a third-party
endpoint, or create another socket/connection/bootstrap path.

Keep existing address/device/layer/max-packet, manual own-trust credential,
`--control-socket`, `--runtime-model` and `--max-path-mtu` behavior. The unchanged
maximum-MTU default remains9000 and participates in the real immutable geometry.
The plan owns all generic initial mutable values and reporting/resource/timing
values. On the generic branch, reject simultaneous `--path-mtu`,
`--swift-forward-kbit`, `--swift-reverse-kbit`, `--swift-channels`,
`--swift-window`, `--swift-repair-permille` and `--swift-report-ms` as conflicting
authorities. Do not silently apply their defaults or round a descriptor to those
fields. These flags retain their complete existing meaning on the old path.
Reject the new selector with another carrier/profile or unrelated mode options.

Represent this privately as a selected legacy/generic sum type, not a fabricated
legacy Policy containing rounded generic values. The common part retains cover,
role, endpoints, Noise pattern and immutable capacity. Preserve the existing
Selection API internally where that reduces churn; no public selection API is
required by this proposal.

## Bounded plan file version1

Use one strict UTF-8 JSON object, read from one already-open regular file with a
256KiB cap and an extra-byte overflow witness. Reject empty, nonregular, truncated,
oversized, trailing-content, duplicate-field and unknown-field input. This is a
nonsecret configuration file, not a replacement for any private credential file.
Do not read a directory, FIFO, device, URL or standard-input stream. Bound catalog
length before constructing its entries, rather than parsing an unbounded Vec and
checking its length afterward. Keep parser recursion finite (the schema needs
fewer than16 levels). The byte cap bounds whitespace too. Test the largest valid
64-member serialized shape; do not shorten a catalog to fit the file cap.

All fields below are required, including zeros where the actual validator permits
them. No optional patch, implicit policy inheritance, comments or extensions are
accepted in version1. JSON integers must fit their declared type without floats,
negative values, saturation or string-to-number coercion. Parse wire-sized values
as u64/u32/u16 and checked-convert every usize. Unknown enum strings fail.

Top-level object:

    version: 1
    backend: "generic_swift_v1"
    initial_index: integer in0..catalog.len
    catalog: array of1..64 Descriptor objects
    transaction: Transaction object
    runtime: Runtime object

`initial_index` indexes the input array before canonical sorting. It selects one
actual complete Descriptor, not a second independently specified initial value.
Construct `Catalog::new(initial, &all_descriptors)` without filtering. The actual
Catalog sorts full canonical bytes, rejects duplicate/unlisted/invalid values and
retains that exact initial member. File order and whitespace are not hash inputs.

Descriptor object:

    path_mtu: u64
    forward: Direction
    reverse: Direction

Direction object has exactly these16 fields, matching the existing canonical
field order and units:

| JSON field | Exact actual value |
| --- | --- |
| channels | records.channels, checked usize |
| layer | "ethernet" or "ip", mapped to records::Layer |
| max_native | records.max_native, checked usize |
| bytes_per_second | policy::Direction byte rate, u64; no kbit conversion |
| datagram_bytes | codec.datagram_bytes, checked usize |
| window | codec.window, checked usize; repair support, not ARQ flight |
| repair_numerator | codec.repair_numerator, u32 |
| repair_denominator | codec.repair_denominator, u32; no permille conversion |
| flow_sources | codec.flow_sources, checked usize; independent retained-source bound |
| queue_bytes | codec.queue_bytes, checked usize |
| max_packet | codec.max_packet, checked usize |
| flush_micros | codec.flush_micros, u64 |
| feedback_micros | codec.feedback_micros, u64 |
| tail_micros | codec.tail_micros, u64 |
| min_rto_micros | codec.min_rto_micros, u64 |
| max_rto_micros | codec.max_rto_micros, u64 |

Build the actual policy/records/codec types and call `Descriptor::new`; do not
write another canonical encoder. Both layers/native maxima must match the fixed
ConnectionConfig and attachment. Carrier geometry is checked by actual Profile
resolution for every descriptor in both roles. Explicit datagram_bytes are
verified, never silently recomputed to make a bad descriptor pass. Current
selected-runtime MTU/native/channel limitations remain explicit rejections;
the pure304-byte configuration's representable range is not a platform claim.

Transaction object:

    retry_ms: u64
    phase_timeout_ms: u64
    reconcile_timeout_ms: u64
    max_operation_ms: u64
    retained_bytes: u64, checked usize

Map these exactly to shared runtime-owned `TransactionSettings` (reexported as
transaction_profile::Parameters). Use its actual validation. Do not add another
client timing owner or convert the original operation cap into a retry timeout.

Runtime object has these required members:

    control_epoch: u64
    data_epoch: u64
    legacy_policy: { transaction_micros: u64, max_outbound: u64 }
    security: { packets_per_key: u64, max_body_bytes_per_key: u64 }
    control: Delivery object
    streams: { transaction: Message object, liveness: Message object,
               data_feedback: Message object }
    wire: { initiator_burst_bytes: u64, responder_burst_bytes: u64 }
    work: { receive_interval_micros: u64, receive_packets: u64,
            send_batch: u64, native_read_batch: u64, native_write_batch: u64 }
    native: { pending_packets: u64, pending_bytes: u64,
              stall_timeout_micros: u64 }
    lifetime: { lease_micros: u64, ping_interval_micros: u64,
                pong_timeout_micros: u64 }
    report_interval_micros: null or u64

Delivery object:

    recovery: { max_source_bytes: u64, send_bytes: u64, receive_bytes: u64,
                send_records: u64, receive_records: u64,
                initial_rto_micros: u64, maximum_rto_micros: u64,
                ack_delay_micros: u64, max_retries: u16 }
    interval_micros: u64
    packets_per_interval: u32
    bytes_per_interval: u64

Message object:

    max_message_bytes: u64
    max_outbound_messages: u64
    max_outbound_bytes: u64
    max_fragments: u16
    max_reassembly_bytes: u64
    max_incomplete_messages: u64
    message_lifetime_micros: u64
    work_per_call: u64

Every usize field above is checked on conversion. Duration fields become exact
`Duration::from_micros`, without floating-point conversion. Actual validators
still decide nonzero/range/time/lease/fence representability. The inactive legacy
policy fields remain explicit because the actual runtime template retains/hashes
them; exposing them does not activate a second coordinator in the generic path.

The following derived fields are deliberately absent, with one authoritative
construction rule for each:

- Role send/receive values come from the initial global Descriptor; responder
  reverses complete directions, including all16 fields. It does not independently
  parse a second mutable catalog.
- Initial transport/stream path MTU comes from the initial descriptor. Later role
  resolutions and per-stream path MTU use actual Profile/runtime resolution.
- Security max_body_bytes comes from the same maximum-MTU/cover geometry used by
  the existing frontend. Both cover capacity and that ceiling remain fixed.
- Control wire_overhead uses the existing IP/cover/common-record/AEAD geometry.
  Each Message's delivery is the exact base Delivery plus the existing8-byte
  stream wrapper. Do not expose independently inconsistent copies of the base
  ARQ/quota contract or manually configured cryptographic overhead.
- Ordered public cover identifiers, bootstrap profile/application seed, outer
  salt, gate/bootstrap bounds and membership admission settings use the shared
  raw builder's existing domains and rules. No user-supplied CID replaces trust.
- Report cadence is one explicit immutable plan value for both role templates;
  no hidden legacy CLI report default overrides it.

This file is a complete constructor for the proposed generic CLI envelope, not
an assertion that it exposes every possible programmatic setup parameter.
Existing carrier/trust/bootstrap CLI capabilities remain intact. Any additional
capability needed to represent a requested deployment must be specified and
rejected explicitly while missing, not removed from its checklist. Future schema
versions require a separate compatibility contract.

## Actual acyclic identity construction

The file accepts no E, H0, D0, catalog root or anchored304-byte configurations as
startup authority. A304-byte C already embeds E, so hashing such values to obtain
the catalog/immutable envelope would create the forbidden cycle.

The common builder supplies raw original session Settings, base ConnectionConfig,
ordered actual Noise public pins, explicit member public identity and two complete
role templates. Construct the full Descriptor catalog, then call the existing:

    transaction_profile::Profile::new(
        connection, raw_settings, actual_peers,
        initiator_template, responder_template, entire_catalog, parameters)

That actual method validates every member under both roles and binds both
immutable inventories, original own-trust/settings, resources and parameters.
Its existing graph is authoritative:

    original settings/pins + base native contract + role templates + K + parameters
        -> E
    C0 = Configuration(E, exact initial Descriptor)
    D0 = actual transaction::configuration_digest(C0)
    original application seed + E + K + D0 -> selected application
    selected Settings.configuration(actual_peers) -> H0

K hashes sorted anchor-free272-byte descriptors. C is304 bytes:8-byte prefix,
32-byte E,8-byte active MTU and two128-byte complete directions. No frontend
reimplements either digest graph, strips E from arbitrary C bytes, modifies a
catalog root, guesses an authenticated digest or calls the runtime contract
constructor as a substitute for Profile. Derivation is not authentication;
H0 becomes effective only through the existing actual factory/handshake/member
success. Keep E/H0/D0 and requested/effective state distinct in output.

Refactor the current legacy builder at its raw Settings/template seam, before it
calls legacy Profile::new. Do not feed legacy Profile.settings() into the generic
constructor: that application value has already been changed by the old digest
graph. Preserve old domain bytes and ordering on the old path with golden tests.

## Shared service execution and observable output

The explicit branch calls only `Prepared::secure_udp_transaction_client/server`
with that Profile, the same actual Noise/member/admission/cookie credentials and
the same deferred readable Attachment. Then use the existing service channel,
connect/wait/cancellation/local server path. It must not call run_transaction,
create a private socket, bypass Prepared's pin/member/pattern/attachment checks or
instantiate a second authentication/lifecycle loop. Attach the device only through
the existing deferred provider after real authentication.

Generic ready/report/terminal projection must use
`Observation::secure_udp_transaction` and its actual frame/status DTO. The current
legacy `emit_performance` lookup returns no generic frame; treating that absence
as legacy output or synthesizing a SwiftPolicyV1 summary would be incorrect.
Keep the current bounded output Sink and setup-failure event path. Emit clearly
separate generic event names, for example secure_udp_transaction_ready/status/
terminal, without changing existing event bytes. Public canonical values and
catalog root/count are safe to report; no key bytes, credential paths, provider
messages or unbounded Debug output are added.

Resource status remains the actual value, including
resource_preallocation_complete=false while the broader reservation work is
unfinished. Plan validation is not storage reservation. A real allocation/budget
failure stays an explicit failure; do not remove catalog members, lower queue
bounds, substitute a smaller C, or silently select legacy. Fresh reconnect retains
the exact accepted plan, not live-file rereading or old-session delivery state.

## Exact strict-v3 command

Add one CLI local action:

    switch-swift-configuration --control-socket PATH --api-version 3 \
        --configuration EXACT_608_LOWERCASE_HEX

Its complete request is the existing schema:

    {"version":3,"action":{"command":"switch_swift_configuration",
       "configuration":"<exact608-character canonical value>"}}

Require explicit --api-version3 for this command. Bound the argument before
copying and parse through the existing CanonicalConfiguration checked DTO. A
small TryFrom<&str>/parse constructor delegating to its existing decoder is an
acceptable additive ergonomic seam; a second hex/configuration parser is not.
Reject legacy partial-policy flags and unknown arguments. Do not map this command
to SetSwiftPolicy or translate units. Send exactly one existing local::Request;
the local adapter reaches Handle::apply_transaction and its exact replay/catalog/
role/cap/peer-completion semantics. A canonical but foreign E/catalog value is
refused by the actual backend before effects, not rewritten by the CLI.

Status/disconnect/reconnect keep their existing default version1 and accept an
explicit version3 for selected generic sessions. Generic rejects1/2; non-generic
rejects3 with existing codes/state rules. Keep the request's version on replies
and never retry a mutating command under a different version. Update stale help/
validation wording to list1/2/3 while preserving v1/v2 bytes and old commands.
Retain existing4096-byte request,8192-byte response, UID/socket ownership and
transport timeout limits. This adds no IPC catalog-discovery action or full
catalog duplication in every status.

To make target selection usable without requiring operators to implement the
identity graph, include one explicit read-only companion in this slice:

    inspect-swift-transaction-plan <same generic startup plan/trust options>

It executes the same bounded file/credential/Profile construction without a
socket, service request, device attachment or claimed authentication/readiness.
It outputs one bounded JSON object containing backend, H0, E, K, initial C,
parameters and all exact supported anchored C values using
Catalog.configurations(Profile.envelope()) and CanonicalConfiguration. Label it
requested/validated and authenticated=false. Catalog indices in this output refer
to the printed canonical order; the file's initial_index selects only initial
construction before sorting. The operator can copy one exact C into the strict-v3
command. At64 members the608-character values occupy under40KiB before small
metadata; test the complete object against the existing128KiB output line bound.
A broken output is an observation failure, not permission to start a connection.
This avoids a new paginated IPC contract while retaining the entire catalog.

The companion's common options include the same explicit connect/serve role,
carrier, layer/max-packet, endpoints, maximum MTU and own-trust inputs needed by
Profile. It does not require or open a device/control socket, admission cookie or
other secret used only by running authentication; do not pretend an unused secret
is necessary for a pure construction. The exact role selector is `--role connect|serve`, using the existing command
role rules. This is an engineering grammar choice, not an owner scope decision.

## Focused validation and acceptance boundary

Before code, freeze final flags/schema/ownership and bind current source bytes.
Suggested disjoint implementation files are a new cli transaction-plan parser/
builder child and isolated tests; root owns cli.rs command registration/API
routing and shared service projection. Reuse current credentials/Profile/Prepared
instead of adding a public protocol dependency on serde or platform APIs.

Required focused evidence includes:

- Exact legacy option/default/profile digest/event/v1-v2 request golden parity;
  no-new-flag selection and old set-swift remain unchanged.
- File boundaries/duplicate and unknown fields/trailing data/nonregular input;
  max64, empty/65th/duplicate catalog; initial index; every integer conversion,
  full asymmetric odd-rate/fraction values, native/MTU/body and all fixed controls.
- Real Profile construction in both command roles and both actual covers;
  unchanged catalog root under JSON reorder, altered E/H0 on immutable/trust/
  parameter changes, exact C/D0, full maximum directional fence capacity and no
  anchored-C/catalog self-reference. Fail before socket/provider effects.
- Full exact catalog preservation through Prepared, factory and status. An
  insufficient budget or unsupported geometry remains explicit. Prove no silent
  pruning, policy rounding, credential generation or legacy fallback.
- Maximum valid608-character command and bounded request/reply; uppercase/odd/
  short/long/noncanonical/foreign-envelope/unlisted values; partial-policy
  conflicts; wrong-version-before-key-consumption; unchanged replay/conflict,
  lost response/outcome_unknown and cross-backend reconnect rules.
- Actual external process/Unix-socket requests for connect/status/switch/
  disconnect/reconnect, including bad version and shared API rejection paths.
  In-process typed calls alone cannot close GCS-09. Any actual native two-process
  run must stay in owned namespaces with the unchanged socket/setup/capture/
  cleanup/80/performance requirements; privilege and execution remain root-owned.
- English help/status/errors, explicit Linux execution support, portable parsing/
  DTO versus real Windows/Android support, meaningful focused tests followed by
  required frozen-source formatting/Clippy/rustdoc/tools/check.py.

Do not check GCS-09 from this proposal or from compiling a parser. GCS external
selection, full generic resource admission, fault acceptance, cross-profile SW-11,
RLNC/parity/rolling/packed/proxy and all carrier/platform/mode-parity gates retain
their full existing definitions. No workload or new default is authorized here.

## Frozen private integration API and ownership

The private parser module is a child of the Unix-only secure UDP CLI frontend:

```rust
pub(super) struct Plan; // checked complete catalog, parameters and runtime DTO
impl Plan {
    pub(super) fn read(path: &Path) -> io::Result<Self>;
    pub(super) fn initial(&self) -> Descriptor;
    pub(super) fn report_interval(&self) -> Option<Duration>;
    pub(super) fn build(&self, connection: ConnectionConfig,
        raw: secure_udp::Settings, peers: establish::Peers,
        maximum_body: usize, wire_overhead: usize)
        -> io::Result<transaction_profile::Profile>;
}
```

Build borrows the Plan and clones only its bounded actual Catalog. Raw gate MTU
must equal the initial descriptor; reject mismatch rather than rewriting it.
Root extracts the common raw settings/geometry before legacy Profile construction.
Retain the existing crate-private Copy `Selection` as the legacy builder, because
existing profile/performance/service tests use it. A separate private Selected
sum chooses Legacy(Selection) or the checked generic Plan plus common physical
inputs. Generic descriptors are never represented by a fabricated legacy Policy.
`report_interval_micros` is required even when null; missing differs from null.
Check actual u32/u16 destinations as well as usize when converting schema integers.

The output module returns bounded serde_json Values built from the actual Profile
and actual transaction Status. Root sends these through the existing bounded Sink.
Inspection is synchronous before host-runtime construction, requires `--role`,
actual local Noise private/remote public pins and member identity/trust inputs,
but rejects device/control/admission/cookie/runtime-model options. Noise profile
and required PSK syntax/validation remain explicit. It does not create a credential
for authentication, socket, service or device. Startup still requires all original
runtime credentials. Add `CanonicalConfiguration::parse(&str)` through its existing
complete decoder; no alternate encoding or parser. The exact output APIs will be
recorded before their owner edits source.

### Frozen output and observation refinement

The private output API is `inspection(&Profile, Role) -> io::Result<Value>`,
`ready(&Frame, expected_generation:u64) -> io::Result<Value>`,
`status(&Frame, expected_generation:u64) -> io::Result<Value>` and
`terminal(&Frame, expected_generation:u64, Terminal) -> io::Result<Value>`.
Frame is the existing SecureUdpTransactionFrame. Distinct schema1 event names are
secure_udp_transaction_plan/ready/status/terminal. Keep actual Status unchanged;
reject generation mismatch, false readiness and inconsistent terminal overlays.
Bound values to128KiB−2048 for existing Sink health/newline headroom. No separate
frontend state machine or deduplication owner is needed. Root retains Sink/I/O.

Inspection reads the actual existing local Noise private/remote public inputs
and, for IKpsk2, the configured existing PSK through the same checked credential
constructor. This validates supplied configuration, not remote possession or
authentication. It never needs admission/cookie keys or a device/control socket.
Report cadence is an explicit local retained plan value, copied to both role
templates. The actual runtime intentionally excludes it from peer identity
digests; do not claim changing cadence alone changes E/H0. Preserve that existing
behavior. Typed Handle keyed retry/conflict remains separate from external IPC:
the current Request has no RequestKey field. External commands send one request,
never silently retry/version-fallback, and report actual backend results.

Nonprivileged external IPC tests may use real Prepared/service owners with
UnixDatagram PacketDevices. They do not prove successful production connect/serve
TunTap attachment. That explicit startup/native acceptance remains required
unless an owned native functional lab supplies actual devices; no hidden device
fallback is authorized and no throughput claim follows from functional traffic.

## Current finite implementation and validation

The [source-stable aggregate](../../work/generic-transaction-cli-20261114/aggregate-attempt-2/validation.json)
passes1960 Rust cases including doctests,376 tooling cases and1658 simulator
cases, with workspace formatting, strict Clippy and strict rustdoc. New focused
parser, frontend construction, output, resource and IPC cases execute inside that
single required batch; they were not followed by per-leaf full-suite reruns.
Earlier diagnostic failures and targeted affected-package logs remain preserved.
The [pre-annotation source check](../../work/generic-transaction-cli-20261114/pre-annotation-source-validation.json)
verifies all1033 recorded inputs before evidence-only documentation changes.

The [external probe receipt](../../work/generic-transaction-cli-20261114/external-cli-validation.json)
records34 real daemon CLI processes for each cover. It checks full64 inspection
for both roles and IK/IKpsk2, exact catalog/order/trust/cadence behavior, strict
negative files/options, and actual v3 commands against two authenticated shared
service owners. The live fixture uses2 supported configurations and actual Unix
packet devices; it carries nonzero traffic through2/3→4/1→2/3, observes actual
Pong, disconnects and freshly reauthenticates. Reporting remains disabled.
Neither endpoint service in that fixture is started by production CLI connect/
serve. Full64 inspection is not64-member live traffic or TAP/TUN qualification.

Fixed v1/v2 wire goldens and strict v3 real IPC tests cover framing/unknown/
duplicate/truncated/oversized values, zero-effect version refusal and finite
reply-loss/mismatch/malformed no-retry cases. The complete GCS-06/07 and GCL-06
matrices remain open. Startup dispatch is implemented through the sole existing
service; successful real CLI deferred TunTap attachment and its full ready/status/
terminal lifecycle are still required by GCL-04/07. No hidden attachment fallback
is present. The generic CLI handles Aborted completion before forgetting its
actual terminal generation; stdout remains bounded best-effort telemetry. A fast
reconnect whose old frame is already superseded records projection_error rather
than inventing prior runtime facts. Local API status remains authoritative.

No new native/performance/remote-CI/Windows/Android execution is inferred. Full
CRS resources, automatic retained-state recovery, fresh rekey, full SW-11 and all
other carrier/profile/mode/GUI requirements remain unchanged.

## Stable child tasks

- [x] [GCL-01] Freeze complete grammar/schema/private ownership and pre-edit source binding without recording engineering choices as owner scope decisions. Evidence: [source-stable combined checks](../../work/generic-transaction-cli-20261114/aggregate-attempt-2/validation.json); production CLI/device and parent gates remain open.
- [x] [GCL-02] Implement bounded nonblocking regular-file reading and strict complete1..64-catalog parsing, required nullable fields, all integer/native/geometry validation, exact asymmetric byte/fraction values and no pruning/rounding/default fallback. Evidence: [source-stable combined checks](../../work/generic-transaction-cli-20261114/aggregate-attempt-2/validation.json); production CLI/device and parent gates remain open.
- [x] [GCL-03] Build actual complementary runtime templates and transaction Profile from original raw Settings before legacy derivation; preserve actual K/E/C0/D0/H0 and full catalog/own-trust/resource semantics with both-role/cover and legacy golden evidence. Evidence: [source-stable combined checks](../../work/generic-transaction-cli-20261114/aggregate-attempt-2/validation.json); production CLI/device and parent gates remain open.
- [ ] [GCL-04] Wire explicit generic startup through actual Prepared and existing service/credentials/deferred device/local server, retaining fresh reconnect ownership, original deadlines and strict requested/effective/capability/terminal status.
- [x] [GCL-05] Implement strict-v3 complete-C CLI action and read-only bounded full-catalog inspection through existing checked DTO/identity construction, with no IPC downgrade/retry or inspection side effects. Evidence: [source-stable combined checks](../../work/generic-transaction-cli-20261114/aggregate-attempt-2/validation.json); production CLI/device and parent gates remain open.
- [ ] [GCL-06] Preserve old CLI/default/domain/event/v1-v2 behavior and verify strict malformed/conflicting/oversized/nonregular/file/catalog/credential/configuration negatives before socket/provider effects.
- [ ] [GCL-07] Verify actual external process and Unix IPC connect/status/switch/disconnect/reconnect/version/error behavior on the selected new CLI path, distinguishing in-process fixtures and any owned native functional lab from performance acceptance.
- [x] [GCL-08] Run focused integration/failure tests and required source-stable workspace formatting/Clippy/rustdoc/tools checks; preserve failed attempts and commit coherent exact evidence without closing unsupported parent gates. Evidence: [source-stable combined checks](../../work/generic-transaction-cli-20261114/aggregate-attempt-2/validation.json); production CLI/device and parent gates remain open.

These tasks are children of GCS-09, not reduced substitutes. Full runtime/resource/
fault/cross-profile/native/platform/GUI and all47 mode requirements remain intact.
