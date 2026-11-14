# Complete common record configuration

Status: **implemented and protocol-tested; runtime selection and full stage acceptance remain open**.
Interfaces were frozen by the integrator against clean checkpoint
`e5c2b93a24cd69f02d5bcaa67592e233f14d3a70`. The complete pure module and independent
fixed vectors pass the [affected checkpoint](../../work/record-composition-20261114/scoped-checkpoint-validation.json).
The machine-readable pre-edit binding
is [configuration-preedit-v0.json](../../work/record-composition-20261114/configuration-preedit-v0.json).

Read the [architecture](../architecture.md), [implementation plan](../implementation-plan.md),
[master checklist](../implementation-checklist.md), [mode parity](../mode-parity.md),
[directional endpoints](directional-record-endpoints.md),
[Swift adapter](swift-record-adapter.md), [generic runtime](generic-secure-udp.md)
and [common engine proposal](common-record-engine.md). Existing pure Swift,
Aligned and Packed owners have scoped tests; this value does not compose their
runtime lifecycles. Full SW-11, opposite-family directional composition, remaining
RLNC/parity/rolling/proxy families, all 47 parity definitions and platform/native/
80 Mbit/s gates remain in scope. No future algorithm variant is implemented by
this configuration design.

## Current source and encoding requirement

`swift_configuration` v1 contains a 272-byte anchor-free Descriptor and a
304-byte Configuration, including independent 128-byte directional policies.
It binds a typed envelope label, path MTU, complete record policies and rates.
Its bytes, digest domains, catalogs, public methods and selected API behavior
remain available unchanged; no v1 byte receives a new interpretation.

Actual Aligned configuration fields occupy 332 bytes per direction in their
existing scalar order; Packed adds 24 bytes. Complete independent policies need
664/712 bytes before common MUX/rate/native-window policy. The current transaction
trait's legacy 512-byte bound cannot represent these values. The integrator's
proposed additive `ConfigurationEncoding::CompleteV2` admits an explicitly
selected exact encoding of at most 4096 bytes. Existing implementations retain
`LegacyV1` and its 512-byte bound. This proposal uses CompleteV2 and a new v2
canonical prefix/domain. It neither changes L2MC's header nor adds a transaction
state machine or automatic protocol downgrade.

## Frozen public values and adapter surface

Add pure `l2tunnel::record_configuration`, with checked constructors and private
Descriptor/Configuration fields. It contains only the three actual families:

```rust
enum Profile {
    Swift { forward: swift::records::Config, reverse: swift::records::Config },
    Aligned { forward: aligned::Config, reverse: aligned::Config },
    Packed { forward: aligned::packed::Config, reverse: aligned::packed::Config },
}
enum NativeWindow { Disabled, Delivery(flow_control::delivery_window::Config) }
struct CommonDirection {
    traffic: core::traffic::TrafficPolicy,
    pipeline: pipeline::PipelineConfig,
    bytes_per_second: u64,
    burst_bytes: usize,
    native_window: NativeWindow,
}
Descriptor::new(path_mtu: usize, duplex: core::Duplex,
    forward: CommonDirection, reverse: CommonDirection, profile: Profile)
    -> Result<Descriptor, Error>;
Configuration::new(envelope: EnvelopeDigest, descriptor: Descriptor)
    -> Result<Configuration, Error>;
Descriptor::{encode_into, decode, validate};
Configuration::{encode_into, decode, validate, envelope, descriptor};
Descriptor::{path_mtu, duplex, profile, direction, local, sender_channels};
Catalog::new(initial: Descriptor, supported: &[Descriptor]) -> Result<Catalog, Error>;
Catalog::{initial, descriptors, root, configurations};
```

`CommonDirection` has a checked constructor and immutable field accessors.
`direction(global_sender: management::Role)` returns a borrowed directional view
containing the exact common value and a typed reference to its complete Swift,
Aligned or Packed value. `local(role)` returns local send/receive views by swapping
the two global directions for the responder. `sender_channels(role)` comes from
the actual installed profile configuration and must equal that direction's MUX
width; it is never inferred from the other direction or reduced modulo a cap.
The view preserves separate native, source and output bounds. Swift's own
`max_native`, codec `max_packet` and `datagram_bytes` remain distinct; Aligned
body symbols, original recovery sources and complete recovery packets remain
distinct. Exact derived workspace/wire geometry belongs to the maintained
profile plan/encoder and common engine binding, not a guessed MTU subtraction.

Profile pairs use the actual same-family duplex constructors. Mixed Aligned/
Packed or other opposite-family directions remain explicit open SW-11 work;
this wave does not synthesize them from two unused bidirectional endpoints.
No Frame/Rolling/RLNC/parity/proxy placeholder variant is added as a delivered
engine. Existing `TrafficPolicy::SplitTcpProxy` can express requested TCP
ownership, but schema validity does not install that owner: capability admission
must reject it until the actual proxy composition exists.

The value is complete for its explicitly selected schema fields. It does not
serialize every Active/profile-specific proxy or platform policy. In particular,
TunnelCredits requires an actual Active/credit protocol and its complete capacity,
feedback and lifecycle configuration; selecting DeliveryWindow alone provides
none of those composition guarantees. All existing Active, rolling, RLNC, parity,
proxy and native-window runtime requirements remain follow-ons. A migration must
carry their complete values or reject the request, with no silent capacities,
default substitution or field-loss conversion.

## Exact CompleteV2 encoding

All scalar words are unsigned big-endian u64. There are no native-width integers,
floats, inferred defaults, optional omitted fields or length prefixes inside the
fixed value. Constants are:

| Constant | Bytes |
| --- | ---: |
| `HEADER_BYTES` | 16 |
| `COMMON_DIRECTION_BYTES` | 272 |
| `PROFILE_SLOT_BYTES` | 356 |
| `DIRECTION_BYTES` | 628 |
| `DESCRIPTOR_BYTES` | 1272 |
| `CONFIGURATION_BYTES` | 1304 |

The 16-byte header is `L2RC` at 0..4, version 2 at byte 4, profile tag at
byte 5 (Swift=1, Aligned=2, Packed=3), duplex at byte 6 (Half=1, Full=2),
zero reserved byte 7, and path MTU as u64 at 8..16. Path MTU is the complete
IP-packet ceiling in 256..=65535, not a body/source/native maximum.

| Complete Configuration range | Content |
| --- | --- |
| 0..16 | Header |
| 16..48 | Exact 32-byte immutable-envelope label |
| 48..320 | Forward common direction |
| 320..676 | Forward record profile slot |
| 676..948 | Reverse common direction |
| 948..1304 | Reverse record profile slot |

The anchor-free Descriptor removes only bytes 16..48: header followed by forward
common/profile and reverse common/profile. Its offsets are header 0..16,
forward common 16..288, forward slot 288..644, reverse common 644..916,
reverse slot 916..1272. The same profile tag applies to both slots in this version.

### Complete common direction: 34 words

| Word indices | Exact fields in order |
| --- | --- |
| 0..3 | TrafficPolicy layer (Tap=1, Tun=2), TCP ownership (System=1, TunnelCredits=2, SplitTcpProxy=3), QoS ownership (System=1, WeightedDeficit=2) |
| 3 | Pipeline profile (TapSystem=1, TunDrr=2) |
| 4..7 | Mapping (Crc32=1, ConnectionRoundRobin=2), flow capacity, flow channel count |
| 7..9 | Flow idle Duration seconds, nanoseconds |
| 9..13 | TunDrr base quantum, maximum trusted weight, per-flow bytes, per-flow packets |
| 13..17 | Parser max packet bytes, max VLAN tags, max IPv6 extensions, max IPv6 extension bytes |
| 17..19 | Shared pipeline queue bytes, queue packets |
| 19..21 | Complete-IP bytes per second, shared full-wire burst bytes |
| 21 | Native-window tag (Disabled=0, Delivery=1) |
| 22..34 | Delivery window fields below |

TapSystem requires words 9..13 to be zero. Disabled window requires words 22..34
to be zero. Decode rejects nonzero inactive words; encoders never retain hidden
policy under them. The twelve native window fields retain the existing complete
order: target_bandwidth_bps, bootstrap_rtt_micros, min_rtt_micros,
max_rtt_micros, headroom_percent, minimum_bytes, max_inflight_bytes, max_records,
max_packet_bytes, metadata_limit_bytes, sample_ttl_micros, flush_timeout_micros.

Wire rate, native delivery target and recovery retention are separate domains.
Do not derive one from another, equate original-native bits to complete-IP bytes,
shrink a native window to a local queue or claim endpoint TCP cwnd ownership.
All user traffic, probes and TCP control frames share this common admission
policy. Feedback/control consume the actual selected carrier's shared wire
allowance; there is no second hidden data bucket or QoS exemption.

### Complete record slots

Swift uses the first 120 bytes as fifteen u64 words: channels, layer
(Ethernet=1, Ip=2), max_native, datagram_bytes, coding window, repair numerator,
repair denominator, flow_sources, queue_bytes, max_packet, flush_micros,
feedback_micros, tail_micros, min_rto_micros, max_rto_micros. The directional
`policy::Direction::bytes_per_second` is encoded once in common word 19 and
reconstructed exactly. Swift slot bytes 120..356 must be zero.

Aligned uses exactly its existing 332-byte field sequence, without the legacy
digest domain. Byte 0 is native policy (EthernetHeaders=1, RawIp=2). Three u64
body fields follow (max_frame_bytes, symbol_bytes, independent_short_frame_bytes),
then three canonical boolean bytes (elide_payload_length, predictive,
timestamp_pair_dictionary). The remaining fields follow in existing order:

1. Ten receiver words: channels, first_record, first_source, record_window,
   source_window, lookahead_records, lookahead_bytes, lookahead_fragments,
   max_fragments_per_record, lifetime_ticks.
2. Five ARQ words: max_source_bytes, send_bytes, receive_bytes, send_records,
   receive_records; then initial_rto, maximum_rto and ack_delay as three
   seconds/nanoseconds pairs; then max_retries.
3. Ten FEC/recovery words: block max_sources, max_source_bytes, max_packet_bytes,
   max_work_per_symbol, max_generations, max_symbols_per_generation,
   max_reserved_bytes, max_lifetime_ticks, generation_window, repair_symbols.
4. flush_after seconds/nanoseconds, then max_restored_packets,
   max_restored_bytes, outer_overhead_bytes, max_recovery_packet_bytes.

Aligned slot bytes 332..356 must be zero. Packed uses all 356 bytes: the same
332-byte base, followed by hold_micros, max_units and work_limit as u64 words.
No field is replaced by a default, maximum, digest-only surrogate or omitted
to fit a smaller management bound. This preserves nanosecond Duration precision
and all currently configured sender/receiver limits, even where the opposite
peer owns the corresponding half of that global data direction.

## Checked validation and capability boundary

Decode checks exact length, magic/version/tags/reserved byte, inactive padding,
checked integer conversion and canonical booleans/durations before admitting a
complete value. Duration nanoseconds must be below 1,000,000,000 before calling
Duration construction; normalization is not canonical acceptance. u64-to-usize,
u32/u16/u8 conversions are checked on the actual target platform. Never index or
allocate from an unvalidated peer count. Re-encode and compare the exact fixed
bytes before transaction/catalog admission. Encode validates first and leaves an
incorrectly sized output untouched.

Validate complete forward common policy, reverse common policy, forward profile,
reverse profile, then cross-policy relations. Reuse actual Swift, Aligned, Packed,
TrafficPolicy and delivery-window scalar validators. Swift retains its actual
equal-native-layer/max_native duplex restriction. Aligned/Packed preserve their
independent complete native maxima and geometry. For each direction, profile
channel count equals pipeline flow channels; parser native maximum equals Swift
max_native or Aligned/Packed body max_frame_bytes; the selected traffic layer and
pipeline profile match the actual record native interpretation. A selected
delivery window's max_packet_bytes equals that direction's native maximum.

Widths are Swift 1..64, ordinary Aligned 1..256 and Packed 1..255. Packed channel
255 is the container marker, not an extra channel. Reject incompatible width
before flows, header contexts, channel rotation or identities exist. Differing
directional widths are retained and returned by `sender_channels(global_role)`.

The frozen implementation consumes the shared allocation-free
`PipelineConfig::validate(self) -> Result<(), PipelineError>` extraction, also
used by the actual Pipeline constructor. It does not copy pipeline predicates
or construct a Pipeline/Scheduler just to validate canonical bytes. Flow bounds,
parse depth, queue/per-flow bounds and maximum-weight arithmetic all remain
checked; the extraction has its own affected acceptance under the integrator.

Common rate is an exact positive u64 bytes/second. It does not inherit the legacy
Swift resolver's 8,000..=1,250,000,000 range. That legacy policy and v1 encoding
retain their existing bounds, while each selected runtime/pacer must explicitly
validate its own supported rate geometry/arithmetic before using a new common
value. Burst is explicit and nonzero; neither value is clamped or defaulted.
This integrator engineering correction was captured in the additive
[rate refinement binding](../../work/record-composition-20261114/configuration-rate-refinement-v0.json)
before changing the production validator; the original proposal receipt remains
unchanged. It is not a new owner scope decision.
Pure scalar validity is separate from authenticated-envelope fit, actual cover
overhead, selected physical duplex/device compatibility and installed capabilities.
Those composition checks must reject unavailable mapping/affinity, TCP ownership,
native credit, family/duplex or packet geometry before runtime preparation.
The common engine must consume every configured policy or refuse it explicitly;
a parsed enum is not execution. Requested and effective values plus rejection
reasons must remain available through the shared service API.

## Digests, catalog and legacy preservation

Configuration digest is maintained SHA-256 over
`b"l2tunnel/record-transaction-config/v2\0" || exact_1304_bytes`.
Catalog supports 1..64 complete validated Descriptors, sorts by all 1272 bytes,
rejects duplicate bytes and requires the exact initial member. Its root is
SHA-256 over `b"l2tunnel/record-transaction-catalog/v2\0"`, then the big-endian
u16 count, then every sorted exact Descriptor. The label is absent from catalog
members to avoid envelope/catalog self-reference. Bind the resulting root and
Configuration's envelope through the existing authenticated contract builder;
constructing/copying a public digest confers no authentication authority.

A 64-entry descriptor hash preimage is 81,410 bytes before the domain, and the
64 complete Configurations occupy 83,456 canonical bytes before Rust metadata.
Hashing may stream the fixed arrays. These are not automatic message/queue
allocations or a waiver of existing control-storage bounds.

The new Configuration implements the same transaction trait only with explicit
`ENCODING=CompleteV2`, `ENCODED_LEN=1304` and the new domain. Root owns that
management extension, actual message/frame fit, complete resource admission and
API version/limits. Legacy Swift/Mode and current fixed-size JSON/API paths remain
available under their original versions; none silently retries/downgrades to
another encoding. Migrating an old Swift Descriptor requires explicit complete
common policies and equality of both original rates/path/native values; no
implicit-default conversion is proposed.

## Stable acceptance and ownership

The interface, codec, digest/catalog and literal-vector deliverables below have
scoped evidence. Remaining leaves retain their full definitions; pure values do
not qualify selected capability/resource/API/runtime admission.

- [x] [RCF-01] Freeze exact fields/lengths/tags/padding, pure API, role projection, validation order, capability boundary, file ownership and source binding. Evidence: [original engineering binding](../../work/record-composition-20261114/configuration-preedit-v0.json), [rate refinement](../../work/record-composition-20261114/configuration-rate-refinement-v0.json); no new owner scope decision or test result is inferred.
- [x] [RCF-02] Implement checked complete Swift/Aligned/Packed encoding/decoding, pure validation and exact immutable accessors with all independent fields. Evidence: [actual module](../../crates/l2tunnel/src/record_configuration.rs), [affected checkpoint](../../work/record-composition-20261114/scoped-checkpoint-validation.json).
- [x] [RCF-03] Implement maintained domain-separated digests and bounded exact catalogs without envelope self-reference; select CompleteV2 explicitly. Evidence: [catalog and digest tests](../../crates/l2tunnel/src/record_configuration/tests.rs), [affected checkpoint](../../work/record-composition-20261114/scoped-checkpoint-validation.json).
- [x] [RCF-04] Pass independent literal byte/digest vectors for all three actual families with asymmetric values, every field mutation, duration precision, profile/branch padding, truncation/trailing bytes, conversion overflow and all channel boundaries. Pure roundtrip alone is insufficient golden evidence. Evidence: [independent fixed vectors](../../crates/l2tunnel/src/record_configuration/vectors.tsv), [actual tests](../../crates/l2tunnel/src/record_configuration/tests.rs), [affected checkpoint](../../work/record-composition-20261114/scoped-checkpoint-validation.json).
- [ ] [RCF-05] Pass role/capability/catalog/legacy regressions and nonallocating
  validation checks. Cover duplicate/unlisted/catalog64/65, unavailable requested
  policies, mismatched native/queue/window bounds and exact original v1 vectors.
- [ ] [RCF-06] Integrate explicit larger encoding selection and recomputed message/
  frame/resource/API bounds in one affected source-stable batch. Keep common
  runtime/Bank composition, native callbacks/feedback/fences, full SW-11 and all
  parent modes/platform/native/performance gates separate until their acceptance.

After integrator freeze, the configuration worker proposes ownership of new
`crates/l2tunnel/src/record_configuration.rs` and dedicated new test files.
It owns this module document and pre-edit binding. Root owns facade registration,
Cargo/manifest/checklist registration, management encoding/bounds, common-runtime
integration, formatting/checks/native execution and Git. Existing Swift v1 source,
wire vectors and APIs must remain unchanged. Any shared pipeline validation edit
requires a separate explicit file/API ownership agreement before source work.

## Authored source and focused verification

`record_configuration.rs` now contains the additive CompleteV2 value, fixed-stack
codec, complete role projection, shared scalar validation, maintained SHA-256 and
fallible bounded catalogs. The source exposes exact complete family references;
it constructs no transport, Active/proxy/credit controller or runtime engine.
Legacy Swift v1 source/vectors/APIs are untouched. Allocation-free validation
does not imply the profile's runtime provisioning is fully fallible or admitted.

Ten cases in `record_configuration/tests.rs` cover fixed independent
full-byte/digest vectors for all three actual families, every wire-byte mutation,
inactive padding in both directions, lengths/tags/booleans/nanoseconds/narrow
conversion, exact channel boundaries/roles, output preservation, catalog limits,
represented-policy boundaries, positive u64 rates and the retained legacy Swift
digest. `vectors.tsv` and `catalog-root.hex` were authored from independent literal
field tables with standard Python struct/hashlib; no project codec, constructor
or encoder was imported or executed to generate expected bytes/digests.

No Cargo, formatting, build, Rust/Python test, native run or project execution was
performed by this worker. Source inspection and independent fixture/hash authoring
are not execution evidence. Subsequent integrator execution passes these ten
cases and the twelve retained Swift-v1 cases. One new test initially mistranscribed
the old v1 digest; its expected literal was corrected against the unchanged
existing independent v1 vector, then only that exact test was repeated. Old
production bytes/vectors were not rewritten. The failed attempt and precise
one-test repair remain in the composite receipt. Strict affected Clippy,
rustdoc and formatting pass; selected capability/resource/API/runtime admission
and the required full stage/native/platform acceptance remain open.
