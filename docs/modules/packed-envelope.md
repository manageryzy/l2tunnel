# Authenticated identity boundary for packed sources

Selected compact v3 now uses this module through the existing runtime owners.
See [runtime algorithm migration](compact-wire-cleanup.md)
for the selected wire representation, exact-cost boundaries and validation scope.
Legacy constructors and historical receipts below retain their original meaning.

Status: canonical envelope and focused tests pass. The pure inner [packer](packed-source.md)
preserves Python container bytes. This separate envelope supplies full identities;
it is not authentication by itself, a packed receiver, or runtime integration.
Only `l2tunnel-codec/src/packed_envelope.rs`, its focused tests and the additive
codec export are owned by this slice.

## Frozen interface and wire version

`Config { symbol_bytes, channels, max_units }` validates channels1..255 (channel255
is reserved), units1..255 and complete maximum source size <=65535. `Identity`
contains the existing authenticated Scope, authoritative recovery SourceId and
`first_unit: SourceId`. Unit IDs form a distinct nonwrapping absolute sequence
space; contiguous units in one source use first_unit + slot. They must never be
confused with the enclosing recovery source ID.

`encode(config, identity, record_ids, payload, output)` validates every unit and
record identity before writing. `decode(config, expected_scope, input)` returns a
borrowed View only after complete validation. View iteration yields exact original
aligned unit bytes and their absolute SymbolIdentity. No decoder context changes,
source allocation, replay admission or native delivery occur here.

All integers are big endian. The fixed56-byte header is:

| Offset | Size | Field |
| --- | ---: | --- |
| 0 | 4 | `L2PK` |
| 4 | 1 | version1 |
| 5 | 1 | direction0 initiator-to-responder,1 responder-to-initiator |
| 6 | 1 | unit count1..max_units |
| 7 | 1 | zero flags |
| 8 | 2 | exact negotiated symbol capacity |
| 10 | 2 | meaningful Python payload length |
| 12 | 16 | nonzero session |
| 28 | 8 | epoch |
| 36 | 8 | authoritative recovery source ID |
| 44 | 8 | first absolute unit ID |
| 52 | 4 | zero reserved |

The header is followed by count u64 absolute RecordIds and exact meaningful Python
payload. A one-unit payload has its original channel/serial/body unchanged; a
multi-unit payload is the existing marker255/count/length container. Count must
match both descriptions, every unit channel must be configured and each serial
must equal its absolute RecordId modulo65536. Canonical envelopes contain no
extra outer or container padding. The coding layer can separately pad symbols
while retaining the exact original source length.

The complete header, record-ID array and payload require existing carrier
integrity/replay protection. Decode additionally checks exact expected scope.
Receiver composition must compare the outer source ID with the actual recovered
source, verify contiguous nonoverlapping unit IDs, reserve the entire batch, and
roll back all affected contexts/admission state on failure. Prefix feedback may
release only record ends contained in actually acknowledged recovery sources.
This metadata costs56+8*count bytes and is charged once per original source and
again on every physical retransmission/copy; no simulator zero-auth overhead
claim applies. Memory/work are bounded by one configured source and255 units.

## Checklist

- [x] [MOD-PACKENV-01] Implement exact canonical source/absolute-unit/record identity encoding and complete borrowed decoding with no partial output mutation on failure. Evidence: [envelope](../../crates/l2tunnel-codec/src/packed_envelope.rs), [four focused tests](../../crates/l2tunnel-codec/src/packed_envelope_tests.rs).
- [x] [MOD-PACKENV-02] Test multiple channels, fragments, record serial wrap, source/unit exhaustion, every truncation, header/scope/count/serial errors and undersized output. Evidence: [envelope](../../crates/l2tunnel-codec/src/packed_envelope.rs), [four focused tests](../../crates/l2tunnel-codec/src/packed_envelope_tests.rs).
- [x] [MOD-PACKENV-03] Run strict focused checks, independent review and stable aggregate validation. Evidence: [stable wave7 receipt](../../work/implementation-wave7/validation.json), [focused tests](../../crates/l2tunnel-codec/src/packed_envelope_tests.rs).
- [ ] [MOD-PACKENV-04] Compose bounded sender metadata and transactional multi-unit receiver/recovery ownership; add native/runtime tests before completing packed-wire parity.

Four focused tests and strict Clippy passed. Independent read-only review found no
material blocker. Validated View identity is private so callers cannot invalidate
the checked iterator arithmetic. The [source-stable wave7 aggregate](../../work/implementation-wave7/validation.json)
passed with this implementation included.
