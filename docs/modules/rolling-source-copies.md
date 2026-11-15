# Authenticated selected Rolling source copies

Status: implemented and protocol-tested, including one actual protected UDP
Common three-copy/loss/feedback/switch case on both covers. It does not qualify a
production TLS/Noise handshake or external native startup. PBA04 and SCP04 retain
complete full8192, native, resource, fault and performance scope.

Complete configuration encoding and actual Engine/Bank selection now retain the
same real FEC scheduler and rolling_records copy policy.
Existing constructors select ONE and preserve old wire/config digests. Add
`rolling_records::CopyPolicies { forward, reverse: codec::source_copy::Policy }`,
`ONE`, validation and domain-separated policy/binding digests. New
`Endpoint::new_with_copies(config,context,stream,now,policies)` and
`storage::Plan::for_endpoint_with_copies(...,policies)` retain explicit complete
role projection; `Endpoint::new_reserved_with_copies(plan,limits)` consumes that
real plan. New `source_copy_policies` observes selected exact policy. The selected
tag5 canonical configuration includes every copy field; a local constructor
alone remains insufficient for authenticated selection.

Actual packed sender receives the maintained immutable policy; its pre-packing
homogeneous count is passed to `Sender::admit_source_with_copies`. One encoder
source, source ID and debt are created. A bounded inline group retains ordinal,
count and original output cap; no per-copy payload queue/history allocation.
First real source acceptance advances sent_sources to permit genuine feedback.
Remaining copies pin encoder retirement at that source; latest authenticated
feedback is retained with monotonic actual prefix, observed end and rank/deficit.
Final whole copy releases pinned prefix and earns source repair credit once.
Feedback/repairs keep their existing individual identity and are never copied.
Tail timing uses actual last acceptance; original group hard expiry never renews.

`SourceCopy` is a local ordinal-bearing witness, not wire identity or physical
proof. `pending_source_copy` observes it; `confirm_source_copy(observed,accepted,
witness)` rejects stale/duplicate before time/state mutation. The legacy
`confirm_output` explicitly refuses a multiple-copy source. Actual
PreparedOutput retains this witness plus existing Endpoint instance/physical
serial. Each next copy gets new output custody and enclosing security PN, and
full wire/pacing debit. An unchanged held copy returns the same token/PN/debit
and bytes. Only actual whole-carrier confirmation consumes it. Pure inner
source bytes remain identical; no crypto/wire primitives change.

All configured policy counts remain1..4 and threshold0..symbol. Newly inline
metadata is counted through actual Sender/Endpoint headers in existing parent
plans; managed heap/allocation counts are unchanged. Existing conservative
memory limits still apply, with no hidden allowance increase. The plan stores
exact policies for construction, not dummy usage. Full all-allocation and
selected external resource qualification remains open.

Focused executed regressions: literal identical source bytes and one identity
for copies1..4; stale/duplicate and invalid counts before mutation; real paired
receiver ACK after first copy, then delayed stale/later feedback without lost
deferred prefix; one repair credit; original cap across held/repeated/final
preparation; separate physical security numbers and per-copy full debits; genuine
native reconstruction without duplicate delivery; one-copy old output/digest
and exact actual reserved heap stability. The actual UDP case physically loses
the first copy, accepts genuine feedback before the final copy, verifies held
WouldBlock ciphertext/token/PN/debit, then delivers native bytes exactly once and
switches back through live management on the original socket. Its protection
owners are real; this fixture does not perform production TLS/Noise setup. See
[Batch9 finite checks and preserved failures](../../work/parallel-features-20261115/parallel-batch9-scoped-validation.json).

## Selected Common encoding contract

Add explicit Profile::RollingCopies with the exact Config, stream and both
CopyPolicies. It uses a new CompleteV2 profile tag5; old tags1..4 and their fixed
bytes/digests remain unchanged. Each tag5 direction retains the original352-byte
Rolling fields, followed by threshold u16 big-endian, copies u8 and scope u8
(AllShort1, ContextAndIndependent2), exactly filling its356-byte slot. Threshold
is validated against the actual symbol width before encoding; never truncate.
Tag4 still requires those four bytes to be zero. Older readers reject tag5.
This explicit new variant binds every selected copy field without reinterpreting
old padding or requiring silent migration of existing fixed-size configurations.

The actual Engine/Bank storage plan and functional constructor project both
policies to the same real Rolling owner. Requested/effective configuration and
catalog retain tag5; a local constructor alone is not authenticated selection.
Selected runtime cases must prove actual repeated protected packets, exact
native-once delivery and live management on the original carrier. This finite
copy integration does not close full8192/128/ACK-coalescing acceptance.

- [x] [RSC-01] Implement bounded physical-copy groups in the same scheduler and real Rolling owner, preserving one source/debt, early-feedback retention, exact witnesses, original caps and per-copy bytes. Evidence: [Batch9 finite checks and preserved failures](../../work/parallel-features-20261115/parallel-batch9-scoped-validation.json).
- [ ] [RSC-02] Encode/decode the complete explicit tag5 policy without changing tags1..4, install it in actual Engine/Bank constructors and retain requested/effective configuration through the selected runtime/service.
- [x] [RSC-03] Validate real source-copy feedback/expiry/WouldBlock/native deduplication and selected authenticated runtime delivery with exact per-copy protection/wire observations; retain complete PBA-04/SCP-04 parent gates. Evidence: [Batch9 finite checks and preserved failures](../../work/parallel-features-20261115/parallel-batch9-scoped-validation.json).

RSC-02 remains open for its complete selected runtime/service requested-versus-effective policy deliverable. The actual tag5 UDP fixture and canonical tests do not by themselves qualify production service/handshake installation.
