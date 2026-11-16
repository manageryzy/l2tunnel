# Exact selected Rolling fragment output charge

Status: implemented and protocol-tested in the current worktree. Source-stable
Build42 passes; all four new geometry/Rolling composition cases in
[Cases27](../../work/parallel-features-20261115/parallel-tcp-cases-attempt-27/validation.json)
pass. That combined receipt remains failed because both new raw Common fixtures
overflowed their default stacks. This additive component preserves the existing
fragment wire and every unselected Rolling default. The later selected Engine/
Bank/protected-UDP runtime slice has finite evidence in [EFG](common-record-fragmentation.md);
complete FOC-03 and batch acceptance remain separate.

`FragmentConfig::geometry(logical_bytes)` and `Fragmenter::geometry(logical_bytes)`
share the same canonical preparation core as actual fragmentation. The returned
`FragmentGeometry` exposes exact logical/chunk/count/encoded/full-wire sizes and
flat fragment ranges without allocating or assigning a message ID. For N
fragments, encoded bytes are logical bytes plus N times the existing 40-byte
LXv1 header; full wire adds N times the selected real outer overhead. Aggregate
charge overflow is explicit. Existing fragment APIs still require only their
original canonical encoding rules, preserving synthetic extreme-limit behavior.

`rolling_records::OutputFraming` contains both complete directional FragmentConfig
values. Validation covers each actual maximum source/repair and feedback, exact
directional outer overhead and positive payload within its path MTU. The additive
`binding_digest` commits the actual existing copy/configuration/stream binding and
all framing fields. That digest is public configuration identity, not peer proof.
The enclosing authenticated selection must bind this policy before installation.

`Plan::for_endpoint_with_output_framing` retains exact optional policy, copies and
independent ingress limits. Old plans/constructors select None. The selected
Endpoint stores its actual local fragment policy; no Fragmenter, extra payload
slab, message counter, recovery owner or protocol loop is introduced. Heap-only
Plan and observed Usage still sum the same actual owners once; parent layouts
must count actual inline header/token growth once.

`prepare_output` reserves N packets and the exact whole full-wire charge before
writing logical output, assigning local custody metadata or consuming any copy.
PreparedOutput retains actual `packets`, original bytes/number/copy witness and
charge. Held retry returns that exact token without rewrite or another debit.
Feedback uses the same selected accounting. The output remains the unchanged
complete Rolling body. The parent owns one actual Fragmenter per generation,
per-fragment protection numbers and whole-write receipts; only after every whole
fragment may it confirm one actual SourceCopy. Partial send, enqueue and local
preparation are not completion or native delivery.

- [x] [FOC-01] Pass literal 1/2/many canonical geometry, actual flat/owned fragment equality, strict configuration/count/overflow limits, preserved wire and unchanged ID/output refusal behavior. Evidence: [Cases27 finite component passes and preserved raw failures](../../work/parallel-features-20261115/parallel-tcp-cases-attempt-27/validation.json).
- [x] [FOC-02] Pass actual functional/reserved Rolling exact/one-short packet and byte admission, held output/token, independent reverse feedback, short physical copy groups, original caps, one source/repair/native debt and exact reconstruction with actual Fragmenter/protection/reassembly owners. Evidence: [Cases27 finite component passes and preserved raw failures](../../work/parallel-features-20261115/parallel-tcp-cases-attempt-27/validation.json).
- [ ] [FOC-03] Install explicit authenticated fragmentation through the existing Engine/Bank/Common sole runtime, exact per-fragment budgets/physical receipts/original reassembly age, full resources and fixed1460/MTU1500/global8192/local128/every16 qualification. Preserve all FIX03/PBA/SW-11/native/platform/performance requirements and all mode definitions; this prerequisite does not close those gates.

Two geometry tests and two actual pure Rolling composition tests pass.
The copy test uses maintained AEAD with imported fixed test keys, fresh per-fragment
numbers and replay checks; it simulates trusted whole writes. It does not prove
Noise/member/TLS startup, real UDP/device completion, selected Engine MTU support,
8192 full-path execution or measured performance. Historical receipts are unchanged.
