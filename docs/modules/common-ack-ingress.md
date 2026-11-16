# Establishment-bound Common benchmark ACK ingress

Status: implemented with finite component and protected original-UDP/Unix-device
integration evidence. Transparent defaults remain unchanged. The bounded ACK owner
is attached to each actual reserved Engine and its actual Pipeline. It neither
generates endpoint ACKs nor owns endpoint cwnd. Complete owned-TCP/native/profile
qualification remains open.

An optional paired `ack_coalescing` object in the complete Common plan supplies
explicit `initiator` and `responder` policies (each complete object or null).
Omission preserves old envelope/resource/record bytes and old status fields;
present null, missing directional fields, unknown fields and both-null objects
refuse. Each policy selects `benchmark`, exact `interval_micros`,
`max_hold_micros`, `max_flows` and `max_ack_bytes`. `owned_tcp` is represented but
refused until a real owned TCP endpoint is composed; the label grants no authority.

Both actual role resource digests bind the optional policy through the explicit
`l2tunnel/common-resources/ack-coalescing/v1\0` extension before E0/C0/H0.
Genuine selected-carrier binding derives E1 with the same policies. Every catalog
member is preflighted against its actual directional Pipeline before I/O. C1304
and existing profile tags are unchanged. Same-envelope record switching retains
this immutable policy; future negotiated hot-policy switching remains required
through a separately versioned authenticated extension, not a local mutation.

Each Engine Plan/Usage includes its actual ingress metadata/slab heaps exactly
once; the Engine/Bank inline headers are separately counted once. Header growth
is an actual physical capacity change even for omitted policy, not a wire change.
Ordinary enqueue explicitly refuses to bypass installed ingress. Typed ingest
returns Forwarded(real metadata), Held or Superseded; a held candidate has no
manufactured Pipeline/native/recovery identity. Original bytes enter the actual
Pipeline only when forwarded, using its existing MUX/QoS and channel budget.

A refused actual native read stays in the existing sole-loop Inputs.native slab
with its issuing Bank generation, first read observation and original cap. No
second device read can overwrite it. Delayed admission uses ingest_at so an old
read cannot start a fresh coalescing interval. The sole loop services at most its
explicit native-read work count per live generation, with at most two generations.
Due backpressure uses the existing receive cadence, never a new product timer.
Control/liveness retain independent service; original lease, challenge, operation
and hard ingress caps remain authoritative. Stage/Drain/retirement wait for both
pending input and actual ingress/Pipeline/profile/native custody. Manual flow
retirement additionally requires the shared profile to drain before history clears.

APIv4 keeps canonical requested paired policies separate from effective local
policy, epoch, actual heap/held/history counts and actual event counters. Raw
read age/cap is reported separately. Offline inspection reports requested only;
no policy label, status value or copied identity supplies authentication proof.
Fresh session setup does not claim retained recovery. Transparent defaults remain.

The executed component cases cover advancing/wrapping ACKs, distinct duplicate
events, checksum/option fallback, original deadlines and actual bounded Pipeline
custody. The real existing-key Common original-UDP/Unix-device case covers a full
queue, retained distinct duplicate read, exact native bytes, negotiated
Swift-to-Packed barrier and live Pong ([Cases21](../../work/parallel-features-20261115/parallel-tcp-cases-attempt-21/validation.json)). Strict paired resource/H0
binding and requested-only offline inspection pass in [Cases22](../../work/parallel-features-20261115/parallel-tcp-cases-attempt-22/validation.json).
The runtime fixture imports established session keys; it does not qualify a fresh
Noise/TLS/member handshake, privileged TAP/TUN or external production CLI.

- [x] [ACKC-01] Pass exact advancing/duplicate/serial/option event semantics, original deadlines, checksum/fallback safety, capacity/refusal and actual Pipeline accounting/custody through the bounded component. Evidence: [Cases21](../../work/parallel-features-20261115/parallel-tcp-cases-attempt-21/validation.json).
- [ ] [ACKC-02] Bind and install explicit owned/benchmark coalescing through actual selected Common configuration, ingress, wake, drain, retained read buffer, status and resources, preserving transparent defaults and live authenticated management.
- [ ] [ACKC-03] Qualify complete named C46/C47/C48 and retained ACK variants through actual client/native/end-to-end differential and performance gates, including full8192/local128/every16, copies, packing and separate delayed ACK behavior.

ACKC-02 retains actual owned-TCP and complete selected-native qualification as
required follow-ons. The first safe packet subset forwards the first observed ACK
and bypasses unsupported checksum/options/window/ECN semantics without rewriting.
Full [Python behavior alignment](python-behavior-alignment.md), PBA-04, all47,
complete resources, native/platform/performance and SW-11 parents stay open.
