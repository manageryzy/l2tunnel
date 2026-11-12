# Internal management, VXLAN and carrier profiles

Status: **planned**, 2026-11-12 (Asia/Tokyo). This document extends the
[architecture](architecture.md) and [implementation plan](implementation-plan.md).
It specifies contracts and acceptance work; none of the mechanisms below is
implemented by the current enums, queue primitive or local reload guard. All
unchecked items require implementation evidence before their status changes.

## Internal Layer 2 management channel

Use a custom internal Layer 2 management protocol between authenticated tunnel
endpoints. Its frame format is available in both TAP and TUN sessions. In a TUN
session this is an internal control envelope; it does not add Ethernet headers to
user IP packets or imply that the OS device supports TAP.

At the authenticated session boundary, distinguish `user_ethernet`, `user_ip` and
`management_l2` record classes. The class is authenticated. Only the local session
engine can originate `management_l2`; a frame arriving from TAP, TUN, a bridge or
a VXLAN adapter always enters a user class. A matching EtherType, destination MAC
or byte prefix in user traffic never grants management privileges. Deliver
management frames only to the control state machine. Never emit them to a user
device, bridge forwarding database or VXLAN socket.

The internal L2 header contains logical endpoint addresses and a versioned
protocol discriminator. Address values are session-scoped identifiers, not MAC
identities used for device learning. Freeze exact fields and byte order with
golden vectors before implementation. Do not assign a random globally meaningful
EtherType. RFC 9542 identifies `0x88B5` and `0x88B6` for local experimental use;
an isolated lab can select one under the administrator's control. The public
library's internal protocol tag needs no claim of a globally assigned EtherType.
Any future on-LAN management mode needs its own assignment/interoperability
review and must not silently reuse the internal mechanism.
[IEEE parameter guidance](https://www.rfc-editor.org/rfc/rfc9542.html#section-3)

### Fixed control decoding and authenticated state

Keep bootstrap/control framing independent of switchable user codecs, FEC
generations, MUX mapping and compression. After session authentication, decode the
stable control envelope before selecting a user-data epoch. Control messages use
their own bounded reliable delivery over the selected carrier, with fixed
framing, retry and deduplication rules established at session creation. A data
mode change cannot change these rules. An incompatible control protocol requires
a fresh authenticated session.

Proposed authenticated fields are control version, exact record length, session
ID, sender role, lane binding, control packet number, message kind, request ID,
proposal-attempt ID, source/target data epochs and canonical configuration digest.
Control packet numbers never reset with a data epoch. Domain-separated control
keys, replay windows, parser work limits and bounded outstanding requests apply
even when optional data confidentiality is disabled. Verify protection before
allocating staged configuration state or changing replay/state-machine records.
Retransmission uses a fresh transport packet number while preserving the request
ID and content; conflicting content for the same request is rejected.

Messages cover capability/status exchange, `PREPARE`, `READY`, directional
`BARRIER`, `COMMIT`, `COMMIT_ACK`, `RETIRE`, reconciliation and explicit rejection.
Liveness and credit/feedback records share bounded control service but have
separate message types and counters. A user-generated latency probe, TCP ACK or
SYN cannot become a management message by selecting a QoS class.

### Service reservation and switching liveness

Reserve a finite control queue, packet count, byte allowance and minimum service
inside the negotiated session budget. This reservation is charged to actual
carrier bytes and remains fixed for the session. It is separate from the
configured user MUX channel pool: it neither consumes a user channel nor creates
an extra user channel. Unused control service may be borrowed by user traffic
only when the control scheduler can reclaim it immediately. Rate-limit control
bursts and coalesce only messages whose replacement semantics are specified.

Both half-duplex and full-duplex modes retain reverse control/feedback service.
Set a bound on queued user bytes already handed to a reliable TCP stream, because
the internal reservation cannot overtake those bytes or overcome TCP loss HOL.
Track control scheduling delay separately from carrier delivery delay. The
reservation prevents local starvation; it cannot guarantee progress over a failed
path or provide an unconditional network-latency bound.

Keep the control decoder, queue reservation and usable control lane alive during
PREPARE through RETIRE, including any make-before-break lane transition. Stop new
old-epoch user admission without stopping its recovery/feedback or control
retries. Barriers enumerate final admitted record IDs and recovery/context
obligations by direction and channel. Commit only after both participants can
read the target epoch and all declared old work has the required confirmation.
If commit may have occurred remotely, a timeout leads to reconciliation or a
failed session, never unilateral rollback. A crash starts a fresh session unless
an explicitly specified persisted resume protocol proves prior state.

### Management acceptance checklist

- [ ] [MG-01] Freeze the internal L2 and control envelope, discriminator strategy,
  canonical config digest and byte-exact bounded parser vectors.
- [ ] [MG-02] Prove identical management behavior for TAP and TUN user payloads without
  exposing management frames to a device, bridge or VTEP.
- [ ] [MG-03] Test forged management-looking Ethernet frames and IP payloads, both from
  devices and authenticated user-data records; none may mutate control state.
- [ ] [MG-04] Test authentication failure, replay, stale session/lane/epoch, conflicting
  request IDs, oversized messages, packet-number exhaustion and key rotation.
- [ ] [MG-05] Implement two-party proposal arbitration, idempotent retries, exact drain
  barriers, commit reconciliation, bounded tombstones and explicit failure reasons.
- [ ] [MG-06] Exercise loss of every control message, duplicates, arbitrary reordering,
  delayed old attempts, full user queues, credit exhaustion and opposite-direction
  load. Test both duplex modes and each selected carrier.
- [ ] [MG-07] Prove control service survives changed MUX mapping, channel count, codec,
  FEC policy and data budgets; reject changes to the fixed control contract.
- [ ] [MG-08] Account for control bytes/retries and queue limits; verify user SYN, ACK and
  benchmark probes still share the configured user MUX policy and channel pool.

## VXLAN support

Provide two independently selectable behaviors. Neither makes an ordinary TUN
device into an Ethernet device, and neither is the outer UDP cover profile.

| Mode | Planned behavior | Ownership |
| --- | --- | --- |
| Transparent nested pass-through | Carry existing VXLAN outer packets as ordinary user IP or Ethernet bytes. Preserve nested bytes; the external VTEPs own VNI and learning. | Normal packet/codec pipeline; no VXLAN termination. |
| Explicit VTEP adapter | Receive/validate VXLAN UDP, map an authorized VNI to a bridge domain, inject the decapsulated Ethernet frame into the L2 tunnel pipeline, and encapsulate authorized egress frames. | Runtime owns sockets; a portable bounded codec/policy module owns parsing and mapping. |

RFC 7348 defines an 8-byte VXLAN header, a 24-bit VNI and default UDP destination
port 4789. It describes MAC learning and broadcast/unknown-destination delivery,
and prohibits VTEPs from fragmenting VXLAN packets. VNI separation is not peer
authentication. These are the interoperability baseline; tunnel-specific
admission and authorization remain our design.
[VXLAN format and behavior](https://www.rfc-editor.org/rfc/rfc7348.html)

### VTEP policy and bridge boundaries

Configure a mapping from authorized ingress VTEP endpoint and VNI to a local
bridge-domain ID and authorized tunnel peer set. Keep VLAN policy explicit within
each domain. A session's VNI/domain allowlist is part of its authenticated
configuration digest; receiving a valid VXLAN header does not grant access.
Reject or count unauthorized endpoints/VNIs before FDB learning. An externally
reachable VXLAN socket needs an operator-selected trust boundary; tunnel
authentication does not automatically authenticate raw VXLAN ingress.

Key learned entries by bridge domain, VLAN context and source MAC. Bound entry
count, lifetime and MAC-move rate; define deterministic replacement, static
entry precedence and peer-down cleanup. Maintain independent FDB and broadcast,
unknown-unicast, multicast (BUM) budgets per domain. Learn only after ingress
validation. Start with configured peers and bounded ingress replication;
underlay multicast and a dynamic discovery/control plane are separate later
capabilities.

Replicated BUM copies consume actual aggregate bytes, the same user QoS/MUX
admission policy, and per-peer quotas. Prevent return to the ingress VTEP/peer
using split-horizon and ingress provenance. Define loop-free supported topologies
and explicit bridge/STP ownership; inner Ethernet has no generic hop limit, so
an outer IP TTL does not solve loops across bridges. Avoid topology auto-discovery
in the first adapter. Do not recursively decapsulate arbitrary nested VXLAN.

Preserve full inner Ethernet bytes including supported VLAN tags, without
inventing or copying an FCS into the packet-device contract. Define whether the
adapter supports outer IPv4, IPv6 or both and test their UDP checksum semantics.
Compute a path budget at each encapsulation boundary, including tunnel protection,
source/repair records, VXLAN, UDP, IP and VLAN overhead. Distinguish inner L3 MTU
from inner frame length. The tunnel may fragment/reassemble its own bounded user
records; a VTEP must reconstruct a complete frame and respect its VXLAN path MTU
before egress. Do not depend on outer IP fragmentation for a valid VTEP deployment.

On Linux, qualify both a system VXLAN netdevice attached to an owned bridge and
the explicit userspace adapter. On Windows, the adapter needs a qualified L2
driver path for local Ethernet delivery. Android's ordinary VpnService remains
L3: nested VXLAN IP pass-through is possible as user traffic, while exposing a
local L2 network needs a separate adapter and is not implied by VTEP support.

### VXLAN acceptance checklist

- [ ] [VX-01] Freeze distinct configuration/capabilities for pass-through and VTEP mode;
  reject ambiguous recursive or incompatible device-layer configurations.
- [ ] [VX-02] Round-trip nested VXLAN bytes through TUN and TAP, including VLAN, IPv6,
  oversized inputs and unsupported header-codec fallback.
- [ ] [VX-03] Implement bounded VXLAN parsing and test truncated headers, flags/reserved
  field behavior, VNI boundaries, invalid lengths and checksum handling.
- [ ] [VX-04] Validate VNI/domain/VLAN/peer isolation, spoofed ingress, bounded FDB aging,
  MAC moves, peer removal, static entries and unknown destination policy.
- [ ] [VX-05] Measure charged BUM replication and per-domain limits; prove split-horizon
  behavior and reject unsupported loop-forming configurations.
- [ ] [VX-06] Test management-looking inner frames through VTEP and pass-through paths;
  they must remain user data and never invoke session control.
- [ ] [VX-07] Verify MTU, nested overhead, path-MTU changes and jumbo frames without
  relying on fragmented VXLAN delivery.
- [ ] [VX-08] Run Linux bridge/VXLAN/netem interoperability tests in owned namespaces,
  including two isolated VNIs, loss/reorder and concurrent QoS classes.
- [ ] [VX-09] Record Windows/Android support separately from Linux interoperability;
  keep unqualified platform/device combinations unavailable.

## Selectable lower carriers and UDP cover

Keep carrier selection separate from cover style, user packet layer, MUX policy,
recovery algorithm and duplex mode. Supported combinations must be explicitly
negotiated and included in the authenticated digest. Preferred deployment order
remains qualified raw TCP, then ordinary TCP, then UDP; an explicit user selection
is respected, with visible failure or an authorized configured fallback.

| Carrier | Connection contract | Cover choices |
| --- | --- | --- |
| `raw_tcp_experimental` | One qualified packet owner from SYN through authentication and data; coherent sequence/window state and required reverse feedback. | Qualified raw profile; valid TLS/HTTPS only while their complete semantics remain in use. |
| `tcp_tls` | Persistent kernel socket and TLS instance through authentication/data; kernel ACK, congestion, window and retransmission behavior remain authoritative. | TLS stream or actual HTTPS profile. |
| `udp_authenticated` | Protected independent datagrams, path validation, replay defense and bounded retransmission/pacing. | Explicit `openvpn_like` or `quic_like` custom cover profile. |

Raw operation does not mean suppressing ACKs on a normal kernel socket. A raw
backend must own and implement its transport state, qualify middlebox behavior,
and preserve reverse control service. It must not apply host-wide ACK/RST rules
to commandeer unrelated traffic. Keeping sequence numbers alone does not prove
flow continuity through NAT or QoS. Normal TCP remains a valid compatibility
backend with acknowledged limitations on custom recovery and ACK behavior.

### UDP authentication and profile boundaries

The first UDP stage joins a session authenticated over the retained TCP/TLS
control connection, using exporter-derived lane keys and fresh single-use
join tokens. This stage is explicitly **not UDP-only**. An independently usable
UDP-only client remains required later and must select a maintained authenticated
handshake implementation, with its concrete library, protocol transcript and
reliability behavior reviewed before implementation. No profile may substitute
header resemblance for key exchange, identity verification or anti-replay.

For both profiles, specify the complete initial flight, retransmission rules,
connection/lane identifiers, version rejection, payload transition, path
validation, rebinding, PMTU behavior and key update. Apply bounded pre-auth work,
anti-amplification and packet/byte budgets. Default to no SNI where the chosen
handshake supports it without weakening identity verification. A configured
cover name is separate from the trusted server identity and becomes observable
unless separately protected. Packet entropy matching remains outside scope.

`openvpn_like` is a custom envelope inspired by OpenVPN's control/data separation
and observable framing. OpenVPN's published packet layout has opcode/key-ID and
session/packet identification fields; copying such fields does not implement its
control protocol or make a standard OpenVPN client a peer.
[OpenVPN network protocol](https://build.openvpn.net/doxygen/network_protocol.html)

Use maintained authentication/AEAD primitives for an optional provisioned
pre-handshake admission key, separate from final member identity and session
traffic keys. OpenVPN's `tls-auth` authenticates control packets before TLS work,
while `tls-crypt` additionally encrypts them; `tls-crypt-v2` supports client-specific
keys and a cookie mode. These mechanisms inform the admission requirement, not a
claim that our custom profile implements OpenVPN key formats or wire semantics.
Actual OpenVPN interoperability would require a separate compatible adapter and
upstream-peer tests. [OpenVPN control protection](https://build.openvpn.net/man/openvpn-2.6/openvpn.8.html)

`quic_like` is a custom UDP cover with a documented initial/established header
shape. Real QUIC v1 requires much more: long/short headers, connection IDs,
version handling, packet-number spaces, transport parameters, address validation
and correctly framed handshakes; client Initial datagrams have a 1200-byte
minimum. A prefix alone cannot claim these semantics.
[QUIC transport](https://www.rfc-editor.org/rfc/rfc9000.html)

Real QUIC integrates TLS handshake messages with QUIC protection and header
protection, rather than transmitting TLS records directly over UDP. Initial keys
are derivable from public connection information, so QUIC-looking Initial traffic
does not conceal a ClientHello or provide authenticated tunnel membership.
[QUIC TLS and Initial protection](https://www.rfc-editor.org/rfc/rfc9001.html)

Keep a genuine QUIC transport adapter and the Python QUIC benchmark as separate
capabilities. A genuine adapter should use a maintained QUIC implementation, and
must report its own recovery/congestion behavior when comparing our ARQ/FEC.
Neither custom cover profile promises indistinguishability, immunity to active
probes, standard-client interoperability or acceptance by a particular router.
Freeze captures and test complete state transitions against the intended path.

### Carrier and cover acceptance checklist

- [ ] [UDP-01] Freeze the capability matrix and explicit selection/fallback rules for
  raw TCP, kernel TCP and UDP, including cover-profile compatibility.
- [ ] [UDP-02] Verify persistent TCP/TLS ownership and same-connection sequence continuity;
  measure actual delayed-ACK options without claiming ACK suppression.
- [ ] [UDP-03] Qualify raw ownership, permissions, sequence/window wrap, options, FIN/RST,
  loss/reorder, NAT/conntrack, idle expiry and shutdown in an isolated lab.
- [ ] [UDP-04] Freeze the full custom `openvpn_like` envelope/handshake state diagram and
  packet captures; document every intentional difference from real OpenVPN.
- [ ] [UDP-05] Freeze the full custom `quic_like` envelope/handshake state diagram and
  packet captures; document every intentional difference from real QUIC.
- [ ] [UDP-06] Select and pin a maintained handshake dependency for UDP-only operation;
  test server/member identity, transcript binding, no-SNI policy and failed auth.
- [ ] [UDP-07] Test TLS-bootstrapped UDP lane joining separately from UDP-only handshake,
  including replay, token expiry, role/lane mismatch and fallback failures.
- [ ] [UDP-08] Verify stateless/pre-auth admission limits, amplification bounds, rebinding,
  PMTU, replay windows, rekey and protected metadata with confidentiality off.
- [ ] [UDP-09] Compare captures and active-probe outcomes for each cover profile; publish
  observed behavior without claiming unprobeability or automatic QoS acceptance.
- [ ] [UDP-10] Run ARQ/FEC and control-switch tests over both UDP covers and each supported
  duplex mode; account for all cover/auth/control overhead in parity reports.
- [ ] [UDP-11] Preserve separate receipts for custom cover tests and any future genuine
  OpenVPN/QUIC interoperability; never infer one from the other.
