# Internal management, VXLAN and carrier profiles

Status: **design requirements under review**, 2026-11-13 (Asia/Tokyo). This document extends the
[architecture](architecture.md) and [implementation plan](implementation-plan.md).
It specifies target contracts and acceptance work. Existing protocol components
and finite Linux runtime receipts are recorded in [implementation status](implementation-status.md)
and module ledgers; they do not implement every composition specified here.
All unchecked items require implementation evidence before their status changes.
This requirements update changes no runtime behavior or historical receipt.

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

<a id="selectable-lower-carriers-and-udp-cover"></a>

## Selectable carriers and cover profiles

The operator explicitly selects OpenVPN-like, QUIC-like, HTTPS-like or the minimal
media cover. Swift is packing and recovery inside that selection, not a standalone
carrier or an automatically selected connection mode. Keep carrier selection,
user packet layer, MUX policy, record/recovery profile and duplex mode separate.
Bind supported combinations into the authenticated configuration digest and expose
requested versus effective values through the shared client/service API. There is
no target automatic raw/TCP/UDP preference that overrides an explicit selection.
Compatibility transports remain independently labelled capabilities; an unavailable
selection fails visibly unless a fallback was explicitly configured.

For each physical lane, handshake, authentication, management and user data retain
the same connection or UDP socket and five-tuple. Paired half duplex can use two
independently authenticated lanes; each lane obeys this continuity rule. The
historical TCP/TLS bootstrap plus separate protected UDP data flow is preserved as
an experiment and existing implementation, not the target selected-carrier design.
Reconnection after terminal failure is a new observable connection attempt, not a
claim that the original connection survived.

| Selected cover | Target connection contract | Evidence and remaining composition gate |
| --- | --- | --- |
| OpenVPN-like | Actual OpenVPN-format outer handshake and corresponding control/data packet layout on one UDP socket; our own authenticated tunnel payload follows. | The existing standalone profile has real TLS over custom reliable UDP control and finite Linux receipts. Its custom gate/control format does not satisfy the actual OpenVPN wire-handshake requirement. Composition with the common inner session remains open. |
| QUIC-like | Selected QUIC-looking outer header layout over one UDP socket, with the common inner session and selected recovery. | Header appearance is the requirement; native QUIC ACK/congestion machinery and complete QUIC dissector validity are not required. The current custom prefix is not evidence of effective ISP classification. Genuine QUIC remains a separate implemented/reference capability. |
| HTTPS-like | Real TCP/TLS handshake, then independently protected TCP-shaped packets on the original ports and sequence space, without ordinary TCP ACK-driven data transport. | The Linux raw transition has finite, separately scoped evidence. General-path qualification and composition with the common inner session remain open. Actual HTTP/2 streaming is an optional distinct compatibility profile, not a substitute. |
| Minimal media | Audio/video/RTP-like outer packet layout on fixed UDP lanes, with the same common inner authentication, control and data protocol. | New planned cover. Freeze concrete headers, identifiers, sequence/timestamp behavior and handshake placement. This does not request a complete WebRTC/ICE/STUN/TURN/DTLS-SRTP/SCTP stack or valid encoded media. |

### Common inner authenticated session

Every cover, including TCP/HTTPS-like, uses one reusable inner authentication,
key-exchange, replay, rekey and management contract. The selected direction is a
lightweight WireGuard-like authenticated session lifecycle; the concrete maintained
implementation and adaptation are still review gates. See the
[secure-session design](modules/secure-session.md). A library choice, exact wire
format, new trust provisioning scheme or unsafe exception is not implied by this
direction. Public protocol APIs still inject time and I/O and own no OS handles,
privileges, Tokio runtime or device setup.

The deployment is fixed point-to-point between configured clients and servers.
Peer identity is not inferred from the outer header, SNI, address alone or a
successful cookie exchange. No packet-prefix format substitutes for key exchange,
identity verification or anti-replay. AEAD data remains required; any existing
separately negotiated integrity-only profile retains authentication and replay
protection. A WireGuard-like design must not silently remove that profile, adopt
WireGuard's IP-only payload interface, or expose a new default WireGuard carrier.

Specify bounded initial flights, retransmission/backoff, duplicate handling,
final-flight confirmation, replay windows, pre-authentication work/byte/state
budgets, anti-amplification, key lifetime and overlap, exhaustion and peer restart.
Keep authenticated management, liveness and rekey available through the selected
carrier with finite reserved service even while user-data epochs drain or switch.
Shared protocol semantics do not reuse keys/nonces between directions, lanes,
sessions or key generations. Ordinary TCP compatibility still adds ordered-stream
loss blocking; a common inner protocol cannot remove that carrier property.

Default recovery is bounded automatic recovery from transient path/session loss:
retry or reauthenticate the configured peer on the selected carrier with bounded
state, backoff and an explicit terminal outcome. Identity/configuration failures
must not trigger an authentication downgrade or unconfigured carrier fallback.
Expose recovery phase, reason, attempt count and effective connection identity.
Fresh sessions reject stale traffic and reconcile or fail uncertain switching;
recovery must not label abandoned old records delivered. Exact retry/deadline and
reconnect/resume semantics remain to be frozen before implementation. Fixed-peer
operation does not grant unsolicited address retargeting; legacy rebinding/NAT
qualification remains a separately tracked gate.

### Outer protocol consistency and claim boundaries

OpenVPN's actual control protocol carries session IDs, packet IDs and ACK state
around TLS. The requested actual wire handshake remains required even though a
standard OpenVPN client need not become our peer. Freeze the version/profile and
dissector expectations and identify precisely where our protected payload begins.
The common inner handshake must coexist with that outer exchange on the same
socket; replacing it with the existing custom Hello/Retry/Echo is not completion.
[OpenVPN network protocol](https://build.openvpn.net/doxygen/network_protocol.html)

OpenVPN `tls-auth`/`tls-crypt` mechanisms can inform pre-authentication protection,
but shared primitive names do not establish compatible packet layouts or key
formats. [OpenVPN control protection](https://build.openvpn.net/man/openvpn-2.6/openvpn.8.html)

QUIC-like deliberately requests header appearance rather than full QUIC transport.
Document its exact intentional differences. Do not call it standards-conformant
QUIC, HTTP/3 or a completely parseable/decryptable QUIC session. A genuine QUIC
adapter instead retains its real packet/header protection, ACKs and congestion
behavior; preserve its evidence and Python benchmark separately.
[QUIC transport](https://www.rfc-editor.org/rfc/rfc9000.html),
[QUIC TLS](https://www.rfc-editor.org/rfc/rfc9001.html)

Minimal media likewise needs a specific observable RTP-like layout, rather than
an assertion that arbitrary UDP is WebRTC. RTP-style fields do not establish a
valid codec, media endpoint or full WebRTC session. Do not add full WebRTC as a
prerequisite for this requested cover. Packet entropy and full traffic-shape
matching are not additional acceptance requirements.
[RTP](https://www.rfc-editor.org/rfc/rfc3550.html)

Report three claims separately: observed packet/header parseability, interoperability
with another implementation, and measured classifier/QoS behavior. Full endpoint
interoperability is not required for these private tunnel covers. QUIC/media header
recognition does not prove complete protocol validity; valid protocol framing does
not prove resistance to identification or better ISP priority. The premise that
initial packets influence this ISP's classification is a measurement hypothesis.

### HTTPS-like packet ownership and failure gates

Retain the original real TCP/TLS handshake requirement. Configurable TLS SNI is an
outer name; server authentication stays anchored to our own roots/pins/identity
configuration. Neither an arbitrary cover name nor SNI off permits accepting an
untrusted server. Decide and verify the exact verifier/name/pin behavior before
enabling named SNI. Once data leaves TLS record and TCP stream semantics, call it
a custom HTTPS-like TCP-shaped carrier, not continuing HTTPS.

Prefer one packet owner from SYN through TLS and the packet phase. A normal kernel
TCP socket continues ACK/window/retransmission processing and can generate RSTs;
opening a raw socket does not disable the kernel TCP handler. Do not assume that
copying sequence numbers detaches a kernel connection. Any handoff must prove
quiescence, original owner transfer, sequence/option/window continuity, bounded
late old traffic and fail-closed recovery before user traffic is released.

Raw operation needs privileged platform support and exact owned-flow isolation.
Linux qualification includes raw-socket capability, existing exact-tuple firewall
policy, kernel ACK/RST ownership and namespace cleanup; never apply host-wide
ACK/RST suppression. Validate sequence wrap, SYN/FIN consumption, checksums,
options/timestamps, PMTU, loss/reordering, NAT/conntrack, idle expiry and failure
cleanup. A stream-validating firewall can reject custom retirement/ACK semantics
despite the original TLS handshake and unchanged tuple. Windows needs its own
qualified packet/driver path; ordinary Android VpnService does not grant raw outer
TCP injection privileges. No Linux receipt establishes those capabilities.
[TCP](https://www.rfc-editor.org/rfc/rfc9293.html),
[Linux raw sockets](https://man7.org/linux/man-pages/man7/raw.7.html)

After irreversible handoff failure, report terminal state and use bounded fresh
authentication/reconnection as specified by the recovery policy. Do not resurrect
discarded TCP/TLS ownership or silently select HTTP/2/UDP. Keep control-loss,
key-exhaustion, unconfirmed-drain and permission failures distinguishable.

Carrier work does not narrow the 47-family mode inventory, RLNC/parity, rolling,
packed, proxy or other existing mode-parity gates. SW-11 still requires negotiated
epoch switching between Swift and the other record profiles over stable control.

### Carrier and cover acceptance checklist

- [ ] [UDP-01] Freeze the capability matrix and explicit selection/fallback rules for
  raw TCP, kernel TCP and UDP, including cover-profile compatibility.
- [ ] [UDP-02] Verify persistent TCP/TLS ownership and same-connection sequence continuity;
  measure actual delayed-ACK options without claiming ACK suppression.
- [ ] [UDP-03] Qualify raw ownership, permissions, sequence/window wrap, options, FIN/RST,
  loss/reorder, NAT/conntrack, idle expiry and shutdown in an isolated lab.
- [ ] [UDP-04] Freeze the full custom `openvpn_like` envelope/handshake state diagram and
  packet captures; retain the actual OpenVPN wire-handshake requirement and document
  every intentional payload/control difference without requiring endpoint interoperability.
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
- [ ] [UDP-10] Run ARQ/FEC and control-switch tests over both original UDP covers,
  the new minimal media cover and each supported duplex mode; account for all
  cover/auth/control overhead in parity reports.
- [ ] [UDP-11] Preserve separate receipts for custom cover tests and any future genuine
  OpenVPN/QUIC interoperability; never infer one from the other.
- [ ] [UDP-12] Specify and integrate the common lightweight WireGuard-like inner
  authentication/key-exchange/replay/rekey/control contract over every selected cover,
  including TCP/HTTPS-like. Preserve AEAD, existing integrity-only requirements,
  injected time/I/O and the full selected record/recovery scope; qualify same-socket
  and same-five-tuple handshake-to-data continuity per lane. Design alone is not completion.
- [ ] [UDP-13] Freeze and implement the minimal audio/video/RTP-like cover, including
  bounded parsers, observable fields, handshake/control placement, MTU accounting and
  captures; no complete WebRTC stack or valid media codec is required.
- [ ] [UDP-14] Preserve and qualify real TCP/TLS to custom TCP-shaped HTTPS-like data
  on the original flow, configurable SNI with independent trusted server identity,
  packet ownership, kernel ACK/RST isolation, firewall/platform permission gates and
  bounded failure recovery. Optional HTTP/2 streaming cannot satisfy this item.
- [ ] [UDP-15] Implement default bounded automatic recovery for fixed point-to-point
  peers with explicit retry/terminal policy and requested/effective status. Test
  failed identity, duplicate/replayed handshakes, final-flight loss, rekey overlap,
  control starvation, uncertain commits and fresh-session stale traffic across all
  covers; preserve SW-11 and all existing MG/VX/mode-parity acceptance definitions.
- [ ] [UDP-16] Run the controlled [carrier/classification validation plan](testing.md#carrier-consistency-and-classification-campaign)
  with source-pinned receipts, matched offered load, randomized repeated comparisons
  and separate parseability/interoperability/QoS results. Treat initial-packet ISP
  classification as a hypothesis; retain failures and historical experiments.
