# Validation plan and isolated Linux lab

`tools/netns_lab.py` provides a deterministic topology plan and an explicitly
enabled topology setup/cleanup implementation. It does **not** launch a tunnel
daemon, run traffic, or prove that a protocol mode works. The Rust implementation
must supply those pieces before end-to-end acceptance is possible. Here, "qc"
is interpreted as Linux `tc` qdisc, with `netem` for delay and loss.

## Safe default and topology

Run from the repository root:

```sh
python3 tools/netns_lab.py --lab-id trial
python3 tools/netns_lab.py --lab-id trial --json
python3 -m unittest tools.test_netns_lab
```

The first two commands only print plans; the third runs unprivileged tests with
mocked network operations. Five newly created namespaces isolate two traffic
hosts, two tunnel endpoints, and an underlay router:

```text
host A                 endpoint A           underlay           endpoint B                 host B
198.18.0.1/24   eth0--lan0--br-lan--tap0    router (forward)    tap0--br-lan--lan0--eth0   198.18.0.2/24
                          daemon--wan0----a0          b0----wan0--daemon
                              192.0.2.2/30           192.0.2.6/30
                         router: 192.0.2.1/30    192.0.2.5/30
```

The two LAN bridges are intentionally disconnected until the endpoint daemons
read/write their local `tap0`. The traffic hosts share an IPv4 subnet only
through the future L2 tunnel. A successful underlay ping does not validate the
tunnel. Each endpoint has only a specific route to the opposite underlay subnet;
there is no added default route. MTU is 1500 on every non-loopback interface.

The requested baseline is 100 Mbps A-to-B, 10 Mbps B-to-A, **35 ms in each
direction (70 ms base RTT)**, and 15% independent random loss at one stage per
direction. Endpoint `wan0` egress uses an HTB class for the rate and a child
`netem` qdisc for delay/loss, with a 1,000-packet queue limit. The router adds no
extra impairment. These are requested kernel settings, not measured guarantees.
Queueing, timer granularity, kernel version, offloads/GSO, TCP pacing, and where
packet loss is counted can change realized latency, rate, and loss. Record and
measure them before comparing with simulator results. Avoid interpreting loss
as exactly 15% of application frames or bytes. A fixed kernel random seed and
offload policy are future reproducibility work; this scaffold does not promise
bit-for-bit repeated packet traces.

## Explicit setup and ownership-aware cleanup

The following commands are for a later authorized Linux integration run; they
were not executed as part of scaffold verification:

```sh
sudo python3 tools/netns_lab.py --lab-id trial --apply
sudo python3 tools/netns_lab.py --lab-id trial --cleanup
```

Setup requires root, `ip`, `tc`, `sysctl`, `/dev/net/tun`, network namespaces,
veth, TAP, bridge, HTB, and netem support. All link, address, route, forwarding,
and qdisc changes occur **inside the new namespaces**. The script never changes
host interfaces, host routes, host sysctls, or host qdiscs. Namespace mount
registrations and the private state directory are the only host-level objects
it creates. It does not enable host IP forwarding, attach to a host bridge,
install firewall rules, or acquire Internet connectivity.

A private root-owned directory, `/run/l2tunnel-labs` by default, holds a locked
per-lab journal. Existing manifests and namespace-name collisions fail without
adopting or deleting that state. The journal records namespace device/inode
identities immediately after creation. Cleanup checks all identities and refuses
to delete replaced namespaces or namespaces with running processes. It only
deletes proven-owned namespaces, whose contained links and qdiscs disappear with
them. Stop daemons, captures, and traffic generators before cleanup. Preserve a
copy of the journal with the experiment receipt before cleanup removes it.

Ordinary setup failures trigger ownership-checked rollback. A machine crash or
forced kill in the gap between namespace creation and journaling may leave an
unrecorded namespace; the next setup fails on that collision and does not adopt
it. Inspect such leftovers manually. External root processes can still race
namespace changes; this is an operational lab boundary, not isolation from a
host administrator. The harness never kills a process to make cleanup succeed.

## Integration runner to implement

The future runner should retain a receipt for each run containing the exact Git
revision, build features, negotiated mode IDs and configuration epochs, kernel
and iproute2 versions, namespace plan, endpoint capabilities, qdisc/class dumps,
offload settings, counters, seed information where available, traffic commands,
timestamps, and output paths. Capture on both traffic-host interfaces, both TAP
interfaces, and both underlay interfaces; record capture drops. Avoid placing
private keys or authentication secrets in receipts. Captures may contain test
payloads and require explicit retention rules.

Start both daemons on their own `tap0` and bind underlay sockets to their
namespace addresses. Authenticate and negotiate the selected mode, then perform
an ARP/neighbor and traffic warmup excluded from measurements. Keep a cold-start
case separately to measure setup and first-packet cost. Use application sequence
IDs and monotonic timestamps for delivery/loss accounting; cross-process
one-way measurements require verified clock comparability. Collect at least:

- Unloaded underlay RTT and packet loss, then throughput under offered load, to
  check the requested impairment profile before interpreting tunnel results.
- Large sustained transfers, short interactive flows, bidirectional traffic,
  frame-size sweeps, burst/idle transitions, and explicit reordered/duplicate
  input where a future profile supports it.
- TCP SYN and SYN-ACK carried as ordinary Ethernet/IP payload through the same
  classifier, MUX, compression, framing, scheduling, repair, and decode paths as
  other data. No SYN bypass, privileged queue, or special SYN retransmission
  may silently invalidate the simulator comparison.
- MTU/fragment boundaries, malformed or unauthenticated records, bounded memory
  and repair queues, multistream stalls, path failure, and transport fallback.
- Each configured repair/FEC and scheduling mode declared by the simulator
  parity inventory. Cover half-duplex and full-duplex operation, optional inner
  encryption, TAP/L2 and TUN/L3 boundaries, and ordinary TCP fallback separately.
- Coordinated configuration epoch changes under load, including delayed or lost
  prepare/commit messages, old-epoch frames in flight, safe pre-commit rollback,
  post-commit uncertainty/reconciliation, and peer restart. Verify frame delivery
  and epoch separation at both traffic hosts.

Count delivered original frames/bytes separately from wire bytes, repair bytes,
duplicate bytes, acknowledgments, control traffic, and compression savings.
Report median and tail latency, completion rate, goodput, CPU, memory, queue
occupancy, and effective loss by direction. Keep offered load and delivered
throughput distinct. Explicitly record failures, timeouts, unsupported modes,
and missing measurements rather than treating them as zero.

Repeat with multiple independent seeds/traces once a seeded runner exists.
Calibrate clean-link, delay-only, rate-only, loss-only, and combined profiles
before attributing a difference to a protocol strategy. Additional non-baseline
profiles and automatic captures are planned, not implemented by the current
fixed-profile harness. A Linux namespace pass is not Windows/Android device
integration evidence; those platforms need adapter-level and native-system
tests of their own.

## Current verification boundary

The unit tests exercise dry-run purity, deterministic namespace-scoped command
generation, the directional impairment plan, invalid identifiers, privilege
checks, pre-existing state/namespace collisions, namespace replacement and live
process refusals, and rollback using mocked commands. They never invoke `sudo`,
create namespaces/TAP devices, or alter network state. A printed plan and passing
unit tests do not establish that this host's kernel accepts every command or that
any end-to-end tunnel behavior exists.

## Added traffic, management, overlay and client gates

The [master checklist](implementation-checklist.md) and FC/MG/VX/UDP/CL detailed
checklists are the source of completion status. The existing topology script
still implements only its fixed TAP plan; the following extensions are pending:

| Workstream | Required real test | Distinguishing evidence |
| --- | --- | --- |
| TUN active credit | Routed IP with 1/2/4/16/64 demanding flows, many idle flows, flow churn and slow receiver | Credit target versus advertised reservation, queue delay, aggregate path allowance, growth/backpressure transitions |
| Actual TCP proxy | Explicitly terminated TCP legs with SACK/scaling/persist/FIN/RST and stalled destination | Per-leg cwnd/rwnd, buffer ownership, retained accepted bytes, reset/crash semantics; contrast with transparent TUN |
| TAP system behavior | Transparent bridged traffic under loss and QoS | Original ACK/window/sequence semantics, system algorithm/settings; no custom TUN credit controller |
| QoS | Saturated bulk plus ordinary interactive/background traffic and competing external TCP | Minimum shares, ceilings, idle borrowing, starvation, P95/P99 sojourn, FEC/retry attribution and lane-count fairness |
| L2 management | Full data queues, lost/replayed/conflicting control, changed data codec/FEC/MUX and peer restart | Stable control decoding, bounded service/overhead, no user EtherType/MAC escalation, no uncertain-commit rollback |
| VXLAN | External Linux VTEPs plus bridges, multiple VNIs, VLAN/IPv6, BUM and MTU changes | Byte-preserving pass-through separately from VTEP termination, tenant isolation, FDB bounds and loop prevention |
| Selected carriers | OpenVPN-like, QUIC-like, HTTPS-like and minimal media cover, each with the same inner session and selected data profile; TCP blocked before UDP-only authentication | Same lane connection/socket/five-tuple through handshake and data; exact declared protocol/header behavior, identity/replay/PMTU and requested/effective state; full endpoint interoperability is a separate optional claim |
| CLI/GUI | Same scripted operations through CLI and GUI, service restart during switch | Same requested/effective configuration and job result; UI detachment cannot terminate the service accidentally |

Do not route a test probe through a special class unavailable to equivalent user
traffic. Test management liveness without promising it can bypass bytes already
queued in a TCP stream. Include total control/auth/cover/repair bytes in comparisons.
No added gate above has been executed by this planning change.

## Carrier consistency and classification campaign

Status: **planned validation**, 2026-11-13 (Asia/Tokyo). This campaign qualifies the
selected-cover/common-inner-session architecture in
[carrier profiles](overlay-and-carriers.md) and [secure-session design](modules/secure-session.md).
It is not an execution receipt. Existing TCP/TLS, protected UDP, genuine QUIC,
OpenVPN-like and raw packet-phase receipts keep their original source hashes,
acceptance criteria, failures and finite scopes. The old TCP/TLS-bootstrap plus
separate UDP data experiments remain historical controls, not evidence of the
target same-flow design.

### Protocol and lifecycle gates before ISP measurements

Use the same authenticated inner protocol, selected packing/recovery, native
payload workload, channel budget and accounting definitions across covers.
Swift is a selected data algorithm within the cover. Include RLNC/parity,
rolling, packed, proxy and all existing mode-parity requirements in their own
qualification matrix; do not replace them with a Swift-only benchmark.

| Gate | Required observations and negative cases |
| --- | --- |
| Flow continuity | Capture before the first handshake packet at both endpoints; correlate socket/connection owner, addresses, ports and IP protocol through authenticated user data. Require no second UDP data flow or new TCP SYN at the handshake/data boundary. Prove each lane separately in paired half duplex. |
| Common inner authentication | Fixed configured peer, wrong identity/key/configuration, tampered/oversized input, replay from another session/lane/direction, loss of each flight, duplicates, reordering, final-response loss and peer restart. Bound unauthenticated CPU work, bytes, allocations, pending states and response amplification. |
| Replay and rekey | Duplicates and packets outside the declared replay horizon cannot mutate application/control state; failed authentication cannot consume accepted replay state. Exercise overlapping key generations, lost/repeated rekey messages, expiry and counter exhaustion without nonce/key reuse or stale-session acceptance. |
| Management and mode switching | Saturated user queues, opposite-direction load and changed user codecs/recovery must retain bounded authenticated control/liveness/rekey service on the selected carrier. Preserve request idempotence, digest/epoch matching, exact drain barriers and commit reconciliation; exercise SW-11 between Swift and other record profiles. |
| Default automatic recovery | Inject short outages, deadline crossings, peer restart and socket loss. Verify configured retry/backoff/state bounds, visible phases/reasons, eventual explicit terminal outcome and fresh authentication where needed. Wrong trust/configuration cannot activate downgrade or an unconfigured carrier. A new connection attempt is labelled as such. |
| Data scope | Exact payload hashes, frame/native delivery confirmation, arbitrary Ethernet fallback, selected AEAD and existing integrity-only profiles, full/half operation, MUX/channel admission and independent local/native-flight/recovery budgets. No successful compile or enum selection counts as a passing path. |

Hold the original deadline and acceptance policy fixed within each case. A shorter
outage recovery pass does not replace a longer outage failure. Preserve actual
outage duration, terminal class, delivery debt and cleanup independently. Record
unsupported, bound-exhausted, protocol failure and tool failure separately.

### Cover-specific consistency checks

- OpenVPN-like retains the actual OpenVPN wire-handshake requirement. Use an
  unmodified standard dissector and a declared protocol/profile to inspect reset,
  session/packet/ACK fields and reassembled outer TLS where visible. Separately
  verify our inner membership, selected recovery and data protection. A custom
  opcode prefix or successful project parser does not complete this gate. The
  composition of that outer exchange with the common inner handshake remains
  design work; standard OpenVPN endpoint interoperability is not required.
- QUIC-like checks only its frozen initial/established header-appearance contract,
  lengths, identifiers and consistency across the same socket. Record what an
  unmodified dissector recognizes and rejects, without demanding or claiming a
  complete valid QUIC handshake/session. It need not run native QUIC ACK/congestion
  machinery. Genuine QUIC is a separate reference with its own transport limits;
  its results do not validate the appearance-only cover or Swift composition.
- Minimal media checks the chosen audio/video/RTP-like header layout, stream
  identifiers, sequence/timestamp policy, packet boundaries and shared inner
  authentication/control placement. It does not require complete WebRTC signaling,
  ICE/STUN/TURN, DTLS-SRTP/SCTP or valid encoded audio/video. RTP recognition alone
  is not evidence of a valid media endpoint or useful QoS classification.
- HTTPS-like captures a real TCP/TLS handshake and verifies configured SNI
  independently from our trusted server identity policy. Prove that the later
  custom packet phase retains original ports and sequence space, with no kernel
  TCP stream owner continuing ACK-driven data transport. Audit owner transfer,
  packet checksums/options/windows, gaps/wrap, late old traffic, kernel ACK/RST
  behavior and exact owned-flow firewall counters. Test permission denial,
  cancellation and irreversible transition failure. Actual HTTP/2 streaming is a
  separate compatibility control, not acceptance of the requested raw phase.

Before wider raw-path testing, qualify Linux namespace ownership/capabilities and
exact-tuple policy, PMTU, NAT/conntrack, idle expiry and stream-validating firewall
behavior. Never install host-wide ACK/RST suppression or change existing host
routes/bridges/qdiscs. Windows and Android require separately implemented and
qualified packet ownership/privilege paths; a Linux pass supplies neither. Record
clean close separately from bounded terminal teardown and resource cleanup.

### Controlled ISP/QoS hypothesis test

The hypothesis is that initial packets influence classification or priority on
the owner's connection. The experiment must distinguish this from transport
recovery, packet-size/timing differences, server load, route changes and ordinary
congestion. Header resemblance does not establish the ISP's internal label, and
measured goodput alone cannot prove the classification mechanism.

1. First calibrate the owned lab with clean, rate-only, delay-only, loss-only,
   burst/reorder and combined conditions. Freeze capture/offload policy, versions,
   source/binary hashes and exact total encapsulation cost. Verify delivery and
   lifecycle gates before comparing performance.
2. On the controlled client/server path, fix endpoint hardware, server location,
   configured endpoints, MTU, traffic direction, DSCP/ECN policy, offered load,
   channel count, recovery policy and inner workload. Record the actual route,
   IP/port/protocol tuple, CPU load and concurrent traffic. Changing TCP to UDP or
   changing ports is a separately labelled factor, not an isolated handshake test.
3. Where feasible, compare different initial/cover exchanges with matched
   post-handshake inner records, outer size/timing policy and offered wire rate.
   State every difference that cannot be controlled. Include direct traffic and
   genuine TCP/TLS/QUIC or actual HTTPS references as distinct controls, retaining
   their native ACK/congestion semantics. Do not attribute their difference to the
   initial handshake alone.
4. Randomize case order within repeated time blocks; measure cold connections,
   warm steady traffic, idle/restart and connection-age effects separately.
   Predeclare duration, repetitions, stopping/failure rules and comparison metrics
   before a campaign. Preserve complete failed cases rather than retrying until
   favorable results or retuning acceptance after observing them.
5. Measure unique delivered goodput, transfer completion, P50/P95/P99 latency,
   loss/reordering, handshake/recovery duration, CPU/RSS and total forward/reverse
   wire bytes, including cookies, protection, management, feedback, repairs and
   retransmissions. Include controlled competing traffic to test priority rather
   than only uncongested link speed. Report per-run results and variation.
6. Observe classifier or queue counters only where available on equipment we
   control or through an explicit ISP diagnostic. Otherwise report a repeatable
   performance difference under the tested conditions; label its classification
   explanation as inference. Initial classification may be revised later in a
   connection. Neither a positive nor negative finite result generalizes to every
   ISP, port, load, router or date.

Every report separates observed outer parsing, optional interoperability results,
actual authenticated tunnel delivery and the QoS hypothesis. Preserve immutable
per-case receipts/captures and exclude private keys/session secrets from ordinary
logs. Report requested/effective carrier and protection, fallback/recovery events,
platform capability limitations and unresolved acceptance gates alongside results.
