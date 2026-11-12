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
  prepare/commit messages, old-epoch frames in flight, rollback, and peer restart.
  Verify frame delivery and epoch separation at both traffic hosts.

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
| UDP covers | Both cover handshakes and data phases, with TCP blocked for the UDP-only case | Actual capture/identity/replay/PMTU outcomes; custom resemblance distinct from real interoperability |
| CLI/GUI | Same scripted operations through CLI and GUI, service restart during switch | Same requested/effective configuration and job result; UI detachment cannot terminate the service accidentally |

Do not route a test probe through a special class unavailable to equivalent user
traffic. Test management liveness without promising it can bypass bytes already
queued in a TCP stream. Include total control/auth/cover/repair bytes in comparisons.
No added gate above has been executed by this planning change.
