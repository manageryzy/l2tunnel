# Explicit raw packet client

Status: implemented with real original-owner TCP/TLS transition and native runtime
integration over finite mock PacketIo. Independent final source review accepted.
Existing retained raw/TCP defaults remain unchanged. The v2 delivery profile passed the
[source28 aggregate](../../work/implementation-wave28/validation.json); new-profile
native packet qualification remains open. See the [current scoped receipt](../../work/raw-delivery28/RECEIPT.md).

The shared API accepts a strict JSON policy of at most 65,536 bytes. Version 2
profile `raw-packet-runtime-v2` specifies explicit IPv4 forward/reverse tuples,
packet MTU/protection/pacing/key lifetime policy, MUX channels and maintained
selective-repeat or Cauchy recovery. Required missing, duplicate and unknown fields are rejected by parsing;
connection-dependent shape, channels and recovery bounds are revalidated before
any opener or native device is touched. `reverse` may be absent/null only in full
mode. Raw stack/bootstrap
resource defaults are fixed and authenticated; local unpredictable seeds are
created at the actual factory, never loaded from policy. Full mode has one lane;
half mode requires two distinct local and peer tuples.

Generic opener factories receive validated raw Config and the actual role, open
only original PacketIo owners, then call runtime `begin_client/server`. One
absolute deadline starts at factory invocation before validation or the first opener and covers both lanes and every
TLS/member/pair/packet transition. Error, expiration and cancellation drop all
attempt-owned inputs; no background driver or data pump is added. After one peer
finishes setup, its Link must continue `poll_progress` while the other finishes.
A Session consumes its original Link in runtime `run`, retaining common MUX and
native-confirmation semantics. The injected opener is synchronous; an overrun
cannot be preempted during the callback, but its late success or error loses to
the same deadline before attachment. A late asynchronous ready result is checked
again before it can expose a Session.

Linux CLI uses explicit `--carrier raw-packet --raw-policy JSON_FILE --raw-mark N`
with existing certificate/member credentials and matching --remote/--listen.
The mark must be nonzero; owned lab firewall/routing setup belongs to the caller.
System traffic/frame records only; active/proxy/UDP/QUIC/packed/aligned and reload
flags are incompatible. No failure permits fallback. Optional local status and
shared Observer expose requested/effective carrier, cover, traffic, exact actual
authenticated profile digest and coalesced runtime counters. Effective selection
requires a returned authenticated Session. Raw pacing is not congestion control,
native credit is not endpoint cwnd, and this profile has no clean drain claim.

- [x] [MOD-RAWCLI-01] Freeze strict policy/shared factory/CLI/status contract and pre-I/O rejection tests. Evidence: [strict policy and original factories](../../crates/l2tunnel-client-core/src/raw_packet.rs), [CLI selection](../../crates/l2tunnel-client-core/src/raw_packet/cli.rs), [parser/deadline/auth/native tests](../../crates/l2tunnel-client-core/src/raw_packet/tests.rs).
- [x] [MOD-RAWCLI-02] Implement actual generic original-owner factories with original setup deadline and native Linux opener dispatch; verify full/half real TLS transition and packet runtime over mock PacketIo. Evidence: six focused tests passed, including byte-exact TAP/TUN in both physical duplex modes with selective repeat/Cauchy and AEAD/HMAC, plus actual authenticated common-MUX and packet-policy mismatch rejection. Native opener evidence is [separate](../../work/raw-native-packet17/validation.json).
- [x] [MOD-RAWCLI-03] Verify bounded requested/effective local status, cancellation/error ownership and strict scoped lint/docs/tests. Evidence: 101 client and 19 example tests, strict Clippy/rustdoc/format checks from immutable source16 plus explicit overlays; independent root source review accepted. Root stable aggregate and privileged native qualification remain separate pending gates in the [receipt](../../work/raw-packet-client/validation.json).


For a full-duplex example, use this complete client policy and mirror only the
forward local/peer fields on the server:

```json
{
  "version": 2,
  "profile": "raw-packet-runtime-v2",
  "delivery": {
    "forward_bandwidth_bps": 80000000, "reverse_bandwidth_bps": 10000000,
    "bootstrap_rtt_micros": 70000, "min_rtt_micros": 2000,
    "max_rtt_micros": 1000000, "headroom_percent": 125,
    "minimum_bytes": 4000, "max_inflight_bytes": 4194304,
    "max_records": 8192, "metadata_limit_bytes": 2097152,
    "sample_ttl_micros": 4000000, "flush_timeout_micros": 10000000
  },
  "forward": {"local": "192.0.2.11:45001", "peer": "192.0.2.12:45002"},
  "reverse": null,
  "channels": 4,
  "packet": {
    "mtu": 1500,
    "protection": "aead",
    "queue_packets": 8,
    "horizon_bytes": 32768,
    "minimum_transfer_bytes": 65536,
    "bytes_per_second": 1048576,
    "packets_per_second": 2048,
    "burst_bytes": 16384,
    "burst_packets": 32,
    "max_key_packets": 1048576,
    "max_key_bytes": 1073741824
  },
  "recovery": {"mode": "selective_repeat"}
}
```

Half mode additionally supplies a reverse object with distinct local/peer ports.
Cauchy is `{"mode":"cauchy","sources":4,"repairs":2,"flush_micros":2000}`.
Outer packet tuples are currently IPv4; native TUN payloads are independently
parsed by the existing IPv4/IPv6 Pipeline. The shared setup timeout accepts exact
microseconds from 1 ms through 30 s (CLI uses 30 s). Bootstrap raw rings are
32,768 bytes each, packet queues 16 slots, ACK delay 1 ms, keepalive 1 s and idle
30 s; message/record/work/resource limits use the existing authenticated defaults.

The CLI emits bounded JSON `raw_packet_authenticated` with the actual Session
snapshot after device open. That snapshot may still say Setup until the runtime
starts. The local API's actual Active phase and advancing admitted/delivered
counters witness forwarding. A returned runtime error emits
`raw_packet_terminal` with the observed stopped state and I/O category; process
cancellation is never converted to a successful result. Only Status is supported
on this profile's local service; every mutation/drain action returns unsupported.
The fixed 8,192-byte local response cap and legacy omitted-field reply bytes stay
unchanged. Setup observers expose no effective selection; callers obtain a new
Observer from the returned authenticated Session for its effective profile/digest.

Runtime profile v2 requires the shared twelve-field delivery policy; v1 documents
are rejected rather than migrated silently. The lower `raw_packet_v1` carrier
status still names the unchanged protected record wire. `runtime_profile` names
the separately authenticated v2 native accounting contract. Native-flight,
receiver-pending, local-Pipeline and source-recovery occupancy remain separate.
RTT/sample fields are null until genuine causal observation and retain their
original feedback timestamp when stale. The example raw wire allowance remains
1 MiB/s (8.39 Mbit/s); its 80 Mbit/s target is not an achieved-throughput claim.

- [x] [MOD-RAWCLI-04] Require typed canonical v2 native delivery policy and expose separate native, local queue and recovery accounting through the shared API. Evidence: [six actual client cases and scoped receipt](../../work/raw-delivery28/RECEIPT.md); historical v1 receipts retain their original meaning.
