# Linux TAP/TUN adapter, interface v0

Scope: attach an explicitly named TAP/TUN device inside the caller's current network
namespace and provide nonblocking packet I/O. The adapter does not configure host
routes, bring devices up, create bridges or change persistent-device ownership.
Those actions belong to the runtime/lab owner. Closing the descriptor follows Linux
TUN/TAP lifetime semantics: a nonpersistent device disappears; a precreated
persistent device remains owned by its creator.

## Key interfaces and trust boundary

`TunTap::attach(name, PacketLayer) -> io::Result<TunTap>` opens `/dev/net/tun` with
O_CLOEXEC/O_NONBLOCK and uses `TUNSETIFF` with IFF_NO_PI plus TAP/TUN. Validate the
name before opening anything; no wildcard/template names. `name()` and `layer()`
report effective attachment. `PacketDevice::receive/transmit` operate on complete
packets and return backpressure/errors explicitly. A receive buffer must have
`READ_BUFFER_BYTES` space to detect a packet exceeding the supported record bound.

This is an OS adapter and intentionally outside the pure protocol facade. The
only unsafe exception is one private audited ioctl helper: zero-initialize the
platform libc `ifreq`, set its name/flags, and pass a live mutable object to the
synchronous ioctl. The descriptor and object remain valid for the call; no pointer
is retained and all returned names are bounded. Protocol crates retain forbid.
The crate is Linux-only; unsupported hosts compile no Linux API and never claim
native device support. Native privileges are verified by the caller at runtime.

`TunTap::create_persistent(name, layer, owner)` creates a named persistent
TUN/TAP device for the service's device management (DGUI-06). It adds two
value ioctls to the same audited boundary: `TUNSETPERSIST` (argument 1) and,
when an owner UID is given, `TUNSETOWNER`. Both pass a plain integer, no
pointer, on the descriptor returned by `TUNSETIFF`; the descriptor is closed
afterwards and the device remains until it is deleted.

`netconf` manages links, addresses and main-table routes over rtnetlink
(`rtnetlink =0.24.0`, no unsafe). Lists are bounded by `LIST_LIMIT`; routes
are added and deleted as protocol `static` in table 254 only.
`best_route` finds the longest-prefix route toward an address, optionally
excluding one device, for the default-route peer exception. Ownership of
devices and routes is kept by the client-core Linux host, not by this crate.

## TODO and acceptance

- [x] [MOD-LNX-01] Implement explicit-name attachment, checked packet buffers and nonblocking receive/transmit. Evidence: [implementation/tests](../../crates/l2tunnel-platform-linux/src/lib.rs).
- [x] [MOD-LNX-02] Test name validation and packet-shape/size errors without privileges. Evidence: [implementation/tests](../../crates/l2tunnel-platform-linux/src/lib.rs).
- [x] [MOD-LNX-03] Review the isolated native ABI exception and Clippy/build on Linux; retain pure-core unsafe prohibition. Evidence: [implementation/tests](../../crates/l2tunnel-platform-linux/src/lib.rs).
- [x] [MOD-LNX-04] Run real TAP and TUN exchange in owned namespaces with authenticated runtime endpoints. Evidence: [implementation/tests](../../work/native-wave1/receipt.json).
- [ ] [MOD-LNX-05] Implement runtime device lifecycle, cancellation, multiqueue policy and native cleanup receipts.

Reference: [Linux TUN/TAP](https://docs.kernel.org/networking/tuntap.html).

For a Linux TUN transmitting local IP packets to its userspace reader,
Linux can drop packets at a full device TX ring after a TUN packet capture
has seen them. The interface owner controls this bounded ring with
`ip link set dev <name> txqueuelen <packets>`. Size is in packets.
The Common native matrix accepts `--native-tun-txqueuelen` when provisioning
its two owned devices. The receipt records the requested and effective sizes,
the device TX packet and drop counts, and the separate TUN qdisc statistics
before and after the workload. Omitting the option uses the system setting.
A greater depth can absorb a larger burst and can increase residence time.
[Single-flow packet and latency evidence](frame-channel-experiment.md#sender-tun-loss-before-packed-source-assignment).

The optional `--native-forward-tun-maxrate-mbit 82` in the Common native
matrix installs Linux FQ on the owned sender TUN with a per-flow maximum of
82 Mbit/s. The matrix verifies the requested rate against the kernel's
numeric bytes/s readback, as well as the total and per-flow queue limits.
Each phase retains the effective settings for both TUN interfaces. In the
single-flow experiment this paced the producer before the TUN reader ring
while the WAN remained at 100/10 Mbit/s. Actual throughput and the resulting
queue delay depend on service at the downstream tunnel.
