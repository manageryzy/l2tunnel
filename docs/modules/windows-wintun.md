# Windows foreground Wintun boundary

Current status: the obsolete foreground service and staging chain have been
removed. The owner approved deleting the old entry before the Common Windows
service migration is complete; that migration remains pending. Portable device,
input, setup and diagnostic helpers are not an implemented tunnel service.

The descriptions and receipts below document the retired foreground slice;
they do not qualify the current application. Its prior portable and GNU checks
are source-bound historical evidence. The earlier root portable cases and affected
Windows GNU lint/link checks pass in the separate [Batch13 receipt](../../work/parallel-features-20261115/parallel-batch13-scoped-validation.json).
This receipt preserves the first full-check failures and scoped continuations. Native Windows operation remains unqualified until a Windows receipt
records actual device traffic, cancellation and resource cleanup. Compilation,
portable tests, `help`, `version` and `plan` are not native tunnel evidence.

The platform crate is `crates/l2tunnel-platform-windows`. It exports portable
`Config::new(PathBuf, [u8; 32], Ipv4Addr, u8, u16)` validation and, only on
Windows, `Device::open(&Config)`, `Device::name()` and the existing
`l2tunnel_device::PacketDevice` implementation. It owns no protocol,
authentication, reconnect or service state machine. Its owning application
must create the device on a blocking worker and supply it to the same shared
client/service runtime used by other clients.

## Explicit foreground lifecycle controls

The additive `--control-stdin` selection accepts bounded exact `status`,
`disconnect` and `reconnect` commands through the existing shared service. It
retains one service owner and one request continuation. Reconnect first observes
old-generation/device release, then stages a fresh device and submits the next
shared operation. Requested settings and actual generation/status remain separate.
Input closure and Ctrl+C stop ownership; a blocked stdin reader holds no tunnel
owner. Commands do not trigger automatic retry or acquire native privileges.

A retained Staging guard owns blocking device creation until its actual worker
returns. Cancellation joins it, including late successful creation, before final
release. There is no fabricated hard cancellation for an unresponsive driver;
status remains pollable while the worker completes. Portable fake-device and
real TLS/service evidence from external commit `c7935d9` is preserved in the
[delivery receipt](../../work/parallel-features-20261115/batch15-staging/external-windows/validation.json).
Current root [Batch15](../../work/parallel-features-20261115/parallel-batch15-scoped-validation.json)
passes all 31 portable application cases and affected GNU cross-target lint/link.
Its initial unrelated Unix-helper cross-compile error and repair remain preserved.
Windows driver/device execution remains unqualified.

## Dependency and safety decision

The implementation uses the safe synchronous API of exactly `tun-rs 2.8.18`
with default features disabled. The package was published on 2026-11-04 and
was inspected from the published crate archive, including its Windows loader,
session, adapter, packet and destructor paths. The workspace and this crate
retain `unsafe_code = "forbid"` for the device; no local FFI exception is
introduced for Wintun. This is a dependency-boundary source review, not a full
dependency audit or a claim of native qualification. The crate's later
named-pipe security module `local_pipe::ffi` is a separate, narrow exception
(the crate now `deny`s `unsafe` everywhere else). It is documented in
[Windows local service](windows-local-service.md) and is awaiting owner
approval under the rule below.

Relevant primary sources:

- [Published package and API](https://docs.rs/tun-rs/2.8.18/tun_rs/).
- [Published source](https://docs.rs/crate/tun-rs/2.8.18/source/), specifically
  `src/platform/mod.rs`, `src/builder.rs`,
  `src/platform/windows/device.rs`, `src/platform/windows/tun/mod.rs`, and
  `src/platform/windows/tun/bindings_x86_64.rs`.
- [Maintainer repository](https://github.com/tun-rs/tun-rs).
- [Official Wintun API contract](https://git.zx2c4.com/wintun/plain/api/wintun.h)
  and [signed distribution requirements](https://www.wintun.net/).

The direct `wintun 0.5.1` package was considered: its DLL-loading entry points
are unsafe, so adopting those calls would require a separately approved local
FFI exception. That alternative is not used. A future direct loader, raw handle
adapter or credential/service FFI must first document ownership, ABI checks,
pointer and buffer lifetimes, cancellation, DLL trust and destructor ordering,
then obtain the owner's approval for that exact boundary. Protocol libraries
must retain their existing rules.

## Local DLL and privilege boundary

`Config` requires an explicit absolute DLL file path and a mandatory SHA-256
pin selected by the local operator from a trusted distribution. Neither value
may be taken from an authenticated or unauthenticated peer. No bare filename,
current-directory or PATH lookup is offered. An explicit `.dll` extension is
required before and after canonicalization: Windows must not append an extension
and load a different file from the one hashed. Windows UNC and device namespace
paths are rejected. Opening resolves the local drive path before use, opens it
read-only with `FILE_SHARE_READ`, and hashes at most a bounded 16 MiB input
before allowing the dependency to load the DLL. The file remains open while
the native device exists, denying file write/deletion sharing during this
lifetime. An incorrect pin or an empty/oversized file fails before loading.

The pin authenticates the selected bytes only relative to the operator's trust
decision. It is not an Authenticode check and does not identify a publisher by
itself. The selected DLL, executable directory and their parent directories must be administrator-owned
and protected from untrusted changes. The file lock does not replace directory
ACLs or protect a malicious administrator's directory/reparse-point changes.
The dependency uses `libloading` internally; Windows image loading and system
dependency resolution remain part of this trusted platform boundary. Application
`.local` redirection or an already-loaded module can affect Windows loading; this
pre-load pin is not an attestation of the mapped image. See the official
[Windows loader remarks](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryw). Wrong
architecture, missing exports, driver setup failure and insufficient privilege
must return construction errors, not an effective connected capability.

No DLL or driver is bundled or published by this change. Wintun's official
distribution terms and native architecture selection must be resolved by any
future package work. The foreground process is explicitly elevated; an
unprivileged CLI and installed service are separate unfinished work.

## Device ownership and packet contract

Each construction uses a fresh name consisting of `l2t-` and 128 random bits
from `ring::rand::SystemRandom`. A caller cannot supply an existing adapter
name. This matters because `tun-rs` may open an existing named Wintun adapter;
its `reuse_dev(false)` option applies only to TAP and is not an L3 creation
guarantee. The random namespace makes accidental reuse negligible, but this
API cannot prove exclusive creation against a colliding privileged process.
That limitation is explicit; stronger create-only ownership would require an
upstream API addition or separately approved direct adapter boundary.

The builder selects L3, a fixed power-of-two one MiB ring, no driver deletion,
and no native logging callback. It assigns only the new interface's explicit
IPv4 address/prefix and IPv4/IPv6 MTU. Prefixes are restricted to 1..=32 and
MTUs to 1280..=65535. There is no gateway, default-route, DNS, metric, bridge or
VXLAN request. Windows may install the normal address-related on-link route;
that is an owned-interface effect and must be captured in native receipts.

Packet operations use `SyncDevice::try_recv` and `try_send`. There is no
blocking read thread or unbounded packet queue. `WouldBlock` on receive maps
to `None`; other errors remain errors. Receive requires the shared complete
packet buffer and rejects malformed IPv4/IPv6 lengths. Transmit validates one
complete IP packet of at most 65,535 bytes, preserves backpressure as an I/O
error and rejects a short successful write. The shared runtime retains MUX
admission, negotiated MTU and channel-budget ownership.

## Cancellation and release

The shared runtime owns the device. When cancellation or any startup/runtime
failure drops that ownership, the wrapper calls the safe `shutdown` operation.
The dependency stops its Wintun session, then releases the session and adapter
through RAII. Its adapter destructor calls `WintunCloseAdapter` after ending
the session; Wintun specifies that closing a created adapter also removes that
adapter. The dependency-owned event handle and loaded library are then
released. The locked DLL file is the last wrapper field released. Construction
errors also drop already-acquired dependency resources. `WintunDeleteDriver`
is disabled, so shared driver installation is never removed here.

The wrapper creates no blocking reader task that can retain the session after
the owning runtime stops. Constructor cancellation cannot abort an in-progress
Windows driver setup call; the application must await its blocking worker and
drop any returned device. Native shutdown errors and crash cleanup still
require real Windows fault-injection receipts; destructor source inspection
does not prove them.

## Native qualification still required

- Start from an elevated native Windows process with the pinned signed DLL;
  record Windows version, architecture, DLL hash/version, adapter identity,
  effective carrier and shared-service status.
- Exchange byte-exact IPv4 and IPv6 packets through the actual Wintun device and
  selected existing authenticated runtime, including MTU limits and malformed
  packet/backpressure paths.
- Cancel while idle, under bidirectional load and during constructor failure;
  confirm shared-service termination and adapter/session/event/file release.
- Prove a DLL pin failure occurs before a driver/device side effect; check
  replacement attempts while the file is locked and missing/wrong-architecture
  DLL errors.
- Record adapter, address and route state before/after normal exit, setup
  failure, driver failure and process crash. Confirm pre-existing interfaces,
  routes and shared driver installation survive.
- Preserve CL-25 Windows service/named-pipe ACLs, CL-26 TAP L2 and independent
  VXLAN qualification, and CL-27 credential storage, event logging, recovery,
  sleep/resume and network-change work. This foreground L3 slice closes none
  of those broader acceptance gates by itself.

Portable validation and Windows cross-compilation must be reported separately
from every native receipt. The root integration ledger owns commands and
evidence for the combined app/platform change.

## Foreground startup and operation

The actual call chain is:

```text
l2tunnel-windows.exe connect
  -> cli::parse (explicit tcp-tls / tun, bounded configuration)
  -> native::execute -> Plan::prepare
     -> existing ClientTls / MemberKey -> service::Prepared::client
  -> Setup::spawn -> Device::open (locked/pinned DLL, owned Wintun L3)
  -> foreground::run -> service::channel -> Handle::connect
     -> existing establish_managed -> TLS/member authentication
     -> Attachment::new closure transfers the already-owned Device
     -> existing run_managed_with_profile -> actual running observation
     -> PacketDevice::receive/transmit -> Wintun try_recv/try_send
  -> Ctrl+C -> Handle::cancel or Handle::disconnect -> owner release
```

The one-time platform constructor intentionally runs **before** network
authentication, after bounded credential parsing and shared plan validation.
It may create an interface even if the peer later fails authentication. The
shared service attachment remains deferred until authentication; it performs
only a finite ownership transfer. Failed authentication or cancellation before
that transfer drops the unused device at foreground exit. This distinction is
observable and is not described as authenticated device creation.

An owned setup thread sends only readiness notification and retains its actual
result in its join handle. Cancellation and dropping the foreground future join
that exact thread and release an unclaimed successful device. Windows driver
creation cannot safely be force-aborted: shutdown may wait for the OS call, so
this implementation does not promise a hard constructor cancellation latency.
The connected managed runtime uses the existing inline owners; its abort is a
local release, not authenticated peer drain or retained-state reconnect.

The console observer receives bounded requested settings and actual managed
snapshots (phase, operation/generation, effective compressor, epoch, packet and
peer-delivery counters). Requested TCP/TLS, no UDP cover and system traffic are
explicit; effective carrier is absent until actual running status. Diagnostics
are best-effort through a bounded, nonblocking text queue; a blocked output
writer owns no native/service/credential handles and cannot delay cancellation.
The full Windows service event-log requirement remains CL-27. No Windows local
IPC endpoint or GUI is claimed by this foreground adapter.

Example native Windows invocation, after locally provisioning the official
architecture-matching DLL and existing DER/PKCS#8 member credentials in
administrator-controlled locations:

```powershell
.\l2tunnel-windows.exe connect --carrier tcp-tls --layer tun `
  --remote 192.0.2.10:4433 --ca C:\l2tunnel\ca.der `
  --server-name tunnel.example --identity C:\l2tunnel\member.pk8 `
  --wintun-dll C:\l2tunnel\wintun.dll --wintun-sha256 TRUSTED_64_HEX_DIGEST `
  --address 10.81.0.2/24 --mtu 1500 --duplex half --compression off
```

This command is an unexecuted native recipe, not a saved successful run. Replace
the documentation address and digest from your trusted local provisioning. The
peer must use the existing matching managed TCP/TLS frame configuration, e.g.
Linux `serve --layer tun --carrier tcp --max-packet 1500 --duplex half`, with its
own certificate/key, allowlist, device and owned interface configuration. Both
half and full duplex are explicit existing modes. The outer IPv4 peer cannot be
inside the newly configured Wintun on-link subnet; the frontend rejects that
route-loop configuration before creating the device.

Credential input is bounded and private key input buffers are zeroized after
parsing. This slice reads explicitly provisioned files; it neither writes keys
nor claims Windows credential-vault or ACL administration. Configure restrictive
file ACLs locally. No route, DNS, default carrier, protocol authentication,
window-control or service state-machine replacement is introduced.

## Scoped implementation ledger

- [x] [WFG-01] Implement the real safe-dependency Wintun adapter with bounded validation, explicit trust inputs, nonblocking packet I/O and owned handle release; record affected checks. Evidence: [scoped validation](../../work/windows-wintun-20261116/validation.json), [platform source](../../crates/l2tunnel-platform-windows/src/lib.rs), [foreground source](../../apps/l2tunnel-windows/src/native.rs).
- [x] [WFG-02] Wire explicit foreground startup and cancellation through the existing shared Prepared/Run/Handle API, preserving requested/effective observations and platform credential ownership; record affected checks. Evidence: [scoped validation](../../work/windows-wintun-20261116/validation.json), [platform source](../../crates/l2tunnel-platform-windows/src/lib.rs), [foreground source](../../apps/l2tunnel-windows/src/native.rs).
- [x] [WFG-03] Validate failure/cancellation ownership, actual maintained TLS with fake packet devices, both duplex selections and DLL/configuration bounds on Linux; record this as portable evidence only. Evidence: [scoped validation](../../work/windows-wintun-20261116/validation.json), [platform source](../../crates/l2tunnel-platform-windows/src/lib.rs), [foreground source](../../apps/l2tunnel-windows/src/native.rs).
- [x] [WFG-04] Cross-check and link the actual Windows app/adapter with pinned dependencies; record that no native device operation was executed. Evidence: [scoped validation](../../work/windows-wintun-20261116/validation.json), [platform source](../../crates/l2tunnel-platform-windows/src/lib.rs), [foreground source](../../apps/l2tunnel-windows/src/native.rs).
- [ ] [WFG-05] Run the native Windows device matrix above, including driver faults, privileges, both IP families, cancellation, output stalls and all owned resource cleanup. Preserve full CL-25..27 and TEST-14 acceptance.

## Executed checks and integration handoff

Baseline: `99f45488f01f0f215e7b6c3bbb58b3c9a7d74360`; isolated branch
`codex/windows-wintun-foreground`. The integration worktree was not modified.
The [scoped receipt](../../work/windows-wintun-20261116/validation.json) retains
exact commands, source SHA-256s, binary hash and both failed attempts. The initial
Windows baseline failed because a portable local DTO was Unix-gated; the shared
patch only adjusts four cfg sites/files. A first app test build also failed on
an incorrect existing compressor variant spelling, then was corrected. These
failed logs remain preserved.

Executed in `/tmp/l2tunnel-windows-20261116-target`:

- `cargo test --locked -p l2tunnel-platform-windows -p l2tunnel-windows`: passed
  16 Linux tests, including real TLS/shared service and fake device byte delivery
  under both Half and Full. No Windows test was executed.
- `cargo fmt --check -p l2tunnel-windows -p l2tunnel-platform-windows -p l2tunnel-client-core`: passed.
- `cargo clippy --locked -p l2tunnel-windows -p l2tunnel-platform-windows --all-targets --no-deps -- -D warnings`: passed.
- The same affected Clippy command with `--target x86_64-pc-windows-gnu`: passed.
  The dependency build reports 27 pre-existing client-core dead-code warnings;
  this is not a strict whole-workspace Windows pass.
- `cargo check --locked --target x86_64-pc-windows-gnu -p l2tunnel-windows -p l2tunnel-platform-windows --all-targets`: passed before the final diagnostics refinement; final Windows Clippy and linking include that refinement.
- `cargo build --locked --target x86_64-pc-windows-gnu -p l2tunnel-windows`: passed
  and linked the actual executable; it was not run on Windows.
- `python3 tools/check_checklists.py` and `git diff --check`: passed.

Per the owner's explicit parallel-work instruction, full `python3 tools/check.py`
was left to the integrator. No native Windows environment was available. No
package was published, no license selected, no memory modified and no push made.
