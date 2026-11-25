# Explicit packed record client selection

Status: implemented with independent source review, focused client tests and
[stable wave11 checks](../../work/implementation-wave11/validation.json).
Native qualification remains pending. The implemented
`l2tunnel_runtime::packed` owns authenticated UDP/QUIC bindings, common MUX,
timed packing and recovery. This client slice selects those owners; it does not
create another codec, queue, sender, management path or native-drain mechanism.

## API and configuration

Add `l2tunnel_client_core::packed` with:

```text
Settings { channels: u16, packing: runtime::packed::Options }
Settings::validate(ConnectionConfig, udp::RecoveryMode) -> io::Result<()>
udp_config(ConnectionConfig, udp::Settings, Settings)
    -> io::Result<(runtime::udp::Config, runtime::packed::Config)>
quic_config(ConnectionConfig, quic::Settings, Settings)
    -> io::Result<(runtime::quic::Config, runtime::packed::Config)>
connect_udp/accept_udp(existing credentials/endpoints, ConnectionConfig,
    udp::Settings, Settings) -> actual typed packed link and validated configs
connect_quic(existing roots/name/member, ConnectionConfig,
    quic::Settings, Settings) -> actual typed packed link and validated configs
QuicListener::bind(certs, key, ConnectionConfig, quic::Settings, Settings)
QuicListener::accept(allowlist) -> actual typed packed link and validated configs
```

The packed settings require channels 1..255, hold_micros 1..1000, max_units 1..255,
work_limit 1..255, compression off and explicit Cauchy recovery. Runtime config
derivation remains the sole authority for tighter MTU, source/batch, memory,
fragment and recovery-lifetime bounds. Max units are a ceiling, not a guaranteed
number of native frames per source. No implicit MTU increase or recovery fallback.
TAP/VXLAN use the Ethernet body selection, TUN raw IP; system TCP algorithms stay
unchanged. All native traffic including probes uses the common channel pool.

Extend CLI `--record-profile frame|aligned|packed`, keeping default `frame`.
Packed-only options are `--packed-channels` (default 4), `--packed-hold-micros`
(default 1000), `--packed-max-units` (default 4), and `--packed-work-limit`
(default 16). Reject these options for other profiles and reject aligned-only
options for packed. Reject duplicate/unknown values with existing strict parsing.
Require explicit `--carrier udp|quic`, `--fec cauchy`, `--compression off`, system
traffic, and existing fixed endpoints/duplex configuration. Reject TCP/raw TCP,
standalone openvpn-like, active/proxy/adaptive settings, managed catalog,
compression reload and local-control socket combinations before credentials or
device I/O. No packet-profile switching or GUI implementation is implied.

## Actual lane ownership and time

Add only a private `udp::Records::Packed(&packed::Config)` binding branch to the
existing lane builder. The binding uses the runtime's exact packed digest and
full expected session config for each actual lane. Ordinary Frame and Aligned
branches keep their bytes, factories and defaults. Genuine QUIC continues through
the existing base-config/owned endpoint helper with no TCP bootstrap. Return the
runtime's typed Packed UdpLink/QuicLink after actual pair validation; never adopt
an ordinary link or reconstruct session proof from status/config values.

For the new packed factories, capture one original setup deadline before the
first bind/accept/connect operation, using ConnectionConfig.handshake_timeout.
Wrap the entire lane and pair assembly in that one remaining allowance, with
explicit pre/post deadline checks (ready futures can otherwise win at expiry).
Listener bind validates all configuration before socket work. Each listener
accept call starts a single attempt deadline; a peer rejection ends that attempt.
Partial second-lane establishment and cancellation drop all attempt-owned client
handles/connections and newly accepted authenticated lanes. Maintained Quinn
drivers can retain a UDP socket during protocol closing after the application
owners drop: this is separate from factory completion, not immediate port reuse
or a successful native drain. A caller-owned TCP
listener and a reusable QUIC listener retain their pre-existing bound endpoints;
accept cancellation does not dispose of those listener owners. The existing shared lane helpers' internal bounds cannot
extend this new outer packed deadline. Do not change legacy helper deadline
semantics in this slice. QUIC's pair_deadline must also remain enforced; the
effective limit is the earlier remaining deadline, never a renewed duration.

Authenticate and pair before constructing a native device, exactly as existing
CLI dispatch does. New Connected variants retain actual typed links/configs and
call only `runtime::packed::run_udp/run_quic`. Runtime cancellation remains
cancellation; there is no successful drain result or fabricated terminal report.
Existing command startup output identifies the requested/effective record profile
and negotiated packing settings without printing credentials or implementation
details into user packet flows.

## Tests and qualification gates

Focused tests must use real client entry points with full/half UDP and genuine
QUIC, TAP/TUN memory devices, exact bidirectional small/context/fragment/zero-tail
payloads, and actual original owner cleanup on cancellation. Runtime packet/loss
coverage is referenced separately rather than recreated in a second engine.
Exercise a peer mismatch for channels and each packing parameter during actual
authentication, wrong certificate/member, failed/missing second lane, expired
original setup/pair deadline, and pre-I/O rejection of incompatible flags or MTU.
Pin ordinary Frame/Aligned configuration digests and regress their real factories.
Test that client cancellation cannot yield a link and eventually releases the
original bound UDP tuples, while canceled accepts preserve reusable listener
ownership. The cleanup observation has its own fixed bound and cannot extend the
setup deadline. Test zero-match filters explicitly by reporting actual executed
case counts.

The original two-second cleanup observation failed for a canceled no-peer QUIC
attempt. Source review of pinned `quinn 0.11.11` / `quinn-proto 0.11.17` found
`ConnectionRef::drop` initiates implicit close; `EndpointDriver` retains the
endpoint until its connections drain. The close timer is three PTOs; the unchanged
333 ms initial RTT and half-RTT variance give 2,997 ms for an Initial-space
connection. A finite diagnostic observed exact simultaneous tuple reuse after
3.0015 seconds, while the factory itself retained its original 100 ms deadline.
The corrected test uses a separate five-second cleanup observation. No QUIC
transport defaults, production timeout, close semantics or runtime success
claims changed. Dropping an unused reusable listener released its tuples in
about 3 ms in the same diagnostic. These are local cancellation observations,
not general network close bounds.

The later frozen wave15b cleanup failures showed that this historical PTO-based
observation was not an ownership guarantee. The [QUIC endpoint owner correction](quic-owner-cleanup.md)
now releases only the abandoned endpoint's driver resources independently of PTO,
retains actual sessions/reusable listeners, and preserves the same five-second
observation. The packed original-deadline postcheck now also classifies a late
inner error as TimedOut. Before/after regressions and scoped source provenance are
recorded in the [owner cleanup receipt](../../work/quic-owner-cleanup/validation.json).
This does not revise the historical wave11 observations above.

Native harness selection is a later independently reviewed checkpoint. Preserve
existing frame/aligned defaults and historical receipts; use a new immutable build
and first clean finite case before expansion to TAP/TUN/VXLAN full/half and impaired
cases. Real multi-unit packed wire observation, whole-IP MTU, no outer fragmentation,
exact payloads and cleanup are required. Integrity mode permits cleartext envelope
inspection; encrypted-header guesses cannot prove packed contents. No catalog
parity checkbox is completed by only this client or compile success.

## Checklist

- [x] [MOD-PACKCLI-01] Independently review API, flags, ownership, original deadlines and fixed qualification scope before implementation. Evidence: [actual lane ownership and time](#actual-lane-ownership-and-time), [API and compatibility](#api-and-configuration); independent review accepted with explicit reusable-listener cancellation semantics.
- [x] [MOD-PACKCLI-02] Implement typed UDP/QUIC settings and real lane factories with complete packed binding and cancellation cleanup. Evidence: [typed factories (retired in Common cutover)](compact-wire-cleanup.md), [actual cancellation and missing-second-lane regressions (retired in Common cutover)](compact-wire-cleanup.md); independent source review accepted and 11 packed/CLI focused tests passed before adding the separate fixed ordinary-digest regression.
- [x] [MOD-PACKCLI-03] Add strict opt-in CLI dispatch and profile status while preserving Frame/Aligned defaults and exact policy digests. Evidence: [strict selection (retired in Common cutover)](compact-wire-cleanup.md), [four fixed ordinary binding regressions (retired in Common cutover)](compact-wire-cleanup.md), [wave11](../../work/implementation-wave11/validation.json).
- [x] [MOD-PACKCLI-04] Pass actual authenticated full/half TAP/TUN client tests, policy/auth mismatch, deadline, second-lane and original-socket cleanup regressions. Evidence: [real client tests (retired in Common cutover)](compact-wire-cleanup.md), [failure and cancellation tests (retired in Common cutover)](compact-wire-cleanup.md), [wave11 log](../../work/implementation-wave11/local-check.log); 12 packed/CLI tests passed within all 80 client tests, including separately bounded maintained QUIC close observation.
- [x] [MOD-PACKCLI-05] Independently review source ownership and run focused strict lint/docs plus stable workspace aggregate. Evidence: independent source review accepted actual lane authority, original deadlines, listener ownership and early CLI rejection; [wave11](../../work/implementation-wave11/validation.json) passed 702 Rust and 85 Python tests with unchanged source hashes, strict Clippy/rustdoc and formatting.
- [ ] [MOD-PACKCLI-06] Design, review and implement additive native harness options, then qualify one immutable clean case with captures and exact payloads; tracked in the [packed native checkpoint](packed-native.md).
- [ ] [MOD-PACKCLI-07] Qualify the separately reviewed finite native matrix and record failures/unrun cases without changing bounds or catalog parity claims.
