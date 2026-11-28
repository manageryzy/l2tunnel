# Embedded OpenGFW Inspection & Survival Lab

This module embeds [OpenGFW](https://github.com/HyNetworks/OpenGFW) (pinned to commit `581518071fbe72519887fc92250df31d86b4386c`) into the repository's isolated Linux network-namespace testing system (`tools/opengfw_lab.py`).

It answers two concrete questions with real Linux kernel packets and live `l2tunneld` daemons:

1. **Classification ("What do our carriers look like in OpenGFW?"):**
   Under an `observe-all` ruleset that activates all 10 built-in OpenGFW analyzers (`fet`, `http`, `socks`, `ssh`, `tls`, `trojan`, `dns`, `openvpn`, `quic`, `wireguard`), what exact protocol properties does OpenGFW extract for every implemented `l2tunnel` carrier?
2. **Survival ("How many carriers survive under OpenGFW blocking rulesets?"):**
   Across individual analyzer rules, SNI blocklists/allowlists, and a composite GFW-style ruleset with active TCP RST injection (`io.rst: true`), which carriers complete the tunnel handshake, pass TUN ICMP pings, and transfer TCP payloads — and which are blocked, dropped, or reset?

## Scope and Honesty Boundaries

- **What this tests:** Real compiled OpenGFW running inline on Linux `FORWARD` NFQUEUE (`nf_tables` `inet opengfw`, queue 100, `ct mark` accept/drop/TCP-RST) inspecting real `l2tunneld` UDP, TCP/TLS 1.3, Quinn QUIC, OpenVPN-like, and raw-packet traffic across isolated kernel namespaces.
- **What this does NOT claim:** OpenGFW is an open-source signature/heuristic DPI engine; surviving OpenGFW does **not** guarantee survival against live ISP/nation-state active probing, statistical ML flow classifiers, IP reputation lists, or port-based blocking. Negative findings (for example, `openvpn-like` matching OpenGFW's USENIX '22 OpenVPN opcode analyzer, or `quic-like` remaining unclassified to OpenGFW's RFC 9000 QUIC decryptor) are recorded verbatim rather than hidden.

## Isolation & Safety Guarantees

`tools/opengfw_lab.py` follows the same isolation contract as `tools/netns_lab.py`:

- **Dry-run by default:** Running `python3 tools/opengfw_lab.py` prints the execution plan without calling `sudo`, creating namespaces, compiling binaries, or touching the network.
- **Zero host network/firewall changes:** OpenGFW runs strictly inside the ephemeral router namespace `l2t-<lab>-wan` with `io.local: false` and `io.rst: true`. Its `inet opengfw` nftables table exists only inside that namespace and disappears automatically on teardown.
- **Ownership-tracked teardown:** Every cell creates a fresh namespace set via `netns_lab.apply` (zero loss, 2 ms RTT so failures come exclusively from OpenGFW), runs OpenGFW + `l2tunneld` server/client, collects logs and probe receipts, terminates all child processes, and removes owned namespaces via `netns_lab.cleanup` inside `finally`.
- **Isolated OpenGFW cache:** Source and compiled binary live under `target/opengfw-cache/` (gitignored), pinned to `HyNetworks/OpenGFW@581518071fbe72519887fc92250df31d86b4386c`.

```text
endpoint_a (l2t-<id>-ea)         router (l2t-<id>-wan)            endpoint_b (l2t-<id>-eb)
  l2tunneld connect               OpenGFW (FORWARD NFQUEUE 100)     l2tunneld serve
  tun0: 10.231.0.2/30             nft table inet opengfw (rst=on)   tun0: 10.231.0.1/30
  wan0: 192.0.2.2/30  <-------->  a0: 192.0.2.1/30 | b0: .5/30 <--> wan0: 192.0.2.6/30
```

## Carrier Profiles Under Test (10 Variants Covering All 7 Carriers)

| Profile ID | Carrier | Outer Transport / Cover | ClientHello SNI | Provisioning Path |
| --- | --- | --- | --- | --- |
| `quic-like` | `quic-like` | UDP + QUIC-like cover | N/A | `l2tunnelctl wizard init --offline` |
| `media-like` | `media-like` | UDP + media/RTP-like cover | N/A | `l2tunnelctl wizard init --offline` |
| `tls-like` | `tls-like` | UDP + TLS-like cover | N/A | `l2tunnelctl wizard init --offline` |
| `openvpn-like-google` | `openvpn-like` | UDP + OpenVPN wire handshake + TLS 1.3 | `google.com` | `l2tunnelctl wizard init --offline` |
| `tcp-nosni` | `tcp` | Maintained TCP/TLS 1.3 | *(none)* | `l2tunnelctl wizard init --offline` (`--sni` stripped) |
| `tcp-google` | `tcp` | Maintained TCP/TLS 1.3 | `google.com` | `l2tunnelctl wizard init --offline` |
| `tcp-blocked` | `tcp` | Maintained TCP/TLS 1.3 (positive control) | `blocked.example` | `l2tunnelctl wizard init --offline` |
| `quic` | `quic` | Genuine Quinn QUIC (RFC 9000) | *(Quinn default)* | `l2tunnelctl wizard init --offline` |
| `raw-packet-google` | `raw-packet` | TCP/TLS 1.3 bootstrap -> AEAD raw TCP phase | `google.com` | Ephemeral EC cert + `raw-packet-runtime-v2` policy |
| `raw-packet-blocked` | `raw-packet` | TCP/TLS 1.3 bootstrap -> AEAD raw TCP phase (control) | `blocked.example` | Ephemeral EC cert + `raw-packet-runtime-v2` policy |

## OpenGFW Ruleset Matrix (8 Rulesets)

OpenGFW only activates analyzers explicitly referenced in rule expressions (`ruleset/expr.go`). Every ruleset is generated deterministically by `tools/opengfw_lab.py`:

| Ruleset ID | Purpose | OpenGFW Rule Logic |
| --- | --- | --- |
| `observe-all` | Passive classification across all 10 analyzers | Log-only fallthrough rules referencing `fet`, `tls`, `http`, `socks`, `ssh`, `trojan`, `dns`, `openvpn`, `quic`, `wireguard`, plus `proto == "tcp" \|\| proto == "udp"` (no blocking action). |
| `block-fet` | USENIX '23 Fully Encrypted Traffic detector | `action: block` when `fet != nil && fet.yes`. |
| `block-openvpn` | USENIX '22 OpenVPN opcode LSM detector | `action: block` when `openvpn != nil && (openvpn.tx_pkt_cnt >= 1 \|\| openvpn.rx_pkt_cnt >= 1)`. |
| `block-wireguard` | WireGuard UDP signature detector | `action: block` when `wireguard != nil`. |
| `block-quic` | RFC 9000 QUIC Initial detector | `action: block` when `quic != nil`. |
| `block-sni-blocklist` | Targeted SNI censorship (TLS + QUIC, TCP RST on) | `action: block` when `tls?.req?.sni == "blocked.example"` or `quic?.req?.sni == "blocked.example"`. |
| `allow-only-google-sni` | Strict enterprise/firewall SNI allowlist | Allow only `tls?.req?.sni == "google.com"` or `quic?.req?.sni == "google.com"`; block other TLS, FET TCP, and non-matching UDP. |
| `gfw-composite` | Realistic combined GFW-style ruleset | Block `fet.yes`, `openvpn`, `wireguard`, and `blocked.example` SNI (TLS + QUIC); allow remaining flows. |

## Survival Criteria Per Cell

Each `(carrier, ruleset)` cell passes ("SURVIVED") only when all three checks succeed within bounded timeouts:

1. **Tunnel readiness:** Both `l2tunneld serve` and `l2tunneld connect` reach active tunnel state (or remain live while forwarding).
2. **ICMP liveness over TUN:** `ping -c 5 -i 0.1 -W 2 10.231.0.1` from `endpoint_a` receives all 5 replies (100% delivery).
3. **TCP data transfer over TUN:** A 64 KiB SHA-256-verified TCP payload transfer from `endpoint_a` (`10.231.0.2`) to `endpoint_b` (`10.231.0.1:24555`) completes with exact byte match.

Cells that fail handshake, ICMP, or TCP transfer are classified as **BLOCKED** (when OpenGFW logged a `block`/`drop` action on the underlay flow) or **FAILED** (if no OpenGFW block occurred, flagging a genuine transport/harness issue).

## Usage

```sh
# 1. Dry-run plan (default, unprivileged, no side effects)
python3 tools/opengfw_lab.py
python3 tools/opengfw_lab.py --json

# 2. Build pinned OpenGFW binary into target/opengfw-cache/opengfw
python3 tools/opengfw_lab.py --build-opengfw

# 3. Run unprivileged unit tests
python3 -m unittest tools.test_opengfw_lab -v

# 4. Run full isolated Linux netns OpenGFW matrix (requires root + compiled l2tunneld/l2tunnelctl)
sudo python3 tools/opengfw_lab.py --run-matrix --output-dir work/opengfw-20261127

# 5. Run a targeted subset (e.g. only observe-all and gfw-composite)
sudo python3 tools/opengfw_lab.py --run-matrix --rulesets observe-all,gfw-composite --output-dir work/opengfw-sample
```

## Measured Results (`work/opengfw-20261127`)

Full 80-cell isolated Linux kernel netns matrix (`10 carrier profiles × 8 OpenGFW rulesets`, `0 FAILED`, every non-passing cell cleanly explained by an OpenGFW `BLOCKED` verdict) recorded in [work/opengfw-20261127/RESULTS.md](../../work/opengfw-20261127/RESULTS.md) and [work/opengfw-20261127/receipt.json](../../work/opengfw-20261127/receipt.json):

- **OpenGFW commit:** `581518071fbe72519887fc92250df31d86b4386c` (`HyNetworks/OpenGFW`)
- **OpenGFW binary SHA-256:** `4e1d6ca489516c963d2e42698bea7e7057f7b006a46a28e0d3caacd6310ba349`
- **l2tunneld SHA-256:** `008a405ca4b9bdd4ff8bfa8ef96d992e0413b8145f3cb115480bb32914f8e256`

### 1. What Each Carrier Looks Like in OpenGFW (`observe-all`)

| Carrier Profile | Outer Proto | Matched Analyzers | OpenGFW Classification Details | Observe-All Survival |
| --- | --- | --- | --- | --- |
| `quic-like` | `udp` | `(none)` | `unclassified (udp)` | **SURVIVED** (5/5 ping, 65536 B TCP) |
| `media-like` | `udp` | `(none)` | `unclassified (udp)` | **SURVIVED** (5/5 ping, 65536 B TCP) |
| `tls-like` | `udp` | `(none)` | `unclassified (udp)` | **SURVIVED** (5/5 ping, 65536 B TCP) |
| `openvpn-like-google` | `udp` | `openvpn` | `openvpn(tx=18, rx=14)` | **SURVIVED** (5/5 ping, 65536 B TCP) |
| `tcp-nosni` | `tcp` | `fet, tls, trojan` | `tls(sni=none); fet(yes=False, ex5=True, ex1=2.74); trojan(yes=False, seq=[80, 165, 213, 100])` | **SURVIVED** (5/5 ping, 65536 B TCP) |
| `tcp-google` | `tcp` | `fet, tls, trojan` | `tls(sni=google.com); fet(yes=False, ex5=True, ex1=2.64); trojan(yes=False, seq=[80, 165, 213, 100])` | **SURVIVED** (5/5 ping, 65536 B TCP) |
| `tcp-blocked` | `tcp` | `fet, tls, trojan` | `tls(sni=blocked.example); fet(yes=False, ex5=True, ex1=2.68); trojan(yes=False, seq=[80, 165, 213, 100])` | **SURVIVED** (5/5 ping, 65536 B TCP) |
| `quic` | `udp` | `quic` | `quic(sni=none, alpn=l2t-quic-v1\x00\x00\x00\x00\x01)` | **SURVIVED** (5/5 ping, 65536 B TCP) |
| `raw-packet-google` | `tcp` | `fet, tls, trojan` | `tls(sni=google.com); fet(yes=False, ex5=True, ex1=2.69); trojan(yes=False, seq=[80, 165, 213, 100])` | **SURVIVED** (5/5 ping, 65536 B TCP) |
| `raw-packet-blocked` | `tcp` | `fet, tls, trojan` | `tls(sni=blocked.example); fet(yes=False, ex5=True, ex1=2.59); trojan(yes=False, seq=[80, 165, 213, 100])` | **SURVIVED** (5/5 ping, 65536 B TCP) |

### 2. Survival Matrix (Carrier × Active OpenGFW Ruleset)

| Carrier Profile | `observe-all` | `block-fet` | `block-openvpn` | `block-wireguard` | `block-quic` | `block-sni-blocklist` | `allow-only-google-sni` | `gfw-composite` | Active Survival |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `tcp-google` | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** | **7/7 (100%)** |
| `raw-packet-google` | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** | **7/7 (100%)** |
| `quic-like` | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** | BLOCKED | **PASS** | **6/7 (86%)** |
| `media-like` | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** | BLOCKED | **PASS** | **6/7 (86%)** |
| `tls-like` | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** | BLOCKED | **PASS** | **6/7 (86%)** |
| `tcp-nosni` | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** | BLOCKED | **PASS** | **6/7 (86%)** |
| `quic` | **PASS** | **PASS** | **PASS** | **PASS** | BLOCKED | **PASS** | BLOCKED | **PASS** | **5/7 (71%)** |
| `openvpn-like-google` | **PASS** | **PASS** | BLOCKED | **PASS** | **PASS** | **PASS** | BLOCKED | BLOCKED | **4/7 (57%)** |
| `tcp-blocked` *(control)* | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** | BLOCKED | BLOCKED | BLOCKED | 4/7 (57%) |
| `raw-packet-blocked` *(control)* | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** | BLOCKED | BLOCKED | BLOCKED | 4/7 (57%) |

### 3. Key Findings & Actionable Observations

1. **Highest survival (`7/7`, `100%`) — `tcp-google` and `raw-packet-google`:**
   Both appear to OpenGFW as standard TLS 1.3 (`version=771`, `supported_versions=[772]`, `sni="google.com"`), pass the USENIX '23 FET detector (`fet.yes=false`, `ex5=true`, `ex1≈2.65`), and pass OpenGFW's Trojan TLS-in-TLS length-sequence tree (`trojan.yes=false`, `seq=[80, 165, 213, 100]`). Importantly, `raw-packet-google` also survives OpenGFW's inline NFQUEUE conntrack + `rst=true` across both its TLS 1.3 handshake and its subsequent AEAD raw TCP-shaped packet phase. Both positive controls (`tcp-blocked`, `raw-packet-blocked`) were immediately blocked/reset by OpenGFW.
2. **Appearance-only UDP covers (`quic-like`, `media-like`, `tls-like`, `6/7`, `86%`):**
   All three remain `unclassified (udp)` in OpenGFW — they trigger zero false positives in `openvpn`, `wireguard`, `dns`, or `quic` (because OpenGFW's `quic` analyzer decrypts RFC 9000 Initial packets rather than matching header bitmasks). They survive `gfw-composite` and every signature blocker, and are only stopped by a strict SNI allowlist (`allow-only-google-sni`) that drops all non-matching UDP.
3. **Genuine Quinn `quic` (`5/7`, `71%`) — plaintext ALPN & missing SNI discovered:**
   OpenGFW's RFC 9000 `quic` analyzer decrypted Quinn's Initial packet immediately and extracted `sni=none` and `alpn=["l2t-quic-v1\x00\x00\x00\x00\x01"]`. It survived `gfw-composite` (which only blocks `blocked.example` SNI) and failed `block-quic` and `allow-only-google-sni`. Adding configurable ClientHello `--sni` and standard `h3` ALPN cover to `l2tunnel-quic` would eliminate the plaintext `l2t-quic-v1` ALPN fingerprint and allow `quic` to pass `allow-only-google-sni`.
4. **`openvpn-like` (`4/7`, `57%`) — detected by USENIX '22 OpenVPN opcode LSM:**
   Because `openvpn-like` faithfully uses real OpenVPN wire opcodes (`HardResetClient` -> `HardResetServer` -> `ControlV1`/`AckV1`/`DataV2`), OpenGFW's `openvpn` analyzer reliably classifies it (`openvpn(tx=18, rx=14)`) and blocks it under both `block-openvpn` and `gfw-composite`. It is appropriate only on networks that permit standard OpenVPN traffic.
5. **Zero FET or WireGuard detections across all carriers:**
   `block-fet` (`10/10` survived) and `block-wireguard` (`10/10` survived) produced zero blocks across all 10 carrier profiles.

