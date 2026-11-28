#!/usr/bin/env python3
"""Embedded OpenGFW inspection & carrier survival lab (dry-run by default).

Runs compiled upstream OpenGFW inline inside an isolated ephemeral Linux router
namespace (l2t-<id>-wan, NFQUEUE FORWARD hook, rst=true) between two isolated
l2tunneld endpoints. Never modifies host interfaces, host routes, host qdiscs,
or host nftables/iptables.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any

try:
    from . import netns_lab
except ImportError:
    import netns_lab


ROOT = Path(__file__).resolve().parents[1]
OPENGFW_REPO = "https://github.com/HyNetworks/OpenGFW.git"
OPENGFW_COMMIT = "581518071fbe72519887fc92250df31d86b4386c"
DEFAULT_CACHE_DIR = ROOT / "target" / "opengfw-cache"
DEFAULT_OPENGFW_BIN = DEFAULT_CACHE_DIR / "opengfw"
DEFAULT_DAEMON_BIN = ROOT / "target" / "release" / "l2tunneld"
DEFAULT_CTL_BIN = ROOT / "target" / "release" / "l2tunnelctl"
DEFAULT_STATE_DIR = Path("/run/l2tunnel-labs")

CLIENT_WAN_IP = "192.0.2.2"
SERVER_WAN_IP = "192.0.2.6"
TUN_SERVER_IP = "10.231.0.1"
TUN_CLIENT_IP = "10.231.0.2"
SERVER_PORT = 24440
RAW_CLIENT_PORT = 24440
RAW_SERVER_PORT = 24441
RAW_SOCKET_MARK = 0x12AA0001
TCP_PROBE_PORT = 24555
TCP_PROBE_BYTES = 65536

ALL_ANALYZERS = (
    "fet",
    "tls",
    "http",
    "socks",
    "ssh",
    "trojan",
    "dns",
    "openvpn",
    "quic",
    "wireguard",
)


@dataclass(frozen=True)
class CarrierCase:
    id: str
    carrier: str
    description: str
    sni: str | None = None
    strip_sni: bool = False
    raw_suite: str = "aead"


CARRIER_CASES: tuple[CarrierCase, ...] = (
    CarrierCase(
        id="quic-like",
        carrier="quic-like",
        description="UDP with QUIC-like appearance cover",
    ),
    CarrierCase(
        id="media-like",
        carrier="media-like",
        description="UDP with RTP/media-like appearance cover",
    ),
    CarrierCase(
        id="tls-like",
        carrier="tls-like",
        description="UDP with TLS-like appearance cover",
    ),
    CarrierCase(
        id="openvpn-like-google",
        carrier="openvpn-like",
        description="UDP OpenVPN wire handshake + outer TLS 1.3 (SNI google.com)",
        sni="google.com",
    ),
    CarrierCase(
        id="tcp-nosni",
        carrier="tcp",
        description="Maintained TCP/TLS 1.3 without ClientHello SNI",
        sni=None,
        strip_sni=True,
    ),
    CarrierCase(
        id="tcp-google",
        carrier="tcp",
        description="Maintained TCP/TLS 1.3 with ClientHello SNI google.com",
        sni="google.com",
    ),
    CarrierCase(
        id="tcp-blocked",
        carrier="tcp",
        description="Maintained TCP/TLS 1.3 with blocked SNI (positive control)",
        sni="blocked.example",
    ),
    CarrierCase(
        id="quic",
        carrier="quic",
        description="Genuine maintained Quinn QUIC (RFC 9000)",
    ),
    CarrierCase(
        id="raw-packet-google",
        carrier="raw-packet",
        description="TCP/TLS 1.3 (SNI google.com) -> AEAD raw TCP-shaped packet phase",
        sni="google.com",
        raw_suite="aead",
    ),
    CarrierCase(
        id="raw-packet-blocked",
        carrier="raw-packet",
        description="TCP/TLS 1.3 (blocked SNI) -> AEAD raw TCP phase (control)",
        sni="blocked.example",
        raw_suite="aead",
    ),
)

CARRIER_BY_ID = {item.id: item for item in CARRIER_CASES}


@dataclass(frozen=True)
class RulesetSpec:
    id: str
    description: str
    rules: tuple[dict[str, Any], ...]


RULESET_SPECS: tuple[RulesetSpec, ...] = (
    RulesetSpec(
        id="observe-all",
        description="Log-only classification across all 10 OpenGFW analyzers (never blocks)",
        rules=(
            {"name": "obs-fet", "log": True, "expr": "fet != nil"},
            {"name": "obs-tls", "log": True, "expr": "tls != nil"},
            {"name": "obs-http", "log": True, "expr": "http != nil"},
            {"name": "obs-socks", "log": True, "expr": "socks != nil"},
            {"name": "obs-ssh", "log": True, "expr": "ssh != nil"},
            {"name": "obs-trojan", "log": True, "expr": "trojan != nil"},
            {"name": "obs-dns", "log": True, "expr": "dns != nil"},
            {"name": "obs-openvpn", "log": True, "expr": "openvpn != nil"},
            {"name": "obs-quic", "log": True, "expr": "quic != nil"},
            {"name": "obs-wireguard", "log": True, "expr": "wireguard != nil"},
            {"name": "obs-any", "log": True, "expr": 'proto == "tcp" || proto == "udp"'},
        ),
    ),
    RulesetSpec(
        id="block-fet",
        description="Block USENIX '23 Fully Encrypted Traffic (fet.yes)",
        rules=(
            {"name": "block-fet", "action": "block", "log": True, "expr": "fet != nil && fet.yes"},
            {"name": "obs-tls", "log": True, "expr": "tls != nil"},
        ),
    ),
    RulesetSpec(
        id="block-openvpn",
        description="Block USENIX '22 OpenVPN opcode sequence detector",
        rules=(
            {
                "name": "block-openvpn",
                "action": "block",
                "log": True,
                "expr": "openvpn != nil && (openvpn.tx_pkt_cnt >= 1 || openvpn.rx_pkt_cnt >= 1)",
            },
        ),
    ),
    RulesetSpec(
        id="block-wireguard",
        description="Block WireGuard UDP protocol signature",
        rules=(
            {"name": "block-wireguard", "action": "block", "log": True, "expr": "wireguard != nil"},
        ),
    ),
    RulesetSpec(
        id="block-quic",
        description="Block all RFC 9000 QUIC streams decrypted by OpenGFW",
        rules=(
            {"name": "block-quic", "action": "block", "log": True, "expr": "quic != nil"},
        ),
    ),
    RulesetSpec(
        id="block-sni-blocklist",
        description="Block TLS/QUIC SNI == blocked.example with TCP RST injection",
        rules=(
            {
                "name": "block-tls-sni",
                "action": "block",
                "log": True,
                "expr": 'tls != nil && tls?.req?.sni == "blocked.example"',
            },
            {
                "name": "block-quic-sni",
                "action": "block",
                "log": True,
                "expr": 'quic != nil && quic?.req?.sni == "blocked.example"',
            },
        ),
    ),
    RulesetSpec(
        id="allow-only-google-sni",
        description="Strict allowlist: allow only TLS/QUIC SNI == google.com; block all else",
        rules=(
            {
                "name": "allow-tls-google",
                "action": "allow",
                "log": True,
                "expr": 'tls != nil && tls?.req?.sni == "google.com"',
            },
            {
                "name": "allow-quic-google",
                "action": "allow",
                "log": True,
                "expr": 'quic != nil && quic?.req?.sni == "google.com"',
            },
            {
                "name": "block-other-tls",
                "action": "block",
                "log": True,
                "expr": 'tls != nil && tls?.req?.sni != "google.com"',
            },
            {
                "name": "block-fet-tcp",
                "action": "block",
                "log": True,
                "expr": "fet != nil && fet.yes",
            },
            {
                "name": "block-other-udp",
                "action": "block",
                "log": True,
                "expr": 'proto == "udp" && (quic == nil || quic?.req?.sni != "google.com")',
            },
        ),
    ),
    RulesetSpec(
        id="gfw-composite",
        description="Composite GFW-style ruleset: block FET, Trojan, OpenVPN, WireGuard, and blocked.example SNI",
        rules=(
            {"name": "block-fet", "action": "block", "log": True, "expr": "fet != nil && fet.yes"},
            {"name": "block-trojan", "action": "block", "log": True, "expr": "trojan != nil && trojan.yes"},
            {
                "name": "block-openvpn",
                "action": "block",
                "log": True,
                "expr": "openvpn != nil && (openvpn.tx_pkt_cnt >= 1 || openvpn.rx_pkt_cnt >= 1)",
            },
            {"name": "block-wireguard", "action": "block", "log": True, "expr": "wireguard != nil"},
            {
                "name": "block-tls-sni",
                "action": "block",
                "log": True,
                "expr": 'tls != nil && tls?.req?.sni == "blocked.example"',
            },
            {
                "name": "block-quic-sni",
                "action": "block",
                "log": True,
                "expr": 'quic != nil && quic?.req?.sni == "blocked.example"',
            },
            {"name": "obs-tls", "log": True, "expr": "tls != nil"},
            {"name": "obs-quic", "log": True, "expr": "quic != nil"},
        ),
    ),
)

RULESET_BY_ID = {item.id: item for item in RULESET_SPECS}


def yaml_quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def render_opengfw_config_yaml(*, rst: bool = True, workers: int = 2) -> str:
    """Render minimal OpenGFW config YAML for isolated router FORWARD inspection."""
    return "\n".join(
        [
            "io:",
            "  queueSize: 1024",
            "  rcvBuf: 4194304",
            "  sndBuf: 4194304",
            "  local: false",
            f"  rst: {'true' if rst else 'false'}",
            "workers:",
            f"  count: {workers}",
            "  queueSize: 64",
            "  tcpMaxBufferedPagesTotal: 4096",
            "  tcpMaxBufferedPagesPerConn: 256",
            "  udpMaxStreams: 4096",
            "",
        ]
    )


def render_ruleset_yaml(spec: RulesetSpec) -> str:
    """Render deterministic OpenGFW YAML ruleset without external PyYAML dependency."""
    lines: list[str] = []
    for rule in spec.rules:
        lines.append(f"- name: {yaml_quote(str(rule['name']))}")
        if "action" in rule and rule["action"]:
            lines.append(f"  action: {rule['action']}")
        lines.append(f"  log: {'true' if rule.get('log', False) else 'false'}")
        lines.append(f"  expr: {yaml_quote(str(rule['expr']))}")
    lines.append("")
    return "\n".join(lines)


def select_items(
    raw: str | None,
    all_items: tuple[Any, ...],
    by_id: dict[str, Any],
    kind: str,
) -> list[Any]:
    if not raw:
        return list(all_items)
    selected: list[Any] = []
    seen: set[str] = set()
    for token in raw.split(","):
        name = token.strip()
        if not name:
            continue
        if name not in by_id:
            valid = ", ".join(by_id)
            raise ValueError(f"unknown {kind} '{name}' (valid: {valid})")
        if name not in seen:
            seen.add(name)
            selected.append(by_id[name])
    if not selected:
        raise ValueError(f"empty {kind} selection")
    return selected


def validate_lab_prefix(prefix: str) -> str:
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,9}", prefix):
        raise ValueError("lab prefix must match [a-z][a-z0-9-]{0,9}")
    return prefix


def cell_lab_id(prefix: str, index: int) -> str:
    validate_lab_prefix(prefix)
    if index < 0 or index > 9999:
        raise ValueError("cell index out of range 0..9999")
    lab_id = f"{prefix}-{index:03d}"
    netns_lab.LabSpec(lab_id, loss_percent=0)
    return lab_id


def _deep_merge(dst: dict[str, Any], src: dict[str, Any]) -> None:
    for key, val in src.items():
        if isinstance(val, dict) and isinstance(dst.get(key), dict):
            _deep_merge(dst[key], val)
        else:
            dst[key] = val


STREAM_LOG_MSGS = frozenset(
    {
        "new TCP stream",
        "new UDP stream",
        "TCP stream property update",
        "UDP stream property update",
        "ruleset log",
        "TCP stream action",
        "UDP stream action",
    }
)


def parse_opengfw_log(text: str) -> dict[str, Any]:
    """Parse OpenGFW JSON log lines into structured stream classifications & actions."""
    engine_started = False
    streams: dict[int, dict[str, Any]] = {}
    rule_hits: list[dict[str, Any]] = []
    actions: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    total_json_lines = 0

    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(entry, dict):
            continue
        total_json_lines += 1
        msg = entry.get("msg")
        level = entry.get("level")
        if msg == "engine started":
            engine_started = True
        if level in ("error", "fatal"):
            errors.append(entry)

        stream_id = entry.get("id")
        if msg in STREAM_LOG_MSGS and isinstance(stream_id, int):
            record = streams.setdefault(
                stream_id,
                {
                    "id": stream_id,
                    "proto": None,
                    "src": entry.get("src"),
                    "dst": entry.get("dst"),
                    "props": {},
                    "actions": [],
                    "matched_rules": [],
                },
            )
            if entry.get("src"):
                record["src"] = entry["src"]
            if entry.get("dst"):
                record["dst"] = entry["dst"]

            if msg == "new TCP stream":
                record["proto"] = "tcp"
            elif msg == "new UDP stream":
                record["proto"] = "udp"
            elif msg in ("TCP stream property update", "UDP stream property update"):
                record["proto"] = "tcp" if msg.startswith("TCP") else "udp"
                props = entry.get("props")
                if isinstance(props, dict):
                    for an_name, an_val in props.items():
                        if isinstance(an_val, dict) and an_val:
                            existing = record["props"].setdefault(an_name, {})
                            _deep_merge(existing, an_val)
            elif msg == "ruleset log":
                rule_name = str(entry.get("name", ""))
                props = entry.get("props")
                if isinstance(props, dict):
                    for an_name, an_val in props.items():
                        if isinstance(an_val, dict) and an_val:
                            existing = record["props"].setdefault(an_name, {})
                            _deep_merge(existing, an_val)
                if rule_name and rule_name not in record["matched_rules"]:
                    record["matched_rules"].append(rule_name)
                rule_hits.append(
                    {
                        "id": stream_id,
                        "name": rule_name,
                        "src": entry.get("src"),
                        "dst": entry.get("dst"),
                        "props": props if isinstance(props, dict) else {},
                    }
                )
            elif msg in ("TCP stream action", "UDP stream action"):
                record["proto"] = "tcp" if msg.startswith("TCP") else "udp"
                act = {
                    "id": stream_id,
                    "proto": record["proto"],
                    "src": entry.get("src"),
                    "dst": entry.get("dst"),
                    "action": entry.get("action"),
                    "noMatch": bool(entry.get("noMatch", False)),
                }
                record["actions"].append(act)
                actions.append(act)

    matched_analyzers: dict[str, list[dict[str, Any]]] = {}
    for record in streams.values():
        for an_name, an_props in record["props"].items():
            matched_analyzers.setdefault(an_name, []).append(an_props)

    blocked = any(
        act.get("action") in ("block", "drop") and not act.get("noMatch")
        for act in actions
    )
    allowed_explicit = any(
        act.get("action") == "allow" and not act.get("noMatch") for act in actions
    )

    return {
        "engine_started": engine_started,
        "total_json_lines": total_json_lines,
        "stream_count": len(streams),
        "streams": list(streams.values()),
        "matched_analyzers": sorted(matched_analyzers.keys()),
        "analyzer_props": matched_analyzers,
        "rule_hits": rule_hits,
        "actions": actions,
        "blocked_by_opengfw": blocked,
        "explicitly_allowed": allowed_explicit,
        "errors": errors,
    }


def _escape_printable(value: str) -> str:
    out: list[str] = []
    for ch in value:
        code = ord(ch)
        if 0x20 <= code <= 0x7E:
            out.append(ch)
        else:
            out.append(f"\\x{code:02x}")
    return "".join(out)


def summarize_classification(parsed: dict[str, Any]) -> str:
    """Build a concise human-readable summary of how OpenGFW classified a carrier."""
    if not parsed.get("streams"):
        return "no streams observed"
    parts: list[str] = []
    props_by_an: dict[str, list[dict[str, Any]]] = parsed.get("analyzer_props", {})

    if "tls" in props_by_an:
        tls_items = props_by_an["tls"]
        snis = sorted(
            {
                str(item.get("req", {}).get("sni"))
                for item in tls_items
                if isinstance(item.get("req"), dict) and item["req"].get("sni")
            }
        )
        alpns = sorted(
            {
                ",".join(_escape_printable(str(a)) for a in item.get("req", {}).get("alpn", []))
                for item in tls_items
                if isinstance(item.get("req"), dict) and item["req"].get("alpn")
            }
        )
        sni_label = ",".join(snis) if snis else "none"
        alpn_label = f", alpn={','.join(alpns)}" if alpns else ""
        parts.append(f"tls(sni={sni_label}{alpn_label})")

    if "fet" in props_by_an:
        fet_items = props_by_an["fet"]
        yes_any = any(bool(item.get("yes")) for item in fet_items)
        ex5_any = any(bool(item.get("ex5")) for item in fet_items)
        ex1_vals = [item.get("ex1") for item in fet_items if isinstance(item.get("ex1"), (int, float))]
        ex1_str = f", ex1={ex1_vals[0]:.2f}" if ex1_vals else ""
        parts.append(f"fet(yes={yes_any}, ex5={ex5_any}{ex1_str})")

    if "quic" in props_by_an:
        q_items = props_by_an["quic"]
        snis = sorted(
            {
                str(item.get("req", {}).get("sni"))
                for item in q_items
                if isinstance(item.get("req"), dict) and item["req"].get("sni")
            }
        )
        alpns = sorted(
            {
                ",".join(_escape_printable(str(a)) for a in item.get("req", {}).get("alpn", []))
                for item in q_items
                if isinstance(item.get("req"), dict) and item["req"].get("alpn")
            }
        )
        sni_label = ",".join(snis) if snis else "none"
        alpn_label = f", alpn={','.join(alpns)}" if alpns else ""
        parts.append(f"quic(sni={sni_label}{alpn_label})")

    if "openvpn" in props_by_an:
        o_items = props_by_an["openvpn"]
        max_tx = max((int(item.get("tx_pkt_cnt", 0)) for item in o_items), default=0)
        max_rx = max((int(item.get("rx_pkt_cnt", 0)) for item in o_items), default=0)
        parts.append(f"openvpn(tx={max_tx}, rx={max_rx})")

    if "wireguard" in props_by_an:
        wg_types = sorted({str(item.get("message_type")) for item in props_by_an["wireguard"]})
        parts.append(f"wireguard(types={','.join(wg_types)})")

    if "trojan" in props_by_an:
        t_items = props_by_an["trojan"]
        yes_any = any(bool(item.get("yes")) for item in t_items)
        seqs = [item.get("seq") for item in t_items if isinstance(item.get("seq"), list)]
        seq_str = f", seq={seqs[0]}" if seqs else ""
        parts.append(f"trojan(yes={yes_any}{seq_str})")

    for other in ("http", "socks", "ssh", "dns"):
        if other in props_by_an:
            parts.append(other)

    if not parts:
        protos = sorted({s.get("proto") or "?" for s in parsed.get("streams", [])})
        return f"unclassified ({'/'.join(protos)})"
    return "; ".join(parts)


def plan_document(
    *,
    carriers: list[CarrierCase],
    rulesets: list[RulesetSpec],
    lab_prefix: str,
    opengfw_bin: Path,
    daemon_bin: Path,
    ctl_bin: Path,
    output_dir: Path | None,
) -> dict[str, Any]:
    return {
        "mode": "dry-run",
        "opengfw": {
            "repo": OPENGFW_REPO,
            "commit": OPENGFW_COMMIT,
            "binary": str(opengfw_bin),
            "binary_exists": opengfw_bin.is_file(),
            "config_yaml": render_opengfw_config_yaml(),
        },
        "binaries": {
            "l2tunneld": str(daemon_bin),
            "l2tunneld_exists": daemon_bin.is_file(),
            "l2tunnelctl": str(ctl_bin),
            "l2tunnelctl_exists": ctl_bin.is_file(),
        },
        "topology": {
            "lab_prefix": validate_lab_prefix(lab_prefix),
            "client_wan": f"{CLIENT_WAN_IP}/30",
            "server_wan": f"{SERVER_WAN_IP}/30",
            "tun_client": f"{TUN_CLIENT_IP}/30",
            "tun_server": f"{TUN_SERVER_IP}/30",
            "router_opengfw_hook": "FORWARD (NFQUEUE 100, rst=true, inside isolated router netns only)",
            "host_changes": "none",
        },
        "carriers": [
            {
                "id": c.id,
                "carrier": c.carrier,
                "sni": c.sni,
                "description": c.description,
            }
            for c in carriers
        ],
        "rulesets": [
            {
                "id": r.id,
                "description": r.description,
                "rule_count": len(r.rules),
            }
            for r in rulesets
        ],
        "total_cells": len(carriers) * len(rulesets),
        "output_dir": str(output_dir) if output_dir else None,
    }


def find_go_binary() -> str:
    candidates = [
        shutil.which("go"),
        "/home/mana/.g/go/bin/go",
        "/usr/local/go/bin/go",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    raise RuntimeError("go toolchain not found in PATH or standard locations")


def build_opengfw(cache_dir: Path = DEFAULT_CACHE_DIR, binary_path: Path | None = None) -> dict[str, Any]:
    """Clone (if absent) and compile pinned HyNetworks/OpenGFW into cache_dir."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    repo_dir = cache_dir / "OpenGFW"
    out_bin = binary_path or (cache_dir / "opengfw")
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    if not (repo_dir / ".git").exists():
        subprocess.run(
            ["git", "clone", OPENGFW_REPO, str(repo_dir)],
            check=True,
            env=env,
        )
    subprocess.run(
        ["git", "-C", str(repo_dir), "checkout", "--detach", OPENGFW_COMMIT],
        check=True,
        env=env,
    )
    head = subprocess.check_output(
        ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    if head != OPENGFW_COMMIT:
        raise RuntimeError(f"OpenGFW commit mismatch: got {head}, expected {OPENGFW_COMMIT}")
    go_bin = find_go_binary()
    go_env = {**env, "PATH": f"{Path(go_bin).parent}:{env.get('PATH', '')}"}
    subprocess.run(
        [go_bin, "build", "-o", str(out_bin), "."],
        cwd=repo_dir,
        check=True,
        env=go_env,
    )
    digest = hashlib.sha256(out_bin.read_bytes()).hexdigest()
    return {
        "repo": OPENGFW_REPO,
        "commit": head,
        "binary": str(out_bin),
        "sha256": digest,
    }


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_cmd(argv: list[str], *, timeout: float = 30.0) -> str:
    res = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if res.returncode != 0:
        raise RuntimeError(
            f"command failed ({res.returncode}): {argv!r}\nstdout: {res.stdout}\nstderr: {res.stderr}"
        )
    return res.stdout


def stop_process(proc: subprocess.Popen[Any], timeout: float = 5.0) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=timeout)


def wait_for_text(proc: subprocess.Popen[Any], log_path: Path, needle: str, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if log_path.exists():
            text = log_path.read_text(errors="replace")
            if needle in text:
                return True
        if proc.poll() is not None:
            return False
        time.sleep(0.05)
    return False


def options_to_argv(options: dict[str, str]) -> list[str]:
    argv: list[str] = []
    for key, val in options.items():
        argv.extend([key, str(val)])
    return argv


CARRIER_OVERHEAD_BYTES = {
    "quic-like": 49,
    "media-like": 49,
    "tls-like": 49,
    "openvpn-like": 50,
    "raw-packet": 66,
    "tcp": 91,
    "quic": 196,
}


def tune_common_plan_for_carrier(
    plan_path: Path,
    carrier: str,
    *,
    ctl_bin: Path,
    device_mtu: int = 1500,
    path_mtu: int = 1500,
) -> None:
    """Tune common-plan.json to exact carrier overhead (and attach openvpn_wire_common when needed)."""
    overhead = CARRIER_OVERHEAD_BYTES[carrier]
    tmp_out = plan_path.with_suffix(".tuned.json")
    run_cmd(
        [
            str(ctl_bin),
            "plan",
            "tune",
            "--input",
            str(plan_path),
            "--output",
            str(tmp_out),
            "--device-mtu",
            str(device_mtu),
            "--path-mtu",
            str(path_mtu),
            "--repair",
            "off",
            "--overhead-bytes",
            str(overhead),
            "--force",
        ],
        timeout=15.0,
    )
    if carrier == "openvpn-like":
        doc = json.loads(tmp_out.read_text())
        doc["outer_carrier"] = {
            "version": 1,
            "backend": "openvpn_wire_common",
            "max_record_bytes": path_mtu - 29,
            "control_arq": doc["runtime"]["control"]["recovery"],
            "handshake_timeout_micros": 10_000_000,
            "lifetime_micros": 600_000_000,
            "packet_slots": 64,
            "stream_bytes": 131_072,
            "poll_interval_micros": 1000,
            "work_limit": 64,
            "wire_budget": {
                "interval_micros": 1000,
                "packets": 512,
                "ip_bytes": 768_000,
                "reserved_control_packets": 16,
                "reserved_control_bytes": 16_384,
                "maximum_control_packets": 128,
            },
        }
        plan_path.write_text(json.dumps(doc, indent=2) + "\n")
        tmp_out.unlink(missing_ok=True)
    else:
        tmp_out.replace(plan_path)


def generate_carrier_bundle(
    case: CarrierCase,
    bundle_dir: Path,
    *,
    ctl_bin: Path,
) -> dict[str, Any]:
    """Generate ephemeral server/client configs & credentials for a carrier case."""
    bundle_dir.mkdir(parents=True, exist_ok=True)
    if case.carrier == "raw-packet":
        return _generate_raw_packet_bundle(case, bundle_dir, ctl_bin=ctl_bin)

    argv = [
        str(ctl_bin),
        "wizard",
        "init",
        "--name",
        case.id.replace("_", "-"),
        "--carrier",
        case.carrier,
        "--server",
        f"{SERVER_WAN_IP}:{SERVER_PORT}",
        "--server-bind",
        f"{SERVER_WAN_IP}:{SERVER_PORT}",
        "--layer",
        "tun",
        "--offline",
        "--output",
        str(bundle_dir),
    ]
    if case.carrier in ("tcp", "quic"):
        argv.extend(["--client-bind", f"{CLIENT_WAN_IP}:{SERVER_PORT + 1}"])
    if case.sni:
        argv.extend(["--look-like", case.sni])
    run_cmd(argv, timeout=30.0)

    for sub in ("server", "client"):
        tune_common_plan_for_carrier(bundle_dir / sub / "common-plan.json", case.carrier, ctl_bin=ctl_bin)

    server_profile = json.loads((bundle_dir / "server" / "profile.json").read_text())
    client_profile = json.loads((bundle_dir / "client" / "profile.json").read_text())

    srv_opts: dict[str, str] = dict(server_profile["options"])
    cli_opts: dict[str, str] = dict(client_profile["options"])
    srv_opts["--device"] = "tun0"
    cli_opts["--device"] = "tun0"

    if case.carrier in ("quic-like", "media-like", "tls-like", "openvpn-like"):
        # Pin exact local client bind in isolated namespace for deterministic flow correlation.
        cli_opts["--udp-bind"] = f"{CLIENT_WAN_IP}:{SERVER_PORT}"
        srv_opts["--udp-peer"] = f"{CLIENT_WAN_IP}:{SERVER_PORT}"

    if case.strip_sni:
        cli_opts.pop("--sni", None)
    elif case.sni and case.carrier in ("tcp", "openvpn-like"):
        cli_opts["--sni"] = case.sni

    return {
        "server_argv": ["serve", *options_to_argv(srv_opts)],
        "client_argv": ["connect", *options_to_argv(cli_opts)],
        "needs_raw_rst_drop": False,
        "expected_proto": "tcp" if case.carrier == "tcp" else "udp",
    }


def _generate_raw_packet_bundle(
    case: CarrierCase,
    bundle_dir: Path,
    *,
    ctl_bin: Path,
) -> dict[str, Any]:
    """Provision raw-packet on --record-profile common using wizard credentials + raw-common-carrier-v1."""
    argv = [
        str(ctl_bin),
        "wizard",
        "init",
        "--name",
        case.id.replace("_", "-"),
        "--carrier",
        "tcp",
        "--server",
        f"{SERVER_WAN_IP}:{RAW_SERVER_PORT}",
        "--server-bind",
        f"{SERVER_WAN_IP}:{RAW_SERVER_PORT}",
        "--client-bind",
        f"{CLIENT_WAN_IP}:{RAW_CLIENT_PORT}",
        "--layer",
        "tun",
        "--offline",
        "--output",
        str(bundle_dir),
    ]
    if case.sni:
        argv.extend(["--look-like", case.sni])
    run_cmd(argv, timeout=30.0)

    for sub in ("server", "client"):
        tune_common_plan_for_carrier(bundle_dir / sub / "common-plan.json", "raw-packet", ctl_bin=ctl_bin)

    server_profile = json.loads((bundle_dir / "server" / "profile.json").read_text())
    client_profile = json.loads((bundle_dir / "client" / "profile.json").read_text())
    srv_opts: dict[str, str] = dict(server_profile["options"])
    cli_opts: dict[str, str] = dict(client_profile["options"])

    for side, opts in (("a", cli_opts), ("b", srv_opts)):
        local_ep = f"{CLIENT_WAN_IP}:{RAW_CLIENT_PORT}" if side == "a" else f"{SERVER_WAN_IP}:{RAW_SERVER_PORT}"
        peer_ep = f"{SERVER_WAN_IP}:{RAW_SERVER_PORT}" if side == "a" else f"{CLIENT_WAN_IP}:{RAW_CLIENT_PORT}"
        pol = {
            "version": 1,
            "profile": "raw-common-carrier-v1",
            "forward": {"local": local_ep, "peer": peer_ep},
            "reverse": None,
            "packet": {
                "mtu": 1500,
                "protection": case.raw_suite,
                "queue_packets": 8,
                "horizon_bytes": 32768,
                "minimum_transfer_bytes": 65536,
                "bytes_per_second": 1048576,
                "packets_per_second": 2048,
                "burst_bytes": 16384,
                "burst_packets": 32,
                "max_key_packets": 1048576,
                "max_key_bytes": 1073741824,
            },
        }
        pol_path = bundle_dir / f"raw-policy-{side}.json"
        pol_path.write_text(json.dumps(pol, indent=2) + "\n")
        opts.pop("--maintained-policy", None)
        opts["--carrier"] = "raw-packet"
        opts["--device"] = "tun0"
        opts["--raw-mark"] = str(RAW_SOCKET_MARK)
        opts["--raw-policy"] = str(pol_path)

    if case.sni:
        cli_opts["--sni"] = case.sni
    else:
        cli_opts.pop("--sni", None)

    return {
        "server_argv": ["serve", *options_to_argv(srv_opts)],
        "client_argv": ["connect", *options_to_argv(cli_opts)],
        "needs_raw_rst_drop": True,
        "expected_proto": "tcp",
    }


def _tcp_probe_script() -> str:
    return (
        "import hashlib, json, socket, sys\n"
        "role, host, port, nbytes = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])\n"
        "data = bytes((i * 31 + 7) & 0xff for i in range(nbytes))\n"
        "expected = hashlib.sha256(data).hexdigest()\n"
        "if role == 'listen':\n"
        "    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        "    s.settimeout(12)\n"
        "    s.bind((host, port))\n"
        "    s.listen(1)\n"
        "    print('LISTENING', flush=True)\n"
        "    conn, _ = s.accept()\n"
        "    conn.settimeout(12)\n"
        "    buf = bytearray()\n"
        "    while len(buf) < nbytes:\n"
        "        chunk = conn.recv(min(16384, nbytes - len(buf)))\n"
        "        if not chunk: break\n"
        "        buf.extend(chunk)\n"
        "    got = hashlib.sha256(buf).hexdigest()\n"
        "    conn.sendall(b'OK' if (len(buf) == nbytes and got == expected) else b'BAD')\n"
        "    conn.close(); s.close()\n"
        "    print(json.dumps({'bytes': len(buf), 'ok': len(buf) == nbytes and got == expected}), flush=True)\n"
        "    sys.exit(0 if (len(buf) == nbytes and got == expected) else 1)\n"
        "else:\n"
        "    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "    c.settimeout(12)\n"
        "    c.connect((host, port))\n"
        "    c.sendall(data)\n"
        "    ack = c.recv(8)\n"
        "    c.close()\n"
        "    ok = ack == b'OK'\n"
        "    print(json.dumps({'bytes': len(data), 'ok': ok}), flush=True)\n"
        "    sys.exit(0 if ok else 1)\n"
    )


def install_raw_endpoint_rst_drop(ns: dict[str, str]) -> None:
    """Install exact isolated endpoint OUTPUT RST-drop rules for raw-packet carrier only."""
    for side, local_ip, peer_ip, sport, dport in (
        ("a", CLIENT_WAN_IP, SERVER_WAN_IP, RAW_CLIENT_PORT, RAW_SERVER_PORT),
        ("b", SERVER_WAN_IP, CLIENT_WAN_IP, RAW_SERVER_PORT, RAW_CLIENT_PORT),
    ):
        run_cmd(
            [
                "ip",
                "netns",
                "exec",
                ns[f"endpoint_{side}"],
                "iptables",
                "-I",
                "OUTPUT",
                "1",
                "-p",
                "tcp",
                "-s",
                local_ip,
                "--sport",
                str(sport),
                "-d",
                peer_ip,
                "--dport",
                str(dport),
                "--tcp-flags",
                "RST",
                "RST",
                "-m",
                "mark",
                "!",
                "--mark",
                hex(RAW_SOCKET_MARK),
                "-j",
                "DROP",
            ]
        )


def run_single_cell(
    *,
    case: CarrierCase,
    ruleset: RulesetSpec,
    lab_id: str,
    cell_dir: Path,
    bundle: dict[str, Any],
    opengfw_bin: Path,
    daemon_bin: Path,
    state_dir: Path,
    handshake_timeout: float = 8.0,
) -> dict[str, Any]:
    cell_dir.mkdir(parents=True, exist_ok=True)
    spec = netns_lab.LabSpec(lab_id, loss_percent=0)
    ns = spec.namespaces

    cfg_path = cell_dir / "opengfw-config.yaml"
    rules_path = cell_dir / "opengfw-rules.yaml"
    cfg_path.write_text(render_opengfw_config_yaml(rst=True, workers=2))
    rules_path.write_text(render_ruleset_yaml(ruleset))

    ogfw_log = cell_dir / "opengfw.jsonl"
    srv_log = cell_dir / "server.log"
    cli_log = cell_dir / "client.log"
    probe_script = cell_dir / "tcp_probe.py"
    probe_script.write_text(_tcp_probe_script())

    processes: list[subprocess.Popen[Any]] = []
    handles: list[Any] = []
    created = False
    started = time.monotonic()

    ping_ok = False
    ping_received = 0
    ping_stdout = ""
    tcp_ok = False
    tcp_bytes = 0
    tcp_error = ""
    nft_counters = ""
    cell_error = ""

    try:
        netns_lab.apply(spec, state_dir)
        created = True

        # Clean 2 ms RTT, 0% loss so every drop/block comes exclusively from OpenGFW.
        for side, tun_ip in (("a", f"{TUN_CLIENT_IP}/30"), ("b", f"{TUN_SERVER_IP}/30")):
            ep = ns[f"endpoint_{side}"]
            run_cmd(
                [
                    "ip",
                    "netns",
                    "exec",
                    ep,
                    "tc",
                    "qdisc",
                    "change",
                    "dev",
                    "wan0",
                    "parent",
                    "1:10",
                    "handle",
                    "10:",
                    "netem",
                    "limit",
                    "1000",
                    "delay",
                    "1ms",
                    "loss",
                    "random",
                    "0%",
                ]
            )
            run_cmd(["ip", "-n", ep, "tuntap", "add", "dev", "tun0", "mode", "tun"])
            run_cmd(["ip", "-n", ep, "link", "set", "tun0", "mtu", "1500", "up"])
            run_cmd(["ip", "-n", ep, "address", "add", tun_ip, "dev", "tun0"])

        if bundle["needs_raw_rst_drop"]:
            install_raw_endpoint_rst_drop(ns)

        # Start OpenGFW inside isolated router namespace.
        ogfw_fh = ogfw_log.open("w")
        handles.append(ogfw_fh)
        ogfw_proc = subprocess.Popen(
            [
                "ip",
                "netns",
                "exec",
                ns["router"],
                str(opengfw_bin),
                "-c",
                str(cfg_path),
                "-l",
                "debug",
                "-f",
                "json",
                str(rules_path),
            ],
            stdout=ogfw_fh,
            stderr=subprocess.STDOUT,
        )
        processes.append(ogfw_proc)
        if not wait_for_text(ogfw_proc, ogfw_log, "engine started", timeout=10.0):
            raise RuntimeError(f"OpenGFW failed to start:\n{ogfw_log.read_text(errors='replace')}")

        # Verify OpenGFW installed its FORWARD nft table strictly inside router netns.
        nft_deadline = time.monotonic() + 5.0
        nft_ready = False
        while time.monotonic() < nft_deadline:
            chk = subprocess.run(
                ["ip", "netns", "exec", ns["router"], "nft", "list", "table", "inet", "opengfw"],
                capture_output=True,
                text=True,
                timeout=3.0,
            )
            if chk.returncode == 0:
                nft_ready = True
                break
            if ogfw_proc.poll() is not None:
                break
            time.sleep(0.05)
        if not nft_ready:
            raise RuntimeError(
                f"OpenGFW did not install inet opengfw table inside router netns:\n"
                f"{ogfw_log.read_text(errors='replace')}"
            )

        # Launch server and client inside endpoint_b and endpoint_a.
        srv_fh = srv_log.open("w")
        handles.append(srv_fh)
        srv_proc = subprocess.Popen(
            ["ip", "netns", "exec", ns["endpoint_b"], str(daemon_bin), *bundle["server_argv"]],
            stdout=srv_fh,
            stderr=subprocess.STDOUT,
        )
        processes.append(srv_proc)
        time.sleep(0.35)

        cli_fh = cli_log.open("w")
        handles.append(cli_fh)
        cli_proc = subprocess.Popen(
            ["ip", "netns", "exec", ns["endpoint_a"], str(daemon_bin), *bundle["client_argv"]],
            stdout=cli_fh,
            stderr=subprocess.STDOUT,
        )
        processes.append(cli_proc)

        # Probe TUN ICMP connectivity until the tunnel becomes active or handshake_timeout expires.
        probe_deadline = time.monotonic() + handshake_timeout
        while time.monotonic() < probe_deadline:
            if cli_proc.poll() is not None and srv_proc.poll() is not None:
                break
            res = subprocess.run(
                [
                    "ip",
                    "netns",
                    "exec",
                    ns["endpoint_a"],
                    "ping",
                    "-n",
                    "-c",
                    "1",
                    "-W",
                    "1",
                    TUN_SERVER_IP,
                ],
                capture_output=True,
                text=True,
                timeout=3.0,
            )
            if res.returncode == 0:
                break
            time.sleep(0.15)

        # Now run the formal 5-packet ICMP check over TUN.
        ping_res = subprocess.run(
            [
                "ip",
                "netns",
                "exec",
                ns["endpoint_a"],
                "ping",
                "-n",
                "-c",
                "5",
                "-i",
                "0.1",
                "-W",
                "1",
                TUN_SERVER_IP,
            ],
            capture_output=True,
            text=True,
            timeout=10.0,
        )
        ping_stdout = ping_res.stdout + ping_res.stderr
        m_rx = re.search(r"(\d+)\s+received", ping_stdout)
        ping_received = int(m_rx.group(1)) if m_rx else 0
        ping_ok = ping_res.returncode == 0 and ping_received == 5

        # If ICMP succeeded, also verify 64 KiB TCP payload transfer through the tunnel.
        if ping_ok:
            srv_probe_log = cell_dir / "tcp-probe-server.log"
            sp_fh = srv_probe_log.open("w")
            handles.append(sp_fh)
            sp = subprocess.Popen(
                [
                    "ip",
                    "netns",
                    "exec",
                    ns["endpoint_b"],
                    sys.executable,
                    str(probe_script),
                    "listen",
                    TUN_SERVER_IP,
                    str(TCP_PROBE_PORT),
                    str(TCP_PROBE_BYTES),
                ],
                stdout=sp_fh,
                stderr=subprocess.STDOUT,
            )
            processes.append(sp)
            if wait_for_text(sp, srv_probe_log, "LISTENING", timeout=5.0):
                cp = subprocess.run(
                    [
                        "ip",
                        "netns",
                        "exec",
                        ns["endpoint_a"],
                        sys.executable,
                        str(probe_script),
                        "send",
                        TUN_SERVER_IP,
                        str(TCP_PROBE_PORT),
                        str(TCP_PROBE_BYTES),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=15.0,
                )
                try:
                    sp.wait(timeout=5.0)
                except subprocess.TimeoutExpired:
                    stop_process(sp)
                if cp.returncode == 0 and sp.returncode == 0:
                    payload_res = json.loads(cp.stdout.strip().splitlines()[-1])
                    tcp_ok = bool(payload_res.get("ok"))
                    tcp_bytes = int(payload_res.get("bytes", 0))
                else:
                    tcp_error = f"client_rc={cp.returncode} server_rc={sp.returncode} {cp.stderr.strip()}"
            else:
                tcp_error = "TCP probe listener failed to bind"

        # Capture nftables packet/byte counters inside router netns before stopping OpenGFW.
        nft_res = subprocess.run(
            ["ip", "netns", "exec", ns["router"], "nft", "list", "table", "inet", "opengfw"],
            capture_output=True,
            text=True,
            timeout=5.0,
        )
        nft_counters = nft_res.stdout

    except Exception as exc:
        cell_error = str(exc)
    finally:
        for proc in reversed(processes):
            stop_process(proc)
        for fh in handles:
            try:
                fh.close()
            except Exception:
                pass
        if created:
            netns_lab.cleanup(spec, state_dir)

    parsed_ogfw = parse_opengfw_log(ogfw_log.read_text(errors="replace") if ogfw_log.exists() else "")
    survived = ping_ok and tcp_ok and not cell_error
    if survived:
        verdict = "SURVIVED"
    elif parsed_ogfw["blocked_by_opengfw"]:
        verdict = "BLOCKED"
    else:
        verdict = "FAILED"

    return {
        "carrier_id": case.id,
        "carrier": case.carrier,
        "sni": case.sni,
        "ruleset_id": ruleset.id,
        "lab_id": lab_id,
        "verdict": verdict,
        "survived": survived,
        "ping_ok": ping_ok,
        "ping_received": ping_received,
        "tcp_ok": tcp_ok,
        "tcp_bytes": tcp_bytes,
        "tcp_error": tcp_error,
        "cell_error": cell_error,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "opengfw_summary": summarize_classification(parsed_ogfw),
        "opengfw": parsed_ogfw,
        "nft_counters": nft_counters,
    }


def render_markdown_report(receipt: dict[str, Any]) -> str:
    """Render a concise Markdown report with classification table and survival matrix."""
    carriers = receipt["carriers"]
    rulesets = receipt["rulesets"]
    cells: list[dict[str, Any]] = receipt["cells"]
    by_key = {(c["carrier_id"], c["ruleset_id"]): c for c in cells}

    lines = [
        "# OpenGFW Carrier Classification & Survival Results",
        "",
        f"- **OpenGFW commit:** `{receipt['opengfw']['commit']}` (`{receipt['opengfw']['repo']}`)",
        f"- **OpenGFW binary SHA-256:** `{receipt['opengfw'].get('sha256', 'unknown')}`",
        f"- **l2tunneld SHA-256:** `{receipt['binaries'].get('l2tunneld_sha256', 'unknown')}`",
        f"- **Topology:** Isolated Linux netns (`192.0.2.2` <-> OpenGFW router `FORWARD` NFQUEUE 100 `rst=true` <-> `192.0.2.6`, 2 ms RTT, 0% loss)",
        f"- **Total cells executed:** {len(cells)}",
        "",
        "## 1. What Each Carrier Looks Like in OpenGFW (`observe-all`)",
        "",
        "| Carrier Profile | Outer Proto | Matched Analyzers | OpenGFW Classification Details | Observe-All Survival |",
        "| --- | --- | --- | --- | --- |",
    ]
    for c in carriers:
        cell = by_key.get((c["id"], "observe-all"))
        if not cell:
            continue
        protos = sorted({s.get("proto") or "?" for s in cell["opengfw"].get("streams", [])})
        proto_str = "/".join(protos) if protos else "none"
        ans = ", ".join(cell["opengfw"].get("matched_analyzers", [])) or "(none)"
        lines.append(
            f"| `{c['id']}` | `{proto_str}` | `{ans}` | {cell['opengfw_summary']} | **{cell['verdict']}** ({cell['ping_received']}/5 ping, {cell['tcp_bytes']} B TCP) |"
        )

    lines.extend(
        [
            "",
            "## 2. Survival Matrix (Carrier x OpenGFW Ruleset)",
            "",
        ]
    )
    header = "| Carrier Profile | " + " | ".join(f"`{r['id']}`" for r in rulesets) + " | Survival Rate |"
    sep = "| --- | " + " | ".join("---" for _ in rulesets) + " | --- |"
    lines.extend([header, sep])

    active_rulesets = [r["id"] for r in rulesets if r["id"] != "observe-all"]
    for c in carriers:
        row = [f"`{c['id']}`"]
        active_pass = 0
        for r in rulesets:
            cell = by_key.get((c["id"], r["id"]))
            if not cell:
                row.append("-")
                continue
            v = cell["verdict"]
            badge = "PASS" if v == "SURVIVED" else v
            row.append(f"**{badge}**" if v == "SURVIVED" else badge)
            if r["id"] in active_rulesets and v == "SURVIVED":
                active_pass += 1
        denom = len(active_rulesets) if active_rulesets else len(rulesets)
        num = active_pass if active_rulesets else sum(
            1 for r in rulesets if by_key.get((c["id"], r["id"]), {}).get("survived")
        )
        row.append(f"{num}/{denom} ({100.0 * num / denom:.0f}%)" if denom else "-")
        lines.append("| " + " | ".join(row) + " |")

    lines.extend(
        [
            "",
            "## 3. Ruleset Survival Summary",
            "",
            "| Ruleset | Description | Survived | Blocked | Failed |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for r in rulesets:
        rcells = [by_key[(c["id"], r["id"])] for c in carriers if (c["id"], r["id"]) in by_key]
        n_pass = sum(1 for x in rcells if x["verdict"] == "SURVIVED")
        n_blk = sum(1 for x in rcells if x["verdict"] == "BLOCKED")
        n_fail = sum(1 for x in rcells if x["verdict"] == "FAILED")
        lines.append(
            f"| `{r['id']}` | {r['description']} | {n_pass}/{len(rcells)} | {n_blk} | {n_fail} |"
        )

    lines.append("")
    return "\n".join(lines)


def run_matrix(
    *,
    carriers: list[CarrierCase],
    rulesets: list[RulesetSpec],
    lab_prefix: str,
    opengfw_bin: Path,
    daemon_bin: Path,
    ctl_bin: Path,
    output_dir: Path,
    state_dir: Path,
    handshake_timeout: float,
) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise PermissionError("running the isolated netns OpenGFW matrix requires root (use sudo)")
    for label, path in (
        ("OpenGFW binary", opengfw_bin),
        ("l2tunneld binary", daemon_bin),
        ("l2tunnelctl binary", ctl_bin),
    ):
        if not path.is_file():
            raise FileNotFoundError(f"missing {label}: {path}")

    output_dir.mkdir(parents=True, exist_ok=True)
    bundles_dir = output_dir / "bundles"
    cells_dir = output_dir / "cells"
    bundles_dir.mkdir(exist_ok=True)
    cells_dir.mkdir(exist_ok=True)

    bundles: dict[str, dict[str, Any]] = {}
    for case in carriers:
        print(f"[setup] provisioning carrier bundle: {case.id}", flush=True)
        bundles[case.id] = generate_carrier_bundle(case, bundles_dir / case.id, ctl_bin=ctl_bin)

    results: list[dict[str, Any]] = []
    idx = 0
    total = len(carriers) * len(rulesets)
    for case in carriers:
        for ruleset in rulesets:
            idx += 1
            lab_id = cell_lab_id(lab_prefix, idx)
            cell_dir = cells_dir / f"{case.id}__{ruleset.id}"
            print(
                f"[{idx:02d}/{total:02d}] {case.id} x {ruleset.id} (lab={lab_id})...",
                end=" ",
                flush=True,
            )
            res = run_single_cell(
                case=case,
                ruleset=ruleset,
                lab_id=lab_id,
                cell_dir=cell_dir,
                bundle=bundles[case.id],
                opengfw_bin=opengfw_bin,
                daemon_bin=daemon_bin,
                state_dir=state_dir,
                handshake_timeout=handshake_timeout,
            )
            results.append(res)
            print(
                f"{res['verdict']} ({res['elapsed_seconds']}s) | {res['opengfw_summary']}",
                flush=True,
            )

    receipt = {
        "schema_version": 1,
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "opengfw": {
            "repo": OPENGFW_REPO,
            "commit": OPENGFW_COMMIT,
            "binary": str(opengfw_bin),
            "sha256": file_sha256(opengfw_bin),
        },
        "binaries": {
            "l2tunneld": str(daemon_bin),
            "l2tunneld_sha256": file_sha256(daemon_bin),
            "l2tunnelctl": str(ctl_bin),
            "l2tunnelctl_sha256": file_sha256(ctl_bin),
        },
        "carriers": [
            {"id": c.id, "carrier": c.carrier, "sni": c.sni, "description": c.description}
            for c in carriers
        ],
        "rulesets": [
            {"id": r.id, "description": r.description, "rules": list(r.rules)} for r in rulesets
        ],
        "cells": results,
    }
    (output_dir / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    report_md = render_markdown_report(receipt)
    (output_dir / "RESULTS.md").write_text(report_md)
    print(f"\nSaved receipt: {output_dir / 'receipt.json'}", flush=True)
    print(f"Saved report:  {output_dir / 'RESULTS.md'}", flush=True)
    return receipt


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Embedded OpenGFW carrier inspection & survival lab (dry-run by default)."
    )
    p.add_argument(
        "--build-opengfw",
        action="store_true",
        help="Clone/checkout pinned HyNetworks/OpenGFW and compile into target/opengfw-cache/opengfw.",
    )
    p.add_argument(
        "--run-matrix",
        action="store_true",
        help="Execute the isolated Linux netns OpenGFW matrix (requires root).",
    )
    p.add_argument(
        "--carriers",
        default=None,
        help="Comma-separated carrier profile IDs to include (default: all 10).",
    )
    p.add_argument(
        "--rulesets",
        default=None,
        help="Comma-separated OpenGFW ruleset IDs to include (default: all 8).",
    )
    p.add_argument(
        "--lab-prefix",
        default="ogfw",
        help="Short namespace lab prefix [a-z][a-z0-9-]{0,9} (default: ogfw).",
    )
    p.add_argument(
        "--opengfw-bin",
        type=Path,
        default=DEFAULT_OPENGFW_BIN,
        help=f"Path to compiled OpenGFW binary (default: {DEFAULT_OPENGFW_BIN}).",
    )
    p.add_argument(
        "--daemon-bin",
        type=Path,
        default=DEFAULT_DAEMON_BIN,
        help=f"Path to l2tunneld binary (default: {DEFAULT_DAEMON_BIN}).",
    )
    p.add_argument(
        "--ctl-bin",
        type=Path,
        default=DEFAULT_CTL_BIN,
        help=f"Path to l2tunnelctl binary (default: {DEFAULT_CTL_BIN}).",
    )
    p.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Output directory for receipt.json, RESULTS.md, and per-cell logs.",
    )
    p.add_argument(
        "--state-dir",
        type=Path,
        default=DEFAULT_STATE_DIR,
        help=f"Owned netns_lab journal directory (default: {DEFAULT_STATE_DIR}).",
    )
    p.add_argument(
        "--handshake-timeout",
        type=float,
        default=8.0,
        help="Max seconds to wait for tunnel ICMP readiness per cell (default: 8.0).",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Print plan or build result as JSON.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    carriers = select_items(args.carriers, CARRIER_CASES, CARRIER_BY_ID, "carrier")
    rulesets = select_items(args.rulesets, RULESET_SPECS, RULESET_BY_ID, "ruleset")
    validate_lab_prefix(args.lab_prefix)

    if args.build_opengfw:
        info = build_opengfw(cache_dir=args.opengfw_bin.parent, binary_path=args.opengfw_bin)
        if args.json:
            print(json.dumps(info, indent=2))
        else:
            print(f"Built OpenGFW {info['commit']} -> {info['binary']} (sha256={info['sha256']})")
        if not args.run_matrix:
            return 0

    if args.run_matrix:
        out = args.output_dir or (ROOT / "work" / time.strftime("opengfw-%Y%m%d-%H%M%S"))
        run_matrix(
            carriers=carriers,
            rulesets=rulesets,
            lab_prefix=args.lab_prefix,
            opengfw_bin=args.opengfw_bin,
            daemon_bin=args.daemon_bin,
            ctl_bin=args.ctl_bin,
            output_dir=out,
            state_dir=args.state_dir,
            handshake_timeout=args.handshake_timeout,
        )
        return 0

    doc = plan_document(
        carriers=carriers,
        rulesets=rulesets,
        lab_prefix=args.lab_prefix,
        opengfw_bin=args.opengfw_bin,
        daemon_bin=args.daemon_bin,
        ctl_bin=args.ctl_bin,
        output_dir=args.output_dir,
    )
    if args.json:
        print(json.dumps(doc, indent=2))
    else:
        print(f"OpenGFW lab dry-run plan ({doc['total_cells']} cells; pass --run-matrix with sudo to execute)")
        print(f"  OpenGFW:   {doc['opengfw']['binary']} (exists={doc['opengfw']['binary_exists']}, commit={OPENGFW_COMMIT[:12]})")
        print(f"  l2tunneld: {doc['binaries']['l2tunneld']} (exists={doc['binaries']['l2tunneld_exists']})")
        print(f"  Carriers ({len(carriers)}): {', '.join(c.id for c in carriers)}")
        print(f"  Rulesets ({len(rulesets)}): {', '.join(r.id for r in rulesets)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
