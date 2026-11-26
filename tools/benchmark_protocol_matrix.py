#!/usr/bin/env python3
"""Reproducible Linux isolated-netns speed & RTT benchmark matrix across ALL
runnable Common protocols/carriers AND Internal-MTU > Capsule-MTU profiles.

Runs inside an isolated `unshare --net --mount --fork --propagation private`
namespace pair (`ns-srv` <-> `ns-cli` over a veth pair) so host routes, bridges,
qdiscs, and firewalls are NEVER modified.

Protocols covered:
  1. quic-like    (UDP cover, Swift ARQ & FEC 1/8)
  2. media-like   (UDP cover, Swift ARQ)
  3. tls-like     (UDP cover, Swift ARQ)
  4. openvpn-like (Real OpenVPN UDP outer handshake + TLS, Swift ARQ)
  5. raw-packet   (TCP-to-raw with RST drop inside owned netns, Swift ARQ)
  6. tcp          (Maintained TLS 1.3 with named SNI, Swift ARQ)
  7. quic         (Genuine Quinn QUIC, Swift ARQ)

Internal MTU > Capsule MTU matrix (quic-like):
  - 1500 / 1500 (baseline)
  - 1500 / 1300 (Internal > Capsule)
  - 1500 / 1280 (Internal > Capsule)
  - 4096 / 1400 (Jumbo Internal > Capsule)
  - 9000 / 1400 (Jumbo Internal > Capsule)
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parent.parent
DAEMON = ROOT / "target/release/l2tunneld"
CTL = ROOT / "target/release/l2tunnelctl"
BASE_PLAN = ROOT / "clients/android/app/src/main/res/raw/default_common_plan.json"

SRV_OUTER = "198.18.10.1"
CLI_OUTER = "198.18.10.2"
SRV_TUN = "10.241.0.1"
CLI_TUN = "10.241.0.2"


def sh(*args: str, check: bool = True, timeout: float = 30.0) -> subprocess.CompletedProcess:
    res = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and res.returncode != 0:
        raise RuntimeError(f"cmd failed ({res.returncode}): {' '.join(args)}\nstderr={res.stderr}\nstdout={res.stdout}")
    return res


def ns_cmd(ns: str, *args: str) -> list[str]:
    return ["ip", "netns", "exec", ns, *args]


def ctl(sock: Path, *args: str) -> dict:
    res = subprocess.run(
        [str(CTL), *args, "--json", "--control-socket", str(sock)],
        capture_output=True,
        text=True,
        timeout=15.0,
    )
    lines = [ln for ln in res.stdout.strip().splitlines() if ln.strip()]
    if not lines:
        return {"ok": False, "stderr": res.stderr.strip()}
    try:
        return json.loads(lines[-1])
    except ValueError:
        return {"ok": False, "raw": lines[-1]}


def gen_tls_certs(sec: Path) -> None:
    sh(
        "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-nodes", "-keyout", str(sec / "server.key.pem"), "-out", str(sec / "server.crt.pem"),
        "-days", "1", "-subj", "/CN=l2tunnel.local",
        "-addext", "subjectAltName=DNS:l2tunnel.local",
        "-addext", "basicConstraints=critical,CA:FALSE",
    )
    # l2tunnel TLS/QUIC/OpenVPN/Raw readers require DER-encoded X.509 cert & PKCS#8 private key (mode 0600)
    sh("openssl", "x509", "-in", str(sec / "server.crt.pem"), "-outform", "DER", "-out", str(sec / "server.crt"))
    sh("openssl", "pkcs8", "-topk8", "-nocrypt", "-in", str(sec / "server.key.pem"), "-outform", "DER", "-out", str(sec / "server.key"))
    for p in sec.iterdir():
        os.chmod(p, 0o600)


def build_openvpn_plan(base_plan_path: Path, out_path: Path, path_mtu: int) -> None:
    doc = json.loads(base_plan_path.read_text())
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
    out_path.write_text(json.dumps(doc, indent=2) + "\n")


def setup_namespaces(loss_pct: float = 0.0, delay_ms: float = 0.0) -> None:
    for ns in ("bm-srv", "bm-cli"):
        subprocess.run(["ip", "netns", "del", ns], capture_output=True)
    sh("ip", "netns", "add", "bm-srv")
    sh("ip", "netns", "add", "bm-cli")
    sh("ip", "link", "add", "veth-srv", "type", "veth", "peer", "name", "veth-cli")
    sh("ip", "link", "set", "veth-srv", "netns", "bm-srv")
    sh("ip", "link", "set", "veth-cli", "netns", "bm-cli")
    for ns, dev, ip in [("bm-srv", "veth-srv", f"{SRV_OUTER}/24"), ("bm-cli", "veth-cli", f"{CLI_OUTER}/24")]:
        sh(*ns_cmd(ns, "ip", "link", "set", "lo", "up"))
        sh(*ns_cmd(ns, "ip", "addr", "add", ip, "dev", dev))
        sh(*ns_cmd(ns, "ip", "link", "set", dev, "mtu", "1500", "up"))
        if loss_pct > 0.0 or delay_ms > 0.0:
            qargs = ["tc", "qdisc", "replace", "dev", dev, "root", "netem"]
            if delay_ms > 0.0:
                qargs += ["delay", f"{delay_ms}ms"]
            if loss_pct > 0.0:
                qargs += ["loss", f"{loss_pct}%"]
            sh(*ns_cmd(ns, *qargs))


def setup_tuns(dev_mtu: int) -> None:
    for ns, dev, ip in [("bm-srv", "tun-srv", f"{SRV_TUN}/30"), ("bm-cli", "tun-cli", f"{CLI_TUN}/30")]:
        subprocess.run(ns_cmd(ns, "ip", "link", "del", dev), capture_output=True)
        sh(*ns_cmd(ns, "ip", "tuntap", "add", "dev", dev, "mode", "tun"))
        sh(*ns_cmd(ns, "ip", "addr", "add", ip, "dev", dev))
        sh(*ns_cmd(ns, "ip", "link", "set", dev, "mtu", str(dev_mtu), "txqueuelen", "1000", "up"))


def measure_ping(ns: str, target: str, count: int = 10, payload_size: int = 56, df: bool = False) -> dict:
    args = ns_cmd(ns, "ping", "-c", str(count), "-i", "0.05", "-W", "2", "-s", str(payload_size))
    if df:
        args += ["-M", "do"]
    args.append(target)
    res = subprocess.run(args, capture_output=True, text=True, timeout=15.0)
    out = res.stdout + "\n" + res.stderr
    loss_m = re.search(r"(\d+(?:\.\d+)?)% packet loss", out)
    rtt_m = re.search(r"min/avg/max/mdev = ([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+)", out)
    return {
        "ok": res.returncode == 0,
        "payload_bytes": payload_size,
        "df": df,
        "loss_pct": float(loss_m.group(1)) if loss_m else 100.0,
        "min_ms": float(rtt_m.group(1)) if rtt_m else None,
        "avg_ms": float(rtt_m.group(2)) if rtt_m else None,
        "max_ms": float(rtt_m.group(3)) if rtt_m else None,
    }


def measure_tcp_throughput(duration_s: float = 4.0, streams: int = 4, port: int = 19100) -> dict:
    """Real kernel-stack multi-stream TCP throughput across bm-cli -> bm-srv TUN."""
    srv_code = f"""
import socket, threading, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('{SRV_TUN}', {port}))
s.listen(32)
s.settimeout({duration_s + 6.0})
total = [0]
lock = threading.Lock()
def handle(c):
    buf = bytearray(262144)
    n_local = 0
    while True:
        try:
            n = c.recv_into(buf)
        except Exception:
            break
        if not n:
            break
        n_local += n
    c.close()
    with lock:
        total[0] += n_local
threads = []
deadline = time.monotonic() + {duration_s + 4.0}
while len(threads) < {streams} and time.monotonic() < deadline:
    try:
        c, _ = s.accept()
    except socket.timeout:
        break
    t = threading.Thread(target=handle, args=(c,), daemon=True)
    t.start()
    threads.append(t)
for t in threads:
    t.join(timeout={duration_s + 5.0})
s.close()
print(total[0], flush=True)
"""
    cli_code = f"""
import socket, threading, time
payload = b'A' * 131072
sent = [0]
lock = threading.Lock()
barrier = threading.Barrier({streams})
def worker():
    c = socket.create_connection(('{SRV_TUN}', {port}), timeout=5.0)
    c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    barrier.wait()
    end = time.monotonic() + {duration_s}
    n_local = 0
    while time.monotonic() < end:
        try:
            c.sendall(payload)
            n_local += len(payload)
        except Exception:
            break
    try:
        c.shutdown(socket.SHUT_WR)
    except Exception:
        pass
    c.close()
    with lock:
        sent[0] += n_local
ts = [threading.Thread(target=worker) for _ in range({streams})]
t0 = time.monotonic()
for t in ts: t.start()
for t in ts: t.join()
dt = time.monotonic() - t0
print(f"{{sent[0]}} {{dt:.4f}}", flush=True)
"""
    srv_p = subprocess.Popen(ns_cmd("bm-srv", sys.executable, "-c", srv_code), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(0.25)
    cli_res = subprocess.run(ns_cmd("bm-cli", sys.executable, "-c", cli_code), capture_output=True, text=True, timeout=duration_s + 15.0)
    srv_out, srv_err = srv_p.communicate(timeout=10.0)
    recv_bytes = int(srv_out.strip() or "0")
    parts = cli_res.stdout.strip().split()
    elapsed = float(parts[1]) if len(parts) >= 2 else duration_s
    mbps = (recv_bytes * 8.0) / (max(elapsed, 0.1) * 1_000_000.0)
    return {
        "streams": streams,
        "duration_s": round(elapsed, 3),
        "received_bytes": recv_bytes,
        "throughput_mbps": round(mbps, 2),
        "ok": recv_bytes > 0,
        "err": (srv_err + cli_res.stderr).strip()[:200] if recv_bytes == 0 else "",
    }


def wait_connected(sock: Path, timeout_s: float = 12.0) -> tuple[bool, dict]:
    deadline = time.monotonic() + timeout_s
    last = {}
    while time.monotonic() < deadline:
        if sock.exists():
            st = ctl(sock, "service", "status")
            last = st
            phase = (st.get("status") or {}).get("phase")
            if phase == "connected":
                return True, st
            if phase == "failed":
                return False, st
        time.sleep(0.15)
    return False, last


def run_cell(
    case_id: str,
    carrier: str,
    device_mtu: int,
    path_mtu: int,
    repair: str,
    sec: Path,
    work: Path,
    port: int,
    duration_s: float,
    verify_outer_cap: bool = False,
) -> dict:
    setup_tuns(device_mtu)
    cdir = work / case_id
    cdir.mkdir(parents=True, exist_ok=True)
    os.chmod(cdir, 0o700)
    plan_path = cdir / "plan.json"

    overhead_map = {
        "quic-like": 49,
        "media-like": 49,
        "tls-like": 49,
        "openvpn-like": 50,
        "raw-packet": 66,
        "tcp": 91,
        "quic": 177,
    }
    # Generate exact tuned Common plan (supports Internal MTU > Capsule MTU & every carrier overhead!)
    tuned_base = cdir / "tuned.json"
    sh(
        str(CTL), "plan", "tune",
        "--input", str(BASE_PLAN),
        "--output", str(tuned_base),
        "--device-mtu", str(device_mtu),
        "--path-mtu", str(path_mtu),
        "--repair", repair,
        "--overhead-bytes", str(overhead_map[carrier]),
        "--force",
    )
    if carrier == "openvpn-like":
        build_openvpn_plan(tuned_base, plan_path, path_mtu)
    else:
        shutil.copyfile(tuned_base, plan_path)

    srv_sock = cdir / "srv.sock"
    cli_sock = cdir / "cli.sock"
    srv_log = open(cdir / "srv.log", "w")
    cli_log = open(cdir / "cli.log", "w")

    common_args = [
        "--record-profile", "common",
        "--common-transaction-plan", str(plan_path),
        "--duplex", "full",
        "--compression", "off",
        "--layer", "tun",
        "--max-packet", str(device_mtu),
        "--max-path-mtu", str(path_mtu),
        "--noise-profile", "ik",
        "--session-admission-key-file", str(sec / "admission.key"),
    ]
    srv_args = [
        str(DAEMON), "serve", *common_args,
        "--carrier", carrier,
        "--device", "tun-srv",
        "--control-socket", str(srv_sock),
        "--noise-private-key-file", str(sec / "noise-srv.key"),
        "--noise-peer-key-file", str(sec / "noise-cli.pub"),
        "--session-cookie-key-file", str(sec / "cookie.key"),
        "--allow-key", str(sec / "member.pub"),
    ]
    cli_args = [
        str(DAEMON), "connect", *common_args,
        "--carrier", carrier,
        "--device", "tun-cli",
        "--control-socket", str(cli_sock),
        "--noise-private-key-file", str(sec / "noise-cli.key"),
        "--noise-peer-key-file", str(sec / "noise-srv.pub"),
        "--identity", str(sec / "member.pk8"),
    ]

    if carrier in ("quic-like", "media-like", "tls-like"):
        srv_args += ["--udp-bind", f"{SRV_OUTER}:{port}", "--udp-peer", f"{CLI_OUTER}:{port}"]
        cli_args += ["--udp-bind", f"{CLI_OUTER}:{port}", "--udp-peer", f"{SRV_OUTER}:{port}"]
    elif carrier == "openvpn-like":
        srv_args += [
            "--udp-cover", "quic-like",
            "--udp-bind", f"{SRV_OUTER}:{port}", "--udp-peer", f"{CLI_OUTER}:{port}",
            "--cert", str(sec / "server.crt"), "--key", str(sec / "server.key"),
        ]
        cli_args += [
            "--udp-cover", "quic-like",
            "--udp-bind", f"{CLI_OUTER}:{port}", "--udp-peer", f"{SRV_OUTER}:{port}",
            "--ca", str(sec / "server.crt"), "--server-name", "l2tunnel.local",
        ]
    elif carrier in ("tcp", "quic"):
        mpol = cdir / "maintained.json"
        if carrier == "tcp":
            mpol.write_text(json.dumps({
                "version": 1,
                "first": {"client": f"{CLI_OUTER}:{port + 1}", "server": f"{SRV_OUTER}:{port}"},
                "second": None,
                "geometry": {
                    "path_mtu": path_mtu,
                    "max_record_bytes": path_mtu - 70,
                    "max_bootstrap_bytes": path_mtu - 70,
                    "charged_overhead_bytes": 70,
                    "bootstrap_overhead_bytes": 70,
                    "framing_bytes": 5,
                },
                "transport": {"kind": "tls", "record_timeout_micros": 5_000_000},
            }))
            cover_arg = "tls-like"
        else:
            mpol.write_text(json.dumps({
                "version": 1,
                "first": {"client": f"{CLI_OUTER}:{port + 1}", "server": f"{SRV_OUTER}:{port}"},
                "second": None,
                "geometry": {
                    "path_mtu": path_mtu,
                    "max_record_bytes": path_mtu - 156,
                    "max_bootstrap_bytes": path_mtu - 204,
                    "charged_overhead_bytes": 156,
                    "bootstrap_overhead_bytes": 204,
                    "framing_bytes": 0,
                },
                "transport": {
                    "kind": "quic",
                    "application_id": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                    "queued_datagrams": 128,
                    "control_window_bytes": 131072,
                    "idle_timeout_micros": 30_000_000,
                    "io_timeout_micros": 5_000_000,
                },
            }))
            cover_arg = "quic-like"
        srv_args += [
            "--udp-cover", cover_arg,
            "--maintained-policy", str(mpol),
            "--listen", f"{SRV_OUTER}:{port}",
            "--cert", str(sec / "server.crt"), "--key", str(sec / "server.key"),
        ]
        cli_args += [
            "--udp-cover", cover_arg,
            "--maintained-policy", str(mpol),
            "--remote", f"{SRV_OUTER}:{port}",
            "--ca", str(sec / "server.crt"), "--server-name", "l2tunnel.local",
        ]
        if carrier == "tcp":
            cli_args += ["--sni", "cdn.example.net"]
    elif carrier == "raw-packet":
        # Inside our isolated bm-srv / bm-cli namespaces ONLY, install the exact marked 4-tuple RST drop rule.
        for ns, lip, lport, pip, pport in [
            ("bm-srv", SRV_OUTER, port, CLI_OUTER, port + 1),
            ("bm-cli", CLI_OUTER, port + 1, SRV_OUTER, port),
        ]:
            sh(*ns_cmd(ns, "iptables", "-F", "OUTPUT"))
            sh(
                *ns_cmd(
                    ns, "iptables", "-I", "OUTPUT", "1",
                    "-p", "tcp", "-s", lip, "--sport", str(lport),
                    "-d", pip, "--dport", str(pport),
                    "--tcp-flags", "RST", "RST",
                    "-m", "mark", "!", "--mark", hex(77),
                    "-j", "DROP",
                )
            )
        pkt_cfg = {
            "mtu": path_mtu,
            "protection": "aead",
            "queue_packets": 64,
            "horizon_bytes": 1_048_576,
            "minimum_transfer_bytes": 65536,
            "bytes_per_second": 125_000_000,
            "packets_per_second": 200_000,
            "burst_bytes": 1_048_576,
            "burst_packets": 1024,
            "max_key_packets": 268_435_456,
            "max_key_bytes": 1_099_511_627_776,
        }
        rpol_srv = cdir / "raw_srv.json"
        rpol_cli = cdir / "raw_cli.json"
        rpol_srv.write_text(json.dumps({
            "version": 1,
            "profile": "raw-common-carrier-v1",
            "forward": {"local": f"{SRV_OUTER}:{port}", "peer": f"{CLI_OUTER}:{port + 1}"},
            "reverse": None,
            "packet": pkt_cfg,
        }))
        rpol_cli.write_text(json.dumps({
            "version": 1,
            "profile": "raw-common-carrier-v1",
            "forward": {"local": f"{CLI_OUTER}:{port + 1}", "peer": f"{SRV_OUTER}:{port}"},
            "reverse": None,
            "packet": pkt_cfg,
        }))
        srv_args += [
            "--udp-cover", "tls-like",
            "--raw-policy", str(rpol_srv), "--raw-mark", "77",
            "--listen", f"{SRV_OUTER}:{port}",
            "--cert", str(sec / "server.crt"), "--key", str(sec / "server.key"),
        ]
        cli_args += [
            "--udp-cover", "tls-like",
            "--raw-policy", str(rpol_cli), "--raw-mark", "77",
            "--remote", f"{SRV_OUTER}:{port}",
            "--ca", str(sec / "server.crt"), "--server-name", "l2tunnel.local",
        ]

    tcpdump_proc = None
    pcap_path = cdir / "outer.pcap"
    if verify_outer_cap:
        tcpdump_proc = subprocess.Popen(
            ns_cmd("bm-cli", "tcpdump", "-i", "veth-cli", "-s", "64", "-w", str(pcap_path), "ip"),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(0.2)

    srv_p = subprocess.Popen(ns_cmd("bm-srv", *srv_args), stdout=srv_log, stderr=subprocess.STDOUT)
    time.sleep(0.35)
    cli_p = subprocess.Popen(ns_cmd("bm-cli", *cli_args), stdout=cli_log, stderr=subprocess.STDOUT)

    result = {
        "case_id": case_id,
        "carrier": carrier,
        "internal_mtu": device_mtu,
        "capsule_mtu": path_mtu,
        "internal_gt_capsule": device_mtu > path_mtu,
        "repair": repair,
    }
    try:
        ok, st = wait_connected(cli_sock, timeout_s=12.0)
        result["connected"] = ok
        if not ok:
            result["status"] = st
            srv_log.flush()
            cli_log.flush()
            result["srv_log"] = (cdir / "srv.log").read_text()[:1200]
            result["cli_log"] = (cdir / "cli.log").read_text()[:1200]
            return result

        # Raise live speed budget to 1 Gbit/s so we measure true protocol/CPU speed.
        ctl(cli_sock, "tune", "budget", "--symmetric", "1000")
        time.sleep(0.2)

        # Standard 64B ping RTT
        result["ping_64b"] = measure_ping("bm-cli", SRV_TUN, count=10, payload_size=56, df=False)

        # If Internal MTU > Capsule MTU, explicitly verify DF large ICMP packet (Internal MTU - 28)!
        if device_mtu > path_mtu:
            large_payload = device_mtu - 28
            result["ping_large_df"] = measure_ping("bm-cli", SRV_TUN, count=6, payload_size=large_payload, df=True)

        # Multi-stream real kernel TUN TCP throughput
        result["tcp_tun"] = measure_tcp_throughput(duration_s=duration_s, streams=4, port=19100 + (port % 100))

        # In-process TunnelTestV1 download throughput
        tt = ctl(cli_sock, "test", "speed", "--download", "--streams", "4", "--seconds", "3")
        tinfo = (tt.get("test") or {}).get("test") or {}
        if tinfo:
            result["tunnel_test_dl_mbps"] = round(tinfo.get("bits_per_second", 0) / 1_000_000.0, 2)
        else:
            result["tunnel_test_dl_mbps"] = None
    finally:
        for p in (cli_p, srv_p):
            try:
                p.send_signal(signal.SIGTERM)
                p.wait(timeout=3.0)
            except Exception:
                p.kill()
        srv_log.close()
        cli_log.close()
        if tcpdump_proc is not None:
            tcpdump_proc.send_signal(signal.SIGINT)
            try:
                tcpdump_proc.wait(timeout=3.0)
            except Exception:
                tcpdump_proc.kill()
            # Parse maximum IPv4 wire packet length from pcap
            if pcap_path.is_file():
                td = subprocess.run(
                    ["tcpdump", "-nn", "-v", "-r", str(pcap_path)],
                    capture_output=True, text=True, timeout=10.0,
                )
                lens = [int(m) for m in re.findall(r"length (\d+)\)", td.stdout)]
                max_len = max(lens) if lens else 0
                result["outer_wire_packets_captured"] = len(lens)
                result["outer_wire_max_ip_bytes"] = max_len
                result["outer_wire_within_capsule_mtu"] = (len(lens) > 0 and max_len <= path_mtu)
        if carrier == "raw-packet":
            for ns in ("bm-srv", "bm-cli"):
                subprocess.run(ns_cmd(ns, "iptables", "-F", "OUTPUT"), capture_output=True)
    return result


def run_all(output_dir: Path, duration_s: float) -> int:
    output_dir.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="l2t-proto-matrix-"))
    sec = work / "sec"
    sec.mkdir(mode=0o700)
    try:
        sh(str(CTL), "key", "generate", "--private", str(sec / "member.pk8"), "--public", str(sec / "member.pub"))
        sh(str(CTL), "key", "generate-noise", "--private", str(sec / "noise-cli.key"), "--public", str(sec / "noise-cli.pub"))
        sh(str(CTL), "key", "generate-noise", "--private", str(sec / "noise-srv.key"), "--public", str(sec / "noise-srv.pub"))
        sh(str(CTL), "key", "generate-secret", "--output", str(sec / "admission.key"))
        sh(str(CTL), "key", "generate-secret", "--output", str(sec / "cookie.key"))
        gen_tls_certs(sec)

        setup_namespaces(loss_pct=0.0, delay_ms=0.0)

        matrix = [
            # All 7 runnable Common carriers/protocols at baseline 1500/1500
            ("udp_quic_like_arq", "quic-like", 1500, 1500, "off", False),
            ("udp_quic_like_fec_1_8", "quic-like", 1500, 1500, "1/8", False),
            ("udp_media_like_arq", "media-like", 1500, 1500, "off", False),
            ("udp_tls_like_arq", "tls-like", 1500, 1500, "off", False),
            ("udp_openvpn_like_arq", "openvpn-like", 1500, 1500, "off", False),
            ("raw_packet_arq", "raw-packet", 1500, 1500, "off", False),
            ("tcp_tls13_sni_arq", "tcp", 1500, 1500, "off", False),
            ("quic_quinn_arq", "quic", 1500, 1500, "off", False),
            # Internal MTU > Capsule MTU matrix (verified with outer wire tcpdump!)
            ("mtu_1500_over_1300", "quic-like", 1500, 1300, "off", True),
            ("mtu_1500_over_1280", "quic-like", 1500, 1280, "off", True),
            ("mtu_4096_over_1400", "quic-like", 4096, 1400, "off", True),
            ("mtu_4096_over_1300_fec", "quic-like", 4096, 1300, "1/8", True),
            ("mtu_9000_over_1400", "quic-like", 9000, 1400, "off", True),
        ]

        results = []
        base_port = 26400
        for idx, (cid, carrier, dev_mtu, p_mtu, rep, cap) in enumerate(matrix):
            print(f"==> [{idx + 1}/{len(matrix)}] {cid}: carrier={carrier} internal={dev_mtu} capsule={p_mtu} repair={rep}", flush=True)
            row = run_cell(cid, carrier, dev_mtu, p_mtu, rep, sec, work, base_port + idx * 10, duration_s, verify_outer_cap=cap)
            results.append(row)
            tcp_m = (row.get("tcp_tun") or {}).get("throughput_mbps")
            rtt = (row.get("ping_64b") or {}).get("avg_ms")
            tt_m = row.get("tunnel_test_dl_mbps")
            outer_max = row.get("outer_wire_max_ip_bytes")
            print(f"    connected={row.get('connected')} tcp_tun={tcp_m} Mbps tunnel_test={tt_m} Mbps rtt={rtt} ms outer_max={outer_max}", flush=True)
            if not row.get("connected"):
                print(f"    [ERR] srv={row.get('srv_log', '').strip()} | cli={row.get('cli_log', '').strip()}", flush=True)

        receipt = {
            "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "environment": "Linux isolated unshare netns veth (0% loss, 0ms added delay, 4 TCP streams)",
            "binary": str(DAEMON),
            "results": results,
        }
        (output_dir / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")

        lines = [
            "# All-Protocol & Internal-MTU > Capsule-MTU Speed Matrix",
            "",
            f"- Generated: `{receipt['generated_at_utc']}`",
            f"- Environment: {receipt['environment']}",
            "",
            "| Case | Carrier | Internal MTU | Capsule MTU | Repair | Connected | Real TUN TCP (Mbit/s) | In-Process DL (Mbit/s) | Ping Avg RTT (ms) | Large DF Ping | Outer Wire Max IP (B) |",
            "| --- | --- | ---: | ---: | --- | :---: | ---: | ---: | ---: | --- | ---: |",
        ]
        for r in results:
            tcp_m = (r.get("tcp_tun") or {}).get("throughput_mbps", "—")
            rtt = (r.get("ping_64b") or {}).get("avg_ms", "—")
            tt_m = r.get("tunnel_test_dl_mbps")
            tt_s = f"{tt_m}" if tt_m is not None else "—"
            df_p = r.get("ping_large_df")
            df_s = f"{df_p['payload_bytes'] + 28}B ({df_p['loss_pct']:.0f}% loss)" if df_p else "—"
            omax = r.get("outer_wire_max_ip_bytes")
            omax_s = f"{omax} (<= {r['capsule_mtu']} {'OK' if r.get('outer_wire_within_capsule_mtu') else 'FAIL'})" if omax else "—"
            lines.append(
                f"| `{r['case_id']}` | `{r['carrier']}` | {r['internal_mtu']} | {r['capsule_mtu']} | `{r['repair']}` | "
                f"{'PASS' if r.get('connected') else 'FAIL'} | {tcp_m} | {tt_s} | {rtt} | {df_s} | {omax_s} |"
            )
        (output_dir / "RESULTS.md").write_text("\n".join(lines) + "\n")
        print(f"Wrote {output_dir / 'RESULTS.md'} and {output_dir / 'receipt.json'}", flush=True)
        return 0 if all(r.get("connected") for r in results) else 1
    finally:
        for ns in ("bm-srv", "bm-cli"):
            subprocess.run(["ip", "netns", "del", ns], capture_output=True)
        shutil.rmtree(work, ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--duration", type=float, default=3.5)
    ap.add_argument("--inside-unshare", action="store_true")
    args = ap.parse_args()

    if not args.inside_unshare:
        cmd = [
            "sudo", "-n", "unshare", "--net", "--mount", "--fork", "--propagation", "private",
            sys.executable, str(Path(__file__).resolve()),
            "--inside-unshare", "--output", str(args.output.resolve()), "--duration", str(args.duration),
        ]
        res = subprocess.run(cmd)
        # Ensure invoking user owns output files cleanly
        subprocess.run(["sudo", "-n", "chmod", "-R", "a+rX", str(args.output.resolve())], capture_output=True)
        return res.returncode

    os.umask(0o022)
    sh("mount", "--make-rprivate", "/")
    sh("mount", "-t", "tmpfs", "-o", "size=64m,mode=755", "tmpfs", "/run")
    Path("/run/netns").mkdir(exist_ok=True)
    return run_all(args.output, args.duration)


if __name__ == "__main__":
    raise SystemExit(main())
