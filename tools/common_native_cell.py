"""Run one common_native_matrix.py cell inside fresh outer net and mount namespaces.

Replaces the per-campaign ``isolated_cell.py`` copies. Invoke through
``sudo -n unshare --net --mount --fork --propagation private``; without
``--apply`` it only prints the matrix dry-run plan. The outer namespaces must be
pristine (only ``lo``, no routes) and differ from PID 1's, so every lab change
stays inside namespaces created and removed by this cell.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

TOOLS = Path(__file__).resolve().parent


def matrix_args(a: argparse.Namespace) -> list[str]:
    args = [sys.executable, "-B", str(TOOLS / "common_native_matrix.py"),
            "--manifest", str(a.manifest), "--binary", str(a.binary), "--case", a.row,
            "--phase", "forward", "--flow-count", str(a.flows),
            "--netem-seed", str(a.seed), "--loss-percent", str(a.loss_percent),
            "--outstanding-credit-bytes", str(a.outstanding_credit_bytes),
            "--native-tun-txqueuelen", str(a.txqueuelen),
            "--native-forward-tun-maxrate-mbit", str(a.forward_maxrate_mbit),
            "--lab-id", a.lab_id, "--output", str(a.output)]
    if not a.capture:
        args.append("--no-capture")
    if a.switch:
        args.append("--switch-during-phase")
    if a.raw_rst_observation:
        args.append("--raw-rst-observation")
    return args


def parse(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--binary-sha256", help="Refuse to run unless the daemon has this digest")
    p.add_argument("--row", required=True)
    p.add_argument("--flows", type=int, choices=(1, 4, 16), required=True)
    p.add_argument("--seed", type=int, default=31248)
    p.add_argument("--loss-percent", type=int, default=15)
    p.add_argument("--outstanding-credit-bytes", type=int, default=4 * 1024 * 1024,
                   help="Total unconfirmed application credit divided over the flows (default 4 MiB)")
    p.add_argument("--txqueuelen", type=int, default=768)
    p.add_argument("--forward-maxrate-mbit", type=int, default=85)
    p.add_argument("--lab-id", default="cell")
    p.add_argument("--capture", action="store_true", help="Keep tcpdump captures (default: counters only)")
    p.add_argument("--switch", action="store_true")
    p.add_argument("--raw-rst-observation", action="store_true")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--apply", action="store_true")
    a = p.parse_args(argv)
    a.manifest = a.manifest.resolve(strict=True)
    a.binary = a.binary.resolve(strict=True)
    a.output = a.output.absolute()
    if a.output.exists() or a.output.is_symlink():
        p.error("--output must not exist")
    ready = {r["id"] for r in json.loads(a.manifest.read_text())["rows"] if r.get("status") == "ready"}
    if a.row not in ready:
        p.error("the requested row is not ready in the manifest")
    if a.binary_sha256 and hashlib.sha256(a.binary.read_bytes()).hexdigest() != a.binary_sha256:
        p.error("daemon digest mismatch")
    return a


def main(argv: list[str] | None = None) -> int:
    a = parse(argv)
    args = matrix_args(a)
    if not a.apply:
        return subprocess.call(args)
    if os.geteuid() != 0 or not os.environ.get("SUDO_UID"):
        raise SystemExit("run through sudo -n unshare --net --mount --fork --propagation private")
    for ns in ("net", "mnt"):
        if os.readlink(f"/proc/self/ns/{ns}") == os.readlink(f"/proc/1/ns/{ns}"):
            raise SystemExit("outer namespace isolation absent")
    links = json.loads(subprocess.check_output(["ip", "-j", "link"]))
    if [x["ifname"] for x in links] != ["lo"] or subprocess.check_output(["ip", "route", "show"]).strip():
        raise SystemExit("outer network is not pristine")
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "size=64m,mode=755", "tmpfs", "/run"], check=True)
    Path("/run/netns").mkdir()
    os.umask(0o022)
    try:
        rc = subprocess.call([*args, "--apply"])
        survivors = subprocess.check_output(["ip", "netns", "list"], text=True).strip()
        if a.output.is_dir():
            (a.output / "outer-isolation.json").write_text(json.dumps({
                "initial_links": ["lo"], "outer_net_ns": os.readlink("/proc/self/ns/net"),
                "outer_mount_ns": os.readlink("/proc/self/ns/mnt"),
                "remaining_named_namespaces": survivors.splitlines(), "return_code": rc,
                "netem_seed": a.seed, "loss_percent": a.loss_percent,
                "outstanding_credit_bytes": a.outstanding_credit_bytes}) + "\n")
        return rc if not survivors else 3
    finally:
        # Give the invoking user read access to the fresh cell output only.
        if a.output.is_dir():
            for directory, _, files in os.walk(a.output):
                Path(directory).chmod(0o755)
                for name in files:
                    f = Path(directory) / name
                    if f.is_file() and not f.is_symlink():
                        f.chmod(0o644)


if __name__ == "__main__":
    raise SystemExit(main())
