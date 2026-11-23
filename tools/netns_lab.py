#!/usr/bin/env python3
"""Plan or explicitly create an isolated Linux TAP/bridge tunnel test lab.

The default invocation only prints a plan. This topology tool does not launch tunnel daemons or traffic generators. All network changes are scoped to newly owned namespaces.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
from typing import Iterator
import uuid


STATE_VERSION = 1
NETNS_DIRECTORY = Path("/run/netns")


@dataclass(frozen=True)
class LabSpec:
    lab_id: str = "demo"
    loss_percent: int = 15

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,19}", self.lab_id):
            raise ValueError("lab ID must match [a-z][a-z0-9-]{0,19}")
        if type(self.loss_percent) is not int or not 0 <= self.loss_percent <= 100:
            raise ValueError("loss percent must be an integer within 0..100")

    @property
    def namespaces(self) -> dict[str, str]:
        return {
            role: f"l2t-{self.lab_id}-{suffix}"
            for role, suffix in (
                ("endpoint_a", "ea"),
                ("endpoint_b", "eb"),
                ("router", "wan"),
                ("host_a", "ha"),
                ("host_b", "hb"),
            )
        }


@dataclass(frozen=True)
class Step:
    argv: tuple[str, ...]
    creates_namespace: str | None = None


def build_plan(spec: LabSpec) -> list[Step]:
    """Return deterministic argv vectors; never execute commands or use a shell."""
    ns = spec.namespaces
    steps: list[Step] = []

    def add(*argv: str) -> None:
        steps.append(Step(argv))

    def ip(role: str, *argv: str) -> None:
        add("ip", "-n", ns[role], *argv)

    def tc(role: str, *argv: str) -> None:
        add("ip", "netns", "exec", ns[role], "tc", *argv)

    for namespace in ns.values():
        steps.append(Step(("ip", "netns", "add", namespace), namespace))
    for role in ns:
        ip(role, "link", "set", "lo", "up")

    for side, local_ip, router_ip, remote_subnet, host_ip, rate in (
        (
            "a",
            "192.0.2.2/30",
            "192.0.2.1/30",
            "192.0.2.4/30",
            "198.18.0.1/24",
            "100mbit",
        ),
        (
            "b",
            "192.0.2.6/30",
            "192.0.2.5/30",
            "192.0.2.0/30",
            "198.18.0.2/24",
            "10mbit",
        ),
    ):
        endpoint = f"endpoint_{side}"
        host = f"host_{side}"
        router_link = f"{side}0"
        ip(
            endpoint,
            "link",
            "add",
            "wan0",
            "type",
            "veth",
            "peer",
            "name",
            router_link,
            "netns",
            ns["router"],
        )
        ip(endpoint, "address", "add", local_ip, "dev", "wan0")
        ip("router", "address", "add", router_ip, "dev", router_link)
        ip(endpoint, "link", "set", "wan0", "mtu", "1500", "up")
        ip("router", "link", "set", router_link, "mtu", "1500", "up")
        ip(
            endpoint,
            "route",
            "add",
            remote_subnet,
            "via",
            router_ip.split("/")[0],
            "dev",
            "wan0",
        )

        ip(endpoint, "link", "add", "br-lan", "type", "bridge", "stp_state", "0")
        ip(
            endpoint,
            "link",
            "add",
            "lan0",
            "type",
            "veth",
            "peer",
            "name",
            "eth0",
            "netns",
            ns[host],
        )
        ip(endpoint, "tuntap", "add", "dev", "tap0", "mode", "tap")
        for interface in ("lan0", "tap0"):
            ip(endpoint, "link", "set", interface, "master", "br-lan")
            ip(endpoint, "link", "set", interface, "mtu", "1500", "up")
        ip(endpoint, "link", "set", "br-lan", "mtu", "1500", "up")
        ip(host, "link", "set", "eth0", "mtu", "1500", "up")
        ip(host, "address", "add", host_ip, "dev", "eth0")

        # Each direction has one loss stage and 35 ms delay: base RTT is 70 ms.
        tc(
            endpoint,
            "qdisc",
            "add",
            "dev",
            "wan0",
            "root",
            "handle",
            "1:",
            "htb",
            "default",
            "10",
        )
        tc(
            endpoint,
            "class",
            "add",
            "dev",
            "wan0",
            "parent",
            "1:",
            "classid",
            "1:10",
            "htb",
            "rate",
            rate,
            "ceil",
            rate,
        )
        tc(
            endpoint,
            "qdisc",
            "add",
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
            "35ms",
            "loss",
            "random",
            f"{spec.loss_percent}%",
        )

    add(
        "ip",
        "netns",
        "exec",
        ns["router"],
        "sysctl",
        "-q",
        "-w",
        "net.ipv4.ip_forward=1",
    )
    return steps


def plan_document(spec: LabSpec) -> dict:
    return {
        "status": "topology_only_no_tunnel_daemon",
        "lab_id": spec.lab_id,
        "namespaces": spec.namespaces,
        "parameters": {
            "mtu": 1500,
            "a_to_b_rate_mbps": 100,
            "b_to_a_rate_mbps": 10,
            "one_way_delay_ms": 35,
            "base_rtt_ms": 70,
            "iid_loss_percent_per_direction": spec.loss_percent,
            "netem_queue_packets": 1000,
        },
        "commands": [list(step.argv) for step in build_plan(spec)],
    }


def run(argv: tuple[str, ...] | list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(argv, check=True, capture_output=True, text=True)


def require_root() -> None:
    if os.geteuid() != 0:
        raise RuntimeError(
            "--apply and --cleanup require root; the default plan needs no privileges"
        )


@contextmanager
def locked_state(directory: Path, spec: LabSpec) -> Iterator[Path]:
    """Keep journals in a private directory and serialize one lab's operations."""
    require_root()
    directory.mkdir(mode=0o700, parents=False, exist_ok=True)
    info = directory.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise RuntimeError(
            "state directory must be a non-symlink, root-owned directory with mode 0700"
        )
    # Resolve only after validating the final component; parents must be trusted.
    directory = directory.resolve()
    for parent in directory.parents:
        info = parent.stat()
        if info.st_uid != 0 or (
            stat.S_IMODE(info.st_mode) & 0o022 and not info.st_mode & stat.S_ISVTX
        ):
            raise RuntimeError(
                "state directory parents must be root-owned and not writable by other users (sticky /tmp allowed)"
            )
    lock_path = directory / f"{spec.lab_id}.lock"
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield directory / f"{spec.lab_id}.json"
    finally:
        os.close(descriptor)


def namespace_identity(name: str) -> dict[str, int]:
    info = (NETNS_DIRECTORY / name).stat()
    return {"device": info.st_dev, "inode": info.st_ino}


def save_manifest(path: Path, manifest: dict) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(manifest, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def load_manifest(path: Path, spec: LabSpec) -> dict:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, encoding="utf-8") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise RuntimeError("manifest must be a private root-owned regular file")
        manifest = json.load(stream)
    validate_manifest(manifest, spec)
    return manifest


def validate_manifest(manifest: dict, spec: LabSpec) -> None:
    if (
        not isinstance(manifest, dict)
        or manifest.get("version") != STATE_VERSION
        or manifest.get("lab_id") != spec.lab_id
        or manifest.get("uid") != 0
    ):
        raise RuntimeError("manifest identity/version does not match the requested lab")
    owned = manifest.get("owned_namespaces")
    if not isinstance(owned, dict) or not set(owned).issubset(spec.namespaces.values()):
        raise RuntimeError("manifest contains unexpected namespace names")
    for identity in owned.values():
        if (
            not isinstance(identity, dict)
            or set(identity) != {"device", "inode"}
            or any(type(value) is not int or value < 0 for value in identity.values())
        ):
            raise RuntimeError("manifest has an invalid namespace identity")


def verify_cleanup(manifest: dict) -> list[str]:
    """Check every namespace before deleting any; mismatched ownership fails shut."""
    present: list[str] = []
    for name, expected in manifest["owned_namespaces"].items():
        try:
            current = namespace_identity(name)
        except FileNotFoundError:
            continue
        if current != expected:
            raise RuntimeError(f"refusing to remove replaced namespace: {name}")
        if run(["ip", "netns", "pids", name]).stdout.strip():
            raise RuntimeError(
                f"namespace {name} still has processes; stop its daemons/captures first"
            )
        present.append(name)
    return present


def remove_owned(manifest: dict, path: Path) -> None:
    for name in reversed(verify_cleanup(manifest)):
        # Recheck immediately before deletion; never delete by name alone.
        if namespace_identity(name) != manifest["owned_namespaces"][name]:
            raise RuntimeError(f"namespace ownership changed during cleanup: {name}")
        run(["ip", "netns", "delete", name])
        del manifest["owned_namespaces"][name]
        save_manifest(path, manifest)
    path.unlink()


def apply(spec: LabSpec, directory: Path) -> None:
    require_root()
    for executable in ("ip", "tc", "sysctl"):
        if shutil.which(executable) is None:
            raise RuntimeError(f"required executable is unavailable: {executable}")
    with locked_state(directory, spec) as path:
        if path.exists() or path.is_symlink():
            raise RuntimeError(
                f"state already exists: {path}; inspect and explicitly --cleanup first"
            )
        for name in spec.namespaces.values():
            if (NETNS_DIRECTORY / name).exists() or (
                NETNS_DIRECTORY / name
            ).is_symlink():
                raise RuntimeError(
                    f"namespace already exists: {name}; refusing to adopt it"
                )
        manifest = {
            "version": STATE_VERSION,
            "lab_id": spec.lab_id,
            "uid": os.geteuid(),
            "run_id": uuid.uuid4().hex,
            "owned_namespaces": {},
            "plan": plan_document(spec),
        }
        save_manifest(path, manifest)
        try:
            for step in build_plan(spec):
                run(step.argv)
                if step.creates_namespace is not None:
                    name = step.creates_namespace
                    manifest["owned_namespaces"][name] = namespace_identity(name)
                    save_manifest(path, manifest)
        except BaseException:
            try:
                remove_owned(manifest, path)
            except Exception as cleanup_error:
                print(
                    f"partial setup retained for inspection at {path}: {cleanup_error}",
                    file=sys.stderr,
                )
            raise
        print(f"Created topology; receipt: {path}")
        print(
            "Topology created; this command does not launch tunnel daemons."
        )


def cleanup(spec: LabSpec, directory: Path) -> None:
    with locked_state(directory, spec) as path:
        manifest = load_manifest(path, spec)
        remove_owned(manifest, path)
    print(f"Removed owned namespaces for {spec.lab_id}.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab-id", default="demo")
    parser.add_argument("--state-dir", type=Path, default=Path("/run/l2tunnel-labs"))
    action = parser.add_mutually_exclusive_group()
    action.add_argument(
        "--apply",
        action="store_true",
        help="explicitly create the topology (root only)",
    )
    action.add_argument(
        "--cleanup",
        action="store_true",
        help="remove only namespaces proven owned by the lab (root only)",
    )
    parser.add_argument(
        "--json", action="store_true", help="print the dry-run plan as JSON"
    )
    args = parser.parse_args(argv)
    try:
        spec = LabSpec(args.lab_id)
        if args.json and (args.apply or args.cleanup):
            raise ValueError("--json is only available for a dry run")
        if args.apply:
            apply(spec, args.state_dir)
        elif args.cleanup:
            cleanup(spec, args.state_dir)
        elif args.json:
            print(json.dumps(plan_document(spec), indent=2))
        else:
            print(
                "DRY RUN: isolated topology only; no tunnel daemon or traffic is started."
            )
            for step in build_plan(spec):
                print(shlex.join(step.argv))
        return 0
    except (ValueError, RuntimeError, OSError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            print(error.stderr.rstrip(), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
