"""Read back and set only the RNG seed on an existing owned laboratory netem."""

import argparse
import json
import os
from pathlib import Path
import re
import socket
import struct

HEADER = struct.Struct("=IHHII")
TC = struct.Struct("=BBHiIII")
QOPT = struct.Struct("=6I")
U64 = struct.Struct("=Q")
SEED, PAD = 14, 9


def aligned(n):
    return (n + 3) & ~3


def attrs(raw):
    result = {}
    pos = 0
    while pos < len(raw):
        length, tag = struct.unpack_from("=HH", raw, pos)
        if not 4 <= length <= len(raw) - pos:
            raise ValueError("invalid netlink attribute length")
        tag &= 0x3FFF
        if tag != PAD or tag not in result:
            if tag in result:
                raise ValueError("duplicate netlink attribute")
            result[tag] = raw[pos + 4 : pos + length]
        pos += aligned(length)
    return result


def attr(tag, data):
    size = 4 + len(data)
    return struct.pack("=HH", size, tag) + data + bytes(aligned(size) - size)


def request(sock, seq, kind, flags, payload):
    sock.sendto(HEADER.pack(16 + len(payload), kind, flags, seq, 0) + payload, (0, 0))
    result = []
    while True:
        raw, peer = sock.recvfrom(65536)
        if peer[0]:
            raise ValueError("unexpected netlink peer")
        p = 0
        while p < len(raw):
            size, typ, response_flags, serial, _ = HEADER.unpack_from(raw, p)
            if serial != seq or not 16 <= size <= len(raw) - p or response_flags & 0x10:
                raise ValueError("incomplete qdisc dump")
            body = raw[p + 16 : p + size]
            if typ == 2:
                (code,) = struct.unpack_from("=i", body)
                if code:
                    raise OSError(-code, os.strerror(-code))
                return result
            if typ == 3:
                return result
            result.append((typ, body))
            p += aligned(size)


def options(sock, index, seq, parent_id=0x10010, loss_percent=15):
    matches = []
    for kind, body in request(sock, seq, 38, 0x301, TC.pack(0, 0, 0, index, 0, 0, 0)):
        family, pad1, pad2, link, handle, parent, info = TC.unpack_from(body)
        if kind != 36 or link != index or (handle, parent) != (0x100000, parent_id):
            continue
        values = attrs(body[TC.size :])
        if values.get(1) != b"netem\0":
            raise ValueError("owned leaf is not netem")
        opts = values[2]
        fixed = opts[: QOPT.size]
        extras = attrs(opts[QOPT.size :])
        _, limit, loss, gap, dup, jitter = QOPT.unpack(fixed)
        if (limit, gap, dup, jitter) != (1000, 0, 0, 0) or abs(
            loss / (2**32 - 1) - loss_percent / 100
        ) > 1e-7:
            raise ValueError("unexpected owned netem limit or loss")
        if U64.unpack(extras[10]) != (35_000_000,) or SEED not in extras:
            raise ValueError("kernel does not expose expected delay and netem seed")
        matches.append((fixed, extras))
    (result,) = matches
    return result


def run(name, seed, router_interface=None, loss_percent=15):
    inode = os.stat("/proc/self/ns/net").st_ino
    router = router_interface is not None
    if router and router_interface not in ("a0", "b0"):
        raise ValueError("expected an owned router egress")
    pattern = r"l2t-[a-z][a-z0-9-]{0,19}-wan" if router else r"l2t-[a-z][a-z0-9-]{0,19}-e[ab]"
    if (
        not re.fullmatch(pattern, name)
        or inode == os.stat("/proc/1/ns/net").st_ino
        or inode != os.stat(Path("/run/netns") / name).st_ino
    ):
        raise ValueError("expected the owned endpoint namespace")
    if not 0 < seed < 2**64:
        raise ValueError("invalid seed")
    if not 0 <= loss_percent <= 100:
        raise ValueError("invalid loss percent")
    interface = router_interface if router else "wan0"
    parent = 0xFFFFFFFF if router else 0x10010
    index = socket.if_nametoindex(interface)
    with socket.socket(
        socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE
    ) as sock:
        sock.settimeout(2)
        sock.bind((0, 0))
        fixed, original = options(sock, index, 1, parent, loss_percent)
        chosen = {k: v for k, v in original.items() if k not in (PAD, SEED)}
        selected = (
            fixed
            + b"".join(attr(k, v) for k, v in chosen.items())
            + attr(SEED, U64.pack(seed))
        )
        # RTM_NEWQDISC with ACK and no CREATE/REPLACE may only change this existing leaf.
        request(
            sock,
            2,
            36,
            5,
            TC.pack(0, 0, 0, index, 0x100000, parent, 0)
            + attr(1, b"netem\0")
            + attr(2, selected),
        )
        after, current = options(sock, index, 3, parent, loss_percent)
        if (
            after != fixed
            or chosen != {k: v for k, v in current.items() if k not in (PAD, SEED)}
            or U64.unpack(current[SEED]) != (seed,)
        ):
            raise ValueError("netem readback differs")
    return dict(
        namespace=name,
        namespace_inode=inode,
        interface=interface,
        seed=seed,
        loss_percent=loss_percent,
        delay_ms=35,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name")
    parser.add_argument("seed", type=int)
    parser.add_argument("--router-interface", choices=("a0", "b0"))
    parser.add_argument("--loss-percent", type=int, default=15)
    args = parser.parse_args()
    print(json.dumps(run(args.name, args.seed, args.router_interface, args.loss_percent)))
