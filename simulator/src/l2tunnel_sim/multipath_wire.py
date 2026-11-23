"""Plaintext inside authenticated multicarrier DATA, ACK and named-request records."""

from .aggregate_ack import _decode_bounded_varint as read_integer
from .aligned_records import _unsigned_varint as put_integer
from .striped_cauchy import Geometry, Receiver, encode_group


MAX = (1 << 64) - 1
LOGICAL = 255
MAX_BYTES = 65535
ACK_SPAN = 8192


def _number(value, limit=MAX):
    if type(value) is not int or not 0 <= value <= limit:
        raise ValueError("field outside its wire range")
    return value


def _dimensions(n, k, size):
    if not 1 <= _number(k, LOGICAL) <= _number(n, LOGICAL) or not _number(size, MAX_BYTES):
        raise ValueError("invalid coding dimensions or original length")
    largest = (size + n - 1) // n
    return (2 + largest + k - 1) // k


def shards(payload, n, k):
    """Return one self-describing shard per path, before per-path batching."""
    size = len(payload)
    width = _dimensions(n, k, size)
    direct = [payload[size * i // n:size * (i + 1) // n] for i in range(n)]
    prefix = put_integer(size)
    if k == n:
        return tuple(prefix + part for part in direct)
    # The existing Cauchy codec admits nonempty direct cells. An empty interval
    # is represented canonically by a zero byte in coding, implicit on the wire.
    rows = encode_group([part or b"\0" for part in direct], Geometry(k, n - k))
    return tuple(prefix + part + row[k * width:] for part, row in zip(direct, rows))


def shard_length(body):
    size, _ = read_integer(body, 0, MAX_BYTES)
    if not size:
        raise ValueError("empty native record")
    return size


def recover(n, k, original_length, shards_by_path):
    """Reconstruct an original from distinct authenticated coding ordinals."""
    width = _dimensions(n, k, original_length)
    if not k <= len(shards_by_path) <= n:
        raise ValueError("insufficient or excessive distinct shards")
    geometry = Geometry(k, n - k) if k < n else None
    rx = Receiver(geometry) if geometry else None
    parts = {}
    for ordinal, body in shards_by_path.items():
        _number(ordinal, n - 1)
        size, offset = read_integer(body, 0, MAX_BYTES)
        length = (ordinal + 1) * original_length // n - ordinal * original_length // n
        end = offset + length
        if size != original_length or len(body) != end + (n - k) * width:
            raise ValueError("inconsistent shard identity or extent")
        part = body[offset:end]
        parts[ordinal] = part
        if rx:
            direct = part or b"\0"
            row = (len(direct).to_bytes(2, "big") + direct).ljust(k * width, b"\0")
            rx.add(ordinal, row + body[end:])
    if rx:
        for ordinal, raw in rx.recover_missing().items():
            length = (ordinal + 1) * original_length // n - ordinal * original_length // n
            if len(raw) != max(1, length) or (not length and raw != b"\0"):
                raise ValueError("inconsistent reconstructed size")
            parts[ordinal] = raw[:length]
    return b"".join(parts[i] for i in range(n))


def encode_data(path_id, packet_number, entries, feedback=b""):
    """Each entry is (stable group ID, original coding ordinal, immutable body)."""
    _number(path_id, LOGICAL - 1)
    _number(packet_number, MAX - 1)
    if not 1 <= len(entries) <= 255:
        raise ValueError("empty or oversized DATA batch")
    out = bytearray([2 if feedback else 1, path_id])
    out.extend(put_integer(packet_number))
    out.append(len(entries))
    for group, ordinal, body in entries:
        _number(ordinal, LOGICAL - 1)
        if not 0 < len(body) <= MAX_BYTES:
            raise ValueError("invalid DATA entry size")
        out.extend(put_integer(_number(group, MAX - 1)))
        out.extend(put_integer(2 * len(body) + int(ordinal != path_id)))
        if ordinal != path_id:
            out.append(ordinal)
        out.extend(body)
        if len(out) > MAX_BYTES:
            raise ValueError("oversized DATA datagram")
    if feedback:
        decode_ack(feedback)
        out.extend(feedback)
        if len(out) > MAX_BYTES:
            raise ValueError("oversized piggyback datagram")
    return bytes(out)


def decode_packet(wire):
    """Return (physical path, per-path DATA sequence, entries, complete ACK bytes)."""
    if not 4 <= len(wire) <= MAX_BYTES or wire[0] not in (1, 2) or wire[1] == LOGICAL:
        raise ValueError("invalid DATA prefix")
    path = wire[1]
    packet, pos = read_integer(wire, 2, MAX - 1)
    if pos >= len(wire) or not wire[pos]:
        raise ValueError("missing DATA entries")
    count = wire[pos]
    pos += 1
    entries = []
    for _ in range(count):
        group, pos = read_integer(wire, pos, MAX - 1)
        packed_size, pos = read_integer(wire, pos, 2 * MAX_BYTES + 1)
        size = packed_size >> 1
        ordinal = path
        if packed_size & 1:
            if pos == len(wire) or wire[pos] in (path, LOGICAL):
                raise ValueError("invalid explicit shard ordinal")
            ordinal = wire[pos]
            pos += 1
        if size == 0 or pos + size > len(wire):
            raise ValueError("invalid shard size")
        entries.append((group, ordinal, wire[pos:pos + size]))
        pos += size
    tail = wire[pos:]
    if wire[0] == 2:
        decode_ack(tail)
    elif tail:
        raise ValueError("unexpected DATA suffix")
    return path, packet, tuple(entries), tail


def _check_block(path, floor, next_id, ranges):
    _number(path, LOGICAL)
    _number(floor)
    _number(next_id)
    if floor > next_id or (path == LOGICAL and floor) or len(ranges) > 8:
        raise ValueError("invalid ACK floor or extent")
    end = next_id
    for first, stop in ranges:
        _number(first)
        _number(stop)
        if not end < first < stop:
            raise ValueError("overlapping or adjacent ACK ranges")
        end = stop
    if end - (next_id if path == LOGICAL else floor) > ACK_SPAN:
        raise ValueError("ACK exceeds observation window")


def encode_ack(blocks):
    """Ranges use absolute half-open bounds at this API and gap/length on wire."""
    if not 1 <= len(blocks) <= 8:
        raise ValueError("invalid ACK block count")
    out = bytearray([0xA1, len(blocks)])
    previous_path = -1
    for path, floor, next_id, ranges in blocks:
        _check_block(path, floor, next_id, ranges)
        if path <= previous_path:
            raise ValueError("ACK paths must be unique and sorted")
        previous_path = path
        out.append(path)
        out.extend(put_integer(floor))
        out.extend(put_integer(next_id))
        out.append(len(ranges))
        end = next_id
        for first, stop in ranges:
            out.extend(put_integer(first - end))
            out.extend(put_integer(stop - first))
            end = stop
    return bytes(out)


def decode_ack(wire):
    if len(wire) < 2 or wire[0] != 0xA1 or not 1 <= wire[1] <= 8:
        raise ValueError("invalid ACK prefix")
    pos = 2
    blocks = []
    for _ in range(wire[1]):
        if pos == len(wire):
            raise ValueError("truncated ACK block")
        path = wire[pos]
        floor, pos = read_integer(wire, pos + 1, MAX)
        next_id, pos = read_integer(wire, pos, MAX)
        if (blocks and path <= blocks[-1][0]) or pos == len(wire) or wire[pos] > 8:
            raise ValueError("invalid ACK block")
        count = wire[pos]
        pos += 1
        end = next_id
        ranges = []
        for _ in range(count):
            gap, pos = read_integer(wire, pos, ACK_SPAN)
            run, pos = read_integer(wire, pos, ACK_SPAN)
            first = end + gap
            end = first + run
            ranges.append((first, end))
        _check_block(path, floor, next_id, ranges)
        blocks.append((path, floor, next_id, tuple(ranges)))
    if pos != len(wire):
        raise ValueError("unexpected ACK suffix")
    return tuple(blocks)


def encode_request(ids):
    """Name old logical groups independently of the physical observation floor."""
    if not 1 <= len(ids) <= 64:
        raise ValueError("invalid named request count")
    out = bytearray([0xA2, len(ids)])
    previous = -1
    for group in ids:
        if _number(group, MAX - 1) <= previous:
            raise ValueError("duplicate or unordered group")
        out.extend(put_integer(group - previous - 1))
        previous = group
    return bytes(out)


def decode_request(wire):
    if len(wire) < 2 or wire[0] != 0xA2 or not 1 <= wire[1] <= 64:
        raise ValueError("invalid named request prefix")
    pos = 2
    previous = -1
    ids = []
    for _ in range(wire[1]):
        gap, pos = read_integer(wire, pos, MAX - 2 - previous)
        previous += 1 + gap
        ids.append(previous)
    if pos != len(wire):
        raise ValueError("unexpected named request suffix")
    return tuple(ids)


def encode_shard_request(rows, n):
    """Request exactly the named ordinals. Bit zero of the first byte names ordinal zero."""
    if not _number(n, LOGICAL) or not 1 <= len(rows) <= 64:
        raise ValueError("invalid shard request extent")
    out = bytearray([0xA3, len(rows)])
    previous = -1
    for group, ordinals in rows:
        if _number(group, MAX - 1) <= previous or not 1 <= len(ordinals) <= n:
            raise ValueError("invalid named group or shard count")
        mask = 0
        for ordinal in ordinals:
            bit = 1 << _number(ordinal, n - 1)
            if mask & bit:
                raise ValueError("duplicate requested shard")
            mask |= bit
        out.extend(put_integer(group - previous - 1))
        out.extend(mask.to_bytes((n + 7) // 8, "little"))
        previous = group
    return bytes(out)


def decode_shard_request(wire, n):
    if not _number(n, LOGICAL) or len(wire) < 2 or wire[0] != 0xA3 or not 1 <= wire[1] <= 64:
        raise ValueError("invalid shard request prefix")
    pos = 2
    previous = -1
    width = (n + 7) // 8
    rows = []
    for _ in range(wire[1]):
        gap, pos = read_integer(wire, pos, MAX - 2 - previous)
        previous += gap + 1
        if pos + width > len(wire):
            raise ValueError("truncated shard mask")
        mask = int.from_bytes(wire[pos:pos + width], "little")
        pos += width
        if not mask or mask >> n:
            raise ValueError("invalid shard mask")
        rows.append((previous, tuple(i for i in range(n) if mask & (1 << i))))
    if pos != len(wire):
        raise ValueError("unexpected shard request suffix")
    return tuple(rows)
