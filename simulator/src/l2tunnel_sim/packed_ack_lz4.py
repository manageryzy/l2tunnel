"""Independent reverse ACK source representation for the single-flow C48 study.

Model Packed sources contain Ethernet frames and a channel byte. Channel 254
is reserved here as the compressed marker. The native compact Packed envelope
instead reserves a zero record count. Both wrappers cost three bytes and retain
the whole original source for FEC. Neither needs earlier sources to decode.
"""
from collections import Counter

from .packed_wire import PACKED_CHANNEL, packed_units


def valid_options(options, tcp):
    offset = 0
    timestamp = False
    while offset < len(options):
        kind = options[offset]
        if kind == 0:
            return not tcp or not any(options[offset + 1:])
        if kind == 1:
            offset += 1
            continue
        if offset + 2 > len(options):
            return False
        size = options[offset + 1]
        if size < 2 or offset + size > len(options):
            return False
        if tcp:
            if kind in (2, 3, 4, 34) or kind == 5 and (size < 10 or (size - 2) % 8):
                return False
            if kind == 8:
                if timestamp or size != 10:
                    return False
                timestamp = True
        offset += size
    return True


class ShortAckBlocks:
    marker = 254

    def __init__(self, symbol_bytes, short_frame_bytes, channels):
        from lz4 import block
        if not 0 < symbol_bytes <= 65535 or not 0 < short_frame_bytes <= symbol_bytes:
            raise ValueError("invalid ACK compression limits")
        if not 0 < channels <= self.marker:
            raise ValueError("ACK compression requires a reserved channel marker")
        self.block = block
        self.maximum = symbol_bytes
        self.short = short_frame_bytes
        self.channels = channels
        self.physical = Counter()
        self.representations = Counter()

    def eligible(self, data):
        if not 0 < len(data) <= self.maximum:
            return False
        units = packed_units(data, self.maximum) if data[0] == PACKED_CHANNEL else (data,)
        for unit in units:
            frame = unit[6:]
            if (len(unit) < 6 or unit[0] >= self.channels or unit[3] != 2
                    or len(frame) != int.from_bytes(unit[4:6], "big")
                    or len(frame) > self.short or frame[12:14] != b"\x08\x00"):
                return False
            ip = frame[14:]
            if (not 40 <= len(ip) <= 128 or ip[0] >> 4 != 4 or ip[9] != 6
                    or int.from_bytes(ip[2:4], "big") != len(ip)
                    or int.from_bytes(ip[6:8], "big") & 0xbfff):
                return False
            ihl = (ip[0] & 15) * 4
            tcp = ip[ihl:]
            if (ihl < 20 or len(tcp) < 20 or tcp[12] & 15
                    or (tcp[12] >> 4) * 4 != len(tcp) or tcp[13] & 0x3f != 0x10
                    or not valid_options(ip[20:ihl], False) or not valid_options(tcp[20:], True)):
                return False
        return bool(units)

    def encode(self, source):
        if not self.eligible(source):
            self.representations["ineligible"] += 1
            return source
        body = self.block.compress(source, store_size=False)
        if len(body) + 3 >= len(source):
            self.representations["raw_when_not_smaller"] += 1
            return source
        self.representations["compressed"] += 1
        return bytes([self.marker]) + len(source).to_bytes(2, "big") + body

    def decode(self, wire):
        if not wire or len(wire) > self.maximum:
            raise ValueError("invalid transmitted ACK source length")
        if wire[0] != self.marker:
            return wire
        original = int.from_bytes(wire[1:3], "big")
        if not 3 < len(wire) < original <= self.maximum:
            raise ValueError("invalid compressed ACK extent")
        try:
            data = self.block.decompress(wire[3:], uncompressed_size=original)
        except self.block.LZ4BlockError as error:
            raise ValueError("invalid compressed ACK block") from error
        if len(data) != original or not self.eligible(data):
            raise ValueError("invalid reconstructed ACK source")
        return data

    def account(self, kind, nominal_bytes, physical_bytes):
        self.physical[kind + "_packets"] += 1
        self.physical[kind + "_ip_bytes"] += physical_bytes
        self.physical[kind + "_ip_bytes_saved"] += nominal_bytes - physical_bytes
