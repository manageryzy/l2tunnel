"""Small ctypes binding to the pinned, unmodified upstream KCP v1 algorithm.

The caller supplies the millisecond clock and delivers the actual UDP payloads.
Compilation is cached by source and compiler identity outside the source tree.
"""

import ctypes
from functools import lru_cache
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import tempfile


OUTPUT = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
VENDOR = Path(__file__).with_name('_vendor') / 'kcp'


@lru_cache(maxsize=1)
def library():
    provenance = json.loads((VENDOR / 'provenance.json').read_text())
    for name, item in provenance['files'].items():
        if sha256((VENDOR / name).read_bytes()).hexdigest() != item['sha256']:
            raise ValueError('KCP upstream source hash differs ' + name)
    compiler = subprocess.check_output(['cc', '--version'], text=True).splitlines()[0]
    identity = sha256(((VENDOR / 'ikcp.c').read_bytes() + (VENDOR / 'ikcp.h').read_bytes()
                       + compiler.encode() + b'-O2 -fPIC -shared')).hexdigest()
    cache = Path(tempfile.gettempdir()) / f'l2tunnel-kcp-{os.getuid()}'
    cache.mkdir(mode=0o700, exist_ok=True)
    target = cache / (identity + '.so')
    if not target.exists():
        with tempfile.TemporaryDirectory(dir=cache) as directory:
            temporary = Path(directory) / 'kcp.so'
            subprocess.run(['cc', '-O2', '-fPIC', '-shared', str(VENDOR / 'ikcp.c'), '-o', str(temporary)],
                           check=True, capture_output=True)
            temporary.replace(target)
    lib = ctypes.CDLL(str(target))
    signatures = {
        'ikcp_create': (ctypes.c_void_p, [ctypes.c_uint32, ctypes.c_void_p]),
        'ikcp_release': (None, [ctypes.c_void_p]),
        'ikcp_setoutput': (None, [ctypes.c_void_p, OUTPUT]),
        'ikcp_setmtu': (ctypes.c_int, [ctypes.c_void_p, ctypes.c_int]),
        'ikcp_wndsize': (ctypes.c_int, [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]),
        'ikcp_nodelay': (ctypes.c_int, [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int]),
        'ikcp_send': (ctypes.c_int, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]),
        'ikcp_recv': (ctypes.c_int, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]),
        'ikcp_input': (ctypes.c_int, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long]),
        'ikcp_peeksize': (ctypes.c_int, [ctypes.c_void_p]),
        'ikcp_waitsnd': (ctypes.c_int, [ctypes.c_void_p]),
        'ikcp_update': (None, [ctypes.c_void_p, ctypes.c_uint32]),
        'ikcp_check': (ctypes.c_uint32, [ctypes.c_void_p, ctypes.c_uint32]),
    }
    for name, (restype, argtypes) in signatures.items():
        function = getattr(lib, name)
        function.restype, function.argtypes = restype, argtypes
    lib.receipt = dict(upstream_commit=provenance['commit'], source_files=provenance['files'],
                       compiler=compiler, flags=['-O2', '-fPIC', '-shared'],
                       library_sha256=sha256(target.read_bytes()).hexdigest())
    return lib


class KCPContext:
    """One upstream KCP endpoint with actual ordered message bytes."""

    def __init__(self, conversation, *, mtu=1472, window=128, nodelay=1, interval=10, resend=2, nocwnd=1):
        if not 50 <= mtu <= 65507 or not 1 <= window <= 65535:
            raise ValueError('invalid KCP MTU or window')
        if nodelay not in (0, 1) or nocwnd not in (0, 1) or not 10 <= interval <= 5000 or resend < 0:
            raise ValueError('invalid KCP timing or congestion configuration')
        self.lib = library()
        self.pointer = self.lib.ikcp_create(conversation, None)
        if not self.pointer:
            raise MemoryError('KCP endpoint allocation failed')
        self.output = []
        self.callback = OUTPUT(self._output)
        self.lib.ikcp_setoutput(self.pointer, self.callback)
        self.lib.ikcp_setmtu(self.pointer, mtu)
        self.lib.ikcp_wndsize(self.pointer, window, window)
        self.lib.ikcp_nodelay(self.pointer, nodelay, interval, resend, nocwnd)
        self.mtu, self.mss, self.window = mtu, mtu - 24, window

    def _output(self, data, size, _context, _user):
        self.output.append(ctypes.string_at(data, size))
        return 0

    def send(self, body):
        body = bytes(body)
        if not body or len(body) > self.mss * 127:
            raise ValueError('KCP message must fit the upstream fragment bound')
        result = self.lib.ikcp_send(self.pointer, body, len(body))
        if result < 0:
            raise RuntimeError(f'KCP send failed {result}')

    def input(self, body):
        body = bytes(body)
        result = self.lib.ikcp_input(self.pointer, body, len(body))
        if result < 0:
            raise ValueError(f'KCP input failed {result}')

    def receive(self):
        size = self.lib.ikcp_peeksize(self.pointer)
        if size < 0:
            return None
        body = ctypes.create_string_buffer(size)
        result = self.lib.ikcp_recv(self.pointer, body, size)
        if result != size:
            raise RuntimeError('KCP receive length differs from message size')
        return body.raw

    @property
    def waiting(self):
        return self.lib.ikcp_waitsnd(self.pointer)

    def update(self, milliseconds):
        self.lib.ikcp_update(self.pointer, milliseconds)
        packets, self.output = self.output, []
        return packets

    def check(self, milliseconds):
        return self.lib.ikcp_check(self.pointer, milliseconds)

    def close(self):
        if self.pointer:
            self.lib.ikcp_release(self.pointer)
            self.pointer = None

    def __del__(self):
        if getattr(self, 'pointer', None):
            self.close()
