#!/usr/bin/env python3
"""FAKE l2tunnel local service for GUI/CLI development and tests.

Speaks local API version 5 (docs/modules/local-operations.md) on a private
Unix socket and *simulates* a service: connect walks through the real setup
stage names on a timer, then reports `connected`; nothing is authenticated,
no carrier or device exists, and no packet is forwarded. The real
`l2tunnelctl` and GUI talk to it unchanged, so only the service is fake.
Versions 1/4 and Common-only actions are refused explicitly.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import socketserver
import struct
import threading
import time

VERSION = 5
REQUEST_LIMIT = 4096
REPLY_LIMIT = 32768
EVENT_CAPACITY = 256
WAIT_LIMIT_MS = 30_000
SETUP_STAGES = ('socket_bind', 'socket_connect', 'admission_owner', 'configuration', 'admission',
                'noise', 'membership', 'attachment', 'driver_readiness')
SETUP_TIMEOUT_MS = 60_000


class FakeService:
    """All state under one condition; every change records events and notifies."""

    def __init__(self, step_seconds: float = 0.5, fail_connect: bool = False, server: bool = False):
        self.step = step_seconds
        self.fail_connect = fail_connect
        self.server = server
        # SIMULATED profile store: documents are kept, never validated or run.
        self.profiles: dict[str, dict] = {}
        self.default_profile: str | None = None
        self.active_profile: str | None = None
        self.test: dict | None = None
        self.test_ids = 0
        self.generation: int | None = None
        self.instance = secrets.token_hex(8)
        self.lock = threading.Condition()
        self.phase = 'disconnected'
        self.operation: int | None = None
        self.generation: int | None = None
        self.terminal: dict | None = None
        self.last_key = 0
        self.entries: dict[int, dict] = {}
        self.events: list[dict] = []
        self.sequence = 0
        self.recorded: tuple | None = None
        self.closed = False
        self.started = time.monotonic()
        self.connected_at: float | None = None
        # SIMULATED host state: nothing touches the real system.
        self.devices: dict[str, dict] = {
            'fake-eth0': {'name': 'fake-eth0', 'mtu': 1500, 'up': True,
                          'addresses': ['192.0.2.10/24'], 'owned': False},
        }
        self.routes: list[dict] = [
            {'destination': '0.0.0.0/0', 'gateway': '192.0.2.1', 'device': 'fake-eth0',
             'metric': 100, 'owned': False},
        ]
        # SIMULATED SOCKS5 state (DGUI-08): no real socket is opened.
        self.socks_settings: dict = {
            'enabled': False,
            'listen_host': '127.0.0.1',
            'listen_port': 1080,
            'auth_mode': 'none',
            'username': None,
            'password_set': False,
            'allowed_clients': ['127.0.0.1/32'],
            'max_flows': 128,
        }
        self.socks_password: str | None = None
        self.socks_error: str | None = None
        # SIMULATED live carrier switch state (DGUI-14).
        self.carrier_cover: str = 'quic-like'
        self.carrier_switches: int = 0
        with self.lock:
            self.publish()

    # --- event log (caller holds the lock) ---------------------------------
    def push(self, body: dict) -> None:
        self.sequence += 1
        self.events.append({'sequence': self.sequence, 'event': body})
        del self.events[:-EVENT_CAPACITY]

    def publish(self) -> None:
        for operation, entry in self.entries.items():
            if not entry['reported_accepted']:
                self.push({'type': 'operation_accepted', 'operation': operation, 'kind': entry['kind']})
                entry['reported_accepted'] = True
                entry['reported_stage'] = entry['setup']['stage'] if entry['setup'] else None
            stage = entry['setup']['stage'] if entry['setup'] else None
            if stage is not None and stage != entry['reported_stage']:
                self.push({'type': 'operation_progress', 'operation': operation, 'stage': stage})
                entry['reported_stage'] = stage
            if entry['result'] and not entry['reported_completed']:
                self.push({'type': 'operation_completed', 'operation': operation,
                           'outcome': entry['result']['outcome']})
                entry['reported_completed'] = True
        terminal_key = json.dumps(self.terminal, sort_keys=True)
        state = (self.phase, self.operation, self.generation, terminal_key)
        if state != self.recorded:
            self.push({'type': 'lifecycle', 'phase': self.phase, 'operation': self.operation,
                       'generation': self.generation, 'terminal': self.terminal})
            self.recorded = state
        self.lock.notify_all()

    # --- views ---------------------------------------------------------------
    def status_view(self) -> dict:
        view = {'phase': self.phase, 'operation': self.operation, 'generation': self.generation,
                'terminal': self.terminal, 'next_request_key': None if self.closed else self.last_key + 1,
                'event_cursor': self.sequence, 'listening': None, 'observation': None}
        if self.active_profile:
            view['profile'] = self.active_profile
        if self.phase == 'connected' and self.connected_at is not None:
            view['connected_ms'] = int((time.monotonic() - self.connected_at) * 1000)
        return view

    def operation_view(self, operation: int) -> dict:
        entry = self.entries[operation]
        deadline = entry['deadline']
        return {'id': operation, 'kind': entry['kind'],
                'state': 'completed' if entry['result'] else 'pending',
                'deadline_ms': None if deadline is None else max(0, int((deadline - time.monotonic()) * 1000)),
                'cancel_requested': entry['cancel'], 'setup': entry['setup'], 'result': entry['result']}

    def reply(self, ok: bool, code: str, **fields) -> dict:
        reply = {'version': VERSION, 'ok': ok, 'code': code, 'service': self.instance}
        reply.update({key: value for key, value in fields.items() if value is not None})
        return reply

    # --- operations ----------------------------------------------------------
    def submit(self, kind: str, key: int, request=None, profile: str | None = None,
               reported: str | None = None) -> dict:
        request = kind if request is None else request
        if key == 0:
            return self.reply(False, 'invalid_request_key')
        with self.lock:
            if self.closed:
                return self.reply(False, 'closed')
            if key <= self.last_key:
                entry = self.entries.get(key)
                if entry is None:
                    return self.reply(False, 'expired_key')
                if entry['request'] != request:
                    return self.reply(False, 'conflict')
                return self.reply(True, 'accepted', operation=self.operation_view(key))
            if key != self.last_key + 1:
                return self.reply(False, 'future_key')
            if self.operation is not None or self.phase == 'stopping':
                return self.reply(False, 'busy')
            connected = self.phase == 'connected'
            if profile is not None:
                self.active_profile = profile
            if kind == 'drain_proxy':
                return self.reply(False, 'unsupported')
            if kind == 'connect' and connected or kind == 'disconnect' and not connected:
                return self.reply(False, 'state')
            effective = 'reconnect' if kind == 'reconnect' and connected else ('connect' if kind == 'reconnect' else kind)
            setup = effective in {'connect', 'reconnect'}
            self.last_key = key
            self.entries[key] = {
                'kind': reported or effective, 'request': request, 'cancel': False, 'result': None,
                'deadline': time.monotonic() + SETUP_TIMEOUT_MS / 1000 if setup else None,
                'setup': {'stage': 'accepted', 'outcome': 'pending', 'failure': None, 'elapsed_micros': 0} if setup else None,
                'reported_accepted': False, 'reported_stage': None, 'reported_completed': False,
                'started': time.monotonic(),
            }
            if len(self.entries) > 32:
                del self.entries[min(self.entries)]
            self.operation = key
            if connected:
                # The session ends: its routes are removed (devices stay).
                self.routes = [r for r in self.routes if not r['owned']]
            self.phase = 'preparing' if effective == 'connect' else 'stopping'
            self.publish()
            reply = self.reply(True, 'accepted', operation=self.operation_view(key))
        threading.Thread(target=self.drive, args=(key,), daemon=True).start()
        return reply

    def finish(self, key: int, result: dict, phase: str) -> None:
        entry = self.entries[key]
        if entry['setup']:
            entry['setup']['outcome'] = {'connected': 'ready', 'failed': 'failed', 'cancelled': 'cancelled'}.get(result['outcome'], 'owner_closed')
            entry['setup']['elapsed_micros'] = int((time.monotonic() - entry['started']) * 1e6)
        entry['result'] = result
        self.operation = None
        if phase == 'connected':
            self.connected_at = time.monotonic()
            self.generation = key
        self.phase = phase
        self.publish()

    def drive(self, key: int) -> None:
        with self.lock:
            kind = self.entries[key]['kind']
        if kind in {'disconnect', 'reconnect'}:
            time.sleep(self.step)
            with self.lock:
                self.terminal = {'kind': 'aborted'}
                if kind == 'disconnect':
                    self.finish(key, {'outcome': 'aborted'}, 'disconnected')
                    return
                self.phase = 'preparing'
                self.publish()
        for index, stage in enumerate(SETUP_STAGES):
            time.sleep(self.step)
            with self.lock:
                entry = self.entries[key]
                if self.closed:
                    return
                if entry['cancel']:
                    self.finish(key, {'outcome': 'cancelled'}, 'disconnected')
                    return
                if index == 1:
                    self.phase = 'authenticating'
                entry['setup']['stage'] = stage
                entry['setup']['elapsed_micros'] = int((time.monotonic() - entry['started']) * 1e6)
                if self.fail_connect and stage == 'noise':
                    entry['setup']['failure'] = 'timed_out:Unknown'
                    self.terminal = None
                    self.finish(key, {'outcome': 'failed', 'error_kind': 'timed_out'}, 'failed')
                    return
                self.publish()
        time.sleep(self.step)
        with self.lock:
            entry = self.entries[key]
            if entry['cancel']:
                self.finish(key, {'outcome': 'cancelled'}, 'disconnected')
                return
            entry['setup']['stage'] = 'ready_publication'
            self.generation = key
            self.terminal = None
            self.finish(key, {'outcome': 'connected', 'generation': key}, 'connected')

    def lookup(self, operation: int, service: str | None) -> dict | None:
        if service is not None and service != self.instance:
            return self.reply(False, 'service_restarted')
        if operation not in self.entries:
            return self.reply(False, 'unknown_operation')
        return None

    def uptime_ms(self) -> int:
        return int((time.monotonic() - self.started) * 1000)

    def socks_status_view(self) -> dict:
        proxy_active = (not self.server) and self.phase == 'connected'
        listening = None
        if proxy_active and self.socks_settings['enabled']:
            listening = f"{self.socks_settings['listen_host']}:{self.socks_settings['listen_port']}"
        settings = {k: v for k, v in self.socks_settings.items() if v is not None}
        settings['password_set'] = self.socks_password is not None
        status = {
            'proxy_active': proxy_active,
            'settings': settings,
            'active_flows': 1 if listening else 0,
            'total_flows': 2 if listening else 0,
            'rejected_clients': 0,
            'failed_connects': 1 if listening else 0,
        }
        if listening:
            status['listening'] = listening
        if self.socks_error:
            status['last_error'] = self.socks_error
        return status

    def socks_flows_view(self) -> dict:
        proxy_active = (not self.server) and self.phase == 'connected'
        if not (proxy_active and self.socks_settings['enabled']):
            return {'flows': [], 'total_active': 0}
        age = max(100, int((time.monotonic() - (self.connected_at or time.monotonic())) * 1000))
        return {
            'total_active': 1,
            'flows': [
                {
                    'id': 1,
                    'client': '127.0.0.1:53122',
                    'target': 'example.org:443',
                    'sent_bytes': 3_145_728,
                    'received_bytes': 41_943_040,
                    'state': 'open',
                    'age_ms': age,
                },
                {
                    'id': 2,
                    'client': '127.0.0.1:53124',
                    'target': '192.0.2.99:25',
                    'sent_bytes': 0,
                    'received_bytes': 0,
                    'state': 'refused',
                    'age_ms': max(50, age // 2),
                    'error': 'connection refused by egress policy (simulated)',
                },
            ],
        }

    def socks_apply(self, settings: dict) -> dict:
        if self.server:
            return self.reply(False, 'unsupported', socks=self.socks_status_view())
        proxy_active = self.phase == 'connected'
        enabled = bool(settings.get('enabled', False))
        if enabled and not proxy_active:
            self.socks_error = 'SOCKS5 needs a connected TCP-proxy profile'
            return self.reply(False, 'not_proxy_profile', socks=self.socks_status_view())
        auth_mode = settings.get('auth_mode', 'none')
        if auth_mode == 'user_pass':
            if not settings.get('username'):
                self.socks_error = 'username is required'
                return self.reply(False, 'invalid_settings', socks=self.socks_status_view())
            if settings.get('password'):
                self.socks_password = settings['password']
            elif self.socks_password is None:
                self.socks_error = 'password is required'
                return self.reply(False, 'invalid_settings', socks=self.socks_status_view())
        else:
            self.socks_password = None
        self.socks_settings = {
            'enabled': enabled,
            'listen_host': settings.get('listen_host', '127.0.0.1'),
            'listen_port': int(settings.get('listen_port', 1080)),
            'auth_mode': auth_mode,
            'username': settings.get('username') if auth_mode == 'user_pass' else None,
            'password_set': self.socks_password is not None,
            'allowed_clients': list(settings.get('allowed_clients', ['127.0.0.1/32'])),
            'max_flows': int(settings.get('max_flows', 128)),
        }
        self.socks_error = None
        return self.reply(True, 'ok', socks=self.socks_status_view())

    def carrier_switch_view(self) -> dict:
        reason = 'client initiates live carrier switches' if self.server else None
        def udp(cid: str, label: str) -> dict:
            item = {'id': cid, 'label': label, 'available': reason is None}
            if reason:
                item['reason'] = reason
            return item
        return {
            'current_carrier': 'udp',
            'current_cover': self.carrier_cover,
            'local': f'127.0.0.1:{41000 + self.carrier_switches}',
            'peer': f'127.0.0.1:{51820 + self.carrier_switches}',
            'switches': self.carrier_switches,
            'choices': [
                udp('quic-like', 'UDP · QUIC-like'),
                udp('media-like', 'UDP · Media-like (RTP)'),
                udp('tls-like', 'UDP · TLS-like'),
                {'id': 'tcp', 'label': 'TCP / TLS', 'available': False,
                 'reason': 'requires TLS credentials (--cert/--key/--ca) and a TCP listener'},
                {'id': 'quic', 'label': 'QUIC (Quinn)', 'available': False,
                 'reason': 'requires TLS credentials (--cert/--key/--ca) and a QUIC listener'},
            ],
        }

    def carrier_switch_apply(self, target: str) -> dict:
        if self.phase != 'connected':
            return self.reply(False, 'not_running')
        if self.server:
            return self.reply(False, 'not_coordinator')
        if target not in {'quic-like', 'media-like', 'tls-like'}:
            return self.reply(False, 'invalid_target')
        self.carrier_cover = target
        self.carrier_switches += 1
        return self.reply(True, 'ok', status=self.status_view(), carrier_switch=self.carrier_switch_view())

    def info_view(self) -> dict:
        def capability(feature: str, reason: str | None) -> dict:
            if reason is None:
                return {'feature': feature, 'available': True}
            return {'feature': feature, 'available': False, 'reason': reason}
        connected = self.phase == 'connected'
        not_simulated = 'FAKE service: not simulated'
        return {
            'version': 'fake', 'role': 'server' if self.server else 'client', 'api': 5,
            'uptime_ms': self.uptime_ms(),
            'capabilities': [
                capability('lifecycle', None),
                capability('catalog', not_simulated),
                capability('metrics', None if connected else 'needs a running Common profile'),
                capability('meters', None if connected else 'needs a running Common profile'),
                capability('devices', None),
                capability('routes', None),
                capability('profiles', None),
                capability('keys', None),
                capability(
                    'socks5',
                    'client role only' if self.server else (
                        None if connected else 'SOCKS5 needs a connected TCP-proxy profile'
                    ),
                ),
                capability('sessions', None if self.server else 'server role only'),
                capability('stop', not_simulated),
                capability('tests', None if connected else 'needs a connected session'),
            ],
        }

    # --- tunnel tests (SIMULATED: fixed shapes so the GUI and CLI can be shown) --
    def test_view(self) -> dict | None:
        test = self.test
        if test is None:
            return None
        now = test['ended'] if test['ended'] is not None else time.monotonic()
        elapsed = now - test['start']
        request = test['request']
        view = {'id': test['id'], 'kind': request['kind'], 'state': test['state'],
                'elapsed_ms': int(elapsed * 1000), 'bytes': 0, 'bits_per_second': 0, 'samples': []}
        if request['kind'] == 'speed':
            seconds = request['duration_ms'] / 1000
            measured = min(elapsed, seconds)
            # SIMULATED 40 Mbit/s per stream (capped at 150), with a ripple.
            rate = min(40_000_000 * request['streams'], 150_000_000)
            samples = [int(rate * (0.9 + 0.1 * ((i * 7) % 3))) for i in range(int(measured))]
            total = int(rate / 8 * measured)
            view.update(direction=request['direction'], streams=request['streams'],
                        duration_ms=request['duration_ms'], bytes=total, samples=samples,
                        bits_per_second=int(total * 8 / elapsed) if elapsed > 0 else 0)
            if test['state'] == 'running' and elapsed >= seconds + 0.3:
                test['state'], test['ended'] = 'completed', test['start'] + seconds + 0.3
                return self.test_view()
        else:
            interval = request['interval_ms'] / 1000
            sent = min(request['count'], int(elapsed / interval) + 1)
            # SIMULATED 20-24 ms round trips; every seventh probe is lost.
            rtts = [None if i % 7 == 6 else 20_000 + (i * 1_300) % 4_000 for i in range(sent)]
            answered = [rtt for rtt in rtts if rtt is not None]
            ping = {'sent': sent, 'received': len(answered), 'rtts_us': rtts}
            if answered:
                ping.update(min_us=min(answered), avg_us=sum(answered) // len(answered), max_us=max(answered))
            view['ping'] = ping
            if test['state'] == 'running' and sent == request['count'] and elapsed >= (sent - 1) * interval + 0.05:
                test['state'], test['ended'] = 'completed', time.monotonic()
                return self.test_view()
        if test.get('error'):
            view['error'] = test['error']
        return view

    def test_start(self, request: dict) -> dict:
        kind = request.get('kind')
        valid = (kind == 'speed' and request.get('direction') in {'upload', 'download'}
                 and 1 <= request.get('streams', 0) <= 8 and 1_000 <= request.get('duration_ms', 0) <= 30_000
                 and set(request) == {'kind', 'direction', 'streams', 'duration_ms'}) or \
                (kind == 'ping' and 1 <= request.get('count', 0) <= 100 and 100 <= request.get('interval_ms', 0) <= 1_000
                 and set(request) == {'kind', 'count', 'interval_ms'})
        if not valid:
            return self.reply(False, 'invalid_test')
        if self.phase != 'connected':
            return self.reply(False, 'not_connected')
        current = self.test_view()
        if current is not None and current['state'] == 'running':
            return self.reply(False, 'busy', test={'test': current})
        self.test_ids += 1
        self.test = {'id': self.test_ids, 'request': request, 'start': time.monotonic(),
                     'state': 'running', 'ended': None}
        return self.reply(True, 'accepted', test={'test': self.test_view()})

    def metrics_view(self) -> dict:
        # SIMULATED counters: a steady ~4 Mb/s upload so charts move in demos.
        seconds = time.monotonic() - (self.connected_at or time.monotonic())
        sent = int(seconds * 500_000)
        wire = {
            'sent_packets': sent // 1200, 'sent_bytes': sent, 'accepted_packets': sent // 1200,
            'accepted_bytes': sent, 'send_drops': 0, 'received_packets': sent // 2400,
            'receive_errors': 0, 'rejected_packets': 0, 'replay_rejections': 0,
        }
        return {
            'generation': self.generation or 0, 'sampled_ms': self.uptime_ms(), 'carrier': 'fake',
            'wire': wire,
            'device': {'read_packets': sent // 1300, 'written_packets': sent // 2600,
                       'oversize': 0, 'backpressure_drops': 0, 'pending_packets': 0,
                       'pending_bytes': 0},
            'send_channels': 2, 'receive_channels': 2,
            'lanes': [{'lane': 0, 'carrier': 'fake', 'local': '127.0.0.1:0',
                       'remote': '127.0.0.1:0', 'wire': wire}],
            'channels': [], 'flows': [],
            'unreported': ['rtt', 'channel_counters', 'flow_counters'],
        }

    # --- SIMULATED meter CSR (docs/modules/meter-csr.md) ------------------------
    def meters_table(self, side: str) -> dict[str, int]:
        """SIMULATED registers with real catalog paths; values only move."""
        seconds = time.monotonic() - (self.connected_at or time.monotonic())
        scale = 1 if side == 'local' else 2  # the FAKE peer sends twice as much
        sent = int(seconds * 500_000) * scale
        table = {
            'meta.version': 1, 'meta.sampled_us': int(seconds * 1_000_000),
            'runtime.session.elapsed_us': int(seconds * 1_000_000),
            'runtime.session.send_rate': 625_000 * scale, 'runtime.session.receive_rate': 625_000,
            'runtime.session.send_channels': 2, 'runtime.session.receive_channels': 2,
        }
        for name, value in (('sent_packets', sent // 1200), ('sent_bytes', sent),
                            ('accepted_packets', sent // 1200), ('accepted_bytes', sent),
                            ('send_drops', 0), ('received_packets', sent // 2400),
                            ('receive_errors', 0), ('rejected_packets', 0), ('replay_rejections', 0)):
            table[f'runtime.wire.shared.{name}'] = value
        for name, value in (('read_packets', sent // 1300), ('written_packets', sent // 2600),
                            ('oversize', 0), ('backpressure_drops', 0), ('pending_packets', 0),
                            ('pending_bytes', 0)):
            table[f'runtime.device.{name}'] = value
        base = 'runtime.native_ingress.lane0.user'
        waits = int(seconds * 10)
        table.update({
            f'{base}.samples': waits * 4, f'{base}.occupancy_bytes': (waits * 37) % 65536,
            f'{base}.high_water_bytes': 65536, f'{base}.capacity_bytes': 131072,
            f'{base}.refusals': waits, f'{base}.untimed_refusals': 0, f'{base}.progress': waits,
        })
        wait = f'{base}.wait.buffer_capacity'
        table.update({
            f'{wait}.episodes': waits, f'{wait}.completed_episodes': waits,
            f'{wait}.censored_episodes': 0, f'{wait}.completed_us': waits * 300,
            f'{wait}.censored_us': 0, f'{wait}.open_us': 0, f'{wait}.max_us': 4000,
            f'{wait}.invalid': 0,
        })
        for bucket in range(24):
            table[f'{wait}.hist.b{bucket:02}'] = waits // 2 if bucket in (7, 8) else 0
        for channel in range(2):
            ch = f'mux.channel.ch{channel}.tx'
            table.update({f'{ch}.packets': sent // 2400, f'{ch}.bytes': sent // 2,
                          f'{ch}.admitted': sent // 2400, f'{ch}.refused': waits,
                          f'{ch}.queued_bytes': (waits * 11) % 8192})
        return dict(sorted(table.items()))

    @staticmethod
    def meter_path_ok(path: str, prefix: bool) -> bool:
        if prefix and path == '':
            return True
        limit = 96 if prefix else 128
        segments = path.split('.')
        return (0 < len(path) <= limit and len(segments) <= 10
                and all(segment and all(c in 'abcdefghijklmnopqrstuvwxyz0123456789_' for c in segment)
                        for segment in segments))

    def meters_read(self, action: dict) -> dict:
        side, prefix, cursor = action.get('side'), action.get('prefix', ''), action.get('cursor')
        limit = action.get('limit')
        if type(limit) is not int or not 1 <= limit <= 256:
            return self.reply(False, 'invalid_limit')
        if side not in ('local', 'remote') or not self.meter_path_ok(prefix, True):
            return self.reply(False, 'invalid_prefix')
        def under(path: str) -> bool:
            return prefix == '' or path == prefix or path.startswith(prefix + '.')
        if cursor is not None and (not self.meter_path_ok(cursor, False) or not under(cursor)):
            return self.reply(False, 'invalid_cursor')
        if self.phase != 'connected':
            return self.reply(False, 'not_running')
        matching = [(path, value) for path, value in self.meters_table(side).items()
                    if under(path) and (cursor is None or path > cursor)]
        page, rest = matching[:limit], matching[limit:]
        return self.reply(True, 'ok', meters={
            'side': side, 'generation': self.generation or 0, 'sampled_ms': self.uptime_ms(),
            'age_ms': 0, 'entries': [{'path': path, 'value': value} for path, value in page],
            **({'next': page[-1][0]} if rest and page else {}),
        })

    METER_CATALOG = (
        ('meta.version', 'state', 'code', 'meta', 'meter-csr'),
        ('runtime.wire.{lane}.sent_bytes', 'counter', 'bytes', 'carrier', 'metrics'),
        ('runtime.native_ingress.{lane}.{class}.occupancy_bytes', 'gauge', 'bytes', 'buffer', 'BP-14'),
        ('runtime.native_ingress.{lane}.{class}.wait.{reason}.hist.{bucket}', 'bucket', 'count', 'buffer', 'BP-14'),
        ('mux.channel.{ch}.{dir}.queued_bytes', 'gauge', 'bytes', 'mux', 'BP-01'),
    )

    def meters_catalog(self, action: dict) -> dict:
        prefix, cursor, limit = action.get('prefix', ''), action.get('cursor') or 0, action.get('limit')
        if type(limit) is not int or not 1 <= limit <= 256:
            return self.reply(False, 'invalid_limit')
        if not self.meter_path_ok(prefix, True):
            return self.reply(False, 'invalid_prefix')
        rows = [(index, row) for index, row in enumerate(self.METER_CATALOG)
                if index >= cursor and (prefix == '' or row[0].startswith(prefix))]
        page, rest = rows[:limit], rows[limit:]
        return self.reply(True, 'ok', meter_catalog={
            'version': 1,
            'entries': [{'pattern': row[0], 'kind': row[1], 'unit': row[2], 'family': row[3],
                         'row': row[4], 'state': 'reported'} for _, row in page],
            **({'next': rest[0][0]} if rest else {}),
        })

    # --- simulated devices and routes ------------------------------------------
    def apply_host(self, kind: str, change: dict) -> dict:
        op = change.get('op')
        def refused(reason: str) -> dict:
            return {'outcome': 'host_refused', 'reason': reason}
        if kind == 'device':
            name = change['name']
            device = self.devices.get(name)
            if op == 'create':
                if device is not None:
                    return refused(f'{name} already exists')
                self.devices[name] = {'name': name, 'layer': change['layer'], 'mtu': change.get('mtu'),
                                      'up': change['up'], 'addresses': list(change.get('addresses', [])),
                                      'owned': True}
                return {'outcome': 'host_applied', 'summary': f'created {name} (FAKE)'}
            if device is None or not device['owned']:
                return refused(f'{name} is not owned by this service')
            if op == 'configure':
                if change.get('mtu') is not None:
                    device['mtu'] = change['mtu']
                device['addresses'] = [a for a in device['addresses'] if a not in change.get('remove', [])]
                device['addresses'] += [a for a in change.get('add', []) if a not in device['addresses']]
                if change.get('up') is not None:
                    device['up'] = change['up']
                return {'outcome': 'host_applied', 'summary': f'configured {name} (FAKE)'}
            del self.devices[name]
            self.routes = [r for r in self.routes if r['device'] != name]
            return {'outcome': 'host_applied', 'summary': f'deleted {name} (FAKE)'}
        device = change['device']
        if device not in self.devices:
            return refused(f'{device} does not exist')
        if op == 'add':
            self.routes.append({'destination': change['destination'], 'gateway': change.get('gateway'),
                                'device': device, 'metric': change.get('metric'), 'owned': True,
                                'purpose': 'route'})
            return {'outcome': 'host_applied', 'summary': f"route {change['destination']} via {device} (FAKE)"}
        if op == 'remove':
            before = len(self.routes)
            self.routes = [r for r in self.routes if not (r['owned'] and r['destination'] == change['destination']
                                                          and r['device'] == device)]
            if len(self.routes) == before:
                return refused('not owned by this service')
            return {'outcome': 'host_applied', 'summary': 'removed (FAKE)'}
        self.routes = [r for r in self.routes if r.get('purpose') not in {'default', 'peer_exception'}]
        if change['enabled']:
            self.routes.append({'destination': '198.51.100.7/32', 'gateway': '192.0.2.1', 'device': 'fake-eth0',
                                'metric': None, 'owned': True, 'purpose': 'peer_exception'})
            for half in ('0.0.0.0/1', '128.0.0.0/1'):
                self.routes.append({'destination': half, 'gateway': None, 'device': device, 'metric': None,
                                    'owned': True, 'purpose': 'default'})
        return {'outcome': 'host_applied', 'summary': 'default routing changed (FAKE)'}

    def apply_profile(self, change: dict) -> dict:
        op, name = change['op'], change.get('name')
        def refused(reason: str) -> dict:
            return {'outcome': 'profile_refused', 'reason': reason}
        stored = self.profiles.get(name) if name else None
        if op == 'save':
            current = stored['revision'] if stored else None
            if current != change.get('expected_revision'):
                return refused(f'{name} is at revision {current}' if stored else f'{name} does not exist')
            revision = (current or 0) + 1
            self.profiles[name] = {'revision': revision, 'document': change['document']}
            return {'outcome': 'profile_applied', 'summary': f'saved {name} at revision {revision} (FAKE)'}
        if op == 'delete':
            if not stored or stored['revision'] != change['expected_revision']:
                return refused('revision mismatch or missing')
            del self.profiles[name]
            if self.default_profile == name:
                self.default_profile = None
            return {'outcome': 'profile_applied', 'summary': f'deleted {name} (FAKE)'}
        if name is not None and not stored:
            return refused(f'{name} does not exist')
        self.default_profile = name
        return {'outcome': 'profile_applied', 'summary': 'default changed (FAKE)'}

    def profile_rows(self) -> list[dict]:
        rows = []
        for name, stored in sorted(self.profiles.items()):
            document = stored['document']
            options = document['options']
            rows.append({'name': name, 'revision': stored['revision'], 'version': document['version'],
                         'role': document['role'], 'default': name == self.default_profile, 'editable': True,
                         'summary': ' · '.join(part for part in (options.get('--carrier', 'no carrier'),
                                                                  options.get('--device')) if part) + ' (FAKE)'})
            if options.get('--device'):
                rows[-1]['device'] = options['--device']
        return rows

    def sessions_view(self) -> list[dict]:
        if self.phase != 'connected' or self.generation is None:
            return []
        session = {'generation': self.generation, 'peer': '198.51.100.7:5121',
                   'connected_ms': int((time.monotonic() - (self.connected_at or time.monotonic())) * 1000)}
        if self.active_profile:
            session['profile'] = self.active_profile
            allow = self.profiles.get(self.active_profile, {}).get('document', {}).get('options', {}).get('--allow-key')
            if allow:
                # SIMULATED: a stable stand-in for the key, derived from the path.
                session['member'] = hashlib.sha256(allow.encode()).hexdigest()
        wire = self.metrics_view().get('wire') or {}
        if wire:
            session['sent_bytes'] = wire['sent_bytes']
            session['received_bytes'] = wire['accepted_bytes']
        return [session]

    def submit_host(self, kind: str, key: int, change: dict) -> dict:
        if key == 0:
            return self.reply(False, 'invalid_request_key')
        request = (kind, json.dumps(change, sort_keys=True))
        with self.lock:
            if key <= self.last_key:
                entry = self.entries.get(key)
                if entry is None:
                    return self.reply(False, 'expired_key')
                if entry['request'] != request:
                    return self.reply(False, 'conflict')
                return self.reply(True, 'accepted', operation=self.operation_view(key))
            if key != self.last_key + 1:
                return self.reply(False, 'future_key')
            if self.operation is not None or self.phase == 'stopping':
                return self.reply(False, 'busy')
            if kind == 'route' and self.phase != 'connected':
                return self.reply(False, 'state')
            if kind == 'profile' and change.get('op') == 'save' and not change.get('document', {}).get('options'):
                return self.reply(False, 'invalid_change')
            self.last_key = key
            self.entries[key] = {
                'kind': kind, 'request': request, 'cancel': False, 'result': None, 'deadline': None,
                'setup': None, 'reported_accepted': False, 'reported_stage': None,
                'reported_completed': False, 'started': time.monotonic(),
            }
            self.operation = key
            self.publish()
            reply = self.reply(True, 'accepted', operation=self.operation_view(key))

        def complete() -> None:
            time.sleep(self.step)
            with self.lock:
                result = self.apply_profile(change) if kind == 'profile' else self.apply_host(kind, change)
                self.finish(key, result, self.phase)
        threading.Thread(target=complete, daemon=True).start()
        return reply

    def handle(self, request: dict) -> dict:
        action = request['action']
        command = action.get('command')
        if command == 'device_list':
            with self.lock:
                return self.reply(True, 'ok', devices=[dict(d) for d in self.devices.values()])
        if command == 'route_list':
            with self.lock:
                return self.reply(True, 'ok', routes=[dict(r) for r in self.routes])
        if command in {'device', 'route', 'profile'}:
            return self.submit_host(command, int(action['request_key']), action['change'])
        if command == 'profile_list':
            with self.lock:
                return self.reply(True, 'ok', profiles=self.profile_rows())
        if command in {'profile_get', 'profile_validate', 'profile_keys'}:
            with self.lock:
                stored = self.profiles.get(action['name'])
                if stored is None:
                    return self.reply(False, 'unknown_profile')
                if command == 'profile_get':
                    return self.reply(True, 'ok', profile={'name': action['name'], 'revision': stored['revision'],
                                                           'document': stored['document']})
                if command == 'profile_validate':
                    return self.reply(True, 'ok', check={'valid': True, 'summary': 'FAKE: not validated'})
                return self.reply(True, 'ok', keys=[])
        if command == 'profile_connect':
            name, replace = action['name'], bool(action.get('replace', False))
            with self.lock:
                if name not in self.profiles:
                    return self.reply(False, 'invalid_profile',
                                      check={'valid': False, 'summary': name, 'reason': f'{name} does not exist'})
                if self.phase == 'connected' and not replace:
                    return self.reply(False, 'state')
            return self.submit('reconnect' if replace else 'connect', int(action['request_key']),
                               request=('profile_connect', name, replace), profile=name)
        if command == 'session_list':
            if not self.server:
                return self.reply(False, 'unsupported')
            with self.lock:
                return self.reply(True, 'ok', sessions=self.sessions_view())
        if command == 'session_kick':
            if not self.server:
                return self.reply(False, 'unsupported')
            with self.lock:
                if self.phase != 'connected' and int(action['request_key']) > self.last_key:
                    return self.reply(False, 'state')
            return self.submit('reconnect', int(action['request_key']), request='session_kick',
                               reported='session_kick')
        if command == 'status':
            with self.lock:
                return self.reply(True, 'ok', status=self.status_view())
        if command == 'test_start':
            with self.lock:
                return self.test_start(action['test'])
        if command in {'test_get', 'test_cancel'}:
            with self.lock:
                view = self.test_view()
                wanted = action.get('id')
                if view is None or (wanted is not None and wanted != view['id']):
                    return self.reply(False, 'unknown_test')
                if command == 'test_cancel':
                    if view['state'] != 'running':
                        return self.reply(False, 'completed', test={'test': view})
                    self.test['state'], self.test['ended'] = 'cancelled', time.monotonic()
                    view = self.test_view()
                return self.reply(True, 'ok', test={'test': view})
        if command == 'service_info':
            with self.lock:
                return self.reply(True, 'ok', info=self.info_view())
        if command == 'socks_get':
            with self.lock:
                return self.reply(True, 'ok', socks=self.socks_status_view())
        if command == 'socks_set':
            with self.lock:
                return self.socks_apply(action['settings'])
        if command == 'socks_flows':
            with self.lock:
                return self.reply(True, 'ok', socks_flows=self.socks_flows_view())
        if command == 'carrier_switch_get':
            with self.lock:
                if self.phase != 'connected':
                    return self.reply(False, 'not_running')
                return self.reply(True, 'ok', carrier_switch=self.carrier_switch_view())
        if command == 'carrier_switch':
            with self.lock:
                return self.carrier_switch_apply(action.get('target', ''))
        if command == 'meters_read':
            with self.lock:
                return self.meters_read(action)
        if command == 'meters_catalog':
            with self.lock:
                return self.meters_catalog(action)
        if command == 'metrics':
            with self.lock:
                if self.phase != 'connected':
                    return self.reply(False, 'not_running')
                return self.reply(True, 'ok', metrics=self.metrics_view())
        if command in {'connect', 'reconnect', 'disconnect', 'drain_proxy'}:
            return self.submit(command, int(action['request_key']))
        if command in {'switch_common_configuration', 'reuse_connection', 'catalog'}:
            return self.reply(False, 'unsupported')
        service = action.get('service')
        if command == 'operation_get':
            with self.lock:
                return self.lookup(action['operation'], service) or self.reply(True, 'ok', operation=self.operation_view(action['operation']))
        if command == 'operation_wait':
            timeout = action['timeout_ms']
            if not 1 <= timeout <= WAIT_LIMIT_MS:
                return self.reply(False, 'invalid_timeout')
            deadline = time.monotonic() + timeout / 1000
            with self.lock:
                refusal = self.lookup(action['operation'], service)
                if refusal:
                    return refusal
                entry = self.entries[action['operation']]
                while not entry['result'] and not self.closed and time.monotonic() < deadline:
                    self.lock.wait(max(0.0, deadline - time.monotonic()))
                code = 'completed' if entry['result'] else ('closed' if self.closed else 'running')
                return self.reply(True, code, operation=self.operation_view(action['operation']))
        if command == 'operation_cancel':
            with self.lock:
                refusal = self.lookup(action['operation'], service)
                if refusal:
                    return refusal
                entry = self.entries[action['operation']]
                if entry['result']:
                    return self.reply(False, 'completed', operation=self.operation_view(action['operation']))
                if entry['kind'] not in {'connect', 'reconnect'}:
                    return self.reply(False, 'cancel_unsupported', operation=self.operation_view(action['operation']))
                entry['cancel'] = True
                return self.reply(True, 'cancel_requested', operation=self.operation_view(action['operation']))
        if command == 'events':
            if service is not None and service != self.instance:
                return self.reply(False, 'service_restarted')
            after, limit, timeout = action['after'], action['limit'], action['timeout_ms']
            if not 1 <= limit <= 32 or timeout > WAIT_LIMIT_MS:
                return self.reply(False, 'invalid_page')
            deadline = time.monotonic() + timeout / 1000
            with self.lock:
                while self.sequence <= after and not self.closed and time.monotonic() < deadline:
                    self.lock.wait(max(0.0, deadline - time.monotonic()))
                oldest = self.events[0]['sequence'] if self.events else self.sequence + 1
                gap = after + 1 < oldest and after < self.sequence
                page = [event for event in self.events if event['sequence'] > after][:limit]
                batch = {'events': page, 'next': page[-1]['sequence'] if page else min(after, self.sequence), 'gap': gap}
                return self.reply(True, 'gap' if gap else 'ok', events=batch, status=self.status_view() if gap else None)
        return self.reply(False, 'unsupported')

    def close(self) -> None:
        with self.lock:
            self.closed = True
            for key, entry in self.entries.items():
                if not entry['result']:
                    self.finish(key, {'outcome': 'cancelled' if entry['setup'] else 'outcome_unknown'}, 'closed')
            self.phase = 'closed'
            self.publish()


def read_exact(connection: socket.socket, count: int) -> bytes:
    data = b''
    while len(data) < count:
        chunk = connection.recv(count - len(data))
        if not chunk:
            raise ConnectionError('closed')
        data += chunk
    return data


class Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        connection: socket.socket = self.request
        credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
        if struct.unpack('3i', credentials)[1] != os.geteuid():
            return
        connection.settimeout(5)
        try:
            (count,) = struct.unpack('>I', read_exact(connection, 4))
            if not 0 < count <= REQUEST_LIMIT:
                return
            request = json.loads(read_exact(connection, count))
        except (OSError, ConnectionError, ValueError):
            return
        if type(request) is not dict or request.get('version') != VERSION or type(request.get('action')) is not dict:
            return  # versions 1/4 and malformed requests: closed without reply
        server = self.server
        if not isinstance(server, Server):
            return
        try:
            reply = server.service.handle(request)
        except (KeyError, TypeError, ValueError):
            return
        body = json.dumps(reply, separators=(',', ':')).encode()
        if len(body) > REPLY_LIMIT:
            return
        connection.settimeout(5)
        try:
            connection.sendall(struct.pack('>I', len(body)) + body)
        except OSError:
            pass


class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, path: Path, service: FakeService):
        self.service = service
        super().__init__(str(path), Handler)
        os.chmod(path, 0o600)


def serve(path: Path, service: FakeService) -> Server:
    """Bind in an owned private directory and serve in a background thread."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.stat().st_uid != os.geteuid() or path.parent.stat().st_mode & 0o077:
        raise SystemExit(f'{path.parent} must be a private directory owned by this user')
    if path.is_socket():
        path.unlink()
    server = Server(path, service)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--socket', default='/tmp/l2tunnel-gui-demo/api.sock')
    parser.add_argument('--step', type=float, default=0.5, help='seconds per simulated setup stage')
    parser.add_argument('--fail-connect', action='store_true', help='simulate setup failing at the noise stage')
    parser.add_argument('--server', action='store_true', help='simulate the server role (sessions)')
    args = parser.parse_args()
    path = Path(args.socket)
    service = FakeService(args.step, args.fail_connect, args.server)
    server = serve(path, service)
    print(f'FAKE l2tunnel service {service.instance} on {path} (no tunnel, simulated only). Ctrl+C stops.', flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        service.close()
        server.shutdown()
        server.server_close()
        if path.is_socket():
            path.unlink()


if __name__ == '__main__':
    main()
