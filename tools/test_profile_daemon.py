"""The REAL `l2tunneld daemon` (stored profiles, owner decision 2026-11-23)
driven by the real `l2tunnelctl`. Profiles come from
`tools/local_real_pair.py prepare` (fresh demo credentials and a plan exported
from current Rust code), so validation builds real plans. No device, route or
host network state is touched: the TUN devices named in the profiles do not
need to exist, and the one connect attempt has no peer and fails admission."""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest

from tools import local_real_pair

ROOT = Path(__file__).resolve().parents[1]


def binaries() -> Path:
    target = local_real_pair.target()
    if not all((target / name).is_file() for name in ('l2tunneld', 'l2tunnelctl')):
        subprocess.run(['cargo', 'build', '--quiet', '--locked', '-p', 'l2tunneld', '-p', 'l2tunnelctl'],
                       cwd=ROOT, check=True)
    return target


class ProfileDaemonTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.target = binaries()
        cls.pair = tempfile.TemporaryDirectory(prefix='l2tpair-')
        directory = Path(cls.pair.name) / 'pair'
        local_real_pair.prepare(directory, local_real_pair.DEFAULT_ROW)
        sides = json.loads((directory / 'pair.json').read_text())['sides']
        cls.documents = {}
        for side, role in (('a', 'connect'), ('b', 'serve')):
            args = sides[side][1:]
            options = dict(zip(args[0::2], args[1::2]))
            options.pop('--control-socket')
            path = directory / f'profile-{side}.json'
            path.write_text(json.dumps({'version': 1, 'role': role, 'options': options}))
            cls.documents[side] = path

    @classmethod
    def tearDownClass(cls):
        cls.pair.cleanup()

    def setUp(self):
        # Short path: Unix socket names are length-limited.
        self.directory = tempfile.TemporaryDirectory(prefix='l2tp-', dir='/tmp')
        self.socket = Path(self.directory.name) / 'api.sock'
        self.state = Path(self.directory.name) / 'state'
        self.state.mkdir(mode=0o700)
        self.daemon = None

    def tearDown(self):
        self.stop()
        self.directory.cleanup()

    def start(self):
        self.daemon = subprocess.Popen([str(self.target / 'l2tunneld'), 'daemon', '--control-socket', str(self.socket),
                                        '--state-dir', str(self.state)],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            probe = socket.socket(socket.AF_UNIX)
            try:
                probe.connect(str(self.socket))
                return
            except OSError:
                time.sleep(0.05)
            finally:
                probe.close()
        self.fail('daemon did not listen')

    def stop(self) -> str:
        if self.daemon is None:
            return ''
        self.daemon.terminate()
        _, stderr = self.daemon.communicate(timeout=10)
        self.daemon = None
        if self.socket.exists():
            self.socket.unlink()
        return stderr

    def ctl(self, *args):
        result = subprocess.run([str(self.target / 'l2tunnelctl'), *args, '--control-socket', str(self.socket), '--json'],
                                capture_output=True, text=True, timeout=60)
        return result.returncode, [json.loads(line) for line in result.stdout.splitlines()]

    def test_stored_profiles_round_trip_and_connect(self):
        self.start()
        code, replies = self.ctl('service', 'info')
        capabilities = {item['feature']: item['available'] for item in replies[-1]['info']['capabilities']}
        self.assertEqual((code, replies[-1]['info']['role']), (0, 'unconfigured'))
        self.assertTrue(capabilities['profiles'] and capabilities['lifecycle'])
        for name, side in (('client', 'a'), ('server', 'b')):
            code, replies = self.ctl('profile', 'import', name, '--file', str(self.documents[side]))
            self.assertEqual((code, replies[-1]['operation']['result']['outcome']), (0, 'profile_applied'))
        code, replies = self.ctl('profile', 'list')
        rows = {row['name']: row for row in replies[-1]['profiles']}
        self.assertEqual((rows['client']['role'], rows['server']['role']), ('connect', 'serve'))
        code, replies = self.ctl('profile', 'validate', 'server')
        self.assertEqual((code, replies[-1]['check']['valid']), (0, True))
        # Key files the profile names, with public keys; never private material.
        code, replies = self.ctl('profile', 'keys', 'client')
        keys = {key['option']: key for key in replies[-1]['keys']}
        self.assertEqual(code, 0)
        self.assertEqual(set(keys), {'--identity', '--noise-private-key-file', '--noise-peer-key-file',
                                     '--session-admission-key-file'})
        self.assertTrue(all(key['usable'] for key in keys.values()))
        self.assertEqual(len(keys['--identity']['public']), 64)
        self.assertNotIn('public', keys['--session-admission-key-file'])
        code, replies = self.ctl('profile', 'keys', 'server')
        server = {key['option']: key for key in replies[-1]['keys']}
        self.assertEqual(server['--allow-key']['public'], keys['--identity']['public'],
                         'the server trusts the client member key')
        self.assertEqual(server['--noise-peer-key-file']['public'], keys['--noise-private-key-file']['public'],
                         "the server pins the client's Noise key")
        # Local, unprivileged key generation needs no service.
        generated = Path(self.directory.name)
        result = subprocess.run([str(self.target / 'l2tunnelctl'), 'key', 'generate-noise', '--private',
                                 str(generated / 'n.key'), '--public', str(generated / 'n.pub'), '--json'],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['public'], (generated / 'n.pub').read_bytes().hex())
        result = subprocess.run([str(self.target / 'l2tunnelctl'), 'key', 'generate-secret', '--output',
                                 str(generated / 'n.key')], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 1, 'never overwrites')
        # Stale revision and unrunnable documents are refused; the store is unchanged.
        code, replies = self.ctl('profile', 'import', 'client', '--file', str(self.documents['b']))
        self.assertEqual((code, replies[-1]['operation']['result']['outcome']), (1, 'profile_refused'))
        broken = Path(self.directory.name) / 'broken.json'
        document = json.loads(self.documents['a'].read_text())
        document['options']['--noise-private-key-file'] = '/nonexistent/noise.key'
        broken.write_text(json.dumps(document))
        code, replies = self.ctl('profile', 'import', 'broken', '--file', str(broken))
        self.assertEqual(code, 1)
        self.assertIn('not runnable', replies[-1]['operation']['result']['reason'])
        self.assertEqual(self.ctl('profile', 'import', 'x', '--file', str(broken), '--revision', 'z')[0], 2)
        # Export is the importable document; never overwrites.
        exported = Path(self.directory.name) / 'export.json'
        self.assertEqual(self.ctl('profile', 'export', 'client', '--output', str(exported))[0], 0)
        self.assertEqual(json.loads(exported.read_text()), json.loads(self.documents['a'].read_text()))
        self.assertEqual(exported.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.ctl('profile', 'export', 'client', '--output', str(exported))[0], 1)
        # A profile connect is a keyed connect; with no peer it fails admission
        # and the service stays reachable and keeps the plan for reconnect.
        self.assertEqual(self.ctl('profile', 'default', 'client')[0], 0)
        code, replies = self.ctl('service', 'connect', '--profile', 'client', '--watch', '30')
        self.assertEqual(code, 1)
        self.assertEqual(replies[-1]['operation']['kind'], 'connect')
        code, replies = self.ctl('service', 'connect', '--profile', 'nope', '--detach')
        self.assertEqual((code, replies[-1]['code']), (1, 'invalid_profile'))
        code, replies = self.ctl('service', 'info')
        self.assertEqual(replies[-1]['info']['role'], 'client', 'the profile plan is retained')
        # A restarted daemon finds the store and tries the default profile.
        self.assertEqual(self.stop(), '')
        self.start()
        code, replies = self.ctl('profile', 'list')
        self.assertEqual({row['name']: row['default'] for row in replies[-1]['profiles']},
                         {'client': True, 'server': False})
        code, replies = self.ctl('service', 'status')
        self.assertIsNotNone(replies[-1]['status']['next_request_key'])
        code, replies = self.ctl('operation', 'watch', '1', '--timeout', '30')
        self.assertEqual(replies[-1]['operation']['kind'], 'connect', 'default profile connect on start')
        # Server role (DGUI-11): a listening server has no session to list,
        # kick or revoke. A connected pair needs the TUN devices (DGUI-03).
        code, replies = self.ctl('service', 'connect', '--profile', 'server', '--detach')
        self.assertEqual(code, 0, replies)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            status = self.ctl('service', 'status')[1][-1]['status']
            if status['listening'] or status['phase'] in ('failed', 'disconnected'):
                break
            time.sleep(0.1)
        # The server setup operation stays pending while it waits for its member.
        self.assertEqual((status['phase'], bool(status['listening'])), ('authenticating', True), status)
        code, replies = self.ctl('service', 'info')
        capabilities = {item['feature']: item['available'] for item in replies[-1]['info']['capabilities']}
        self.assertEqual((replies[-1]['info']['role'], capabilities['sessions']), ('server', True))
        code, replies = self.ctl('session', 'list')
        self.assertEqual((code, replies[-1]['sessions']), (0, []))
        code, replies = self.ctl('session', 'kick', '--detach')
        self.assertEqual((code, replies[-1]['code']), (1, 'state'))
        code, _ = self.ctl('member', 'revoke', '--allow-key', str(generated / 'n.pub'))
        self.assertEqual(code, 1, 'no live session from a stored profile')
        self.assertEqual(self.ctl('operation', 'cancel', str(status['operation']))[0], 0)
        code, replies = self.ctl('operation', 'watch', str(status['operation']), '--timeout', '20')
        self.assertEqual(replies[-1]['operation']['result']['outcome'], 'cancelled')
        self.assertEqual(self.ctl('profile', 'delete', 'server', '--revision', '1')[0], 0)
        self.assertEqual(oct(self.state.stat().st_mode & 0o777), oct(0o700))
        self.assertEqual(sorted(os.listdir(self.state / 'profiles')), ['client.json'])
        # Stop: disconnect, then the daemon process exits by itself.
        code, replies = self.ctl('service', 'info')
        capabilities = {item['feature']: item['available'] for item in replies[-1]['info']['capabilities']}
        self.assertTrue(capabilities['stop'])
        result = subprocess.run([str(self.target / 'l2tunnelctl'), 'service', 'stop', '--watch', '20',
                                 '--control-socket', str(self.socket)], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('service stopped', result.stdout)
        _, stderr = self.daemon.communicate(timeout=10)
        self.assertEqual((self.daemon.returncode, stderr), (0, ''))
        self.daemon = None

    def test_tcp_proxy_profile_reaches_proxy_plan_validation_in_daemon(self):
        """DGUI-10: l2tunneld no longer refuses TCP-proxy profiles as unsupported."""
        self.start()
        policy_path = Path(self.directory.name) / 'proxy-policy.json'
        policy_path.write_text(json.dumps({
            'version': 1,
            'channels': 4,
            'time_wait_reset': 'maintained',
            'routes': [{
                'source': '10.231.255.0/30',
                'destination': '10.231.255.0/30',
                'ports': {'first': 80, 'last': 443},
            }],
        }))
        doc = json.loads(self.documents['a'].read_text())
        doc['options']['--duplex'] = 'full'
        doc['options']['--traffic'] = 'proxy'
        doc['options']['--proxy-policy'] = str(policy_path)
        proxy_profile = Path(self.directory.name) / 'proxy-client.json'
        proxy_profile.write_text(json.dumps(doc))
        code, replies = self.ctl('profile', 'import', 'proxy-client', '--file', str(proxy_profile))
        self.assertEqual(code, 1)
        reason = replies[-1]['operation']['result']['reason']
        self.assertNotIn('does not host yet', reason)
        self.assertIn('Common proxy record capacity differs from actor frames', reason)


if __name__ == '__main__':
    unittest.main()
