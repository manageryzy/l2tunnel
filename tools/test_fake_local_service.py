"""The FAKE local service (tools/fake_local_service.py) against the real,
strict l2tunnelctl: connect progress, cancel, failure, refusal classes and
restart detection. Keeps the GUI development service byte-compatible."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from tools import fake_local_service as fake

ROOT = Path(__file__).resolve().parents[1]


def ctl_binary() -> str:
    binary = Path(os.environ.get('CARGO_TARGET_DIR', ROOT / 'target')).resolve() / 'debug' / 'l2tunnelctl'
    if not binary.is_file():
        subprocess.run(['cargo', 'build', '--quiet', '--locked', '-p', 'l2tunnelctl'], cwd=ROOT, check=True)
    return str(binary)


class FakeServiceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = ctl_binary()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='l2tf-', dir='/tmp')
        self.path = Path(self.directory.name) / 'api.sock'
        self.running = []

    def tearDown(self):
        for service, server in self.running:
            service.close()
            server.shutdown()
            server.server_close()
        self.directory.cleanup()

    def start(self, **options) -> fake.FakeService:
        if self.path.exists():
            self.path.unlink()
        service = fake.FakeService(step_seconds=0.02, **options)
        self.running.append((service, fake.serve(self.path, service)))
        return service

    def ctl(self, *args):
        result = subprocess.run([self.binary, *args, '--control-socket', str(self.path), '--json'],
                                capture_output=True, text=True, timeout=60)
        return result.returncode, [json.loads(line) for line in result.stdout.splitlines()]

    def test_connect_cancel_disconnect_and_refusals(self):
        self.start()
        code, replies = self.ctl('service', 'status')
        self.assertEqual((code, replies[-1]['status']['phase']), (0, 'disconnected'))
        code, replies = self.ctl('service', 'reconnect', '--watch', '10')
        self.assertEqual(code, 0)
        self.assertEqual(replies[-1]['operation']['result'], {'outcome': 'connected', 'generation': 1})
        code, replies = self.ctl('events', '--limit', '32')
        stages = [event['event'].get('stage') for event in replies[-1]['events']['events']]
        self.assertIn('noise', stages)
        self.assertEqual(self.ctl('service', 'connect')[0], 1, 'connect while connected is refused')
        self.assertEqual(self.ctl('service', 'disconnect')[0], 0)
        code, replies = self.ctl('service', 'reconnect', '--detach')
        operation = replies[-1]['operation']['id']
        self.assertEqual(self.ctl('operation', 'cancel', str(operation))[0], 0)
        code, replies = self.ctl('operation', 'watch', str(operation), '--timeout', '10')
        self.assertEqual((code, replies[-1]['operation']['result']['outcome']), (1, 'cancelled'))
        self.assertEqual(self.ctl('service', 'drain-proxy')[0], 6)
        self.assertEqual(self.ctl('operation', 'show', '99')[0], 1)

    def test_simulated_meter_reads_page_local_remote_and_catalog(self):
        self.start()
        self.assertEqual(self.ctl('meters', 'read')[0], 1, 'refused while disconnected')
        self.assertEqual(self.ctl('service', 'reconnect', '--watch', '10')[0], 0)
        code, replies = self.ctl('meters', 'read', 'runtime.native_ingress', '--limit', '5', '--all')
        self.assertEqual(code, 0)
        pages = [reply['meters'] for reply in replies]
        self.assertGreater(len(pages), 1, 'five per page must page')
        paths = [entry['path'] for page in pages for entry in page['entries']]
        self.assertEqual(paths, sorted(set(paths)), 'pages never repeat or reorder')
        self.assertTrue(all(path.startswith('runtime.native_ingress.') for path in paths))
        self.assertNotIn('next', pages[-1])
        code, replies = self.ctl('meters', 'read', 'runtime.native_ingress', '--limit', '5')
        self.assertEqual((code, len(replies)), (0, 1), 'without --all one page')
        code, replies = self.ctl('meters', 'read', 'runtime.session', '--remote')
        self.assertEqual((code, replies[-1]['meters']['side']), (0, 'remote'))
        self.assertEqual(self.ctl('meters', 'read', 'Bad.Prefix')[0], 2, 'usage error')
        self.assertEqual(self.ctl('meters', 'read', '--limit', '0')[0], 2)
        code, replies = self.ctl('meters', 'catalog', '--limit', '2', '--all')
        self.assertEqual(code, 0)
        patterns = [row['pattern'] for reply in replies for row in reply['meter_catalog']['entries']]
        self.assertIn('meta.version', patterns)
        code, replies = self.ctl('meters', 'watch', 'runtime.wire', '--count', '2', '--interval', '1')
        self.assertEqual(code, 0)
        self.assertTrue(all(reply['meters']['side'] == 'local' for reply in replies))

    def test_simulated_speed_and_ping_tests_follow_to_the_end(self):
        self.start()
        self.assertEqual(self.ctl('test', 'ping', '--count', '2')[0], 1, 'refused while disconnected')
        self.assertEqual(self.ctl('service', 'reconnect', '--watch', '10')[0], 0)
        code, replies = self.ctl('test', 'speed', '--seconds', '1', '--streams', '2', '--download')
        self.assertEqual(code, 0)
        final = replies[-1]['test']['test']
        self.assertEqual((final['state'], final['direction'], final['streams']), ('completed', 'download', 2))
        self.assertGreater(final['bits_per_second'], 0)
        code, replies = self.ctl('test', 'ping', '--count', '3', '--interval-ms', '100')
        ping = replies[-1]['test']['test']['ping']
        self.assertEqual((code, ping['sent'], ping['received']), (0, 3, 3))
        code, replies = self.ctl('test', 'speed', '--seconds', '5', '--detach')
        test_id = replies[-1]['test']['test']['id']
        self.assertEqual(self.ctl('test', 'speed', '--seconds', '5', '--detach')[0], 1, 'busy')
        self.assertEqual(self.ctl('test', 'cancel', str(test_id))[0], 0)
        code, replies = self.ctl('test', 'status')
        self.assertEqual((code, replies[-1]['test']['test']['state']), (1, 'cancelled'))
        self.assertEqual(self.ctl('test', 'speed', '--streams', '9')[0], 2, 'usage')

    def test_failure_and_restart_detection(self):
        first = self.start(fail_connect=True)
        code, replies = self.ctl('service', 'reconnect', '--watch', '10')
        self.assertEqual((code, replies[-1]['operation']['result']['outcome']), (1, 'failed'))
        service, server = self.running.pop()
        service.close()
        server.shutdown()
        server.server_close()
        second = self.start()
        self.assertNotEqual(first.instance, second.instance)
        code, _ = self.ctl('events', '--service', first.instance)
        self.assertEqual(code, 5, 'a restarted service refuses the old identity')

    def test_simulated_devices_and_session_routes(self):
        """Nothing changes on this host: the fake service keeps dictionaries."""
        self.start()
        code, replies = self.ctl('device', 'list')
        self.assertEqual(code, 0)
        self.assertEqual([d['name'] for d in replies[-1]['devices']], ['fake-eth0'])
        code, replies = self.ctl('device', 'create', 'l2t0', '--layer', 'tun', '--addresses', '10.88.0.2/24')
        self.assertEqual((code, replies[-1]['operation']['result']['outcome']), (0, 'host_applied'))
        code, replies = self.ctl('device', 'delete', 'fake-eth0')
        self.assertEqual((code, replies[-1]['operation']['result']['outcome']), (1, 'host_refused'))
        self.assertEqual(self.ctl('route', 'default', 'on', '--device', 'l2t0')[0], 1, 'routes need a session')
        self.assertEqual(self.ctl('service', 'reconnect', '--watch', '10')[0], 0)
        code, replies = self.ctl('route', 'default', 'on', '--device', 'l2t0')
        self.assertEqual(code, 0)
        code, replies = self.ctl('route', 'list')
        purposes = sorted(r.get('purpose', '') for r in replies[-1]['routes'] if r['owned'])
        self.assertEqual(purposes, ['default', 'default', 'peer_exception'])
        self.assertEqual(self.ctl('service', 'disconnect')[0], 0)
        code, replies = self.ctl('route', 'list')
        self.assertFalse([r for r in replies[-1]['routes'] if r['owned']], 'session routes are released')

    def test_diagnostics_export_is_redacted_and_never_overwrites(self):
        self.start()
        self.assertEqual(self.ctl('service', 'reconnect', '--watch', '10')[0], 0)
        report = Path(self.directory.name) / 'report.json'
        code, replies = self.ctl('diagnostics', 'export', '--output', str(report))
        self.assertEqual((code, replies[-1]), (0, {'written': str(report)}))
        self.assertEqual(report.stat().st_mode & 0o777, 0o600)
        data = json.loads(report.read_text())
        self.assertEqual((data['format'], data['addresses']), ('l2tunnel-diagnostics', 'redacted'))
        self.assertTrue(data['events'] and data['operations'] and data['metrics'])
        self.assertNotIn('192.0.2.10', report.read_text())
        self.assertEqual(self.ctl('diagnostics', 'export', '--output', str(report))[0], 1, 'never overwrites')
        full = Path(self.directory.name) / 'full.json'
        self.assertEqual(self.ctl('diagnostics', 'export', '--output', str(full), '--include-addresses')[0], 0)
        self.assertIn('192.0.2.10/24', full.read_text())
    def test_simulated_server_sessions_kick_and_revoke(self):
        """Server role: one live session; kick and the composite member revoke."""
        self.start(server=True)
        document = Path(self.directory.name) / 'server.json'
        document.write_text(json.dumps({'version': 1, 'role': 'serve',
                                        'options': {'--carrier': 'quic-like', '--allow-key': '/keys/old.pub'}}))
        self.assertEqual(self.ctl('profile', 'import', 'server', '--file', str(document))[0], 0)
        code, replies = self.ctl('session', 'list')
        self.assertEqual((code, replies[-1]['sessions']), (0, []))
        self.assertEqual(self.ctl('session', 'kick')[0], 1, 'no live session to kick')
        self.assertEqual(self.ctl('service', 'connect', '--profile', 'server', '--watch', '10')[0], 0)
        code, replies = self.ctl('session', 'list')
        [session] = replies[-1]['sessions']
        self.assertEqual(session['profile'], 'server')
        old_member, old_generation = session['member'], session['generation']
        code, replies = self.ctl('session', 'kick', '--watch', '10')
        self.assertEqual((code, replies[-1]['operation']['kind']), (0, 'session_kick'))
        [session] = self.ctl('session', 'list')[1][-1]['sessions']
        self.assertGreater(session['generation'], old_generation)
        self.assertEqual(session['member'], old_member, 'a kick keeps the trusted member')
        self.assertEqual(self.ctl('member', 'revoke', '--allow-key', 'relative.pub')[0], 2)
        code, _ = self.ctl('member', 'revoke', '--allow-key', '/keys/new.pub', '--watch', '10')
        self.assertEqual(code, 0)
        code, replies = self.ctl('profile', 'show', 'server')
        entry = replies[-1]['profile']
        self.assertEqual((entry['revision'], entry['document']['options']['--allow-key']), (2, '/keys/new.pub'))
        [session] = self.ctl('session', 'list')[1][-1]['sessions']
        self.assertNotEqual(session['member'], old_member, 'only the new member key is trusted')

    def test_simulated_socks5_settings_and_flows(self):
        self.start()
        code, replies = self.ctl('socks', 'show')
        self.assertEqual((code, replies[-1]['socks']['proxy_active']), (0, False))
        # Enabling while disconnected is refused.
        code, replies = self.ctl('socks', 'set', '--enable')
        self.assertEqual((code, replies[-1]['code']), (1, 'not_proxy_profile'))
        self.assertEqual(self.ctl('service', 'reconnect', '--watch', '10')[0], 0)
        # Non-loopback without explicit --allow fails validation.
        self.assertEqual(self.ctl('socks', 'set', '--enable', '--listen', '0.0.0.0:1080', '--allow', '')[0], 2)
        code, replies = self.ctl('socks', 'set', '--enable', '--listen', '127.0.0.1:1088',
                                 '--allow', '127.0.0.1/32', '--max-flows', '64')
        self.assertEqual((code, replies[-1]['socks']['listening']), (0, '127.0.0.1:1088'))
        code, replies = self.ctl('socks', 'flows')
        self.assertEqual((code, replies[-1]['socks_flows']['total_active']), (0, 1))
        self.assertEqual(replies[-1]['socks_flows']['flows'][0]['target'], 'example.org:443')
        self.assertEqual(replies[-1]['socks_flows']['flows'][1]['state'], 'refused')
        code, replies = self.ctl('socks', 'set', '--disable')
        self.assertEqual(code, 0)
        self.assertNotIn('listening', replies[-1]['socks'])

if __name__ == '__main__':
    unittest.main()
