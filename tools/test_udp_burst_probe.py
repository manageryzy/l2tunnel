"""Fixed payload, finite observation and deadline tests; no namespaces."""
import json
import socket
import unittest
from . import udp_burst_probe as burst


class Clock:
    def __init__(self): self.value = 100
    def __call__(self): return self.value


class Receiver:
    def __init__(self, clock, events, end):
        self.clock, self.events, self.end = clock, list(events), end
        self.calls = 0
    def settimeout(self, seconds):
        if not 0 < seconds <= 10: raise AssertionError('deadline renewed')
    def recvfrom(self, limit):
        self.calls += 1
        if limit != 65: raise AssertionError('unbounded input')
        if self.events:
            stamp, packet, peer = self.events.pop(0)
            self.clock.value = stamp
            return packet, peer
        self.clock.value = self.end
        raise socket.timeout()


class BurstTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.record = {'version': 1, 'started_ns': 100,
                       'observation_end_ns': 100 + burst.OBSERVATION_NS}
        self.peer = ('127.0.0.1', 12345)

    def events(self):
        return [(101 + i, burst.payload(0, i), self.peer) for i in range(64)]

    def test_payload_is_fixed_distinct_directional_and_exact_multiset(self):
        values = {burst.payload(d, i) for d in (0, 1) for i in range(64)}
        self.assertEqual(len(values), 128)
        self.assertTrue(all(len(value) == 64 for value in values))
        state = burst.Multiset(0)
        for i in reversed(range(64)): state.accept(burst.payload(0, i))
        self.assertEqual(state.finish(), burst.expected_hash(0))
        with self.assertRaisesRegex(ValueError, 'duplicate'): state.accept(burst.payload(0, 0))
        for value in [b'', burst.payload(1, 0), burst.payload(0, 1) + b'x', b'L2B1\0\xff' + b'0' * 58]:
            with self.assertRaises(ValueError): burst.Multiset(0).accept(value)

    def test_observation_waits_until_cutoff_after_all_64(self):
        sock = Receiver(self.clock, self.events(), self.record['observation_end_ns'])
        result = burst.observe(sock, self.peer, 0, self.record, self.clock)
        self.assertEqual(result['count'], 64)
        self.assertEqual(result['observed_until_ns'], self.record['observation_end_ns'])
        self.assertEqual(sock.calls, 65)

    def test_65th_duplicate_before_cutoff_is_failure(self):
        events = self.events() + [(self.record['observation_end_ns'] - 1, burst.payload(0, 0), self.peer)]
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            burst.observe(Receiver(self.clock, events, self.record['observation_end_ns']), self.peer, 0, self.record, self.clock)

    def test_read_completed_at_cutoff_is_not_counted_or_extended(self):
        events = self.events()[:-1] + [(self.record['observation_end_ns'], burst.payload(0, 63), self.peer)]
        sock = Receiver(self.clock, events, self.record['observation_end_ns'])
        with self.assertRaisesRegex(ValueError, 'missing'):
            burst.observe(sock, self.peer, 0, self.record, self.clock)
        self.assertEqual(sock.calls, 64)
        # Out-of-window traffic cannot alter an already complete observation.
        self.clock.value = 100
        sock = Receiver(self.clock, self.events() + [(self.record['observation_end_ns'], b'late', self.peer)], self.record['observation_end_ns'])
        self.assertEqual(burst.observe(sock, self.peer, 0, self.record, self.clock)['count'], 64)
        self.assertEqual(sock.calls, 65)

    def test_wrong_peer_and_missing_payloads_fail(self):
        for events in [self.events()[:-1], [(101, burst.payload(0, 0), ('127.0.0.2', 12345))]]:
            self.clock.value = 100
            with self.assertRaises(ValueError):
                burst.observe(Receiver(self.clock, events, self.record['observation_end_ns']), self.peer, 0, self.record, self.clock)

    def test_start_record_and_timestamp_bounds_are_strict(self):
        self.assertEqual(burst.start_record(json.dumps(self.record)), self.record)
        for change in [{'version': True}, {'extra': 1}, {'observation_end_ns': 200}, {'started_ns': -1}, {'started_ns': 1.0}]:
            with self.assertRaises(ValueError): burst.start_record(json.dumps({**self.record, **change}))
        for raw in ['{"version":1,"version":1}', 'NaN', ' ' * 8193]:
            with self.assertRaises(ValueError): burst.start_record(raw)

    def test_producer_checks_actual_send_completion_against_same_cutoff(self):
        clock, end = self.clock, self.record['observation_end_ns']
        class Sender:
            def __init__(self): self.count = 0
            def settimeout(self, seconds): self.allowance = seconds
            def sendto(self, packet, peer):
                self.count += 1
                self.packet, self.peer = packet, peer
                clock.value = end if self.count == 5 else clock.value + 1
                return len(packet)
        sock = Sender()
        with self.assertRaises(TimeoutError): burst.send(sock, self.peer, 0, self.record, clock)
        self.assertEqual(sock.count, 5)
        self.assertEqual(sock.peer, self.peer)




class ActualLoopbackTests(unittest.TestCase):
    def test_two_direction_real_helpers_share_ten_second_cutoff_and_one_second_reap(self):
        import subprocess
        import sys
        import tempfile
        import time
        from pathlib import Path
        from .native_smoke import validate_burst_results
        # All operations are ordinary loopback sockets, never network namespaces.
        held = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(4)]
        for sock in held: sock.bind(('127.0.0.1', 0))
        ports = [sock.getsockname()[1] for sock in held]
        for sock in held: sock.close()
        children, streams, results = {}, [], {}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); start_path = root / 'start.json'
            helper = Path(__file__).with_name('udp_burst_probe.py')
            setup_end = time.monotonic_ns() + 5_000_000_000
            try:
                def launch(kind, direction, bound):
                    source, target = ports[direction], ports[2 + direction]
                    argv = [sys.executable, str(helper), kind, '--bind', f'127.0.0.1:{source if kind == "send" else target}', '--peer', f'127.0.0.1:{target if kind == "send" else source}', '--direction', str(direction), '--start', str(start_path), '--setup-deadline-ns', str(bound)]
                    if kind == 'receive': argv += ['--ready', str(root / f'ready-{direction}')]
                    key = f'{kind}-{direction}'; stream = (root / key).open('wb'); streams.append(stream)
                    children[key] = subprocess.Popen(argv, stdout=stream, stderr=subprocess.STDOUT)
                for direction in (0, 1): launch('receive', direction, setup_end)
                while not all((root / f'ready-{direction}').exists() for direction in (0, 1)):
                    burst.remaining_ns(setup_end)
                    self.assertTrue(all(child.poll() is None for child in children.values()))
                    time.sleep(.001)
                started = time.monotonic_ns(); record = {'version': 1, 'started_ns': started, 'observation_end_ns': started + burst.OBSERVATION_NS}
                temporary = start_path.with_suffix('.tmp'); temporary.write_text(json.dumps(record)); temporary.replace(start_path)
                reap = record['observation_end_ns'] + burst.REAP_NS
                for direction in (0, 1): launch('send', direction, record['observation_end_ns'])
                for key, child in children.items():
                    self.assertEqual(child.wait(timeout=burst.remaining_ns(reap)), 0, (root / key).read_text())
                    results[key] = json.loads((root / key).read_text())
                burst.remaining_ns(reap)
                validate_burst_results(results, record, reap)
            finally:
                for child in children.values():
                    if child.poll() is None: child.kill()
                for child in children.values(): child.wait(timeout=2)
                for stream in streams: stream.close()


if __name__ == '__main__': unittest.main()
