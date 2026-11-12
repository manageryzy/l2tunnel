"""Pure helper tests for the TAP self-test; no namespaces, sockets or binaries."""
import argparse
from pathlib import Path
import unittest
from . import selftest


def arguments(**changes):
    values = dict(binary='/bin/l2tunneld', profile='swift', duplex='full', forward_mbit=100,
                  reverse_mbit=10, swift_utilization=0.99, swift_channels=16, swift_window=64,
                  swift_repair_permille=0, protection='aead', extra=[])
    values.update(changes)
    return argparse.Namespace(**values)


class SelfTestHelpers(unittest.TestCase):
    def test_swift_endpoints_mirror_each_other_and_leave_the_shaper_a_margin(self):
        work = Path('/work')
        client = selftest.endpoint_command(arguments(), 'a', work)
        server = selftest.endpoint_command(arguments(), 'b', work)
        self.assertEqual(client[:2], ['/bin/l2tunneld', 'connect'])
        self.assertEqual(server[:2], ['/bin/l2tunneld', 'serve'])

        def option(command, name):
            return command[command.index(name) + 1]
        for command in (client, server):
            self.assertEqual(option(command, '--record-profile'), 'swift')
            self.assertEqual(option(command, '--carrier'), 'udp')
            self.assertEqual(option(command, '--layer'), 'tap')
            # Both peers state both budgets, each 99% of the shaped rate.
            self.assertEqual(option(command, '--swift-forward-kbit'), '99000')
            self.assertEqual(option(command, '--swift-reverse-kbit'), '9900')
            self.assertEqual(option(command, '--swift-channels'), '16')
            self.assertEqual(option(command, '--swift-repair-permille'), '0')
        self.assertEqual(option(client, '--control-socket'), '/work/control-a.sock')
        self.assertEqual(option(server, '--control-socket'), '/work/control-b.sock')
        self.assertEqual(option(client, '--udp-bind'), option(server, '--udp-peer'))
        self.assertEqual(option(server, '--udp-bind'), option(client, '--udp-peer'))
        self.assertEqual(option(client, '--remote'), option(server, '--listen'))
        self.assertNotIn('--udp-cover', client)
        extra = selftest.endpoint_command(arguments(extra=['--swift-report-ms', '500']), 'a', work)
        self.assertEqual(extra[-2:], ['--swift-report-ms', '500'])

    def test_udp_echo_answers_with_the_digest_of_each_datagram(self):
        import hashlib, json, io, socket, threading
        from contextlib import redirect_stdout
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
        probe.close()
        server = threading.Thread(target=selftest.udp_echo, args=(port, 3.0))
        server.start()
        output = io.StringIO()
        with redirect_stdout(output):
            selftest.udp_probe('127.0.0.1', port)
        server.join()
        self.assertEqual(json.loads(output.getvalue()), {'sizes': 6, 'answered': 6})
        self.assertEqual(len(hashlib.sha256(b'').digest()), 32)

    def test_goodput_uses_only_samples_inside_the_window(self):
        samples = [(0.0, 0), (1.0, 1_000_000), (2.0, 3_000_000), (3.0, 6_000_000), (9.0, 7_000_000)]
        self.assertAlmostEqual(selftest.rate_mbit(samples, 1.0, 3.0), 20.0)
        self.assertEqual(selftest.rate_mbit(samples, 4.0, 5.0), 0.0)
        self.assertEqual(selftest.rate_mbit([], 0.0, 1.0), 0.0)

    def test_reference_follows_the_path_the_inner_rto_and_the_tolerance(self):
        table = selftest.SIMULATOR_REFERENCE
        slow = selftest.reference(79.7, 'impaired', 1000, 0.025)
        self.assertTrue(slow['meets_reference'])
        self.assertEqual(slow['simulator_goodput_mbit'], table[('impaired', 1000)])
        self.assertAlmostEqual(slow['required_goodput_mbit'], 78.702)
        self.assertFalse(selftest.reference(78.6, 'impaired', 1000, 0.025)['meets_reference'])
        self.assertFalse(selftest.reference(79.7, 'impaired', 1000, 0.0)['meets_reference'])
        # The kernel default minimum RTO is the simulator's 200 ms case.
        default = selftest.reference(78.0, 'impaired', 0, 0.025)
        self.assertEqual(default['simulator_inner_rto_min_ms'], 200)
        self.assertTrue(default['meets_reference'])
        # Every self-test path has a simulator run at the default inner RTO.
        for path in selftest.PATHS:
            self.assertTrue(selftest.reference(200.0, path, 1000, 0.025)['available'], path)
        self.assertFalse(selftest.reference(80.0, 'clean', 1000, 0.025)['meets_reference'])
        self.assertFalse(selftest.reference(60.0, 'impaired', 500, 0.025)['available'])
        self.assertFalse(selftest.reference(60.0, 'clean', 0, 0.025)['available'])
        override = selftest.reference(50.0, 'impaired', 500, 0.1, override=55.0)
        self.assertTrue(override['meets_reference'])
        self.assertEqual(override['observed_over_simulator'], round(50 / 55, 4))

    def test_paths_cover_the_reference_scenario(self):
        self.assertEqual(selftest.PATHS['impaired'], (35, 15))
        self.assertEqual(selftest.PATHS['clean'][1], 0)


if __name__ == '__main__':
    unittest.main()
