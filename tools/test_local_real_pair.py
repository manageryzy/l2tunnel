"""tools/local_real_pair.py: address rewriting and the forwarding layout's
printed commands (nothing privileged runs here)."""
from __future__ import annotations

import unittest

from tools import local_real_pair as pair

ROW = ['--carrier', 'quic-like', '--udp-bind', '192.0.2.2:24440', '--udp-peer', '192.0.2.6:24441', '--layer', 'tun']


class LocalRealPairTest(unittest.TestCase):
    def test_loopback_and_forwarding_addresses(self):
        self.assertEqual(pair.side_arguments(ROW, 'a', False),
                         ['--carrier', 'quic-like', '--udp-bind', '127.0.0.1:24440',
                          '--udp-peer', '127.0.0.1:24441', '--layer', 'tun'])
        client = pair.side_arguments(ROW, 'a', True)
        server_row = ['--udp-bind', '192.0.2.6:24441', '--udp-peer', '192.0.2.2:24440']
        server = pair.side_arguments(server_row, 'b', True)
        self.assertEqual(client[3], '10.231.254.1:24440')
        self.assertEqual(client[5], '10.231.254.2:24441')
        self.assertEqual(server, ['--udp-bind', '10.231.254.2:24441', '--udp-peer', '10.231.254.1:24440'])

    def test_network_commands_only_create_owned_objects(self):
        setup, teardown = pair.network_commands('alice')
        text = '\n'.join(setup)
        self.assertIn('ip netns add l2tdemo', text)
        self.assertIn('ip link set l2tdemo-b netns l2tdemo', text)
        self.assertIn('ip addr add 10.231.255.1/30 dev l2tdemo-a', text)
        for forbidden in ('route', 'qdisc', 'bridge', 'master', 'default'):
            self.assertNotIn(forbidden, text, forbidden)
        self.assertTrue(teardown[0].startswith('ip netns delete l2tdemo'))


if __name__ == '__main__':
    unittest.main()
