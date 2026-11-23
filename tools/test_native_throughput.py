"""Finite throughput accounting, immutable ownership and actual kernel loopback."""
import contextlib
import copy
import io
import json
from pathlib import Path
import socket
import subprocess
import struct
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from . import native_throughput as h, throughput_probe as probe


# Exact stdout grammar observed with iproute2-6.1.0 in the owned diagnostic lab:
# work/throughput23-tc-diagnostic/receipt.json. Counters made nonzero below.
HTB_TEXT = ("class htb 1:10 root leaf 10: prio 0 rate 100Mbit ceil 100Mbit burst 1600b cburst 1600b \n"
    " Sent 12345 bytes 17 pkt (dropped 2, overlimits 3 requeues 4) \n"
    " backlog 0b 0p requeues 4\n"
    " lended: 17 borrowed: 0 giants: 0\n"
    " tokens: -2000 ctokens: 2000\n\n")
QDISC_JSON = json.dumps([
    {'kind': 'htb', 'handle': '1:', 'root': True, 'bytes': 12345, 'packets': 17, 'drops': 2, 'overlimits': 3, 'requeues': 4},
    {'kind': 'netem', 'handle': '10:', 'parent': '1:10', 'bytes': 12345, 'packets': 17, 'drops': 2, 'overlimits': 3, 'requeues': 4}])


class ContractTests(unittest.TestCase):
    def test_profiling_validation_and_explicit_performance_gate(self):
        for profile in ('tap-system', 'tun-system'):
            p = h.plan('profile24', profile, 'half', 'delay', 1, profile_ms=500)
            self.assertEqual(p['runtime_profile_interval_ms'], 500)
            self.assertEqual(p['forward_acceptance_mbps'], 80)
        for profile, millis in [('tun-active', 500), ('tun-measured-proxy', 500),
                                ('tap-system', True), ('tap-system', 99), ('tun-system', 60001)]:
            with self.assertRaises(ValueError):
                h.plan('profile24', profile, 'half', 'delay', 1, profile_ms=millis)

    def test_delivery_budget_uses_same_explicit_policy_across_paths(self):
        policies = [h.plan('bdp25', 'tap-system', 'half', path, 1, delivery_window='bdp')['delivery_policy']
                    for path in ('clean', 'delay', 'loss1', 'impaired')]
        self.assertTrue(all(value == policies[0] for value in policies))
        self.assertEqual(policies[0]['forward_mbps'], 100)
        self.assertEqual(policies[0]['reverse_mbps'], 10)
        self.assertEqual(policies[0]['bootstrap_rtt_ms'], 70)
        for profile in ('tun-active', 'tun-measured-proxy'):
            with self.assertRaises(ValueError):
                h.plan('bdp25', profile, 'half', 'delay', 1, delivery_window='bdp')

    def test_wan_policy_is_explicit_coherent_and_historical_policy_unchanged(self):
        old = h.measured.policy()
        policy = h.wan_measured_policy()
        self.assertEqual(h.measured.policy(), old)
        self.assertEqual(old['ownership']['probe_timeout_micros'], 30000)
        self.assertEqual(policy['ownership']['probe_timeout_micros'], 2000000)
        self.assertEqual(policy['ownership']['handoff_timeout_micros'], 2000000)
        self.assertEqual(policy['ownership']['pending_ttl_micros'], 1000000)
        self.assertEqual(policy['observation']['sample_ttl_micros'], 4000000)
        self.assertEqual(policy['observation']['rate_interval_micros'], 250000)
        self.assertEqual(policy['observation']['rate_bins'], 8)
        self.assertEqual(policy['allocation']['target']['bootstrap_rtt_micros'], 70000)
        self.assertEqual(h.plan('wanpolicy', 'tun-measured-proxy', 'half', 'impaired', 4)['measured_policy'], policy)
        self.assertEqual(policy['fixed'], old['fixed'])
        self.assertEqual(policy['service'], old['service'])
        with self.assertRaises(ValueError): h.validate_wan_policy(old)
        for section, field, value in [('ownership', 'probe_timeout_micros', 120000001),
                ('ownership', 'handoff_timeout_micros', True),
                ('observation', 'sample_ttl_micros', 1000000),
                ('observation', 'demand_idle_micros', 1000),
                ('observation', 'rate_bins', 17),
                ('service', 'callback_work_per_turn', 0),
                ('allocation', 'target', None)]:
            bad = copy.deepcopy(policy)
            if section == 'allocation':
                bad['allocation']['target']['bootstrap_rtt_micros'] = 120000001
            else:
                bad[section][field] = value
            with self.subTest(section=section, field=field), self.assertRaises(ValueError): h.validate_wan_policy(bad)

    def test_observed_htb_text_full_counters_rates_and_root(self):
        rows, observed_format = h.parse_tc_class(HTB_TEXT, 100)
        self.assertEqual(observed_format, 'htb-text-iproute2')
        self.assertEqual(rows[0]['handle'], '1:10')
        self.assertTrue(rows[0]['root'])
        self.assertEqual({k: rows[0][k] for k in ('bytes', 'packets', 'drops', 'overlimits', 'requeues')},
                         {'bytes': 12345, 'packets': 17, 'drops': 2, 'overlimits': 3, 'requeues': 4})
        ten = HTB_TEXT.replace('100Mbit', '10Mbit')
        h.parse_tc_class(ten, 10)
        h.parse_tc_class(HTB_TEXT.replace('root leaf', 'parent 1: leaf'), 100)
        value = [{'kind': 'htb', 'handle': '1:10', 'root': True, 'options': {'rate': 12500000, 'ceil': 12500000},
                  'bytes': 1, 'packets': 2, 'drops': 3, 'overlimits': 4, 'requeues': 5}]
        self.assertEqual(h.parse_tc_class(json.dumps(value), 100)[1], 'json')
        self.assertEqual(len(h.parse_tc_qdisc(QDISC_JSON)), 2)

    def test_tc_incompatibility_is_tool_failure_not_protocol_or_empty_success(self):
        invalid = ['', '[]', '[', HTB_TEXT + HTB_TEXT, HTB_TEXT.replace('1:10 root', '1:20 root'),
            HTB_TEXT.replace('root leaf', 'parent 2: leaf'), HTB_TEXT.replace('100Mbit', '10Mbit'),
            HTB_TEXT.replace('ceil 100Mbit', 'ceil 10Mbit'), HTB_TEXT.replace('12345 bytes', '-1 bytes'),
            HTB_TEXT.replace('dropped 2, ', ''), HTB_TEXT.replace('overlimits 3 ', ''),
            HTB_TEXT.replace('requeues 4)', 'requeues 5)'), HTB_TEXT.replace('tokens: -2000 ctokens: 2000', 'unknown: 1'),
            HTB_TEXT + 'class htb 1:11 root\n']
        for raw in invalid:
            with self.subTest(raw=raw), self.assertRaises(h.ToolObservationError): h.parse_tc_class(raw, 100)
        for raw in ['', '[]', HTB_TEXT, QDISC_JSON.replace('"parent": "1:10"', '"parent": "2:10"')]:
            with self.subTest(raw=raw), self.assertRaises(h.ToolObservationError): h.parse_tc_qdisc(raw)
        self.assertEqual(h.failure_status(h.ToolObservationError('format')), 'tool_failure')
        self.assertEqual(h.failure_status(TimeoutError()), 'bound_exhausted')
        self.assertEqual(h.failure_status(ValueError('exact hash mismatch')), 'failed')

    def test_explicit_profiles_paths_and_shared_rate(self):
        for profile in h.PROFILES:
            for path, delay, loss in [('clean', 1, 0), ('delay', 35, 0), ('loss1', 35, 1), ('impaired', 35, 15)]:
                p = h.plan('testspeed', profile, 'half', path, 4)
                self.assertEqual((p['one_way_delay_ms'], p['loss_percent_per_direction']), (delay, loss))
                self.assertEqual(p['shared_htb_mbps'], {'a_to_b': 100, 'b_to_a': 10})
                self.assertEqual(p['probe_original_seconds'], 30)
                self.assertTrue(all('l2t-testspeed-' in ns for ns in p['namespaces'].values()))
        self.assertEqual(h.plan('testspeed', 'tap-system', 'full', 'delay', 1)['application_roles'], ['host_a', 'host_b'])

    def test_invalid_before_io(self):
        for flows in (True, 0, 3, 8):
            with self.assertRaises(ValueError): h.plan('test', 'tap-system', 'full', 'clean', flows)
        for maximum in (True, -1, 65535, probe.MAX_BYTES + 1):
            with self.assertRaises(ValueError): probe.validate(1, maximum)
        with self.assertRaises(ValueError): h.plan('../host', 'tun-system', 'full', 'clean', 1)
        with self.assertRaises(ValueError): h.plan('test', 'tap-proxy', 'full', 'clean', 1)

    def test_dry_run_never_mutates_or_reads_binary(self):
        with tempfile.TemporaryDirectory() as d, patch.object(h.lab, 'apply') as apply, patch.object(h.fixed, 'command') as command:
            output = Path(d) / 'never-created'
            with contextlib.redirect_stdout(io.StringIO()) as text:
                self.assertEqual(h.main(['--profile', 'tun-active', '--duplex', 'full', '--path', 'loss1',
                    '--flows', '2', '--output', str(output), '--binary', '/does/not/exist']), 0)
            self.assertEqual(json.loads(text.getvalue())['status'], 'dry_run')
            self.assertFalse(output.exists())
            apply.assert_not_called(); command.assert_not_called()

    def test_hash_eof_and_drain_separate_from_measurement(self):
        row = {'sent': 30, 'received': 30, 'sent_sha256': 'a', 'received_sha256': 'a',
               'warmup': 5, 'measured': 10, 'postwindow': 15, 'eof': True, 'write_closed': True, 'bound_exhausted': False}
        value = {'clock': {'measure_start_ns': 100, 'end_ns': 1_000_000_100}, 'flows': [row]}
        result = h.compare(value, value, 1)
        self.assertEqual(result['directions']['a_to_b']['receiver_unique_bytes'], 10)
        self.assertEqual(result['directions']['a_to_b']['postwindow_drain_bytes'], 15)
        self.assertEqual(result['directions']['a_to_b']['goodput_mbps'], 0.00008)
        self.assertEqual(result['performance_acceptance']['status'], 'failed')
        bad = copy.deepcopy(value); bad['flows'][0]['received_sha256'] = 'b'
        with self.assertRaises(ValueError): h.compare(value, bad, 1)
        bad = copy.deepcopy(value); bad['flows'][0]['eof'] = False
        with self.assertRaises(ValueError): h.compare(value, bad, 1)
        bad = copy.deepcopy(value); bad['flows'][0]['bound_exhausted'] = True
        self.assertEqual(h.compare(value, bad, 1)['status'], 'bound_exhausted')

    def test_wire_counters_and_tc_drops_are_separate(self):
        raw = json.dumps([{'ifname': 'wan0', 'stats64': {'tx': {'bytes': 900}, 'rx': {'bytes': 100}}}])
        self.assertEqual(h.link_counters(raw), {'tx_bytes': 900, 'rx_bytes': 100})
        with self.assertRaises(ValueError): h.link_counters(raw.replace('wan0', 'eth0'))
        samples = [{'wan': {side: {'read_begin_ns': t, 'read_end_ns': t + 2, 'tx_bytes': n, 'rx_bytes': n // 2}
                               for side in ('a', 'b')}} for t, n in [(10, 100), (1_000_000_010, 300)]]
        series = h.wire_intervals(samples, {'measure_start_ns': 0, 'end_ns': 2_000_000_000})
        self.assertEqual(series['interfaces']['a'][0]['tx_bytes'], 200)
        self.assertEqual(series['interfaces']['a'][0]['tx_mbps'], .0016)
        self.assertTrue(series['interfaces']['a'][0]['inside_measurement_window'])
        self.assertEqual(series['measurement_coverage']['a']['tx_bytes'], 200)
        self.assertEqual(h.wire_intervals([], {'measure_start_ns': 0, 'end_ns': 10})['measurement_coverage']['a']['status'], 'unobserved')
        before = {side: {kind: [{'kind': 'htb', 'handle': '1:', 'bytes': 10, 'drops': 2}]
                        for kind in ('class', 'qdisc')} for side in ('a', 'b')}
        after = copy.deepcopy(before); after['a']['class'][0].update(bytes=110, drops=5)
        self.assertEqual(h.tc_deltas(before, after)[0]['counter_deltas'], {'bytes': 100, 'drops': 3})
        after['a']['class'][0]['bytes'] = 0
        with self.assertRaises(ValueError): h.tc_deltas(before, after)

    def test_helper_source_identity_required(self):
        with tempfile.TemporaryDirectory() as d:
            output = Path(d)
            for name in h.HELPERS: (output / name).write_text(name)
            hashes = {'tools/' + name: h.fixed.file_hash(output / name) for name in h.HELPERS}
            self.assertEqual(h.verify_helpers({'source_sha256_after': hashes}, output), hashes)
            with self.assertRaises(ValueError): h.verify_helpers({'source_sha256_after': hashes}, output, True)
            (output / h.HELPERS[0]).write_text('changed')
            with self.assertRaises(ValueError): h.verify_helpers({'source_sha256_after': hashes}, output)

    def test_tcp_info_nullable_scaled_peer_window_and_64bit_bytes(self):
        self.assertIsNone(probe.decode_tcp_info(bytes(67))['rcv_ssthresh_bytes'])
        self.assertIsNone(probe.decode_tcp_info(bytes(87))['advmss_bytes'])
        short = probe.decode_tcp_info(bytes(104))
        self.assertIsNone(short['peer_advertised_rwnd_bytes'])
        self.assertIsNone(short['bytes_sent'])
        raw = bytearray(236)
        struct.pack_into('=I', raw, 16, 1400)
        struct.pack_into('=I', raw, 64, 5792)
        struct.pack_into('=I', raw, 80, 10)
        struct.pack_into('=I', raw, 84, 1448)
        self.assertEqual(probe.decode_tcp_info(raw[:68])['rcv_ssthresh_bytes'], 5792)
        self.assertEqual(probe.decode_tcp_info(raw[:88])['advmss_bytes'], 1448)
        struct.pack_into('=I', raw, 96, 777)
        struct.pack_into('=I', raw, 228, 196608)
        struct.pack_into('=I', raw, 232, 131072)
        for offset, value in [(120, 2**40), (200, 2**41), (208, 2**33)]:
            struct.pack_into('=Q', raw, offset, value)
        info = probe.decode_tcp_info(raw)
        self.assertEqual(info['peer_advertised_rwnd_bytes'], 196608)
        self.assertEqual(info['local_advertised_rwnd_bytes'], 131072)
        self.assertEqual(info['snd_cwnd_bytes'], 14000)
        self.assertEqual(info['rcv_space_bytes'], 777)
        self.assertEqual(info['bytes_acked'], 2**40)
        self.assertEqual(info['bytes_sent'], 2**41)
        self.assertEqual(info['bytes_retransmitted'], 2**33)

    def test_clock_publication_is_complete_and_never_replaces(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'clock'
            value = {'start_ns': 123, 'warmup_ns': 456, 'measure_ns': 789}
            real_link = h.os.link
            def visible_after_closed(source, target):
                self.assertFalse(Path(target).exists())
                self.assertEqual(json.loads(Path(source).read_text()), value)
                return real_link(source, target)
            with patch.object(h.os, 'link', side_effect=visible_after_closed):
                h.publish_clock(path, value)
            with self.assertRaises(FileExistsError): h.publish_clock(path, {'other': 1})
            self.assertEqual(json.loads(path.read_text()), value)

    def test_clock_deadline_and_unknown_fields(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'clock'
            with self.assertRaises(TimeoutError): probe.clock_file(path, time.monotonic_ns() - 1)
            path.write_text(json.dumps({'start_ns': time.monotonic_ns() - 1, 'warmup_ns': 1, 'measure_ns': 1}))
            with self.assertRaises(ValueError): probe.clock_file(path, time.monotonic_ns() + 1_000_000_000)


@unittest.skipUnless(sys.platform == 'linux', 'Linux TCP_INFO required')
class KernelLoopbackTests(unittest.TestCase):
    def case(self, flows, family, maximum=256 * 1024 * 1024):
        address = '127.0.0.1' if family == 4 else '::1'
        with socket.socket(socket.AF_INET if family == 4 else socket.AF_INET6) as reserve:
            reserve.bind((address, 0)); port = reserve.getsockname()[1]
        with tempfile.TemporaryDirectory() as d:
            output, processes, logs = Path(d), [], []
            try:
                for role in ('listen', 'connect'):
                    path = output / (role + '.log'); logs.append(path)
                    with path.open('xb') as log:
                        child = subprocess.Popen([sys.executable, str(Path(probe.__file__)), role, '--address', address,
                            '--port', str(port), '--flows', str(flows), '--max-bytes', str(maximum), '--clock', str(output / 'clock')],
                            stdout=log, stderr=subprocess.STDOUT)
                    processes.append(child)
                    h.fixed.wait_log(child, path, 'Listening' if role == 'listen' else 'Connected', time.monotonic() + 3)
                h.fixed.wait_log(processes[0], logs[0], 'Connected', time.monotonic() + 3)
                clock = {'start_ns': time.monotonic_ns() + 100_000_000, 'warmup_ns': 100_000_000, 'measure_ns': 100_000_000}
                h.publish_clock(output / 'clock', clock)
                for child in processes:
                    self.assertEqual(child.wait(timeout=5), 0, [p.read_text() for p in logs])
                results = [json.loads(p.read_text().splitlines()[-1]) for p in logs]
                result = h.compare(results[1], results[0], flows)
                for endpoint in results:
                    self.assertEqual(len(endpoint['flows']), flows)
                    self.assertTrue(all(row['eof'] and row['write_closed'] for row in endpoint['flows']))
                    info = endpoint['tcp_info'][0]['flows'][0]
                    self.assertEqual(info['snd_cwnd_bytes'], info['snd_cwnd_segments'] * info['snd_mss'])
                    self.assertIn('sampled kernel', info['advertised_rwnd_observation'])
                    self.assertTrue(all(key in info for key in ('bytes_acked', 'bytes_sent', 'bytes_retransmitted', 'peer_advertised_rwnd_bytes')))
                    self.assertIn('application_counters', info)
                return result
            finally:
                for child in processes: h.fixed.stop(child)

    def test_actual_ipv4_one_two_four_flows_bidirectional_hashes_eof(self):
        for flows in (1, 2, 4):
            with self.subTest(flows=flows): self.assertEqual(self.case(flows, 4)['status'], 'passed')

    def test_actual_early_byte_ceiling_is_bound_exhausted_even_before_window(self):
        result = self.case(1, 4, 65536)
        self.assertEqual(result['status'], 'bound_exhausted')
        self.assertEqual(result['hashes_and_eof'], 'passed')

    @unittest.skipUnless(socket.has_ipv6, 'IPv6 unavailable')
    def test_actual_ipv6_hashes_and_tcp_info(self):
        self.assertEqual(self.case(1, 6)['status'], 'passed')


if __name__ == '__main__': unittest.main()
