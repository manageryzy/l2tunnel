import unittest

from l2tunnel_sim.tcp_reorder_hold import TCPReorderHold


class TCPReorderHoldTests(unittest.TestCase):
    def gate(self, *, start=0, span=256, frames=4):
        self.events = []
        self.delivered = []
        return TCPReorderHold(
            start, hold_s=.035, max_span_bytes=span, max_frames=frames,
            schedule=lambda *event: self.events.append(event), deliver=self.delivered.append)

    def expire_first(self):
        _, callback, deadline = self.events.pop(0)
        callback(deadline)

    def test_short_hole_restored_and_overlapping_attempts_preserved(self):
        gate = self.gate()
        for time, seq, tag in [(0, 5, "ahead"), (.01, 5, "duplicate"), (.02, 0, "prefix")]:
            gate.receive(time, seq, 7, tag, record=seq)
        self.assertEqual(self.delivered, ["prefix", "ahead", "duplicate"])
        self.expire_first()
        self.assertIsNone(gate.bypass_high)
        self.assertEqual(gate.next_byte, 12)

    def test_permanent_hole_does_not_rearm_and_old_gap_can_return(self):
        gate = self.gate()
        gate.receive(0, 30, 10, "three", record=2)
        gate.receive(.033, 10, 10, "one", record=1)
        self.assertEqual(len(self.events), 1)
        self.assertEqual(self.events[0][0], .035)
        self.expire_first()
        gate.receive(.05, 60, 10, "six", record=3)
        self.assertEqual(self.delivered, ["one", "three", "six"])
        self.assertFalse(self.events)
        gate.receive(.10, 0, 10, "old gap", record=4)
        self.assertEqual(gate.next_byte, 20)
        self.assertEqual(gate.bypass_high, 40)
        gate.receive(.11, 20, 10, "other old gap", record=5)
        self.assertEqual(self.delivered[-2:], ["old gap", "other old gap"])
        self.assertEqual(gate.next_byte, 40)
        self.assertIsNone(gate.bypass_high)
        gate.receive(.12, 40, 20, "later", record=6)
        self.assertEqual(gate.next_byte, 70)

    def test_byte_and_frame_pressure_release(self):
        for span, cap in [(25, 4), (256, 2)]:
            with self.subTest(span=span, cap=cap):
                gate = self.gate(span=span, frames=cap)
                gate.receive(0, 10, 10, 1, record=10)
                gate.receive(.002, 20, 10, 2, record=5)
                self.assertEqual(self.delivered, [2, 1])
                self.assertEqual(gate.counts["pressure_episodes"], 1)
                self.expire_first()
                self.assertFalse(gate.pending)

    def test_wire_wrap_late_duplicate_and_independent_flows(self):
        a = self.gate(start=(1 << 32) - 5)
        first_flow = self.delivered
        b = self.gate()
        a.receive(0, 0, 5, 2, record=2)
        b.receive(0, 0, 1, 3, record=0)
        self.assertEqual(self.delivered, [3])
        a.receive(.005, (1 << 32) - 5, 5, 1, record=1)
        a.receive(.01, (1 << 32) - 2, 2, 4, record=3)
        self.assertEqual(a.next_byte, (1 << 32) + 5)
        self.assertEqual(b.next_byte, 1)
        self.assertEqual(first_flow, [1, 2, 4])
        self.assertFalse(a.pending)

    def test_fragmented_scoreboard_fails_open_without_dropping_data(self):
        gate = self.gate(span=1)
        for i in range(1, 35):
            gate.receive(i * .001, 2 * i, 1, i, record=i)
        self.assertEqual(self.delivered, list(range(1, 35)))
        self.assertEqual(gate.counts["range_overflow"], 1)
        self.assertTrue(gate.tracking_disabled)
