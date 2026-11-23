"""Paced single-flow application writes ahead of an established model TCP socket."""
from array import array
from bisect import bisect_left, bisect_right
from math import ceil, floor

from .tcp import IP_TCP_BYTES


class PacedSocketWriter:
    """Pace fixed-size application writes and issue bytes when the TCP window allows.

    Written-but-unacknowledged bytes include both unsent socket data and flight.
    ACK processing and transmission remain in the existing TCP model. The caller
    must attach before producers run and record application and TCP origins separately.
    """

    retry_ns = 500_000  # Per-flow SIOCOUTQ recheck in the native comparison probe.

    def __init__(self, flow, credit_bytes, offer_bps, issue_limit, *, tcp_mss=None):
        self.flow = flow
        self.size = flow.traffic.payload_bytes
        if (type(credit_bytes) is not int or credit_bytes < self.size or
                type(offer_bps) is not int or offer_bps <= 0 or
                type(issue_limit) is not int or issue_limit < 1):
            raise ValueError("positive offer and flight limits and one record of credit required")
        if flow.now != 0 or flow.next_source != 0 or flow.sent_times or flow.forward.pending:
            raise ValueError("attach before the single-flow workload starts")
        if tcp_mss is not None and (type(tcp_mss) is not int or
                                     not 0 < tcp_mss <= flow.scenario.mtu - IP_TCP_BYTES):
            raise ValueError("TCP MSS must fit one inner IPv4/TCP datagram including timestamps")
        self.credit = credit_bytes
        self.rate = offer_bps
        self.issue_limit = issue_limit
        self.tcp_mss = tcp_mss
        if tcp_mss is not None:
            flow.segment_offsets = array("Q", [0])
            flow.smss_bytes = tcp_mss
        self.end_ns = round(flow.traffic.duration_s * 1e9)
        self.record_bit_ns = self.size * 8 * 1_000_000_000
        self.writes = array("d")
        self.denials = 0
        self.peak_outq = self.peak_unsent = 0
        # ACKs can immediately send already written bytes, even when the
        # application is waiting for its next offer or a credit recheck.
        flow.produce = self.send_available
        flow.at(0, self.offer)

    def due_ns(self, index):
        return (index * self.record_bit_ns + self.rate - 1) // self.rate

    def outstanding(self):
        issued = len(self.flow.sent_times)
        first_unsent = self.flow.byte_offset(issued)
        first_unacked = self.flow.byte_offset(self.flow.tcp_acked)
        return dict(written=len(self.writes), issued=first_unsent // self.size,
                    acked=first_unacked // self.size,
                    socket_unsent_bytes=len(self.writes) * self.size - first_unsent,
                    tcp_unacked_bytes=first_unsent - first_unacked)

    def offer(self):
        flow = self.flow
        now_ns = round(flow.now * 1e9)
        if now_ns >= self.end_ns:
            return
        due = self.due_ns(len(self.writes))
        while due <= now_ns:
            outq = len(self.writes) * self.size - flow.byte_offset(flow.tcp_acked)
            if outq + self.size > self.credit:
                self.denials += 1
                due = now_ns + self.retry_ns
                break
            self.writes.append(flow.now)
            self.peak_outq = max(self.peak_outq, outq + self.size)
            self.peak_unsent = max(self.peak_unsent, len(self.writes) * self.size -
                                   flow.byte_offset(len(flow.sent_times)))
            due = self.due_ns(len(self.writes))
        self.send_available()
        if due < self.end_ns:
            flow.at(due / 1e9, self.offer)

    def send_available(self):
        flow = self.flow
        slots = min(flow.window_limit, self.issue_limit, floor(flow.cwnd))
        if flow.sack_sender is not None:
            flow.sack_sender.service(flow)
            if flow.rack is not None:
                # SACK-delivered bytes retain ordinary application credit until
                # cumulative ACK, but they no longer consume congestion flight.
                slots = min(flow.window_limit, self.issue_limit)
                credit = flow.rack.send_credit()
            else:
                credit = max(0, floor(flow.cwnd) - flow.sack_sender.pipe(len(flow.sent_times)))
            slots = min(slots, len(flow.forward.pending) + credit)
        written = len(self.writes) * self.size
        while len(flow.forward.pending) < slots and flow.byte_offset(len(flow.sent_times)) < written:
            if self.tcp_mss is not None:
                start = flow.segment_offsets[-1]
                size = min(self.tcp_mss, written - start,
                           flow.traffic.window_bytes - (start - flow.byte_offset(flow.tcp_acked)))
                if size <= 0:
                    break
                flow.segment_offsets.append(start + size)
            flow.issue_original_segment()
        flow.record_window_usage()

    def report(self):
        flow = self.flow
        completed = flow.byte_offset(flow.tcp_received) // self.size
        if len(flow.forward.delays) != flow.tcp_received:
            raise ValueError("receiver must report one in-order TCP completion per segment")
        def distribution(values):
            ordered = sorted(values)
            return dict(n=len(ordered),
                        p50=ordered[ceil(.50 * len(ordered)) - 1] if ordered else None,
                        p99=ordered[ceil(.99 * len(ordered)) - 1] if ordered else None)
        offsets = flow.segment_offsets
        first = range(completed) if offsets is None else [
            bisect_right(offsets, i * self.size) - 1 for i in range(completed)]
        last = range(completed) if offsets is None else [
            bisect_left(offsets, (i + 1) * self.size) - 1 for i in range(completed)]
        completed_at = [flow.sent_times[i] + flow.forward.delays[i] / 1000 for i in last]
        slots = ((self.end_ns - 1) * self.rate) // self.record_bit_ns + 1
        state = self.outstanding()
        report = dict(
            offered_records=slots, written_records=len(self.writes), tcp_issued=len(flow.sent_times),
            fully_read=completed, cumulatively_acked=state["acked"],
            scheduled_unwritten=slots - len(self.writes),
            end_unsent=len(self.writes) - state["issued"],
            end_unconfirmed=len(self.writes) - state["acked"],
            issue_limit_segments=self.issue_limit, credit_bytes=self.credit,
            peak_outq_bytes=self.peak_outq, peak_unsent_bytes=self.peak_unsent,
            credit_denials=self.denials, credit_recheck_us=self.retry_ns // 1000,
            scheduled_to_write_ms=distribution((self.writes[i] - self.due_ns(i) / 1e9) * 1000
                                                for i in range(len(self.writes))),
            write_to_issue_ms=distribution((flow.sent_times[seg] - self.writes[i]) * 1000
                                           for i, seg in enumerate(first)),
            issue_to_read_ms=distribution(flow.forward.delays if offsets is None else
                                          ((t - flow.sent_times[seg]) * 1000
                                           for t, seg in zip(completed_at, first, strict=True))),
            write_to_read_ms=distribution((t - self.writes[i]) * 1000 for i, t in enumerate(completed_at)),
            scheduled_to_read_ms=distribution((t - self.due_ns(i) / 1e9) * 1000
                                               for i, t in enumerate(completed_at)),
        )
        if offsets is not None:
            report["packetization"] = dict(
                mss=self.tcp_mss, application_record_bytes=self.size, issued_bytes=offsets[-1],
                fully_read_bytes=flow.byte_offset(flow.tcp_received),
                cumulatively_acked_bytes=flow.byte_offset(flow.tcp_acked),
                issued_segments=len(offsets)-1,
                full_size_segments=sum(end - offsets[i] == self.tcp_mss
                                       for i, end in enumerate(offsets[1:])))
        return report
