"""Linux 6.8 established DATA timestamp checks for a timestamp-negotiated peer.

Sequence edges are unwrapped, half-open native TCP ranges in any consistent
unit. TSval is the unsigned 32-bit wire value. The caller supplies the cumulative
edge from the last ACK emitted by the TCP endpoint, including ACKs subsequently
delayed, superseded or lost in the tunnel. No SYN, RST or ACK-only processing.
"""


class LinuxDataPAWS:
    # tcp_paws_check() in the 6.8.0-60 Ubuntu headers uses ktime_get_seconds()
    # and INT_MAX / USEC_PER_SEC for either negotiated TS clock frequency.
    expiry_seconds = 2147

    def __init__(self):
        self.recent = None
        self.recent_stamp = 0
        self.rejections = 0

    def receive(self, start, end, tsval, now, last_ack_sent):
        """Return (accept DATA, refresh the echo), before reassembly mutates."""
        if tsval is None:
            return True, False
        if not 0 <= tsval < 2**32 or not start < end:
            raise ValueError("established DATA needs a 32-bit TSval and nonempty sequence range")
        stamp = int(now)
        valid = self.recent not in (None, 0) and stamp-self.recent_stamp < self.expiry_seconds
        lag = 0 if not valid else ((self.recent-tsval+2**31) % 2**32)-2**31
        # tcp_validate_incoming() permits one tick of backwards movement on
        # DATA. tcp_replace_ts_recent() applies the stricter zero-tick check.
        if valid and lag > 1:
            self.rejections += 1
            return False, False
        # tcp_sequence() excludes segments whose exclusive end precedes
        # rcv_wup. Even a newer, very old duplicate must not raise TS.Recent.
        refresh = start <= last_ack_sent <= end and (not valid or lag <= 0)
        if refresh:
            self.recent = tsval
            self.recent_stamp = stamp
        return True, refresh
