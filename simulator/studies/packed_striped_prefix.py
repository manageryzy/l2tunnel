"""Paid early named feedback for one observable rank deficit at the oldest mixed group."""
from packed_striped_path import MixedPacket


def install(path):
    service, transport = path.service, path.t
    if transport.reverse or service.gap_observer is not transport:
        raise ValueError("striped frontier requests require forward FIFO gap observation")
    admit = transport.accept_fifo_source
    next_slot = 0.

    def observe(wire):
        nonlocal next_slot
        source = admit(wire)
        if source is None or transport.sim.now < next_slot or not isinstance(wire, MixedPacket):
            return source
        base, group, split, ordinal, _ = path.codec.inspect_packet(wire, path.geometry, path.max_wire)
        # The terminal ordinal establishes the whole range. With k-1 members
        # present, either one of m+1 missing originals closes the rank deficit.
        if (split is None and ordinal == group.n-1 and
                transport.request_fresh_frontier(base, base+group.n, group.m+1)):
            next_slot = transport.sim.now + transport.policy.gap_ms/1000
            path.counts["expedited_frontier_masks"] += 1
            path.counts["expedited_frontier_ids"] += group.m+1
        return source

    transport.accept_fifo_source = observe
