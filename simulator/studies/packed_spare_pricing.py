"""Original C48 authenticated IP pricing for an explicitly selected Packed study."""
import collections

from l2tunnel_sim.compact_wire import ID_MASK, _unwrap
from l2tunnel_sim.packed_targeted import decode_request

fixed = 28 + 21
def vlen(value):
    assert value >= 0
    return max(1,(value.bit_length()+6)//7)

def install(sim, services):
    transports = {bool(service.transport.reverse):service.transport for service in services.values()}
    classes = collections.Counter()
    maximum = collections.Counter()
    feedback_sequence = collections.Counter()
    def price(kind, size):
        assert size <= 1500 and size >= fixed
        classes[kind] += 1
        maximum[kind] = max(maximum[kind], size)
        return size
    def patch_transport(t):
        assert t.ip_header_bytes == 20 and t.crc_bytes == 4
        # Outside an exact selected emission, account fixed costs as 45 + 4 old opaque CRC bytes.
        t.ip_header_bytes = fixed - 4
        old_wire = t._send_wire
        def emit(wire, kind, header_bytes):
            body_size = len(wire)-t.crc_bytes-header_bytes
            if kind in ("source","retry"):
                source = _unwrap(int.from_bytes(wire[:2],"big") & ID_MASK,len(t.sources)-1)
                union = 1 + vlen(source)
            else:
                assert kind == "repair"
                union = 1 + vlen(t.repair_serial) + vlen(len(t.sources)) + 2
            target = price(kind, fixed + union + body_size)
            prior = t.ip_header_bytes
            t.ip_header_bytes = target - len(wire)
            try:
                return old_wire(wire,kind,header_bytes)
            finally:
                t.ip_header_bytes = prior
        t._send_wire = emit
        old_retry = t._resend
        def retry(source,reason):
            t.source_header = fixed + 1 + vlen(source)
            return old_retry(source,reason)
        t._resend = retry
        old_repair = t._repair
        def repair(tail):
            t.repair_header = fixed + 1 + vlen(t.repair_serial+1) + vlen(len(t.sources)) + 2
            return old_repair(tail)
        t._repair = repair
    for t in transports.values():
        patch_transport(t)
    def install_link(net):
        original = net.send
        def send(reverse,size,kind,receive):
            if kind in ("feedback","gap_request"):
                t = transports[not reverse]
                feedback_sequence[reverse] += 1
                identity = feedback_sequence[reverse]
                if kind == "gap_request":
                    wire, = receive.__defaults__
                    prefix, indices = decode_request(wire,t.policy,t.config.encapsulation)
                    # The first requested offset is zero in the C48 encoder.
                    hdr = 5 + vlen(identity) + vlen(prefix) + vlen(indices[0])
                else:
                    # These are the same values captured by CompactTransport._feedback.
                    prefix = t.received_prefix
                    deficit = max(0,t.highest_received + 1 - len(t.decoder.known) - len(t.decoder.rows))
                    observed = t.highest_received + 1
                    hdr = 1 + sum(map(vlen,(identity,prefix,observed,deficit)))
                size = price(kind,fixed+hdr)
            return original(reverse,size,kind,receive)
        net.send = send
    for net in {id(t.sim):t.sim for t in transports.values()}.values():
        install_link(net)
    return classes, maximum
