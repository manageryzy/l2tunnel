"""Offline mixed-shard geometry, delayed feedback and paid retry byte budgets."""
import argparse
from collections import Counter, defaultdict, deque
import csv
from functools import lru_cache
import hashlib
import json
from math import expm1, log1p
from pathlib import Path
from statistics import mean
import struct

from path_geometry_model import OUTER, poisson_binomial, shard_shape, uint_len, wire


REPAIR = {"path_retry_paid", "named_paid", "named_copy_paid", "quiet_paid"}
ETHERNET = 14


def native_lengths(path, port):
    sizes = defaultdict(deque)
    with path.open("rb") as f:
        hdr = f.read(24)
        order = {bytes.fromhex("d4c3b2a1"):"<", bytes.fromhex("a1b2c3d4"):">"}[hdr[:4]]
        offset = {1:14,12:0,101:0,113:16,276:20,228:0}[struct.unpack_from(order+"I",hdr,20)[0]]
        while row := f.read(16):
            length = struct.unpack(order+"4I",row)[2]
            ip = f.read(length)[offset:]
            tcp = ip[(ip[0]&15)*4:]
            if ip[9] != 6:
                continue
            source, dest, seq, ack = struct.unpack_from("!HHII",tcp)
            if source != port:
                continue
            size = int.from_bytes(ip[2:4],"big")
            flags = tcp[13]
            data = size-(ip[0]&15)*4-(tcp[12]>>4)*4
            end = (seq+data+bool(flags&1)+bool(flags&2)) % (1<<32)
            sizes[source,dest,seq,end,ack,flags].append(size)
    return sizes


def digest(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f,"sha256").hexdigest()


def parse(arm, side, result, port):
    sizes = native_lengths(arm/f"{side}-native.pcap", port)
    native, packets, seqmap, opened, kth, first_ordinal, received_positive = {}, {}, {}, {}, {}, {}, defaultdict(dict)
    jump = defaultdict(dict)
    with (arm/f"{side}-trace.csv").open() as f:
        rows = csv.reader(f)
        next(rows)
        for row in rows:
            ev = row[1]
            if ev == "native_read":
                signature = tuple(int(row[i]) for i in (11,12,7,8,9,10))
                native[int(row[2])] = (int(row[0]), sizes[signature].popleft())
            elif ev == "socket_paid":
                t, pn, slot = int(row[0]), int(row[5]), int(row[3])
                seq = int(row[4]) if row[4] else None
                packets[pn] = (t, int(row[-1]), slot, seq, [])
                if seq is not None:
                    seqmap[slot,seq] = pn
            elif ev == "fresh_paid" or ev in REPAIR:
                old = int(row[-2]) if ev == "path_retry_paid" else None
                packets[int(row[5])][4].append((int(row[2]),int(row[6]),ev,old))
            elif ev == "shard_rx":
                t, pn = int(row[0]),int(row[5])
                opened.setdefault(pn,t)
                first_ordinal.setdefault((int(row[2]),int(row[6])),t)
            elif ev == "kth":
                kth[int(row[2])] = int(row[0])
            elif ev in ("physical_ack_prefix_rx","physical_ack_range_rx"):
                slot = int(row[6])
                lo, hi = map(int,row[-2:])
                while lo < hi:
                    nxt = jump[slot].get(lo)
                    if nxt is None:
                        received_positive[slot][lo] = int(row[0])
                        nxt = lo+1
                    jump[slot][lo] = max(nxt,hi)
                    lo = nxt
    assert not any(sizes.values())
    assert len(native) == result["adapter_stats"][side]["next_generation"]
    return native,packets,seqmap,opened,kth,first_ordinal,received_positive


WINDOWS = (8, 13, 16, 32, 49, 64, 128, 751)


def window_observations(failures):
    prefix = [0]
    for failed in failures:
        prefix.append(prefix[-1]+failed)
    result = {}
    for width in WINDOWS:
        spans = len(failures)-width+1
        if spans > 0:
            holes = sum(prefix[i+width] != prefix[i] for i in range(spans))
            result[width] = dict(windows=spans,any_failed=holes,probability=holes/spans)
    return result


def window_scenarios(fail, lag):
    def any_hole(width, correlation):
        if fail == 1:
            return 1.
        return -expm1(log1p(-fail)+(width-1)*log1p(-fail*(1-correlation)))
    return {w:dict(independent_groups=any_hole(w,0), fitted_lag_one=any_hole(w,lag),
                   dependence_free_upper=min(1.,w*fail)) for w in WINDOWS}


def calibrate(own, peer, steady, unique, n, k):
    native, packets, seqmap, _, _, _, ack = own
    _, _, _, opened, kth, first_ordinal, _ = peer
    lo,hi = steady
    size_hist = Counter(v for t,v in native.values() if lo <= t < hi)
    groups = {g:[None]*n for g,(t,_) in native.items() if lo <= t < hi}
    paid, budgets, retry = Counter(), Counter(), Counter()
    first_slot = [Counter() for _ in range(n)]
    byslot = [[] for _ in range(n)]
    false_retry = Counter()
    for pn,(t,ip,slot,seq,members) in packets.items():
        steady_pay = lo <= t < hi
        if seq is None:
            if steady_pay:
                budgets["standalone_control_l2"] += ip+ETHERNET
            continue
        header = OUTER + 3 + uint_len(seq) + ETHERNET
        extents = Counter()
        for gid,ordinal,role,old in members:
            fresh = role == "fresh_paid"
            if fresh and gid in groups:
                assert groups[gid][ordinal] is None
                groups[gid][ordinal] = pn
            if not steady_pay:
                continue
            shard = shard_shape(n,k,native[gid][1],ordinal)
            cross = ordinal != slot
            extent = uint_len(gid)+uint_len(2*shard+cross)+cross+shard
            cls = "fresh" if fresh else "retry"
            extents[cls] += extent
            paid[cls+"_members"] += 1
            if fresh:
                continue
            retry[role+"_entry_bytes"] += extent
            if kth.get(gid,1<<63) <= t or first_ordinal.get((gid,ordinal),1<<63) <= t:
                false_retry["after_peer_k_or_ordinal_members"] += 1
                false_retry["after_peer_k_or_ordinal_entry_bytes"] += extent
            if old is not None:
                oldpn = seqmap[slot,old]
                if opened.get(oldpn,1<<63) <= t:
                    key = ("old_open_positive_ack_before_retry" if ack[slot].get(old,1<<63) <= t
                           else "old_open_positive_ack_after_retry" if old in ack[slot]
                           else "old_open_positive_ack_unseen")
                    false_retry[key+"_members"] += 1
                    false_retry[key+"_entry_bytes"] += extent
        if steady_pay:
            byslot[slot].append((seq,pn not in opened))
            total = sum(extents.values())
            assert total and ip+ETHERNET >= total+header,(pn,ip,total,header)
            budgets["DATA_l2"] += ip+ETHERNET
            budgets["fresh_entry_bytes"] += extents["fresh"]
            budgets["retry_entry_bytes"] += extents["retry"]
            budgets["piggyback_bytes"] += ip+ETHERNET-header-total
            budgets["retry_allocated_l2"] += extents["retry"]*(1+header/total)
            budgets["DATA_shared_header_l2"] += header
            paid["DATA_packets"] += 1
            paid["DATA_missing"] += pn not in opened
            paid["fresh_only_packets"] += not extents["retry"]
            if not extents["retry"]:
                paid["fresh_only_entries"] += len(members)
    previous = None
    same = Counter()
    hist = Counter()
    block = defaultdict(list)
    failures = []
    loss_sum = sum(paid_bit for lane in byslot for _,paid_bit in lane)
    assert loss_sum == paid["DATA_missing"]
    for g,members in groups.items():
        assert all(p is not None for p in members)
        mask = [pn not in opened for pn in members]
        hist[sum(mask)] += 1
        failures.append(sum(mask) > n-k)
        for i,v in enumerate(mask):
            first_slot[i]["lost"] += v
        if previous is not None:
            same[sum(a==b for a,b in zip(previous,members))] += 1
        previous = members
        block[(native[g][0]-lo)//250000000].append(sum(mask)/n)
    G = len(groups)
    p = sum(i*c for i,c in hist.items())/(n*G)
    pair = sum(i*(i-1)*c for i,c in hist.items())/(n*(n-1)*G)
    rho = min(.999,max(0,(pair-p*p)/(p*(1-p)))) if 0<p<1 else 0
    transitions = Counter()
    for lane in byslot:
        ordered = sorted(lane)
        for (s,v),(z,w) in zip(ordered,ordered[1:]):
            if z==s+1:
                transitions[v,w]+=1
    pl = transitions[True,True]/max(1,transitions[True,True]+transitions[True,False])
    pg = transitions[False,True]/max(1,transitions[False,True]+transitions[False,False])
    deficit = sum(max(0,i-(n-k))*c for i,c in hist.items())/G
    all_l2 = budgets["DATA_l2"]+budgets["standalone_control_l2"]
    blocks = [(i,mean(v),len(v)) for i,v in sorted(block.items())]
    fail = mean(failures)
    transitions_across_groups = sum(a and b for a,b in zip(failures,failures[1:]))/max(1,len(failures)-1)
    group_lag = max(0,min(1,(transitions_across_groups-fail*fail)/(fail*(1-fail)))) if 0<fail<1 else 0
    assert abs(budgets["DATA_l2"]-sum(budgets[x] for x in ("fresh_entry_bytes","retry_entry_bytes","piggyback_bytes","DATA_shared_header_l2"))) < .1
    return dict(groups=G,unique_application_bytes_for_same_wall_window=unique, size_hist=dict(size_hist),
                physical=paid, byte_ledger=budgets, retry_roles=retry, receiver_known_at_retry_payment=false_retry,
                first_loss_by_slot=[v["lost"]/G for v in first_slot],first_loss_p=p,
                physical_data_missing_fraction=paid["DATA_missing"]/paid["DATA_packets"],
                rank_loss_hist=dict(hist),rank_failure=sum(c for i,c in hist.items() if i>n-k)/G,
                deficit=deficit, lag_one_loss_after_loss=pl, lag_one_loss_after_success=pg,
                joint_first_loss=pair, rho=rho, same_PN_with_previous_group=dict(same),
                consecutive_native_groups_window=window_observations(failures), rank_failure_lag=group_lag,
                quarter_second_loss_blocks=blocks,
                mean_occupancy=(paid["fresh_members"]+paid["retry_members"])/paid["DATA_packets"],
                fresh_only_mean_occupancy=paid["fresh_only_entries"]/max(1,paid["fresh_only_packets"]),
                charged_retry_share_DATA=budgets["retry_allocated_l2"]/budgets["DATA_l2"],
                charged_retry_share_total=budgets["retry_allocated_l2"]/all_l2)


@lru_cache(maxsize=2048)
def rank_cost(n,k,p,rho):
    if not 0 <= p <= 1 or not 0 <= rho < 1 or not 1 <= k <= n:
        raise ValueError("invalid mixed geometry")
    if p in (0,1) or rho == 0:
        mass = poisson_binomial((p,)*n)
    else:
        # Local random loss probability shared by distinct packets within this group.
        scale = 1/rho-1
        a,b = p*scale,(1-p)*scale
        value = 1.
        for i in range(n):
            value *= (b+i)/(a+b+i)
        mass = [value]
        for i in range(n):
            mass.append(mass[-1]*(n-i)/(i+1)*(a+i)/(b+n-i-1))
    assert abs(sum(mass)-1)<1e-7
    return sum(mass[n-k+1:]),sum((i-(n-k))*v for i,v in enumerate(mass) if i>n-k)


def price(n,k,cal,scenario,occupancy,feedback):
    p = cal["first_loss_p"]
    rho = cal["rho"] if scenario.startswith("correlated") else 0
    fail,need = rank_cost(n,k,p,rho)
    q = (cal["lag_one_loss_after_loss"] if scenario.endswith("burst") else p)
    # Same-slot next-packet retry under persistence. A different independent slot uses its marginal.
    if q>=1:
        return None
    attempts = need/(1-q)
    G = cal["groups"]
    paid = cal["physical"]
    stale_per_original = cal["receiver_known_at_retry_payment"]["after_peer_k_or_ordinal_members"]/max(1,paid["fresh_members"])
    actual_need = cal["deficit"]/(1-cal["physical_data_missing_fraction"])
    excess = max(0,(paid["retry_members"]-cal["receiver_known_at_retry_payment"]["after_peer_k_or_ordinal_members"])
                 /G/max(actual_need,1e-12))
    if feedback == "observed":
        attempts = attempts*excess + n*stale_per_original
    fresh = retry_one = 0.
    for size,count in cal["size_hist"].items():
        size = int(size)
        f = wire(n,k,size,1500,occupancy,4096,4096)
        r = wire(n,k,size,1500,occupancy,4096,4096,cross=True)
        if not f or not r:
            return None
        fresh += (f[0]+ETHERNET*f[1])*count/G
        retry_one += (r[0]+ETHERNET*r[1])/n*count/G
    b = cal["byte_ledger"]
    piggy = b["piggyback_bytes"]/G
    standalone = b["standalone_control_l2"]/G
    retry = retry_one*attempts
    data = fresh+retry+piggy
    total = data+standalone
    return dict(rank_failure=fail,missing_innovative=need,expected_retry_members=attempts,
                window_any_initially_undecodable=window_scenarios(fail,cal["rank_failure_lag"]),
                retry_l2_per_group=retry,retry_share_DATA=retry/data,retry_share_total=retry/total,
                base_l2_per_group=fresh, total_l2_per_group=total,
                demand_mbps_at_70=70*total*G/cal["unique_application_bytes_for_same_wall_window"])


def screen(cal, max_paths, targets):
    output = {}
    for case,scenario,batch,feedback in (
            ("independent_full_ideal","independent","full","ideal"),
            ("independent_measured_load_ideal","independent","observed","ideal"),
            ("correlated_burst_measured_load_ideal","correlated-burst","observed","ideal"),
            ("correlated_burst_measured_load_feedback","correlated-burst","observed","observed")):
        candidates = []
        for n in range(5,max_paths+1):
            for k in range(1,n):
                sides = []
                for side in "ab":
                    s = cal[side]
                    occ = 255 if batch=="full" else s["mean_occupancy"]
                    sides.append(price(n,k,s,scenario,occ,feedback))
                if all(sides):
                    a,b = sides
                    candidates.append(dict(n=n,k=k,a=a,b=b,ceiling=min(7000/a["demand_mbps_at_70"],700/b["demand_mbps_at_70"])))
        def pick(rows,target):
            fits = [r for r in rows if max(r["a"]["retry_share_DATA"],r["b"]["retry_share_DATA"])<=target]
            feasible = [r for r in fits if r["ceiling"]>=70]
            winner = max(feasible or fits,key=lambda r:r["ceiling"],default=None)
            return dict(retry_eligible=len(fits),both_budget_feasible=len(feasible),
                        min_feasible_n=min((r["n"] for r in feasible),default=None),
                        best=winner)
        output[case] = dict(six_five=next(r for r in candidates if r["n"]==6 and r["k"]==5),
                            targets={str(t):dict(any_k=pick(candidates,t), fixed_k5=pick([r for r in candidates if r["k"]==5],t),
                                    current_six_slots=pick([r for r in candidates if r["n"]==6],t)) for t in targets})
    return output


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("case",nargs="+",type=Path)
    ap.add_argument("--output",required=True,type=Path)
    ap.add_argument("--max-paths",type=int,default=24)
    ap.add_argument("--targets",nargs="+",type=float,default=(.01,.03,.05,.10,.20))
    args = ap.parse_args()
    if not 6<=args.max_paths<=255 or not all(0<t<1 for t in args.targets):
        ap.error("invalid requested screening limits")
    if args.output.exists():
        raise FileExistsError(args.output)
    output = {"cases":{}, "targets":args.targets,"max_paths":args.max_paths,
              "source_sha256":digest(Path(__file__)),"base_geometry_sha256":digest(Path(__file__).with_name("path_geometry_model.py"))}
    for arm in args.case:
        result = json.loads((arm/"result.json").read_bytes())
        assert result["status"]=="passed" and result["request"]["loss_after_shaper"]
        probe = json.loads((arm/"probe/a.json").read_bytes())
        steady = [probe["clock"][x] for x in ("measure_start_ns","end_ns")]
        unique = result["throughput"]["a_to_b"]["receiver_unique_sample_bytes"]
        byside = {}
        pins = {"result.json":digest(arm/"result.json"),"probe/a.json":digest(arm/"probe/a.json")}
        for side in "ab":
            port = result["flow_identity"][0]["connections"][0]["local" if side=="a" else "peer"][1]
            for suffix, field in (("-native.pcap","native_capture"),("-trace.csv","adapter_trace")):
                pins[side+suffix] = digest(arm/(side+suffix))
                assert pins[side+suffix]==result[field][side]["sha256"]
            assert result["adapter_stats"][side]["trace"]["dropped"]==0
            assert result["native_capture"][side]["counters"]["dropped"]==0
            byside[side] = parse(arm,side,result,port)
        c = {s:calibrate(byside[s],byside["b" if s=="a" else "a"],steady,unique,6,5) for s in "ab"}
        output["cases"][arm.name] = dict(steady=steady, pins=pins, native_goodput_mbps=result["throughput"]["a_to_b"]["goodput_mbit_s"],
                                           measured=c,screen=screen(c,args.max_paths,args.targets))
    with args.output.open("x") as f:
        json.dump(output,f,indent=2)
        f.write("\n")


if __name__ == "__main__":
    main()

