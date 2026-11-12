"""Audit implicit repair padding from frozen counters and saved source traces.

This program executes no TCP or loss process. Sliding-window replay changes
only analytical coefficient support and record-length projection. Every saved
source ID remains present, including contexts and retransmitted records.
"""
import argparse
from collections import Counter, defaultdict, deque
import csv
from fractions import Fraction
from hashlib import sha256
from html import escape
import json
from math import ceil, floor
from pathlib import Path
import shutil

import numpy as np


STUDIES = ('aligned-record-elision-long','aggregate-ack-long','compact-wire-screen',
           'compact-wire-ack-screen','compact-wire-ack-long')
RATIOS = (.220,.221,.222)


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def write_csv(path, rows):
    with path.open('w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def sliding_maximum(extents, window):
    pending = deque()
    result = []
    for index, value in enumerate(extents):
        while pending and pending[0][0] <= index - window:
            pending.popleft()
        while pending and pending[-1][1] <= value:
            pending.pop()
        pending.append((index, value))
        result.append(pending[0][1])
    return result


def project_packed(rows):
    """Apply the exact normal-entry consecutive-segment predictor relation."""
    by_record = defaultdict(list)
    for row in rows:
        by_record[int(row['flow_id']), int(row['record_serial'])].append(row)
    previous = {}
    result = {}
    for key, group in by_record.items():
        flow, _ = key
        if group[0]['is_context'] == 'True':
            for row in group:
                result[int(row['source_id'])] = (int(row['protected_bytes']), False)
            continue
        segment = int(group[0]['segment_id'])
        eligible = len(group) == 1 and flow in previous and segment == previous[flow] + 1
        if eligible and int(group[0]['protected_bytes']) < 1457:
            raise ValueError('source extent contradicts the modeled sequential header fields')
        for row in group:
            size = int(row['protected_bytes'])
            result[int(row['source_id'])] = (size - 4 if eligible else size, eligible)
        previous[flow] = segment
    assert set(result) == set(range(len(rows)))
    return [result[i] for i in range(len(rows))]


def replay_extent(extents, ratio, tail_count):
    local = sliding_maximum(extents, 128)
    glob = sliding_maximum(extents, 8192)
    ratio=Fraction(str(ratio))
    ends=[end for end in range(1,len(extents)+1) if floor(end*ratio)>floor((end-1)*ratio)]
    local_savings=[1460-local[end-1] for end in ends]
    penalties=[glob[end-1]-local[end-1] for end in ends]
    count=len(ends)
    # Unknown original tail positions can advance the regular G16 phase.
    # Bounds permit every arrangement of that many global opportunities.
    minimum_globals=max(0,count//16-tail_count)
    maximum_globals=min(count,ceil((count+tail_count)/16))
    ordered=sorted(penalties)
    lower=sum(local_savings)-sum(ordered[-maximum_globals:] if maximum_globals else [])
    upper=sum(local_savings)-sum(ordered[:minimum_globals])
    nominal=sum(1460-(glob[end-1] if serial%16==0 else local[end-1]) for serial,end in enumerate(ends,1))
    assert lower<=nominal<=upper
    return dict(source_count=len(extents),regular_repairs=count,retained_tail_repairs=tail_count,
                local_extent_p50=float(np.percentile([local[e-1] for e in ends],50)),
                local_extent_p99=float(np.percentile([local[e-1] for e in ends],99)),
                global_extent_p50=float(np.percentile([glob[e-1] for e in ends],50)),
                global_extent_p99=float(np.percentile([glob[e-1] for e in ends],99)),
                final_tail_extent=glob[-1],source_extent_max=max(extents),
                regular_padding_saved_lower_bytes=lower,regular_padding_saved_nominal_bytes=nominal,
                regular_padding_saved_upper_bytes=upper,mean_saved_per_regular_lower=lower/count,
                mean_saved_per_regular_nominal=nominal/count,mean_saved_per_regular_upper=upper/count,
                tails_charged_full_length=True,global_slot_count_lower=minimum_globals,global_slot_count_upper=maximum_globals)


def load_observations(root):
    rows = []
    receipts = []
    for study in STUDIES:
        base = root / study
        manifest = json.loads((base / 'experiment.json').read_text())
        check = json.loads((base / 'source-verification.json').read_text())
        assert not check['changed_during_run']
        for name, expected in manifest['sources'].items():
            path = base / 'sources' / name
            assert digest(path) == expected
        for path in sorted((base/'runs').glob('*.json')):
            run = json.loads(path.read_text())
            profile = json.loads(run['profile'])
            count = run['shared_source_count']
            padding = run['shared_implicit_padding_bytes']
            contexts = run['shared_context_records']
            header = 26 if profile.get('wire_format') == 'compact_wire' else 36
            assert run['forward_source_bytes'] - header * count == 1460 * count - padding
            rows.append(dict(observation_id=f'{study}/run{run["run_id"]}',study=study,run_id=run['run_id'],seed=run['seed'],
                replication=run['replication'],duration_s=run['duration_s'],flow_count=profile['flow_count'],repair_ratio=profile['compact']['repair_ratio'],
                wire_format=profile.get('wire_format'),source_datagrams=count,context_sources=contexts,fragment_sources=run['shared_fragment_sources'],
                implicit_source_padding_bytes=padding,mean_source_padding_bytes=padding/count,
                mean_noncontext_source_extent=(1460*count-padding-72*contexts)/(count-contexts),
                application_goodput_mbps=run['application_goodput_mbps'],
                all_segment_ack_p99_ms=run['with_drain_tcp_all_segment_ack_rtt_p99_ms'],
                fully_confirmed=run['fully_confirmed'],actual_repair_extent_histogram_available=False,
                source_file=str(path.resolve()),source_sha256=digest(path)))
            receipts.append(dict(path=str(path.resolve()),sha256=digest(path)))
        receipts.extend(dict(path=str((base/name).resolve()),sha256=digest(base/name)) for name in ['experiment.json','source-verification.json'])
    return rows,receipts


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path('work/results-20261110/tcp-latency'))
    parser.add_argument('--out',type=Path,default=Path('work/results-20261110/tcp-latency/repair-extent-audit'))
    args=parser.parse_args();out=args.out;out.mkdir(parents=True,exist_ok=True)
    shutil.copy2(__file__,out/'analysis-source.py')
    observations,receipts=load_observations(args.root)
    write_csv(out/'archive-observations.csv',observations)
    trace_rows=[];trace_hist=[];trace_source=args.root/'aligned-latency-stages'
    trace_manifest=json.loads((trace_source/'experiment.json').read_text())
    receipts.append(dict(path=str((trace_source/'experiment.json').resolve()),sha256=digest(trace_source/'experiment.json')))
    for name,expected in trace_manifest['sources'].items():assert digest(trace_source/'sources'/name)==expected
    for run_id in (2,4,6):
        path=trace_source/'stages'/f'{run_id:05d}-sources.csv';rows=list(csv.DictReader(path.open()))
        rows.sort(key=lambda r:int(r['source_id']))
        run=json.loads((trace_source/'runs'/f'{run_id:05d}.json').read_text())
        task=next(t for t in trace_manifest['tasks'] if t['run_id']==run_id)
        assert task['profile']['flow_count']==64 and task['profile']['compact']['elide_payload_length']
        assert task['payload_bytes']==1448 and task['duration_s']==10 and task['rtt_ms']==70
        projected=project_packed(rows);original=[int(r['protected_bytes']) for r in rows]
        assert len(rows)==run['shared_source_count'] and sum(1460-x for x in original)==run['shared_implicit_padding_bytes']
        source_projection=[dict(source_id=i,original_extent=size,projected_packed_extent=projected[i][0],prediction_eligible=projected[i][1]) for i,size in enumerate(original)]
        write_csv(out/f'trace-{run_id:05d}-projection.csv',source_projection)
        for codec,extents in [('original_kind6',original),('packed_kind_projection',[p[0] for p in projected])]:
            for extent,count in sorted(Counter(extents).items()):trace_hist.append(dict(source_run=run_id,codec=codec,extent=extent,source_count=count))
            for ratio in RATIOS:
                result=replay_extent(extents,ratio,run['shared_tail_repairs'])
                trace_rows.append(dict(case_id=f'trace{run_id}-{codec}-r{ratio}',analysis_kind='fixed_source_sequence_extent_replay',
                    source_run=run_id,seed=run['seed'],source_duration_s=10,flow_count=64,codec=codec,repair_ratio=ratio,
                    **result,source_file=str(path.resolve()),source_sha256=digest(path)))
        receipts.extend(dict(path=str(p.resolve()),sha256=digest(p)) for p in [path,trace_source/'runs'/f'{run_id:05d}.json'])
    write_csv(out/'trace-cases.csv',trace_rows);write_csv(out/'trace-histograms.csv',trace_hist)
    budgets=[]
    for observation in observations:
        if observation['study']!='compact-wire-ack-long':continue
        run=json.loads(Path(observation['source_file']).read_text());source_count=run['shared_source_count'];n=run['offered_frames'];tails=run['shared_tail_repairs']
        for ratio in RATIOS:
            repairs=floor(Fraction(str(ratio))*source_count)
            full=run['forward_source_bytes']+repairs*1488+tails*1496
            for saving in (0,8):
                total=full-saving*(repairs+tails)
                budgets.append(dict(case_id=f'long{run["run_id"]}-r{ratio}-save{saving}',analysis_kind='fixed_long_cohort_wire_bound',
                    source_run=run['run_id'],seed=run['seed'],duration_s=60,flow_count=64,repair_ratio=ratio,
                    assumed_saving_per_repair=saving,assumption='full1460' if saving==0 else 'optimistic_minimum1452_extent',
                    original_segments=n,source_datagrams=source_count,regular_repairs=repairs,tail_repairs=tails,
                    forward_ip_bytes=total,analytical_byte_capacity_mbps=100*n*1448/total,
                    reference_measured_full_mbps=run['application_goodput_mbps'],
                    reference_wire_capacity_mbps=100*n*1448/run['forward_wire_bytes'],
                    actual_short_repair_throughput_mbps=None,actual_short_repair_latency_ms=None,
                    source_file=observation['source_file'],source_sha256=observation['source_sha256']))
    write_csv(out/'long-cohort-bounds.csv',budgets)
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig,axes=plt.subplots(1,3,figsize=(17,5.2))
    palette=['#334155','#7b3294','#2171b5','#238b45','#d95f02']
    for color,study in zip(palette,STUDIES):
        subset=[r for r in observations if r['study']==study]
        axes[0].scatter([r['mean_source_padding_bytes'] for r in subset],[r['application_goodput_mbps'] for r in subset],color=color,s=20,label=study)
    for codec,color in [('original_kind6','#334155'),('packed_kind_projection','#238b45')]:
        subset=[r for r in trace_rows if r['codec']==codec]
        axes[1].errorbar([100*r['repair_ratio'] for r in subset],[r['mean_saved_per_regular_nominal'] for r in subset],
            yerr=[[r['mean_saved_per_regular_nominal']-r['mean_saved_per_regular_lower'] for r in subset],[r['mean_saved_per_regular_upper']-r['mean_saved_per_regular_nominal'] for r in subset]],
            fmt='o',ms=4,color=color,capsize=2,label=codec)
    for saving,color in [(0,'#334155'),(8,'#b45309')]:
        subset=[r for r in budgets if r['assumed_saving_per_repair']==saving]
        axes[2].scatter([100*r['repair_ratio'] for r in subset],[r['analytical_byte_capacity_mbps'] for r in subset],color=color,label=f'{saving} B saved per repair',s=24)
    axes[0].set(xlabel='Observed mean implicit source padding (B)',ylabel='Measured application goodput (Mbps)',title='Every archived observation · mixed durations')
    axes[1].set(xlabel='Repair/source ratio (%)',ylabel='Saved bytes per regular repair',title='64-flow source sequence replay · all 18 cases')
    axes[2].set(xlabel='Repair/source ratio (%)',ylabel='Analytical byte capacity (Mbps)',title='Three 60 s cohorts · all 18 budget points')
    axes[2].axhline(80,color='red',ls='--',lw=1)
    for axis in axes:axis.grid(alpha=.2);axis.legend(fontsize=6)
    fig.tight_layout();fig.savefig(out/'all-audit-points.png',dpi=180);plt.close(fig)
    table=''.join(f'<tr><td>{r["source_run"]}</td><td>{r["codec"]}</td><td>{r["repair_ratio"]:.3f}</td><td>{r["source_count"]}</td><td>{r["local_extent_p50"]:.0f}/{r["local_extent_p99"]:.0f}</td><td>{r["global_extent_p50"]:.0f}/{r["global_extent_p99"]:.0f}</td><td>{r["mean_saved_per_regular_nominal"]:.6f}</td><td>{r["mean_saved_per_regular_lower"]:.6f}–{r["mean_saved_per_regular_upper"]:.6f}</td><td>{r["final_tail_extent"]}</td></tr>' for r in trace_rows)
    budget_table=''.join(f'<tr><td>{r["source_run"]}</td><td>{r["repair_ratio"]:.3f}</td><td>{r["assumed_saving_per_repair"]}</td><td>{r["analytical_byte_capacity_mbps"]:.6f}</td><td>{r["reference_measured_full_mbps"]:.6f}</td></tr>' for r in budgets)
    observed_table=''.join(f'<tr><td>{escape(r["observation_id"])}</td><td>{r["flow_count"]}</td><td>{r["duration_s"]}</td><td>{r["mean_source_padding_bytes"]:.6f}</td><td>{r["mean_noncontext_source_extent"]:.6f}</td><td>{r["context_sources"]}</td><td>{r["fragment_sources"]}</td><td>{r["application_goodput_mbps"]:.6f}</td></tr>' for r in observations)
    (out/'report.html').write_text(f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Repair extent audit</title><style>body{{font:16px/1.5 system-ui;max-width:1300px;margin:auto;padding:20px;background:#f8fafc;color:#172033}}section{{padding:20px;margin:18px 0;background:white;border-radius:12px}}.scroll{{overflow:auto;max-width:100%}}img{{width:1450px;max-width:none}}table{{border-collapse:collapse;min-width:950px;font-size:14px}}td,th{{padding:8px;border-bottom:1px solid #ddd;text-align:left}}a{{color:#155e9b}}code{{overflow-wrap:anywhere}}.notice{{border-left:5px solid #b45309}}</style>
<h1>Repair extent audit</h1><p>Fixed 1460-byte protected symbols · 100/10 Mbps IP service · 70 ms RTT · 15% IID loss · 1448-byte application payload</p>
<section class="notice"><strong>Source-trace replay and byte-bound analysis with zero new TCP executions</strong><p>This audit preserves {len(observations)} archived run observations, {len(trace_rows)} fixed-source-sequence cases and {len(budgets)} long-cohort byte bounds. All points are plotted. Exact per-source extents exist for three older 64-flow 10 s traces. The current 64-flow 60 s compact-wire runs and 128/224-flow 10 s runs retain aggregate padding counters only. The historical 128/256-flow 60 s observations use the older format. A 224-flow 60 s source trace is absent.</p><p>Encoded source extent and repair extent differ. A repair must include the largest encoded extent in its actual support. An opaque payload containing zero-valued bytes still occupies its complete encoded extent.</p></section>
<section><h2>Every observation and analytical case</h2><div class="scroll"><img src="all-audit-points.png" alt="All archived observations, source replay cases and long-run byte bounds"></div><p>The first panel combines observed padding and measured throughput with durations retained in the table. It defines no shared Pareto frontier across those durations. The other panels contain analytical cases with their own denominators. Proposed truncation has no measured TCP throughput or latency coordinate.</p><p><a href="archive-observations.csv">All observations</a> · <a href="trace-cases.csv">Every replay case</a> · <a href="trace-histograms.csv">All extent histograms</a> · <a href="long-cohort-bounds.csv">Every long-cohort bound</a></p></section>
<section><h2>Exact fixed-source-sequence replay</h2><div class="scroll"><table><thead><tr><th>Source run</th><th>Codec</th><th>Ratio</th><th>Original source count</th><th>Local extent P50/P99</th><th>Global extent P50/P99</th><th>Nominal saved B/repair</th><th>Global-phase bound</th><th>Final tail extent</th></tr></thead><tbody>{table}</tbody></table></div><p>Original kind6 extents come directly from saved source rows. The packed projection saves 4 bytes only for a single-source record whose per-flow TCP segment follows its predecessor. The normal-entry frame construction proves IPID+1, sequence+1448 and unchanged ACK for these records. Initial data, contexts, retries, retry neighbors and fragments retain their original extent whenever the relation fails. Original source IDs and order remain intact.</p><p>Nominal repair slots follow floor(r×source count), with every 16th regular opportunity global. The original trace omits actual tail send positions, so phase bounds allow the recorded tail count to shift global opportunities. All tails are conservatively charged at 1460 bytes. Local support is the last 128 sources and global support the last 8192. These are metadata-only support calculations with every original source included. New forward sizes and FEC rates would change TCP events.</p></section>
<section><h2>Current 60-second cohort byte bounds</h2><div class="scroll"><table><thead><tr><th>Source run</th><th>Ratio</th><th>Assumed saved B/repair</th><th>Analytical byte capacity Mbps</th><th>Original measured full Mbps</th></tr></thead><tbody>{budget_table}</tbody></table></div><p>The 8-byte case is an optimistic format ceiling. A full 1448-byte record carries at least a 3-byte protected channel prefix and 1-byte codec kind, giving an extent of at least 1452. Each fixed support in this established full-payload workload contains a complete data source. Actual maxima, timestamp varints and fragment sources can reduce savings. The current long traces have no fragment sources. The byte-capacity calculation keeps original source bytes, segment denominator and tail count, changes the scheduled repair count, and assumes continuous forward service. Startup, queueing, changed recovery and ACK timing remain additional constraints.</p></section>
<section><h2>Minimal implementation candidate</h2><ol><li>Use the existing <code>CompactSource.size</code> values to compute <code>extent = max(source.size for source in sources[start:end])</code> for the exact transmitted support. The 8192-source sender payload retention already covers global support. The current 1460-byte zero extension is explicit encoder padding.</li><li>Serialize only the first extent repair bytes. Keep the typed source/end and serial fields unchanged, including the 12-byte tail escape. Packet length conveys extent. Validate the CRC over the received compact header and transmitted payload before parsing or zero extension.</li><li>Accept a repair payload of 1–1460 bytes, then append exactly 1460−extent zeros before existing coefficient/block interpretation. Every omitted source column is zero across the support, which makes the omitted GF256 repair column zero. Actual byte fixtures check this identity using nonzero payload contents.</li><li>Retain full extent whenever any covered source occupies 1460 bytes. A first fragment usually does so. A local repair keeps that cost until it leaves W128, and a global or tail repair until it leaves W8192. Short context records reduce source averages while longer data records determine repair length.</li></ol><p>The expected saving from the older packed trace is a few bytes per repair. Each additional 0.001 repair/source ratio costs about 1.488 IP bytes per original data source before small context effects. This makes r=.221 a narrow candidate for full-goodput verification. The r=.222 joint outcome remains unresolved by the byte bounds. Actual current-profile extent histograms and a controlled protocol run are needed to turn this candidate into a measured result.</p><p>Bulk repair RHS arithmetic and CPU costs remain outside the simulator. This audit computes exact scalar GF identities in a small test, then analyzes lengths. Model fidelity remains explicitly separate from reduced byte accounting.</p></section>
<section><h2>All archived source observations</h2><div class="scroll"><table><thead><tr><th>Observation</th><th>Flows</th><th>Traffic seconds</th><th>Mean implicit source padding B</th><th>Mean noncontext extent B</th><th>Contexts</th><th>Fragment sources</th><th>Measured full Mbps</th></tr></thead><tbody>{observed_table}</tbody></table></div></section>
<section><h2>Reproduce and verify</h2><p><a href="analysis-source.py">Frozen analysis source</a> · <a href="validation.json">Validation and source hashes</a> · <a href="trace-00002-projection.csv">Source2 projection</a> · <a href="trace-00004-projection.csv">Source4 projection</a> · <a href="trace-00006-projection.csv">Source6 projection</a></p></section></html>''')
    validation=dict(protocol_executions=0,archived_observations=len(observations),trace_cases=len(trace_rows),long_bound_cases=len(budgets),
        distinct_source_traces=3,original_trace_sources=sum(r['source_count'] for r in trace_rows if r['codec']=='original_kind6' and r['repair_ratio']==.22),
        original_trace_source_ids_preserved=True,source_snapshots_verified=True,script_sha256=digest(Path(__file__)),source_receipts=receipts)
    assert all(digest(Path(r['path']))==r['sha256'] for r in receipts)
    (out/'validation.json').write_text(json.dumps(validation,indent=2)+'\n')
    print(json.dumps({k:v for k,v in validation.items() if k!='source_receipts'}))


if __name__=='__main__':main()
