from pathlib import Path
import csv
import json
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'studies'))
from repair_extent_audit import project_packed,replay_extent,sliding_maximum
import repair_extent_audit
from l2tunnel_sim.coding import PRODUCT


def test_sliding_maximum_expires_only_after_support_moves():
    values=[1454,1460,1453,1453,1453]
    assert sliding_maximum(values,3)==[1454,1460,1460,1460,1453]


def test_packed_projection_preserves_context_retry_and_ids():
    rows=[dict(source_id=str(i),flow_id='0',record_serial=str(i),segment_id=str(segment),is_context=str(context),protected_bytes=str(size))
          for i,(segment,context,size) in enumerate([(0,True,72),(0,False,1453),(1,False,1458),(0,False,1459),(2,False,1458),(3,False,1457)])]
    assert project_packed(rows)==[(72,False),(1453,False),(1454,True),(1459,False),(1458,False),(1453,True)]


def test_full_extent_inside_window_removes_truncation_opportunity():
    result=replay_extent([1460]*1000,.22,3)
    assert result['regular_padding_saved_lower_bytes']==result['regular_padding_saved_upper_bytes']==0


def test_global_phase_bounds_include_every_static_phase():
    extents=[1453+(i%113==0)*7 for i in range(2000)]
    result=replay_extent(extents,.22,8)
    assert result['regular_padding_saved_lower_bytes']<=result['regular_padding_saved_nominal_bytes']<=result['regular_padding_saved_upper_bytes']


def test_numeric_gf_tail_truncation_uses_encoded_extent_not_payload_zeros():
    sources=[b'\x00\x00\x00\x00',b'abc',b'\xff\x10']
    coefficients=[17,201,6]
    extent=max(map(len,sources));padded=[s+bytes(8-len(s)) for s in sources]
    parity=bytes(PRODUCT[coefficients[0]][a]^PRODUCT[coefficients[1]][b]^PRODUCT[coefficients[2]][c] for a,b,c in zip(*padded))
    assert extent==4
    assert parity[extent:]==bytes(8-extent)
    assert parity[:extent]+bytes(8-extent)==parity


def test_observation_export_preserves_raw_replication_and_duration(tmp_path, monkeypatch):
    study = tmp_path / 'example'
    (study / 'runs').mkdir(parents=True)
    (study / 'experiment.json').write_text(json.dumps({'sources': {}}))
    (study / 'source-verification.json').write_text(json.dumps({'changed_during_run': []}))
    raw = dict(run_id=7, seed=991, replication=2, duration_s=60,
               profile=json.dumps({'flow_count': 64, 'compact': {'repair_ratio': .22},
                                   'wire_format': 'compact_wire'}),
               shared_source_count=2, shared_implicit_padding_bytes=1394,
               shared_context_records=1, shared_fragment_sources=0,
               forward_source_bytes=1578, application_goodput_mbps=80.01,
               with_drain_tcp_all_segment_ack_rtt_p99_ms=110.2, fully_confirmed=True)
    (study / 'runs' / '00007.json').write_text(json.dumps(raw))
    monkeypatch.setattr(repair_extent_audit, 'STUDIES', ('example',))
    rows, _ = repair_extent_audit.load_observations(tmp_path)
    assert rows[0]['replication'] == 2
    assert type(rows[0]['duration_s']) is int
    export = tmp_path / 'observations.csv'
    repair_extent_audit.write_csv(export, rows)
    with export.open() as stream:
        saved = next(csv.DictReader(stream))
    for key in ('run_id', 'seed', 'replication', 'duration_s'):
        assert saved[key] == str(raw[key])
