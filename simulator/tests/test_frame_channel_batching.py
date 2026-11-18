import importlib
from pathlib import Path

import pytest


@pytest.fixture
def study(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "studies"))
    return importlib.import_module("frame_channel_batching")


def test_length_table_preserves_arbitrary_frames_and_rejects_bad_lengths(study):
    frames = [b"xy", b"\x00", b"\xff\x10", bytes(range(7))]
    encoded = study.encode(frames)
    assert encoded[:9] == b"\x04\x00\x02\x00\x01\x00\x02\x00\x07"
    assert study.decode(encoded) == frames
    for bad in (b"", b"\x00", b"\x05", encoded[:3], encoded[:-1], encoded + b"z", b"\1\0\0"):
        with pytest.raises(ValueError):
            study.decode(bad)


def test_flush_timer_and_one_lost_batch_preserve_individual_delivery_age(study):
    job = study.PackedWorkload(4, 99)
    job.net.forced_loss = lambda rev, kind, identity: kind == "source" and identity == (0,0,1)
    for n in range(3):
        job.net.at(n * .0005, job.offer, n * study.LANES)
    job.net.run(.0024)
    assert not job.records
    job.net.run(.0026)
    assert job.records == {3: 1}
    job.net.run(.5)
    assert len(job.samples) == 3
    assert len({sample[0] for sample in job.samples}) == 1
    assert [round((a-o)*1000, 3) for d,o,a in job.samples] == [2.5, 2, 1.5]
    assert job.core.metrics["rto"] == 1 and job.counts()["retained_originals"] == 0
