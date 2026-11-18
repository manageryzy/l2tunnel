"""Verify cross-lane reassembly and measurement accounting in the normal study."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "studies"))
from frame_channel_recovery import BASE, Study, replace, run_load


def test_independent_stripes_wait_for_actual_frame_bytes():
    def lose(reverse, kind, identity):
        return kind == "source" and identity == (0, 0, 1)

    study = Study(replace(BASE, stripes=2), 9, forced_loss=lose)
    study.offer(0, 1400)
    # Flow 2 uses lanes 2 and 3. Frame 0 uses lanes 0 and 1.
    study.offer(2, 1400)
    study.link.run(.06)
    assert study.delivered == 1
    assert list(study.frame_state) == [0]
    assert list(study.partial[0]) == [1]
    study.link.run(.4)
    assert study.delivered == 2
    assert not study.partial and study.core.pending_frames == 0


def test_short_cutoff_preserves_unfinished_frames_and_zero_measurement():
    result = run_load(BASE, 9, load_mbps=60, duration=.02, warmup=.01, drain=0)
    end = result["after_drain"]
    assert end["offered"] == end["awaiting_delivery"] > 0
    assert end["delivered"] == 0
    assert result["goodput_mbps"] == 0
    assert result["original_to_delivery_ms"]["p99"] is None
    assert result["wire_mbps"][0] > 0
