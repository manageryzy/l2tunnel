"""Synthetic carrier backpressure separates timer preparation, departure and arrival."""
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import pytest

from test_packed_targeted import fixture, step


def test_compact_mixed_feedback_actual_payload(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "studies"))
    from packed_striped_timing import feedback_bytes, parse_feedback
    combined = bytes.fromhex("13 80 01 7f 80 01 81 01")
    assert feedback_bytes(128,128,(128,135)) == combined
    assert parse_feedback(combined) == (128,128,(128,135))
    for malformed in (combined+b"\0",bytes.fromhex("12 01 00 02"),bytes.fromhex("11 80 00 00")):
        with pytest.raises(ValueError):
            parse_feedback(malformed)


def clock(monkeypatch, erased=()):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "studies"))
    from packed_striped_timing import PaidTimers
    sim,t,log=fixture(set(erased))
    missing=set()
    path=SimpleNamespace(t=t,net=sim,counts=Counter(),receiver_needs=lambda i, _: i in missing)
    timers=PaidTimers(path,True)
    def feedback(prefix,_):
        t.base=max(t.base,prefix)
    t._receive_feedback=feedback
    def retry(i,reason):
        emitted.append((sim.now,i,reason))
        return sim.send(False,130,"retry",lambda:None)[0]
    emitted=[]
    path.retry=retry
    timers.install()
    return timers,sim,missing,log,emitted


def test_only_a_paid_request_arms_a_repeat_even_with_two_losses(monkeypatch):
    timers,sim,missing,log,_=clock(monkeypatch,{("mixed_gap_request",1),("mixed_gap_request",2)})
    missing.update((0,1,65))
    sim.links[True][0].free_at=.020
    timers.accept(70,False)
    step(sim,.001)
    assert not timers.repeats and timers.pending_feedback == (1,0,(0,1))
    first_paid=sim.links[True][0].free_at
    # Feedback covers multiple absent sources. One becomes solvable before
    # departure and does not acquire a repeat deadline.
    missing.remove(1)
    step(sim,first_paid)
    assert timers.repeats=={0:first_paid+.035}
    assert timers.pending_feedback==(2,0,(65,))
    second_paid=sim.links[True][0].free_at
    step(sim,second_paid)
    assert timers.repeats[65]==second_paid+.035
    step(sim,first_paid+.035)
    assert timers.pending_feedback==(3,0,(0,))
    gap=[row for row in log if row[3]=="mixed_gap_request"]
    assert [row[4] for row in gap]==[True,True,False]
    assert gap[-1][0]==pytest.approx(first_paid+.035)


def test_ack_coalescence_frozen_prefix_and_one_repeat_from_payment(monkeypatch):
    timers,sim,_,log,_=clock(monkeypatch)
    t=timers.t
    sim.links[True][0].free_at=.015
    t.received_prefix=1
    timers.prefix_advanced()
    step(sim,.0005)
    t.received_prefix=2
    timers.prefix_advanced()
    step(sim,.001)
    assert timers.pending_feedback==(1,2,())
    first_paid=sim.links[True][0].free_at
    step(sim,.003)
    t.received_prefix=3
    timers.prefix_advanced()
    step(sim,first_paid)
    assert timers.pending_feedback==(2,3,())
    second_paid=sim.links[True][0].free_at
    step(sim,.06)
    acks=[r[0] for r in log if r[3]=="mixed_feedback"]
    assert acks==pytest.approx([.001,first_paid,second_paid+.035])
    timers.accept(2,True)
    step(sim,.2)
    assert len([r for r in log if r[3]=="mixed_feedback"])==5
    assert timers.pending_feedback is None and timers.ack_due is None


def test_quiet_uses_last_fresh_or_quiet_paid_time_and_oldest_paid_source(monkeypatch):
    timers,sim,_,_,emitted=clock(monkeypatch)
    # A request cannot charge an original that has not physically departed.
    timers.hear((1,0,(0,)))
    assert not timers.requests
    timers.fresh_paid(0)
    step(sim,.005)
    timers.fresh_paid(1)
    step(sim,.020)
    timers.hear((2,0,(1,)))
    step(sim,.069)
    assert emitted==[(.020,1,"requested_retries")]
    sim.links[False][0].free_at=.090
    step(sim,.076)
    assert emitted[-1][0]==pytest.approx(.075)
    assert emitted[-1][1:]==(0,"quiet_probes")
    paid=sim.links[False][0].free_at
    step(sim,.145)
    assert len(emitted)==2
    step(sim,paid+.070)
    assert emitted[-1]==(paid+.070,0,"quiet_probes")
    timers.hear((3,2,()))
    step(sim,.4)
    assert len(emitted)==3
