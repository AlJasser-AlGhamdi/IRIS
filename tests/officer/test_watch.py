from pathlib import Path

from officer.cli import sim_session
from officer.contract import FixId, FixOut
from officer.fixes import FIXES
from officer.questions import AnswerClass
from officer.watch import watch


def _rounds(agent):
    return [ev["data"] for ev in agent.log.events
            if ev["type"] == "monitor_round" and ev["data"]["stage"] == "end"]


def test_returning_problem_is_fixed_again_and_a_new_one_needs_approval() -> None:
    _m, agent, worker, _o = sim_session(1, "honest", "scripted", None)
    trusted = agent.state.fixes_verified[0]
    back = FIXES[FixId(trusted)].clears[0]
    new = next(f for f in FIXES.values() if f.fix_id.value not in agent.state.fixes_verified
               and not set(f.clears) & {c for _h, c in agent.state.findings})
    worker_host = worker.apex if worker._readable(worker.apex, back) else worker.hosts[-1]
    drift = {(worker_host, back), (worker.apex, new.clears[0])}
    asked: list[str] = []
    reply = agent.owner.reply
    agent.owner.reply = lambda r: (asked.append(r.kind), reply(r))[1]

    totals = watch(agent, 2, lambda n: worker.drift(drift) if n == 1 else None)

    first, quiet = _rounds(agent)
    assert trusted in first["reapplied"] and trusted in first["verified"]
    assert new.fix_id.value not in first["reapplied"]
    assert "approve_fixes" in asked
    assert quiet["new"] == [] and totals["rounds"] == 2


def test_a_sibling_fix_is_offered_only_for_what_the_approved_fix_left_open() -> None:
    _m, agent, worker, _o = sim_session(1, "honest", "scripted", None)
    agent.state.fixes_verified.append(FixId.CLOSE_DB_PORT.value)
    check = FIXES[FixId.CLOSE_DB_PORT].clears[0]
    assert check not in {c for _h, c in agent.state.findings}
    host = next(h for h in worker.hosts if worker._readable(h, check))
    asked: list[tuple[str, ...]] = []
    reply = agent.owner.reply
    agent.owner.reply = lambda r: (asked.append(r.options), reply(r))[1]

    watch(agent, 1, lambda n: worker.drift({(host, check)}))

    first = _rounds(agent)[0]
    assert FixId.CLOSE_DB_PORT.value in first["reapplied"]
    assert (FixId.CLOSE_CACHE_PORT.value,) not in asked


def test_monitoring_stops_when_the_ownership_record_is_gone() -> None:
    _m, agent, worker, _o = sim_session(2, "honest", "scripted", None)
    worker.lose_txt = True
    totals = watch(agent, 2)
    assert totals["stopped"] == "ownership_lost"
    assert any(e["reason"] == "ownership_lost" for e in agent.state.escalations)


def test_drafts_only_for_gaps_and_into_the_report(tmp_path: Path) -> None:
    _m, agent, _w, _o = sim_session(3, "honest", "scripted", tmp_path / "run.jsonl")
    assert agent.drafts, "an honest owner of a synthetic firm has at least one gap"
    for d in agent.drafts:
        assert agent.state.answers[d.qid].answer is not AnswerClass.YES
        assert d.sections >= 2
    report = (tmp_path / "run.report.html").read_text(encoding="utf-8")
    assert "مسودات جاهزة لاعتمادكم" in report
    drafted = [ev for ev in agent.log.events if ev["type"] == "document_drafted"]
    assert len(drafted) == len(agent.drafts)


def test_a_fix_with_nothing_to_change_is_not_claimed() -> None:
    _m, agent, worker, _o = sim_session(4, "honest", "scripted", None)
    proposed = [ev["data"]["fix_id"] for ev in agent.log.events
                if ev["type"] == "tool_call" and ev["data"]["tool"] == "fix"]
    if not proposed:
        return
    target = FixId(proposed[0])
    real_fix = worker.fix
    worker.fix = lambda f: FixOut(fix_id=f, applied=False) if f is target else real_fix(f)  # type: ignore[method-assign]
    agent.state.fixes_verified.clear()
    agent._apply_group([FIXES[target]])
    assert target.value not in agent.state.fixes_verified
    last = [ev["data"] for ev in agent.log.events if ev["type"] == "fix_result"][-1]
    assert last == {"fix_id": target.value, "verified": None, "reason": "nothing_to_change"}
