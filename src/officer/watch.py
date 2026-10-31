"""Continuous monitoring after the assessment.

Each round re-scans every group under the same ownership proof and compares with the previous round. A
problem that comes back is fixed again without asking when the owner approved that fix earlier and a
re-scan proved it worked; anything new needs the owner's approval; risky changes go to a person. The
model picks each response from a menu code has filtered, and every fix is confirmed by a re-scan.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from officer.contract import FixId, Group
from officer.fixes import ESCALATE_ONLY, FixSpec, fixes_for
from officer.labels import count_ar
from officer.session import Agent, OwnerRequest
from p2c.scanning.catalog import CheckId


def _open(agent: Agent) -> set[str]:
    return {c.value for _h, c in agent.state.findings}


def watch(agent: Agent, rounds: int, before_round: Callable[[int], None] | None = None) -> dict[str, Any]:
    """Run ``rounds`` monitoring rounds on a finished session; ``before_round(n)`` lets a harness change
    the estate between rounds (the lab's simulated drift)."""
    trusted = {FixId(f) for f in agent.state.fixes_verified}
    agent.log.emit("phase", phase="monitor")
    agent._say("انتهى التقييم، وسأبقى أراقب. في كل جولة أفحص من جديد، وأعيد ما أصلحناه إذا رجع، وأستأذنكم قبل أي "
               "تعديل جديد.",
               "The assessment is done and I keep watching. Each round I scan again, re-apply what we fixed if "
               "it comes back, and ask you before any new change.", topic="monitor")
    totals: dict[str, Any] = {"rounds": 0, "new": [], "resolved": [], "reapplied": [], "approved": [],
                              "declined": [], "escalated": [], "verified": [], "not_verified": [], "stopped": None}
    for n in range(1, rounds + 1):
        if before_round is not None:
            before_round(n)
        before = _open(agent)
        verified_before = len(agent.state.fixes_verified)
        failed_before = len(agent.state.fixes_failed)
        agent.log.emit("monitor_round", round=n, stage="start")
        for group in Group:
            if not agent._scan_group(group):
                totals["stopped"] = agent.state.halted
                agent.log.emit("monitor_round", round=n, stage="stopped", reason=agent.state.halted)
                return _finish(agent, totals)
        after = _open(agent)
        new, resolved = sorted(after - before), sorted(before - after)
        agent._publish_assessment(stage="monitor")
        record: dict[str, list[str]] = {"reapplied": [], "approved": [], "declined": [], "escalated": []}
        _apply(agent, _respond(agent, n, set(new), trusted, record, known=True))
        still = set(new) & _open(agent)  # what the fixes the owner already approved did not clear
        _apply(agent, _respond(agent, n, still, trusted, record, known=False))
        verified = agent.state.fixes_verified[verified_before:]
        not_verified = agent.state.fixes_failed[failed_before:]
        trusted |= {FixId(f) for f in verified}
        agent._publish_assessment(stage="monitor")
        agent.log.emit("monitor_round", round=n, stage="end", new=new, resolved=resolved, verified=verified,
                       not_verified=not_verified, **record)
        agent._say(_digest_ar(n, new, resolved, verified, record), _digest_en(n, new, resolved, verified, record),
                   topic="monitor")
        totals["rounds"] = n
        for key, values in (("new", new), ("resolved", resolved), ("verified", verified),
                            ("not_verified", not_verified), *record.items()):
            totals[key] += values
    return _finish(agent, totals)


def _apply(agent: Agent, specs: list[FixSpec]) -> None:
    by_group: dict[Group, list[FixSpec]] = {}
    for spec in specs:
        by_group.setdefault(spec.group, []).append(spec)
    for group_specs in by_group.values():
        agent._apply_group(group_specs)


def _respond(agent: Agent, n: int, new: set[str], trusted: set[FixId], record: dict[str, list[str]],
             *, known: bool) -> list[FixSpec]:
    """Decide, per new problem, between re-applying, asking and escalating. Returns the fixes to apply.
    ``known`` handles risky problems and fixes the owner approved before; the second pass offers the rest
    for what those did not clear, so two fixes that clear the same detector are not both put to the owner."""
    to_apply: list[FixSpec] = []
    for check, reason in ESCALATE_ONLY.items():
        if known and check.value in new:
            record["escalated"].append(check.value)
            agent._escalate(f"monitor_risky:{check.value}",
                            "ظهر من جديد دخول عن بُعد مفتوح على الإنترنت. إغلاقه تلقائياً قد يمنعكم من الوصول "
                            "إلى الخادم، لذلك أحلناه إلى المسؤول عنه.",
                            f"Remote management is open again, but {reason}; handed to a person.")
    for spec in fixes_for({CheckId(c) for c in new}):
        if (spec.fix_id in trusted) is not known:
            continue
        fix = spec.fix_id.value
        if spec.fix_id in trusted:
            menu = [(f"reapply_{fix}", f"Re-apply the fix the owner approved and a re-scan verified: {spec.title_en}"),
                    (f"ask_{fix}", "Ask the owner before re-applying")]
        else:
            menu = [(f"ask_{fix}", f"Ask the owner to approve a new fix: {spec.title_en}"),
                    (f"escalate_{fix}", "Hand it to a person")]
        facts = [f"Monitoring round {n}.", f"New since the last round: {', '.join(c.value for c in spec.clears)}.",
                 f"Owner approved this fix earlier and a re-scan verified it: {'yes' if spec.fix_id in trusted else 'no'}."]
        action = agent._choose("MONITOR", facts, menu)
        if action.startswith("reapply_"):
            record["reapplied"].append(fix)
            to_apply.append(spec)
        elif action.startswith("escalate_"):
            record["escalated"].append(fix)
            agent._escalate(f"monitor_handover:{fix}", f"أحلنا إلى مختص: {spec.title_ar}.",
                            f"Handed to a person: {spec.title_en}.")
        else:
            reply = agent._ask(OwnerRequest(
                "approve_fixes",
                f"رصدت المراقبة مشكلة جديدة. هل توافقون على: {spec.title_ar}؟",
                f"Monitoring found something new. Do you approve: {spec.title_en}?",
                options=(fix,), payload={"monitor_round": n}))
            if fix in reply.choices:
                record["approved"].append(fix)
                to_apply.append(spec)
            else:
                record["declined"].append(fix)
    return to_apply


def _digest_ar(n: int, new: list[str], resolved: list[str], verified: list[str], record: dict[str, list[str]]) -> str:
    if not new and not resolved:
        return f"جولة المراقبة {n}: لا تغيير منذ الجولة السابقة."
    changes = count_ar(len(new), "تغييراً جديداً", "تغييرين جديدين", "تغييرات جديدة", "تغييراً جديداً")
    parts = [f"جولة المراقبة {n}: رصدنا {changes}"]
    if verified:
        k = len(verified)
        fixed = "وأصلحناه" if len(new) == 1 else f"وأصلحنا {({1: 'واحداً', 2: 'اثنين'}).get(k, k)} منها"
        parts.append(f"{fixed} وتحققنا من ذلك بفحص جديد")
    if record["approved"] or record["declined"]:
        parts.append("واستأذناكم قبل إصلاح الجديد منها")
    if record["escalated"]:
        parts.append("وأحلنا ما في إصلاحه خطورة إلى مختص")
    if resolved:
        parts.append(f"وعدد ما اختفى دون تدخل منا: {len(resolved)}")
    return "، ".join(parts) + "."


def _digest_en(n: int, new: list[str], resolved: list[str], verified: list[str], record: dict[str, list[str]]) -> str:
    if not new and not resolved:
        return f"Monitoring round {n}: nothing changed since the last round."
    text = f"Monitoring round {n}: {len(new)} new problem(s); {len(verified)} fixed and verified by a new scan"
    if record["approved"] or record["declined"]:
        text += f"; {len(record['approved']) + len(record['declined'])} needed your approval"
    if record["escalated"]:
        text += f"; {len(record['escalated'])} handed to a person"
    if resolved:
        text += f"; {len(resolved)} disappeared on their own"
    return text + "."


def _finish(agent: Agent, totals: dict[str, Any]) -> dict[str, Any]:
    agent.monitor = totals
    agent.log.emit("monitor_summary", **totals)
    if agent.log.path is not None:
        from officer.report import render  # noqa: PLC0415

        a = agent._publish_assessment(stage="monitor_end")
        report = agent.log.path.with_suffix(".report.html")
        report.write_text(render(agent, a, agent.metrics), encoding="utf-8", newline="\n")
        agent.log.emit("report_ready", file=report.name)
    agent.log.emit("phase", phase="done")
    return totals
