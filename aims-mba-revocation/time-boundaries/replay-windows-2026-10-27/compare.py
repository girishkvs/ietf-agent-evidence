"""Check the Windows replay against Mikhail Sergeev's expected results and recorded traces.

Run from this folder: python compare.py
Exit code 0 means every executed case matches.
"""
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXT = HERE.parent
T0 = datetime(2026, 10, 23, 4, 0, tzinfo=timezone.utc)
# Values that differ on every run: random ids, digests over them and signed evidence.
RUN_SPECIFIC = {"id", "evidence_id", "policy_view_id", "value", "decision_id", "evaluation_id"}
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def walk(value, path=""):
    if isinstance(value, dict):
        for key, item in value.items():
            yield from walk(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from walk(item, f"{path}[{index}]")
    else:
        yield path, value


def strip(value):
    if isinstance(value, dict):
        return {k: strip(v) for k, v in value.items() if k not in RUN_SPECIFIC}
    if isinstance(value, list):
        return [strip(v) for v in value]
    if isinstance(value, str):
        return UUID.sub("<uuid>", value)
    return value


def observed(case):
    source = case.get("outcome") if case.get("outcome") is not None else case.get("decision")
    ok = source.get("ok", source.get("decision"))
    text = json.dumps(source)
    reason = None
    if not ok:
        reason = next((r for r in ("stale_state", "permit_expired", "mission_inactive", "unknown_mission") if r in text), None)
    deadlines = sorted({v for p, v in walk(case) if p.endswith("valid_until") and isinstance(v, str)})
    offsets = [int((datetime.fromisoformat(v.replace("Z", "+00:00")) - T0).total_seconds() * 1000) for v in deadlines]
    return ok, reason, offsets


def check(label, traces_path, expected_path, reference_path=None):
    traces = load(traces_path)
    expected = {c["caseId"]: c for c in load(expected_path)["cases"]}
    reference = {c["caseId"]: c for c in load(reference_path)["cases"]} if reference_path else {}
    failures = 0
    for case in traces["cases"]:
        exp = expected.get(case["caseId"])
        if exp is None:
            continue
        ok, reason, offsets = observed(case)
        good = ok == exp["ok"] and reason == exp["reason"]
        if exp.get("ageMs") is not None:
            good = good and case.get("ageMs") == exp["ageMs"]
        if exp.get("validUntilOffsetFromAsOfMs") is not None:
            good = good and exp["validUntilOffsetFromAsOfMs"] in offsets
        same_trace = ""
        if case["caseId"] in reference:
            same_trace = " trace=same" if strip(case) == strip(reference[case["caseId"]]) else " trace=DIFFERENT"
            good = good and same_trace == " trace=same"
        failures += not good
        print(f"{label:<14} {case['caseId']:<34} ok={ok!s:<5} reason={reason!s:<16} deadline-T0={offsets}{same_trace} {'OK' if good else 'MISMATCH'}")
    return failures


failures = 0
failures += check("ea1a149", HERE / "ea1a149" / "boundary-traces.json", EXT / "ea1a149" / "expected-results.json",
                  EXT / "ea1a149" / "results" / "boundary-traces.json")
failures += check("c941a738", HERE / "c941a738-b7" / "boundary-traces.json", EXT / "c941a738-b7" / "expected-results.json",
                  EXT / "c941a738-b7" / "results" / "boundary-traces.json")
failures += check("main-ef8568a", HERE / "main-ef8568a" / "boundary-traces.json", EXT / "ea1a149" / "expected-results.json")
print("mismatches:", failures)
sys.exit(1 if failures else 0)
