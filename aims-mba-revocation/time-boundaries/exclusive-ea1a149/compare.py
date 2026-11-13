#!/usr/bin/env python3
"""Compare observed MBA outcomes (boundary-traces.json) with the
exclusive-rule expectations. Usage: compare.py expected.json traces.json"""
import json, sys
exp = {c["caseId"]: c for c in json.load(open(sys.argv[1]))["cases"]}
obs = {c["caseId"]: c for c in json.load(open(sys.argv[2]))["cases"]}
rows, diverge = [], 0
for cid, e in exp.items():
    o = obs.get(cid)
    if o is None:
        rows.append((cid, "MISSING", "", "")); diverge += 1; continue
    out = o.get("outcome", {})
    ook = bool(out.get("ok"))
    oreason = out.get("denial_reason") or out.get("refusal_reason")
    same = (ook == e["ok"]) and (ook or oreason == e["reason"])
    if not same: diverge += 1
    rows.append((cid, "agree" if same else "DIFFERS",
                 f"rule: {'admit' if e['ok'] else 'refuse ' + str(e['reason'])}",
                 f"MBA: {'admit' if ook else 'refuse ' + str(oreason)}"))
for r in rows: print(" | ".join(r))
print(f"\n{len(rows)} cases, {len(rows)-diverge} agree, {diverge} differ")
