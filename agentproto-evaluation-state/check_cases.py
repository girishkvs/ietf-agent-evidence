from __future__ import annotations

import argparse
import datetime
import hashlib
import json
from pathlib import Path
from typing import Any


class CaseError(ValueError):
    pass


class EvaluationStateCases:
    WITHIN = "age-equal-is-within"
    PAST = "age-equal-is-past"
    NOT_ESTABLISHED = (
        "no-value",
        "unreachable",
        "blocked-by-own-policy",
        "profile-not-held",
        "lookup-incomplete",
    )
    COMPARED = (
        "state", "reason", "asOf", "ageSeconds", "profile", "component", "decision", "refusal",
        "callerView",
    )
    SOURCES = ("cases.json", "check_cases.py")

    def __init__(self, folder: Path):
        self.folder = folder.resolve(strict=True)
        self.document = json.loads((self.folder / "cases.json").read_text(encoding="utf-8"))
        self.check_document()
        self.skew = self.document["skewToleranceSeconds"]

    def vectors(self) -> list[dict[str, Any]]:
        return [vector for case in self.document["cases"] for vector in case["vectors"]]

    def check_document(self) -> None:
        if self.document["boundaryRule"] != self.WITHIN:
            raise CaseError("unexpected-boundary-rule")
        case_ids = [case["id"] for case in self.document["cases"]]
        if case_ids != [f"TC-{number}" for number in range(1, 16)]:
            raise CaseError(f"unexpected-case-ids: {case_ids}")
        vector_ids = [vector["id"] for vector in self.vectors()]
        if len(vector_ids) != len(set(vector_ids)):
            raise CaseError("duplicate-vector-id")
        for vector in self.vectors():
            if len(vector["evaluations"]) != len(vector["expected"]):
                raise CaseError(f"expected-count: {vector['id']}")
            for evaluation in vector["evaluations"]:
                self.check_observation(vector["id"], evaluation["observation"])

    def check_observation(self, vector_id: str, observation: dict[str, Any]) -> None:
        outcome = observation["outcome"]
        if outcome in self.NOT_ESTABLISHED:
            return
        if outcome != "value":
            raise CaseError(f"unknown-outcome: {vector_id}: {outcome}")
        if ("asOf" not in observation or
                type(observation.get("satisfies")) is not bool):
            raise CaseError(f"incomplete-value: {vector_id}")

    def instant(self, text: str) -> datetime.datetime:
        value = datetime.datetime.fromisoformat(text)
        if value.tzinfo is None:
            raise CaseError(f"instant-without-offset: {text}")
        return value

    def seconds(self, start: str, end: str) -> int:
        return int((self.instant(end) - self.instant(start)).total_seconds())

    def outside_bound(self, age: int, bound: int, rule: str) -> bool:
        if rule == self.PAST:
            return age >= bound
        return age > bound

    def arrived_after_decision(self, evaluation: dict[str, Any]) -> bool:
        available_at = evaluation["observation"].get("availableAt")
        if available_at is None:
            return False
        return self.instant(available_at) > self.instant(evaluation["decisionAt"])

    def settle(self, record: dict[str, Any], state: str, reason: str) -> dict[str, Any]:
        record["state"] = state
        record["reason"] = reason
        return record

    def evaluate(
        self, evaluation: dict[str, Any], rule: str = WITHIN, age_from: str = "source"
    ) -> dict[str, Any]:
        observation = evaluation["observation"]
        record: dict[str, Any] = {
            "hop": evaluation["hop"],
            "input": evaluation["input"],
            "decisionAt": evaluation["decisionAt"],
            "boundSeconds": evaluation["boundSeconds"],
            "asOf": None,
            "ageSeconds": None,
        }
        for key in ("profile", "component"):
            if key in observation:
                record[key] = observation[key]
        if observation["outcome"] in self.NOT_ESTABLISHED:
            return self.settle(record, "not-established", observation["outcome"])
        if self.arrived_after_decision(evaluation):
            return self.settle(record, "not-established", "not-available-at-decision")
        start = observation["asOf"] if age_from == "source" else observation["receivedAt"]
        record["asOf"] = observation["asOf"]
        record["ageSeconds"] = self.seconds(start, evaluation["decisionAt"])
        if record["ageSeconds"] < -self.skew:
            return self.settle(record, "not-established", "as-of-after-decision")
        if self.outside_bound(record["ageSeconds"], record["boundSeconds"], rule):
            return self.settle(record, "stale", "older-than-bound")
        state = "established-positive" if observation["satisfies"] else "established-negative"
        return self.settle(record, state, "within-bound")

    def decide(self, record: dict[str, Any]) -> dict[str, str]:
        if record["state"] == "established-positive":
            return {"decision": "permit"}
        if record["state"] == "established-negative":
            return {"decision": "refuse", "refusal": "permanent"}
        return {"decision": "refuse", "refusal": "transient"}

    def caller_view(self, decision: dict[str, str]) -> dict[str, str]:
        if decision["decision"] == "permit":
            return {"decision": "permit"}
        if decision["refusal"] == "permanent":
            return {"decision": "refuse", "reason": "denied"}
        return {"decision": "refuse", "reason": "evaluation-incomplete"}

    def canonical(self, value: Any) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def digest(self, value: Any) -> str:
        return hashlib.sha256(self.canonical(value)).hexdigest()

    def changed_records(self, records: list[dict[str, Any]], digests: list[str]) -> list[int]:
        return [
            index for index, (record, digest) in enumerate(zip(records, digests))
            if self.digest(record) != digest
        ]

    def compare(self, label: str, expected: dict[str, Any], result: dict[str, Any]) -> list[str]:
        problems = []
        for key in self.COMPARED:
            if (key in expected and
                    expected[key] != result.get(key)):
                problems.append(f"{label}: {key} expected {expected[key]!r}, got {result.get(key)!r}")
        return problems

    def run_vector(self, vector: dict[str, Any]) -> dict[str, Any]:
        records, digests, results, problems = [], [], [], []
        for index, (evaluation, expected) in enumerate(zip(vector["evaluations"], vector["expected"])):
            label = f"{vector['id']}#{index + 1}"
            record = self.evaluate(evaluation)
            records.append(record)
            digests.append(self.digest(record))
            decision = self.decide(record)
            result = {**record, **decision, "callerView": self.caller_view(decision)}
            problems.extend(self.compare(label, expected, result))
            for rule, state in expected.get("stateUnderRule", {}).items():
                other = self.evaluate(evaluation, rule)["state"]
                result.setdefault("stateUnderRule", {})[rule] = other
                if other != state:
                    problems.append(f"{label}: under {rule} expected {state}, got {other}")
            if "stateIfAgeFromReceipt" in expected:
                other = self.evaluate(evaluation, age_from="receipt")["state"]
                result["stateIfAgeFromReceipt"] = other
                if other != expected["stateIfAgeFromReceipt"]:
                    problems.append(f"{label}: from receipt expected "
                                    f"{expected['stateIfAgeFromReceipt']}, got {other}")
            results.append(result)
        changed = self.changed_records(records, digests)
        if (vector.get("earlierRecordsUnchanged") and
                changed):
            problems.append(f"{vector['id']}: earlier records changed: {changed}")
        return {
            "id": vector["id"],
            "evaluations": results,
            "earlierRecordsUnchanged": not changed,
            "mismatches": problems,
        }

    def sha256(self, path: Path) -> str:
        return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()

    def run(self) -> dict[str, Any]:
        reports = [self.run_vector(vector) for vector in self.vectors()]
        mismatches = [problem for report in reports for problem in report["mismatches"]]
        return {
            "draft": self.document["draft"],
            "draftSection": self.document["draftSection"],
            "boundaryRule": self.document["boundaryRule"],
            "skewToleranceSeconds": self.skew,
            "counts": {
                "cases": len(self.document["cases"]),
                "vectors": len(reports),
                "evaluations": sum(len(report["evaluations"]) for report in reports),
                "mismatches": len(mismatches),
            },
            "sources": {name: self.sha256(self.folder / name) for name in self.SOURCES},
            "reports": reports,
        }

    def write(self, output: Path) -> dict[str, Any]:
        if output.exists():
            raise CaseError(f"output-exists: {output}")
        summary = self.run()
        if summary["counts"]["mismatches"]:
            problems = [problem for report in summary["reports"] for problem in report["mismatches"]]
            raise CaseError("mismatches: " + "; ".join(problems))
        with output.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(summary, indent=2, sort_keys=True) + "\n")
        return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    summary = EvaluationStateCases(Path(__file__).parent).write(arguments.output)
    print(json.dumps(summary["counts"], indent=2))
