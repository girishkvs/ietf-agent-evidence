from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from check_cases import CaseError, EvaluationStateCases


class EvaluationStateCaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.folder = Path(__file__).resolve().parent
        self.cases = EvaluationStateCases(self.folder)
        self.vectors = {vector["id"]: vector for vector in self.cases.vectors()}

    def evaluation(self, vector_id: str, index: int = 0) -> dict:
        return copy.deepcopy(self.vectors[vector_id]["evaluations"][index])

    def state(self, evaluation: dict, rule: str = EvaluationStateCases.WITHIN,
              age_from: str = "source") -> str:
        return self.cases.evaluate(evaluation, rule, age_from)["state"]

    def test_every_vector_matches(self) -> None:
        summary = self.cases.run()
        self.assertEqual(summary["counts"],
                         {"cases": 15, "vectors": 24, "evaluations": 27, "mismatches": 0})

    def test_boundary_rules_differ_only_at_equality(self) -> None:
        rows = (
            ("TC-2/one-second-less", "established-positive", "established-positive"),
            ("TC-2/equal", "established-positive", "stale"),
            ("TC-2/one-second-more", "stale", "stale"),
        )
        for vector_id, within, past in rows:
            with self.subTest(vector=vector_id):
                evaluation = self.evaluation(vector_id)
                self.assertEqual(self.state(evaluation), within)
                self.assertEqual(self.state(evaluation, EvaluationStateCases.PAST), past)

    def test_age_runs_from_the_source_not_the_receipt(self) -> None:
        evaluation = self.evaluation("TC-10/stale-from-source")
        self.assertEqual(self.state(evaluation), "stale")
        self.assertEqual(self.state(evaluation, age_from="receipt"), "established-positive")
        evaluation["observation"]["receivedAt"] = "2026-10-19T10:30:00Z"
        self.assertEqual(self.state(evaluation), "stale")

    def test_each_hop_applies_its_own_bound(self) -> None:
        first = self.evaluation("TC-11/two-bounds", 0)
        second = self.evaluation("TC-11/two-bounds", 1)
        self.assertEqual(self.state(first), "established-positive")
        self.assertEqual(self.state(second), "stale")
        second["boundSeconds"] = first["boundSeconds"]
        self.assertEqual(self.state(second), "established-positive")

    def test_never_established_is_not_stale(self) -> None:
        record = self.cases.evaluate(self.evaluation("TC-4/never-held"))
        self.assertEqual(record["state"], "not-established")
        self.assertIsNone(record["asOf"])
        self.assertIsNone(record["ageSeconds"])

    def test_skew_tolerance_is_a_limit_not_a_margin(self) -> None:
        self.assertEqual(self.state(self.evaluation("TC-13/at-tolerance")), "established-positive")
        record = self.cases.evaluate(self.evaluation("TC-13/beyond-tolerance"))
        self.assertEqual(record["state"], "not-established")
        self.assertEqual(record["reason"], "as-of-after-decision")

    def test_absence_counts_only_from_a_complete_lookup(self) -> None:
        self.assertEqual(self.state(self.evaluation("TC-6/absent-where-required")),
                         "established-negative")
        self.assertEqual(self.state(self.evaluation("TC-6/absent-from-revocation-list")),
                         "established-positive")
        self.assertEqual(self.state(self.evaluation("TC-6/lookup-incomplete")), "not-established")

    def test_an_input_that_was_not_established_is_never_reported_negative(self) -> None:
        for vector in self.cases.vectors():
            for evaluation in vector["evaluations"]:
                record = self.cases.evaluate(copy.deepcopy(evaluation))
                if record["state"] not in ("not-established", "stale"):
                    continue
                with self.subTest(vector=vector["id"], hop=evaluation["hop"]):
                    self.assertEqual(self.cases.decide(record),
                                     {"decision": "refuse", "refusal": "transient"})

    def test_state_that_arrives_after_the_decision_is_not_used(self) -> None:
        first = self.cases.evaluate(self.evaluation("TC-14/state-arrives-late", 0))
        second = self.cases.evaluate(self.evaluation("TC-14/state-arrives-late", 1))
        self.assertEqual((first["state"], first["reason"]),
                         ("not-established", "not-available-at-decision"))
        self.assertIsNone(first["asOf"])
        self.assertEqual(second["state"], "established-positive")

    def test_caller_view_carries_no_input_detail(self) -> None:
        record = self.cases.evaluate(self.evaluation("TC-15/coarse-caller-reason"))
        view = self.cases.caller_view(self.cases.decide(record))
        self.assertEqual(view, {"decision": "refuse", "reason": "evaluation-incomplete"})
        for detail in (record["input"], record["reason"], record["state"]):
            self.assertNotIn(detail, json.dumps(view))

    def test_an_amended_earlier_record_is_detected(self) -> None:
        report = self.cases.run_vector(self.vectors["TC-12/later-hop"])
        self.assertTrue(report["earlierRecordsUnchanged"])
        records = [self.cases.evaluate(evaluation)
                   for evaluation in copy.deepcopy(self.vectors["TC-12/later-hop"]["evaluations"])]
        digests = [self.cases.digest(record) for record in records]
        records[0]["state"] = records[1]["state"]
        self.assertEqual(self.cases.changed_records(records, digests), [0])

    def test_profile_is_named_in_the_record(self) -> None:
        record = self.cases.evaluate(self.evaluation("TC-7/profile-not-held"))
        self.assertEqual(record["profile"], "urn:example:profile:transfer-limits:3")
        self.assertEqual(record["state"], "not-established")

    def test_unknown_outcome_is_rejected(self) -> None:
        self.cases.document["cases"][0]["vectors"][0]["evaluations"][0]["observation"]["outcome"] = "maybe"
        with self.assertRaises(CaseError):
            self.cases.check_document()

    def test_recorded_run_replays_byte_for_byte(self) -> None:
        recorded = (self.folder / "results.json").read_bytes().replace(b"\r\n", b"\n")
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "replay.json"
            self.cases.write(output)
            self.assertEqual(output.read_bytes(), recorded)
            with self.assertRaises(CaseError):
                self.cases.write(output)


if __name__ == "__main__":
    unittest.main()
