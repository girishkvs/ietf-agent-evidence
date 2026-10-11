from __future__ import annotations

import base64
import copy
import json
import os
import tempfile
import unittest
from pathlib import Path

from run_r8 import EvidenceError, FreshnessCases


class R8Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = FreshnessCases(Path(os.environ["R8_UPSTREAM"]))
        self.cases = {case["id"]: case for case in self.fixture.cases()}

    def read(self, name: str, bundle: dict | None = None) -> dict:
        case = self.cases[name]
        return self.fixture.read(
            bundle if bundle is not None else case["bundle"],
            receiver_at_ms=case["receiverAtMs"], comparator=case["comparator"],
        )

    def changed_evidence(self, name: str, change) -> dict:
        bundle = copy.deepcopy(self.cases[name]["bundle"])
        evidence = self.fixture.decode(bundle["evidenceEnvelope"])
        change(evidence)
        bundle["evidenceEnvelope"] = self.fixture.sign_companion(evidence)
        return bundle

    def test_seven_variants(self) -> None:
        expected = {
            "R8-F1": "within-bound", "R8-F2": "stale", "R8-F3": "not-established",
            "R8-F4-inclusive": "within-bound", "R8-F4-strict": "stale",
            "R8-F5": "stale", "R8-F6": "not-established",
        }
        for name, state in expected.items():
            with self.subTest(name=name):
                report = self.read(name)
                self.assertEqual(report["receiverState"], state)
                self.assertEqual(report["auditVerdict"], "valid")
                self.assertEqual(report["auditDerivedTier"], "voluntary")
                self.assertEqual(report["reportedDecision"], "deny")

    def test_identical_core_record_does_not_encode_the_two_histories(self) -> None:
        stale = self.cases["R8-F2"]["bundle"]
        absent = self.cases["R8-F3"]["bundle"]
        self.assertEqual(stale["auditEnvelope"], absent["auditEnvelope"])
        self.assertNotEqual(stale["evidenceEnvelope"], absent["evidenceEnvelope"])
        for bundle in (stale, absent):
            report = self.fixture.read(
                {"auditEnvelope": bundle["auditEnvelope"]},
                receiver_at_ms=120_001, comparator="inclusive",
            )
            self.assertEqual(report["receiverState"], "insufficient-evidence")

    def test_missing_result_is_not_explicit_no_result(self) -> None:
        bundle = self.changed_evidence("R8-F3", lambda value: value.pop("result"))
        self.assertEqual(self.read("R8-F3", bundle)["receiverState"], "insufficient-evidence")

    def test_attempt_time_is_not_result_time(self) -> None:
        report = self.read("R8-F3")
        self.assertEqual(report["receiverState"], "not-established")
        self.assertIsNone(report["receiverAgeMs"])
        bundle = self.changed_evidence(
            "R8-F2", lambda value: value["result"].pop("asOfMs")
        )
        self.assertEqual(self.read("R8-F2", bundle)["receiverState"], "insufficient-evidence")

    def test_boundary_and_both_sides(self) -> None:
        self.assertEqual(self.read("R8-F1")["receiverAgeMs"], 119_999)
        self.assertEqual(self.read("R8-F2")["receiverAgeMs"], 120_001)
        self.assertEqual(self.read("R8-F4-inclusive")["receiverAgeMs"], 120_000)
        self.assertEqual(self.read("R8-F4-strict")["receiverAgeMs"], 120_000)

    def test_receiver_rule_does_not_rewrite_the_origin_rule(self) -> None:
        bundle = self.cases["R8-F4-strict"]["bundle"]
        report = self.fixture.read(bundle, receiver_at_ms=120_000, comparator="inclusive")
        self.assertEqual(report["originComparator"], "strict")
        self.assertEqual(report["originState"], "stale")
        self.assertEqual(report["receiverState"], "within-bound")

    def test_forwarding_retains_exact_origin_envelopes(self) -> None:
        for old, new in (("R8-F2", "R8-F5"), ("R8-F3", "R8-F6")):
            for field in ("auditEnvelope", "evidenceEnvelope"):
                self.assertEqual(
                    self.cases[old]["bundle"][field], self.cases[new]["bundle"][field]
                )
        report = self.read("R8-F5")
        self.assertEqual(report["originAgeMs"], 120_001)
        self.assertEqual(report["receiverAgeMs"], 130_000)
        self.assertEqual(self.read("R8-F6")["receiverState"], "not-established")

    def test_tampered_result_time_fails_signature(self) -> None:
        bundle = copy.deepcopy(self.cases["R8-F2"]["bundle"])
        envelope = bundle["evidenceEnvelope"]
        evidence = self.fixture.decode(envelope)
        evidence["result"]["asOfMs"] = 119_999
        envelope["payload"] = base64.b64encode(self.fixture.encoded(evidence)).decode("ascii")
        with self.assertRaisesRegex(EvidenceError, "signature-invalid"):
            self.read("R8-F2", bundle)

    def test_wrong_audit_binding(self) -> None:
        bundle = copy.deepcopy(self.cases["R8-F2"]["bundle"])
        bundle["auditEnvelope"] = self.cases["R8-F1"]["bundle"]["auditEnvelope"]
        with self.assertRaisesRegex(EvidenceError, "auditPayloadSha256-mismatch"):
            self.read("R8-F2", bundle)

    def test_forwarding_binds_companion_even_when_audit_is_identical(self) -> None:
        bundle = copy.deepcopy(self.cases["R8-F5"]["bundle"])
        bundle["evidenceEnvelope"] = self.cases["R8-F3"]["bundle"]["evidenceEnvelope"]
        with self.assertRaisesRegex(EvidenceError, "evidenceEnvelopeSha256-mismatch"):
            self.read("R8-F5", bundle)

    def test_forwarder_cannot_sign_as_origin(self) -> None:
        bundle = copy.deepcopy(self.cases["R8-F5"]["bundle"])
        value = self.fixture.decode(bundle["evidenceEnvelope"])
        value["result"]["asOfMs"] = 129_999
        payload = self.fixture.encoded(value)
        signature = self.fixture.generator.AGENT_KEY.sign(
            self.fixture.reader.pae(self.fixture.EVIDENCE_TYPE, payload)
        )
        bundle["evidenceEnvelope"]["payload"] = base64.b64encode(payload).decode("ascii")
        bundle["evidenceEnvelope"]["signatures"][0]["sig"] = (
            base64.b64encode(signature).decode("ascii")
        )
        with self.assertRaisesRegex(EvidenceError, "signature-invalid"):
            self.read("R8-F5", bundle)

    def test_rejects_context_substitution(self) -> None:
        for field, value in (
            ("source", "urn:example:other-source"),
            ("input", "key-source"),
            ("clock", "seconds"),
            ("profile", "urn:example:other-profile"),
            ("capturedAtMs", 120_000),
            ("maximumAgeMs", 999_999),
            ("comparison", "unknown"),
        ):
            with self.subTest(field=field):
                bundle = self.changed_evidence(
                    "R8-F2", lambda evidence: evidence.update({field: value})
                )
                with self.assertRaises(EvidenceError):
                    self.read("R8-F2", bundle)

    def test_invalid_time_values(self) -> None:
        for value in (True, -1, 1.5, "0", None, 2**53):
            with self.subTest(value=value):
                bundle = copy.deepcopy(self.cases["R8-F2"]["bundle"])
                evidence = self.fixture.decode(bundle["evidenceEnvelope"])
                evidence["result"]["asOfMs"] = value
                payload = json.dumps(
                    evidence, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
                signature = self.fixture.generator.OBSERVER_KEY.sign(
                    self.fixture.reader.pae(self.fixture.EVIDENCE_TYPE, payload)
                )
                bundle["evidenceEnvelope"]["payload"] = base64.b64encode(payload).decode("ascii")
                bundle["evidenceEnvelope"]["signatures"][0]["sig"] = (
                    base64.b64encode(signature).decode("ascii")
                )
                with self.assertRaises(EvidenceError):
                    self.read("R8-F2", bundle)

    def test_future_result_is_not_fresh(self) -> None:
        bundle = self.changed_evidence(
            "R8-F2", lambda evidence: evidence["result"].update(asOfMs=130_000)
        )
        with self.assertRaisesRegex(EvidenceError, "result-after-capture"):
            self.read("R8-F2", bundle)

    def test_extra_evaluation_fields_remain_rejected_by_upstream(self) -> None:
        for field, value in (("asOf", 0), ("reason", "stale")):
            predicate = self.fixture.decode(
                self.cases["R8-F2"]["bundle"]["auditEnvelope"]
            )["predicate"]
            predicate["evaluation"][field] = value
            envelope = self.fixture.generator.envelope(
                self.fixture.generator.signed(predicate)["payload"]
            )
            report = self.fixture.reader.verify(self.fixture.encoded(envelope), self.fixture.policy)
            self.assertEqual(report.verdict, "malformed")
            self.assertEqual(report.codes, ["evaluation-malformed"])

    def test_genuine_refresh_creates_a_new_record(self) -> None:
        original = copy.deepcopy(self.cases["R8-F3"]["bundle"])
        refreshed = self.fixture.origin(130_000, 129_999, evaluated=True)
        report = self.fixture.read(refreshed, receiver_at_ms=130_000, comparator="inclusive")
        self.assertEqual(report["receiverState"], "within-bound")
        self.assertEqual(report["receiverAgeMs"], 1)
        self.assertNotEqual(original["auditEnvelope"], refreshed["auditEnvelope"])
        self.assertEqual(self.read("R8-F3", original)["originState"], "not-established")
        self.assertEqual(original, self.cases["R8-F3"]["bundle"])

    def test_deterministic_cases_and_no_overwrite(self) -> None:
        self.assertEqual(self.fixture.cases(), list(self.cases.values()))
        with tempfile.TemporaryDirectory(prefix="r8-case-check-") as directory:
            output = Path(directory) / "new-run"
            first = self.fixture.write(output)
            self.assertEqual(len(first["files"]), 7)
            with self.assertRaises(FileExistsError):
                self.fixture.write(output)


if __name__ == "__main__":
    unittest.main()
