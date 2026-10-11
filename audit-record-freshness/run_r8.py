from __future__ import annotations

import argparse
import base64
import copy
import datetime
import hashlib
import importlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class EvidenceError(ValueError):
    pass


class FreshnessCases:
    PIN = "8c153446b697ad2fa68abac2b2e56a6cadffd865"
    EPOCH = datetime.datetime(2026, 10, 11, tzinfo=datetime.timezone.utc)
    CLOCK = "urn:example:r8:elapsed-milliseconds:zero-skew"
    SOURCE = "urn:example:r8:policy-source:one"
    INPUT = "policy-source"
    MAX_AGE_MS = 120_000
    EVIDENCE_TYPE = "application/vnd.example.r8-input-evidence+json"
    FORWARD_TYPE = "application/vnd.example.r8-forwarding+json"
    PROFILE = "urn:example:r8:experimental-companion:1"

    def __init__(self, upstream: Path):
        self.upstream = upstream.resolve(strict=True)
        self.check_upstream()
        sys.dont_write_bytecode = True
        sys.path.insert(0, str(self.upstream / "packaging"))
        self.reader = importlib.import_module("agent_evidence_vectors.auditrecord")
        self.rail = importlib.import_module("run_vectors")
        generator_path = self.upstream / "vectors-agent-audit-record" / "gen_vectors.py"
        spec = importlib.util.spec_from_file_location("r8_fixture_generator", generator_path)
        if (spec is None or
                spec.loader is None):
            raise EvidenceError("fixture-generator-unavailable")
        self.generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.generator)
        for module in (self.reader, self.rail, self.generator):
            module_path = Path(module.__file__).resolve()
            if not module_path.is_relative_to(self.upstream):
                raise EvidenceError(f"foreign-module: {module_path}")
        self.generator.build_a2()
        self.generator.build_a14()
        self.policy = self.reader.Policy(
            self.generator.PREDICATE_TYPE, self.generator.OBSERVER_PUB
        )

    def check_upstream(self) -> None:
        command = ["git", "-C", str(self.upstream)]
        head = subprocess.check_output(
            command + ["rev-parse", "HEAD"], text=True
        ).strip()
        if head != self.PIN:
            raise EvidenceError(f"unexpected-upstream: {head}")
        subprocess.run(command + ["diff", "--quiet", "HEAD", "--"], check=True)

    def encoded(self, value: Any) -> bytes:
        return self.generator.canonical_bytes(value)

    def sha256(self, value: bytes) -> str:
        return hashlib.sha256(value).hexdigest()

    def integer(self, value: Any, label: str) -> int:
        if (type(value) is not int or
                value < 0 or
                value >= 2**53):
            raise EvidenceError(f"invalid-{label}")
        return value

    def instant(self, milliseconds: int) -> str:
        time = self.EPOCH + datetime.timedelta(milliseconds=milliseconds)
        return time.isoformat(timespec="milliseconds").replace("+00:00", "Z")

    def decode(self, envelope: dict[str, Any]) -> dict[str, Any]:
        try:
            payload = base64.b64decode(envelope["payload"], validate=True)
            value = self.reader.parse_statement(payload)
        except (KeyError, TypeError, ValueError, self.reader.Malformed) as exc:
            raise EvidenceError("payload-unreadable") from exc
        if not isinstance(value, dict):
            raise EvidenceError("payload-not-object")
        return value

    def payload_digest(self, envelope: dict[str, Any]) -> str:
        return self.sha256(base64.b64decode(envelope["payload"], validate=True))

    def sign_companion(
        self, value: dict[str, Any], *, forwarding: bool = False
    ) -> dict[str, Any]:
        kind = self.FORWARD_TYPE if forwarding else self.EVIDENCE_TYPE
        key = self.generator.AGENT_KEY if forwarding else self.generator.OBSERVER_KEY
        key_id = self.generator.AGENT_KEYID if forwarding else self.generator.OBSERVER_KEYID
        payload = self.encoded(value)
        signature = key.sign(self.reader.pae(kind, payload))
        return {
            "payloadType": kind,
            "payload": base64.b64encode(payload).decode("ascii"),
            "signatures": [
                {"keyid": key_id, "sig": base64.b64encode(signature).decode("ascii")}
            ],
        }

    def verify_companion(
        self, envelope: dict[str, Any], *, forwarding: bool = False
    ) -> dict[str, Any]:
        kind = self.FORWARD_TYPE if forwarding else self.EVIDENCE_TYPE
        public = self.generator.AGENT_PUB if forwarding else self.generator.OBSERVER_PUB
        key_id = self.generator.AGENT_KEYID if forwarding else self.generator.OBSERVER_KEYID
        if envelope.get("payloadType") != kind:
            raise EvidenceError("companion-type-mismatch")
        value = self.decode(envelope)
        payload = base64.b64decode(envelope["payload"], validate=True)
        if payload != self.encoded(value):
            raise EvidenceError("companion-not-canonical")
        signatures = envelope.get("signatures")
        if (not isinstance(signatures, list) or
                len(signatures) != 1):
            raise EvidenceError("companion-signature-shape")
        entry = signatures[0]
        if (not isinstance(entry, dict) or
                entry.get("keyid") != key_id):
            raise EvidenceError("companion-signer-mismatch")
        try:
            signature = base64.b64decode(entry["sig"], validate=True)
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(public)).verify(
                signature, self.reader.pae(kind, payload)
            )
        except (KeyError, TypeError, ValueError, InvalidSignature) as exc:
            raise EvidenceError("companion-signature-invalid") from exc
        return value

    def audit_record(self, at_ms: int, *, evaluated: bool) -> dict[str, Any]:
        name = "A2" if evaluated else "A14"
        predicate = self.generator.from_pred(name)
        predicate["recordId"] = f"urn:example:r8:record:{at_ms}"
        predicate["decision"]["reportedAt"] = self.instant(at_ms)
        predicate["effect"]["interval"]["openedAt"] = self.instant(at_ms - 1_000)
        predicate["effect"]["interval"]["sealedAt"] = self.instant(at_ms + 1_000)
        predicate["issuedAt"] = self.instant(at_ms + 2_000)
        predicate["tier"] = "voluntary"
        predicate["observation"] = {
            "vantage": "self",
            "coverage": {"scopeComplete": True, "gaps": []},
        }
        predicate["fieldEvidence"] = {
            name: "producer-asserted" for name in predicate["fieldEvidence"]
        }
        return self.generator.envelope(self.generator.signed(predicate)["payload"])

    def origin(
        self, at_ms: int, result_at_ms: int | None, *,
        evaluated: bool, comparator: str = "inclusive",
    ) -> dict[str, Any]:
        audit = self.audit_record(at_ms, evaluated=evaluated)
        result = None
        if result_at_ms is not None:
            result = {
                "asOfMs": result_at_ms,
                "valueDigest": self.generator.h("policy/ledger-writers"),
            }
        evidence = {
            "profile": self.PROFILE,
            "auditPayloadSha256": self.payload_digest(audit),
            "input": self.INPUT,
            "source": self.SOURCE,
            "clock": self.CLOCK,
            "capturedAtMs": at_ms,
            "maximumAgeMs": self.MAX_AGE_MS,
            "comparison": comparator,
            "result": result,
        }
        if result is None:
            evidence["attemptAtMs"] = at_ms - 2
        return {
            "auditEnvelope": audit,
            "evidenceEnvelope": self.sign_companion(evidence),
        }

    def forwarded(self, original: dict[str, Any], at_ms: int) -> dict[str, Any]:
        bundle = copy.deepcopy(original)
        forwarding = {
            "profile": self.PROFILE,
            "clock": self.CLOCK,
            "auditPayloadSha256": self.payload_digest(bundle["auditEnvelope"]),
            "evidenceEnvelopeSha256": self.sha256(self.encoded(bundle["evidenceEnvelope"])),
            "forwardedAtMs": at_ms,
        }
        bundle["forwardingEnvelope"] = self.sign_companion(forwarding, forwarding=True)
        return bundle

    def observation_state(
        self, evidence: dict[str, Any], at_ms: int, comparator: str
    ) -> tuple[str, int | None]:
        if "result" not in evidence:
            return "insufficient-evidence", None
        result = evidence["result"]
        if result is None:
            return "not-established", None
        if not isinstance(result, dict):
            raise EvidenceError("result-not-object")
        if set(result) - {"asOfMs", "valueDigest"}:
            raise EvidenceError("unsupported-result-member")
        if "asOfMs" not in result:
            return "insufficient-evidence", None
        as_of = self.integer(result["asOfMs"], "result-time")
        if as_of > evidence["capturedAtMs"]:
            raise EvidenceError("result-after-capture")
        digest = result.get("valueDigest")
        if (not isinstance(digest, str) or
                len(digest) != 64 or
                any(c not in "0123456789abcdef" for c in digest)):
            raise EvidenceError("invalid-result-digest")
        age = at_ms - as_of
        within = age <= self.MAX_AGE_MS if comparator == "inclusive" else age < self.MAX_AGE_MS
        return ("within-bound" if within else "stale"), age

    def read(
        self, bundle: dict[str, Any], *, receiver_at_ms: int, comparator: str
    ) -> dict[str, Any]:
        receiver_at_ms = self.integer(receiver_at_ms, "receiver-time")
        if comparator not in ("inclusive", "strict"):
            raise EvidenceError("unknown-comparator")
        audit = bundle["auditEnvelope"]
        report = self.reader.verify(self.encoded(audit), self.policy)
        if report.verdict != "valid":
            raise EvidenceError(f"audit-malformed: {report.codes}")
        statement = self.decode(audit)
        result = {
            "auditVerdict": report.verdict,
            "auditCodes": report.codes,
            "auditDerivedTier": report.derived_tier,
            "reportedDecision": statement["predicate"]["decision"]["reported"],
            "originState": "insufficient-evidence",
            "receiverState": "insufficient-evidence",
            "originAgeMs": None,
            "receiverAgeMs": None,
            "comparator": comparator,
            "originComparator": None,
            "metadataReader": "local experimental mapper, not the Gilda reader",
        }
        companion = bundle.get("evidenceEnvelope")
        if companion is None:
            return result
        evidence = self.verify_companion(companion)
        allowed = {
            "profile", "auditPayloadSha256", "input", "source", "clock",
            "capturedAtMs", "maximumAgeMs", "comparison", "result", "attemptAtMs",
        }
        if set(evidence) - allowed:
            raise EvidenceError("unsupported-evidence-member")
        expected = {
            "profile": self.PROFILE,
            "auditPayloadSha256": self.payload_digest(audit),
            "input": self.INPUT,
            "source": self.SOURCE,
            "clock": self.CLOCK,
        }
        for name, value in expected.items():
            if evidence.get(name) != value:
                raise EvidenceError(f"evidence-{name}-mismatch")
        captured = self.integer(evidence.get("capturedAtMs"), "capture-time")
        maximum = self.integer(evidence.get("maximumAgeMs"), "maximum-age")
        if maximum != self.MAX_AGE_MS:
            raise EvidenceError("maximum-age-policy-mismatch")
        original_comparator = evidence.get("comparison")
        if original_comparator not in ("inclusive", "strict"):
            raise EvidenceError("unknown-origin-comparator")
        if statement["predicate"]["decision"]["reportedAt"] != self.instant(captured):
            raise EvidenceError("decision-time-mismatch")
        if receiver_at_ms < captured:
            raise EvidenceError("receiver-before-capture")
        if "attemptAtMs" in evidence:
            attempted = self.integer(evidence["attemptAtMs"], "attempt-time")
            if attempted > captured:
                raise EvidenceError("attempt-after-capture")
        forwarding = bundle.get("forwardingEnvelope")
        if forwarding is not None:
            forwarded = self.verify_companion(forwarding, forwarding=True)
            expected_forward = {
                "profile": self.PROFILE,
                "clock": self.CLOCK,
                "auditPayloadSha256": self.payload_digest(audit),
                "evidenceEnvelopeSha256": self.sha256(self.encoded(companion)),
            }
            if set(forwarded) != set(expected_forward) | {"forwardedAtMs"}:
                raise EvidenceError("forwarding-shape")
            for name, value in expected_forward.items():
                if forwarded[name] != value:
                    raise EvidenceError(f"forwarding-{name}-mismatch")
            forwarded_at = self.integer(forwarded["forwardedAtMs"], "forwarding-time")
            if not captured <= forwarded_at <= receiver_at_ms:
                raise EvidenceError("forwarding-time-order")
        origin_state, origin_age = self.observation_state(
            evidence, captured, original_comparator
        )
        receiver_state, receiver_age = self.observation_state(
            evidence, receiver_at_ms, comparator
        )
        result.update(
            originState=origin_state, receiverState=receiver_state,
            originAgeMs=origin_age, receiverAgeMs=receiver_age,
            originComparator=original_comparator,
        )
        return result

    def cases(self) -> list[dict[str, Any]]:
        definitions = [
            ("R8-F1", "inclusive", 119_999, 0, True, "within-bound"),
            ("R8-F2", "inclusive", 120_001, 0, False, "stale"),
            ("R8-F3", "inclusive", 120_001, None, False, "not-established"),
            ("R8-F4-inclusive", "inclusive", 120_000, 0, True, "within-bound"),
            ("R8-F4-strict", "strict", 120_000, 0, False, "stale"),
        ]
        cases = [
            {
                "id": name,
                "comparator": comparator,
                "receiverAtMs": at_ms,
                "expectedReceiverState": expected,
                "bundle": self.origin(
                    at_ms, result_at, evaluated=evaluated, comparator=comparator
                ),
            }
            for name, comparator, at_ms, result_at, evaluated, expected in definitions
        ]
        for case_id, original, expected in [
            ("R8-F5", cases[1], "stale"),
            ("R8-F6", cases[2], "not-established"),
        ]:
            cases.append({
                "id": case_id,
                "comparator": "inclusive",
                "receiverAtMs": 130_000,
                "expectedReceiverState": expected,
                "bundle": self.forwarded(original["bundle"], 129_999),
            })
        return cases

    def write(self, output: Path) -> dict[str, Any]:
        cases = self.cases()
        reports = []
        for case in cases:
            report = self.read(
                case["bundle"], receiver_at_ms=case["receiverAtMs"],
                comparator=case["comparator"],
            )
            if report["receiverState"] != case["expectedReceiverState"]:
                raise EvidenceError(f"unexpected-case-result: {case['id']}")
            reports.append({"id": case["id"], **report})
        same_audit = cases[1]["bundle"]["auditEnvelope"] == cases[2]["bundle"]["auditEnvelope"]
        if not same_audit:
            raise EvidenceError("stale-and-no-result-audit-pair-drifted")
        self.check_upstream()
        output.mkdir(parents=True, exist_ok=False)
        files = []
        for case in cases:
            path = output / f"{case['id']}.json"
            body = (json.dumps(case, indent=2, sort_keys=True) + "\n").encode("utf-8")
            with path.open("xb") as stream:
                stream.write(body)
            files.append({"file": path.name, "bytes": len(body), "sha256": self.sha256(body)})
        source_paths = [
            Path("vectors-agent-audit-record") / "gen_vectors.py",
            Path("vectors-agent-audit-record") / "canonical.py",
            Path("packaging") / "agent_evidence_vectors" / "auditrecord.py",
            Path("packaging") / "run_vectors.py",
        ]
        summary = {
            "scope": "Experimental local mapping; no agreed Gilda extension or runtime result",
            "upstreamCommit": self.PIN,
            "upstreamPullRequest": "https://github.com/probityai/agent-evidence-vectors/pull/85",
            "sixScenariosSevenVariants": True,
            "staleAndNoResultHaveIdenticalAuditEnvelope": same_audit,
            "clock": {"id": self.CLOCK, "epoch": self.instant(0), "assumedSkewMs": 0},
            "testKeysOnly": True,
            "files": files,
            "sources": {
                name.as_posix(): self.sha256((self.upstream / name).read_bytes())
                for name in source_paths
            },
            "reports": reports,
        }
        with (output / "summary.json").open("x", encoding="utf-8") as stream:
            json.dump(summary, stream, indent=2, sort_keys=True)
            stream.write("\n")
        return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    summary = FreshnessCases(arguments.upstream).write(arguments.output)
    print(json.dumps({
        "upstreamCommit": summary["upstreamCommit"],
        "variants": len(summary["reports"]),
        "states": {report["id"]: report["receiverState"] for report in summary["reports"]},
        "identicalStaleAndNoResultAudit": summary["staleAndNoResultHaveIdenticalAuditEnvelope"],
    }, indent=2))
