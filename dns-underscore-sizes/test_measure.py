import base64
import hashlib
import json
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.rdatatype

from measure import Measurement


class MeasurementTests(unittest.TestCase):
    def setUp(self):
        self.lab = Measurement()
        self.fixtures = {item.key: item for item in self.lab.fixtures}

    def test_txt_reassembles_and_counts_length_octets(self):
        for fixture in self.lab.fixtures:
            if fixture.rrset.rdtype == dns.rdatatype.TXT:
                data = fixture.rrset[0]
                self.assertEqual(b"".join(data.strings).decode("ascii"), fixture.details["text"])
                self.assertTrue(all(len(value) <= 255 for value in data.strings))
                self.assertEqual(len(data.to_wire()), sum(map(len, data.strings)) + len(data.strings))

    def test_dnsid_signature_is_fixed_width_and_verifies(self):
        fixture = self.fixtures["dnsid"]
        fields = dict(part.strip().split("=", 1) for part in fixture.details["text"].split(";"))
        signature = base64.urlsafe_b64decode(fields.pop("sg") + "==")
        self.assertEqual(len(signature), 64)
        canonical = ";".join(f"{key}={fields[key]}" for key in sorted(fields)).encode("ascii")
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        self.lab.entity_key.public_key().verify(
            utils.encode_dss_signature(r, s), canonical, ec.ECDSA(hashes.SHA256())
        )

    def test_dnsid_segmentation_changes_only_length_octets(self):
        compact = self.fixtures["dnsid"].rrset[0]
        published = self.fixtures["dnsid-six-chunks"].rrset[0]
        self.assertEqual(b"".join(compact.strings), b"".join(published.strings))
        self.assertEqual(len(published.strings), 6)
        self.assertEqual(len(published.to_wire()) - len(compact.to_wire()), 4)

    def test_apertoid_key_is_raw_standard_base64(self):
        fields = dict(part.split("=", 1) for part in self.fixtures["apertoid"].details["text"].split("; "))
        self.assertEqual(fields["k"], "ed25519")
        self.assertEqual(base64.b64decode(fields["pk"] + "="), self.lab.app_key.public_key().public_bytes_raw())
        self.assertGreater(int(fields["exp"]), self.lab.epoch)

    def test_alter_exact_signing_shape_and_timestamp_type(self):
        fixture = self.fixtures["mcp-alter"]
        fields = dict(part.split("=", 1) for part in fixture.details["text"].split("; "))
        self.assertEqual(list(fields), ["v", "h", "pk", "ilr", "ts", "rev", "sig"])
        canonical = fixture.details["canonical_signing_input"].encode("ascii")
        obj = json.loads(canonical)
        self.assertEqual(set(obj), {"v", "h", "pk", "ilr", "ts", "rev", "signature_alg", "caveats"})
        self.assertIsInstance(obj["ts"], str)
        self.assertEqual(obj["caveats"], [])
        signature = base64.urlsafe_b64decode(fields["sig"] + "==")
        self.lab.app_key.public_key().verify(signature, canonical)
        obj["ts"] = int(obj["ts"])
        with self.assertRaises(InvalidSignature):
            self.lab.app_key.public_key().verify(
                signature, json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("ascii")
            )

    def test_tlsa_hashes_der_spki_not_raw_key(self):
        fixture = self.fixtures["dane-did"]
        rdata = fixture.rrset[0].to_wire()
        self.assertEqual(len(rdata), 35)
        self.assertEqual(rdata[:3], bytes([3, 1, 1]))
        self.assertEqual(rdata[3:], hashlib.sha256(bytes.fromhex(fixture.details["spki_der_hex"])).digest())
        self.assertNotEqual(rdata[3:], hashlib.sha256(self.lab.app_key.public_key().public_bytes_raw()).digest())

    def test_positive_packet_accounting(self):
        fixture = self.fixtures["dane-did"]
        measured = self.lab.packet_measurement(fixture, False, False)
        expected = 12 + len(fixture.rrset.name.to_wire()) + 4 + 2 + 10 + 35
        self.assertEqual(measured["response_dns_bytes"], expected)
        edns = self.lab.packet_measurement(fixture, False)
        self.assertEqual(edns["response_dns_bytes"] - expected, 11)

    def test_signed_negative_responses_include_soa_and_denials(self):
        for fixture in self.lab.fixtures:
            if not fixture.primary:
                continue
            for mode in ["nsec", "nsec3"]:
                for kind in ["nodata", "nxdomain"]:
                    with self.subTest(fixture=fixture.key, mode=mode, kind=kind):
                        measured = self.lab.packet_measurement(fixture, True, denial=(mode, kind))
                        parsed = dns.message.from_wire(bytes.fromhex(measured["response_hex"]))
                        self.assertFalse(parsed.answer)
                        self.assertEqual(measured["rcode"], "NXDOMAIN" if kind == "nxdomain" else "NOERROR")
                        self.assertEqual(parsed.authority[0].rdtype, dns.rdatatype.SOA)
                        self.assertEqual(parsed.authority[0].ttl, 300)
                        self.assertEqual(parsed.authority[0][0].minimum, 300)
                        self.assertGreaterEqual(measured["denial_record_count"], 1)
                        self.assertEqual(measured["rrsig_count"], 1 + measured["denial_record_count"])

    def test_signed_response_rejects_expired_signature(self):
        fixture = self.fixtures["dnsid"]
        _, response, _ = self.lab.response(fixture, True)
        with self.assertRaises(dns.exception.ValidationFailure):
            dns.dnssec.validate(
                response.answer[0], response.answer[1],
                {fixture.zone: self.lab.dnskeys(fixture.zone)}, now=self.lab.epoch + 172801,
            )

    def test_rollover_adds_one_rr_not_another_rrsig(self):
        first = self.lab.packet_measurement(self.fixtures["dane-did"], True)
        second = self.lab.packet_measurement(self.fixtures["dane-two-keys"], True)
        self.assertEqual(second["response_dns_bytes"] - first["response_dns_bytes"], 47)
        self.assertEqual(first["rrsig_count"], 1)
        self.assertEqual(second["rrsig_count"], 1)

    def test_full_measurement_is_deterministic(self):
        self.assertEqual(Measurement().run(), Measurement().run())


if __name__ == "__main__":
    unittest.main()
