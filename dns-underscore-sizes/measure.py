import argparse
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

import cryptography
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
import dns
import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset


SOURCES = {
    "dnsid": {
        "document": "draft-ihsanullah-dnsid-01",
        "sections": ["5.8", "6.2"],
        "sha256": "a2b7952c8840be104c9633f9acbd46d403c47492cfd1a557948bb28a7baf0039",
    },
    "apertoid": {
        "document": "draft-ferro-dnsop-apertoid-02",
        "sections": ["8", "11"],
        "sha256": "52e78c69d30fe51a8578f69c90258bd60a72fa4f36f4d9076cf23a673759980b",
    },
    "mcp": {
        "document": "draft-morrison-mcp-dns-discovery-08",
        "sections": ["7.1", "7.2", "7.3", "7.4"],
        "sha256": "3645d5536cf08b686cb9adff3c0bd82d1044eb13c6dfec8581b7c73642b34dc0",
    },
    "dane": {
        "document": "draft-ranjbar-dane-did-01",
        "sections": ["4", "7", "9"],
        "sha256": "f8402905fa3bdd4681ae7be6391341330c28b48c9cd17d8041d783d47f0c2830",
    },
}


@dataclass
class Fixture:
    key: str
    source: str
    zone: dns.name.Name
    rrset: dns.rrset.RRset
    details: dict
    primary: bool = True


class Measurement:
    def __init__(self):
        self.epoch = int(datetime(2026, 10, 11, tzinfo=timezone.utc).timestamp())
        self.signature_checks = 0
        self.condition_checks = 0
        # Public deterministic fixture keys, not credentials or deployable keys.
        self.dns_key = ed25519.Ed25519PrivateKey.from_private_bytes(
            hashlib.sha256(b"DNS wire measurements: public DNSSEC test seed").digest()
        )
        self.app_key = ed25519.Ed25519PrivateKey.from_private_bytes(
            hashlib.sha256(b"DNS wire measurements: public application test seed").digest()
        )
        self.entity_key = ec.derive_private_key(1, ec.SECP256R1())
        self.dnskey = dns.dnssec.make_dnskey(self.dns_key.public_key(), 15)
        self.fixtures = self.make_fixtures()

    def require(self, condition, message):
        if not condition:
            raise ValueError(message)
        self.condition_checks += 1

    def b64url(self, value):
        return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")

    def txt_fixture(self, key, source, owner, zone, ttl, text, details, chunks=None):
        data = text.encode("ascii")
        if chunks is None:
            chunks = [data[index:index + 255] for index in range(0, len(data), 255)]
        self.require(b"".join(chunks) == data, "TXT chunks changed the record text")
        self.require(all(0 < len(chunk) <= 255 for chunk in chunks), "Invalid TXT chunk")
        quoted = " ".join('"' + chunk.decode("ascii") + '"' for chunk in chunks)
        rrset = dns.rrset.from_text(owner, ttl, "IN", "TXT", quoted)
        self.require(
            len(rrset[0].to_wire()) == len(data) + len(chunks),
            "TXT length-octet accounting differs",
        )
        return Fixture(key, source, dns.name.from_text(zone), rrset, {
            **details,
            "text": text,
            "text_bytes": len(data),
            "chunk_bytes": [len(chunk) for chunk in chunks],
        })

    def make_fixtures(self):
        fields = {
            "v": "DNSid1",
            "gi": "billing-agent-acme.example",
            "fl": "mtls,logchk",
            "ek": "https://billing-agent-acme.example/dnsid/entity-keys.json",
            "ku": "https://billing-agent-acme.example/dnsid/op-keys.json",
            "lr": "scitt:https://log.billing-agent-acme.example/entries/3f9a",
            "su": "https://billing-agent-acme.example/dnsid/status",
        }
        canonical = ";".join(f"{key}={fields[key]}" for key in sorted(fields)).encode("ascii")
        algorithm = ec.ECDSA(hashes.SHA256(), deterministic_signing=True)
        der_signature = self.entity_key.sign(canonical, algorithm)
        self.entity_key.public_key().verify(der_signature, canonical, algorithm)
        r, s = utils.decode_dss_signature(der_signature)
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        fields["sg"] = self.b64url(signature)
        dnsid_text = ";".join(f"{key}={value}" for key, value in fields.items())
        dnsid = self.txt_fixture(
            "dnsid", "dnsid", "_dnsid.billing-agent-acme.example.", "example.", 300,
            dnsid_text, {"entity_signature": "ES256, fixed 64-byte R||S",
                         "canonical_signing_input": canonical.decode("ascii")},
        )
        published_chunks = [
            ";".join(f"{key}={fields[key]}" for key in ["v", "gi", "fl"]) + ";",
            *[f"{key}={fields[key]};" for key in ["ek", "ku", "lr", "su"]],
            "sg=" + fields["sg"],
        ]
        split = self.txt_fixture(
            "dnsid-six-chunks", "dnsid", dnsid.rrset.name, "example.", 300,
            dnsid_text, dnsid.details, [chunk.encode("ascii") for chunk in published_chunks],
        )
        split.primary = False
        raw_key = self.app_key.public_key().public_bytes_raw()
        standard_b64 = base64.b64encode(raw_key).decode("ascii").rstrip("=")
        apertoid = self.txt_fixture(
            "apertoid", "apertoid", "leadhunter._apertoid.example.com.", "example.com.", 3600,
            "v=APERTOID1; url=https://agent.example.com/mcp; k=ed25519; "
            f"pk={standard_b64}; type=ai; exp={self.epoch + 86400}",
            {"key_encoding": "standard unpadded Base64; raw 32-byte Ed25519 key"},
        )
        revoked = self.txt_fixture(
            "apertoid-revoked", "apertoid", apertoid.rrset.name, "example.com.", 300,
            "v=APERTOID1; status=revoked", {"meaning": "positive revocation marker, not NXDOMAIN"},
        )
        revoked.primary = False
        envelope = {
            "v": "alter1",
            "h": "~example.com",
            "pk": "ed25519:" + self.b64url(raw_key),
            "ilr": self.b64url(hashlib.sha256(b"synthetic IdentityLog root").digest()),
            "ts": str(self.epoch),
            "rev": self.b64url(hashlib.sha256(b"synthetic revocation commitment").digest()),
        }
        signing_object = {**envelope, "signature_alg": "Ed25519", "caveats": []}
        # This ASCII/string/empty-array subset has no JCS number or Unicode edge cases.
        signing_input = json.dumps(signing_object, sort_keys=True, separators=(",", ":")).encode("ascii")
        detached = self.app_key.sign(signing_input)
        self.app_key.public_key().verify(detached, signing_input)
        envelope["sig"] = self.b64url(detached)
        mcp = self.txt_fixture(
            "mcp-alter", "mcp", "_alter.example.com.", "example.com.", 300,
            "; ".join(f"{key}={value}" for key, value in envelope.items()),
            {"signing_object": signing_object, "canonical_signing_input": signing_input.decode("ascii"),
             "scope": "_alter envelope only, not _mcp service discovery or IdentityLog queries"},
        )
        spki = self.app_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        digest = hashlib.sha256(spki).hexdigest()
        tlsa = dns.rrset.from_text("_did.agent.example.com.", 300, "IN", "TLSA", "3 1 1 " + digest)
        dane = Fixture("dane-did", "dane", dns.name.from_text("example.com."), tlsa,
                       {"spki_der_hex": spki.hex(), "digest": digest, "public_key_location": "external DID document"})
        other_key = ed25519.Ed25519PrivateKey.from_private_bytes(
            hashlib.sha256(b"DNS wire measurements: second public application test seed").digest()
        )
        other_spki = other_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        rollover = dns.rrset.from_text(
            tlsa.name, 300, "IN", "TLSA", "3 1 1 " + digest,
            "3 1 1 " + hashlib.sha256(other_spki).hexdigest(),
        )
        two_keys = Fixture("dane-two-keys", "dane", dane.zone, rollover,
                           {"scope": "two TLSA digests in one RRset, one covering RRSIG"}, False)
        return [dnsid, apertoid, mcp, dane, split, revoked, two_keys]

    def signature(self, rrset, zone):
        signature = dns.dnssec.sign(
            rrset, self.dns_key, zone, self.dnskey,
            inception=self.epoch - 3600, expiration=self.epoch + 172800,
            deterministic=True, verify=True,
        )
        self.require(len(signature.signature) == 64, "Expected an Ed25519 DNSSEC signature")
        return dns.rrset.from_rdata(rrset.name, rrset.ttl, signature)

    def dnskeys(self, zone):
        return dns.rrset.from_rdata(zone, 300, self.dnskey)

    def response(self, fixture, signed, edns=True, payload=1232, denial=None):
        query = dns.message.make_query(
            fixture.rrset.name, fixture.rrset.rdtype, use_edns=edns,
            want_dnssec=signed, payload=payload, id=0x4B44,
        )
        query.flags = 0
        response = dns.message.make_response(query)
        response.flags |= dns.flags.AA
        if edns:
            response.use_edns(edns=0, ednsflags=dns.flags.DO if signed else 0, payload=1232)
        proof_roles = []
        if denial is None:
            response.answer.append(fixture.rrset)
            if signed:
                response.answer.append(self.signature(fixture.rrset, fixture.zone))
        else:
            mode, kind = denial
            soa = dns.rrset.from_text(
                fixture.zone, 300, "IN", "SOA",
                f"ns.{fixture.zone} hostmaster.{fixture.zone} 2026101001 3600 600 86400 300",
            )
            response.authority.extend([soa, self.signature(soa, fixture.zone)])
            proof_sets, proof_roles = self.denial_proofs(fixture, mode, kind)
            for rrset in proof_sets:
                response.authority.extend([rrset, self.signature(rrset, fixture.zone)])
            if kind == "nxdomain":
                response.set_rcode(dns.rcode.NXDOMAIN)
        return query, response, proof_roles

    def interval_contains(self, start, end, target):
        if start < end:
            return start < target < end
        return target > start or target < end

    def denial_proofs(self, fixture, mode, kind):
        name = fixture.rrset.name
        parent = name.parent()
        nodes = {fixture.zone: {"NS", "SOA", "DNSKEY"}}
        for node in [parent, dns.name.from_text("ns", fixture.zone), dns.name.from_text("z", parent)]:
            nodes.setdefault(node, set()).add("A")
        if kind == "nodata":
            nodes.setdefault(name, set()).add("A")
        self.require(dns.rdatatype.to_text(fixture.rrset.rdtype) not in nodes.get(name, set()),
                     "Denial fixture unexpectedly contains the queried type")
        wildcard = dns.name.from_text("*", parent)
        transform = lambda value: value
        if mode == "nsec3":
            transform = lambda value: dns.dnssec.nsec3_hash(value, None, 0, 1)
        transformed = {transform(node): node for node in nodes}
        keys = sorted(transformed)
        ring = {}
        for index, key in enumerate(keys):
            following = keys[(index + 1) % len(keys)]
            types = nodes[transformed[key]] | {"RRSIG"}
            if mode == "nsec":
                types.add("NSEC")
            bitmap = " ".join(sorted(types, key=dns.rdatatype.from_text))
            if mode == "nsec":
                rrset = dns.rrset.from_text(key, 300, "IN", "NSEC", f"{following} {bitmap}")
            else:
                owner = dns.name.from_text(key, fixture.zone)
                rrset = dns.rrset.from_text(owner, 300, "IN", "NSEC3", f"1 0 0 - {following} {bitmap}")
            ring[key] = (following, rrset)
        selected = {}
        roles = []
        if kind == "nodata":
            key = transform(name)
            selected[key] = ring[key][1]
            roles.append({"role": "matching-owner-type-absent", "target": str(key)})
        else:
            self.require(name not in nodes, "NXDOMAIN name exists")
            self.require(wildcard not in nodes, "Wildcard would prevent NXDOMAIN")
            if mode == "nsec3":
                key = transform(parent)
                selected[key] = ring[key][1]
                roles.append({"role": "closest-encloser", "target": str(key)})
            for role, target in [("queried-name", transform(name)), ("wildcard", transform(wildcard))]:
                covering = [key for key, (following, _) in ring.items()
                            if self.interval_contains(key, following, target)]
                self.require(len(covering) == 1, "No unique authenticated denial interval")
                key = covering[0]
                selected[key] = ring[key][1]
                roles.append({"role": role, "target": str(target), "start": str(key), "end": str(ring[key][0])})
        return list(selected.values()), roles

    def validate_packet(self, wire, zone):
        parsed = dns.message.from_wire(wire)
        self.require(parsed.to_wire(max_size=65535, want_shuffle=False) == wire,
                     "DNS packet round trip changed bytes")
        for section in [parsed.answer, parsed.authority]:
            for rrset in section:
                if rrset.rdtype == dns.rdatatype.RRSIG:
                    continue
                signatures = [item for item in section
                              if item.name == rrset.name and
                              item.rdtype == dns.rdatatype.RRSIG and
                              item.covers == rrset.rdtype]
                if signatures:
                    dns.dnssec.validate(rrset, signatures[0], {zone: self.dnskeys(zone)}, now=self.epoch)
                    self.signature_checks += 1
        return parsed

    def packet_measurement(self, fixture, signed, edns=True, denial=None):
        query, response, roles = self.response(fixture, signed, edns, denial=denial)
        wire = response.to_wire(max_size=65535, want_shuffle=False)
        parsed = self.validate_packet(wire, fixture.zone)
        query_wire = query.to_wire()
        self.require(query.is_response(parsed), "Response is not paired with its query")
        limits = {}
        for limit in [512, 1232]:
            _, limited_response, _ = self.response(fixture, signed, edns, limit, denial)
            limited = limited_response.to_wire(max_size=limit, prefer_truncation=True, want_shuffle=False)
            tc = bool(dns.message.from_wire(limited).flags & dns.flags.TC)
            self.require(tc == (len(wire) > limit), "Truncation flag disagrees with the full-message size")
            self.require(len(limited) <= limit, "Truncated response exceeds the advertised limit")
            limits[str(limit)] = {
                "dns_bytes": len(limited), "tc": tc, "wire_hex": limited.hex(),
                "tcp_fallback_needed_for_complete_response": tc,
            }
        return {
            "query_dns_bytes": len(query_wire),
            "response_dns_bytes": len(wire),
            "tcp_framed_response_bytes": len(wire) + 2,
            "udp_ipv4_response_bytes_no_options": len(wire) + 28,
            "udp_ipv6_response_bytes_no_extensions": len(wire) + 48,
            "query_hex": query_wire.hex(),
            "response_hex": wire.hex(),
            "response_sha256": hashlib.sha256(wire).hexdigest(),
            "rcode": dns.rcode.to_text(parsed.rcode()),
            "rrsig_count": sum(len(rrset) for section in [parsed.answer, parsed.authority]
                               for rrset in section if rrset.rdtype == dns.rdatatype.RRSIG),
            "denial_record_count": sum(len(rrset) for rrset in parsed.authority
                                       if rrset.rdtype in [dns.rdatatype.NSEC, dns.rdatatype.NSEC3]),
            "proof_roles": roles,
            "udp_limits": limits,
        }

    def run(self):
        records = []
        key_responses = {}
        for fixture in self.fixtures:
            packets = {
                "unsigned_no_edns": self.packet_measurement(fixture, False, False),
                "unsigned_edns": self.packet_measurement(fixture, False),
                "signed_edns": self.packet_measurement(fixture, True),
            }
            if fixture.primary:
                for mode in ["nsec", "nsec3"]:
                    for kind in ["nodata", "nxdomain"]:
                        packets[f"{mode}_{kind}"] = self.packet_measurement(fixture, True, denial=(mode, kind))
            signed = packets["signed_edns"]
            daily_cost = []
            for ttl in [60, 300, 3600]:
                queries = 86400 // ttl
                daily_cost.append({
                    "ttl_seconds": ttl,
                    "queries_per_continuously_used_cache_per_day": queries,
                    "dns_query_and_response_bytes_per_day": queries * (
                        signed["query_dns_bytes"] + signed["response_dns_bytes"]
                    ),
                })
            records.append({
                "key": fixture.key, "source": fixture.source, "primary": fixture.primary,
                "owner": str(fixture.rrset.name), "zone": str(fixture.zone),
                "rrtype": dns.rdatatype.to_text(fixture.rrset.rdtype), "ttl": fixture.rrset.ttl,
                "rr_count": len(fixture.rrset),
                "rdata_bytes_each": [len(rdata.to_wire()) for rdata in fixture.rrset],
                "rdata_hex_each": [rdata.to_wire().hex() for rdata in fixture.rrset],
                "details": fixture.details, "packets": packets,
                "derived_busy_cache_cost": daily_cost,
            })
            zone = str(fixture.zone)
            if zone not in key_responses:
                key_fixture = Fixture("dnskey", "", fixture.zone, self.dnskeys(fixture.zone), {})
                key_responses[zone] = self.packet_measurement(key_fixture, True)
        return {
            "method": "local deterministic DNS wire serialization; no network packet capture",
            "fixture_epoch_utc": datetime.fromtimestamp(self.epoch, timezone.utc).isoformat(),
            "dependencies": {"dnspython": dns.__version__, "cryptography": cryptography.__version__},
            "sources": {key: {**value, "url": "https://www.ietf.org/archive/id/" + value["document"] + ".txt"}
                        for key, value in SOURCES.items()},
            "dnssec": {"algorithm": "Ed25519 (15)", "signature_octets": 64,
                       "dnskey_rdata_hex": self.dnskey.to_wire().hex(),
                       "inception": self.epoch - 3600, "expiration": self.epoch + 172800,
                       "remaining_validity_seconds_at_fixture_epoch": 172800,
                       "trust_model": "fixture DNSKEY supplied directly; parent DS/root validation not measured",
                       "nsec3": {"hash": "SHA-1 (1)", "iterations": 0, "salt": "", "opt_out": False}},
            "records": records, "separate_dnskey_responses": key_responses,
            "checks": {"parsed_packet_signature_validations": self.signature_checks,
                       "conditions": self.condition_checks},
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("measurements.json"))
    args = parser.parse_args()
    result = Measurement().run()
    with args.output.open("x", encoding="utf-8", newline="\n") as output:
        json.dump(result, output, indent=2)
        output.write("\n")
    for record in result["records"]:
        if record["primary"]:
            sizes = record["packets"]
            print(f'{record["key"]}: RDATA={record["rdata_bytes_each"]}; '
                  f'DNS={sizes["unsigned_no_edns"]["response_dns_bytes"]}; '
                  f'DNSSEC+EDNS={sizes["signed_edns"]["response_dns_bytes"]}')
    print(json.dumps(result["checks"]))
