# DNS wire sizes for underscore-label key records

Serialized sizes for the four drafts compared in Blake Morrison's
[Four drafts side by side, on five axes](https://mailarchive.ietf.org/arch/msg/dns-underscore-keys/IZ2sMGeSEHr-A16iL6VCwtQWQeY/)
on dns-underscore-keys.

| Draft and selected record | RDATA | Whole DNS response, unsigned, no EDNS | With DNSSEC and EDNS |
|---|---:|---:|---:|
| [DNSid `-01`](https://www.ietf.org/archive/id/draft-ihsanullah-dnsid-01.txt), self-accounted `_dnsid` TXT | 375 | 438 | 552 |
| [ApertoID `-02`](https://www.ietf.org/archive/id/draft-ferro-dnsop-apertoid-02.txt), agent declaration TXT | 131 | 193 | 311 |
| [MCP DNS discovery `-08`](https://www.ietf.org/archive/id/draft-morrison-mcp-dns-discovery-08.txt), `_alter` envelope TXT | 287 | 335 | 453 |
| [DANE DID `-01`](https://www.ietf.org/archive/id/draft-ranjbar-dane-did-01.txt), one TLSA `3 1 1` | 35 | 87 | 205 |

Sizes are in bytes. Each is one concrete fixture record built to the draft's text, not a claim
about every deployment.

## What this is and is not

These are lengths of generated DNS messages: deterministic fixtures, application and DNSSEC
signatures, wire serialization, denial proofs and size accounting. They are not packet captures,
resolver benchmarks or protocol conformance. The fixture DNSKEY is supplied directly for signature
verification; no root or parent DS chain is fetched. Denial results cover only the constructed
zones. Cache refresh bytes are derived, not measured latency or revocation timing.

No network calls are made. All private keys are intentionally public, deterministic test material;
never use them in a service.

## Replay

Verified on Windows x64 with Python 3.13.7, dnspython 2.8.0 and cryptography 46.0.6.

```sh
python -m venv .venv            # then activate it
pip install -r requirements.txt
python -B -m unittest -q test_measure
python -B measure.py --output ./replay.json
```

Expected: 11 tests pass, 46 signatures validate on parsed packets, 531 fixture and accounting
conditions hold, and `replay.json` is byte-identical to `measurements.json`. `--output` must be a
new file.

## Files

| File | Contents |
|---|---|
| `measure.py` | Fixtures, signatures, serialization, denial proofs and size accounting |
| `test_measure.py` | TXT, signature, encoding, timestamp, TLSA/SPKI, denial, truncation, rollover and determinism checks |
| `measurements.json` | Every fixture field, source hash, query and response hex, size, 512/1,232-byte truncation result and modeled cache cost |
