# Audit-record freshness: stale, never obtained, and forwarded

Experimental cases for the WIMSE discussion of `draft-gilda-wimse-agent-audit-record`
(thread: [recording "could not evaluate"](https://mailarchive.ietf.org/arch/msg/wimse/6cNM8xY__MqPUjjDSPDRpvsasT8/)).
This is not an agreed extension of that draft, and the field names below are not proposed
standard names.

The point it shows: a decision that relied on a result that had gone stale, and a decision that
never obtained a result at all, can produce the same denial and the same audit record. They need
something else to stay distinguishable, and forwarding must not refresh either one.

## What this executes

The generator reuses the upstream builders, canonicalizer, DSSE signer and Python reference
reader at
[`probityai/agent-evidence-vectors@8c15344`](https://github.com/probityai/agent-evidence-vectors/pull/85)
(the head of PR #85). It does not modify that checkout or call its corpus generator.

Six scenarios, seven variants (the exact-boundary case has an inclusive and a strict variant).
`R8-F*` are local case labels; they do not replace the upstream corpus's `F*` identifiers. All
report a deny. Records are synthetic, voluntary-tier, with producer-asserted fields.

| Case | Receiver age, ms | Reading |
|---|---:|---|
| `R8-F1` | 119,999 | Known result within the bound; evaluated deny |
| `R8-F2` | 120,001 | Known result stale; fallback deny |
| `R8-F3` | 120,001 | Explicitly no result obtained; fallback deny |
| `R8-F4-inclusive` | 120,000 | Within `age <= 120000`; evaluated deny |
| `R8-F4-strict` | 120,000 | Outside `age < 120000`; fallback deny |
| `R8-F5` | 130,000 | A stale result is still stale after forwarding |
| `R8-F6` | 130,000 | A no-result report is still no-result after forwarding |

The fixture clock has one declared epoch, millisecond precision and zero assumed skew. Result
time is zero and the maximum age is 120,000 ms. Receiver instant and comparator are explicit test
inputs, not taken from transport timestamps.

## The experimental companion

The audit record keeps its existing shape. A separate signed companion binds the audit payload
digest, input, source, clock, capture time, age bound and origin comparator:

- `result: {"asOfMs": 0, "valueDigest": "..."}` means a result was held.
- `result: null` explicitly reports that no result was obtained.
- An omitted `result` is insufficient evidence; it is not read as the explicit no-result case.
- `attemptAtMs` is only an attempt time and never stands in for a result time.

The origin key signs the companion. A separate forwarding key signs references to the exact
original audit payload and companion; forwarding carries them unchanged, and its own time is not a
new observation. The `urn:example:*` and `application/vnd.example.*` identifiers are fixtures, not
registrations.

`R8-F2` and `R8-F3` have byte-identical audit envelopes and different signed companions. Without
the companion the mapper reports insufficient evidence. That shows the representation gap; it is
not a bug report against the reference reader.

## Limits

All keys are the upstream repository's published test keys. Signatures show integrity under the
fixture trust assumptions only, not real origin authentication or the truth of a producer's
assertions. The Gilda reference reader judges only the audit record; the companion is read by the
local experimental mapper. No Go reader change, upstream CI, conformance or runtime enforcement is
claimed.

## Replay

Verified on Windows x64 with Python 3.13.7 and cryptography 46.0.6.

```sh
git clone https://github.com/probityai/agent-evidence-vectors.git
git -C agent-evidence-vectors fetch origin pull/85/head
git -C agent-evidence-vectors checkout 8c153446b697ad2fa68abac2b2e56a6cadffd865

python -m venv .venv            # then activate it
pip install -r requirements.txt
python -B -m unittest -q test_r8                  # needs R8_UPSTREAM set to the checkout above
python -B run_r8.py --upstream ../agent-evidence-vectors --output ./run-new
```

The runner refuses a different upstream commit, modified upstream sources, or an existing output
folder. Expected: 17 tests pass, and the seven case files and `summary.json` in `run-new/` are
byte-identical to `run-01/` (the run is deterministic).

## Files

| File | Contents |
|---|---|
| `run_r8.py` | Generator and experimental mapper |
| `test_r8.py` | 17 focused checks: both boundary policies, absent versus null, attempt times, unchanged forwarding, re-signed substitutions, tampering, cross-record binding and a later new decision |
| `run-01/` | The seven signed case bundles and `summary.json` from the recorded run |
