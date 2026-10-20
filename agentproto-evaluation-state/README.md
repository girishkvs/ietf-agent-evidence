# Evaluation-state test vectors

Test vectors for the test cases in Section 7.1 of
[`draft-konda-agentproto-evaluation-state-02`](https://datatracker.ietf.org/doc/draft-konda-agentproto-evaluation-state/),
with a small checker that applies the draft's rules to each vector and compares the result with the
expected state. This is discussion evidence for the draft, not a conformance suite. [Names](#names)
says which names are candidates and which are fixture names.

The point it shows: the same refusal can come from an established negative input, a stale input,
an input that was never obtained, or one whose state arrived after the decision. The rules that
keep these apart are small enough to state exactly and check by machine.

## Rules the checker applies

From Sections 6 and 7 of the draft:

- An input's age is the time of the decision minus its "as of" time, the time its source produced
  the value. A forwarded value keeps the source's "as of" time. The time a hop received it is not
  used.
- An input is stale only when its age is greater than the freshness bound. An age equal to the
  bound is within it. Each hop applies its own bound.
- An input that was never obtained has no "as of" time. It is not-established, not stale.
- An "as of" time later than the decision by more than the skew tolerance (300 seconds here) makes
  the input not-established. At exactly the tolerance it does not.
- A value that reaches the deciding participant after the decision is not used for that decision.
- A source that can't be reached, a source the decision point's own policy blocks, a policy profile
  it doesn't hold, and a lookup that did not complete all leave the input not-established. Only a
  completed lookup can establish that something is absent, and whether absence is positive or
  negative depends on the predicate.
- Each evaluation writes a new record. An earlier record is never changed.

Every case uses a fail-closed policy: the checker refuses unless the input is established-positive.
A refusal on an established-negative input is permanent. A refusal on a stale or not-established
input is transient. The caller sees only `denied` or `evaluation-incomplete`, while the operator
record names the input, its state and the reason.

To show where two drafts differ, TC-2 is also evaluated under the rule in Section 3 of
`draft-jackson-wimse-evaluation-04`. Under that rule a fetched input may not be used at or past its
horizon, so an age equal to the maximum is already outside the bound.

## Names

The states are the ones in Section 6 of the draft: `established-positive`, `established-negative`,
`stale` and `not-established`. The reasons are candidate names for why an input reached its state:
`within-bound`, `older-than-bound`, `no-value`, `unreachable`, `blocked-by-own-policy`,
`profile-not-held`, `lookup-incomplete`, `as-of-after-decision` and `not-available-at-decision`.
A caller sees only `denied` or `evaluation-incomplete`. A `profile-not-held` record also carries the
exact profile identifier and the compared component, as Section 4.2 of the draft describes. All
other JSON field names are fixture names, not proposed protocol fields.

## Cases

| Case | Condition | Expected | Matching public vector or case |
|---|---|---|---|
| TC-1 | Age below the bound | Established; the record keeps the "as of" time and bound | Jackson `-04` A.3 G1, G4 |
| TC-2 | Age equal to the bound | Within the bound; stale under Jackson's rule | Gilda `-00` FR2 (same); Jackson `-04` A.3 G2, G3 (different) |
| TC-3 | Age above the bound | Stale; transient refusal | Gilda `-00` FR3; Jackson `-04` A.3 G3 |
| TC-4 | Never obtained | Not-established; no "as of" time | Gilda `-00` A10, FR4 |
| TC-5 | Source unreachable, or blocked by own retrieval policy | Not-established, with two different reasons | DAWN `-02` REQ-PROP-3 |
| TC-6 | Complete lookup finds absence; lookup did not complete | Established, positive or negative by predicate; not-established | DAWN `-02` REQ-PROP-3 |
| TC-7 | Policy profile not held | Not-established; the record carries the reason, the exact profile identifier and the compared component | Gilda `-00` A20; Schrock `-06` Section 7; Ahuja `-02` Sections 4 and 6 |
| TC-8 | Consumption state cannot be read | Not-established; transient refusal | Jackson `-04` A.1 E7 |
| TC-9 | Status list not fetched; cached answer expired | Not-established; stale; never "not revoked" | Asor `-02` Section 6 step 7 |
| TC-10 | Value received from another hop | Age runs from the source | Gilda `-00` FR1, FR3 |
| TC-11 | One value at two hops, bounds 7200 and 3600 seconds | Within at the first hop, stale at the second | PR 185 FR15a, FR15b (open) |
| TC-12 | A later hop obtains the input | New record; earlier record unchanged | Gilda `-00` Section 5.4 |
| TC-13 | "As of" time after the decision | Beyond tolerance: not-established; at tolerance: within | Gilda `-00` FR9; PR 185 FR16 (open) |
| TC-14 | State reaches the deciding participant after the decision | Not-established for that decision; the later record is separate | - |
| TC-15 | Coarse reason for the caller | Caller: `evaluation-incomplete`; record: input and state | UC&R `-04` Section 7 |

There are 24 vectors and 27 evaluations. Times are UTC with whole seconds.

Gilda `-00` is `draft-gilda-audit-agent-audit-record-00` (vectors in its Appendix B), Jackson `-04`
is `draft-jackson-wimse-evaluation-04` (cases in its Appendix A), Asor `-02` is
`draft-asor-wimse-agent-delegation-chain-02`, DAWN `-02` is `draft-king-dawn-requirements-02`,
Schrock `-06` is `draft-schrock-ep-bounded-capability-receipts-06`, Ahuja `-02` is
`draft-ahuja-agent-routing-policy-02`, and UC&R `-04` is
`draft-agentic-ai-usecases-requirements-04`. PR 185 is
[`probityai/agent-evidence-vectors#185`](https://github.com/probityai/agent-evidence-vectors/pull/185),
compared at commit `c11b55d`.

## Limits

The cases are synthetic. The checker is a reference reading of the draft's rules, not an
implementation of any audit format, token or protocol. Nothing is signed and no network is used.
The matching column compares expected outcomes only, because the formats differ. For example,
Gilda's format treats the TC-13 record as malformed, while this draft calls the input
not-established. FR15a, FR15b and FR16 are in an open pull request and may change.

## Replay

Verified on Windows x64 with Python 3.13.7. No third-party packages are needed.

```sh
python -B -m unittest -q test_check_cases
python -B check_cases.py --output ./replay.json
```

Expected: 14 tests pass, all 24 vectors match, and `replay.json` is byte-identical to
`results.json`, apart from any CRLF line endings a Windows checkout adds to `results.json`.
`--output` must be a new file.

## Files

| File | Contents |
|---|---|
| `cases.json` | The 15 cases: conditions, expected states and records, and the matching public vectors |
| `check_cases.py` | Reference checker |
| `test_check_cases.py` | 14 focused checks: both boundary rules, source time versus receipt time, per-hop bounds, skew, absence, late state, the profile-not-held record, the caller view, unchanged earlier records and replay |
| `results.json` | The recorded run |
