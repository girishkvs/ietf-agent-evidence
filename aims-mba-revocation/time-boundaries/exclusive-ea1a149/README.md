# Exclusive (at-or-past) boundary rule: expectations and MBA comparison

Prepared 12 November 2026 by Mikhail Sergeev, following the WIMSE AIMS
thread on the multi-hop example: Wes Jackson, Blake Morrison and Sankalp
Gilda settled on at-or-past, and Kieran Sweeney asked that the
23 October inclusive wording and vectors move to it.

The 23 October package in `../ea1a149` and Girish Konda's replay are
left unchanged as the record for the inclusive rule.

## Rule tested

- State whose age equals S is stale.
- A permit is not usable at or after its expiry.
- Issuance requires a permit deadline later than the issuance time.
- S is applied at final issuance (after any awaited checks).

Same time contract as `../ea1a149`: T0 = 2026-10-23T04:00:00.000Z,
S = L = 300,000 ms, injected integer-millisecond clock, epsilon 1 ms,
zero skew and grace.

## What was run

- MBA `mcguinness/mission-bound-authorization@ea1a1490716f045d9fda42d73b1a7b891dea5fb9`.
- `results/inclusive-replay/`: the unchanged 23 October test via
  `../ea1a149/run-boundaries.sh`; 21/21, matching the earlier results.
- `results/exclusive-run/`: `w7-time-boundaries-exclusive.test.ts`, the
  same harness plus one instant (B4, issue at S-1 ms, admission at
  S+L-2 ms). Its assertions still describe what MBA does; 22/22.
- `expected-results-exclusive.json`: what the at-or-past rule expects for
  the same 22 instants (expectations, not run evidence).
- `compare.py`: compares observed outcomes with those expectations.
  Output in `results/comparison-exclusive.txt`.

## Result: 15 agree, 7 differ

MBA at this pin applies inclusive limits (age <= S; use while
now <= valid_until), so it differs from the at-or-past rule exactly at
equality:

- B1-issue-0: issuance at age exactly S — rule refuses, MBA issues.
- B3-use-0: use at exactly valid_until — rule refuses, MBA admits.
- B4 issue S-1 ms, admission at S+L-1 ms (the permit's own expiry) —
  rule refuses, MBA admits. At S+L-2 ms both admit.
- B4 issue at S (three cases) — rule refuses at issuance; MBA issues and
  admits through S+L, then refuses with permit_expired.
- B7-age-check-to-issuance-gap — rule refuses (source age S+1 ms at final
  issuance); MBA issues. This is the question already open as
  mission-bound-authorization issue #1564; the boundary convention does
  not change it.

B2 agrees at equality: without an explicit state expiry, MBA's fallback
deadline already refuses issuance at age S.

Under the rule, every admission on pre-revocation state happens strictly
before S+L from the original as-of; at 1 ms resolution the last admission
is at S+L-2 ms for a permit issued at S-1 ms.

## Limits

- Component execution with test adapters, as in `../ea1a149`; not a
  distributed deployment, no clock-error or processing-delay budget.
- The differences are differences from a convention, not defects: MBA
  documents its own inclusive comparisons.
- Current MBA main (e456a5fb, 10 Nov) was attempted; the harness is not
  compatible with it (0/22 for harness reasons). Not adapted here.

## Replay

As in `../ea1a149` (Node 24, frozen lockfile). Copy
`w7-time-boundaries-exclusive.test.ts` into
`src/packages/mission-signals/test/` of a clean MBA checkout at the pin,
run it with `W7_BOUNDARY_RESULT_DIRECTORY=<dir> pnpm exec vitest run
packages/mission-signals/test/w7-time-boundaries-exclusive.test.ts`, then
`python3 compare.py expected-results-exclusive.json <dir>/boundary-traces.json`.
