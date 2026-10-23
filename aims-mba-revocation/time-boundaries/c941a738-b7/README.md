# B7 rerun on MBA c941a738

23 October 2026. Addendum to the W7 exact-boundary extension. The original 21-case result at `ea1a1490716f045d9fda42d73b1a7b891dea5fb9` remains a separate result.

**Actual execution at `c941a738f11ea66ace2af4be5932477b21b4fce1`: 2 B7 cases passed; 19 other extension cases were not selected.** The explicit-expiry case still issues a permit after the initial state-age limit has been crossed during evaluation. Passing here means that the assertions describing this behavior passed; it does not mean an S-at-issuance guarantee passed.

| Selected case | Evaluation starts | Completion | Observed result |
|---|---|---|---|
| Observation-only control | Original state age 299,999 ms | Age 300,001 ms | `stale_state`; no permit; local read refused |
| Explicit future expiry | Original state age 299,999 ms | Age 300,001 ms | Permit; `valid_until = T0 + 600,001 ms`; local read succeeds at age 300,001 ms |

Both start with the same original as-of `T0 = 2026-10-23T04:00:00.000Z`. The allowing FGA stub advances the injected clock by exactly 2 ms. S and L are each 300,000 ms. The explicit expiry is `2027-01-01T00:00:00Z`, copied from Mission expiry by the Girish-style test adapter. It is not evidence of a deployed status service's freshness commitment. The observation-only control keeps the same as-of and omits the explicit expiry; its final fallback deadline is T0+S.

The test clock uses integer epoch milliseconds, epsilon 1 ms, zero injected skew, zero configured future-observation skew tolerance, and zero age/expiry grace. Real clock precision and synchronization were not measured.

## What this establishes

This executes actual MBA components in one process: MissionKernel, signed lifecycle-event creation and verification, PDP, permit-deadline calculation, PEP, and the local payments read. FGA and Resource policy are named allowing test fixtures; token facts enter through the existing verified-token seam. There is no separately authored arithmetic model standing in for MBA.

The source check locates the age gate before awaited FGA work, followed by a later issuance clock and deadline calculation. The observed trace is consistent with the absence of a final state-age check on the explicit-expiry path. If S is intended to constrain state age at final issuance, that check or an explicitly bounded evaluation-delay allowance is needed. This is a question about the intended contract, not a demonstrated violation of a particular deployment.

The B7 rerun does not revoke a Mission, hold the permit until its deadline, test admission at that deadline, measure real FGA delay, or test distributed deployment behavior. The original B1-B6 equality, admission, revocation, and cache/source results were not rerun on this newer pin. No general S+L guarantee follows from these two passing characterization tests.

## Fixture compatibility

The unadapted old fixture failed before reaching FGA: PEP reported `pdp_unreachable`, and the injected clock did not advance. That failure is retained under `initial-incompatible/`; it is not a temporal result.

The current test has these changes relative to the original delivered extension:

1. Update the declared MBA target pin to `c941a738f11ea66ace2af4be5932477b21b4fce1`.
2. Bind upstream `RESOURCE_POLICY_PERMITS_ALL_FIXTURE` to the ephemeral decision point. This is the new required Resource-policy fixture; it holds that unrelated bound open and supplies no evidence about production Resource-policy evaluation.
3. Close the current receiver's SQLite resources during teardown.
4. Preserve traces for incomplete cases so early failures remain diagnosable.

No tracked MBA implementation file was changed. The artifact contains the full adapted extension for reproducibility, but this addendum validates only the selected B7 pair. `fixture-adaptation.patch` shows the complete difference.

## Reproduce

Use a clean MBA checkout at the exact current pin, with dependencies installed from its frozen lockfile and a working `better-sqlite3` native binding. Then run:

```sh
bash run-current-b7.sh /absolute/path/to/mba /absolute/path/to/new-results
```

The runner checks HEAD and tracked source, refuses to overwrite a different extension or existing results, and selects only `-t B7`. The recorded run used the equivalent direct Vitest command in `results/run-manifest.json`. The runner itself was syntax-checked.

Validation completed: both selected component tests; workspace TypeScript build; workspace lint; strict standalone typecheck of the extension; and Biome on the extension. The standalone check includes upstream `oidc-provider-internals.d.ts`, needed by this newer source tree. Without that upstream declaration input, an initial standalone invocation reported TS7016. The full current upstream suite was not run. See `results/` for logs, Vitest JSON, original-as-of traces, exact commands, versions, and hashes.

## Source anchors

- [MBA source pin](https://github.com/mcguinness/mission-bound-authorization/tree/c941a738f11ea66ace2af4be5932477b21b4fce1)
- [State-age gate, awaited FGA, and final deadline](https://github.com/mcguinness/mission-bound-authorization/blob/c941a738f11ea66ace2af4be5932477b21b4fce1/src/services/pdp/src/evaluate.ts): lines 1321-1335, 1895-1898, 2127, 2146-2168.
- [Deadline calculation](https://github.com/mcguinness/mission-bound-authorization/blob/c941a738f11ea66ace2af4be5932477b21b4fce1/src/services/pdp/src/permit-deadline.ts): explicit expiry replaces the fallback observation deadline, lines 112-119.
- [Named Resource-policy fixtures](https://github.com/mcguinness/mission-bound-authorization/blob/c941a738f11ea66ace2af4be5932477b21b4fce1/src/services/pdp/src/test-support.ts)

This addendum is a component-test handoff for review.

## Publication replay

The selected cases were rerun without changing the test bytes. `results/` contains that fresh replay. Earlier workspace checks and their logs are retained separately under `prior-checks/`. The full current upstream suite was not run.
