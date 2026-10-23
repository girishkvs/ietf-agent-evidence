# Exact time boundaries: additional W7 cases

Prepared 23 October 2026 for review by Girish Konda. This is a separate, runnable extension; it does not import or repeat the eight original W7 scenarios.

## Scope and pins

- MBA: [`mcguinness/mission-bound-authorization@ea1a1490716f045d9fda42d73b1a7b891dea5fb9`](https://github.com/mcguinness/mission-bound-authorization/tree/ea1a1490716f045d9fda42d73b1a7b891dea5fb9).
- Girish fixture basis: [`girishkvs/ietf-agent-evidence@aaa3c27a88eebffda1974e9106e3d2eae7218d3e`](https://github.com/girishkvs/ietf-agent-evidence/blob/aaa3c27a88eebffda1974e9106e3d2eae7218d3e/aims-mba-revocation/w7-cases.test.ts). The main branch still contained eight W7 cases when retrieved for this work.
- Added file: `w7-time-boundaries.test.ts`. Copy it into MBA's `src/packages/mission-signals/test/`.

The local run executes unmodified MBA MissionKernel, signed lifecycle SET generation and receiver verification, PDP evaluation, permitDeadline, Pep, and McpPaymentsServer against in-memory SQLite. FGA is an always-allow test stub. Access-token facts enter at the existing verified TokenFacts seam. This is actual execution of pinned MBA components, not execution of a separately authored arithmetic reference model. Direct permitDeadline calls in B2 are calls to the upstream helper itself.

The test supplies the receiver-cache loader, controlled clock, held PDP-response gate, and optional admission guard. The optional guard in B5/B6 is an extension adapter, not shipped MBA behavior: it reads either the receiver cache or the in-process kernel, calls the real PDP again, refuses on a negative decision, and discards any new positive permit while retaining the original permit and its deadline. It models a guard immediately before the held response reaches PEP admission with no clock advance during that guard. It does not implement or measure a production status-query protocol.

## Time contract

- Source as-of `T0 = 2026-10-23T04:00:00.000Z`; S = 300,000 ms; L = 300,000 ms for this read action.
- Time is a single injected clock expressed as integer epoch milliseconds. Epsilon is exactly 1 ms, not a floating-point delta or a timed sleep. All comparisons use fixed logical instants.
- Injected inter-component skew = 0 ms. The extension sets PDP `freshnessSkewToleranceSeconds: 0`; old-state and permit-expiry grace = 0 ms. Upstream's default 5-second future-observation tolerance is therefore not exercised. It is not an extra five seconds added to the old-state age limit.
- RFC 3339 state and permit timestamps retain milliseconds. Lifecycle token NumericDates are not a measurement of millisecond wall-clock accuracy. No hardware clock accuracy, network delay, synchronization error, or distributed scheduling tolerance is measured here.
- Every attempt has an isolated fixture. Successful attempts do not consume a permit later reused by another boundary test. The held clock stays fixed through both admission and the final local result-release check.
- Equality is stage-specific: the state-age gate accepts `age <= S`; issuance requires `valid_until > issuance_time`; permit use accepts `now <= valid_until`, subject to other conditions.

Production claims need a stated, enforced clock-error and processing-delay budget. These zero-skew logical tests do not supply that budget.

## Expected results

All rows below are expectations for this pin and these fixtures, not proposed universal AIMS requirements. `expected-results.json` gives every individual case. The separately recorded results are in `results/boundary-traces.json` and `results/vitest.json`.

| Cases | Condition | Just before | Exactly equal | Just after |
|---|---|---|---|---|
| B1 (3) | Issue at state age S; explicit source expiry is 2027-01-01 | Permit, full L | Permit, full L | `stale_state` |
| B2 (3) | Issue at state age S; no explicit source expiry, fallback deadline is T0+S | Permit with 1 ms left | No permit: `stale_state` from elapsed deadline | `stale_state` |
| B3 (3) | Admit held permit relative to its `valid_until` | Admit | Admit | `permit_expired`, no result |
| B4a (3) | Issue at T0+S-1 ms; admit relative to T0+S+L | Admit at own expiry | `permit_expired` | `permit_expired` |
| B4b (3) | Issue at T0+S; admit relative to T0+S+L | Admit | Admit at own expiry | `permit_expired` |

The B1/B2 difference is intentional. In the original Girish adapter, `mission_status_expires_at` is a distant explicit state valid-through. MBA uses it instead of the fallback T0+S cap. In B2, a synthetic observation-only `fresh` mode carries the same old source time and omits that expiry. It is not described as a new authoritative lookup. At equality, B1 isolates age-gate acceptance while B2 and the direct helper call establish the later deadline refusal. The common `stale_state` string alone would not distinguish these stages.

In B4 the authoritative source revokes at T0+1 ms and the event is withheld from the receiver. The source is terminated, the cached view remains active, and `freshness_at` remains T0. The tested combined boundary is T0+S+L, not time-of-reread+S+L. It is 599,999 ms after that revocation, so S+L from revocation remains a conservative upper envelope under the issuance premise. No notification-delivery bound is inferred.

| Cases | Additional distinguishing condition | Expected result |
|---|---|---|
| B5-cache | Permit issued at T0+100 s; source revoked at T0+125 s; cached state re-evaluated at T0+150 s | Active cache still within S; admit using the old permit |
| B5-source | Same timing, but read the current in-process authoritative kernel | Terminated source; `mission_inactive` |
| B6-read-only | Issue at S-1 ms, then reread unchanged cache at S+1 ms while old permit remains unexpired | Admit; reread alone adds no age enforcement |
| B6-revalidate | Same timing, but re-evaluate cached state with its original T0 | Refuse `stale_state`; this is not a negative revocation result |
| B7-explicit-expiry | Start evaluation at S-1 ms; FGA stub advances clock by 2 ms after the age gate | Permit completes at S+1 ms; deadline T0+S+L+1 ms |
| B7-observation-only | Same 2 ms crossing, without explicit source expiry | Final deadline calculation refuses `stale_state` |

## Material result: the issuance premise needs its own check

B7 characterizes a relevant interval in the pinned implementation. The age check precedes an awaited FGA call, and the final deadline is calculated afterwards. With the explicit future state expiry, that later calculation does not reapply the T0+S age cap. The test therefore observes a positive permit at source age S+1 ms, although the earlier age check ran at S-1 ms. This is a controlled logical schedule, not a measured production delay.

Consequently, the static B4 successes do not establish that MBA always enforces S at final issuance, and do not by themselves establish a deployment-wide S+L bound. The generic derivation requires `t_issue <= t_asof + S` and `t_admit <= t_issue + L`. An implementation can enforce the first premise at final issuance, or account explicitly for a bounded evaluation interval in its claimed bound. Rechecking only at the beginning of an arbitrarily long evaluation is insufficient for that premise. No production code is modified here; B7's PASS records the observed behavior, not approval of it.

For an admission-time S bound, the guard must apply the original source-time limit to the actual admission decision and handle current negative or unavailable status appropriately. Reading the same cache does not reset the source time. A cache age check can enforce an S limit while still returning old positive state within S; an authoritative lookup can discover revocation earlier. The extra S-only premise is not proved for a deployed system by B5/B6.

## Proposed minimal AIMS example wording

> This example uses inclusive limits: state age may equal S, and an outstanding permit may be used at, but not after, its expiry, provided all other validity conditions hold. Issuance requires a permit deadline later than the issuance time.

Two small supporting clarifications, if the surrounding paragraph needs them:

> S is enforced at permit issuance, including after any awaited checks. L is the maximum lifetime of a permit whose authorization status is not revalidated at use.

> An admission-time state-age check preserves the original as-of time; rereading a cache does not reset it.

This is proposed text for the example. It is not a statement that AIMS currently mandates these inclusive conventions, nor a guarantee that a permit survives applicable revocation rules. The bound concerns admission of new actions, not completion or cancellation of already-admitted work.

## Replay

Use a disposable checkout and Node 24 or newer. This local run used Node 24.19.0, pnpm 11.25.0, Vitest 4.1.10, and Linux x64. The pinned workspace declares pnpm 11.15.1; the available runner used 11.25.0 with the frozen upstream lockfile. See `results/run-manifest.json` for hashes and checks.

```sh
git clone https://github.com/mcguinness/mission-bound-authorization.git
cd mission-bound-authorization
git checkout --detach ea1a1490716f045d9fda42d73b1a7b891dea5fb9
cd src
corepack pnpm install --frozen-lockfile
cp /path/to/extension/w7-time-boundaries.test.ts packages/mission-signals/test/
mkdir -p boundary-results
W7_BOUNDARY_RESULT_DIRECTORY="$PWD/boundary-results" corepack pnpm exec vitest run packages/mission-signals/test/w7-time-boundaries.test.ts --reporter=verbose
```

Expected: **21 passed**. The output directory must exist. The extension writes `boundary-traces.json`; it does not overwrite the original `case-traces.json`. `run-boundaries.sh /absolute/path/to/mba /absolute/path/to/results` additionally checks Git HEAD and refuses to overwrite a different existing extension file. Dependencies must already be installed.

Locally, installation used `pnpm install --frozen-lockfile --ignore-scripts`, followed by the installed `prebuild-install` helper in the better-sqlite3 package to obtain its upstream Linux x64 Node ABI 137 binary. No MBA source changes or dependency-version substitutions were needed.

## Local verification and evidence boundary

- Extension: 21/21 cases passed against the pinned MBA components; 0 skipped. The test-run JSON and ordered component traces are included.
- Upstream baseline, before adding the extension: 2703 passed, 152 skipped; 175 test files passed and 14 skipped. Those skipped cases remain untested in this environment. This is ancillary baseline evidence, not 2703 new boundary tests.
- Workspace typecheck and lint passed before adding the extension. The extension is also checked separately because the normal workspace tsconfig excludes test files; the separate check uses strict TypeScript options and ES2024 library declarations for `Promise.withResolvers` on Node 24.

Not established: distributed deployment behavior, AIMS conformance or interoperability, network signal delivery, clock synchronization, real OpenFGA or OAuth/DPoP execution, cancellation, external effects, or production revocation latency. The result released by the successful read path is the local fixture invoice. The MBA pin's behavior and the proposed example convention are kept separate.

## Pinned source locations

- [State-age check and accepted source time, evaluate.ts lines 924-965](https://github.com/mcguinness/mission-bound-authorization/blob/ea1a1490716f045d9fda42d73b1a7b891dea5fb9/src/services/pdp/src/evaluate.ts#L924-L965).
- [Awaited FGA, evaluate.ts lines 1365-1368](https://github.com/mcguinness/mission-bound-authorization/blob/ea1a1490716f045d9fda42d73b1a7b891dea5fb9/src/services/pdp/src/evaluate.ts#L1365-L1368).
- [Permit lifetime and final issuance deadline, evaluate.ts lines 1513-1551](https://github.com/mcguinness/mission-bound-authorization/blob/ea1a1490716f045d9fda42d73b1a7b891dea5fb9/src/services/pdp/src/evaluate.ts#L1513-L1551).
- [Explicit expiry, fallback and elapsed-deadline rule, permit-deadline.ts lines 112-143](https://github.com/mcguinness/mission-bound-authorization/blob/ea1a1490716f045d9fda42d73b1a7b891dea5fb9/src/services/pdp/src/permit-deadline.ts#L112-L143).
- [Permit-use table, pep.ts lines 424-464](https://github.com/mcguinness/mission-bound-authorization/blob/ea1a1490716f045d9fda42d73b1a7b891dea5fb9/src/services/mcp-payments/src/pep.ts#L424-L464).
- [Read-path admission and final release checks, server.ts lines 1093-1125](https://github.com/mcguinness/mission-bound-authorization/blob/ea1a1490716f045d9fda42d73b1a7b891dea5fb9/src/services/mcp-payments/src/server.ts#L1093-L1125).

The fixture scaffolding retains Girish's BSD 3-Clause notice. Upstream MBA retains its own license. This package contains no Gmail message export or private correspondence attachments.

## Publication replay

The selected cases were rerun without changing the test bytes. `results/` contains that fresh replay. Earlier workspace checks and their logs are retained separately under `prior-checks/`. The full current upstream suite was not run.
