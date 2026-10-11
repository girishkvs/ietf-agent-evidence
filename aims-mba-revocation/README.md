# AIMS multi-hop example: revocation, outstanding permits and receiver state

Component test cases run against the Mission-Bound Authorization (MBA) reference code at
[`mcguinness/mission-bound-authorization@ea1a149`](https://github.com/mcguinness/mission-bound-authorization/tree/ea1a1490716f045d9fda42d73b1a7b891dea5fb9),
for the WIMSE discussion of the multi-hop example in `draft-ietf-wimse-aims` (Section 11 and the
Hop 0 step).

The question they illustrate: when a revocation is received and applied, which work does it stop?
New decisions, permits that were already issued, and receivers that have not seen it yet are
three different things.

## What ran

MBA code, unmodified:

- `MissionKernel` approval and revocation, and its lifecycle commit hook
- `signLifecycleEvent` (signed lifecycle SET) and `MissionSignalReceiver.verifyAndApply`
- the PDP decision, and `Pep` / `McpPaymentsServer.callReadTool("get_invoice")` against an
  in-memory SQLite store

Added by this test file, and not shipped MBA behavior:

- A `loadView` adapter that reads Mission state only from the signal receiver's cache and keeps
  the event's `committed_at` as the observation time. Upstream's own
  [`signals.test.ts`](https://github.com/mcguinness/mission-bound-authorization/blob/ea1a1490716f045d9fda42d73b1a7b891dea5fb9/src/packages/mission-signals/test/signals.test.ts)
  uses the same receiver-cache pattern against the PDP; this file carries it through the PEP read
  path. The shipped demo instead reads the kernel synchronously
  ([`stack.ts` L789-L810](https://github.com/mcguinness/mission-bound-authorization/blob/ea1a1490716f045d9fda42d73b1a7b891dea5fb9/src/demo/src/stack.ts#L789-L810)),
  and Signals demo wiring is deferred upstream
  ([`mission-signals/src/index.ts` L1-L30](https://github.com/mcguinness/mission-bound-authorization/blob/ea1a1490716f045d9fda42d73b1a7b891dea5fb9/src/packages/mission-signals/src/index.ts#L1-L30)).
- A pause after the PDP has computed a permit and before that response reaches the PEP.
- Two receiver/PEP instances in one process, not separately deployed workers.
- An always-permit FGA stub, access-token facts supplied at the verified `TokenFacts` input, and
  a controlled clock. Signatures, issuer and audience checks on the lifecycle SETs are real, with
  ephemeral test keys.

## Cases and recorded results

| Case | Setup | Result |
|---|---|---|
| `C1-control` | Receiver applies a revocation before the next decision | Next call denied, `mission_inactive` |
| `C1-in-flight` | PDP computes a permit from active state; the response is held; the revocation is committed and applied at the receiver; the held response is released | The held read returns the invoice; the next call is denied, `mission_inactive` |
| `C1-expiry-control` | Same held permit; the clock moves 301 s past its validity before release | Refused, `permit_expired`; no invoice |
| `C2-workers` | Receivers A and B both cache active state; only A receives the revocation | A denies `mission_inactive` while B still returns the invoice. At +301 s B denies `stale_state` and keeps the original observation time. After B receives the event it denies `mission_inactive` |
| `C2-missing` | Receiver has never received state for the Mission | PEP refuses `unknown_mission`; no PDP request and no invented observation |
| `C2-issuer` | Same Mission id, different issuer | The local receiver refuses the event (`issuer`) and keeps its state; a separately configured receiver for that issuer accepts it. Cross-issuer only, not same-issuer tenant isolation |
| `C2-receipt` | A lifecycle SET is handed to a receiver with a non-matching verification key | Refused (`signature`), no state applied, while the emitter reports no pending delivery. Hand-off is not verified application |
| `C2-cache-key` | Vary the PDP decision cache-key inputs | Issuer, audience, actor/client and state version change the key; observation time alone does not |

In `C1-in-flight` the ordering comes from sequence numbers and awaited gates on a controlled clock.
It is not a measured delay.

## What this does and does not show

- The held read completing after revocation is consistent with MBA's documented bounded
  run-to-completion
  ([`initial-runtime-deployment.md` L168-L199](https://github.com/mcguinness/mission-bound-authorization/blob/ea1a1490716f045d9fda42d73b1a7b891dea5fb9/src/docs/initial-runtime-deployment.md#L168-L199)).
  It is not reported as a defect.
- The permit was held before PEP admission. Nothing here shows an external operation that had
  already started, its cancellation, or a rollback.
- Not shown: AIMS conformance or interoperability, OAuth or DPoP, deployed multi-worker behavior,
  network delivery of signals, or revocation latency.

## Replay

Verified on Windows x64 with Node 24.11.0 and pnpm 11.15.1 (through corepack).

```sh
git clone https://github.com/mcguinness/mission-bound-authorization.git
cd mission-bound-authorization
git checkout ea1a1490716f045d9fda42d73b1a7b891dea5fb9
cd src
corepack pnpm install --frozen-lockfile
cp <path-to-this-folder>/w7-cases.test.ts packages/mission-signals/test/
mkdir results
W7_RESULT_DIRECTORY="$PWD/results" corepack pnpm exec vitest run packages/mission-signals/test/w7-cases.test.ts
```

PowerShell: set `$env:W7_RESULT_DIRECTORY` to the `results` folder before the last command.

Expected: `8 passed`. `results/case-traces.json` then holds the outcome and ordered events for
each case. The test requires `W7_RESULT_DIRECTORY` and fails in `afterAll` without it.

Upstream's `pnpm-workspace.yaml` allows the `better-sqlite3` install script, so a normal install
fetches its prebuilt binary. The verified run used `--ignore-scripts` and placed that same upstream
prebuilt binary by hand (`better-sqlite3` v12.11.1, `node-v137-win32-x64`, SHA-256
`e75b8c024a85179d8e0e51203a8b8867916e9a51327ce3953db5f8483cc9a91e`).

## Files

| File | Contents |
|---|---|
| `w7-cases.test.ts` | The eight cases. SHA-256 `6547d081b2c548f6dbd450843dd01e84253eb1cf16602c82575c63c0440a9237`. `W7` is only an internal label. |
| `results/case-traces.json` | Recorded outcomes and ordered events from 10 October 2026 |
| `results/runs.json` | The recorded runs, environment and the 11 October fresh-clone replay |
