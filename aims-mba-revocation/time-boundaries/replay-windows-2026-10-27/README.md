# Windows replay of the exact-boundary cases

Girish Konda replayed Mikhail Sergeev's exact-boundary extension on 27 October 2026 on Windows x64, with
Node 24.22.1, pnpm 11.15.1 (the version the MBA workspace pins), Vitest 4.1.10 and `TZ=UTC`. Each MBA commit
ran in a clean worktree installed from its frozen upstream lockfile with `--ignore-scripts`; better-sqlite3
12.11.1 used its upstream prebuilt binary for Node ABI 137, win32-x64 (SHA-256 `e75b8c02...`, recorded in
`run-manifest.json`). MBA source was not changed.

| MBA commit | Test file | Cases | Result |
|---|---|---|---|
| `ea1a149` | `../ea1a149/w7-time-boundaries.test.ts`, unchanged | All 21 | 21 passed |
| `ea1a149` | `../../w7-cases.test.ts`, the original eight W7 cases | 8 | 8 passed |
| `c941a738` | `../c941a738-b7/w7-time-boundaries.test.ts`, unchanged, `-t B7` | B7 pair | 2 passed, 19 not selected |
| `ef8568a` (main on 26 Oct) | The `c941a738` file with only `MBA_COMMIT` changed | All 21 | 21 passed |

`python compare.py` checks every case against `expected-results.json` (outcome, refusal reason, state age and
permit deadline) and, where Mikhail recorded traces, compares the full trace. All cases match. The traces equal
his except for values that differ on every run: the Mission id, evidence id, policy-view digest and signed
evidence value.

## What the runs show

- **Combined case.** A permit issued at state age S has `valid_until` T0+S+L (600,000 ms after the original
  as-of). It is admitted at that instant and refused with `permit_expired` 1 ms later. Issued at S-1 ms, it
  expires 1 ms earlier.
- **Issuance after S.** At all three commits, an awaited FGA step that crosses S after the age check still
  returns a permit at state age S+1 ms with `valid_until` T0+S+L+1 ms when the adapter supplies an explicit
  future state expiry; the observation-only control refuses with `stale_state`. S is not applied again at
  final issuance in these commits, which is the question in
  [mission-bound-authorization#1564](https://github.com/mcguinness/mission-bound-authorization/issues/1564).

The evidence boundary is the same as the extension's: component runs with stubs on one machine, not deployment,
interoperability or conformance tests.

## Files

- `ea1a149/`, `c941a738-b7/`, `main-ef8568a/`: `boundary-traces.json` and `vitest.json` from each run (the local
  work folder is replaced with `<mba>`).
- `ea1a149-original-w7/case-traces.json`: the original eight cases.
- `run-manifest.json`: commits, file hashes and tool versions.
- `compare.py`: the comparison above.

## Replay (PowerShell)

```powershell
git clone https://github.com/mcguinness/mission-bound-authorization.git mba
git -C mba checkout --detach ea1a1490716f045d9fda42d73b1a7b891dea5fb9
cd mba\src
pnpm install --frozen-lockfile --ignore-scripts
# place the better-sqlite3 prebuilt binary in node_modules\.pnpm\better-sqlite3@12.11.1\node_modules\better-sqlite3\build\Release
copy <this repo>\aims-mba-revocation\time-boundaries\ea1a149\w7-time-boundaries.test.ts packages\mission-signals\test\
$env:W7_BOUNDARY_RESULT_DIRECTORY = "<an empty results folder>"; $env:TZ = "UTC"
pnpm exec vitest run packages/mission-signals/test/w7-time-boundaries.test.ts --reporter=verbose
```
