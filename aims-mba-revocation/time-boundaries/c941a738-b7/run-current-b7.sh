#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo 'Usage: run-current-b7.sh /absolute/path/to/mba /absolute/path/to/results' >&2
  exit 64
fi
task_repo=$(cd -- "$1" && pwd)
task_output=$2
case "$task_output" in /*) ;; *) echo 'Results path must be absolute' >&2; exit 64 ;; esac
task_pin=c941a738f11ea66ace2af4be5932477b21b4fce1
task_head=$(git -C "$task_repo" rev-parse HEAD)
if [ "$task_head" != "$task_pin" ]; then
  echo "Wrong MBA HEAD: $task_head (expected $task_pin)" >&2
  exit 65
fi
if ! git -C "$task_repo" diff --quiet HEAD -- src; then
  echo 'Tracked MBA source differs from the pinned commit; use a clean checkout.' >&2
  exit 65
fi
task_bundle=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
task_test="$task_repo/src/packages/mission-signals/test/w7-time-boundaries.test.ts"
if [ -e "$task_test" ] && ! cmp -s "$task_bundle/w7-time-boundaries.test.ts" "$task_test"; then
  echo 'A different extension already exists at the target path; nothing overwritten.' >&2
  exit 65
fi
mkdir -p -- "$task_output"
if [ -e "$task_output/boundary-traces.json" ] || [ -e "$task_output/vitest.json" ]; then
  echo 'Results already exist; choose a new output directory.' >&2
  exit 65
fi
if [ ! -e "$task_test" ]; then cp -- "$task_bundle/w7-time-boundaries.test.ts" "$task_test"; fi
cd -- "$task_repo/src"
# Dependencies must already be installed from the frozen upstream lockfile.
# This executes local pinned components, not a distributed deployment.
W7_BOUNDARY_RESULT_DIRECTORY="$task_output" pnpm exec vitest run \
  packages/mission-signals/test/w7-time-boundaries.test.ts \
  -t B7 --reporter=verbose --reporter=json --outputFile="$task_output/vitest.json"
