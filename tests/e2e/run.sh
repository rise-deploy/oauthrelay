#!/usr/bin/env bash
set -euo pipefail

compose=(docker compose --project-name oauthrelay-e2e --file tests/e2e/compose.yaml)

cleanup() {
  "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

cleanup
"${compose[@]}" up --detach

status=0
env RUSTC_WRAPPER= cargo test -p oauthrelay --test dex_e2e -- --ignored --nocapture || status=$?
if (( status != 0 )); then
  "${compose[@]}" logs --no-color >&2 || true
fi
exit "$status"
