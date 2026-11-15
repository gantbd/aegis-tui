#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/aegis-tui-live.XXXXXX")
pid=
cleanup() { if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi; rm -rf "$tmp"; }
trap cleanup EXIT INT TERM
cargo run --quiet --manifest-path "$root/Cargo.toml" -p aegis-tui-cli --example real_daemon_fixture -- "$tmp/authority" "$tmp/aegis.sock" >"$tmp/out" 2>"$tmp/err" &
pid=$!
i=0
while [ ! -S "$tmp/aegis.sock" ]; do i=$((i+1)); if [ "$i" -ge 100 ]; then cat "$tmp/err" >&2; exit 1; fi; sleep 0.05; done
output=$(cargo run --quiet --manifest-path "$root/Cargo.toml" -p aegis-tui-cli -- headless "$tmp/aegis.sock")
wait "$pid"; pid=
printf '%s\n' "$output" | grep '"complete": true' >/dev/null
printf '%s\n' "$output" | grep '"capability": "authority.observe.v1"' >/dev/null
printf '%s\n' "$output" | grep '"epoch": 0' >/dev/null

