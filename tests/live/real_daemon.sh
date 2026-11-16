#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/aegis-tui-live.XXXXXX")
fixture="$root/target/debug/examples/real_daemon_fixture"
client="$root/target/debug/aegis-tui"
pid=

cleanup() {
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT HUP INT TERM

cargo build --manifest-path "$root/Cargo.toml" --package aegis-tui-cli \
  --bin aegis-tui --example real_daemon_fixture --locked --offline

start_fixture() {
  name=$1
  rm -rf "$tmp/$name-authority"
  rm -f "$tmp/$name.sock"
  "$fixture" "$tmp/$name-authority" "$tmp/$name.sock" >"$tmp/$name.log" 2>&1 &
  pid=$!
  attempt=0
  while [ ! -S "$tmp/$name.sock" ]; do
    if ! kill -0 "$pid" 2>/dev/null || [ "$attempt" -eq 100 ]; then
      sed -n '1,160p' "$tmp/$name.log" >&2
      echo 'FAIL: Aegis fixture did not become ready' >&2
      exit 1
    fi
    attempt=$((attempt + 1))
    sleep 0.025
  done
}

finish_fixture() {
  wait "$pid"
  pid=
}

start_fixture headless
snapshot=$("$client" headless "$tmp/headless.sock")
finish_fixture
printf '%s' "$snapshot" | python3 -c '
import json, sys
value = json.load(sys.stdin)
assert value["complete"] and value["capability"] == "authority.observe.v1"
assert value["epoch"] == 0 and value["active_grants"] == 6
assert value["retained_decisions"] == 6
assert value["page_grants"] == 4 and value["more_grants"]
assert value["page_decisions"] == 4 and value["more_decisions"]
'

start_fixture wrong-confirmation
if refusal=$("$client" revoke-epoch "$tmp/wrong-confirmation.sock" 0 'revoke aegis epoch 0' 2>"$tmp/wrong-confirmation.err"); then
  echo 'FAIL: inexact revocation confirmation was accepted' >&2
  exit 1
fi
finish_fixture
printf '%s' "$refusal" | python3 -c '
import json, sys
value = json.load(sys.stdin)
assert not value["complete"] and value["status"] == "confirmation_refused"
assert value["required_confirmation"] == "REVOKE AEGIS EPOCH 0"
'

start_fixture stale-epoch
if refusal=$("$client" revoke-epoch "$tmp/stale-epoch.sock" 1 'REVOKE AEGIS EPOCH 1' 2>"$tmp/stale-epoch.err"); then
  echo 'FAIL: stale revocation epoch was accepted' >&2
  exit 1
fi
finish_fixture
printf '%s' "$refusal" | python3 -c '
import json, sys
value = json.load(sys.stdin)
assert not value["complete"] and value["status"] == "stale_epoch"
'

resource=abababababababababababababababab
confirmation="AUTHORIZE AEGIS EPOCH 0 hermes $resource observe UNTIL 20"
start_fixture authority-journey
authorized=$("$client" attenuate-authorize-once "$tmp/authority-journey.sock" \
  0 10 30 20 hermes "$resource" observe "$confirmation")
finish_fixture
printf '%s' "$authorized" | python3 -c '
import json, sys
value = json.load(sys.stdin)
assert value["complete"] and value["status"] == "authorized"
assert value["capability"] == "authority.attenuate-authorize-once.v1"
assert value["epoch"] == 0 and value["expires_at"] == 20
assert value["engine"] == "hermes" and value["action"] == "observe"
assert "grant" not in value and "resource" not in value and "session" not in value
'

start_fixture revoke
revoked=$("$client" revoke-epoch "$tmp/revoke.sock" 0 'REVOKE AEGIS EPOCH 0')
finish_fixture
printf '%s' "$revoked" | python3 -c '
import json, sys
value = json.load(sys.stdin)
assert value["complete"] and value["status"] == "accepted"
assert value["capability"] == "authority.revoke-epoch.v1"
assert value["expected_epoch"] == 0 and value["epoch"] == 1
'

start_fixture interactive
python3 - "$tmp" "$client" <<'PYTHON'
from pathlib import Path
import shlex
import subprocess
import sys
import time

scratch, binary = sys.argv[1:]
tmux_socket = str(Path(scratch) / "tmux.sock")
command = shlex.join([binary, "interactive", str(Path(scratch) / "interactive.sock")])

def tmux(*args, check=True):
    return subprocess.run(
        ["tmux", "-S", tmux_socket, "-f", "/dev/null", *args],
        capture_output=True, text=True, check=check, timeout=5,
    )

def expect(*markers):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        screen = tmux("capture-pane", "-p", "-t", "aegis").stdout
        if all(marker in screen for marker in markers):
            return
        time.sleep(0.025)
    raise AssertionError(f"Missing {markers!r} in:\n{screen}")

try:
    tmux("new-session", "-d", "-x", "120", "-y", "28", "-s", "aegis", command)
    expect("page: 1", "active grants: 6", "grant #0", "grant #3", "decision #3")
    tmux("send-keys", "-t", "aegis", "n")
    expect("page: 2", "grant #4", "grant #5", "decision #4", "decision #5")
    tmux("send-keys", "-t", "aegis", "p")
    expect("page: 1", "grant #0", "decision #0")
    tmux("send-keys", "-t", "aegis", "q")
    deadline = time.monotonic() + 5
    while tmux("has-session", "-t", "aegis", check=False).returncode == 0:
        if time.monotonic() >= deadline:
            raise AssertionError("Aegis TUI did not exit")
        time.sleep(0.025)
finally:
    tmux("kill-server", check=False)
PYTHON
finish_fixture

echo 'PASS: real Aegis daemon -> bounded pages, private-handle authority journey, and exact-confirmed epoch revocation'
