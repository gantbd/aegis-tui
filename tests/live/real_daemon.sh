#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/aegis-tui-live.XXXXXX")
fixture="$root/target/debug/examples/real_daemon_fixture"
client="$root/target/debug/aegis-tui"
daemon="$root/../aegis/target/debug/aegis-daemon"
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
cargo build --manifest-path "$root/../aegis/Cargo.toml" --package aegis-daemon \
  --bin aegis-daemon --locked --offline

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

managed_resource=cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd
parent=11111111111111111111111111111111
child=22222222222222222222222222222222
start_fixture managed-session
managed=$(printf '%s\n' \
  "{\"version\":1,\"command\":\"issue\",\"operation\":\"$parent\",\"expected_epoch\":0,\"now\":10,\"expires_at\":40,\"scopes\":[{\"engine\":\"hermes\",\"resource\":\"$managed_resource\",\"actions\":[\"observe\",\"delegate\"]}],\"confirmation\":\"ISSUE AEGIS OP $parent EPOCH 0 UNTIL 40 SCOPES hermes:$managed_resource:observe+delegate\"}" \
  "{\"version\":1,\"command\":\"attenuate\",\"operation\":\"$child\",\"parent\":\"$parent\",\"expected_epoch\":0,\"now\":11,\"expires_at\":30,\"scopes\":[{\"engine\":\"hermes\",\"resource\":\"$managed_resource\",\"actions\":[\"observe\"]}],\"confirmation\":\"ATTENUATE AEGIS OP $child FROM $parent EPOCH 0 UNTIL 30 SCOPES hermes:$managed_resource:observe\"}" \
  "{\"version\":1,\"command\":\"authorize\",\"operation\":\"$child\",\"now\":12,\"engine\":\"hermes\",\"resource\":\"$managed_resource\",\"action\":\"observe\",\"confirmation\":\"AUTHORIZE AEGIS OP $child hermes $managed_resource observe\"}" \
  '{"version":1,"command":"list"}' \
  '{"version":1,"command":"close"}' | \
  "$client" manage-session "$tmp/managed-session.sock")
finish_fixture
printf '%s' "$managed" | python3 -c '
import json, sys
values = [json.loads(line) for line in sys.stdin if line.strip()]
assert [value["status"] for value in values] == [
    "issued", "attenuated", "authorized", "current", "closed"
]
assert values[3]["grants"][1]["parent"] == "11111111111111111111111111111111"
assert values[-1]["terminal"]
rendered = json.dumps(values)
assert "handle" not in rendered and "credential" not in rendered
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

reconnect_socket="$tmp/reconnect.sock"
reconnect_authority="$tmp/reconnect-authority"
authority_id=31313131313131313131313131313131
principal_id=32323232323232323232323232323232
session_namespace=3333333333333333
"$daemon" create "$reconnect_authority" "$reconnect_socket" "$authority_id" \
  "$(id -u)" "$(id -g)" "$principal_id" "$session_namespace" administrator \
  >"$tmp/reconnect.log" 2>&1 &
pid=$!
attempt=0
while [ ! -S "$reconnect_socket" ]; do
  if ! kill -0 "$pid" 2>/dev/null || [ "$attempt" -eq 100 ]; then
    sed -n '1,160p' "$tmp/reconnect.log" >&2
    echo 'FAIL: selected Aegis daemon did not become ready' >&2
    exit 1
  fi
  attempt=$((attempt + 1))
  sleep 0.025
done

abandoned=41414141414141414141414141414141
rebuilt=42424242424242424242424242424242
reconnect_resource=43434343434343434343434343434343
first=$(printf '%s\n' \
  "{\"version\":1,\"command\":\"issue\",\"operation\":\"$abandoned\",\"expected_epoch\":0,\"now\":10,\"expires_at\":40,\"scopes\":[{\"engine\":\"hermes\",\"resource\":\"$reconnect_resource\",\"actions\":[\"observe\"]}],\"confirmation\":\"ISSUE AEGIS OP $abandoned EPOCH 0 UNTIL 40 SCOPES hermes:$reconnect_resource:observe\"}" | \
  "$client" manage-session "$reconnect_socket")
printf '%s' "$first" | python3 -c '
import json, sys
value = json.load(sys.stdin)
assert value["status"] == "issued" and not value["terminal"]
'

second=$(printf '%s\n' \
  '{"version":1,"command":"list"}' \
  "{\"version\":1,\"command\":\"issue\",\"operation\":\"$rebuilt\",\"expected_epoch\":0,\"now\":11,\"expires_at\":50,\"scopes\":[{\"engine\":\"hermes\",\"resource\":\"$reconnect_resource\",\"actions\":[\"observe\"]}],\"confirmation\":\"ISSUE AEGIS OP $rebuilt EPOCH 0 UNTIL 50 SCOPES hermes:$reconnect_resource:observe\"}" \
  "{\"version\":1,\"command\":\"authorize\",\"operation\":\"$rebuilt\",\"now\":12,\"engine\":\"hermes\",\"resource\":\"$reconnect_resource\",\"action\":\"observe\",\"confirmation\":\"AUTHORIZE AEGIS OP $rebuilt hermes $reconnect_resource observe\"}" \
  '{"version":1,"command":"close"}' | \
  "$client" manage-session "$reconnect_socket")
printf '%s' "$second" | python3 -c '
import json, sys
values = [json.loads(line) for line in sys.stdin if line.strip()]
assert [value["status"] for value in values] == ["current", "issued", "authorized", "closed"]
assert values[0]["grants"] == []
assert values[1]["grant"]["operation"] == "42424242424242424242424242424242"
assert "41414141414141414141414141414141" not in json.dumps(values)
'
kill -TERM "$pid"
wait "$pid"
pid=
if [ -e "$reconnect_socket" ]; then
  echo 'FAIL: selected Aegis daemon left its owned socket behind' >&2
  exit 1
fi

echo 'PASS: real Aegis daemon -> bounded pages, managed private-handle session, authority journey, and epoch revocation'
