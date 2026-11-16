# Aegis TUI

Status: published through the qualified GitHub source channel at the exact
revision and CI run recorded in
[`release/github-source.json`](release/github-source.json).

`aegis-tui` is the composable, read-only terminal presentation for Aegis. It
depends on Aegis's public `ReadOnlyClient`, owns no terminal lifecycle, and can
be embedded by Workbench or another host.
Aegis's owner-maintained `aegis-local-client` implements that public port over
the selected Unix wire without importing Aegis's service or durability graph.
`aegis-tui-local-client` remains only as a source-compatibility facade.

The separate `aegis-tui` executable supports interactive display, a bounded,
versioned headless `authority.observe.v1` observation, and separately guarded
authority commands from Aegis-owned `aegis-admin-command`. `revoke-epoch` requires the exact observed
epoch and literal `REVOKE AEGIS EPOCH N` confirmation. It performs one attempt
and reports a post-send transport failure as `outcome_unknown`; it never retries.
The reusable Ratatui component remains read-only.

`attenuate-authorize-once` is a bounded same-connection journey rather than a
grant-management command. It observes the exact epoch, issues a parent grant,
attenuates it to one exact scope, authorizes once, and returns only redacted
decision facts. Parent and child handles never leave the guard and are destroyed
on disconnect. Every mutation is attempted at most once; a lost reply is
`outcome_unknown`. Reusable issue and attenuation remain excluded because their
handles are session-local and cannot survive a one-shot command.

`manage-session` is the standalone long-lived shell for Aegis's owner-supplied
`aegis.admin-session.v1` NDJSON application protocol. The CLI only selects the
socket and connects standard input/output; parsing, bounds, exact confirmation,
operation names, private handle retention, redacted responses and terminal
uncertainty fencing remain in Aegis. See Aegis's `docs/admin-session.md` for the
closed request/response schema.

Interactive mode pages through bounded redacted grant and decision summaries
with `n` and `p`. Handles remain service-local references, not credentials or
exported grant material. Headless mode emits only the first bounded page and
truthfully reports whether more entries exist.

```sh
cargo run -p aegis-tui-cli -- capabilities
cargo run -p aegis-tui-cli -- headless /path/to/aegis.sock
cargo run -p aegis-tui-cli -- revoke-epoch /path/to/aegis.sock 7 \
  'REVOKE AEGIS EPOCH 7'
cargo run -p aegis-tui-cli -- attenuate-authorize-once /path/to/aegis.sock \
  7 100 300 200 hermes 00112233445566778899aabbccddeeff observe \
  'AUTHORIZE AEGIS EPOCH 7 hermes 00112233445566778899aabbccddeeff observe UNTIL 200'
cargo run -p aegis-tui-cli -- manage-session /path/to/aegis.sock < commands.ndjson
./tests/live/real_daemon.sh
```

