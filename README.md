# Aegis TUI

`aegis-tui` is the composable, read-only terminal presentation for Aegis. It
depends on Aegis's public `ReadOnlyClient`, owns no terminal lifecycle, and can
be embedded by Workbench or another host.
The small `aegis-tui-local-client` adapter implements that public port over the
selected Unix wire without importing Aegis's service or durability graph.

The separate `aegis-tui` executable supports interactive display, a bounded,
versioned headless `authority.observe.v1` observation, and one separately
guarded administrative command. `revoke-epoch` requires the exact observed
epoch and literal `REVOKE AEGIS EPOCH N` confirmation. It performs one attempt
and reports a post-send transport failure as `outcome_unknown`; it never retries.
The reusable Ratatui component remains read-only.

Issue and attenuation remain excluded. Their handles are session-local, so a
one-shot command would destroy the useful handle on disconnect, and a lost
reply cannot yet be reconciled to an exact grant. They need a long-lived,
authority-bearing session contract and operation identity before exposure.

Interactive mode pages through bounded redacted grant and decision summaries
with `n` and `p`. Handles remain service-local references, not credentials or
exported grant material. Headless mode emits only the first bounded page and
truthfully reports whether more entries exist.

```sh
cargo run -p aegis-tui-cli -- capabilities
cargo run -p aegis-tui-cli -- headless /path/to/aegis.sock
cargo run -p aegis-tui-cli -- revoke-epoch /path/to/aegis.sock 7 \
  'REVOKE AEGIS EPOCH 7'
./tests/live/real_daemon.sh
```

