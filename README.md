# Aegis TUI

`aegis-tui` is the composable, read-only terminal presentation for Aegis. It
depends on Aegis's public `ReadOnlyClient`, owns no terminal lifecycle, and can
be embedded by Workbench or another host.
The small `aegis-tui-local-client` adapter implements that public port over the
selected Unix wire without importing Aegis's service or durability graph.

The separate `aegis-tui` executable supports interactive display and a bounded,
versioned headless `authority.observe.v1` observation. Its first contract does
not issue, attenuate, authorize with, serialize, or revoke authority. Those
operations require separate authority-bearing CLI contracts and confirmation
laws before they can be added safely.

```sh
cargo run -p aegis-tui-cli -- capabilities
cargo run -p aegis-tui-cli -- headless /path/to/aegis.sock
./tests/live/real_daemon.sh
```

