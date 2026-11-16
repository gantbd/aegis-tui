# Contributing

Keep the reusable component read-only and terminal-lifecycle-free. Authority
commands must remain in Aegis-owned guards, and local transport must remain in
the Aegis-owned client.

Run `make check` before submitting a change. Refresh the advisory attestation
whenever `Cargo.lock` changes.
