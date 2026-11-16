# RustSec advisory attestation

Status: clean root-lockfile audit against a pinned current RustSec database;
not an SBOM, source review, provider assessment, or legal opinion.

audited-at-utc: 2026-11-16T22:50:00Z
cargo-audit-version: 0.23.0
advisory-database-commit: 02e2517f457a359fc6d3440ea4560c8ea188fee8
advisory-database-commit-date: 2026-11-15T10:59:21+01:00
advisory-count: 1509
lockfile-sha256: 6e302a09f8f732d1c1f95c4e77a8c9849dbf52f1279aa0611ce1fcab7634f8d4
dependency-count: 112
vulnerability-count: 0
warning-count: 0

Produced with `cargo audit 0.23.0 --no-fetch --deny warnings` against the exact
database commit above. No advisory is ignored. CI audits against the then-current
database. This evidence covers only the coordinated source lockfile.
