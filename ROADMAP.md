# Roadmap

## Qualified foundation

- [x] Reusable Ratatui component over Aegis's public read-only client.
- [x] Separate standalone interactive and headless CLI composition root.
- [x] Explicit `authority.observe.v1` capability manifest.
- [x] Bounded status, grant-summary, and decision-summary observation.
- [x] Forward/backward bounded page navigation with asymmetric exhaustion that
  never replays the final page as new evidence.
- [x] Real durable Aegis daemon qualification.
- [x] Workbench interactive and headless attach qualification against the real
  durable daemon through the same public client and reusable component.

## Guarded administration

- [x] Add a peer-owned epoch-revocation guard with an exact literal
  confirmation and current-epoch observation on the same authenticated
  connection.
- [x] Preserve post-send transport uncertainty without automatic retry and
  qualify confirmation refusal, stale-epoch refusal and success against the
  real durable daemon.
- [ ] Specify a long-lived authority-bearing session for issue and attenuation
  without accepting credentials or exporting grant material. One-shot commands
  are invalid because handles are session-local and lost replies cannot be
  reconciled to exact grants.
- [ ] Qualify issue/attenuation recovery, non-amplification and refusal laws
  before exposing either command.

