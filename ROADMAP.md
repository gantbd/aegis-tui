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

- [ ] Specify typed issue and attenuation inputs without accepting credentials
  or exporting grant material.
- [ ] Add exact confirmation and current-epoch preconditions for mutation.
- [ ] Preserve outcome-unknown failures without automatic retry.
- [ ] Qualify revocation, recovery fencing, non-amplification, and refusal laws
  before exposing any authority-bearing command.

