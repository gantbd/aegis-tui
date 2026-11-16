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

- [x] Reuse the Aegis-owned epoch-revocation guard with an exact literal
  confirmation and current-epoch observation on the same authenticated
  connection.
- [x] Preserve post-send transport uncertainty without automatic retry and
  qualify confirmation refusal, stale-epoch refusal and success against the
  real durable daemon.
- [x] Add an exact-confirmed, same-connection issue → attenuation → one-time
  authorization journey. It exports only redacted decision facts, never grant
  handles, and preserves per-phase transport uncertainty without retry.
- [x] Move the non-presentation command guard into Aegis ownership; this
  repository retains only the reusable read-only component, local client and
  standalone shell that invokes the owner guard.
- [x] Expose Aegis's bounded long-lived `aegis.admin-session.v1` application
  protocol as a thin standalone `manage-session` shell. The shell selects the
  socket and standard streams only; Aegis owns parsing, operation identity,
  private handles, exact confirmation and terminal fencing.
- [x] Qualify named issue, attenuation, authorization, listing and clean close
  through the standalone shell against a real daemon without handle export.
- [ ] Qualify explicit disconnect/reconnect abandonment and deliberate rebuild
  under new operation names. Durable grant replay and lost-reply reconciliation
  remain nonclaims.

