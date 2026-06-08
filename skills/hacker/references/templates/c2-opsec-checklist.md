---
phase: c2
status: draft
gate: [c2_authorized, callbacks_bounded, teardown_defined]
depends_on: [scope-definition.md, cleanup-plan.md]
produces: []
---

# C2 And OPSEC Checklist

C2 planning is skipped unless explicitly authorized. Use simulation or tabletop review when live callbacks are not allowed.

## Authorization

- [ ] C2 simulation explicitly in scope
- [ ] Callback destinations owned or approved
- [ ] Network monitoring coordination documented
- [ ] Teardown plan approved

## Boundaries

| Boundary | Value |
|---|---|
| Allowed hosts | |
| Allowed protocols | |
| Testing window | |
| Data allowed in callbacks | |
| Forbidden destinations | |

## OPSEC Review

| Concern | Decision |
|---|---|
| Source infrastructure ownership | |
| Logging and audit trail | |
| Detection coordination | |
| Rate limits | |
| Kill switch | |

## Teardown

1. Stop callbacks.
2. Remove test infrastructure.
3. Verify no scheduled tasks, agents, credentials, or rules remain.
4. Archive approved logs.
5. Document residual risk.
