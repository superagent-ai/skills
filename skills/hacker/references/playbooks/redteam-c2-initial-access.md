# Red Team, C2, And Initial Access Playbook

Use for full red-team planning, initial-access simulations, C2 tabletop design, OPSEC review, and objectives mapping.

## Coverage

Maps these reference areas:

- `red-team-ops`
- `advanced-redteam`
- `initial-access`
- `edr-evasion` only as defensive detection and lab-planning context
- `keylogger-arch` only as defensive architecture and risk analysis

## Safe workflow

1. Confirm the engagement explicitly authorizes red-team simulation.
2. Separate planning, tabletop simulation, lab validation, and live execution.
3. Require operator approval before any active delivery, callback, persistence, or objective step.
4. Prefer simulated payloads, canaries, and benign callbacks.
5. Prepare cleanup and emergency stop procedures before execution.

## Focus areas

- attack path design
- allowed initial access channels
- OPSEC constraints and detection coordination
- simulated C2 callback boundaries
- objective proof without real data access
- cleanup and after-action reporting

## Evidence bar

- written RoE for each active tactic
- benign proof artifacts
- timestamps and logs
- detection and response observations
- cleanup verification

## Unsafe by default

- phishing, pretexting, or social engineering
- stealth persistence
- unauthorized C2
- malware deployment
- credential theft
- keylogging or input capture
- evasion intended to bypass real defenses outside an approved lab
