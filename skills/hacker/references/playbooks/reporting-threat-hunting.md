# Reporting And Threat Hunting Playbook

Use during report generation, detection mapping, purple-team handoff, incident-response aligned deliverables, and remediation planning.

## Coverage

Maps these reference areas:

- `threat-hunting`
- `incident-response`
- report templates
- MITRE ATT&CK mapping
- finding quality review

## Safe workflow

1. Separate confirmed findings from leads and unsafe-to-test items.
2. Map each finding to affected assets, actors, impact, and remediation owner.
3. Include detection opportunities only when supported by evidence.
4. Redact secrets, PII, tokens, customer data, and sensitive infrastructure details.
5. Provide validation steps for fixes.

## Finding quality checklist

- severity uses P0-P3 or Informational
- impact is specific and scoped
- evidence is redacted and reproducible
- false-positive reasoning is captured
- remediation is concrete
- verification is testable

## Threat-hunting handoff

For each confirmed or likely issue, include:

- relevant ATT&CK tactic or technique when applicable
- logs or telemetry to review
- indicators from the engagement
- expected benign vs suspicious patterns
- gaps in monitoring

## Unsafe by default

- publishing sensitive evidence
- overstating unconfirmed impact
- including raw credentials or personal data
- hiding skipped tests or limitations
