# Recon, Web, And API Playbook

Use for recon, OSINT, web app testing, API review, auth flows, business logic, and client-facing attack surface.

## Coverage

Maps these reference areas:

- `recon-osint`
- `web-pentest`
- `vulnerability-analysis`
- web/API vulnerability references

## Safe workflow

1. Confirm scope and program rules.
2. Build target inventory from supplied assets, public records, and approved passive sources.
3. Identify live web/API surfaces only when active probing is authorized.
4. Map trust boundaries: unauthenticated, user, tenant admin, org admin, service account.
5. Prioritize hypotheses by reachability, data sensitivity, and privilege boundary.
6. Validate with minimum proof and negative controls.

## Focus areas

- authentication and session management
- authorization, IDOR, BOLA, mass assignment
- injection classes
- SSRF and internal access boundaries
- file upload and path handling
- GraphQL and API batching
- request smuggling and cache behavior, planning-only unless explicitly scoped
- business logic and race conditions, rate-limited and non-destructive only

## Evidence bar

- exact endpoint or route
- request/response summary with secrets redacted
- actor role and tenant boundary
- expected vs actual authorization behavior
- impact without bulk data access
- negative control

## Unsafe by default

- credential brute force
- high-volume fuzzing
- DoS or resource exhaustion
- real data extraction
- testing third-party integrations outside scope
