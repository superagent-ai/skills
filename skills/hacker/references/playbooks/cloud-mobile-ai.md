# Cloud, Mobile, And AI Playbook

Use for cloud security audits, mobile app assessments, and AI/ML system offensive review.

## Coverage

Maps these reference areas:

- `cloud-security`
- `mobile-pentest`
- `ai-security`
- `crypto-analysis`
- supply-chain and API references when relevant

## Cloud workflow

1. Confirm account, project, subscription, cluster, and tenant boundaries.
2. Prefer read-only evidence and IaC review.
3. Map identities, roles, trust policies, exposed services, storage, secrets, and deployment paths.
4. Validate privilege paths with approved test principals or local policy simulation.
5. Avoid listing or copying sensitive object contents unless explicitly allowed.

## Mobile workflow

1. Confirm app package, backend APIs, test account, and device/emulator boundary.
2. Review manifest, permissions, storage, network security, deep links, and backend trust boundaries.
3. Use dynamic instrumentation only on owned devices or approved labs.
4. Validate findings with redacted local evidence and API boundary checks.

## AI workflow

1. Define model, RAG, agent, tool, and data boundaries.
2. Map trust boundaries between user input, retrieval, tools, memory, and actions.
3. Design safe test cases for prompt injection, data exposure, authorization, and tool misuse.
4. Avoid extraction of real private data; use fixtures or canaries.

## Evidence bar

- exact cloud/mobile/AI boundary
- identity or role used
- data sensitivity class
- safe proof and negative control
- remediation mapped to owner

## Unsafe by default

- privilege changes in production
- use of discovered secrets against live services
- real user data access
- bypassing third-party systems outside scope
- model extraction or data extraction beyond approved canaries
