# Authorization Review Checklist

A flat checklist for PR review or a full audit. Walk it top to bottom. Anything that fails needs work before merge. "Principal" always means the server-derived identity (session or verified token), never a value from the request.

## Per endpoint / handler

### Object-level (BOLA / IDOR)

- [ ] Every object loaded by a client-supplied id is scoped to the principal — either the lookup carries the owner (`where id = ? AND owner_id = ?`) or an explicit ownership check follows the load
- [ ] The check uses the principal from the session/token, not an id from the body, query, path, or a header
- [ ] Non-owned ids return 404/403, not the object
- [ ] The same ownership check exists for **every verb** on the resource (GET, POST, PUT, PATCH, DELETE), not just reads
- [ ] Nested routes verify the full parent→child chain, not just the leaf object

### Function-level (BFLA / vertical)

- [ ] Privileged actions (admin, user/role management, billing, export, internal tools) assert a role/permission, not just authentication
- [ ] The role check runs server-side on the API, not only in the frontend
- [ ] No "hidden" endpoints relying on an undocumented path for protection

### Mass assignment (property-level)

- [ ] The handler does not bind a raw request body to a persistence model
- [ ] Client-writable fields are allowlisted (strong params, serializer `fields`, DTO); `role`, `is_admin`, `*_verified`, `owner_id`, `org_id`, `tenant_id`, `balance`, `price`, `status` are not client-settable

### Collections & special shapes

- [ ] List/search/count/export endpoints are scoped to the principal's tenant before filtering and pagination
- [ ] Batch/bulk endpoints check authorization on **every** element of the array, not the first
- [ ] GraphQL: the `node(id:)` resolver and every related-object field resolver enforce authorization (not just the HTTP middleware)

## Per resource / model

- [ ] The model has an explicit owner/tenant column (`user_id`, `org_id`, `tenant_id`), and it is documented which it is
- [ ] All access paths to the resource go through a scoped queryset/repository, or a centralized policy is called on every path
- [ ] For multi-tenant data: a single enforcement point (base manager, scoped repository, or Postgres RLS) applies the tenant filter so individual queries can't forget it
- [ ] The principal's tenant is derived from the principal, never from the request

## Per application

### Mechanism

- [ ] There is a centralized authorization layer (policies/abilities/`@PreAuthorize`/policy engine), not ad-hoc `if` checks scattered across handlers
- [ ] A "forgotten authorization" fails loudly — e.g. Pundit `verify_authorized`, method security enabled so `@PreAuthorize` isn't inert, a policy default of deny
- [ ] Default is deny: authentication required globally with public routes allowlisted (not the reverse); the policy engine's no-match decision is deny

### Identity

- [ ] Identity is established by auth middleware from a verified session or token before any handler runs
- [ ] JWTs (if used) are verified for signature, `iss`, `aud`, and `exp`, with an algorithm allowlist (no `none`, no RS256→HS256 confusion)
- [ ] Authentication and authorization are distinct in the code — being logged in is never treated as permission to touch a specific object

### Regression safety

- [ ] Negative authorization tests exist: user B denied user A's object (per object-by-id endpoint)
- [ ] Privileged-action tests exist: a normal user is denied
- [ ] Multi-tenant apps have an explicit cross-tenant denial test per resource
- [ ] New routes are not merged without a corresponding deny test (convention or CI check)

## What static review can't confirm — verify separately

- [ ] Runtime middleware ordering and wiring actually protect every route (a route registered above a guard bypasses it)
- [ ] The deployed configuration matches the reviewed code (framework defaults, env-specific permission settings)
- [ ] A dynamic BOLA test (two accounts, swap object ids) has been run against a running instance to confirm the static findings

## Triage priorities when scanning at scale

When you have many findings across a codebase, work in this order:

1. **Unscoped collection/list/export endpoints** — leak the whole table in one request. P0.
2. **Missing object-level check on writes/deletes** — `PUT`/`PATCH`/`DELETE` by id with no ownership scope. Data tampering and destruction. P0.
3. **Missing object-level check on sensitive reads** — PII, payment, messages, documents. P0.
4. **Scoping keyed on client-supplied identity** — `?user_id=` / `X-Tenant`. P0; trivially exploited.
5. **Function-level gaps** — admin/privileged actions behind authentication only. P0–P1 by sensitivity.
6. **Mass assignment of privilege/tenant fields** — P1.
7. **Cross-tenant exposure in multi-tenant queries missing the tenant filter** — P0 if reachable, but verify the enforcement isn't applied below (base manager/RLS) before flagging.
8. **Uneven verb coverage / fragile nested checks** — P2.
9. **Reliance on id secrecy, missing regression tests** — P3.

Don't file a P0–P2 finding without a fix proposal. A ticket without a fix rots; a diff that scopes the query gets merged. For each finding, name the object, its owner, and the principal — that triad is the proof the check is missing and the spec for the fix.
