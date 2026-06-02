# Safe Authorization Patterns

When a pass flags a missing check, the user wants the safe replacement, not just the diagnosis. This file is the cookbook: each entry pairs a common goal with the right way to accomplish it. The fixes are framework-shaped in `references/frameworks.md`; here is the reasoning behind each.

## "I want to fetch an object by id safely"

**Wrong:** look up by the client-supplied id, return it.
```python
invoice = Invoice.objects.get(id=request_id)
```

**Right:** make ownership part of the lookup, so a non-owned id is simply *not found*. The owner term comes from the session, never the request.
```python
invoice = Invoice.objects.get(id=request_id, org=request.user.org)
```

Why scope-in-the-query beats load-then-check: there's no window where the object exists in memory before the check, no second code path to forget, and the natural failure is a 404 — which also avoids leaking *existence* of other users' objects. Prefer it. Use an explicit post-load check only when the lookup can't carry the owner (e.g. the object is reached through a service that doesn't know the principal).

## "I want one place to make authorization decisions"

Scattering `if user.id == obj.owner_id` across handlers guarantees one will be forgotten — and forgotten checks are invisible in review. Centralize.

**Right:** a policy/ability layer that every handler calls.

- Rails: Pundit policies + `after_action :verify_authorized` so a forgotten `authorize` *raises*.
- Laravel: Policies + `$this->authorize(...)`.
- Spring: `@PreAuthorize` with method security enabled.
- Node/TS: CASL abilities, or a small `can(user, action, resource)` module.
- Cross-language at scale: a policy engine — OPA/Rego, AWS Cedar, OpenFGA, Oso — queried from one choke point.

The win isn't the engine; it's that authorization becomes a thing you *cannot silently omit*. Pair it with a default-deny (next entry) and a lint/test that fails when a handler skips the call.

## "I want to be safe by default"

A handler that's authorized because no rule matched is a latent breach. Default to deny; allow only on an explicit, matched grant.

**Wrong:** open routes, with auth bolted on per-endpoint (you will miss one). Or a policy engine whose default decision is `allow`.

**Right:**
- Require authentication globally, then carve out public routes by allowlist — not the reverse.
  - DRF: set `DEFAULT_PERMISSION_CLASSES = ['rest_framework.permissions.IsAuthenticated']`, opt specific views into `AllowAny`.
  - Spring: `.anyRequest().authenticated()` as the final matcher, public paths listed above it.
- Make the policy layer return deny when no rule matches, and treat "no policy for this action" as a failure in tests, not a pass.

Authentication-by-default is the floor. It is **not** object-level authorization — you still need per-object ownership on top. But default-deny ensures a forgotten endpoint fails closed.

## "I want to know which user is making the request"

**Wrong:** trust the client.
```javascript
const userId = req.query.userId || req.body.userId || req.headers["x-user-id"];
```
Any of these lets the caller *be* anyone.

**Right:** derive identity server-side, from the session or a fully verified token, and use only that for scoping and decisions.
```javascript
const userId = req.user.id;   // set by auth middleware from a verified session/JWT
```

If you use JWTs, "verified" means signature **and** `iss`, **and** `aud`, **and** `exp` — and an algorithm allowlist that rejects `none` and refuses to treat an `RS256` public key as an `HS256` secret. A decoded-but-unverified claim is client input.

## "I want to isolate tenants in a shared database"

Row-level multi-tenancy (one table, a `tenant_id` column) is correct only if **every** query carries the tenant filter. One forgotten `WHERE tenant_id = ?` leaks across customers — the highest-blast-radius BOLA there is.

**Right, in order of robustness:**

1. **Push the filter below the handlers** so it can't be forgotten per-query:
   - A base queryset/repository that always applies the current tenant (Django manager, Rails `default_scope` used carefully, a scoped repository).
   - Postgres Row-Level Security: a policy `USING (tenant_id = current_setting('app.tenant_id'))`, with the tenant set per request/connection. The database enforces isolation even if a query forgets.
2. **Derive the tenant from the principal, never from the request.** `request.user.tenant_id`, not `?tenant=` or `X-Tenant`.
3. **Test cross-tenant denial explicitly** (see the last entry).

Schema-per-tenant or database-per-tenant moves the boundary lower and is harder to get wrong, at the cost of operational complexity.

## "I want to update only the fields the user should control"

**Wrong:** bind the whole body to the model.
```ruby
@user.update!(params[:user])          # client can send role: "admin"
```

**Right:** allowlist the writable fields; never let the client name a field.
```ruby
def user_params
  params.require(:user).permit(:name, :email)   # role, *_id, balance NOT permitted
end
@user.update!(user_params)
```

Equivalents: DRF serializers with explicit `fields` (and `read_only_fields` for `role`/owner columns); a typed DTO/Pydantic input model distinct from the persistence model; Laravel `$fillable` excluding privilege and `*_id` columns. The rule: the set of client-writable fields is declared in code, not inferred from the request.

## "I want list and search endpoints to be safe"

A collection endpoint has no id to swap, so it's easy to forget — and an unscoped list leaks the entire table at once.

**Wrong:** `Invoice.objects.all()` / `SELECT * FROM invoices`.

**Right:** scope the collection to the principal's tenant *before* pagination and filtering, and apply the same scope to count/aggregate/export variants.
```python
def get_queryset(self):
    return Invoice.objects.filter(org=self.request.user.org)
```
Watch the siblings: search, export-to-CSV, `/count`, and report endpoints often re-implement the query and miss the scope.

## "I want safe nested resources"

`/orgs/{orgId}/projects/{projectId}/tasks/{taskId}` — verify the **whole chain**, not just the leaf. A bug that checks the user owns the task but trusts `orgId` from the path lets an attacker mix and match.

**Right:** resolve each level scoped to the previous, ending at the principal.
```ruby
org     = current_user.organizations.find(params[:org_id])
project = org.projects.find(params[:project_id])
task    = project.tasks.find(params[:task_id])
```
Each `find` 404s if the parent→child link is broken, so a forged path component fails closed.

## "I want admin / privileged endpoints"

Authentication is not enough; assert the role or permission server-side, on the API, every time.

**Wrong:** rely on the admin UI hiding the button, or on the route being undocumented.

**Right:** a function-level guard at the endpoint — `@Roles('admin')` + a registered guard, `hasRole('ADMIN')`, `authorize :manage, :admin_panel`, `if not user.is_admin: 403`. Keep these checks coarse and central; combine with object-level checks where an admin still shouldn't cross tenants.

## "I want to keep authorization correct as the code changes"

Manual review catches today's gap; tests catch tomorrow's regression. Add authorization tests that encode the negative case:

- For each object-by-id endpoint: a test where **user B requests user A's object** and asserts `403`/`404`.
- For each privileged action: a test where a **normal user** is denied.
- For multi-tenant apps: a **cross-tenant** test per resource.
- In CI: fail the build when a new route is added without a corresponding deny test (a lightweight convention or a lint on the policy layer's coverage).

These tests are also the cheapest way to *prove* a fix: write the failing cross-user test first, apply the scope, watch it pass.
