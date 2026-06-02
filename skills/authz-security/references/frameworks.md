# Authorization by Framework

To decide whether an object-level or function-level check is *missing*, you have to know what a *present* one looks like in the stack you're reading. This file is that reference: per framework, where the trustworthy principal comes from, what a correct owner-scoped lookup looks like, how centralized policies are expressed, and the shape of the bug to flag.

The recurring tells, in any language:

- A lookup keyed on a **client-supplied id alone** (`findById(params.id)`) with no owner term and no following check.
- A privileged action behind an **authentication** guard but no **role/permission** guard.
- The **principal taken from the request** (body/query/header) instead of the session or a verified token.

---

## Express (Node.js)

**Principal:** `req.user`, set by an auth middleware (Passport, a JWT verifier). Anything off `req.params`, `req.query`, `req.body`, or `req.headers` is attacker-controlled.

**Correct — owner-scoped query:**
```javascript
app.get("/api/orders/:id", requireAuth, async (req, res) => {
  const order = await Order.findOne({ where: { id: req.params.id, userId: req.user.id } });
  if (!order) return res.sendStatus(404);   // indistinguishable from "not yours"
  res.json(order);
});
```

**Correct — explicit check after load:**
```javascript
const order = await Order.findByPk(req.params.id);
if (!order || order.userId !== req.user.id) return res.sendStatus(404);
```

**Bug to flag:** `Order.findByPk(req.params.id)` returned directly; or `where: { userId: req.query.userId }` (client-supplied identity, Pass 5); or a role check missing on an admin route (only `requireAuth`, no `requireAdmin`).

> Note: an auth *middleware* proves authentication, not authorization. `requireAuth` on a route says nothing about object ownership — that check must live in the handler or a resource-specific guard.

---

## NestJS (Node.js)

**Principal:** `request.user`, via a `Guard` (e.g. `AuthGuard('jwt')`). NestJS splits the two concerns cleanly: `@UseGuards(JwtAuthGuard)` is authentication; a `RolesGuard` plus `@Roles('admin')` is function-level authorization.

**Correct — role guard for vertical authz:**
```typescript
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('admin')
@Post('users/:id/role')
setRole(@Param('id') id: string, @Body() dto: RoleDto) { ... }
```

**Correct — object-level authz stays in the service:** guards rarely have the object loaded, so ownership is enforced where the entity is fetched:
```typescript
async findOne(id: string, user: User) {
  const order = await this.repo.findOne({ where: { id, ownerId: user.id } });
  if (!order) throw new NotFoundException();
  return order;
}
```

**Bug to flag:** `@Roles` present but `RolesGuard` not registered (annotation is inert); a service method taking `id` with no `user` scoping; a `CASL`/`@casl/ability` `ability.can(...)` check defined but never called on the resource.

---

## Django (Python)

**Principal:** `request.user` (an `AuthenticatedUser` or `AnonymousUser`). `@login_required` / `LoginRequiredMixin` is authentication only.

**Correct — owner-scoped queryset:**
```python
def get_invoice(request, id):
    invoice = get_object_or_404(Invoice, id=id, org=request.user.org)  # 404 if not yours
    return render(request, "invoice.html", {"invoice": invoice})
```

**Correct — class-based view scoping the queryset (so detail/update/delete all inherit it):**
```python
class InvoiceDetail(LoginRequiredMixin, DetailView):
    model = Invoice
    def get_queryset(self):
        return super().get_queryset().filter(org=self.request.user.org)
```

**Bug to flag:** `get_object_or_404(Invoice, id=id)` with no owner term; `Invoice.objects.get(pk=id)` in a view; a `DetailView` without an overridden `get_queryset`; `UserPassesTestMixin` whose `test_func` checks a role but not object ownership.

---

## Django REST Framework (Python)

**Principal:** `request.user`. DRF has two distinct hooks and **both** matter: `permission_classes` (coarse, often function-level) and `get_queryset` / `check_object_permissions` (object-level).

**Correct — scope the queryset *and* keep object permissions:**
```python
class InvoiceViewSet(ModelViewSet):
    serializer_class = InvoiceSerializer
    permission_classes = [IsAuthenticated]
    def get_queryset(self):
        return Invoice.objects.filter(org=self.request.user.org)
```

**Correct — object-level permission class** (DRF calls `has_object_permission` only on single-object lookups, not on `list`, so the queryset filter above is still required):
```python
class IsOwner(BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.org_id == request.user.org_id
```

**Bug to flag:** `queryset = Invoice.objects.all()` with no `get_queryset` override (every user sees every row on `list`); `permission_classes` left at a permissive `DEFAULT_PERMISSION_CLASSES`; `has_object_permission` defined but the view is a plain `APIView` that loads the object manually and never calls `check_object_permissions`.

---

## Rails (Ruby)

**Principal:** `current_user` (from the session via Devise/Warden). `before_action :authenticate_user!` is authentication only.

**Correct — scope through the association:**
```ruby
def show
  @order = current_user.orders.find(params[:id])   # RecordNotFound (404) if not owned
end
```

**Bug to flag — the classic Rails IDOR:**
```ruby
def show
  @order = Order.find(params[:id])   # any logged-in user, any order
end
```
Also flag `Order.find(params[:id])` followed by a mutation, and `permit!`/`params.permit(:role, :admin)` (mass assignment, Pass 4).

### Pundit

Authorization is explicit per action; the tell is a **missing** `authorize`:
```ruby
def update
  @order = Order.find(params[:id])
  authorize @order        # calls OrderPolicy#update?(current_user, @order)
  @order.update!(order_params)
end
```
`after_action :verify_authorized` makes a forgotten `authorize` raise instead of silently allowing — its absence in `ApplicationController` is itself worth noting. The policy must compare to ownership: `record.user_id == user.id`, not merely `user.present?`.

### CanCanCan

```ruby
load_and_authorize_resource          # in the controller
# ability.rb
can :manage, Order, user_id: user.id # the ownership condition lives here
```
**Bug to flag:** `can :manage, :all` for non-admins; `authorize_resource` without the ownership condition in `Ability`.

---

## Spring Security (Java / Kotlin)

**Principal:** the `Authentication` in the `SecurityContext`, or an `@AuthenticationPrincipal` argument. URL-pattern rules (`.requestMatchers("/admin/**").hasRole("ADMIN")`) handle function-level authz; method security handles object-level.

**Correct — method-level role and ownership:**
```java
@PreAuthorize("hasRole('ADMIN')")
public void deleteUser(Long id) { ... }

@PreAuthorize("@authz.ownsOrder(authentication, #id)")  // custom bean returns boolean
public Order getOrder(Long id) { ... }

@PostAuthorize("returnObject.ownerId == authentication.name")
public Order load(Long id) { ... }
```

**Bug to flag:** `@EnableMethodSecurity` (or legacy `@EnableGlobalMethodSecurity`) absent, so `@PreAuthorize` annotations are silently ignored; a repository call `orderRepository.findById(id)` in a service with no preceding ownership check; a security config with `.anyRequest().permitAll()` or `.anyRequest().authenticated()` only (authenticated, not authorized).

---

## Laravel (PHP)

**Principal:** `Auth::user()` / `$request->user()`. `auth` middleware is authentication only.

**Correct — Policy enforced via `authorize`:**
```php
public function show(Order $order)
{
    $this->authorize('view', $order);   // OrderPolicy::view(User $user, Order $order)
    return $order;
}
// OrderPolicy
public function view(User $user, Order $order): bool
{
    return $user->id === $order->user_id;
}
```

**Correct — scope by relationship** (route-model binding alone does NOT check ownership):
```php
$order = $request->user()->orders()->findOrFail($id);
```

**Bug to flag:** route-model binding (`Route::get('/orders/{order}', ...)`) that resolves any `Order` with no `authorize` call and no `scopeBindings`; `$request->all()` passed to `update()`/`create()` (mass assignment — confirm the model's `$fillable` excludes `role`, `is_admin`, `*_id`); `Gate`/`can` defined but never called.

---

## Go (net/http, chi, gin, echo)

**Principal:** typically a value pulled from `r.Context()` that auth middleware placed there. Anything from `chi.URLParam`, `r.URL.Query()`, or the body is attacker-controlled.

**Correct — carry the owner into the query:**
```go
userID := auth.UserID(r.Context())                 // from verified session/token
row := db.QueryRowContext(r.Context(),
    "SELECT id, total FROM orders WHERE id = $1 AND user_id = $2",
    chi.URLParam(r, "id"), userID)
if errors.Is(row.Scan(&o.ID, &o.Total), sql.ErrNoRows) {
    http.Error(w, "not found", http.StatusNotFound)
    return
}
```

**Bug to flag:** `WHERE id = $1` with no `user_id`/`tenant_id` term; an admin handler mounted without a role-checking middleware; the principal read from `r.Header.Get("X-User-Id")` (Pass 5); a gin handler using `c.Param("id")` straight into a `First(&order, id)` GORM call with no scope.

---

## Cross-cutting: GraphQL (any language)

Authorization must be enforced **in resolvers**, because a single query reaches many objects through relationships:

- The root `node(id:)` / `Query.order(id:)` resolver needs the same owner check as a REST endpoint.
- **Field resolvers that load related objects** (`Order.customer`, `User.paymentMethods`) each need their own check — a user authorized for object A is not automatically authorized for everything A links to.
- Mutations need function-level checks just like REST.

**Bug to flag:** authorization done only in a top-level HTTP middleware (it can't see which object ids the query will resolve); a `node` resolver that decodes the global id and loads without scoping; nested resolvers that trust the parent was authorized.
