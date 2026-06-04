# Remediation Playbook

Bad→good fixes for the most common IaC misconfigurations. Each entry pairs a minimal broken example with the corrected one, the rationale, and the **pitfall** — the "fix" that looks right but isn't. Cite the `control id` from `controls.md` alongside the fix in your report.

---

## 1. Public S3 bucket (`storage-s3-public-acl`, `storage-s3-no-public-access-block`)

Platforms: Terraform, CloudFormation.

```hcl
# Bad
resource "aws_s3_bucket" "data" {
  bucket = "acme-customer-data"
  acl    = "public-read"
}

# Good
resource "aws_s3_bucket" "data" {
  bucket = "acme-customer-data"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

Rationale: the public-access-block is the account-level backstop; even a future careless ACL or bucket policy can't make the bucket public while all four flags are `true`.

Pitfall: setting `acl = "private"` alone is **not** enough — a later `aws_s3_bucket_policy` with a `*` principal still opens it. The public-access-block is what makes "private" durable. Also: serve genuinely public assets via CloudFront + Origin Access Control, never a public bucket.

---

## 2. Security group open to the world on SSH/DB ports (`network-ssh-world-open`, `network-db-world-open`)

Platforms: Terraform, CloudFormation.

```hcl
# Bad
ingress {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

# Good
ingress {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = [var.admin_cidr]   # e.g. ["10.0.0.0/16"] or a VPN range
}
```

Rationale: SSH/RDP/database ports exposed to `0.0.0.0/0` are scanned and brute-forced within minutes. Scope them to known admin ranges, or remove SSH entirely in favor of SSM Session Manager.

Pitfall: an IPv4 `0.0.0.0/0` fix that forgets `ipv6_cidr_blocks = ["::/0"]` leaves the same hole open over IPv6. Fix both. And a "temporary" `0.0.0.0/0` in a `*.tfvars` override is still production.

---

## 3. IAM wildcard on Action or Resource (`iam-wildcard-action`, `iam-wildcard-resource`)

Platforms: Terraform, CloudFormation.

```json
// Bad
{ "Effect": "Allow", "Action": "*", "Resource": "*" }

// Good
{
  "Effect": "Allow",
  "Action": ["s3:GetObject", "s3:PutObject"],
  "Resource": "arn:aws:s3:::acme-app-bucket/*"
}
```

Rationale: least privilege contains the blast radius of any single compromised credential. `*:*` turns one leaked key into account-wide control.

Pitfall: `Action: ["s3:*"]` is still a wildcard — it grants `s3:DeleteBucket`, `s3:PutBucketPolicy`, etc. Enumerate the verbs. And note the asymmetry: `NotAction`/`NotResource` with `Allow` is a wildcard in disguise (allows everything *except* a list).

---

## 4. Container running as root / no SecurityContext (`container-run-as-root`, `container-privileged`)

Platforms: Kubernetes, Helm.

```yaml
# Bad
containers:
  - name: app
    image: acme/app:1.4.2

# Good
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  seccompProfile: { type: RuntimeDefault }
containers:
  - name: app
    image: acme/app:1.4.2
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities: { drop: ["ALL"] }
```

Rationale: a container with no `securityContext` runs as root with the full default capability set; a container escape becomes node root. Dropping capabilities and root privileges shrinks what an escape can do.

Pitfall: setting `runAsNonRoot: true` while the image's `USER` is still `0` makes the pod **fail to start** (good — it surfaces the problem) — but setting only `runAsUser: 10001` without `runAsNonRoot: true` lets an image that hardcodes `USER 0` silently win. Set both. Enforce cluster-wide with Pod Security Admission `restricted`, not per-pod hope.

---

## 5. Unrestricted egress (`network-egress-world-open`)

Platforms: Terraform, CloudFormation.

```hcl
# Bad (the default AWS SG egress, copied everywhere)
egress {
  from_port   = 0
  to_port     = 0
  protocol    = "-1"
  cidr_blocks = ["0.0.0.0/0"]
}

# Good
egress {
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = [var.vpc_cidr]   # or specific endpoints / prefix lists
}
```

Rationale: restricting egress cuts the exfiltration and C2 path. If a workload is popped, it can't phone home to arbitrary hosts.

Pitfall: clamping egress can break package installs, OS updates, and AWS API calls. Route those through VPC endpoints / a NAT to known CIDRs rather than leaving `0.0.0.0/0` open "because it broke." This is a P3 — fix it, but don't let it block a deploy over the P0s.

---

## 6. Unencrypted EBS / RDS (`storage-encryption-disabled`)

Platforms: Terraform, CloudFormation.

```hcl
# Bad
resource "aws_db_instance" "main" {
  storage_encrypted = false
}

# Good
resource "aws_db_instance" "main" {
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn   # customer-managed for sensitive data
}
```

Rationale: encryption at rest protects against snapshot leaks, disposed-disk recovery, and cross-account snapshot sharing mistakes.

Pitfall: RDS encryption **cannot be toggled on an existing instance** — it must be set at creation, so this is a Moderate fix (snapshot → encrypted copy → restore), not a one-liner. Flag it before the resource is created. Also, `storage_encrypted = true` with the default AWS-managed key still shares the key's lifecycle with AWS; use a CMK where the rubric calls for it.

---

## 7. Plaintext secrets in variables / env (`secrets-plaintext`)

Platforms: Terraform, Kubernetes, Docker Compose.

```hcl
# Bad
variable "db_password" {
  default = "hunter2"
}

# Good
variable "db_password" {
  type      = string
  sensitive = true   # no default; injected from a secrets manager / TF_VAR_ at runtime
}
```

```yaml
# Bad (Kubernetes)
kind: ConfigMap
data:
  API_KEY: "sk-live-abc123"

# Good — use a Secret (encrypted at rest) sourced from an external manager
kind: Secret
type: Opaque
data:
  API_KEY: <base64>   # better: ExternalSecret / SealedSecret, not committed plaintext
```

Rationale: anything in a committed `default`, env value, or ConfigMap is in git history forever and visible to anyone with repo read. Secrets belong in a manager with rotation and access control.

Pitfall: a Kubernetes `Secret` is only **base64-encoded, not encrypted** in the manifest — committing it is barely better than a ConfigMap. Use SealedSecrets/ExternalSecrets/Vault so the plaintext never lands in git, and enable etcd encryption-at-rest on the cluster. `sensitive = true` in Terraform hides the value from CLI output but it is still in the state file — protect the backend.

---

## 8. Missing log retention (`logging-no-retention`)

Platforms: Terraform, CloudFormation.

```hcl
# Bad
resource "aws_cloudwatch_log_group" "app" {
  name = "/acme/app"
}

# Good
resource "aws_cloudwatch_log_group" "app" {
  name              = "/acme/app"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.logs.arn
}
```

Rationale: an explicit retention bounds cost and satisfies the "keep N days of audit logs" compliance requirement; KMS encryption protects the logs themselves.

Pitfall: the AWS default is "never expire," which reads as *more* logging but is actually an unbounded cost and an undefined retention posture — auditors want a *stated* period, not infinity. Match the number to policy (PCI-DSS expects 12 months, with 3 immediately available).

---

## 9. Wildcard KMS key policy principal (`secrets-kms-wildcard-policy`)

Platforms: Terraform, CloudFormation.

```json
// Bad
{ "Effect": "Allow", "Principal": { "AWS": "*" }, "Action": "kms:*", "Resource": "*" }

// Good
{
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::111122223333:role/app" },
  "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
  "Resource": "*",
  "Condition": { "StringEquals": { "kms:ViaService": "s3.eu-west-1.amazonaws.com" } }
}
```

Rationale: a wildcard principal on a KMS key defeats the whole point of envelope encryption — anyone who can call the key can read everything it wraps.

Pitfall: the *root account* statement (`"Principal": {"AWS": "arn:aws:iam::ACCOUNT:root"}`) is normal and required so IAM can govern the key — don't flag that as a wildcard. The dangerous form is `"*"` (or a foreign account) **without** a `Condition`.

---

## 10. ALB / CloudFront missing HTTPS redirect (`secrets-missing-tls`)

Platforms: Terraform, CloudFormation.

```hcl
# Bad — HTTP listener that serves traffic directly
resource "aws_lb_listener" "http" {
  port     = 80
  protocol = "HTTP"
  default_action { type = "forward"  target_group_arn = aws_lb_target_group.app.arn }
}

# Good — HTTP redirects to HTTPS; HTTPS terminates TLS
resource "aws_lb_listener" "http" {
  port     = 80
  protocol = "HTTP"
  default_action {
    type = "redirect"
    redirect { port = "443"  protocol = "HTTPS"  status_code = "HTTP_301" }
  }
}

resource "aws_lb_listener" "https" {
  port            = 443
  protocol        = "HTTPS"
  ssl_policy      = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn = var.cert_arn
  default_action { type = "forward"  target_group_arn = aws_lb_target_group.app.arn }
}
```

Rationale: plaintext HTTP exposes credentials and session tokens to anyone on the path; the redirect guarantees clients land on TLS.

Pitfall: adding the HTTPS listener but leaving the HTTP one set to `forward` (not `redirect`) keeps the cleartext door open. CloudFront equivalent: `viewer_protocol_policy = "redirect-to-https"`, not `"allow-all"`.

---

## 11. Container `:latest` / untagged image (`supply-image-untrusted`)

Platforms: Kubernetes, Docker, Compose.

```yaml
# Bad
image: nginx:latest

# Good
image: nginx:1.27.3@sha256:6af79ae5de407...   # tag for humans, digest for immutability
```

Rationale: `:latest` is mutable — the bytes you reviewed are not guaranteed to be the bytes you run, and rollbacks become non-deterministic. A digest pins exactly one image.

Pitfall: pinning a tag alone (`nginx:1.27.3`) is better but still mutable — a tag can be re-pushed. The `@sha256:` digest is what makes it immutable. Also set `imagePullPolicy: IfNotPresent` (or `Always` only with a digest) so a re-pushed `latest` doesn't surprise you.

---

## 12. No Pod Security enforcement (`container-privileged` cluster-wide)

Platforms: Kubernetes.

```yaml
# Bad — relying on each manifest to set securityContext correctly (PSP is removed in 1.25+)

# Good — enforce the baseline at the namespace with Pod Security Admission
apiVersion: v1
kind: Namespace
metadata:
  name: app
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
```

Rationale: per-pod `securityContext` is opt-in and easy to forget. Namespace-level Pod Security Admission (`restricted`) rejects privileged/root pods at admission time, cluster-wide.

Pitfall: `PodSecurityPolicy` is **removed** in Kubernetes 1.25+ — a manifest still defining a `PodSecurityPolicy` is dead config providing zero protection. Migrate to Pod Security Admission (built-in) or an admission controller (Kyverno, OPA Gatekeeper). Setting `warn`/`audit` labels without `enforce` logs violations but blocks nothing.

---

## 13. Missing resource limits (`container-no-resource-limits`)

Platforms: Kubernetes.

```yaml
# Bad
containers:
  - name: app
    image: acme/app:1.4.2

# Good
containers:
  - name: app
    image: acme/app:1.4.2
    resources:
      requests: { cpu: "100m", memory: "128Mi" }
      limits:   { cpu: "500m", memory: "512Mi" }
```

Rationale: without limits, one pod (compromised or buggy) can consume the whole node's CPU/memory and take down every other workload on it — a denial-of-service.

Pitfall: setting `limits` far above `requests` on memory still allows noisy-neighbor pressure and OOM surprises; and a CPU `limit` that's too tight throttles latency-sensitive apps. Enforce sane defaults with a namespace `LimitRange` rather than trusting every author.

---

## 14. Terraform module from an unverified / unpinned source (`supply-image-untrusted`)

Platforms: Terraform.

```hcl
# Bad — mutable ref, plaintext transport
module "vpc" {
  source = "git::http://internal.example.com/modules/vpc.git"
}

# Good — pinned to a tag (or commit SHA), over HTTPS/SSH
module "vpc" {
  source = "git::https://github.com/acme/terraform-modules.git//vpc?ref=v3.1.0"
}
```

Rationale: an unpinned module source means `terraform init` can pull different code on each run — a supply-chain foothold. Pinning to a tag/SHA freezes the reviewed code.

Pitfall: `?ref=main` is still mutable — pin to a release tag or, for full immutability, a commit SHA. Registry modules (`source = "terraform-aws-modules/vpc/aws"`) must carry a `version = "..."` constraint; a bare registry source floats to the latest release.

---

## 15. No read-only root filesystem (`container-run-as-root`)

Platforms: Kubernetes, Compose.

```yaml
# Bad
securityContext:
  runAsNonRoot: true

# Good
securityContext:
  runAsNonRoot: true
  readOnlyRootFilesystem: true
volumeMounts:
  - { name: tmp, mountPath: /tmp }     # writable scratch where genuinely needed
volumes:
  - { name: tmp, emptyDir: {} }
```

Rationale: a read-only root filesystem stops an attacker who lands code execution from writing a payload, dropping a webshell, or persisting — they can't modify the image at runtime.

Pitfall: flipping `readOnlyRootFilesystem: true` breaks apps that write to `/tmp`, `/var/run`, or a cache dir. The fix is to mount small `emptyDir` volumes for exactly those paths — not to abandon the control. Test the app starts before shipping.
