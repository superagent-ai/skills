# Control Catalog

The canonical list of what this skill checks. Every control has a stable `id`, a default severity, the bad pattern that flags it, the good pattern that clears it, and an indicative compliance mapping. `scripts/scan.py` implements the deterministic, text-detectable subset of these controls keyed by the same `id`; the model covers the judgment-only controls (least-privilege reasoning, missing resources, cross-resource blast radius) that no regex can see.

**Severity is a default, not a verdict.** The listed level is the typical rating for the pattern in isolation. Adjust up or down with the exposure × blast-radius mental model in `severity-rubric.md` — a wildcard IAM policy on an isolated role is P2; the same policy on a role every workload assumes is P0.

**Compliance columns are indicative.** SOC-2 (Trust Services Criteria), PCI-DSS v4.0, and ISO-27001:2022 Annex A control IDs are mapped to the nearest applicable control; confirm against your own audit scope before citing in a formal report.

Scanner-implemented controls are marked **[scanner]**; model-only controls are marked **[model]**.

---

## Identity & Access Management (IAM)

### `iam-wildcard-action` — P1 [scanner]
- **Checks:** An IAM policy statement with `Effect: Allow` grants `Action: "*"` (or a service wildcard like `s3:*` on a sensitive service).
- **Bad:** `"Action": "*"` or `"Action": ["*"]` with `"Effect": "Allow"`.
- **Good:** Enumerate the specific actions the principal needs (`s3:GetObject`, `s3:PutObject`).
- **Compliance:** SOC-2 CC6.1, CC6.3; PCI-DSS 7.2.1; ISO-27001 A.5.15, A.8.2.

### `iam-wildcard-resource` — P2 [scanner]
- **Checks:** An `Allow` statement scopes `Resource: "*"` for actions that support resource-level permissions.
- **Bad:** `"Resource": "*"` on `s3:*`, `dynamodb:*`, `secretsmanager:GetSecretValue`, etc.
- **Good:** Pin to specific ARNs (`arn:aws:s3:::my-bucket/*`).
- **Compliance:** SOC-2 CC6.1; PCI-DSS 7.2.1; ISO-27001 A.5.15.

### `iam-wildcard-principal` — P0 [scanner]
- **Checks:** A resource policy (S3 bucket policy, KMS key policy, SNS/SQS/Secrets policy) grants `Principal: "*"` (or `"AWS": "*"`) with no restricting `Condition`.
- **Bad:** `"Principal": "*"` / `"Principal": {"AWS": "*"}` and no `Condition`.
- **Good:** Name the account/role ARNs allowed, or gate with a `Condition` (e.g. `aws:PrincipalOrgID`, `aws:SourceArn`).
- **Compliance:** SOC-2 CC6.1, CC6.6; PCI-DSS 1.3, 7.2; ISO-27001 A.5.15, A.8.3.

### `iam-passrole-wildcard` — P1 [scanner]
- **Checks:** `iam:PassRole` (or `sts:AssumeRole`) allowed on `Resource: "*"` — lets a principal hand any role to a service and escalate.
- **Bad:** `Action: "iam:PassRole"` with `Resource: "*"`.
- **Good:** Restrict `PassRole` to the specific role ARNs, ideally with an `iam:PassedToService` condition.
- **Compliance:** SOC-2 CC6.3; PCI-DSS 7.2.1; ISO-27001 A.8.2.

### `iam-admin-on-compute` — P1 [model]
- **Checks:** `AdministratorAccess` (or an equivalently broad inline/managed policy) attached to a role assumed by compute (EC2 instance profile, Lambda, ECS task, EKS service account).
- **Bad:** `managed_policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess"]` on an instance/task role.
- **Good:** Least-privilege policy scoped to the workload's real needs.
- **Compliance:** SOC-2 CC6.1, CC6.3; PCI-DSS 7.1, 7.2; ISO-27001 A.8.2.

---

## Network & Firewall

### `network-ssh-world-open` — P0 [scanner]
- **Checks:** A security group / firewall rule allows `0.0.0.0/0` (or `::/0`) to TCP **22** (SSH).
- **Bad:** ingress `from_port = 22, to_port = 22, cidr_blocks = ["0.0.0.0/0"]`.
- **Good:** Scope to a bastion/VPN CIDR, or drop SSH entirely in favor of SSM Session Manager / IAP.
- **Compliance:** SOC-2 CC6.6; PCI-DSS 1.3.1, 1.4; ISO-27001 A.8.20, A.8.22.

### `network-rdp-world-open` — P0 [scanner]
- **Checks:** A rule allows `0.0.0.0/0` to TCP **3389** (RDP).
- **Bad:** ingress to port 3389 from `0.0.0.0/0`.
- **Good:** Restrict to admin CIDR / VPN, or front with a bastion.
- **Compliance:** SOC-2 CC6.6; PCI-DSS 1.3.1; ISO-27001 A.8.20.

### `network-db-world-open` — P0 [scanner]
- **Checks:** A rule allows `0.0.0.0/0` to a database/cache port: 3306, 5432, 1433, 1521 (DB); 6379 (Redis); 27017 (Mongo); 9200/9300 (Elasticsearch); 11211 (Memcached); 5984 (CouchDB); 9042 (Cassandra).
- **Bad:** ingress to `5432` from `0.0.0.0/0`.
- **Good:** Restrict to the app security group; keep the datastore in a private subnet with no public route.
- **Compliance:** SOC-2 CC6.6; PCI-DSS 1.3.1, 1.3.2; ISO-27001 A.8.20, A.8.22.

### `network-all-ports-world-open` — P0 [scanner]
- **Checks:** An **ingress** rule opens **all ports** to `0.0.0.0/0` (`from_port = 0, to_port = 65535`, or protocol `-1`). A superset of the SSH/RDP/DB cases, so it inherits their P0. (The same all-ports pattern on *egress* is the separate, lower-severity `network-egress-world-open`.)
- **Bad:** `from_port = 0, to_port = 0, protocol = "-1", cidr_blocks = ["0.0.0.0/0"]` on an `ingress` block.
- **Good:** Open only the specific service ports actually needed, and only to the CIDRs that need them.
- **Compliance:** SOC-2 CC6.6; PCI-DSS 1.3; ISO-27001 A.8.20.

### `network-egress-world-open` — P3 [scanner]
- **Checks:** Unrestricted egress `0.0.0.0/0` on all ports where the workload doesn't need open outbound (exfiltration / C2 path).
- **Bad:** default `egress { from_port = 0, to_port = 0, protocol = "-1", cidr_blocks = ["0.0.0.0/0"] }`.
- **Good:** Restrict egress to the destinations and ports the workload actually calls (VPC endpoints, specific CIDRs).
- **Compliance:** SOC-2 CC6.6; PCI-DSS 1.3.4; ISO-27001 A.8.20.

---

## Storage & Data

### `storage-s3-public-acl` — P0 [scanner]
- **Checks:** An S3 bucket (or object) ACL set to `public-read` or `public-read-write`.
- **Bad:** `acl = "public-read"` / `AccessControl: PublicRead`.
- **Good:** `acl = "private"` plus an explicit `aws_s3_bucket_public_access_block` with all four flags `true`; serve public content via CloudFront + OAC.
- **Compliance:** SOC-2 CC6.1; PCI-DSS 1.3.6, 3.4; ISO-27001 A.5.15, A.8.3.

### `storage-s3-no-public-access-block` — P1 [model]
- **Checks:** A bucket holding non-public data with no `aws_s3_bucket_public_access_block` (or CloudFormation `PublicAccessBlockConfiguration`) pinning all four flags `true`.
- **Bad:** Bucket defined; no public-access-block resource anywhere in scope.
- **Good:** `block_public_acls = true, block_public_policy = true, ignore_public_acls = true, restrict_public_buckets = true`.
- **Compliance:** SOC-2 CC6.1; PCI-DSS 1.3.6; ISO-27001 A.8.3.

### `storage-encryption-disabled` — P2 [scanner]
- **Checks:** Encryption-at-rest explicitly disabled on EBS, RDS, S3, DynamoDB, or EFS.
- **Bad:** `encrypted = false` / `storage_encrypted = false` / `StorageEncrypted: false`.
- **Good:** `encrypted = true` (or `storage_encrypted = true`), ideally with a customer-managed KMS key for sensitive data.
- **Compliance:** SOC-2 CC6.1, C1.1; PCI-DSS 3.4, 3.5; ISO-27001 A.8.24.

### `storage-no-versioning-logging` — P3 [model]
- **Checks:** Versioning or access logging disabled on a bucket holding sensitive or audit-relevant data.
- **Bad:** `versioning { enabled = false }`, no `logging {}` block on a sensitive bucket.
- **Good:** Enable versioning (ransomware/accidental-delete recovery) and access logging to a separate log bucket.
- **Compliance:** SOC-2 A1.2, PI1.4; PCI-DSS 10.2; ISO-27001 A.8.13, A.8.15.

---

## Compute & Containers

### `container-privileged` — P1 [scanner]
- **Checks:** A container runs privileged, or allows privilege escalation / adds dangerous Linux capabilities.
- **Bad:** `securityContext: { privileged: true }`, `allowPrivilegeEscalation: true`, `capabilities: { add: ["SYS_ADMIN", "NET_ADMIN", "ALL"] }`; Compose `privileged: true`.
- **Good:** `privileged: false`, `allowPrivilegeEscalation: false`, `capabilities: { drop: ["ALL"] }` and add back only what's required.
- **Compliance:** SOC-2 CC6.1, CC6.8; PCI-DSS 2.2; ISO-27001 A.8.9, A.8.27.

### `container-run-as-root` — P1 [scanner]
- **Checks:** A container runs as UID 0. Also covers a `Dockerfile` with no `USER` directive (defaults to root) and `readOnlyRootFilesystem` not set.
- **Bad:** `runAsUser: 0`, `runAsNonRoot: false`, or a Dockerfile that never sets `USER`.
- **Good:** `runAsNonRoot: true`, a non-zero `runAsUser`, `readOnlyRootFilesystem: true`; Dockerfile `USER 10001`.
- **Compliance:** SOC-2 CC6.1; PCI-DSS 2.2; ISO-27001 A.8.9, A.8.27.

### `container-host-namespace` — P1 [scanner]
- **Checks:** A pod shares a host namespace, collapsing isolation.
- **Bad:** `hostNetwork: true`, `hostPID: true`, or `hostIPC: true`.
- **Good:** Leave all three unset/`false`; use a `Service` for networking rather than the host stack.
- **Compliance:** SOC-2 CC6.1, CC6.6; PCI-DSS 2.2; ISO-27001 A.8.22, A.8.27.

### `container-docker-socket-mount` — P0 [scanner]
- **Checks:** A container mounts the Docker/containerd socket or the host root filesystem — equivalent to host root.
- **Bad:** `hostPath: { path: /var/run/docker.sock }`, `hostPath: { path: / }`; Compose `- /var/run/docker.sock:/var/run/docker.sock`.
- **Good:** Don't mount the socket; if a workload truly needs to build images, use a rootless/sandboxed builder (kaniko, buildkit-rootless).
- **Compliance:** SOC-2 CC6.1, CC6.8; PCI-DSS 2.2; ISO-27001 A.8.27.

### `container-no-resource-limits` — P3 [model]
- **Checks:** A workload has no CPU/memory `limits` (and often no `requests`) — a single pod can starve the node (DoS).
- **Bad:** container spec with no `resources.limits`.
- **Good:** Set `resources.requests` and `resources.limits`; enforce with a namespace `LimitRange`/`ResourceQuota`.
- **Compliance:** SOC-2 A1.1; PCI-DSS 2.2; ISO-27001 A.8.6.

---

## Secrets & Encryption

### `secrets-plaintext` — P1 [scanner]
- **Checks:** A secret committed in plaintext — a Terraform variable `default`, an env var, or a Kubernetes ConfigMap.
- **Bad:** `variable "db_password" { default = "hunter2" }`, `env: { name: API_KEY, value: "sk-live-..." }`, a `kind: ConfigMap` holding a token.
- **Good:** Reference a secrets manager (AWS Secrets Manager / SSM SecureString, Vault, sealed/external secrets); mark TF variables `sensitive = true`; use `kind: Secret` (encrypted at rest), never `ConfigMap`, for credentials.
- **Compliance:** SOC-2 CC6.1; PCI-DSS 3.5, 8.3.1; ISO-27001 A.8.24, A.5.17.

### `secrets-missing-tls` — P2 [scanner]
- **Checks:** A public listener serves plaintext HTTP, or TLS is disabled / not redirected.
- **Bad:** ALB/ELB listener on `protocol = "HTTP"` with no HTTPS redirect; CloudFront `viewer_protocol_policy = "allow-all"`; API Gateway without TLS; `ssl_policy` absent.
- **Good:** Terminate TLS (HTTPS/443), redirect HTTP→HTTPS, set a modern `ssl_policy`; CloudFront `redirect-to-https`.
- **Compliance:** SOC-2 CC6.7; PCI-DSS 4.2.1; ISO-27001 A.8.24, A.8.20.

### `secrets-kms-wildcard-policy` — P1 [scanner]
- **Checks:** A KMS key policy grants a wildcard principal (`"AWS": "*"`) without a constraining `Condition`, undermining envelope encryption.
- **Bad:** key policy statement with `"Principal": {"AWS": "*"}` and no `Condition`.
- **Good:** Scope key usage to specific roles/accounts; gate with `kms:ViaService` / `aws:PrincipalOrgID` conditions.
- **Compliance:** SOC-2 CC6.1; PCI-DSS 3.6, 3.7; ISO-27001 A.8.24.

---

## Logging & Monitoring

### `logging-trail-disabled` — P2 [model]
- **Checks:** Audit logging is absent or disabled — no CloudTrail, AWS Config recorder off, or VPC Flow Logs missing on a VPC carrying sensitive traffic.
- **Bad:** No `aws_cloudtrail` in scope; `enable_logging = false`; VPC with no `aws_flow_log`.
- **Good:** Multi-region CloudTrail with log-file validation, Config recorder on, Flow Logs to a retained, encrypted log destination.
- **Compliance:** SOC-2 CC7.2, CC7.3; PCI-DSS 10.2, 10.3; ISO-27001 A.8.15, A.8.16.

### `logging-no-retention` — P3 [scanner]
- **Checks:** A log group/stream has no retention set (logs kept forever or, worse, ambiguously) or logs are unencrypted.
- **Bad:** `aws_cloudwatch_log_group` with no `retention_in_days`; no `kms_key_id`.
- **Good:** Set an explicit `retention_in_days` matching policy; encrypt log groups with KMS.
- **Compliance:** SOC-2 CC7.2; PCI-DSS 10.5, 10.7; ISO-27001 A.8.15.

---

## Supply Chain

### `supply-image-untrusted` — P3 [scanner]
- **Checks:** A container image uses the mutable `:latest` tag (or no tag), or a Terraform module is sourced from an unpinned git/HTTP location.
- **Bad:** `image: nginx:latest` / `image: nginx`; `source = "git::https://example.com/modules/vpc.git"` with no `?ref=<tag-or-sha>`.
- **Good:** Pin images by tag **and** digest (`nginx:1.27.3@sha256:...`) from a trusted registry; pin modules to a tag or commit SHA (`?ref=v3.1.0`).
- **Compliance:** SOC-2 CC8.1; PCI-DSS 6.3.2, 6.5.3; ISO-27001 A.8.28, A.8.30.

---

## How the scanner and the model divide the catalog

- **[scanner]** controls are unambiguous in text — a literal `0.0.0.0/0`, `"Action": "*"`, `privileged: true`. `scripts/scan.py` flags these with `file:line` and high recall. Your job is to confirm exposure/blast radius and suppress the false positives the scanner can't judge.
- **[model]** controls require reasoning the scanner can't do: detecting a *missing* resource (no public-access-block, no CloudTrail), judging whether a managed policy is over-broad for the workload it's attached to, or tracing a cross-resource chain. The scanner won't raise these — you must, during Phase 2.

When you confirm a finding, cite its `id` so the report, the rubric, and the remediation playbook line up.
