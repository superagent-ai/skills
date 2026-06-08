# AD, Network, And Privilege Escalation Playbook

Use for authorized network assessments, Active Directory review, Linux/Windows privilege escalation planning, and lateral movement analysis.

## Coverage

Maps these reference areas:

- `network-attack`
- `active-directory-attack`
- `privesc-linux`
- `privesc-windows`
- protocol and authentication references

## Safe workflow

1. Confirm network ranges, domains, accounts, and test hosts are in scope.
2. Map services, identities, groups, trust relationships, and segmentation.
3. Prefer graph analysis, configuration review, and lab reproduction before live validation.
4. Use test credentials only unless RoE explicitly permits other credential handling.
5. Stop before lateral movement, persistence, or privilege changes unless explicitly approved.

## Focus areas

- exposed services and management planes
- AD trust paths and delegation risk
- Kerberos, NTLM, LDAP, SMB, RDP, WinRM, and VPN boundaries
- local privilege escalation prerequisites
- service account and group policy exposure
- segmentation and egress assumptions

## Evidence bar

- host, domain, account, and privilege context
- exact trust boundary crossed or not crossed
- non-destructive proof
- negative control or denied role
- remediation owner and priority

## Unsafe by default

- password spraying or brute force
- hash cracking or ticket abuse outside explicit scope
- lateral movement
- persistence
- modifying directory, policy, or endpoint configuration
- accessing file shares or mailboxes beyond approved proof
