# AWS Misconfiguration Findings Report

**Scan source:** Mock data (demo mode)  
**Generated:** 2026-09-23 13:19 UTC  
**Total findings:** 10

| Severity | Check ID | Finding | Resource |
|----------|----------|---------|----------|
| CRITICAL | S3-001 | Public S3 bucket: orca-demo-logs-archive | `orca-demo-logs-archive` |
| CRITICAL | SG-001 | SSH open to internet: web-sg | `sg-0a1b2c3d` |
| CRITICAL | SG-001 | RDP open to internet: db-sg | `sg-0e4f5g6h` |
| CRITICAL | IAM-002 | Wildcard admin policy: FullAdminAccess-legacy | `legacy-admin` |
| HIGH | S3-001 | Public S3 bucket: orca-demo-public-assets | `orca-demo-public-assets` |
| HIGH | IAM-001 | IAM user without MFA: svc-ci-deploy | `svc-ci-deploy` |
| HIGH | IAM-001 | IAM user without MFA: legacy-admin | `legacy-admin` |
| MEDIUM | SG-002 | Port 443 open to internet: web-sg | `sg-0a1b2c3d` |
| MEDIUM | EBS-001 | Unencrypted EBS volume: vol-0abc111 | `vol-0abc111` |
| MEDIUM | EBS-001 | Unencrypted EBS volume: vol-0abc333 | `vol-0abc333` |

---

## Details & Remediation

### [CRITICAL] Public S3 bucket: orca-demo-logs-archive
- **Check ID:** S3-001
- **Resource:** `orca-demo-logs-archive`
- **Description:** Bucket 'orca-demo-logs-archive' grants AllUsers WRITE access and Public Access Block is not fully enabled.
- **Runbook:** [`runbooks/public-s3-bucket.md`](../runbooks/public-s3-bucket.md)

### [CRITICAL] SSH open to internet: web-sg
- **Check ID:** SG-001
- **Resource:** `sg-0a1b2c3d`
- **Description:** Security group 'web-sg' (sg-0a1b2c3d) allows inbound SSH (port 22) from 0.0.0.0/0. This port is commonly targeted by automated scanners within minutes of exposure.
- **Runbook:** [`runbooks/open-security-group.md`](../runbooks/open-security-group.md)

### [CRITICAL] RDP open to internet: db-sg
- **Check ID:** SG-001
- **Resource:** `sg-0e4f5g6h`
- **Description:** Security group 'db-sg' (sg-0e4f5g6h) allows inbound RDP (port 3389) from 0.0.0.0/0. This port is commonly targeted by automated scanners within minutes of exposure.
- **Runbook:** [`runbooks/open-security-group.md`](../runbooks/open-security-group.md)

### [CRITICAL] Wildcard admin policy: FullAdminAccess-legacy
- **Check ID:** IAM-002
- **Resource:** `legacy-admin`
- **Description:** Policy 'FullAdminAccess-legacy' attached to 'legacy-admin' grants Action:* on Resource:* — equivalent to full account admin access.
- **Runbook:** [`runbooks/wildcard-iam-policy.md`](../runbooks/wildcard-iam-policy.md)

### [HIGH] Public S3 bucket: orca-demo-public-assets
- **Check ID:** S3-001
- **Resource:** `orca-demo-public-assets`
- **Description:** Bucket 'orca-demo-public-assets' grants AllUsers READ access and Public Access Block is not fully enabled.
- **Runbook:** [`runbooks/public-s3-bucket.md`](../runbooks/public-s3-bucket.md)

### [HIGH] IAM user without MFA: svc-ci-deploy
- **Check ID:** IAM-001
- **Resource:** `svc-ci-deploy`
- **Description:** User 'svc-ci-deploy' has no MFA device registered. Access key age: 412 days.
- **Runbook:** [`runbooks/iam-no-mfa.md`](../runbooks/iam-no-mfa.md)

### [HIGH] IAM user without MFA: legacy-admin
- **Check ID:** IAM-001
- **Resource:** `legacy-admin`
- **Description:** User 'legacy-admin' has no MFA device registered. Access key age: 730 days.
- **Runbook:** [`runbooks/iam-no-mfa.md`](../runbooks/iam-no-mfa.md)

### [MEDIUM] Port 443 open to internet: web-sg
- **Check ID:** SG-002
- **Resource:** `sg-0a1b2c3d`
- **Description:** Security group 'web-sg' (sg-0a1b2c3d) allows inbound traffic on port 443 from 0.0.0.0/0. Confirm this is intentional (e.g. a public web server on 443).
- **Runbook:** [`runbooks/open-security-group.md`](../runbooks/open-security-group.md)

### [MEDIUM] Unencrypted EBS volume: vol-0abc111
- **Check ID:** EBS-001
- **Resource:** `vol-0abc111`
- **Description:** Volume 'vol-0abc111' (100 GiB), attached to i-0prod01, is not encrypted. Data at rest is not protected if the underlying storage is compromised.
- **Runbook:** [`runbooks/unencrypted-ebs.md`](../runbooks/unencrypted-ebs.md)

### [MEDIUM] Unencrypted EBS volume: vol-0abc333
- **Check ID:** EBS-001
- **Resource:** `vol-0abc333`
- **Description:** Volume 'vol-0abc333' (20 GiB), attached to i-0staging01, is not encrypted. Data at rest is not protected if the underlying storage is compromised.
- **Runbook:** [`runbooks/unencrypted-ebs.md`](../runbooks/unencrypted-ebs.md)
