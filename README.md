# AWS Misconfig Triage Toolkit

A small Python CLI that scans an AWS account for common cloud
misconfigurations — the same categories a CNAPP (Cloud-Native Application
Protection Platform) flags — and produces a **prioritized, customer-readable
findings report** with linked remediation runbooks for each finding type.

Built to practice the exact workflow a Customer Success / Support Engineer
does day-to-day in cloud security: **detect a finding → explain the risk in
plain language → hand the customer clear remediation steps → document it as
a reusable runbook.**

## Why this project

I come from a SOC/security-analyst background (SIEM, incident triage,
runbook authoring) and wanted hands-on practice with cloud-provider APIs —
the piece most directly relevant to cloud security customer-facing roles.
This project scans AWS instead of Oracle Cloud (my OCI Foundations
Associate cert) intentionally, to build breadth across the major providers
(AWS/Azure/GCP) that CNAPP platforms actually support.

## What it checks

| Check | What it flags | Why it matters |
|---|---|---|
| **S3-001/002** | Publicly readable/writable S3 buckets | Most common real-world cloud data breach vector |
| **SG-001/002** | Security groups open to `0.0.0.0/0` on sensitive ports (SSH, RDP, DB ports) | Exposed management ports get scanned within minutes |
| **IAM-001** | IAM users without MFA enabled | Password-only accounts are the #1 initial-access vector |
| **IAM-002** | IAM policies granting `Action:*` on `Resource:*` | Removes least-privilege protection account-wide |
| **EBS-001** | Unencrypted EBS volumes | Data-at-rest exposure if underlying storage is compromised |

## Quickstart (no AWS account needed)

The scanner ships with realistic **mock AWS data** so it runs end-to-end
with zero setup, zero cost, and zero credentials:

```bash
cd scanner
python main.py                        # markdown report to stdout
python main.py --format json          # JSON output
python main.py --out ../sample-output/findings-report.md
```

Sample output is already included in [`sample-output/`](sample-output/) —
see [`findings-report.md`](sample-output/findings-report.md) for what a run
looks like.

## Running against a real AWS account

```bash
pip install -r requirements.txt
python scanner/main.py --live
```

Requires AWS credentials configured (env vars, `~/.aws/credentials`, or an
assumed role) with at minimum the AWS-managed **`SecurityAudit`** policy —
this toolkit only ever reads, never writes to your account.

An optional Terraform module in [`terraform/`](terraform/) spins up a small,
intentionally misconfigured sandbox (public bucket, open security group,
unencrypted volume) so you can see the scanner catch real findings. **Only
run this in a disposable AWS account** — see the warning in `main.tf`.

## Runbooks

Every finding links to a runbook in [`runbooks/`](runbooks/) that explains,
for each issue: what it means, how to explain it to a non-technical
stakeholder, exact CLI commands to verify and fix it, and how to prevent it
recurring. This mirrors the internal knowledge-base runbooks a support/CSE
team builds from recurring ticket patterns.

- [`public-s3-bucket.md`](runbooks/public-s3-bucket.md)
- [`open-security-group.md`](runbooks/open-security-group.md)
- [`iam-no-mfa.md`](runbooks/iam-no-mfa.md)
- [`wildcard-iam-policy.md`](runbooks/wildcard-iam-policy.md)
- [`unencrypted-ebs.md`](runbooks/unencrypted-ebs.md)

## Project structure

```
aws-misconfig-triage/
├── scanner/
│   ├── main.py              # CLI entrypoint
│   ├── mock_data.py         # Realistic mock AWS API responses
│   ├── severity.py          # Shared Finding/Severity data model
│   ├── s3_checks.py
│   ├── ec2_sg_checks.py
│   ├── iam_checks.py
│   └── ebs_checks.py
├── runbooks/                 # One remediation guide per finding type
├── sample-output/            # Example report (markdown + JSON)
├── terraform/                # Optional live-AWS sandbox for testing
├── requirements.txt
└── README.md
```

## Possible extensions

- Add Azure/GCP equivalents of each check
- Add CloudTrail-based "who caused this drift and when" lookback
- Slack/email notification on new CRITICAL findings
- Wire wildcard-policy detection into `--live` mode (currently mock-only)

## License

MIT
