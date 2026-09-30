# Runbook: Wildcard (Action:* / Resource:*) IAM Policy

**Check ID:** IAM-002
**Severity:** Critical

## What it means
An IAM policy grants `"Action": "*"` on `"Resource": "*"` — full,
unrestricted administrative access to every service and resource in the
account. This violates the principle of least privilege and means a
single compromised credential equals a fully compromised account.

## Why it matters (customer-facing explanation)
> "This user or role currently has unrestricted admin rights over your
> entire AWS account — not just one service, everything. If this
> credential is ever compromised, an attacker has the same level of
> access as your account owner. We recommend scoping this down to only
> the specific permissions this identity actually needs."

## How to verify
```bash
aws iam list-attached-user-policies --user-name <username>
aws iam get-policy-version --policy-arn <arn> --version-id <version>
```
Look for a statement with `"Effect": "Allow", "Action": "*", "Resource": "*"`.

## Remediation steps
1. **Determine actual usage first — don't guess.** Use
   **IAM Access Analyzer** or **IAM Access Advisor**
   (`aws iam generate-service-last-accessed-details`) to see which
   services this identity has actually used in the last 90+ days.
2. **Draft a scoped policy** covering only those services/actions, using
   least-privilege principles (e.g. `s3:GetObject` on a specific bucket
   ARN, not `s3:*` on `*`).
3. **Attach the new scoped policy, test in a non-critical path**, then
   detach the wildcard policy.
4. **If this is a break-glass emergency-access role**, that's a valid use
   case — but it should require additional approval/logging (e.g. via
   AWS IAM Identity Center emergency access procedures), not be a
   standing, always-on credential.

## Prevention
- Enable **IAM Access Analyzer** account-wide to continuously flag
  overly permissive policies.
- Add a CI check (e.g. `checkov`, `cfn-nag`, or a custom OPA policy) that
  blocks any Terraform/CloudFormation PR introducing `Action: "*"` +
  `Resource: "*"` together.
- Adopt permission boundaries for any role capable of creating new IAM
  policies, to cap the blast radius even if a wildcard slips through.
