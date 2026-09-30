# Runbook: IAM User Without MFA

**Check ID:** IAM-001
**Severity:** High (access key older than 1 year) / Medium (newer key)

## What it means
An IAM user (human or service account) has no Multi-Factor Authentication
device registered. If that user's password or access keys are ever
phished, leaked in a git commit, or reused from another breached site,
there is nothing stopping an attacker from authenticating as that user.

## Why it matters (customer-facing explanation)
> "This account can currently sign in with just a password (or access
> key) — no second factor. Password-only accounts are the single most
> common way attackers gain their first foothold in a cloud environment.
> Enabling MFA takes about two minutes and blocks the vast majority of
> credential-based attacks."

## How to verify
```bash
aws iam list-mfa-devices --user-name <username>
# Empty result = no MFA registered
```

## Remediation steps
1. **For human users:**
   - Have the user enable MFA in the AWS Console
     (IAM → Users → Security credentials → Assign MFA device), using a
     virtual authenticator app (Google Authenticator, Authy) or hardware
     key.
   - Optionally enforce this account-wide with an IAM policy that denies
     all actions unless MFA is present:
     ```json
     {
       "Effect": "Deny",
       "NotAction": ["iam:CreateVirtualMFADevice", "iam:EnableMFADevice", "sts:GetSessionToken"],
       "Resource": "*",
       "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}}
     }
     ```
2. **For service/CI accounts** (which can't use interactive MFA):
   - These should not be long-lived IAM users at all. Migrate to an
     **IAM Role** assumed via `sts:AssumeRole` (for CI/CD, use OIDC
     federation, e.g. GitHub Actions OIDC → AWS role, rather than static
     access keys).
   - If a static key is unavoidable short-term, rotate it on a strict
     schedule (≤ 90 days) and scope its permissions to the minimum needed.
3. **Rotate any access key older than the age flagged** in the finding,
   regardless of MFA status — old, unrotated keys are themselves a risk.

## Prevention
- Enable the AWS Config managed rule `iam-user-mfa-enabled`.
- Periodically run `aws iam generate-credential-report` to catch drift
  across the whole account, not just newly created users.
