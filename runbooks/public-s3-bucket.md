# Runbook: Public S3 Bucket

**Check IDs:** S3-001, S3-002
**Severity:** Critical (write access) / High (read access) / Low (stale ACL blocked by PAB)

## What it means
An S3 bucket allows the `AllUsers` group — meaning literally anyone on the
internet, unauthenticated — to read or write objects in it. This is one of
the most common causes of real-world cloud data breaches (misconfigured
buckets have exposed everything from customer PII to source code and
credentials).

## Why it matters (customer-facing explanation)
> "This storage bucket is currently open to the public internet. Anyone who
> finds or guesses its name can [read / upload] files, with no login
> required. If the bucket contains customer data, credentials, or backups,
> this is a data exposure risk that could lead to a breach or compliance
> violation (GDPR, HIPAA, SOC 2, etc.)."

## How to verify
```bash
# Check Public Access Block status
aws s3api get-public-access-block --bucket <bucket-name>

# Check bucket ACL for public grants
aws s3api get-bucket-acl --bucket <bucket-name>

# Check bucket policy for public statements
aws s3api get-bucket-policy --bucket <bucket-name>
```

## Remediation steps
1. **Enable Public Access Block (do this first, it's the fastest fix):**
   ```bash
   aws s3api put-public-access-block \
     --bucket <bucket-name> \
     --public-access-block-configuration \
       BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
   ```
2. **Remove the public ACL grant** (if PAB doesn't already strip it):
   ```bash
   aws s3api put-bucket-acl --bucket <bucket-name> --acl private
   ```
3. **Review the bucket policy** for any `"Principal": "*"` statements and
   remove or scope them to specific accounts/roles.
4. **If public access is actually required** (e.g. a static website bucket),
   scope it narrowly: enable it only via CloudFront with Origin Access
   Control, never via direct public bucket access.
5. **Audit what was exposed.** Check `S3 Server Access Logs` or
   `CloudTrail` data events for the bucket to see if the public window was
   accessed by unexpected IPs before remediation.

## Prevention
- Enable **S3 Block Public Access at the account level**, not just per-bucket.
- Add an **AWS Config rule** (`s3-bucket-public-read-prohibited`,
  `s3-bucket-public-write-prohibited`) to alert automatically on drift.
- Bake this check into CI/CD if buckets are created via Terraform/CloudFormation.
