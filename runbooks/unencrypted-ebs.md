# Runbook: Unencrypted EBS Volume

**Check ID:** EBS-001
**Severity:** Medium

## What it means
An EBS (Elastic Block Store) volume attached to an EC2 instance is not
encrypted at rest. If the underlying physical storage is ever
decommissioned, snapshotted improperly, or accessed outside normal AWS
API paths, the data on it is readable in plaintext.

## Why it matters (customer-facing explanation)
> "This disk volume isn't encrypted at rest. AWS encryption is free,
> has effectively no performance impact, and is considered baseline
> hygiene for any data classified as sensitive — this is also a common
> requirement in SOC 2 and similar compliance audits."

## How to verify
```bash
aws ec2 describe-volumes \
  --volume-ids <vol-id> \
  --query "Volumes[].Encrypted"
```

## Remediation steps
EBS volumes cannot be encrypted in place — you create an encrypted copy
and swap it in:

1. **Snapshot the existing volume:**
   ```bash
   aws ec2 create-snapshot --volume-id <vol-id> --description "pre-encryption snapshot"
   ```
2. **Copy the snapshot with encryption enabled:**
   ```bash
   aws ec2 copy-snapshot \
     --source-snapshot-id <snapshot-id> \
     --encrypted \
     --kms-key-id <kms-key-arn-or-alias>
   ```
3. **Create a new volume from the encrypted snapshot:**
   ```bash
   aws ec2 create-volume \
     --snapshot-id <encrypted-snapshot-id> \
     --availability-zone <az>
   ```
4. **Detach the old volume, attach the new encrypted one**, in a
   maintenance window (stop the instance first if it's the root volume).
5. **Delete the old unencrypted volume** once confirmed working.

## Prevention
- Enable **"Always encrypt new EBS volumes"** at the account/region level
  (EC2 console → Account attributes → EBS encryption). This makes
  encryption the default for all future volumes with zero extra effort.
- Add the AWS Config managed rule `encrypted-volumes` to catch drift.
