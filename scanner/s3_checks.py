"""
s3_checks.py

Checks S3 buckets for public exposure — one of the most common and highest
-impact cloud misconfigurations (root cause of many real-world breaches).

Real AWS usage:
    s3 = boto3.client("s3")
    buckets = s3.list_buckets()["Buckets"]
    for b in buckets:
        pab = s3.get_public_access_block(Bucket=b["Name"])
        acl = s3.get_bucket_acl(Bucket=b["Name"])
"""

from severity import Finding, Severity


def check_public_buckets(buckets: list) -> list:
    """Flag buckets that allow public access via ACL grants or missing
    Public Access Block settings."""
    findings = []

    for bucket in buckets:
        name = bucket["Name"]
        pab = bucket.get("PublicAccessBlock", {})
        grants = bucket.get("Grants", [])

        public_grant = any(g["Grantee"] == "AllUsers" for g in grants)
        pab_disabled = not all(pab.values()) if pab else True

        if public_grant and pab_disabled:
            perms = [g["Permission"] for g in grants if g["Grantee"] == "AllUsers"]
            findings.append(Finding(
                check_id="S3-001",
                title=f"Public S3 bucket: {name}",
                severity=Severity.CRITICAL if "WRITE" in perms else Severity.HIGH,
                resource=name,
                description=(
                    f"Bucket '{name}' grants AllUsers {'/'.join(perms)} access "
                    f"and Public Access Block is not fully enabled."
                ),
                runbook="public-s3-bucket.md",
            ))
        elif public_grant and not pab_disabled:
            # PAB is on but a stale ACL grant still exists — lower severity,
            # PAB should be blocking it, but the ACL itself is bad hygiene.
            findings.append(Finding(
                check_id="S3-002",
                title=f"Stale public ACL grant (blocked by PAB): {name}",
                severity=Severity.LOW,
                resource=name,
                description=(
                    f"Bucket '{name}' has a public ACL grant, but Public "
                    f"Access Block is enabled and should be blocking it. "
                    f"Clean up the ACL anyway — PAB settings can be changed later."
                ),
                runbook="public-s3-bucket.md",
            ))

    return findings
