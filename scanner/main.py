#!/usr/bin/env python3
"""
main.py — AWS Misconfig Triage Toolkit

A lightweight CLI that scans an AWS account for common misconfigurations
(the same categories a CNAPP platform flags), and produces a prioritized,
customer-readable findings report with linked remediation runbooks.

Usage:
    python main.py                 # run against mock data (no AWS account needed)
    python main.py --format json   # output JSON instead of markdown
    python main.py --live          # run against a real AWS account via boto3
                                    #   (requires AWS credentials + read-only
                                    #    SecurityAudit IAM policy attached)

Why mock mode exists:
    This project is meant to demo the *triage workflow* — running a scan,
    prioritizing findings by severity, and handing off clear remediation
    steps — without requiring a live AWS account or incurring any cost.
    Swap USE_MOCK for --live to point it at a real account.
"""

import argparse
import json
import sys
from datetime import datetime, timezone

from severity import Severity
from s3_checks import check_public_buckets
from ec2_sg_checks import check_open_security_groups
from iam_checks import check_mfa, check_wildcard_policies
from ebs_checks import check_unencrypted_volumes

import mock_data


def get_live_data():
    """Fetch real AWS data via boto3. Requires credentials configured
    (env vars, ~/.aws/credentials, or an assumed role) with at minimum
    the AWS-managed 'SecurityAudit' policy attached."""
    try:
        import boto3
    except ImportError:
        sys.exit("boto3 is required for --live mode. Install with: pip install boto3")

    s3 = boto3.client("s3")
    ec2 = boto3.client("ec2")
    iam = boto3.client("iam")

    buckets = []
    for b in s3.list_buckets()["Buckets"]:
        name = b["Name"]
        try:
            pab = s3.get_bucket_policy_status(Bucket=name)
            acl = s3.get_bucket_acl(Bucket=name)
            grants = [
                {"Grantee": "AllUsers", "Permission": g["Permission"]}
                for g in acl["Grants"]
                if "URI" in g.get("Grantee", {}) and "AllUsers" in g["Grantee"]["URI"]
            ]
            buckets.append({
                "Name": name,
                "PublicAccessBlock": {"RestrictPublicBuckets": not pab["PolicyStatus"]["IsPublic"]},
                "Grants": grants,
            })
        except Exception as e:
            print(f"  [warn] could not inspect bucket {name}: {e}", file=sys.stderr)

    sgs = ec2.describe_security_groups()["SecurityGroups"]

    users = []
    for u in iam.list_users()["Users"]:
        mfa = iam.list_mfa_devices(UserName=u["UserName"])["MFADevices"]
        users.append({"UserName": u["UserName"], "MFADevices": mfa, "AccessKeyAge": 0})

    volumes = ec2.describe_volumes()["Volumes"]

    # Wildcard policy check against live IAM policy documents is intentionally
    # left as an exercise — requires iterating attached + inline policies and
    # url-decoding policy documents. Kept simple here for the mock demo.
    policies = []

    return buckets, sgs, users, policies, volumes


def get_mock_data():
    return (
        mock_data.MOCK_S3_BUCKETS,
        mock_data.MOCK_SECURITY_GROUPS,
        mock_data.MOCK_IAM_USERS,
        mock_data.MOCK_IAM_POLICIES,
        mock_data.MOCK_EBS_VOLUMES,
    )


def run_all_checks(buckets, sgs, users, policies, volumes):
    findings = []
    findings += check_public_buckets(buckets)
    findings += check_open_security_groups(sgs)
    findings += check_mfa(users)
    findings += check_wildcard_policies(policies)
    findings += check_unencrypted_volumes(volumes)
    # Sort by severity, most critical first
    findings.sort(key=lambda f: f.severity.value, reverse=True)
    return findings


def render_markdown(findings, source_label):
    lines = [
        "# AWS Misconfiguration Findings Report",
        "",
        f"**Scan source:** {source_label}  ",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  ",
        f"**Total findings:** {len(findings)}",
        "",
        "| Severity | Check ID | Finding | Resource |",
        "|----------|----------|---------|----------|",
    ]
    for f in findings:
        lines.append(f"| {f.severity} | {f.check_id} | {f.title} | `{f.resource}` |")

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Details & Remediation")
    lines.append("")

    for f in findings:
        lines.append(f"### [{f.severity}] {f.title}")
        lines.append(f"- **Check ID:** {f.check_id}")
        lines.append(f"- **Resource:** `{f.resource}`")
        lines.append(f"- **Description:** {f.description}")
        if f.runbook:
            lines.append(f"- **Runbook:** [`runbooks/{f.runbook}`](../runbooks/{f.runbook})")
        lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="AWS Misconfig Triage Toolkit")
    parser.add_argument("--live", action="store_true", help="Scan a real AWS account via boto3")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    parser.add_argument("--out", default=None, help="Write report to file instead of stdout")
    args = parser.parse_args()

    if args.live:
        print("Running live scan against AWS account...", file=sys.stderr)
        buckets, sgs, users, policies, volumes = get_live_data()
        source_label = "Live AWS account"
    else:
        print("Running scan against mock data (no AWS account required)...", file=sys.stderr)
        buckets, sgs, users, policies, volumes = get_mock_data()
        source_label = "Mock data (demo mode)"

    findings = run_all_checks(buckets, sgs, users, policies, volumes)

    if args.format == "json":
        output = json.dumps({
            "source": source_label,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(findings),
            "findings": [f.to_dict() for f in findings],
        }, indent=2)
    else:
        output = render_markdown(findings, source_label)

    if args.out:
        with open(args.out, "w") as fh:
            fh.write(output)
        print(f"Report written to {args.out}", file=sys.stderr)
    else:
        print(output)

    # Non-zero exit if any CRITICAL findings — useful for CI pipelines
    if any(f.severity == Severity.CRITICAL for f in findings):
        sys.exit(1)


if __name__ == "__main__":
    main()
