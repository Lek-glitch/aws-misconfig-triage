"""
ebs_checks.py

Checks EBS volumes for missing encryption at rest.

Real AWS usage:
    ec2 = boto3.client("ec2")
    volumes = ec2.describe_volumes()["Volumes"]
"""

from severity import Finding, Severity


def check_unencrypted_volumes(volumes: list) -> list:
    """Flag EBS volumes that are not encrypted."""
    findings = []

    for vol in volumes:
        if not vol.get("Encrypted", False):
            findings.append(Finding(
                check_id="EBS-001",
                title=f"Unencrypted EBS volume: {vol['VolumeId']}",
                severity=Severity.MEDIUM,
                resource=vol["VolumeId"],
                description=(
                    f"Volume '{vol['VolumeId']}' ({vol.get('Size', '?')} GiB), attached to "
                    f"{vol.get('AttachedInstance', 'unknown instance')}, is not encrypted. "
                    f"Data at rest is not protected if the underlying storage is compromised."
                ),
                runbook="unencrypted-ebs.md",
            ))

    return findings
