"""
ec2_sg_checks.py

Checks EC2 Security Groups for overly permissive inbound rules,
specifically sensitive management ports open to the entire internet.

Real AWS usage:
    ec2 = boto3.client("ec2")
    sgs = ec2.describe_security_groups()["SecurityGroups"]
"""

from severity import Finding, Severity

SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    27017: "MongoDB",
    6379: "Redis",
}

OPEN_CIDR = "0.0.0.0/0"


def check_open_security_groups(security_groups: list) -> list:
    """Flag security groups exposing sensitive ports to 0.0.0.0/0."""
    findings = []

    for sg in security_groups:
        for rule in sg.get("IpPermissions", []):
            port = rule.get("FromPort")
            is_open = any(r["CidrIp"] == OPEN_CIDR for r in rule.get("IpRanges", []))

            if not is_open:
                continue

            if port in SENSITIVE_PORTS:
                findings.append(Finding(
                    check_id="SG-001",
                    title=f"{SENSITIVE_PORTS[port]} open to internet: {sg['GroupName']}",
                    severity=Severity.CRITICAL,
                    resource=sg["GroupId"],
                    description=(
                        f"Security group '{sg['GroupName']}' ({sg['GroupId']}) allows "
                        f"inbound {SENSITIVE_PORTS[port]} (port {port}) from {OPEN_CIDR}. "
                        f"This port is commonly targeted by automated scanners within minutes "
                        f"of exposure."
                    ),
                    runbook="open-security-group.md",
                ))
            else:
                findings.append(Finding(
                    check_id="SG-002",
                    title=f"Port {port} open to internet: {sg['GroupName']}",
                    severity=Severity.MEDIUM,
                    resource=sg["GroupId"],
                    description=(
                        f"Security group '{sg['GroupName']}' ({sg['GroupId']}) allows "
                        f"inbound traffic on port {port} from {OPEN_CIDR}. Confirm this "
                        f"is intentional (e.g. a public web server on 443)."
                    ),
                    runbook="open-security-group.md",
                ))

    return findings
