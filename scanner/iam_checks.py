"""
iam_checks.py

Checks IAM users and policies for common identity misconfigurations:
missing MFA and overly permissive ("*:*") policies.

Real AWS usage:
    iam = boto3.client("iam")
    users = iam.list_users()["Users"]
    for u in users:
        mfa = iam.list_mfa_devices(UserName=u["UserName"])
"""

from severity import Finding, Severity


def check_mfa(users: list) -> list:
    """Flag IAM users without MFA enabled."""
    findings = []

    for user in users:
        if not user.get("MFADevices"):
            age = user.get("AccessKeyAge", 0)
            severity = Severity.HIGH if age > 365 else Severity.MEDIUM
            findings.append(Finding(
                check_id="IAM-001",
                title=f"IAM user without MFA: {user['UserName']}",
                severity=severity,
                resource=user["UserName"],
                description=(
                    f"User '{user['UserName']}' has no MFA device registered. "
                    f"Access key age: {age} days."
                ),
                runbook="iam-no-mfa.md",
            ))

    return findings


def check_wildcard_policies(policies: list) -> list:
    """Flag IAM policies granting Action:* on Resource:* (full admin)."""
    findings = []

    for policy in policies:
        for stmt in policy.get("Statement", []):
            action = stmt.get("Action")
            resource = stmt.get("Resource")
            is_wildcard_action = action == "*" or (isinstance(action, list) and "*" in action)
            is_wildcard_resource = resource == "*"

            if stmt.get("Effect") == "Allow" and is_wildcard_action and is_wildcard_resource:
                findings.append(Finding(
                    check_id="IAM-002",
                    title=f"Wildcard admin policy: {policy['PolicyName']}",
                    severity=Severity.CRITICAL,
                    resource=policy.get("AttachedTo", policy["PolicyName"]),
                    description=(
                        f"Policy '{policy['PolicyName']}' attached to "
                        f"'{policy.get('AttachedTo', 'unknown')}' grants Action:* on "
                        f"Resource:* — equivalent to full account admin access."
                    ),
                    runbook="wildcard-iam-policy.md",
                ))

    return findings
