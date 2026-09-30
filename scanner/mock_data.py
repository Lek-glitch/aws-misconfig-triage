"""
mock_data.py

Provides mock AWS API responses shaped exactly like boto3 would return them.
This lets the scanner run end-to-end with zero AWS account / credentials,
which is useful for demos, portfolio review, and unit testing.

To run against a REAL AWS account instead: set USE_MOCK = False in main.py
and provide a boto3 session with read-only IAM permissions
(SecurityAudit managed policy is sufficient).
"""

MOCK_S3_BUCKETS = [
    {
        "Name": "orca-demo-public-assets",
        "PublicAccessBlock": {
            "BlockPublicAcls": False,
            "BlockPublicPolicy": False,
            "IgnorePublicAcls": False,
            "RestrictPublicBuckets": False,
        },
        "Grants": [{"Grantee": "AllUsers", "Permission": "READ"}],
    },
    {
        "Name": "orca-demo-customer-backups",
        "PublicAccessBlock": {
            "BlockPublicAcls": True,
            "BlockPublicPolicy": True,
            "IgnorePublicAcls": True,
            "RestrictPublicBuckets": True,
        },
        "Grants": [],
    },
    {
        "Name": "orca-demo-logs-archive",
        "PublicAccessBlock": {
            "BlockPublicAcls": False,
            "BlockPublicPolicy": True,
            "IgnorePublicAcls": False,
            "RestrictPublicBuckets": True,
        },
        "Grants": [{"Grantee": "AllUsers", "Permission": "WRITE"}],
    },
]

MOCK_SECURITY_GROUPS = [
    {
        "GroupId": "sg-0a1b2c3d",
        "GroupName": "web-sg",
        "IpPermissions": [
            {"FromPort": 22, "ToPort": 22, "IpProtocol": "tcp",
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            {"FromPort": 443, "ToPort": 443, "IpProtocol": "tcp",
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        ],
    },
    {
        "GroupId": "sg-0e4f5g6h",
        "GroupName": "db-sg",
        "IpPermissions": [
            {"FromPort": 3389, "ToPort": 3389, "IpProtocol": "tcp",
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        ],
    },
    {
        "GroupId": "sg-0i7j8k9l",
        "GroupName": "internal-sg",
        "IpPermissions": [
            {"FromPort": 5432, "ToPort": 5432, "IpProtocol": "tcp",
             "IpRanges": [{"CidrIp": "10.0.0.0/16"}]},
        ],
    },
]

MOCK_IAM_USERS = [
    {"UserName": "svc-ci-deploy", "MFADevices": [], "AccessKeyAge": 412},
    {"UserName": "priya.k", "MFADevices": ["arn:aws:iam::mfa/priya.k"], "AccessKeyAge": 30},
    {"UserName": "legacy-admin", "MFADevices": [], "AccessKeyAge": 730},
]

MOCK_IAM_POLICIES = [
    {
        "PolicyName": "FullAdminAccess-legacy",
        "AttachedTo": "legacy-admin",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    },
    {
        "PolicyName": "S3ReadOnly",
        "AttachedTo": "priya.k",
        "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": "*"}],
    },
]

MOCK_EBS_VOLUMES = [
    {"VolumeId": "vol-0abc111", "Encrypted": False, "Size": 100, "AttachedInstance": "i-0prod01"},
    {"VolumeId": "vol-0abc222", "Encrypted": True, "Size": 50, "AttachedInstance": "i-0prod02"},
    {"VolumeId": "vol-0abc333", "Encrypted": False, "Size": 20, "AttachedInstance": "i-0staging01"},
]
