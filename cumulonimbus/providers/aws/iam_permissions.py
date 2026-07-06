"""Minimum IAM policy required by the AWS collectors."""

POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "CloudTrailReadOnly",
            "Effect": "Allow",
            "Action": [
                "cloudtrail:LookupEvents",
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetTrailStatus",
            ],
            "Resource": "*",
        },
        {
            "Sid": "GuardDutyReadOnly",
            "Effect": "Allow",
            "Action": [
                "guardduty:ListDetectors",
                "guardduty:ListFindings",
                "guardduty:GetFindings",
            ],
            "Resource": "*",
        },
        {
            "Sid": "VPCFlowReadOnly",
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeFlowLogs",
                "ec2:DescribeVpcs",
                "ec2:DescribeSubnets",
            ],
            "Resource": "*",
        },
        {
            "Sid": "S3ReadOnly",
            "Effect": "Allow",
            "Action": ["s3:GetBucketLocation", "s3:ListBucket", "s3:GetObject"],
            "Resource": "*",
        },
        {
            "Sid": "InventoryReadOnly",
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "iam:ListUsers",
                "iam:ListRoles",
                "iam:ListAttachedUserPolicies",
                "lambda:ListFunctions",
                "rds:DescribeDBInstances",
            ],
            "Resource": "*",
        },
    ],
}
