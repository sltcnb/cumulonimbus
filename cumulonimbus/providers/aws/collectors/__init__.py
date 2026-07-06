"""AWS collectors registry."""

from cumulonimbus.providers.aws.collectors.cloudtrail import CloudTrailCollector
from cumulonimbus.providers.aws.collectors.guardduty import GuardDutyCollector
from cumulonimbus.providers.aws.collectors.inventory import (
    EC2Collector, IAMCollector, LambdaCollector, RDSCollector)
from cumulonimbus.providers.aws.collectors.s3logs import S3LogCollector

# API-only collectors runnable via `aws collect --service <name>`.
COLLECTORS = {
    "cloudtrail": CloudTrailCollector,
    "guardduty": GuardDutyCollector,
    "ec2": EC2Collector,
    "iam": IAMCollector,
    "lambda": LambdaCollector,
    "rds": RDSCollector,
}

__all__ = ["COLLECTORS", "S3LogCollector"]
