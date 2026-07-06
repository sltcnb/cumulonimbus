"""Importing this package registers all AWS parsers."""

from cumulonimbus.providers.aws.parsers import (  # noqa: F401
    cloudtrail, guardduty, vpcflow, s3access, inventory,
)
