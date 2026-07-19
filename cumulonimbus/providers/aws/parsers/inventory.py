"""Asset-inventory parsers: EC2 instances, IAM principals, Lambda, RDS.

These describe cloud state rather than time-ordered activity, so they map to
ECS events with kind="state" and carry the resource under the aws.* namespace.
"""

from __future__ import annotations

from typing import Any, Optional

from cumulonimbus.core.parser import Parser, register
from cumulonimbus.ecs.schema import Cloud, Event, ForensicEvent, Host


def _state_event(dataset: str, action: str) -> Event:
    return Event(
        action=action,
        category=["configuration"],
        type=["info"],
        kind="state",
        provider="aws",
        dataset=dataset,
    )


@register("aws.ec2")
class EC2Parser(Parser):
    """A DescribeInstances Reservation.Instances[] entry."""

    def parse_record(self, record: dict[str, Any]) -> Optional[ForensicEvent]:
        iid = record.get("InstanceId")
        if not iid:
            return None
        return ForensicEvent(
            **{"@timestamp": _iso(record.get("LaunchTime"))},
            event=_state_event("aws.ec2", "DescribeInstance"),
            source=Host(ip=record.get("PublicIpAddress"))
            if record.get("PublicIpAddress")
            else None,
            cloud=Cloud(
                provider="aws", region=(record.get("Placement") or {}).get("AvailabilityZone")
            ),
            aws={
                "ec2": {
                    "instance_id": iid,
                    "instance_type": record.get("InstanceType"),
                    "state": (record.get("State") or {}).get("Name"),
                    "private_ip": record.get("PrivateIpAddress"),
                    "public_ip": record.get("PublicIpAddress"),
                    "image_id": record.get("ImageId"),
                    "vpc_id": record.get("VpcId"),
                    "subnet_id": record.get("SubnetId"),
                    "iam_profile": (record.get("IamInstanceProfile") or {}).get("Arn"),
                    "key_name": record.get("KeyName"),
                    "tags": {t["Key"]: t["Value"] for t in record.get("Tags", [])},
                }
            },
        )


@register("aws.iam")
class IAMParser(Parser):
    """A user/role dict from ListUsers / ListRoles (tagged with _resource_type)."""

    def parse_record(self, record: dict[str, Any]) -> Optional[ForensicEvent]:
        rtype = record.get("_resource_type", "user")
        name = record.get("UserName") or record.get("RoleName")
        if not name:
            return None
        return ForensicEvent(
            **{"@timestamp": _iso(record.get("CreateDate"))},
            event=_state_event("aws.iam", f"Describe{rtype.capitalize()}"),
            cloud=Cloud(provider="aws", service_name="iam"),
            aws={
                "iam": {
                    "resource_type": rtype,
                    "name": name,
                    "arn": record.get("Arn"),
                    "id": record.get("UserId") or record.get("RoleId"),
                    "path": record.get("Path"),
                    "assume_role_policy": record.get("AssumeRolePolicyDocument"),
                    "attached_policies": record.get("AttachedPolicies"),
                    "inline_policies": record.get("InlinePolicies"),
                }
            },
        )


@register("aws.lambda")
class LambdaParser(Parser):
    """A ListFunctions FunctionConfiguration entry."""

    def parse_record(self, record: dict[str, Any]) -> Optional[ForensicEvent]:
        fn = record.get("FunctionName")
        if not fn:
            return None
        return ForensicEvent(
            **{"@timestamp": record.get("LastModified")},
            event=_state_event("aws.lambda", "GetFunction"),
            cloud=Cloud(provider="aws", service_name="lambda"),
            aws={
                "lambda": {
                    "function_name": fn,
                    "arn": record.get("FunctionArn"),
                    "runtime": record.get("Runtime"),
                    "handler": record.get("Handler"),
                    "role": record.get("Role"),
                    "env": (record.get("Environment") or {}).get("Variables"),
                    "code_sha256": record.get("CodeSha256"),
                }
            },
        )


@register("aws.rds")
class RDSParser(Parser):
    """A DescribeDBInstances DBInstances[] entry."""

    def parse_record(self, record: dict[str, Any]) -> Optional[ForensicEvent]:
        db = record.get("DBInstanceIdentifier")
        if not db:
            return None
        endpoint = record.get("Endpoint") or {}
        return ForensicEvent(
            **{"@timestamp": _iso(record.get("InstanceCreateTime"))},
            event=_state_event("aws.rds", "DescribeDBInstance"),
            cloud=Cloud(provider="aws", region=record.get("AvailabilityZone")),
            aws={
                "rds": {
                    "db_instance_id": db,
                    "engine": record.get("Engine"),
                    "engine_version": record.get("EngineVersion"),
                    "endpoint": endpoint.get("Address"),
                    "port": endpoint.get("Port"),
                    "publicly_accessible": record.get("PubliclyAccessible"),
                    "storage_encrypted": record.get("StorageEncrypted"),
                    "vpc_id": (record.get("DBSubnetGroup") or {}).get("VpcId"),
                }
            },
        )


def _iso(v) -> Optional[str]:
    if v is None:
        return None
    if hasattr(v, "isoformat"):
        return v.isoformat()
    return str(v)
