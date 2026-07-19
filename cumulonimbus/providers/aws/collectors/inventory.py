"""AWS inventory collectors: EC2, IAM, Lambda, RDS."""

from __future__ import annotations

from typing import Any, Iterator

from cumulonimbus.core.collector import Collector


class _AwsCollector(Collector):
    service: str = ""

    def __init__(self, *, session=None, **kw):
        super().__init__(**kw)
        self._session = session

    def _client(self):
        import boto3

        session = self._session or boto3.Session()
        return session.client(self.service, region_name=self.region)


class EC2Collector(_AwsCollector):
    dataset = "aws.ec2"
    service = "ec2"

    def collect(self) -> Iterator[dict[str, Any]]:
        paginator = self._client().get_paginator("describe_instances")
        for page in paginator.paginate():
            for res in page.get("Reservations", []):
                yield from res.get("Instances", [])


class IAMCollector(_AwsCollector):
    dataset = "aws.iam"
    service = "iam"

    def collect(self) -> Iterator[dict[str, Any]]:
        client = self._client()
        for page in client.get_paginator("list_users").paginate():
            for u in page.get("Users", []):
                u["_resource_type"] = "user"
                u["AttachedPolicies"] = client.list_attached_user_policies(
                    UserName=u["UserName"]
                ).get("AttachedPolicies")
                yield u
        for page in client.get_paginator("list_roles").paginate():
            for r in page.get("Roles", []):
                r["_resource_type"] = "role"
                yield r


class LambdaCollector(_AwsCollector):
    dataset = "aws.lambda"
    service = "lambda"

    def collect(self) -> Iterator[dict[str, Any]]:
        for page in self._client().get_paginator("list_functions").paginate():
            yield from page.get("Functions", [])


class RDSCollector(_AwsCollector):
    dataset = "aws.rds"
    service = "rds"

    def collect(self) -> Iterator[dict[str, Any]]:
        for page in self._client().get_paginator("describe_db_instances").paginate():
            yield from page.get("DBInstances", [])
