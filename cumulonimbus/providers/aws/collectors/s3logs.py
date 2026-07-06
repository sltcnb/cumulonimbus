"""S3 log collector — download objects under a bucket/prefix as raw lines.

Used to pull S3 server-access logs or VPC Flow logs delivered to S3. Each line
of each object becomes one raw record (a string), matching what the s3access /
vpcflow line parsers expect.
"""

from __future__ import annotations

import gzip
from typing import Any, Iterator

from cumulonimbus.core.collector import Collector


class S3LogCollector(Collector):
    def __init__(self, *, bucket: str, prefix: str = "", dataset: str = "aws.s3access",
                 session=None, **kw):
        super().__init__(**kw)
        self.bucket = bucket
        self.prefix = prefix
        self.dataset = dataset
        self._session = session

    def _client(self):
        import boto3
        session = self._session or boto3.Session()
        return session.client("s3", region_name=self.region)

    def collect(self) -> Iterator[dict[str, Any]]:
        client = self._client()
        paginator = client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=self.prefix):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                body = client.get_object(Bucket=self.bucket, Key=key)["Body"].read()
                if key.endswith(".gz"):
                    body = gzip.decompress(body)
                for line in body.decode("utf-8", "replace").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        # yield the raw string; line parsers accept str records
                        yield line  # type: ignore[misc]
