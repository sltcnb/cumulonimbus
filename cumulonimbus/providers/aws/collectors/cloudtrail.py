"""CloudTrail collector via the LookupEvents API.

Note: LookupEvents returns the full record as a JSON string in
`CloudTrailEvent`; we parse it back to a dict so raw storage matches the
S3 log-file record shape our parser expects.
"""

from __future__ import annotations

import json
from typing import Any, Iterator

from cumulonimbus.core.collector import Collector


class CloudTrailCollector(Collector):
    dataset = "aws.cloudtrail"

    def __init__(self, *, session=None, **kw):
        super().__init__(**kw)
        self._session = session

    def _client(self):
        import boto3  # deferred so boto3 stays an optional dependency

        session = self._session or boto3.Session()
        return session.client("cloudtrail", region_name=self.region)

    def collect(self) -> Iterator[dict[str, Any]]:
        client = self._client()
        paginator = client.get_paginator("lookup_events")
        kwargs: dict[str, Any] = {}
        if self.start_time:
            kwargs["StartTime"] = self.start_time
        if self.end_time:
            kwargs["EndTime"] = self.end_time
        for page in paginator.paginate(**kwargs):
            for event in page.get("Events", []):
                raw = event.get("CloudTrailEvent")
                if raw:
                    try:
                        yield json.loads(raw)
                        continue
                    except (ValueError, TypeError):
                        pass
                yield event
