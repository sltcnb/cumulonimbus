"""GuardDuty collector — enumerate detectors, page findings."""

from __future__ import annotations

from typing import Any, Iterator

from cumulonimbus.core.collector import Collector


class GuardDutyCollector(Collector):
    dataset = "aws.guardduty"

    def __init__(self, *, session=None, **kw):
        super().__init__(**kw)
        self._session = session

    def _client(self):
        import boto3
        session = self._session or boto3.Session()
        return session.client("guardduty", region_name=self.region)

    def collect(self) -> Iterator[dict[str, Any]]:
        client = self._client()
        detectors = client.list_detectors().get("DetectorIds", [])
        for detector_id in detectors:
            finding_ids: list[str] = []
            paginator = client.get_paginator("list_findings")
            for page in paginator.paginate(DetectorId=detector_id):
                finding_ids.extend(page.get("FindingIds", []))
            # get_findings caps at 50 ids per call
            for i in range(0, len(finding_ids), 50):
                batch = finding_ids[i:i + 50]
                if not batch:
                    continue
                resp = client.get_findings(DetectorId=detector_id, FindingIds=batch)
                yield from resp.get("Findings", [])
