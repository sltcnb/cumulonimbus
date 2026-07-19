"""GCP collectors.

Auth via Application Default Credentials or a service-account JSON key
(GOOGLE_APPLICATION_CREDENTIALS). Audit/flow logs come from Cloud Logging;
findings from Security Command Center.
"""

from __future__ import annotations

from typing import Any, Iterator

from cumulonimbus.core.collector import Collector


class _GCPCollector(Collector):
    def __init__(self, *, project: str, credentials=None, **kw):
        super().__init__(**kw)
        self.project = project
        self._credentials = credentials


class _LoggingCollector(_GCPCollector):
    log_filter = ""

    def collect(self) -> Iterator[dict[str, Any]]:
        from google.cloud import logging_v2

        client = logging_v2.Client(project=self.project, credentials=self._credentials)
        filt = [self.log_filter]
        if self.start_time:
            filt.append(f'timestamp >= "{self.start_time.isoformat()}"')
        if self.end_time:
            filt.append(f'timestamp <= "{self.end_time.isoformat()}"')
        for entry in client.list_entries(filter_=" AND ".join(f for f in filt if f)):
            yield entry.to_api_repr()


class AuditLogCollector(_LoggingCollector):
    dataset = "gcp.audit"
    log_filter = 'logName:"cloudaudit.googleapis.com"'


class VPCFlowCollector(_LoggingCollector):
    dataset = "gcp.vpcflow"
    log_filter = 'logName:"compute.googleapis.com%2Fvpc_flows"'


class SCCCollector(_GCPCollector):
    dataset = "gcp.scc"

    def collect(self) -> Iterator[dict[str, Any]]:
        from google.cloud import securitycenter

        client = securitycenter.SecurityCenterClient(credentials=self._credentials)
        parent = f"projects/{self.project}/sources/-"
        for res in client.list_findings(request={"parent": parent}):
            yield {"finding": type(res.finding).to_dict(res.finding)}


COLLECTORS = {
    "audit": AuditLogCollector,
    "vpcflow": VPCFlowCollector,
    "scc": SCCCollector,
}
