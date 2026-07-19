"""Azure collectors.

Auth uses azure-identity's DefaultAzureCredential (env vars, managed identity,
Azure CLI, etc.). Sign-in/audit logs come from Microsoft Graph; Activity Log
from azure-mgmt-monitor.
"""

from __future__ import annotations

from typing import Any, Iterator

from cumulonimbus.core.collector import Collector


class _AzureCollector(Collector):
    def __init__(self, *, credential=None, subscription_id=None, tenant_id=None, **kw):
        super().__init__(**kw)
        self._credential = credential
        self.subscription_id = subscription_id
        self.tenant_id = tenant_id

    def _cred(self):
        if self._credential:
            return self._credential
        from azure.identity import DefaultAzureCredential

        return DefaultAzureCredential()


class ActivityLogCollector(_AzureCollector):
    dataset = "azure.activity"

    def collect(self) -> Iterator[dict[str, Any]]:
        from azure.mgmt.monitor import MonitorManagementClient

        client = MonitorManagementClient(self._cred(), self.subscription_id)
        filt = []
        if self.start_time:
            filt.append(f"eventTimestamp ge '{self.start_time.isoformat()}'")
        if self.end_time:
            filt.append(f"eventTimestamp le '{self.end_time.isoformat()}'")
        for ev in client.activity_logs.list(filter=" and ".join(filt) or None):
            yield ev.as_dict()


class _GraphCollector(_AzureCollector):
    graph_path = ""

    def collect(self) -> Iterator[dict[str, Any]]:
        import requests

        token = self._cred().get_token("https://graph.microsoft.com/.default").token
        url = f"https://graph.microsoft.com/v1.0/{self.graph_path}"
        headers = {"Authorization": f"Bearer {token}"}
        while url:
            resp = requests.get(url, headers=headers, timeout=60)
            resp.raise_for_status()
            data = resp.json()
            yield from data.get("value", [])
            url = data.get("@odata.nextLink")


class SignInCollector(_GraphCollector):
    dataset = "azure.signin"
    graph_path = "auditLogs/signIns"


class AuditCollector(_GraphCollector):
    dataset = "azure.audit"
    graph_path = "auditLogs/directoryAudits"


COLLECTORS = {
    "activity": ActivityLogCollector,
    "signin": SignInCollector,
    "audit": AuditCollector,
}
