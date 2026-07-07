"""Mock-based tests for the SDK-backed collectors (Azure / GCP / Kubernetes).

The provider SDKs are deferred imports inside collect(); we inject fake modules
into sys.modules so the collect() → raw-dict path is exercised without any real
SDK or cloud. Verifies each collector's iteration/pagination shape and that
`collect_to` streams records to disk.
"""

import sys
import types

import cumulonimbus.providers.aws.parsers  # noqa: F401  (registers parsers)
import cumulonimbus.providers.azure.parsers  # noqa: F401
import cumulonimbus.providers.gcp.parsers  # noqa: F401
from cumulonimbus.core.parser import get_parser


def _mod(monkeypatch, dotted: str) -> types.ModuleType:
    """Register a fake module (and all parent packages) in sys.modules."""
    parts = dotted.split(".")
    for i in range(1, len(parts) + 1):
        name = ".".join(parts[:i])
        if name not in sys.modules:
            monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    return sys.modules[dotted]


# ── Azure ──
def test_azure_activity_collector(monkeypatch, tmp_path):
    from cumulonimbus.providers.azure.collectors import ActivityLogCollector

    class FakeEntry:
        def as_dict(self):
            return {"operationName": {"value": "Microsoft.Compute/x/delete"},
                    "eventTimestamp": "2024-02-01T10:00:00Z", "caller": "bob",
                    "status": {"value": "Succeeded"},
                    "resourceId": "/subscriptions/sub-9/rg/x"}

    class FakeClient:
        def __init__(self, cred, sub):
            self.activity_logs = types.SimpleNamespace(
                list=lambda filter=None: iter([FakeEntry()]))

    mod = _mod(monkeypatch, "azure.mgmt.monitor")
    mod.MonitorManagementClient = FakeClient

    c = ActivityLogCollector(credential=object(), subscription_id="sub-9")
    recs = list(c.collect())
    assert recs[0]["caller"] == "bob"
    ev = get_parser("azure.activity")().parse_record(recs[0]).to_ecs()
    assert ev["cloud"]["account_id"] == "sub-9"


def test_azure_signin_collector_paginates(monkeypatch):
    from cumulonimbus.providers.azure.collectors import SignInCollector

    pages = {
        "https://graph.microsoft.com/v1.0/auditLogs/signIns": {
            "value": [{"userPrincipalName": "a@x"}],
            "@odata.nextLink": "https://graph.microsoft.com/next"},
        "https://graph.microsoft.com/next": {"value": [{"userPrincipalName": "b@x"}]},
    }

    class FakeResp:
        def __init__(self, url):
            self._url = url
        def raise_for_status(self):
            pass
        def json(self):
            return pages[self._url]

    requests_mod = _mod(monkeypatch, "requests")
    requests_mod.get = lambda url, headers=None, timeout=None: FakeResp(url)

    cred = types.SimpleNamespace(
        get_token=lambda scope: types.SimpleNamespace(token="t"))
    recs = list(SignInCollector(credential=cred).collect())
    assert [r["userPrincipalName"] for r in recs] == ["a@x", "b@x"]


# ── GCP ──
def test_gcp_audit_collector(monkeypatch, tmp_path):
    from cumulonimbus.providers.gcp.collectors import AuditLogCollector

    class FakeEntry:
        def to_api_repr(self):
            return {"timestamp": "2024-03-01T10:00:00Z",
                    "protoPayload": {"methodName": "storage.objects.get",
                                     "authenticationInfo": {"principalEmail": "s@x"},
                                     "status": {}},
                    "resource": {"labels": {"project_id": "p1"}}}

    class FakeClient:
        def __init__(self, project=None, credentials=None):
            pass
        def list_entries(self, filter_=None):
            return iter([FakeEntry()])

    mod = _mod(monkeypatch, "google.cloud.logging_v2")
    mod.Client = FakeClient

    c = AuditLogCollector(project="p1", credentials=object())
    n = c.collect_to(tmp_path)
    assert n == 1
    assert (tmp_path / "gcp.audit.jsonl").exists()


def test_gcp_scc_collector(monkeypatch):
    from cumulonimbus.providers.gcp.collectors import SCCCollector

    class Finding:
        category = "MALWARE"

        @staticmethod
        def to_dict(x):
            return {"category": "MALWARE", "severity": "HIGH"}

    class FakeResult:
        finding = Finding()

    class FakeSCC:
        def __init__(self, credentials=None):
            pass
        def list_findings(self, request=None):
            return iter([FakeResult()])

    mod = _mod(monkeypatch, "google.cloud.securitycenter")
    mod.SecurityCenterClient = FakeSCC

    recs = list(SCCCollector(project="p1", credentials=object()).collect())
    assert recs[0]["finding"]["category"] == "MALWARE"


# ── Kubernetes ──
def test_k8s_event_collector(monkeypatch):
    from cumulonimbus.providers.k8s.collectors import EventCollector

    event_obj = object()

    class FakeCoreV1:
        def list_event_for_all_namespaces(self):
            return types.SimpleNamespace(items=[event_obj])

    class FakeApiClient:
        def sanitize_for_serialization(self, o):
            return {"reason": "FailedMount", "type": "Warning",
                    "involvedObject": {"kind": "Pod", "name": "web"}}

    kmod = _mod(monkeypatch, "kubernetes")
    kmod.client = types.SimpleNamespace(CoreV1Api=FakeCoreV1, ApiClient=FakeApiClient)
    kmod.config = types.SimpleNamespace(
        load_kube_config=lambda config_file=None: None,
        load_incluster_config=lambda: None)

    recs = list(EventCollector(kubeconfig="/dev/null").collect())
    assert recs[0]["reason"] == "FailedMount"
