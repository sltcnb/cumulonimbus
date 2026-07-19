"""Azure / GCP / Kubernetes parser tests."""

import cumulonimbus.providers.azure.parsers  # noqa: F401
import cumulonimbus.providers.gcp.parsers  # noqa: F401
import cumulonimbus.providers.k8s.parsers  # noqa: F401
from cumulonimbus.core.parser import get_parser


# -- Azure --
def test_azure_activity():
    p = get_parser("azure.activity")()
    ev = p.parse_record(
        {
            "operationName": {"value": "Microsoft.Compute/virtualMachines/delete"},
            "eventTimestamp": "2024-02-01T10:00:00Z",
            "caller": "bob@contoso.com",
            "callerIpAddress": "203.0.113.9",
            "status": {"value": "Succeeded"},
            "resourceId": "/subscriptions/sub-123/resourceGroups/rg/providers/x",
        }
    ).to_ecs()
    assert ev["user"]["name"] == "bob@contoso.com"
    assert ev["cloud"]["account_id"] == "sub-123"
    assert ev["event"]["outcome"] == "success"


def test_azure_signin_failure():
    p = get_parser("azure.signin")()
    ev = p.parse_record(
        {
            "createdDateTime": "2024-02-01T10:00:00Z",
            "userPrincipalName": "eve@contoso.com",
            "ipAddress": "203.0.113.99",
            "status": {"errorCode": 50126},
            "appDisplayName": "Azure Portal",
            "location": {"countryOrRegion": "RU", "city": "Moscow"},
        }
    ).to_ecs()
    assert ev["event"]["outcome"] == "failure"
    assert ev["source"]["geo"]["country_iso_code"] == "RU"


def test_azure_nsgflow_line():
    p = get_parser("azure.nsgflow")()
    ev = p.parse_record("1706780400,10.0.0.4,203.0.113.1,443,52000,T,O,A,B,,,").to_ecs()
    assert ev["network"]["transport"] == "tcp"
    assert ev["network"]["direction"] == "outbound"
    assert ev["event"]["outcome"] == "success"


# -- GCP --
def test_gcp_audit():
    p = get_parser("gcp.audit")()
    ev = p.parse_record(
        {
            "timestamp": "2024-03-01T10:00:00Z",
            "protoPayload": {
                "methodName": "storage.objects.get",
                "authenticationInfo": {"principalEmail": "svc@proj.iam.gserviceaccount.com"},
                "requestMetadata": {"callerIp": "203.0.113.5"},
                "serviceName": "storage.googleapis.com",
                "status": {},
            },
            "resource": {"labels": {"project_id": "my-proj"}},
        }
    ).to_ecs()
    assert ev["user"]["email"].startswith("svc@")
    assert ev["cloud"]["account_id"] == "my-proj"
    assert ev["event"]["outcome"] == "success"


def test_gcp_scc():
    p = get_parser("gcp.scc")()
    ev = p.parse_record(
        {
            "finding": {
                "category": "MALWARE",
                "severity": "HIGH",
                "eventTime": "2024-03-01T10:00:00Z",
                "access": {"callerIp": "203.0.113.7"},
                "state": "ACTIVE",
            }
        }
    ).to_ecs()
    assert ev["event"]["kind"] == "alert"
    assert ev["threat"]["severity_label"] == "high"


# -- Kubernetes --
def test_k8s_audit_secret_access():
    p = get_parser("k8s.audit")()
    ev = p.parse_record(
        {
            "verb": "get",
            "requestReceivedTimestamp": "2024-04-01T10:00:00Z",
            "user": {"username": "system:anonymous"},
            "objectRef": {
                "resource": "secrets",
                "namespace": "kube-system",
                "name": "token",
                "apiVersion": "v1",
            },
            "sourceIPs": ["10.1.2.3"],
            "responseStatus": {"code": 200},
        }
    ).to_ecs()
    assert ev["user"]["name"] == "system:anonymous"
    assert ev["k8s"]["sensitive"] is True
    assert ev["source"]["ip"] == "10.1.2.3"
    assert ev["orchestrator"]["type"] == "kubernetes"
    assert ev["orchestrator"]["namespace"] == "kube-system"
    assert ev["orchestrator"]["resource"]["type"] == "secrets"


def test_k8s_audit_forbidden():
    p = get_parser("k8s.audit")()
    ev = p.parse_record(
        {
            "verb": "create",
            "objectRef": {"resource": "pods"},
            "responseStatus": {"code": 403},
            "requestReceivedTimestamp": "2024-04-01T10:00:00Z",
        }
    ).to_ecs()
    assert ev["event"]["outcome"] == "failure"


def test_k8s_event_warning():
    p = get_parser("k8s.event")()
    ev = p.parse_record(
        {
            "reason": "FailedMount",
            "type": "Warning",
            "message": "mount failed",
            "lastTimestamp": "2024-04-01T10:00:00Z",
            "involvedObject": {"kind": "Pod", "name": "web-1", "namespace": "default"},
        }
    ).to_ecs()
    assert ev["event"]["outcome"] == "failure"
    assert ev["orchestrator"]["resource"]["type"] == "pod"
    assert ev["orchestrator"]["resource"]["name"] == "web-1"


def test_k8s_container():
    p = get_parser("k8s.container")()
    ev = p.parse_record(
        {
            "name": "nginx",
            "image": "nginx:1.25",
            "containerID": "containerd://abc",
            "restartCount": 3,
            "ready": True,
            "securityContext": {"privileged": True},
            "_pod": "web-1",
            "_namespace": "prod",
            "_runtime": "containerd",
            "_host_path_mounts": ["/etc"],
        }
    ).to_ecs()
    assert ev["container"]["name"] == "nginx"
    assert ev["container"]["image"]["name"] == "nginx"
    assert ev["container"]["image"]["tag"] == ["1.25"]
    assert ev["container"]["runtime"] == "containerd"
    assert ev["k8s"]["privileged"] is True
    assert ev["k8s"]["host_path_mounts"] == ["/etc"]
    assert ev["orchestrator"]["resource"]["name"] == "web-1"


def test_k8s_etcd_secret():
    p = get_parser("k8s.etcd")()
    ev = p.parse_record(
        {
            "key": "/registry/secrets/kube-system/admin-token",
            "value": {
                "kind": "Secret",
                "apiVersion": "v1",
                "metadata": {"creationTimestamp": "2024-04-01T10:00:00Z"},
                "data": {"token": "eyJ...", "ca.crt": "..."},
            },
        }
    ).to_ecs()
    assert ev["event"]["kind"] == "state"
    assert ev["orchestrator"]["namespace"] == "kube-system"
    assert ev["orchestrator"]["resource"]["type"] == "secrets"
    assert ev["k8s"]["contains_secret_material"] is True
    assert ev["k8s"]["data_keys"] == ["ca.crt", "token"]
    assert ev["k8s"]["at_rest"] is True


# -- Kubernetes file-based collectors (no cluster) --
def test_k8s_etcd_collector(tmp_path):
    from cumulonimbus.providers.k8s.collectors import EtcdCollector

    f = tmp_path / "etcd.jsonl"
    f.write_text('{"key":"/registry/secrets/ns/s","value":{"kind":"Secret"}}\n')
    recs = list(EtcdCollector(etcd_export=str(f)).collect())
    assert recs[0]["key"].startswith("/registry/secrets")


def test_k8s_audit_collector(tmp_path):
    from cumulonimbus.providers.k8s.collectors import AuditLogCollector

    f = tmp_path / "audit.log"
    f.write_text('{"verb":"get","objectRef":{"resource":"pods"}}\n')
    n = AuditLogCollector(audit_log=str(f)).collect_to(tmp_path)
    assert n == 1
    assert (tmp_path / "k8s.audit.jsonl").exists()
