"""GCP ECS parsers.

Datasets:
  gcp.audit   — Cloud Audit Logs (AuditLog protoPayload)
  gcp.vpcflow — VPC Flow Logs (jsonPayload)
  gcp.scc     — Security Command Center findings
"""

from __future__ import annotations

from typing import Any, Optional

from cumulonimbus.core.parser import Parser, register
from cumulonimbus.ecs.schema import Cloud, Event, ForensicEvent, Host, Network, User

# Cloud Audit method names that authenticate a session.
_AUTH_METHODS = {"google.iam.credentials", "SetIamPolicy"}

# IANA protocol number -> transport name.
_TRANSPORT = {6: "tcp", 17: "udp", 1: "icmp", 58: "ipv6-icmp"}


@register("gcp.audit")
class AuditLogParser(Parser):
    def parse_record(self, r: dict[str, Any]) -> Optional[ForensicEvent]:
        payload = r.get("protoPayload") or {}
        method = payload.get("methodName")
        if not method:
            return None
        auth = payload.get("authenticationInfo") or {}
        meta = payload.get("requestMetadata") or {}
        status = payload.get("status") or {}
        labels = (r.get("resource") or {}).get("labels") or {}
        is_auth = any(k in method for k in _AUTH_METHODS)
        return ForensicEvent(
            **{"@timestamp": r.get("timestamp")},
            event=Event(action=method,
                        category=["authentication"] if is_auth else ["configuration"],
                        type=["access"] if is_auth else ["change"],
                        outcome="failure" if status.get("code") else "success",
                        provider="gcp", dataset="gcp.audit"),
            user=User(name=auth.get("principalEmail"),
                      email=auth.get("principalEmail")) if auth.get("principalEmail") else None,
            source=Host(ip=meta.get("callerIp")) if meta.get("callerIp") else None,
            cloud=Cloud(provider="gcp", account_id=labels.get("project_id"),
                        service_name=payload.get("serviceName")),
            gcp={"audit": {"method": method,
                           "resource_name": payload.get("resourceName"),
                           "caller_agent": meta.get("callerSuppliedUserAgent"),
                           "severity": r.get("severity"),
                           "status_message": status.get("message")}},
        )


@register("gcp.vpcflow")
class VPCFlowParser(Parser):
    def parse_record(self, r: dict[str, Any]) -> Optional[ForensicEvent]:
        jp = r.get("jsonPayload") or r
        conn = jp.get("connection") or {}
        if "src_ip" not in conn and "dest_ip" not in conn:
            return None
        iana = _int(conn.get("protocol"))
        return ForensicEvent(
            **{"@timestamp": r.get("timestamp") or jp.get("start_time")},
            event=Event(action="flow", category=["network"], type=["connection"],
                        provider="gcp", dataset="gcp.vpcflow"),
            source=Host(ip=conn.get("src_ip"), port=_int(conn.get("src_port"))),
            destination=Host(ip=conn.get("dest_ip"), port=_int(conn.get("dest_port"))),
            network=Network(transport=_TRANSPORT.get(iana),
                            iana_number=iana,
                            bytes=_int(jp.get("bytes_sent")),
                            packets=_int(jp.get("packets_sent"))),
            cloud=Cloud(provider="gcp"),
        )


@register("gcp.scc")
class SCCParser(Parser):
    def parse_record(self, r: dict[str, Any]) -> Optional[ForensicEvent]:
        f = r.get("finding") or r
        if "category" not in f:
            return None
        access = f.get("access") or {}
        return ForensicEvent(
            **{"@timestamp": f.get("eventTime") or f.get("createTime")},
            message=f.get("description") or f.get("category"),
            event=Event(action=f.get("category"), category=["intrusion_detection"],
                        type=["indicator"], kind="alert",
                        provider="gcp", dataset="gcp.scc"),
            source=Host(ip=access.get("callerIp")) if access.get("callerIp") else None,
            cloud=Cloud(provider="gcp", service_name="scc"),
            threat={"severity_label": (f.get("severity") or "").lower() or None,
                    "finding_class": f.get("findingClass")},
            gcp={"scc": {"name": f.get("name"), "resource": f.get("resourceName"),
                         "state": f.get("state")}},
        )


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None
