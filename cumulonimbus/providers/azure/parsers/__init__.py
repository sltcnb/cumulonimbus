"""Azure ECS parsers.

Datasets:
  azure.activity  — Azure Monitor Activity Log (control-plane operations)
  azure.signin    — Entra ID (Azure AD) sign-in logs
  azure.audit     — Entra ID audit logs
  azure.nsgflow   — NSG flow logs (v2 tuple format)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from cumulonimbus.core.parser import Parser, register
from cumulonimbus.ecs.schema import Cloud, Event, ForensicEvent, Host, User


def _sub_from_resource_id(rid: Optional[str]) -> Optional[str]:
    if rid and "/subscriptions/" in rid:
        try:
            return rid.split("/subscriptions/")[1].split("/")[0]
        except IndexError:
            return None
    return None


@register("azure.activity")
class ActivityLogParser(Parser):
    def parse_record(self, r: dict[str, Any]) -> Optional[ForensicEvent]:
        op = (r.get("operationName") or {})
        op_name = op.get("value") if isinstance(op, dict) else op
        if not op_name:
            return None
        status = (r.get("status") or {})
        status_val = status.get("value") if isinstance(status, dict) else status
        rid = r.get("resourceId")
        ip = r.get("callerIpAddress")
        return ForensicEvent(
            **{"@timestamp": r.get("eventTimestamp") or r.get("time")},
            event=Event(action=op_name, category=["configuration"], type=["change"],
                        outcome="success" if status_val in ("Succeeded", "Success") else
                        ("failure" if status_val in ("Failed", "Failure") else None),
                        provider="azure", dataset="azure.activity"),
            user=User(name=r.get("caller")) if r.get("caller") else None,
            source=Host(ip=ip) if ip else None,
            cloud=Cloud(provider="azure", account_id=_sub_from_resource_id(rid),
                        service_name=(r.get("resourceProviderName") or {}).get("value")
                        if isinstance(r.get("resourceProviderName"), dict) else None),
            azure={"activity": {"operation": op_name, "resource_id": rid,
                                "level": r.get("level"),
                                "correlation_id": r.get("correlationId")}},
        )


@register("azure.signin")
class SignInParser(Parser):
    def parse_record(self, r: dict[str, Any]) -> Optional[ForensicEvent]:
        upn = r.get("userPrincipalName") or r.get("userDisplayName")
        if not upn and "createdDateTime" not in r:
            return None
        status = r.get("status") or {}
        err = status.get("errorCode")
        loc = r.get("location") or {}
        return ForensicEvent(
            **{"@timestamp": r.get("createdDateTime")},
            event=Event(action="SignIn", category=["authentication"], type=["start"],
                        outcome="success" if err in (0, "0", None) else "failure",
                        provider="azure", dataset="azure.signin"),
            user=User(name=upn, id=r.get("userId"), email=upn),
            source=Host(ip=r.get("ipAddress"),
                        geo=_geo(loc)) if r.get("ipAddress") else None,
            cloud=Cloud(provider="azure", account_id=r.get("tenantId"),
                        service_name="entra-id"),
            azure={"signin": {"app": r.get("appDisplayName"),
                              "client_app": r.get("clientAppUsed"),
                              "error_code": err,
                              "conditional_access": r.get("conditionalAccessStatus"),
                              "device": (r.get("deviceDetail") or {}).get("operatingSystem")}},
        )


@register("azure.audit")
class AuditLogParser(Parser):
    def parse_record(self, r: dict[str, Any]) -> Optional[ForensicEvent]:
        activity = r.get("activityDisplayName")
        if not activity:
            return None
        initiator = (((r.get("initiatedBy") or {}).get("user") or {}).get("userPrincipalName")
                     or ((r.get("initiatedBy") or {}).get("app") or {}).get("displayName"))
        return ForensicEvent(
            **{"@timestamp": r.get("activityDateTime")},
            event=Event(action=activity, category=["iam"], type=["change"],
                        outcome="success" if r.get("result") == "success" else
                        ("failure" if r.get("result") else None),
                        provider="azure", dataset="azure.audit"),
            user=User(name=initiator) if initiator else None,
            cloud=Cloud(provider="azure", service_name="entra-id"),
            azure={"audit": {"category": r.get("category"),
                             "target_resources": r.get("targetResources"),
                             "result_reason": r.get("resultReason")}},
        )


_PROTO = {"T": "tcp", "U": "udp"}


@register("azure.nsgflow")
class NSGFlowParser(Parser):
    """NSG flow tuple: time,srcIp,dstIp,srcPort,dstPort,proto,dir,decision,state,..."""

    def parse_record(self, record: Any) -> Optional[ForensicEvent]:
        if isinstance(record, str):
            parts = record.split(",")
            if len(parts) < 8:
                return None
            ts, s_ip, d_ip, s_p, d_p, proto, direction, decision = parts[:8]
        elif isinstance(record, dict):
            ts = record.get("time")
            s_ip = record.get("srcIp")
            d_ip = record.get("dstIp")
            s_p = record.get("srcPort")
            d_p = record.get("dstPort")
            proto = record.get("protocol")
            direction = record.get("direction")
            decision = record.get("decision")
        else:
            return None
        from cumulonimbus.ecs.schema import Network
        iso = None
        try:
            iso = datetime.fromtimestamp(int(ts), tz=timezone.utc).isoformat()
        except (TypeError, ValueError):
            iso = ts if isinstance(ts, str) else None
        return ForensicEvent(
            **{"@timestamp": iso},
            event=Event(action=decision, category=["network"], type=["connection"],
                        outcome="success" if decision == "A" else
                        ("denied" if decision == "D" else None),
                        provider="azure", dataset="azure.nsgflow"),
            source=Host(ip=s_ip or None, port=_int(s_p)),
            destination=Host(ip=d_ip or None, port=_int(d_p)),
            network=Network(transport=_PROTO.get(proto, proto),
                            direction={"I": "inbound", "O": "outbound"}.get(direction)),
            cloud=Cloud(provider="azure"),
        )


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _geo(loc: dict):
    from cumulonimbus.ecs.schema import Geo
    if not loc:
        return None
    return Geo(country_iso_code=loc.get("countryOrRegion"),
               city_name=loc.get("city"))
