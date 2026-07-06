"""GuardDuty finding -> ForensicEvent (threat.* fields)."""

from __future__ import annotations

from typing import Any, Optional

from cumulonimbus.core.parser import Parser, register
from cumulonimbus.ecs.schema import Cloud, Event, ForensicEvent, Host


def _severity_label(sev) -> Optional[str]:
    try:
        sev = float(sev)
    except (TypeError, ValueError):
        return None
    if sev >= 7:
        return "high"
    if sev >= 4:
        return "medium"
    return "low"


@register("aws.guardduty")
class GuardDutyParser(Parser):
    def parse_record(self, record: dict[str, Any]) -> Optional[ForensicEvent]:
        if "Type" not in record:
            return None
        service = record.get("Service") or {}
        action = service.get("Action") or {}
        remote_ip = (
            ((action.get("NetworkConnectionAction") or {})
                   .get("RemoteIpDetails") or {}).get("IpAddressV4")
            or ((action.get("AwsApiCallAction") or {})
                      .get("RemoteIpDetails") or {}).get("IpAddressV4"))

        return ForensicEvent(
            **{"@timestamp": record.get("UpdatedAt") or record.get("CreatedAt")},
            message=record.get("Title") or record.get("Description"),
            event=Event(
                action=record.get("Type"),
                category=["intrusion_detection"],
                type=["indicator"],
                kind="alert",
                provider="aws",
                dataset="aws.guardduty",
            ),
            source=Host(ip=remote_ip) if remote_ip else None,
            cloud=Cloud(
                provider="aws",
                account_id=record.get("AccountId"),
                region=record.get("Region"),
                service_name="guardduty",
            ),
            threat={
                "framework": "MITRE ATT&CK",
                "severity": record.get("Severity"),
                "severity_label": _severity_label(record.get("Severity")),
            },
            aws={"guardduty": {
                "finding_id": record.get("Id"),
                "type": record.get("Type"),
                "count": (service.get("Count")),
                "resource": record.get("Resource"),
            }},
        )
