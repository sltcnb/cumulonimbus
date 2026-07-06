"""CloudTrail record -> ForensicEvent.

Handles the standard CloudTrail JSON record shape (as found in S3 log files
under Records[], or the CloudTrailEvent payload from lookup_events).
"""

from __future__ import annotations

from typing import Any, Optional

from cumulonimbus.core.parser import Parser, register
from cumulonimbus.ecs.schema import (Cloud, Event, ForensicEvent, Host, User)

# Event names that represent authentication.
_AUTH_EVENTS = {"ConsoleLogin", "AssumeRole", "GetSessionToken",
                "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity"}


def _outcome(rec: dict[str, Any]) -> str:
    if rec.get("errorCode") or rec.get("errorMessage"):
        return "failure"
    # ConsoleLogin puts result in responseElements.ConsoleLogin
    resp = rec.get("responseElements") or {}
    if resp.get("ConsoleLogin") == "Failure":
        return "failure"
    return "success"


def _user(rec: dict[str, Any]) -> Optional[User]:
    ident = rec.get("userIdentity") or {}
    name = (ident.get("userName") or ident.get("arn")
            or ((ident.get("sessionContext") or {}).get("sessionIssuer") or {}).get("userName"))
    uid = ident.get("principalId") or ident.get("accountId")
    if not (name or uid):
        return None
    return User(name=name, id=uid)


@register("aws.cloudtrail")
class CloudTrailParser(Parser):
    def parse_record(self, record: dict[str, Any]) -> Optional[ForensicEvent]:
        name = record.get("eventName")
        if not name:
            return None
        category = ["authentication"] if name in _AUTH_EVENTS else ["iam"]
        read_only = record.get("readOnly")
        etype = ["access"] if name in _AUTH_EVENTS else (
            ["info"] if read_only else ["change"])

        src_ip = record.get("sourceIPAddress")
        source = Host(ip=src_ip) if src_ip and _looks_like_ip(src_ip) else None

        return ForensicEvent(
            **{"@timestamp": record.get("eventTime")},
            event=Event(
                action=name,
                category=category,
                type=etype,
                outcome=_outcome(record),
                provider="aws",
                dataset="aws.cloudtrail",
            ),
            user=_user(record),
            source=source,
            cloud=Cloud(
                provider="aws",
                account_id=record.get("recipientAccountId"),
                region=record.get("awsRegion"),
                service_name=record.get("eventSource"),
            ),
            aws={"cloudtrail": {
                "event_source": record.get("eventSource"),
                "event_name": name,
                "event_id": record.get("eventID"),
                "read_only": read_only,
                "error_code": record.get("errorCode"),
                "user_agent": record.get("userAgent"),
                "request_parameters": record.get("requestParameters"),
                "response_elements": record.get("responseElements"),
            }},
        )


def _looks_like_ip(s: str) -> bool:
    # sourceIPAddress can be a service name like "cloudtrail.amazonaws.com"
    return s[0].isdigit() or ":" in s
