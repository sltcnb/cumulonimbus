"""VPC Flow Log record -> ForensicEvent.

Accepts either a dict (already-split fields) or a raw space-delimited line in
the AWS default v2 format:
  version account-id interface-id srcaddr dstaddr srcport dstport protocol \
  packets bytes start end action log-status
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from cumulonimbus.core.parser import Parser, register
from cumulonimbus.ecs.schema import Cloud, Event, ForensicEvent, Host, Network

_DEFAULT_FIELDS = [
    "version", "account_id", "interface_id", "srcaddr", "dstaddr",
    "srcport", "dstport", "protocol", "packets", "bytes",
    "start", "end", "action", "log_status",
]

# IANA protocol number -> transport name.
_PROTO = {"6": "tcp", "17": "udp", "1": "icmp", "58": "ipv6-icmp"}


def _to_int(v) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


@register("aws.vpcflow")
class VPCFlowParser(Parser):
    def parse_record(self, record: Any) -> Optional[ForensicEvent]:
        if isinstance(record, str):
            parts = record.split()
            if len(parts) != len(_DEFAULT_FIELDS):
                return None
            record = dict(zip(_DEFAULT_FIELDS, parts))
        if record.get("log_status") == "NODATA" or "srcaddr" not in record:
            return None

        proto = str(record.get("protocol", ""))
        proto_num = _to_int(proto)
        start = _to_int(record.get("start"))
        ts = (datetime.fromtimestamp(start, tz=timezone.utc).isoformat()
              if start else None)
        action = record.get("action")

        return ForensicEvent(
            **{"@timestamp": ts},
            event=Event(
                action=action,
                category=["network"],
                type=["connection"],
                outcome="success" if action == "ACCEPT" else (
                    "failure" if action == "REJECT" else None),
                provider="aws",
                dataset="aws.vpcflow",
            ),
            source=Host(ip=record.get("srcaddr"), port=_to_int(record.get("srcport"))),
            destination=Host(ip=record.get("dstaddr"), port=_to_int(record.get("dstport"))),
            network=Network(
                transport=_PROTO.get(proto),
                iana_number=proto_num,
                bytes=_to_int(record.get("bytes")),
                packets=_to_int(record.get("packets")),
            ),
            cloud=Cloud(provider="aws", account_id=record.get("account_id")),
            aws={"vpc": {"interface_id": record.get("interface_id"),
                         "log_status": record.get("log_status")}},
        )
