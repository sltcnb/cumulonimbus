"""S3 server access log line -> ForensicEvent.

S3 access logs are space-delimited with quoted fields. We parse the leading
positional fields defined by the standard log format:
https://docs.aws.amazon.com/AmazonS3/latest/userguide/LogFormat.html
"""

from __future__ import annotations

import re
import shlex
from datetime import datetime, timezone
from typing import Any, Optional

from cumulonimbus.core.parser import Parser, register
from cumulonimbus.ecs.schema import Cloud, Event, ForensicEvent, Host

# bucket_owner bucket time remote_ip requester request_id operation key
# request_uri http_status ...
_TIME_RE = re.compile(r"\[(.*?)\]")


def _split(line: str) -> Optional[list[str]]:
    # Merge the bracketed timestamp so it survives shlex, then lex the rest.
    m = _TIME_RE.search(line)
    if not m:
        return None
    ts_raw = m.group(1)
    line = line.replace(f"[{ts_raw}]", f'"{ts_raw}"', 1)
    try:
        return shlex.split(line)
    except ValueError:
        return None


def _parse_time(raw: str) -> Optional[str]:
    # e.g. 06/Feb/2024:00:00:38 +0000
    try:
        return datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc).isoformat()
    except ValueError:
        return None


@register("aws.s3access")
class S3AccessParser(Parser):
    def parse_record(self, record: Any) -> Optional[ForensicEvent]:
        if isinstance(record, dict):
            # already-split; expect the standard keys
            fields = record
        else:
            parts = _split(str(record))
            if not parts or len(parts) < 8:
                return None
            keys = [
                "bucket_owner",
                "bucket",
                "time",
                "remote_ip",
                "requester",
                "request_id",
                "operation",
                "key",
                "request_uri",
                "http_status",
            ]
            fields = dict(zip(keys, parts))

        status = fields.get("http_status")
        try:
            outcome = "success" if status and int(status) < 400 else "failure"
        except (TypeError, ValueError):
            outcome = None

        op = fields.get("operation")
        # Normalize the S3/Apache-style timestamp to ISO-8601 on both input
        # paths so timelines sort correctly against other datasets.
        raw_time = fields.get("time", "")
        ts = _parse_time(raw_time) or (raw_time or None)
        return ForensicEvent(
            **{"@timestamp": ts},
            event=Event(
                action=op,
                category=["file"],
                type=["access"],
                outcome=outcome,
                provider="aws",
                dataset="aws.s3access",
            ),
            source=Host(ip=fields.get("remote_ip"))
            if fields.get("remote_ip") not in (None, "-")
            else None,
            user=None,
            cloud=Cloud(provider="aws", service_name="s3"),
            aws={
                "s3": {
                    "bucket": fields.get("bucket"),
                    "bucket_owner": fields.get("bucket_owner"),
                    "requester": fields.get("requester"),
                    "operation": op,
                    "key": fields.get("key"),
                    "request_uri": fields.get("request_uri"),
                    "http_status": status,
                }
            },
        )
