"""Export ForensicEvents to disk in various formats."""

from __future__ import annotations

import csv
import gzip
import json
from pathlib import Path
from typing import Iterable

from cumulonimbus.ecs.schema import ForensicEvent

FORMATS = ("jsonl", "csv")

# Flat columns pulled for CSV output.
_CSV_COLUMNS = [
    "@timestamp",
    "event.action",
    "event.category",
    "event.outcome",
    "cloud.provider",
    "cloud.account_id",
    "cloud.region",
    "user.name",
    "source.ip",
    "destination.ip",
    "network.bytes",
    "message",
]


def _get(d: dict, dotted: str):
    cur = d
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    if isinstance(cur, list):
        return ";".join(str(x) for x in cur)
    return cur


def _open(path: Path, gz: bool):
    if gz:
        return gzip.open(path, "wt", encoding="utf-8", newline="")
    return open(path, "w", encoding="utf-8", newline="")


def export(
    events: Iterable[ForensicEvent], output: Path, fmt: str = "jsonl", gz: bool = False
) -> int:
    """Write events; return count. `output` is the destination file path."""
    if fmt not in FORMATS:
        raise ValueError(f"unknown format {fmt!r}; choose from {FORMATS}")
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    if fmt == "jsonl":
        with _open(output, gz) as fh:
            for ev in events:
                fh.write(json.dumps(ev.to_ecs(), ensure_ascii=False, default=str))
                fh.write("\n")
                count += 1
    else:  # csv
        with _open(output, gz) as fh:
            writer = csv.DictWriter(fh, fieldnames=_CSV_COLUMNS, extrasaction="ignore")
            writer.writeheader()
            for ev in events:
                d = ev.to_ecs()
                writer.writerow({c: _get(d, c) for c in _CSV_COLUMNS})
                count += 1
    return count
