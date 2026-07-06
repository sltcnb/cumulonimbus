"""Collector base class.

A collector fetches raw records from a cloud provider and writes them to the
case's raw/ directory as newline-delimited JSON, one file per dataset. Parsing
happens later so raw evidence is preserved verbatim.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator, Optional


class Collector(ABC):
    #: dataset name, e.g. "aws.cloudtrail" — also the raw filename stem.
    dataset: str = "unknown"

    def __init__(self, *, start_time: Optional[datetime] = None,
                 end_time: Optional[datetime] = None, region: Optional[str] = None):
        self.start_time = start_time
        self.end_time = end_time
        self.region = region

    @abstractmethod
    def collect(self) -> Iterator[dict[str, Any]]:
        """Yield raw provider records."""

    def collect_to(self, raw_dir: Path) -> int:
        """Stream records to `<raw_dir>/<dataset>.jsonl`; return count."""
        raw_dir = Path(raw_dir)
        raw_dir.mkdir(parents=True, exist_ok=True)
        out = raw_dir / f"{self.dataset}.jsonl"
        count = 0
        with open(out, "w", encoding="utf-8") as fh:
            for rec in self.collect():
                fh.write(json.dumps(rec, ensure_ascii=False, default=str))
                fh.write("\n")
                count += 1
        return count
