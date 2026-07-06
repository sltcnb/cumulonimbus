"""Parser base class + registry.

A parser turns provider-native records (one dict) into a `ForensicEvent`.
Register parsers by dataset name so the CLI can dispatch on raw file type.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Iterable, Iterator, Optional

from cumulonimbus.ecs.schema import ForensicEvent

_REGISTRY: dict[str, type["Parser"]] = {}


def register(name: str):
    def deco(cls: type["Parser"]):
        _REGISTRY[name] = cls
        cls.dataset = name
        return cls

    return deco


def get_parser(name: str) -> Optional[type["Parser"]]:
    return _REGISTRY.get(name)


def list_parsers() -> list[str]:
    return sorted(_REGISTRY)


class Parser(ABC):
    dataset: str = "unknown"

    @abstractmethod
    def parse_record(self, record: dict[str, Any]) -> Optional[ForensicEvent]:
        """Map a single native record -> ForensicEvent, or None to skip."""

    def parse(self, records: Iterable[dict[str, Any]]) -> Iterator[ForensicEvent]:
        for rec in records:
            try:
                ev = self.parse_record(rec)
            except Exception:  # noqa: BLE001 — one bad record must not kill the run
                ev = None
            if ev is not None:
                yield ev
