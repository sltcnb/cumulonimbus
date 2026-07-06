"""Enrichment pass over ForensicEvents.

Best-effort, dependency-free enrichment. GeoIP/ASN/rDNS hooks are stubbed so
the pipeline works offline; wire real providers (MaxMind, etc.) via `enrichers`.
"""

from __future__ import annotations

import ipaddress
from typing import Callable, Iterable, Iterator

from cumulonimbus.ecs.schema import ForensicEvent

Enricher = Callable[[ForensicEvent], None]


def is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def tag_directions(ev: ForensicEvent) -> None:
    """Mark network.direction from public/private of src/dst."""
    if not ev.network:
        return
    src = ev.source.ip if ev.source else None
    dst = ev.destination.ip if ev.destination else None
    if src and dst:
        s_pub, d_pub = is_public_ip(src), is_public_ip(dst)
        if s_pub and not d_pub:
            ev.network.direction = "inbound"
        elif d_pub and not s_pub:
            ev.network.direction = "outbound"
        elif not s_pub and not d_pub:
            ev.network.direction = "internal"
        else:
            ev.network.direction = "external"


DEFAULT_ENRICHERS: list[Enricher] = [tag_directions]


class Normalizer:
    def __init__(self, enrichers: list[Enricher] | None = None):
        self.enrichers = enrichers if enrichers is not None else DEFAULT_ENRICHERS

    def run(self, events: Iterable[ForensicEvent]) -> Iterator[ForensicEvent]:
        for ev in events:
            for enrich in self.enrichers:
                try:
                    enrich(ev)
                except Exception:  # noqa: BLE001 — enrichment is best-effort
                    pass
            yield ev
