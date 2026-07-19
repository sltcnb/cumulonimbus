"""Additional export encoders: STIX 2.1, Elasticsearch bulk, Citadel bundle.

Each `encode_*` takes an iterable of ECS dicts and returns the bytes/str to
write. Kept separate from the streaming jsonl/csv writer in exporter.py because
these formats need the full set (bundles, deterministic ids) rather than a
line-at-a-time stream.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

Event = dict[str, Any]


def _get(ev: Event, dotted: str):
    cur: Any = ev
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
        if cur is None:
            return None
    return cur


def _det_id(prefix: str, *parts) -> str:
    """Deterministic STIX id from content (no random UUID; reproducible)."""
    h = hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()
    return f"{prefix}--{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def encode_stix(events: Iterable[Event]) -> str:
    """A STIX 2.1 bundle: IP observables + one observed-data per event."""
    objects: list[dict] = []
    seen_ids: set[str] = set()

    def _add(obj: dict) -> str:
        if obj["id"] not in seen_ids:
            objects.append(obj)
            seen_ids.add(obj["id"])
        return obj["id"]

    for i, ev in enumerate(events):
        ts = ev.get("@timestamp")
        refs = []
        for role in ("source", "destination"):
            ip = _get(ev, f"{role}.ip")
            if ip:
                refs.append(
                    _add({"type": "ipv4-addr", "id": _det_id("ipv4-addr", ip), "value": ip})
                )
        _add(
            {
                "type": "observed-data",
                "spec_version": "2.1",
                # include a positional index so distinct events in the same second
                # with identical action/ip do not collapse to one object.
                "id": _det_id(
                    "observed-data",
                    i,
                    ts,
                    _get(ev, "event.action"),
                    _get(ev, "source.ip"),
                    _get(ev, "destination.ip"),
                ),
                "created": ts,
                "modified": ts,
                "first_observed": ts,
                "last_observed": ts,
                "number_observed": 1,
                "object_refs": refs,
                "x_cumulonimbus": {
                    "action": _get(ev, "event.action"),
                    "outcome": _get(ev, "event.outcome"),
                    "user": _get(ev, "user.name"),
                    "cloud_provider": _get(ev, "cloud.provider"),
                },
            }
        )
    bundle = {"type": "bundle", "id": _det_id("bundle", len(objects)), "objects": objects}
    return json.dumps(bundle, indent=2, default=str)


def encode_es_bulk(events: Iterable[Event], index: str = "cumulonimbus") -> str:
    """Elasticsearch _bulk newline-delimited action/doc pairs."""
    lines = []
    for i, ev in enumerate(events):
        # positional index keeps distinct same-second events from overwriting
        _id = _det_id(
            "doc",
            i,
            ev.get("@timestamp"),
            _get(ev, "event.action"),
            _get(ev, "source.ip"),
            _get(ev, "destination.ip"),
        )
        lines.append(json.dumps({"index": {"_index": index, "_id": _id.split("--")[1]}}))
        lines.append(json.dumps(ev, default=str))
    return "\n".join(lines) + "\n"


def encode_citadel_bundle(events: Iterable[Event], case_id: str = "") -> str:
    """Citadel ingest bundle: metadata header + ECS events array."""
    evlist = list(events)
    bundle = {
        "schema": "citadel.bundle.v1",
        "source": "cumulonimbus",
        "case_id": case_id or None,
        "event_count": len(evlist),
        "events": evlist,
    }
    return json.dumps(bundle, default=str)
