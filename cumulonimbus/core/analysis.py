"""Analysis passes over normalized ECS events.

Pure functions over an in-memory list of ECS dicts (as produced by
`ForensicEvent.to_ecs()`). Each returns plain dicts/lists so the CLI can render
or dump them. Built to run on the `ecs/*.ecs.jsonl` output of `parse`.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Iterable

Event = dict[str, Any]


def _get(ev: Event, dotted: str, default=None):
    cur: Any = ev
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return default
        cur = cur.get(part)
        if cur is None:
            return default
    return cur


def timeline(events: Iterable[Event]) -> list[Event]:
    """All events sorted by @timestamp ascending (undated last)."""
    return sorted(events, key=lambda e: (e.get("@timestamp") is None,
                                         e.get("@timestamp") or ""))


def user_activity(events: Iterable[Event]) -> dict[str, dict[str, Any]]:
    """Per-principal summary: action counts, source IPs, first/last seen."""
    out: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"count": 0, "actions": Counter(), "source_ips": set(),
                 "first_seen": None, "last_seen": None, "failures": 0})
    for ev in events:
        name = _get(ev, "user.name") or _get(ev, "user.id")
        if not name:
            continue
        u = out[name]
        u["count"] += 1
        action = _get(ev, "event.action")
        if action:
            u["actions"][action] += 1
        ip = _get(ev, "source.ip")
        if ip:
            u["source_ips"].add(ip)
        if _get(ev, "event.outcome") == "failure":
            u["failures"] += 1
        ts = ev.get("@timestamp")
        if ts:
            if u["first_seen"] is None or ts < u["first_seen"]:
                u["first_seen"] = ts
            if u["last_seen"] is None or ts > u["last_seen"]:
                u["last_seen"] = ts
    # make JSON-friendly
    return {name: {**u, "actions": dict(u["actions"]),
                   "source_ips": sorted(u["source_ips"])}
            for name, u in out.items()}


def top_talkers(events: Iterable[Event], limit: int = 20) -> list[dict[str, Any]]:
    """Network flows aggregated by (src, dst, dport), ranked by bytes."""
    agg: dict[tuple, dict[str, int]] = defaultdict(lambda: {"bytes": 0, "flows": 0})
    for ev in events:
        if "network" not in ev:
            continue
        key = (_get(ev, "source.ip"), _get(ev, "destination.ip"),
               _get(ev, "destination.port"))
        agg[key]["bytes"] += _get(ev, "network.bytes", 0) or 0
        agg[key]["flows"] += 1
    rows = [{"source": k[0], "destination": k[1], "port": k[2], **v}
            for k, v in agg.items()]
    return sorted(rows, key=lambda r: r["bytes"], reverse=True)[:limit]


# IAM API calls that grant or expand privileges.
_PRIVESC_ACTIONS = {
    "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy", "AttachUserPolicy",
    "AttachRolePolicy", "AttachGroupPolicy", "CreateAccessKey", "CreateLoginProfile",
    "UpdateAssumeRolePolicy", "CreatePolicyVersion", "SetDefaultPolicyVersion",
    "AddUserToGroup", "CreateUser", "CreateRole",
}


def privesc_indicators(events: Iterable[Event]) -> list[Event]:
    """CloudTrail events matching known privilege-escalation techniques."""
    hits = []
    for ev in events:
        action = _get(ev, "event.action")
        if action in _PRIVESC_ACTIONS:
            hits.append({
                "@timestamp": ev.get("@timestamp"),
                "action": action,
                "user": _get(ev, "user.name"),
                "source_ip": _get(ev, "source.ip"),
                "outcome": _get(ev, "event.outcome"),
            })
    return timeline(hits)


def correlate_identities(events: Iterable[Event]) -> list[dict[str, Any]]:
    """Group activity across cloud providers by shared identity or source IP.

    Surfaces principals/IPs that appear in more than one provider — the
    cross-cloud pivots an attacker leaves behind.
    """
    by_user: dict[str, set] = defaultdict(set)
    by_ip: dict[str, set] = defaultdict(set)
    for ev in events:
        provider = _get(ev, "cloud.provider") or _get(ev, "event.provider")
        if not provider:
            continue
        # normalize identity: strip domain to catch admin@a vs admin
        name = _get(ev, "user.name") or _get(ev, "user.email")
        if name:
            by_user[str(name).split("@")[0].lower()].add(provider)
        ip = _get(ev, "source.ip")
        if ip:
            by_ip[ip].add(provider)

    hits = []
    for name, provs in by_user.items():
        if len(provs) > 1:
            hits.append({"kind": "identity", "value": name,
                         "providers": sorted(provs)})
    for ip, provs in by_ip.items():
        if len(provs) > 1:
            hits.append({"kind": "source_ip", "value": ip,
                         "providers": sorted(provs)})
    return sorted(hits, key=lambda h: (-len(h["providers"]), h["kind"]))


def exfil_indicators(events: Iterable[Event], byte_threshold: int = 100_000_000,
                     s3_events=("GetObject", "ListObjects", "ListObjectsV2")) -> list[Event]:
    """Large outbound flows + bulk S3 read activity."""
    hits = []
    for ev in events:
        # Large outbound network transfer.
        if _get(ev, "network.direction") == "outbound":
            b = _get(ev, "network.bytes", 0) or 0
            if b >= byte_threshold:
                hits.append({"@timestamp": ev.get("@timestamp"), "kind": "large_egress",
                             "bytes": b, "source": _get(ev, "source.ip"),
                             "destination": _get(ev, "destination.ip")})
        # S3 data-access API calls.
        if _get(ev, "event.action") in s3_events:
            hits.append({"@timestamp": ev.get("@timestamp"), "kind": "s3_access",
                         "action": _get(ev, "event.action"),
                         "user": _get(ev, "user.name"),
                         "source_ip": _get(ev, "source.ip")})
    return timeline(hits)
