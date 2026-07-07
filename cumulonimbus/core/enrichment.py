"""Pluggable enrichers for the normalizer.

Each enricher is a callable taking a ForensicEvent and mutating it in place
(the `Enricher` contract in normalizer.py). All are best-effort: the normalizer
swallows exceptions so a lookup failure never aborts a run.

  GeoIPEnricher   — MaxMind City/ASN DBs → source/destination .geo + .as_number
  ReverseDNSEnricher — PTR lookups → source/destination .domain (cached)
  IOCEnricher     — flag events whose src/dst IP is a known IOC → event.threat

GeoIP needs the optional `geoip2` package + MaxMind .mmdb files; the others are
stdlib-only.
"""

from __future__ import annotations

import ipaddress
import json
import socket
from pathlib import Path
from typing import Iterable, Optional

from cumulonimbus.ecs.schema import ForensicEvent, Geo


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _hosts(ev: ForensicEvent):
    for h in (ev.source, ev.destination):
        if h is not None and h.ip:
            yield h


class GeoIPEnricher:
    """Fill `.geo` and `.as_number` from MaxMind City / ASN databases."""

    def __init__(self, city_db: Optional[str] = None, asn_db: Optional[str] = None):
        import geoip2.database  # deferred: geoip2 is optional
        self._city = geoip2.database.Reader(city_db) if city_db else None
        self._asn = geoip2.database.Reader(asn_db) if asn_db else None

    def __call__(self, ev: ForensicEvent) -> None:
        import geoip2.errors
        for host in _hosts(ev):
            if not _is_public(host.ip):
                continue
            if self._city is not None:
                try:
                    r = self._city.city(host.ip)
                    host.geo = Geo(
                        country_name=r.country.name,
                        country_iso_code=r.country.iso_code,
                        city_name=r.city.name)
                except geoip2.errors.AddressNotFoundError:
                    pass
            if self._asn is not None:
                try:
                    host.as_number = self._asn.asn(host.ip).autonomous_system_number
                except geoip2.errors.AddressNotFoundError:
                    pass

    def close(self) -> None:
        for r in (self._city, self._asn):
            if r is not None:
                r.close()


class ReverseDNSEnricher:
    """Resolve PTR records for public IPs into `.domain`. Results are cached."""

    def __init__(self, timeout: float = 2.0):
        self._cache: dict[str, Optional[str]] = {}
        self._timeout = timeout

    def _resolve(self, ip: str) -> Optional[str]:
        if ip in self._cache:
            return self._cache[ip]
        socket.setdefaulttimeout(self._timeout)
        try:
            name = socket.gethostbyaddr(ip)[0]
        except (OSError, socket.herror):
            name = None
        self._cache[ip] = name
        return name

    def __call__(self, ev: ForensicEvent) -> None:
        for host in _hosts(ev):
            if _is_public(host.ip) and not host.domain:
                name = self._resolve(host.ip)
                if name:
                    host.domain = name


class IOCEnricher:
    """Tag events whose source/destination IP matches a known indicator."""

    def __init__(self, iocs: Iterable[str]):
        self.iocs = {i.strip() for i in iocs if i and i.strip()}

    @classmethod
    def from_file(cls, path: str) -> "IOCEnricher":
        """Load IOCs from a plaintext IP-per-line file or a STIX 2.x bundle."""
        text = Path(path).read_text(encoding="utf-8").strip()
        if text.startswith("{"):
            bundle = json.loads(text)
            ips = [o.get("value") for o in bundle.get("objects", [])
                   if o.get("type") == "ipv4-addr" and o.get("value")]
            return cls(ips)
        return cls(line for line in text.splitlines()
                   if line.strip() and not line.startswith("#"))

    def __call__(self, ev: ForensicEvent) -> None:
        matched = [h.ip for h in _hosts(ev) if h.ip in self.iocs]
        if not matched:
            return
        threat = ev.threat or {}
        threat.setdefault("indicator", {})
        threat["indicator"]["matched"] = matched
        threat["matched"] = True
        ev.threat = threat
        # elevate to an alert so downstream tools surface it
        if ev.event and ev.event.kind == "event":
            ev.event.kind = "alert"
