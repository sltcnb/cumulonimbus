from cumulonimbus.core.enrichment import IOCEnricher, ReverseDNSEnricher
from cumulonimbus.core.normalizer import Normalizer
from cumulonimbus.ecs.schema import Event, ForensicEvent, Host


def _ev(src=None, dst=None):
    return ForensicEvent(source=Host(ip=src) if src else None,
                         destination=Host(ip=dst) if dst else None,
                         event=Event(kind="event"))


def test_ioc_flags_match():
    enr = IOCEnricher(["203.0.113.99", "198.51.100.5"])
    ev = _ev(src="203.0.113.99")
    enr(ev)
    d = ev.to_ecs()
    assert d["threat"]["matched"] is True
    assert d["threat"]["indicator"]["matched"] == ["203.0.113.99"]
    assert d["event"]["kind"] == "alert"  # elevated


def test_ioc_no_match_untouched():
    ev = _ev(src="10.0.0.1")
    IOCEnricher(["203.0.113.99"])(ev)
    assert ev.threat is None
    assert ev.event.kind == "event"


def test_ioc_from_plaintext_file(tmp_path):
    f = tmp_path / "iocs.txt"
    f.write_text("# comment\n203.0.113.99\n\n198.51.100.5\n")
    enr = IOCEnricher.from_file(str(f))
    assert enr.iocs == {"203.0.113.99", "198.51.100.5"}


def test_ioc_from_stix_bundle(tmp_path):
    f = tmp_path / "b.json"
    f.write_text('{"type":"bundle","objects":['
                 '{"type":"ipv4-addr","value":"203.0.113.99"},'
                 '{"type":"observed-data","id":"x"}]}')
    enr = IOCEnricher.from_file(str(f))
    assert enr.iocs == {"203.0.113.99"}


def test_rdns_uses_cache_and_skips_private(monkeypatch):
    calls = []

    def fake_gethostbyaddr(ip):
        calls.append(ip)
        return ("host.example.com", [], [ip])

    monkeypatch.setattr("socket.gethostbyaddr", fake_gethostbyaddr)
    enr = ReverseDNSEnricher()
    pub = _ev(src="8.8.8.8")
    enr(pub)
    assert pub.source.domain == "host.example.com"
    # second event, same IP → cache hit, no extra lookup
    enr(_ev(src="8.8.8.8"))
    assert calls == ["8.8.8.8"]
    # private IP never resolved
    priv = _ev(src="10.0.0.1")
    enr(priv)
    assert priv.source.domain is None
    assert calls == ["8.8.8.8"]


def test_normalizer_runs_ioc_enricher():
    n = Normalizer(enrichers=[IOCEnricher(["203.0.113.99"])])
    out = list(n.run([_ev(dst="203.0.113.99")]))
    assert out[0].to_ecs()["threat"]["matched"] is True
