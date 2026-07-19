import json

from cumulonimbus.core import analysis, exports

EVENTS = [
    {
        "@timestamp": "2024-01-15T10:30:00Z",
        "event": {
            "action": "ConsoleLogin",
            "category": ["authentication"],
            "outcome": "success",
            "provider": "aws",
        },
        "user": {"name": "admin@corp.com"},
        "source": {"ip": "203.0.113.42"},
        "cloud": {"provider": "aws"},
    },
    {
        "@timestamp": "2024-01-15T10:35:00Z",
        "event": {"action": "SignIn", "outcome": "success", "provider": "azure"},
        "user": {"name": "admin"},
        "source": {"ip": "203.0.113.42"},
        "cloud": {"provider": "azure"},
    },
]


def test_stix_bundle():
    bundle = json.loads(exports.encode_stix(EVENTS))
    assert bundle["type"] == "bundle"
    types = {o["type"] for o in bundle["objects"]}
    assert "observed-data" in types and "ipv4-addr" in types
    # shared IP deduped to one observable
    ips = [o for o in bundle["objects"] if o["type"] == "ipv4-addr"]
    assert len(ips) == 1


def test_es_bulk():
    text = exports.encode_es_bulk(EVENTS, index="cases")
    lines = text.strip().split("\n")
    assert len(lines) == 4  # action + doc per event
    assert json.loads(lines[0])["index"]["_index"] == "cases"


def test_citadel_bundle():
    bundle = json.loads(exports.encode_citadel_bundle(EVENTS, case_id="C-1"))
    assert bundle["schema"] == "citadel.bundle.v1"
    assert bundle["case_id"] == "C-1"
    assert bundle["event_count"] == 2


def test_correlate_identities():
    hits = analysis.correlate_identities(EVENTS)
    # "admin@corp.com" and "admin" normalize to same identity across aws+azure
    idents = [h for h in hits if h["kind"] == "identity"]
    assert idents and idents[0]["value"] == "admin"
    assert set(idents[0]["providers"]) == {"aws", "azure"}
    ips = [h for h in hits if h["kind"] == "source_ip"]
    assert ips and set(ips[0]["providers"]) == {"aws", "azure"}
