from cumulonimbus.core import analysis

EVENTS = [
    {"@timestamp": "2024-01-15T10:30:00Z", "event": {"action": "ConsoleLogin",
     "outcome": "success"}, "user": {"name": "admin"}, "source": {"ip": "203.0.113.42"}},
    {"@timestamp": "2024-01-15T10:31:00Z", "event": {"action": "PutUserPolicy",
     "outcome": "failure"}, "user": {"name": "attacker"}, "source": {"ip": "203.0.113.42"}},
    {"@timestamp": "2024-01-15T10:32:00Z", "event": {"action": "CreateAccessKey",
     "outcome": "success"}, "user": {"name": "attacker"}, "source": {"ip": "10.0.0.9"}},
    {"@timestamp": "2024-01-15T10:33:00Z", "event": {"action": "ACCEPT"},
     "source": {"ip": "10.0.1.5"}, "destination": {"ip": "8.8.8.8", "port": 443},
     "network": {"bytes": 200_000_000, "direction": "outbound"}},
]


def test_timeline_sorted():
    ts = [e["@timestamp"] for e in analysis.timeline(reversed(EVENTS))]
    assert ts == sorted(ts)


def test_user_activity():
    ua = analysis.user_activity(EVENTS)
    assert ua["attacker"]["count"] == 2
    assert ua["attacker"]["failures"] == 1
    assert set(ua["attacker"]["source_ips"]) == {"203.0.113.42", "10.0.0.9"}
    assert ua["admin"]["actions"]["ConsoleLogin"] == 1


def test_top_talkers():
    tt = analysis.top_talkers(EVENTS)
    assert tt[0]["destination"] == "8.8.8.8"
    assert tt[0]["bytes"] == 200_000_000


def test_privesc_indicators():
    hits = analysis.privesc_indicators(EVENTS)
    actions = {h["action"] for h in hits}
    assert actions == {"PutUserPolicy", "CreateAccessKey"}


def test_exfil_indicators():
    hits = analysis.exfil_indicators(EVENTS)
    assert any(h["kind"] == "large_egress" and h["bytes"] == 200_000_000 for h in hits)
