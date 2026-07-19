"""Regression tests for the correctness fixes from the code audit."""

import json

import cumulonimbus.providers.aws.parsers  # noqa: F401
import cumulonimbus.providers.azure.parsers  # noqa: F401
from cumulonimbus.core import exports
from cumulonimbus.core.parser import get_parser
from cumulonimbus.providers.aws.parsers.cloudtrail import CloudTrailParser
from cumulonimbus.providers.aws.parsers.guardduty import GuardDutyParser


def _events_same_second():
    # Two distinct S3 reads: same second, same IP, same action, different key.
    return [
        {
            "@timestamp": "2024-01-15T10:30:00Z",
            "event": {"action": "REST.GET.OBJECT"},
            "source": {"ip": "203.0.113.7"},
            "aws": {"s3": {"key": "a.txt"}},
        },
        {
            "@timestamp": "2024-01-15T10:30:00Z",
            "event": {"action": "REST.GET.OBJECT"},
            "source": {"ip": "203.0.113.7"},
            "aws": {"s3": {"key": "b.txt"}},
        },
    ]


def test_fix1_stix_does_not_collapse_same_second_events():
    bundle = json.loads(exports.encode_stix(_events_same_second()))
    obs = [o for o in bundle["objects"] if o["type"] == "observed-data"]
    assert len(obs) == 2, "distinct same-second events must stay distinct in STIX"


def test_fix1_es_bulk_unique_ids():
    text = exports.encode_es_bulk(_events_same_second())
    actions = [json.loads(l) for l in text.strip().split("\n")[::2]]
    ids = [a["index"]["_id"] for a in actions]
    assert len(set(ids)) == 2, "es-bulk _id must be unique per event (no overwrite)"


def test_fix2_guardduty_null_action_subobject():
    # NetworkConnectionAction present but null — must not crash / drop.
    rec = {
        "Type": "Recon:EC2/Portscan",
        "Id": "f1",
        "Severity": 5.0,
        "UpdatedAt": "2024-01-15T11:00:00Z",
        "Service": {"Action": {"NetworkConnectionAction": None, "AwsApiCallAction": None}},
    }
    ev = GuardDutyParser().parse_record(rec)
    assert ev is not None
    assert ev.to_ecs()["event"]["kind"] == "alert"


def test_fix3_s3access_dict_time_normalized():
    p = get_parser("aws.s3access")()
    ev = p.parse_record(
        {
            "operation": "REST.GET.OBJECT",
            "bucket": "b",
            "remote_ip": "1.2.3.4",
            "http_status": "200",
            "time": "06/Feb/2024:00:00:38 +0000",
        }
    ).to_ecs()
    assert ev["@timestamp"].startswith("2024-02-06T00:00:38")


def test_fix4_nsgflow_missing_direction_is_none():
    p = get_parser("azure.nsgflow")()
    ev = p.parse_record(
        {
            "time": "2024-01-01T00:00:00Z",
            "srcIp": "10.0.0.4",
            "dstIp": "10.0.0.5",
            "srcPort": "1",
            "dstPort": "2",
            "protocol": "T",
            "decision": "A",
        }
    ).to_ecs()
    # no direction field → must not be labeled outbound
    assert "direction" not in ev.get("network", {})


def test_fix5_cloudtrail_null_session_context():
    rec = {
        "eventName": "AssumeRole",
        "eventTime": "2024-01-01T00:00:00Z",
        "userIdentity": {"sessionContext": None, "principalId": "AIDA1"},
    }
    ev = CloudTrailParser().parse_record(rec)
    assert ev is not None
    assert ev.to_ecs()["user"]["id"] == "AIDA1"
