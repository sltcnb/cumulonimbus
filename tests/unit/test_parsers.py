import json
from pathlib import Path

import cumulonimbus.providers.aws.parsers  # noqa: F401 — registers parsers
from cumulonimbus.core.normalizer import Normalizer
from cumulonimbus.core.parser import get_parser
from cumulonimbus.providers.aws.parsers.cloudtrail import CloudTrailParser
from cumulonimbus.providers.aws.parsers.guardduty import GuardDutyParser
from cumulonimbus.providers.aws.parsers.vpcflow import VPCFlowParser

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_cloudtrail_console_login_success():
    records = json.loads((FIXTURES / "cloudtrail_sample.json").read_text())["Records"]
    events = list(CloudTrailParser().parse(records))
    assert len(events) == 2

    login = events[0].to_ecs()
    assert login["@timestamp"] == "2024-01-15T10:30:00Z"
    assert login["event"]["action"] == "ConsoleLogin"
    assert login["event"]["category"] == ["authentication"]
    assert login["event"]["outcome"] == "success"
    assert login["user"]["name"] == "admin"
    assert login["source"]["ip"] == "203.0.113.42"
    assert login["cloud"]["account_id"] == "123456789012"


def test_cloudtrail_failure_outcome():
    records = json.loads((FIXTURES / "cloudtrail_sample.json").read_text())["Records"]
    denied = list(CloudTrailParser().parse(records))[1].to_ecs()
    assert denied["event"]["outcome"] == "failure"
    assert denied["event"]["category"] == ["iam"]
    assert denied["aws"]["cloudtrail"]["error_code"] == "AccessDenied"


def test_cloudtrail_service_ip_dropped():
    # sourceIPAddress that is a service name must not become source.ip
    ev = CloudTrailParser().parse_record({
        "eventName": "AssumeRole", "eventTime": "2024-01-01T00:00:00Z",
        "sourceIPAddress": "cloudtrail.amazonaws.com",
    }).to_ecs()
    assert "source" not in ev


def test_vpcflow_line_format():
    line = ("2 123456789012 eni-abc 10.0.1.42 198.51.100.10 54321 443 6 "
            "10 1024 1704067200 1704067260 ACCEPT OK")
    ev = VPCFlowParser().parse_record(line).to_ecs()
    assert ev["source"]["ip"] == "10.0.1.42"
    assert ev["destination"]["port"] == 443
    assert ev["network"]["transport"] == "tcp"
    assert ev["network"]["bytes"] == 1024
    assert ev["event"]["outcome"] == "success"


def test_vpcflow_nodata_skipped():
    fields = ("2 - - - - - - - - - 1704067200 1704067260 - NODATA").split()
    rec = dict(zip(
        ["version", "account_id", "interface_id", "srcaddr", "dstaddr",
         "srcport", "dstport", "protocol", "packets", "bytes", "start",
         "end", "action", "log_status"], fields))
    assert VPCFlowParser().parse_record(rec) is None


def test_guardduty_finding():
    rec = {
        "Type": "UnauthorizedAccess:EC2/SSHBruteForce",
        "Id": "finding-1", "AccountId": "123456789012", "Region": "us-east-1",
        "Severity": 8.0, "Title": "SSH brute force",
        "UpdatedAt": "2024-01-15T11:00:00Z",
        "Service": {"Action": {"NetworkConnectionAction": {
            "RemoteIpDetails": {"IpAddressV4": "203.0.113.99"}}}},
    }
    ev = GuardDutyParser().parse_record(rec).to_ecs()
    assert ev["event"]["kind"] == "alert"
    assert ev["source"]["ip"] == "203.0.113.99"
    assert ev["threat"]["severity_label"] == "high"


def test_registry_lookup():
    assert get_parser("aws.cloudtrail") is CloudTrailParser
    assert get_parser("nope") is None


def test_normalizer_tags_direction():
    ev = VPCFlowParser().parse_record(
        "2 acct eni 10.0.1.5 8.8.8.8 100 53 17 1 60 1704067200 1704067260 ACCEPT OK")
    list(Normalizer().run([ev]))
    assert ev.network.direction == "outbound"
