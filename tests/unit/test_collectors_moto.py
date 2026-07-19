"""Integration tests for AWS collectors against moto-mocked APIs.

Exercises the collect() -> parse() path end-to-end so the SDK-facing code is not
untested. Skipped automatically if moto/boto3 are not installed.
"""

import json

import pytest

boto3 = pytest.importorskip("boto3")
moto = pytest.importorskip("moto")
mock_aws = moto.mock_aws

import cumulonimbus.providers.aws.parsers  # noqa: F401,E402  (registers parsers)
from cumulonimbus.core.parser import get_parser  # noqa: E402
from cumulonimbus.providers.aws.collectors import (  # noqa: E402
    EC2Collector,
    IAMCollector,
    LambdaCollector,
    RDSCollector,
    S3LogCollector,
)

REGION = "us-east-1"


@mock_aws
def test_ec2_collect_and_parse():
    s = boto3.Session(region_name=REGION)
    ec2 = s.client("ec2", region_name=REGION)
    ami = ec2.describe_images()["Images"]
    image_id = ami[0]["ImageId"] if ami else "ami-12345678"
    ec2.run_instances(ImageId=image_id, MinCount=1, MaxCount=1, InstanceType="t3.micro")

    records = list(EC2Collector(session=s, region=REGION).collect())
    assert records, "collector returned no instances"
    ev = get_parser("aws.ec2")().parse_record(records[0]).to_ecs()
    assert ev["aws"]["ec2"]["instance_id"].startswith("i-")
    assert ev["event"]["kind"] == "state"


@mock_aws
def test_iam_collect_and_parse():
    s = boto3.Session(region_name=REGION)
    iam = s.client("iam")
    iam.create_user(UserName="alice")
    iam.create_role(RoleName="admin", AssumeRolePolicyDocument="{}")

    records = list(IAMCollector(session=s).collect())
    names = {r.get("UserName") or r.get("RoleName") for r in records}
    assert {"alice", "admin"} <= names
    user_rec = next(r for r in records if r.get("UserName") == "alice")
    ev = get_parser("aws.iam")().parse_record(user_rec).to_ecs()
    assert ev["aws"]["iam"]["name"] == "alice"
    assert ev["aws"]["iam"]["resource_type"] == "user"


@mock_aws
def test_s3_log_collect_lines():
    s = boto3.Session(region_name=REGION)
    s3 = s.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="flow-logs")
    flow = (
        "2 123456789012 eni-abc 10.0.1.42 198.51.100.10 54321 443 6 "
        "10 1024 1704067200 1704067260 ACCEPT OK"
    )
    s3.put_object(Bucket="flow-logs", Key="logs/1.log", Body=flow.encode())

    lines = list(
        S3LogCollector(
            bucket="flow-logs", prefix="logs/", dataset="aws.vpcflow", session=s, region=REGION
        ).collect()
    )
    assert lines == [flow]
    ev = get_parser("aws.vpcflow")().parse_record(lines[0]).to_ecs()
    assert ev["destination"]["port"] == 443


@mock_aws
def test_rds_collect_empty_ok():
    # No DB instances created — collector must yield nothing, not error.
    s = boto3.Session(region_name=REGION)
    assert list(RDSCollector(session=s, region=REGION).collect()) == []


@mock_aws
def test_lambda_collect_empty_ok():
    s = boto3.Session(region_name=REGION)
    assert list(LambdaCollector(session=s, region=REGION).collect()) == []


@mock_aws
def test_collect_to_writes_file(tmp_path):
    s = boto3.Session(region_name=REGION)
    iam = s.client("iam")
    iam.create_user(UserName="bob")
    n = IAMCollector(session=s).collect_to(tmp_path)
    assert n >= 1
    out = tmp_path / "aws.iam.jsonl"
    assert out.exists()
    first = json.loads(out.read_text().splitlines()[0])
    assert "UserName" in first or "RoleName" in first
