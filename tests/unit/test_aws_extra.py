import cumulonimbus.providers.aws.parsers  # noqa: F401
from cumulonimbus.providers.aws.parsers.inventory import (
    EC2Parser, IAMParser, LambdaParser, RDSParser)
from cumulonimbus.providers.aws.parsers.s3access import S3AccessParser


def test_s3access_line():
    line = ('79a5 mybucket [06/Feb/2024:00:00:38 +0000] 203.0.113.7 '
            'arn:aws:iam::123:user/bob req-1 REST.GET.OBJECT secret.txt '
            '"GET /secret.txt HTTP/1.1" 200')
    ev = S3AccessParser().parse_record(line).to_ecs()
    assert ev["source"]["ip"] == "203.0.113.7"
    assert ev["aws"]["s3"]["bucket"] == "mybucket"
    assert ev["aws"]["s3"]["key"] == "secret.txt"
    assert ev["event"]["outcome"] == "success"
    assert ev["@timestamp"].startswith("2024-02-06T00:00:38")


def test_s3access_forbidden():
    line = ('o b [06/Feb/2024:00:00:38 +0000] 1.2.3.4 - r REST.GET.OBJECT k '
            '"GET /k HTTP/1.1" 403')
    ev = S3AccessParser().parse_record(line).to_ecs()
    assert ev["event"]["outcome"] == "failure"


def test_ec2_parser():
    rec = {"InstanceId": "i-abc", "InstanceType": "t3.micro",
           "PublicIpAddress": "203.0.113.5", "State": {"Name": "running"},
           "Placement": {"AvailabilityZone": "us-east-1a"},
           "Tags": [{"Key": "Name", "Value": "web"}]}
    ev = EC2Parser().parse_record(rec).to_ecs()
    assert ev["source"]["ip"] == "203.0.113.5"
    assert ev["aws"]["ec2"]["instance_id"] == "i-abc"
    assert ev["aws"]["ec2"]["tags"]["Name"] == "web"
    assert ev["event"]["kind"] == "state"


def test_iam_role_parser():
    rec = {"_resource_type": "role", "RoleName": "admin", "Arn": "arn:...:role/admin",
           "RoleId": "AROA1"}
    ev = IAMParser().parse_record(rec).to_ecs()
    assert ev["aws"]["iam"]["resource_type"] == "role"
    assert ev["aws"]["iam"]["name"] == "admin"


def test_lambda_parser():
    rec = {"FunctionName": "f", "Runtime": "python3.12", "Role": "arn:...:role/x",
           "Environment": {"Variables": {"SECRET": "hunter2"}}}
    ev = LambdaParser().parse_record(rec).to_ecs()
    assert ev["aws"]["lambda"]["runtime"] == "python3.12"
    assert ev["aws"]["lambda"]["env"]["SECRET"] == "hunter2"


def test_rds_parser():
    rec = {"DBInstanceIdentifier": "db1", "Engine": "postgres",
           "PubliclyAccessible": True, "Endpoint": {"Address": "db.host", "Port": 5432}}
    ev = RDSParser().parse_record(rec).to_ecs()
    assert ev["aws"]["rds"]["publicly_accessible"] is True
    assert ev["aws"]["rds"]["port"] == 5432
