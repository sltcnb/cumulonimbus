"""CLI-level regression tests (click.testing.CliRunner)."""

import json

from click.testing import CliRunner

from cumulonimbus.cli import cli

TIMELINE_EVENTS = [
    {
        "@timestamp": "2024-01-15T10:30:00Z",
        "event": {"action": "ConsoleLogin", "outcome": "success"},
        "user": {"name": "admin"},
        "source": {"ip": "203.0.113.42"},
    },
    {
        "@timestamp": "2024-01-15T10:31:00Z",
        "event": {"action": "PutUserPolicy", "outcome": "failure"},
        "user": {"name": "attacker"},
        "source": {"ip": "203.0.113.42"},
    },
]


def _write_ecs_jsonl(path, events):
    path.write_text("\n".join(json.dumps(ev) for ev in events) + "\n", encoding="utf-8")


def test_push_splunk_hec_without_token_errors_clearly(tmp_path):
    ecs_file = tmp_path / "sample.ecs.jsonl"
    _write_ecs_jsonl(ecs_file, TIMELINE_EVENTS[:1])

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "push",
            str(ecs_file),
            "--target",
            "splunk-hec",
            "--url",
            "https://splunk.example.com:8088/services/collector",
        ],
    )

    assert result.exit_code != 0
    assert "--token" in result.output
    assert "splunk-hec" in result.output
    # The bug being fixed: a missing token must never be silently sent as
    # a literal "None" in the Authorization header.
    assert "Splunk None" not in result.output


def test_analyze_report_timeline_prints_table(tmp_path):
    ecs_file = tmp_path / "sample.ecs.jsonl"
    _write_ecs_jsonl(ecs_file, TIMELINE_EVENTS)

    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", str(ecs_file), "--report", "timeline"])

    assert result.exit_code == 0, result.output
    assert result.output.strip() != ""
    assert "Timeline" in result.output
    assert "ConsoleLogin" in result.output
    assert "admin" in result.output


def test_analyze_report_timeline_json_still_works(tmp_path):
    ecs_file = tmp_path / "sample.ecs.jsonl"
    _write_ecs_jsonl(ecs_file, TIMELINE_EVENTS)

    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", str(ecs_file), "--report", "timeline", "--json"])

    assert result.exit_code == 0, result.output
    # Output is prefixed with a "loaded N events..." status line; the JSON
    # payload itself starts at the first '{'.
    payload = json.loads(result.output[result.output.index("{") :])
    assert len(payload["timeline"]) == 2
