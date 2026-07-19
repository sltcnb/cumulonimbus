"""Cumulonimbus CLI — collect | parse | export."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

import click
from rich.console import Console
from rich.table import Table

# Import provider parser packages so their @register decorators run.
import cumulonimbus.providers.aws.parsers  # noqa: F401
import cumulonimbus.providers.azure.parsers  # noqa: F401
import cumulonimbus.providers.gcp.parsers  # noqa: F401
import cumulonimbus.providers.k8s.parsers  # noqa: F401
from cumulonimbus.core.exporter import FORMATS
from cumulonimbus.core.exporter import export as export_events
from cumulonimbus.core.normalizer import Normalizer
from cumulonimbus.core.parser import get_parser, list_parsers
from cumulonimbus.ecs.schema import ForensicEvent

console = Console()


def _parse_time(ctx, param, value) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as e:
        raise click.BadParameter(f"expected ISO-8601, got {value!r}") from e
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _read_jsonl(path: Path) -> Iterator:
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)


@click.group()
@click.version_option(package_name="cumulonimbus-dfir", prog_name="cumulonimbus")
def cli():
    """Cumulonimbus — cloud forensics & IR toolkit."""


# -- AWS ------------------------------------------------------------------
@cli.group()
def aws():
    """AWS collectors."""


@aws.command("collect")
@click.option(
    "--service",
    type=click.Choice(["cloudtrail", "guardduty", "ec2", "iam", "lambda", "rds", "all"]),
    default="all",
    show_default=True,
)
@click.option("--profile", default=None, help="AWS named profile.")
@click.option("--region", default=None, help="AWS region.")
@click.option("--start-time", callback=_parse_time, help="ISO-8601 lower bound.")
@click.option("--end-time", callback=_parse_time, help="ISO-8601 upper bound.")
@click.option(
    "--output",
    "-o",
    type=click.Path(file_okay=False),
    required=True,
    help="Case directory (raw/ created inside).",
)
def aws_collect(service, profile, region, start_time, end_time, output):
    """Collect AWS logs into <output>/raw/."""
    try:
        import boto3
    except ImportError:
        raise click.ClickException("boto3 not installed — `pip install cumulonimbus-dfir[aws]`")
    from cumulonimbus.providers.aws.collectors import COLLECTORS

    session = boto3.Session(profile_name=profile)
    raw_dir = Path(output) / "raw"
    services = list(COLLECTORS) if service == "all" else [service]
    for name in services:
        collector = COLLECTORS[name](
            session=session, region=region, start_time=start_time, end_time=end_time
        )
        console.print(f"[cyan]collecting[/] {name}…")
        try:
            n = collector.collect_to(raw_dir)
            console.print(f"  [green]{n}[/] records -> {raw_dir / (collector.dataset + '.jsonl')}")
        except Exception as e:  # noqa: BLE001
            console.print(f"  [red]failed[/]: {e}")


@aws.command("collect-s3")
@click.option("--bucket", required=True, help="Log bucket name.")
@click.option("--prefix", default="", help="Key prefix to scope objects.")
@click.option(
    "--dataset",
    type=click.Choice(["aws.s3access", "aws.vpcflow"]),
    default="aws.s3access",
    show_default=True,
    help="Which line parser these logs feed later.",
)
@click.option("--profile", default=None)
@click.option("--region", default=None)
@click.option("--output", "-o", type=click.Path(file_okay=False), required=True)
def aws_collect_s3(bucket, prefix, dataset, profile, region, output):
    """Download logs delivered to an S3 bucket into <output>/raw/."""
    try:
        import boto3
    except ImportError:
        raise click.ClickException("boto3 not installed — `pip install cumulonimbus-dfir[aws]`")
    from cumulonimbus.providers.aws.collectors import S3LogCollector

    session = boto3.Session(profile_name=profile)
    raw_dir = Path(output) / "raw"
    collector = S3LogCollector(
        bucket=bucket, prefix=prefix, dataset=dataset, session=session, region=region
    )
    console.print(f"[cyan]collecting[/] s3://{bucket}/{prefix} -> {dataset}…")
    n = collector.collect_to(raw_dir)
    console.print(f"  [green]{n}[/] lines -> {raw_dir / (dataset + '.jsonl')}")


def _run_collectors(collectors: dict, names, output, factory) -> None:
    """Shared collect loop for the provider groups."""
    raw_dir = Path(output) / "raw"
    selected = list(collectors) if "all" in names else list(names)
    for name in selected:
        try:
            collector = factory(collectors[name])
            console.print(f"[cyan]collecting[/] {name}…")
            n = collector.collect_to(raw_dir)
            console.print(f"  [green]{n}[/] records -> {raw_dir / (collector.dataset + '.jsonl')}")
        except Exception as e:  # noqa: BLE001
            console.print(f"  [red]failed[/] {name}: {e}")


# -- Azure ----------------------------------------------------------------
@cli.group()
def azure():
    """Azure collectors."""


@azure.command("collect")
@click.option(
    "--service",
    type=click.Choice(["activity", "signin", "audit", "all"]),
    default="all",
    show_default=True,
)
@click.option("--subscription", default=None, help="Subscription ID (activity log).")
@click.option("--tenant", default=None, help="Tenant ID.")
@click.option("--start-time", callback=_parse_time)
@click.option("--end-time", callback=_parse_time)
@click.option("--output", "-o", type=click.Path(file_okay=False), required=True)
def azure_collect(service, subscription, tenant, start_time, end_time, output):
    """Collect Azure logs into <output>/raw/."""
    from cumulonimbus.providers.azure.collectors import COLLECTORS

    _run_collectors(
        COLLECTORS,
        [service],
        output,
        lambda cls: cls(
            subscription_id=subscription, tenant_id=tenant, start_time=start_time, end_time=end_time
        ),
    )


# -- GCP ------------------------------------------------------------------
@cli.group()
def gcp():
    """GCP collectors."""


@gcp.command("collect")
@click.option(
    "--service",
    type=click.Choice(["audit", "vpcflow", "scc", "all"]),
    default="all",
    show_default=True,
)
@click.option("--project", required=True, help="GCP project ID.")
@click.option("--start-time", callback=_parse_time)
@click.option("--end-time", callback=_parse_time)
@click.option("--output", "-o", type=click.Path(file_okay=False), required=True)
def gcp_collect(service, project, start_time, end_time, output):
    """Collect GCP logs into <output>/raw/."""
    from cumulonimbus.providers.gcp.collectors import COLLECTORS

    _run_collectors(
        COLLECTORS,
        [service],
        output,
        lambda cls: cls(project=project, start_time=start_time, end_time=end_time),
    )


# -- Kubernetes -------------------------------------------------------------
@cli.group()
def k8s():
    """Kubernetes collectors."""


@k8s.command("collect")
@click.option(
    "--service",
    type=click.Choice(["event", "audit", "container", "etcd", "all"]),
    default="event",
    show_default=True,
)
@click.option("--kubeconfig", default=None, help="Path to kubeconfig (event/container).")
@click.option("--in-cluster", is_flag=True, help="Use in-cluster service account.")
@click.option("--audit-log", default=None, help="Path to API-server audit JSON-lines file.")
@click.option(
    "--etcd-export",
    default=None,
    help="Path to a decoded etcd snapshot (JSON lines/array of {key,value}).",
)
@click.option("--output", "-o", type=click.Path(file_okay=False), required=True)
def k8s_collect(service, kubeconfig, in_cluster, audit_log, etcd_export, output):
    """Collect Kubernetes evidence into <output>/raw/."""
    from cumulonimbus.providers.k8s.collectors import COLLECTORS

    names = list(COLLECTORS) if service == "all" else [service]

    def factory(cls):
        if cls.dataset == "k8s.audit":
            if not audit_log:
                raise click.ClickException("--audit-log required for the audit collector")
            return cls(audit_log=audit_log)
        if cls.dataset == "k8s.etcd":
            if not etcd_export:
                raise click.ClickException("--etcd-export required for the etcd collector")
            return cls(etcd_export=etcd_export)
        return cls(kubeconfig=kubeconfig, in_cluster=in_cluster)

    _run_collectors(COLLECTORS, names, output, factory)


# -- parse ----------------------------------------------------------------
@cli.command()
@click.argument("raw_dir", type=click.Path(exists=True, file_okay=False))
@click.option(
    "--output",
    "-o",
    type=click.Path(file_okay=False),
    required=True,
    help="Output dir for normalized ECS jsonl.",
)
@click.option("--dataset", default=None, help="Force a parser (default: infer from filename stem).")
@click.option("--geoip-city", default=None, help="MaxMind City .mmdb for GeoIP enrichment.")
@click.option("--geoip-asn", default=None, help="MaxMind ASN .mmdb for ASN enrichment.")
@click.option("--rdns", is_flag=True, help="Reverse-DNS public IPs (network lookups).")
@click.option(
    "--ioc", "ioc_file", default=None, help="IOC file (IP-per-line or STIX bundle) to flag matches."
)
def parse(raw_dir, output, dataset, geoip_city, geoip_asn, rdns, ioc_file):
    """Parse + normalize raw JSONL files into ECS events."""
    from cumulonimbus.core.normalizer import DEFAULT_ENRICHERS

    raw_dir = Path(raw_dir)
    out_dir = Path(output) / "ecs"
    out_dir.mkdir(parents=True, exist_ok=True)

    enrichers = list(DEFAULT_ENRICHERS)
    if geoip_city or geoip_asn:
        try:
            from cumulonimbus.core.enrichment import GeoIPEnricher

            enrichers.append(GeoIPEnricher(city_db=geoip_city, asn_db=geoip_asn))
        except ImportError:
            raise click.ClickException(
                "geoip2 not installed — `pip install cumulonimbus-dfir[geoip]`"
            )
    if rdns:
        from cumulonimbus.core.enrichment import ReverseDNSEnricher

        enrichers.append(ReverseDNSEnricher())
    if ioc_file:
        from cumulonimbus.core.enrichment import IOCEnricher

        enrichers.append(IOCEnricher.from_file(ioc_file))
        console.print(f"[dim]loaded {len(enrichers[-1].iocs)} IOCs[/]")

    normalizer = Normalizer(enrichers=enrichers)
    total = 0
    for f in sorted(raw_dir.glob("*.jsonl")):
        ds = dataset or f.stem
        parser_cls = get_parser(ds)
        if not parser_cls:
            console.print(f"[yellow]skip[/] {f.name}: no parser for {ds!r}")
            continue
        parser = parser_cls()
        events = normalizer.run(parser.parse(_read_jsonl(f)))
        dest = out_dir / f"{ds}.ecs.jsonl"
        n = export_events(events, dest, fmt="jsonl")
        total += n
        console.print(f"[green]{n}[/] events  {f.name} -> {dest}")
    console.print(f"[bold]total:[/] {total} ECS events")


def _load_ecs(ecs_input: Path) -> list[dict]:
    files = sorted(ecs_input.glob("*.ecs.jsonl")) if ecs_input.is_dir() else [ecs_input]
    return [rec for f in files for rec in _read_jsonl(f)]


# -- export ---------------------------------------------------------------
_ALL_FORMATS = list(FORMATS) + ["stix", "es-bulk", "citadel"]


@cli.command()
@click.argument("ecs_input", type=click.Path(exists=True))
@click.option(
    "--format", "fmt", type=click.Choice(_ALL_FORMATS), default="jsonl", show_default=True
)
@click.option("--output", "-o", type=click.Path(), required=True)
@click.option("--gzip", "gz", is_flag=True, help="GZIP the output (jsonl/csv).")
@click.option(
    "--es-index", default="cumulonimbus", show_default=True, help="Index name for es-bulk."
)
@click.option("--case-id", default="", help="Case ID stamped into a Citadel bundle.")
def export(ecs_input, fmt, output, gz, es_index, case_id):
    """Convert normalized ECS JSONL into another format."""
    ecs_input = Path(ecs_input)
    output = Path(output)

    if fmt in FORMATS:  # streaming jsonl / csv

        def _events():
            for rec in _load_ecs(ecs_input):
                yield ForensicEvent(**rec)

        n = export_events(_events(), output, fmt=fmt, gz=gz)
        console.print(f"[green]{n}[/] events -> {output}")
        return

    from cumulonimbus.core import exports  # bundle formats need the full set

    events = _load_ecs(ecs_input)
    if fmt == "stix":
        text = exports.encode_stix(events)
    elif fmt == "es-bulk":
        text = exports.encode_es_bulk(events, index=es_index)
    else:  # citadel
        text = exports.encode_citadel_bundle(events, case_id=case_id)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")
    console.print(f"[green]{len(events)}[/] events -> {output} ({fmt})")


# -- push to Citadel / Splunk -----------------------------------------------
@cli.command("push")
@click.argument("ecs_input", type=click.Path(exists=True))
@click.option("--target", type=click.Choice(["citadel", "splunk-hec", "es-bulk"]), required=True)
@click.option("--url", required=True, help="Endpoint URL.")
@click.option("--token", default=None, help="Auth token / HEC token / API key.")
@click.option("--case-id", default="", help="Citadel case ID.")
@click.option("--es-index", default="cumulonimbus", show_default=True)
@click.option("--verify/--no-verify", default=True, help="TLS verification.")
def push(ecs_input, target, url, token, case_id, es_index, verify):
    """Push normalized ECS events to Citadel, Splunk HEC, or Elasticsearch."""
    try:
        import requests
    except ImportError:
        raise click.ClickException("requests not installed — `pip install requests`")
    from cumulonimbus.core import exports

    events = _load_ecs(Path(ecs_input))
    headers = {}
    if target == "splunk-hec":
        if not token:
            raise click.ClickException("--token is required for --target splunk-hec")
        headers["Authorization"] = f"Splunk {token}"
        body = "".join(json.dumps({"event": e}) for e in events)
        headers["Content-Type"] = "application/json"
    elif target == "es-bulk":
        headers["Content-Type"] = "application/x-ndjson"
        if token:
            headers["Authorization"] = f"ApiKey {token}"
        body = exports.encode_es_bulk(events, index=es_index)
        url = url.rstrip("/") + "/_bulk"
    else:  # citadel
        headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = f"Bearer {token}"
        body = exports.encode_citadel_bundle(events, case_id=case_id)

    resp = requests.post(url, data=body, headers=headers, verify=verify, timeout=120)
    if resp.ok:
        console.print(f"[green]pushed {len(events)} events[/] -> {target} ({resp.status_code})")
    else:
        raise click.ClickException(f"{target} returned {resp.status_code}: {resp.text[:300]}")


# -- analyze --------------------------------------------------------------
@cli.command()
@click.argument("ecs_input", type=click.Path(exists=True))
@click.option(
    "--report",
    type=click.Choice(["all", "timeline", "users", "network", "privesc", "exfil", "correlate"]),
    default="all",
    show_default=True,
)
@click.option("--json", "as_json", is_flag=True, help="Emit raw JSON.")
@click.option("--limit", default=20, show_default=True, help="Rows for ranked reports.")
def analyze(ecs_input, report, as_json, limit):
    """Run analysis passes over normalized ECS events."""
    from cumulonimbus.core import analysis

    ecs_input = Path(ecs_input)
    files = sorted(ecs_input.glob("*.ecs.jsonl")) if ecs_input.is_dir() else [ecs_input]
    events = [rec for f in files for rec in _read_jsonl(f)]
    console.print(f"[dim]loaded {len(events)} events from {len(files)} file(s)[/]")

    out: dict = {}
    if report in ("all", "users"):
        out["users"] = analysis.user_activity(events)
    if report in ("all", "network"):
        out["top_talkers"] = analysis.top_talkers(events, limit=limit)
    if report in ("all", "privesc"):
        out["privesc"] = analysis.privesc_indicators(events)
    if report in ("all", "exfil"):
        out["exfil"] = analysis.exfil_indicators(events)
    if report in ("all", "correlate"):
        out["correlate"] = analysis.correlate_identities(events)
    if report == "timeline":
        out["timeline"] = analysis.timeline(events)

    if as_json:
        click.echo(json.dumps(out, indent=2, default=str))
        return

    if "users" in out:
        t = Table(
            "user", "events", "fails", "src IPs", "first seen", "last seen", title="User activity"
        )
        for name, u in sorted(out["users"].items(), key=lambda kv: -kv[1]["count"]):
            t.add_row(
                str(name),
                str(u["count"]),
                str(u["failures"]),
                ", ".join(u["source_ips"][:3]),
                str(u["first_seen"]),
                str(u["last_seen"]),
            )
        console.print(t)
    if "top_talkers" in out:
        t = Table("source", "destination", "port", "bytes", "flows", title="Top talkers")
        for r in out["top_talkers"]:
            t.add_row(
                str(r["source"]),
                str(r["destination"]),
                str(r["port"]),
                str(r["bytes"]),
                str(r["flows"]),
            )
        console.print(t)
    if out.get("privesc"):
        t = Table(
            "time",
            "action",
            "user",
            "src IP",
            "outcome",
            title="[red]Privilege-escalation indicators[/]",
        )
        for r in out["privesc"]:
            t.add_row(
                str(r["@timestamp"]),
                r["action"],
                str(r["user"]),
                str(r["source_ip"]),
                str(r["outcome"]),
            )
        console.print(t)
    if out.get("exfil"):
        t = Table("time", "kind", "detail", title="[red]Exfiltration indicators[/]")
        for r in out["exfil"]:
            detail = r.get("action") or f"{r.get('bytes')} bytes -> {r.get('destination')}"
            t.add_row(str(r["@timestamp"]), r["kind"], str(detail))
        console.print(t)
    if out.get("correlate"):
        t = Table("kind", "value", "providers", title="[yellow]Cross-cloud correlation[/]")
        for r in out["correlate"]:
            t.add_row(r["kind"], str(r["value"]), ", ".join(r["providers"]))
        console.print(t)


# -- helpers --------------------------------------------------------------
@cli.command("parsers")
def parsers_cmd():
    """List available parsers."""
    table = Table("dataset")
    for name in list_parsers():
        table.add_row(name)
    console.print(table)


@cli.command("iam-policy")
def iam_policy():
    """Print the minimum AWS IAM policy required."""
    from cumulonimbus.providers.aws.iam_permissions import POLICY

    click.echo(json.dumps(POLICY, indent=2))


if __name__ == "__main__":
    cli()
