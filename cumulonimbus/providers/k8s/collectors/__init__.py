"""Kubernetes collectors.

Events come live from the API server (kubernetes client, kubeconfig or
in-cluster). API audit logs are typically a JSON-lines file on the control
plane, so we ingest them from a path rather than an API.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

from cumulonimbus.core.collector import Collector


class EventCollector(Collector):
    dataset = "k8s.event"

    def __init__(self, *, kubeconfig=None, in_cluster=False, **kw):
        super().__init__(**kw)
        self.kubeconfig = kubeconfig
        self.in_cluster = in_cluster

    def collect(self) -> Iterator[dict[str, Any]]:
        from kubernetes import client, config
        if self.in_cluster:
            config.load_incluster_config()
        else:
            config.load_kube_config(config_file=self.kubeconfig)
        v1 = client.CoreV1Api()
        for ev in v1.list_event_for_all_namespaces().items:
            yield client.ApiClient().sanitize_for_serialization(ev)


class AuditLogCollector(Collector):
    """Read an API-server audit log (JSON lines) from disk."""

    dataset = "k8s.audit"

    def __init__(self, *, audit_log: str, **kw):
        super().__init__(**kw)
        self.audit_log = audit_log

    def collect(self) -> Iterator[dict[str, Any]]:
        with open(Path(self.audit_log), "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                # audit files may wrap events under "items"
                if isinstance(rec, dict) and "items" in rec:
                    yield from rec["items"]
                else:
                    yield rec


class ContainerCollector(Collector):
    """List running containers across all pods (kubernetes client)."""

    dataset = "k8s.container"

    def __init__(self, *, kubeconfig=None, in_cluster=False, **kw):
        super().__init__(**kw)
        self.kubeconfig = kubeconfig
        self.in_cluster = in_cluster

    def collect(self) -> Iterator[dict[str, Any]]:
        from kubernetes import client, config
        if self.in_cluster:
            config.load_incluster_config()
        else:
            config.load_kube_config(config_file=self.kubeconfig)
        v1 = client.CoreV1Api()
        sanitize = client.ApiClient().sanitize_for_serialization
        for pod in v1.list_pod_for_all_namespaces().items:
            meta = pod.metadata
            spec = pod.spec
            # spec containers carry image + securityContext; status carries runtime state
            specs = {c.name: c for c in (spec.containers or [])}
            statuses = {s.name: s for s in (pod.status.container_statuses or [])}
            host_paths = [v.host_path.path for v in (spec.volumes or [])
                          if getattr(v, "host_path", None)]
            for name, c in specs.items():
                st = statuses.get(name)
                sc = sanitize(c.security_context) if c.security_context else {}
                yield {
                    "name": name,
                    "image": c.image,
                    "containerID": getattr(st, "container_id", None) if st else None,
                    "ready": getattr(st, "ready", None) if st else None,
                    "restartCount": getattr(st, "restart_count", None) if st else None,
                    "securityContext": sc,
                    "_pod": meta.name,
                    "_namespace": meta.namespace,
                    "_runtime": (getattr(st, "container_id", "") or "").split(":")[0] or None,
                    "_host_path_mounts": host_paths or None,
                }


class EtcdCollector(Collector):
    """Ingest a decoded etcd snapshot: a JSON-lines file of {key, value} objects.

    etcd is a binary bolt DB; decode a `etcdctl snapshot save` file with a tool
    such as `auger extract` first, then point this collector at the JSON output.
    """

    dataset = "k8s.etcd"

    def __init__(self, *, etcd_export: str, **kw):
        super().__init__(**kw)
        self.etcd_export = etcd_export

    def collect(self) -> Iterator[dict[str, Any]]:
        with open(Path(self.etcd_export), "r", encoding="utf-8") as fh:
            content = fh.read().strip()
        # accept either JSON-lines or a single JSON array
        if content.startswith("["):
            yield from json.loads(content)
        else:
            for line in content.splitlines():
                line = line.strip()
                if line:
                    yield json.loads(line)


COLLECTORS = {
    "event": EventCollector,
    "audit": AuditLogCollector,
    "container": ContainerCollector,
    "etcd": EtcdCollector,
}
