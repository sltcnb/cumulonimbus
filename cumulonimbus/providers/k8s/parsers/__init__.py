"""Kubernetes ECS parsers.

Kubernetes-native fields map to ECS `orchestrator.*` and `container.*`. A small
`k8s` extra namespace carries forensics-relevant details ECS has no home for
(verb, response code, sensitivity flag, etcd metadata).

Datasets:
  k8s.audit      — API server audit log events (audit.k8s.io/v1 Event)
  k8s.event      — core/v1 Event objects
  k8s.container  — pod/container inventory (running or from a spec)
  k8s.etcd       — decoded etcd key/value objects (cluster state at rest)
"""

from __future__ import annotations

from typing import Any, Optional

from cumulonimbus.core.parser import Parser, register
from cumulonimbus.ecs.schema import (
    Cloud,
    Container,
    ContainerImage,
    Event,
    ForensicEvent,
    Host,
    Orchestrator,
    OrchestratorResource,
    User,
)

# Verbs that mutate cluster state.
_WRITE_VERBS = {"create", "update", "patch", "delete", "deletecollection"}
# Sensitive resources worth flagging.
_SENSITIVE = {"secrets", "clusterrolebindings", "rolebindings", "pods/exec",
              "pods/attach", "serviceaccounts"}


def _orch(*, namespace=None, api_version=None, resource=None, res_name=None,
          cluster=None) -> Orchestrator:
    return Orchestrator(
        type="kubernetes", namespace=namespace, api_version=api_version,
        cluster_name=cluster,
        resource=OrchestratorResource(name=res_name, type=resource)
        if (res_name or resource) else None)


def _image(ref: Optional[str]) -> Optional[ContainerImage]:
    if not ref:
        return None
    if ":" in ref.rsplit("/", 1)[-1]:
        name, tag = ref.rsplit(":", 1)
        return ContainerImage(name=name, tag=[tag])
    return ContainerImage(name=ref)


@register("k8s.audit")
class AuditParser(Parser):
    def parse_record(self, r: dict[str, Any]) -> Optional[ForensicEvent]:
        verb = r.get("verb")
        if not verb:
            return None
        user = r.get("user") or {}
        obj = r.get("objectRef") or {}
        resource = obj.get("resource")
        subres = obj.get("subresource")
        full_res = f"{resource}/{subres}" if subres else resource
        code = (r.get("responseStatus") or {}).get("code")
        src_ips = r.get("sourceIPs") or []
        return ForensicEvent(
            **{"@timestamp": r.get("requestReceivedTimestamp") or r.get("stageTimestamp")},
            event=Event(action=f"{verb}:{full_res}" if full_res else verb,
                        category=["configuration"] if verb in _WRITE_VERBS else ["process"],
                        type=["change"] if verb in _WRITE_VERBS else ["info"],
                        outcome="failure" if (code and code >= 400) else "success",
                        provider="kubernetes", dataset="k8s.audit"),
            user=User(name=user.get("username"),
                      id=user.get("uid")) if user.get("username") else None,
            source=Host(ip=src_ips[0]) if src_ips else None,
            cloud=Cloud(provider="kubernetes"),
            orchestrator=_orch(namespace=obj.get("namespace"),
                               api_version=obj.get("apiVersion"),
                               resource=resource, res_name=obj.get("name")),
            k8s={"verb": verb, "subresource": subres, "response_code": code,
                 "stage": r.get("stage"), "user_agent": r.get("userAgent"),
                 "groups": user.get("groups"), "sensitive": full_res in _SENSITIVE},
        )


@register("k8s.event")
class EventParser(Parser):
    def parse_record(self, r: dict[str, Any]) -> Optional[ForensicEvent]:
        reason = r.get("reason")
        involved = r.get("involvedObject") or {}
        meta = r.get("metadata") or {}
        if not reason and not involved:
            return None
        return ForensicEvent(
            **{"@timestamp": r.get("lastTimestamp") or r.get("eventTime")
               or meta.get("creationTimestamp")},
            message=r.get("message"),
            event=Event(action=reason, category=["process"], type=["info"],
                        outcome="failure" if r.get("type") == "Warning" else "success",
                        provider="kubernetes", dataset="k8s.event"),
            cloud=Cloud(provider="kubernetes"),
            orchestrator=_orch(namespace=involved.get("namespace"),
                               api_version=involved.get("apiVersion"),
                               resource=(involved.get("kind") or "").lower() or None,
                               res_name=involved.get("name")),
            k8s={"reason": reason, "type": r.get("type"), "count": r.get("count"),
                 "source_component": (r.get("source") or {}).get("component")},
        )


@register("k8s.container")
class ContainerParser(Parser):
    """A container entry: either a pod-spec container (needs _pod/_namespace
    context) or a runtime container from crictl/docker inspect."""

    def parse_record(self, r: dict[str, Any]) -> Optional[ForensicEvent]:
        name = r.get("name") or r.get("Name")
        if not name:
            return None
        image_ref = r.get("image") or r.get("Image")
        cid = r.get("containerID") or r.get("Id") or r.get("id")
        return ForensicEvent(
            **{"@timestamp": r.get("_timestamp") or r.get("startedAt")},
            event=Event(action="DescribeContainer", category=["configuration"],
                        type=["info"], kind="state",
                        provider="kubernetes", dataset="k8s.container"),
            cloud=Cloud(provider="kubernetes"),
            container=Container(id=cid, name=name, image=_image(image_ref),
                                runtime=r.get("_runtime")),
            orchestrator=_orch(namespace=r.get("_namespace"),
                               resource="pod", res_name=r.get("_pod")),
            k8s={"ready": r.get("ready"), "restart_count": r.get("restartCount"),
                 "privileged": (((r.get("securityContext") or {})
                                 .get("privileged"))),
                 "host_path_mounts": r.get("_host_path_mounts")},
        )


@register("k8s.etcd")
class EtcdParser(Parser):
    """A decoded etcd object: {"key": "/registry/secrets/ns/name", "value": {...}}.

    etcd holds every API object at rest, including Secrets. Decode a snapshot
    with a tool like `auger` and feed the resulting objects here.
    """

    def parse_record(self, r: dict[str, Any]) -> Optional[ForensicEvent]:
        key = r.get("key")
        value = r.get("value") or {}
        if not key:
            return None
        # /registry/<resource>/<namespace>/<name>  (namespace optional)
        parts = [p for p in key.split("/") if p]
        resource = parts[1] if len(parts) > 1 else None
        namespace = parts[2] if len(parts) > 3 else None
        res_name = parts[-1] if len(parts) > 2 else None
        kind = value.get("kind") if isinstance(value, dict) else None
        is_secret = resource == "secrets" or kind == "Secret"
        return ForensicEvent(
            **{"@timestamp": ((value.get("metadata") or {}) if isinstance(value, dict) else {})
               .get("creationTimestamp")},
            event=Event(action="EtcdObject", category=["configuration"],
                        type=["info"], kind="state",
                        provider="kubernetes", dataset="k8s.etcd"),
            cloud=Cloud(provider="kubernetes"),
            orchestrator=_orch(namespace=namespace, resource=resource,
                               res_name=res_name,
                               api_version=value.get("apiVersion")
                               if isinstance(value, dict) else None),
            k8s={"etcd_key": key, "kind": kind, "at_rest": True,
                 "contains_secret_material": is_secret,
                 "data_keys": sorted((value.get("data") or {}).keys())
                 if is_secret and isinstance(value, dict) else None},
        )
