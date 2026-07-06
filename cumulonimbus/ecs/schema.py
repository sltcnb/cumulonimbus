"""ECS v8 forensic event model.

A minimal, pydantic-validated subset of Elastic Common Schema v8 covering the
fields Cumulus parsers populate. Extra provider-specific data lives under the
provider namespace (aws/azure/gcp) as free-form dicts.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class _Base(BaseModel):
    # Allow provider dicts with arbitrary keys, drop None on export.
    model_config = ConfigDict(extra="allow")


class Event(_Base):
    action: Optional[str] = None
    category: list[str] = Field(default_factory=list)
    type: list[str] = Field(default_factory=list)
    outcome: Optional[str] = None
    provider: Optional[str] = None
    kind: str = "event"
    dataset: Optional[str] = None


class Geo(_Base):
    country_name: Optional[str] = None
    country_iso_code: Optional[str] = None
    city_name: Optional[str] = None


class Host(_Base):
    ip: Optional[str] = None
    port: Optional[int] = None
    geo: Optional[Geo] = None
    address: Optional[str] = None
    domain: Optional[str] = None
    as_number: Optional[int] = None  # ECS: source.as.number


class User(_Base):
    name: Optional[str] = None
    id: Optional[str] = None
    email: Optional[str] = None


class Network(_Base):
    transport: Optional[str] = None
    protocol: Optional[str] = None
    bytes: Optional[int] = None
    packets: Optional[int] = None
    direction: Optional[str] = None


class Cloud(_Base):
    provider: Optional[str] = None
    account_id: Optional[str] = None
    region: Optional[str] = None
    service_name: Optional[str] = None


class OrchestratorResource(_Base):
    name: Optional[str] = None
    type: Optional[str] = None  # ECS: orchestrator.resource.type (e.g. "pod")


class Orchestrator(_Base):
    """ECS orchestrator.* — Kubernetes and other cluster orchestrators."""

    type: Optional[str] = None  # "kubernetes"
    namespace: Optional[str] = None
    api_version: Optional[str] = None
    cluster_name: Optional[str] = None
    resource: Optional[OrchestratorResource] = None


class ContainerImage(_Base):
    name: Optional[str] = None
    tag: Optional[list[str]] = None


class Container(_Base):
    """ECS container.* — a single container's identity and image."""

    id: Optional[str] = None
    name: Optional[str] = None
    runtime: Optional[str] = None
    image: Optional[ContainerImage] = None


class ForensicEvent(_Base):
    """One normalized event. Serialize with `.to_ecs()`."""

    timestamp: Optional[str] = Field(default=None, alias="@timestamp")
    event: Event = Field(default_factory=Event)
    user: Optional[User] = None
    source: Optional[Host] = None
    destination: Optional[Host] = None
    network: Optional[Network] = None
    cloud: Optional[Cloud] = None
    orchestrator: Optional[Orchestrator] = None
    container: Optional[Container] = None
    message: Optional[str] = None
    # Provider-specific raw namespaces.
    aws: Optional[dict[str, Any]] = None
    azure: Optional[dict[str, Any]] = None
    gcp: Optional[dict[str, Any]] = None
    threat: Optional[dict[str, Any]] = None

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    def to_ecs(self) -> dict[str, Any]:
        """Dict with ECS field names, None/empty pruned, `@timestamp` restored."""
        raw = self.model_dump(by_alias=True, exclude_none=True)
        return _prune(raw)


def _prune(obj: Any) -> Any:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            pv = _prune(v)
            if pv in (None, {}, []):
                continue
            out[k] = pv
        return out
    if isinstance(obj, list):
        return [_prune(v) for v in obj]
    return obj
