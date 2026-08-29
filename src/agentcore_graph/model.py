"""Graph data model — nodes, edges, findings, provenance tiers.

See docs/SPEC.md §4 (graph model) and §7 (document schema).
"""
from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Tier(str, Enum):
    """Edge provenance tier — how confidently we know this edge exists."""

    A = "A"  # static / authoritative (control-plane config or IAM/Cedar)
    B = "B"  # inferred (parsed from environmentVariables / SSM / artifact)
    C = "C"  # observed (seen in runtime traces) — M5


@dataclass
class Node:
    id: str  # canonical: ARN where one exists, else "{type}:{region}:{account}:{id}"
    type: str
    name: str
    region: Optional[str] = None
    account: Optional[str] = None
    attrs: dict[str, Any] = field(default_factory=dict)
    source_api: Optional[str] = None
    raw: Optional[dict[str, Any]] = None

    def to_dict(self, include_raw: bool = True) -> dict[str, Any]:
        d = {
            "id": self.id,
            "type": self.type,
            "name": self.name,
            "region": self.region,
            "account": self.account,
            "attrs": self.attrs,
            "sourceApi": self.source_api,
        }
        if include_raw:
            d["raw"] = self.raw
        return d


@dataclass
class Edge:
    from_id: str
    to_id: str
    type: str
    tier: Tier
    source_api: Optional[str] = None
    attrs: dict[str, Any] = field(default_factory=dict)

    def key(self) -> tuple:
        return (self.from_id, self.to_id, self.type)

    def to_dict(self) -> dict[str, Any]:
        return {
            "from": self.from_id,
            "to": self.to_id,
            "type": self.type,
            "tier": self.tier.value,
            "sourceApi": self.source_api,
            "attrs": self.attrs,
        }


@dataclass
class Finding:
    id: str
    rule: str
    severity: str  # low | medium | high
    node_refs: list[str]
    tier: Tier
    evidence: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule": self.rule,
            "severity": self.severity,
            "nodeRefs": self.node_refs,
            "tier": self.tier.value,
            "evidence": self.evidence,
        }


@dataclass
class CollectionError:
    collector: str
    target: str
    error: str

    def to_dict(self) -> dict[str, Any]:
        return {"collector": self.collector, "target": self.target, "error": self.error}


class Graph:
    """Accumulates nodes/edges/findings; dedupes by id/key."""

    def __init__(self, account: str, region: str, collected_at: str):
        self.account = account
        self.region = region
        self.collected_at = collected_at
        self._nodes: dict[str, Node] = {}
        self._edges: dict[tuple, Edge] = {}
        self.findings: list[Finding] = []
        self.errors: list[CollectionError] = []

    def add_node(self, node: Node) -> Node:
        existing = self._nodes.get(node.id)
        if existing is None:
            self._nodes[node.id] = node
            return node
        # merge: prefer a node that carries a full payload over a stub
        if not existing.raw and node.raw:
            self._nodes[node.id] = node
            return node
        existing.attrs.update({k: v for k, v in node.attrs.items() if v is not None})
        return existing

    def add_edge(self, edge: Edge) -> None:
        k = edge.key()
        existing = self._edges.get(k)
        # a stronger tier (A < B < C ordering by confidence: A strongest) wins
        if existing is None or _tier_rank(edge.tier) < _tier_rank(existing.tier):
            self._edges[k] = edge

    def add_error(self, collector: str, target: str, error: str) -> None:
        self.errors.append(CollectionError(collector, target, error))

    def has_node(self, node_id: str) -> bool:
        return node_id in self._nodes

    @property
    def nodes(self) -> list[Node]:
        return list(self._nodes.values())

    @property
    def edges(self) -> list[Edge]:
        return list(self._edges.values())

    def to_dict(self, include_raw: bool = True) -> dict[str, Any]:
        return {
            "account": self.account,
            "region": self.region,
            "collectedAt": self.collected_at,
            "nodes": [n.to_dict(include_raw) for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "findings": [f.to_dict() for f in self.findings],
            "collectionErrors": [e.to_dict() for e in self.errors],
        }

    def to_json(self, include_raw: bool = True, indent: int = 2) -> str:
        return json.dumps(self.to_dict(include_raw), indent=indent, default=str)


def _tier_rank(t: Tier) -> int:
    # lower rank = stronger provenance
    return {"A": 0, "B": 1, "C": 2}[t.value]


# ---- node type constants ----
class NodeType:
    AGENT_RUNTIME = "AgentRuntime"
    AGENT_ENDPOINT = "AgentRuntimeEndpoint"
    GATEWAY = "Gateway"
    GATEWAY_TARGET = "GatewayTarget"
    TOOL = "Tool"
    CREDENTIAL_PROVIDER = "CredentialProvider"
    WORKLOAD_IDENTITY = "WorkloadIdentity"
    POLICY_ENGINE = "PolicyEngine"
    CEDAR_POLICY = "CedarPolicy"
    REGISTRY = "Registry"
    REGISTRY_RECORD = "RegistryRecord"
    MEMORY = "Memory"
    IAM_ROLE = "IamRole"
    IAM_POLICY = "IamPolicy"
    EXTERNAL_RESOURCE = "ExternalResource"
    DATA_SOURCE = "DataSource"


class EdgeType:
    ASSUMES_ROLE = "assumesRole"
    HAS_WORKLOAD_IDENTITY = "hasWorkloadIdentity"
    USES_GATEWAY = "usesGateway"
    USES_MEMORY = "usesMemory"
    HAS_TARGET = "hasTarget"
    EXPOSES_TOOL = "exposesTool"
    USES_CREDENTIAL = "usesCredential"
    BOUND_TO_POLICY_ENGINE = "boundToPolicyEngine"
    HAS_POLICY = "hasPolicy"
    ATTACHES_POLICY = "attachesPolicy"
    GRANTS_ACCESS_TO = "grantsAccessTo"
    REACHES_RESOURCE = "reachesResource"
    READS_DATA_SOURCE = "readsDataSource"
    DELEGATES_TO = "delegatesTo"  # agent -> agent


def dataclass_asdict(obj: Any) -> Any:
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    return obj
