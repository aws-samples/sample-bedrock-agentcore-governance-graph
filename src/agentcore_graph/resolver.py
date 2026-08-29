"""Resolver — runs collectors, links Tier-B alias edges to real nodes,
computes findings, and returns the final Graph.

See docs/SPEC.md §5.2 (resolver) and §6 (findings).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from .aws import Aws, account_of, gateway_id_from_url, is_arn
from .collectors import ALL_COLLECTORS, ObservabilityCollector
from .model import Edge, EdgeType, Finding, Graph, NodeType, Tier


def build_graph(region: str, aws: Optional[Aws] = None,
                observe: bool = False, observe_window_seconds: int = 3600) -> Graph:
    aws = aws or Aws(region)
    account = aws.account_id()
    aws.account = account  # type: ignore[attr-defined]
    graph = Graph(account=account, region=region,
                  collected_at=datetime.now(timezone.utc).isoformat())
    for collector_cls in ALL_COLLECTORS:
        collector_cls(aws, graph).collect()
    if observe:  # Tier C — opt-in runtime overlay (M5)
        ObservabilityCollector(aws, graph, window_seconds=observe_window_seconds).collect()
    _resolve_aliases(graph)
    _compute_reachability(graph)
    _compute_findings(graph, observed=observe)
    return graph


def _compute_reachability(graph: Graph) -> None:
    """Stamp every node with the set of agent runtimes that can reach it over
    Tier-A/B edges (`sharedByAgents`). Computed once on the full graph so the
    fan-in survives per-agent subgraphing — this is the multi-tenancy / blast-
    radius signal (e.g. one gateway reachable by several runtimes)."""
    out_adj: dict[str, list[str]] = {}
    for e in graph.edges:
        out_adj.setdefault(e.from_id, []).append(e.to_id)

    agents = [n for n in graph.nodes if n.type == NodeType.AGENT_RUNTIME]
    reachers: dict[str, set[str]] = {}
    for agent in agents:
        seen: set[str] = set()
        stack = [agent.id]
        while stack:
            nid = stack.pop()
            for nxt in out_adj.get(nid, []):
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
        for nid in seen:
            reachers.setdefault(nid, set()).add(agent.id)

    for node in graph.nodes:
        if node.type == NodeType.AGENT_RUNTIME:
            continue
        who = sorted(reachers.get(node.id, ()))
        if who:
            node.attrs["sharedByAgents"] = who


def _resolve_aliases(graph: Graph) -> None:
    """Rewrite Tier-B unresolved edges (gatewayurl:*, memoryid:*) to point at
    the real gateway/memory node via the alias nodes the collectors emitted,
    then drop the alias placeholder nodes. Also re-points Tier-C observed-tool
    edges onto the matching real Tool node when one exists (join by tool name)."""
    alias_targets: dict[str, str] = {}
    for n in graph.nodes:
        if n.type == "_GatewayUrlAlias":
            alias_targets[n.id] = n.attrs.get("gatewayArn")
        elif n.type == "_MemoryIdAlias":
            alias_targets[n.id] = n.attrs.get("memoryArn")

    # map observed tool name -> real static Tool node id (first match wins)
    _resolve_observed_tools(graph)

    new_edges: list[Edge] = []
    for e in list(graph._edges.values()):  # noqa: SLF001 - internal rewrite
        if not e.attrs.get("unresolved"):
            new_edges.append(e)
            continue
        real = alias_targets.get(e.to_id)
        if real is None:
            # last-ditch: match a gateway URL env var by its gatewayId host label
            gid = gateway_id_from_url(e.attrs.get("gatewayUrl") or "")
            if gid:
                real = alias_targets.get(f"gatewayurl:{gid}")
        if real:
            new_edges.append(Edge(e.from_id, real, e.type, e.tier, e.source_api,
                                  attrs={k: v for k, v in e.attrs.items() if k != "unresolved"}))
        else:
            # leave dangling but keep visible as unresolved (gateway/memory not in account)
            new_edges.append(e)

    # rebuild edge map + drop alias nodes
    graph._edges = {}  # noqa: SLF001
    for e in new_edges:
        graph.add_edge(e)
    for alias_id in list(graph._nodes):  # noqa: SLF001
        if graph._nodes[alias_id].type in ("_GatewayUrlAlias", "_MemoryIdAlias"):  # noqa: SLF001
            del graph._nodes[alias_id]  # noqa: SLF001


def _resolve_observed_tools(graph: Graph) -> None:
    """Re-point `observed-tool:<name>` edges onto the real Tool node with that
    name (proving an A/B tool was actually used → Tier C). If no static tool
    matches, the observed-tool node stays as a standalone Tier-C node."""
    static_tool_by_name: dict[str, str] = {}
    for n in graph.nodes:
        if n.type == NodeType.TOOL and not n.attrs.get("observed"):
            static_tool_by_name.setdefault(n.name, n.id)

    rewritten: list[Edge] = []
    used_observed_ids: set[str] = set()
    for e in list(graph._edges.values()):  # noqa: SLF001
        if e.to_id.startswith("observed-tool:"):
            real = static_tool_by_name.get(e.attrs.get("observedTool", ""))
            if real:
                rewritten.append(Edge(e.from_id, real, e.type, e.tier, e.source_api,
                                      attrs=dict(e.attrs)))
                # carry the observation onto the real Tool node (drives rule 2)
                graph._nodes[real].attrs["observed"] = True  # noqa: SLF001
                continue
            used_observed_ids.add(e.to_id)
        rewritten.append(e)
    graph._edges = {}  # noqa: SLF001
    for e in rewritten:
        graph.add_edge(e)
    # drop orphan observed-tool nodes that got merged into a real tool
    for nid in list(graph._nodes):  # noqa: SLF001
        if nid.startswith("observed-tool:") and nid not in used_observed_ids:
            del graph._nodes[nid]  # noqa: SLF001


def _compute_findings(graph: Graph, observed: bool = False) -> None:
    n = 0

    def fid() -> str:
        nonlocal n
        n += 1
        return f"F-{n:03d}"

    # Rule 1: over-broad IAM (Resource: * or Action: service:*)
    for node in graph.nodes:
        if node.type != NodeType.IAM_POLICY:
            continue
        doc = node.attrs.get("document")
        for stmt in _stmts(doc):
            if stmt.get("Effect") != "Allow":
                continue
            resources = _as_list(stmt.get("Resource"))
            actions = _as_list(stmt.get("Action"))
            star_res = any(r == "*" for r in resources)
            star_act = any(isinstance(a, str) and a.endswith(":*") for a in actions)
            if star_res:
                sev = "high" if star_act else "medium"
                wild_actions = [a for a in actions if str(a).endswith(":*")]
                ev = f"Policy '{node.name}': Allow on Resource '*'"
                if star_act:
                    ev += f" with wildcard action(s) {wild_actions}"
                graph.findings.append(Finding(
                    fid(), "over-broad-iam", sev, [node.id], Tier.A, ev))

    # Rule 3: unauthenticated inbound (runtime/gateway without JWT authorizer)
    for node in graph.nodes:
        if node.type in (NodeType.AGENT_RUNTIME, NodeType.GATEWAY):
            if node.attrs.get("hasInboundAuth") is False:
                graph.findings.append(Finding(
                    fid(), "unauthenticated-inbound", "high", [node.id], Tier.A,
                    f"{node.type} '{node.name}' has no inbound JWT authorizer"))

    # Rule 6: dangling credential provider (no target references it)
    used_creds = {e.to_id for e in graph.edges if e.type == EdgeType.USES_CREDENTIAL}
    for node in graph.nodes:
        if node.type == NodeType.CREDENTIAL_PROVIDER and node.id not in used_creds:
            graph.findings.append(Finding(
                fid(), "dangling-credential", "low", [node.id], Tier.A,
                f"CredentialProvider '{node.name}' is not referenced by any gateway target"))

    # Rule 5: cross-boundary data egress — a data source / external resource in
    # a different account than the graph's own account, reached from any node.
    home = graph.account
    if home:
        egress_types = {EdgeType.READS_DATA_SOURCE, EdgeType.REACHES_RESOURCE,
                        EdgeType.GRANTS_ACCESS_TO}
        flagged: set[str] = set()
        for e in graph.edges:
            if e.type not in egress_types or e.to_id in flagged:
                continue
            dst = graph._nodes.get(e.to_id)  # noqa: SLF001
            if dst is None or dst.type not in (NodeType.DATA_SOURCE, NodeType.EXTERNAL_RESOURCE):
                continue
            other = account_of(e.to_id) or dst.account
            if other and other != home:
                flagged.add(e.to_id)
                graph.findings.append(Finding(
                    fid(), "cross-boundary-egress", "high", [e.from_id, e.to_id], e.tier,
                    f"{dst.type} '{dst.name}' is in account {other}, outside the "
                    f"home account {home} (via {e.type})"))

    # Rule 4: gateway bound to policy engine but policy not enforcing
    pe_edges = {e.to_id for e in graph.edges if e.type == EdgeType.BOUND_TO_POLICY_ENGINE}
    for pe_id in pe_edges:
        policies = [e.to_id for e in graph.edges
                    if e.from_id == pe_id and e.type == EdgeType.HAS_POLICY]
        non_enforcing = [p for p in policies
                         if _node_attr(graph, p, "enforcementMode") not in ("ENFORCING", "enforce", None)]
        if policies and non_enforcing:
            graph.findings.append(Finding(
                fid(), "cedar-not-enforcing", "medium", [pe_id] + non_enforcing, Tier.A,
                f"PolicyEngine bound to a gateway has {len(non_enforcing)} non-enforcing policies"))

    # Rules 2 & 7 require the Tier-C observability overlay (M5).
    if observed:
        # Rule 2: over-provisioning gap — a tool/resource reachable via Tier A/B
        # that was never seen in Tier C traces (agent granted more than it used).
        # A Tier-C edge collapses into a colliding Tier-A/B edge by key, so the
        # observation is recorded on the target node's `observed` attr, not tier.
        gap_types = (EdgeType.EXPOSES_TOOL, EdgeType.REACHES_RESOURCE,
                     EdgeType.READS_DATA_SOURCE, EdgeType.DELEGATES_TO)
        seen_gap: set[str] = set()
        for e in graph.edges:
            if e.type not in gap_types or e.to_id in seen_gap:
                continue
            dst = graph._nodes.get(e.to_id)  # noqa: SLF001
            if dst is None or dst.type not in (NodeType.TOOL, NodeType.EXTERNAL_RESOURCE,
                                               NodeType.DATA_SOURCE, NodeType.AGENT_RUNTIME):
                continue
            if dst.attrs.get("observed"):
                continue
            seen_gap.add(e.to_id)
            graph.findings.append(Finding(
                fid(), "over-provisioning-gap", "medium", [e.from_id, e.to_id], e.tier,
                f"{dst.type} '{dst.name}' is reachable (Tier {e.tier.value}) but was "
                f"never observed in traces — candidate for least-privilege removal"))

        # Rule 7: untraced agent — no observed (Tier C) activity in the window.
        for node in graph.nodes:
            if node.type == NodeType.AGENT_RUNTIME and not node.attrs.get("observed"):
                graph.findings.append(Finding(
                    fid(), "untraced-agent", "low", [node.id], Tier.C,
                    f"AgentRuntime '{node.name}' has no spans in the observability "
                    f"window (blind spot — cannot assess actual usage)"))

    # sort by severity
    order = {"high": 0, "medium": 1, "low": 2}
    graph.findings.sort(key=lambda f: order.get(f.severity, 3))


def _node_attr(graph: Graph, node_id: str, key: str):
    node = graph._nodes.get(node_id)  # noqa: SLF001
    return node.attrs.get(key) if node else None


def _stmts(doc):
    if not doc:
        return []
    s = doc.get("Statement")
    return s if isinstance(s, list) else ([s] if s else [])


def _as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]
