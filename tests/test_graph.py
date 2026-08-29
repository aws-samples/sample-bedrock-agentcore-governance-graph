"""Offline unit tests for the pure graph logic — no AWS calls.

Covers: target union dispatch, ARN parsing, graph dedup/tier precedence,
Tier-B alias resolution, and findings rules.
Run: PYTHONPATH=src python3 -m pytest tests/ -q   (or: python3 tests/test_graph.py)
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agentcore_graph.aws import (parse_arn, is_arn, role_name_from_arn,  # noqa: E402
                                 account_of, normalize_gateway_url, gateway_id_from_url)
from agentcore_graph.collectors import (_target_kind, spans_to_edges,  # noqa: E402
                                         SsmConfigCollector)
from agentcore_graph.model import Edge, EdgeType, Graph, Node, NodeType, Tier  # noqa: E402
from agentcore_graph.resolver import (_resolve_aliases, _compute_findings,  # noqa: E402
                                      _resolve_observed_tools, _compute_reachability)


def test_parse_arn():
    p = parse_arn("arn:aws:iam::123:role/MyRole")
    assert p["service"] == "iam" and p["resource_type"] == "role" and p["resource_id"] == "MyRole"
    assert role_name_from_arn("arn:aws:iam::123:role/MyRole") == "MyRole"
    assert parse_arn("not-an-arn") is None
    assert is_arn("arn:aws:s3:::b") and not is_arn("x")


def test_target_kind_dispatch():
    assert _target_kind({"mcp": {"lambda": {"lambdaArn": "a"}}})[0] == "mcp.lambda"
    assert _target_kind({"http": {"agentcoreRuntime": {"arn": "x"}}})[0] == "http.agentcoreRuntime"
    assert _target_kind({"mcp": {"openApiSchema": {"s3": {}}}})[0] == "mcp.openApiSchema"
    assert _target_kind({})[0] == "unknown"


def test_graph_dedup_and_tier_precedence():
    g = Graph("acct", "us-east-1", "t")
    g.add_node(Node("n1", NodeType.AGENT_RUNTIME, "a"))
    g.add_node(Node("n1", NodeType.AGENT_RUNTIME, "a"))  # dup
    assert len(g.nodes) == 1
    # Tier A should win over a pre-existing Tier B for the same edge key
    g.add_edge(Edge("a", "b", EdgeType.USES_GATEWAY, Tier.B, "env"))
    g.add_edge(Edge("a", "b", EdgeType.USES_GATEWAY, Tier.A, "config"))
    assert len(g.edges) == 1 and g.edges[0].tier == Tier.A


def test_alias_resolution():
    g = Graph("acct", "us-east-1", "t")
    g.add_node(Node("arn:...:runtime/agent", NodeType.AGENT_RUNTIME, "agent"))
    # memory + its alias, as MemoryCollector would emit
    g.add_node(Node("arn:...:memory/M", NodeType.MEMORY, "M"))
    g.add_node(Node("memoryid:M-123", "_MemoryIdAlias", "M-123",
                    attrs={"memoryArn": "arn:...:memory/M"}))
    # unresolved Tier-B edge from RuntimeCollector
    g.add_edge(Edge("arn:...:runtime/agent", "memoryid:M-123", EdgeType.USES_MEMORY,
                    Tier.B, "env", attrs={"memoryId": "M-123", "unresolved": True}))
    _resolve_aliases(g)
    mem_edges = [e for e in g.edges if e.type == EdgeType.USES_MEMORY]
    assert len(mem_edges) == 1
    assert mem_edges[0].to_id == "arn:...:memory/M"  # rewritten to real ARN
    assert not mem_edges[0].attrs.get("unresolved")
    # alias node dropped
    assert not any(n.type == "_MemoryIdAlias" for n in g.nodes)


def test_findings_over_broad_iam():
    g = Graph("acct", "us-east-1", "t")
    g.add_node(Node("pol1", NodeType.IAM_POLICY, "BroadPolicy", attrs={
        "document": {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}}))
    _compute_findings(g)
    f = [x for x in g.findings if x.rule == "over-broad-iam"]
    assert len(f) == 1 and f[0].severity == "high"  # Resource * AND action :* => high


def test_findings_unauthenticated_inbound():
    g = Graph("acct", "us-east-1", "t")
    g.add_node(Node("gw", NodeType.GATEWAY, "open-gw", attrs={"hasInboundAuth": False}))
    g.add_node(Node("gw2", NodeType.GATEWAY, "secure-gw", attrs={"hasInboundAuth": True}))
    _compute_findings(g)
    f = [x for x in g.findings if x.rule == "unauthenticated-inbound"]
    assert len(f) == 1 and f[0].node_refs == ["gw"]


def test_findings_dangling_credential():
    g = Graph("acct", "us-east-1", "t")
    g.add_node(Node("cred1", NodeType.CREDENTIAL_PROVIDER, "unused"))
    g.add_node(Node("cred2", NodeType.CREDENTIAL_PROVIDER, "used"))
    g.add_node(Node("tgt", NodeType.GATEWAY_TARGET, "t"))
    g.add_edge(Edge("tgt", "cred2", EdgeType.USES_CREDENTIAL, Tier.A, "cfg"))
    _compute_findings(g)
    f = [x for x in g.findings if x.rule == "dangling-credential"]
    assert len(f) == 1 and f[0].node_refs == ["cred1"]


# ---- M2: robust gateway-URL / alias join ----
def test_normalize_gateway_url():
    a = normalize_gateway_url("https://gw-abc.gateway.bedrock-agentcore.us-east-1.amazonaws.com/mcp")
    b = normalize_gateway_url("gw-abc.gateway.bedrock-agentcore.us-east-1.amazonaws.com/")
    assert a == b == "gw-abc.gateway.bedrock-agentcore.us-east-1.amazonaws.com"
    assert gateway_id_from_url(
        "https://gw-abc.gateway.bedrock-agentcore.us-east-1.amazonaws.com/mcp") == "gw-abc"
    assert account_of("arn:aws:s3:::b") in (None, "")  # s3 arns carry no account


def test_alias_join_by_gateway_id_fallback():
    # env var URL differs from control-plane URL, but shares the gatewayId host
    g = Graph("acct", "us-east-1", "t")
    g.add_node(Node("arn:...:runtime/agent", NodeType.AGENT_RUNTIME, "agent"))
    g.add_node(Node("arn:...:gateway/G", NodeType.GATEWAY, "G"))
    # GatewayCollector registers an alias keyed by gatewayId
    g.add_node(Node("gatewayurl:gw-xyz", "_GatewayUrlAlias", "gw-xyz",
                    attrs={"gatewayArn": "arn:...:gateway/G"}))
    # RuntimeCollector emitted an unresolved edge with a normalized URL that
    # does NOT match the alias key directly, but the URL carries the gatewayId
    g.add_edge(Edge("arn:...:runtime/agent",
                    "gatewayurl:gw-xyz.gateway.bedrock-agentcore.us-east-1.amazonaws.com",
                    EdgeType.USES_GATEWAY, Tier.B, "env",
                    attrs={"gatewayUrl": "https://gw-xyz.gateway.bedrock-agentcore.us-east-1.amazonaws.com/mcp",
                           "unresolved": True}))
    _resolve_aliases(g)
    gw_edges = [e for e in g.edges if e.type == EdgeType.USES_GATEWAY]
    assert len(gw_edges) == 1 and gw_edges[0].to_id == "arn:...:gateway/G"


# ---- M4: cross-boundary data egress (rule 5) ----
def test_findings_cross_boundary_egress():
    g = Graph("111122223333", "us-east-1", "t")
    g.add_node(Node("arn:...:runtime/agent", NodeType.AGENT_RUNTIME, "agent"))
    foreign = "arn:aws:s3:us-east-1:999988887777:accesspoint/ap"
    same = "arn:aws:dynamodb:us-east-1:111122223333:table/T"
    g.add_node(Node(foreign, NodeType.DATA_SOURCE, "ap", account="999988887777"))
    g.add_node(Node(same, NodeType.EXTERNAL_RESOURCE, "T", account="111122223333"))
    g.add_edge(Edge("arn:...:runtime/agent", foreign, EdgeType.READS_DATA_SOURCE, Tier.A, "x"))
    g.add_edge(Edge("arn:...:runtime/agent", same, EdgeType.REACHES_RESOURCE, Tier.A, "x"))
    _compute_findings(g)
    f = [x for x in g.findings if x.rule == "cross-boundary-egress"]
    assert len(f) == 1 and foreign in f[0].node_refs and f[0].severity == "high"


# ---- M5: Tier-C observability overlay ----
def test_spans_to_edges():
    agent_by_key = {"arn:...:runtime/agent": "arn:...:runtime/agent", "agent": "arn:...:runtime/agent"}
    rows = [
        {"attributes.agent.name": "agent", "attributes.tool.name": "persist_to_neptune"},
        {"attributes.agent.arn": "arn:...:runtime/agent",
         "attributes.downstream.arn": "arn:aws:lambda:us-east-1:1:function:F"},
        {"attributes.agent.name": "unknown", "attributes.tool.name": "x"},  # dropped
    ]
    edges = spans_to_edges(rows, agent_by_key)
    assert len(edges) == 2
    assert all(e.tier == Tier.C for e in edges)
    assert any(e.to_id == "observed-tool:persist_to_neptune" for e in edges)
    assert any(e.type == EdgeType.REACHES_RESOURCE for e in edges)


def test_spans_to_edges_agentcore_resource_schema():
    """Real AgentCore/OTel GenAI spans attribute the agent via the OTel resource
    (service.name = "<name>.DEFAULT", cloud.resource_id embeds the runtime ARN)
    and carry the tool in attributes.gen_ai.tool.name — not attributes.agent.*."""
    arn = "arn:aws:bedrock-agentcore:us-east-1:1:runtime/orchestrator-abc"
    agent_by_key = {arn: arn, "orchestrator": arn, "orchestrator.DEFAULT": arn}
    rows = [
        # attributed by service.name
        {"resource.attributes.service.name": "orchestrator.DEFAULT",
         "attributes.gen_ai.tool.name": "update_job"},
        # attributed by ARN prefix inside cloud.resource_id (+ endpoint suffix)
        {"resource.attributes.cloud.resource_id": arn + "/runtime-endpoint/DEFAULT:DEFAULT",
         "attributes.gen_ai.tool.name": "search_documents"},
        # duplicate tool for same agent -> deduped
        {"resource.attributes.service.name": "orchestrator.DEFAULT",
         "attributes.gen_ai.tool.name": "update_job"},
        # unknown agent -> dropped
        {"resource.attributes.service.name": "stranger.DEFAULT",
         "attributes.gen_ai.tool.name": "x"},
    ]
    edges = spans_to_edges(rows, agent_by_key)
    assert len(edges) == 2  # two distinct tools, dedup drops the repeat, stranger dropped
    assert all(e.from_id == arn and e.tier == Tier.C for e in edges)
    tools = {e.to_id for e in edges}
    assert tools == {"observed-tool:update_job", "observed-tool:search_documents"}


class _FakeAws:
    """Minimal Aws stand-in for collector unit tests (no boto3)."""
    region = "us-east-1"
    account = "111122223333"


def test_ssm_norm_key():
    n = SsmConfigCollector._norm_key
    # SSM path -> canonical env-style key (last segment, non-alnum -> _, upper)
    assert n("/agenticidp/dev/gateway-url") == "GATEWAY_URL"
    assert n("/agenticidp/agents/create_job_lambda_arn") == "CREATE_JOB_LAMBDA_ARN"
    assert n("/a/b/lessons-memory-id") == "LESSONS_MEMORY_ID"


def test_ssm_prefixes_from_policy():
    c = SsmConfigCollector(_FakeAws(), Graph("acct", "us-east-1", "t"))
    doc = {"Statement": [
        {"Effect": "Allow",
         "Action": ["ssm:GetParametersByPath", "ssm:GetParameter"],
         "Resource": "arn:aws:ssm:us-east-1:1:parameter/agenticidp/dev/*"},
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},  # not ssm
        {"Effect": "Deny", "Action": "ssm:GetParameter",
         "Resource": "arn:aws:ssm:us-east-1:1:parameter/secret/*"},       # denied, skip
    ]}
    assert c._ssm_prefixes(doc) == {"/agenticidp/dev/"}


def test_ssm_classify_links_gateway_and_delegation():
    g = Graph("acct", "us-east-1", "t")
    c = SsmConfigCollector(_FakeAws(), g)
    agent = "arn:aws:bedrock-agentcore:us-east-1:1:runtime/orchestrator-abc"
    # a gateway url -> unresolved gatewayurl: alias edge (resolver links it later)
    c._classify(agent, "GATEWAY_URL",
                "https://gw-xyz.gateway.bedrock-agentcore.us-east-1.amazonaws.com/mcp",
                "ssm:/agenticidp/dev/gateway-url")
    # a sub-agent runtime ARN -> Tier-B delegation edge
    sub = "arn:aws:bedrock-agentcore:us-east-1:1:runtime/child-def"
    c._classify(agent, "CHILD_ARN", sub, "ssm:/agenticidp/agents/child_arn")
    # the agent's own ARN -> self-edge suppressed
    c._classify(agent, "SELF_ARN", agent, "ssm:/agenticidp/agents/orchestrator_arn")
    by_type = {(e.type, e.tier) for e in g.edges}
    assert (EdgeType.USES_GATEWAY, Tier.B) in by_type
    assert (EdgeType.DELEGATES_TO, Tier.B) in by_type
    deleg = [e for e in g.edges if e.type == EdgeType.DELEGATES_TO]
    assert len(deleg) == 1 and deleg[0].to_id == sub  # self-ref dropped


def test_resolve_observed_tools_joins_static():
    g = Graph("acct", "us-east-1", "t")
    g.add_node(Node("arn:...:runtime/agent", NodeType.AGENT_RUNTIME, "agent"))
    g.add_node(Node("tgt/tool/persist_to_neptune", NodeType.TOOL, "persist_to_neptune"))
    g.add_node(Node("observed-tool:persist_to_neptune", NodeType.TOOL, "persist_to_neptune",
                    attrs={"observed": True}))
    g.add_edge(Edge("arn:...:runtime/agent", "observed-tool:persist_to_neptune",
                    EdgeType.EXPOSES_TOOL, Tier.C, "spans",
                    attrs={"observedTool": "persist_to_neptune"}))
    _resolve_observed_tools(g)
    c_edges = [e for e in g.edges if e.tier == Tier.C]
    assert len(c_edges) == 1 and c_edges[0].to_id == "tgt/tool/persist_to_neptune"
    assert not any(n.id.startswith("observed-tool:") for n in g.nodes)


def test_findings_over_provisioning_and_untraced():
    g = Graph("acct", "us-east-1", "t")
    g.add_node(Node("arn:...:runtime/a1", NodeType.AGENT_RUNTIME, "a1", attrs={"observed": True}))
    g.add_node(Node("arn:...:runtime/a2", NodeType.AGENT_RUNTIME, "a2"))  # untraced
    # a1 can reach both tools (Tier A) but only "used" was seen in traces —
    # observation is recorded as the target node's `observed` attr (as the
    # ObservabilityCollector does), since a Tier-C edge collapses by key.
    g.add_node(Node("tool/used", NodeType.TOOL, "used", attrs={"observed": True}))
    g.add_node(Node("tool/unused", NodeType.TOOL, "unused"))
    g.add_edge(Edge("arn:...:runtime/a1", "tool/used", EdgeType.EXPOSES_TOOL, Tier.A, "x"))
    g.add_edge(Edge("arn:...:runtime/a1", "tool/unused", EdgeType.EXPOSES_TOOL, Tier.A, "x"))
    _compute_findings(g, observed=True)
    gap = [x for x in g.findings if x.rule == "over-provisioning-gap"]
    untraced = [x for x in g.findings if x.rule == "untraced-agent"]
    assert len(gap) == 1 and "tool/unused" in gap[0].node_refs
    assert len(untraced) == 1 and untraced[0].node_refs == ["arn:...:runtime/a2"]
    # gated: without observed=True neither rule fires
    g2 = Graph("acct", "us-east-1", "t")
    g2.add_node(Node("arn:...:runtime/a2", NodeType.AGENT_RUNTIME, "a2"))
    _compute_findings(g2, observed=False)
    assert not any(x.rule in ("over-provisioning-gap", "untraced-agent") for x in g2.findings)


# ---- shared-resource fan-in (blast radius) ----
def test_compute_reachability_shared_gateway():
    g = Graph("acct", "us-east-1", "t")
    g.add_node(Node("arn:...:runtime/a1", NodeType.AGENT_RUNTIME, "a1"))
    g.add_node(Node("arn:...:runtime/a2", NodeType.AGENT_RUNTIME, "a2"))
    g.add_node(Node("arn:...:runtime/a3", NodeType.AGENT_RUNTIME, "a3"))
    g.add_node(Node("arn:...:gateway/shared", NodeType.GATEWAY, "shared-gw"))
    g.add_node(Node("arn:...:gateway/solo", NodeType.GATEWAY, "solo-gw"))
    g.add_node(Node("tgt/tool", NodeType.TOOL, "t"))
    # a1 and a2 both reach the shared gateway -> its tool; a3 reaches solo gw
    g.add_edge(Edge("arn:...:runtime/a1", "arn:...:gateway/shared", EdgeType.USES_GATEWAY, Tier.B, "env"))
    g.add_edge(Edge("arn:...:runtime/a2", "arn:...:gateway/shared", EdgeType.USES_GATEWAY, Tier.B, "env"))
    g.add_edge(Edge("arn:...:gateway/shared", "tgt/tool", EdgeType.HAS_TARGET, Tier.A, "cfg"))
    g.add_edge(Edge("arn:...:runtime/a3", "arn:...:gateway/solo", EdgeType.USES_GATEWAY, Tier.B, "env"))
    _compute_reachability(g)
    idx = {n.id: n for n in g.nodes}
    assert idx["arn:...:gateway/shared"].attrs["sharedByAgents"] == \
        ["arn:...:runtime/a1", "arn:...:runtime/a2"]
    # downstream tool inherits both reachers (fan-in propagates transitively)
    assert idx["tgt/tool"].attrs["sharedByAgents"] == ["arn:...:runtime/a1", "arn:...:runtime/a2"]
    assert idx["arn:...:gateway/solo"].attrs["sharedByAgents"] == ["arn:...:runtime/a3"]
    # agents themselves are not stamped
    assert "sharedByAgents" not in idx["arn:...:runtime/a1"].attrs


def _run_all():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        fn()
        passed += 1
        print(f"  ok  {fn.__name__}")
    print(f"\n{passed}/{len(fns)} passed")


if __name__ == "__main__":
    _run_all()
