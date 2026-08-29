"""CLI — build the AgentCore access graph and emit the graph document.

Usage:
  python -m agentcore_graph.cli --region us-east-1 -o graph.json
  python -m agentcore_graph.cli --region us-east-1 --agent <arn>   # subgraph
  python -m agentcore_graph.cli --region us-east-1 --summary        # counts only
"""
from __future__ import annotations

import argparse
import json
import sys

from .model import Graph, Node
from .resolver import build_graph

# Least-privilege, read-only policy the tool's own principal needs (SPEC §8).
# All actions are List/Get/read; there are no write actions anywhere.
READER_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Sid": "AgentCoreControlPlaneRead", "Effect": "Allow",
         "Action": ["bedrock-agentcore:List*", "bedrock-agentcore:Get*",
                    "bedrock-agentcore:Search*"], "Resource": "*"},
        {"Sid": "IamRoleAndPolicyRead", "Effect": "Allow",
         "Action": ["iam:GetRole", "iam:ListAttachedRolePolicies", "iam:ListRolePolicies",
                    "iam:GetPolicy", "iam:GetPolicyVersion", "iam:GetRolePolicy"],
         "Resource": "*"},
        {"Sid": "SsmParameterRead", "Effect": "Allow",
         "Action": ["ssm:GetParameter", "ssm:GetParametersByPath"], "Resource": "*"},
        {"Sid": "ObservabilityRead", "Effect": "Allow",
         "Action": ["logs:StartQuery", "logs:GetQueryResults", "logs:StopQuery",
                    "xray:GetTraceSummaries", "xray:BatchGetTraces",
                    "cloudwatch:GetMetricData"], "Resource": "*"},
        {"Sid": "StsWhoAmI", "Effect": "Allow",
         "Action": "sts:GetCallerIdentity", "Resource": "*"},
    ],
}


def _reader_policy_json() -> str:
    return json.dumps(READER_POLICY, indent=2)


def _subgraph(graph: Graph, agent_arn: str, max_depth: int = 6) -> Graph:
    """BFS out from an agent node over outgoing edges up to max_depth."""
    keep: set[str] = set()
    frontier = {agent_arn}
    out_adj: dict[str, list] = {}
    for e in graph.edges:
        out_adj.setdefault(e.from_id, []).append(e)
    depth = 0
    while frontier and depth <= max_depth:
        keep |= frontier
        nxt = set()
        for nid in frontier:
            for e in out_adj.get(nid, []):
                if e.to_id not in keep:
                    nxt.add(e.to_id)
        frontier = nxt
        depth += 1
    sub = Graph(graph.account, graph.region, graph.collected_at)
    for node in graph.nodes:
        if node.id in keep:
            sub.add_node(node)
    for e in graph.edges:
        if e.from_id in keep and e.to_id in keep:
            sub.add_edge(e)
    sub.findings = [f for f in graph.findings if any(r in keep for r in f.node_refs)]
    sub.errors = graph.errors
    return sub


def _print_summary(graph: Graph) -> None:
    from collections import Counter
    ntypes = Counter(n.type for n in graph.nodes)
    etypes = Counter(e.type for e in graph.edges)
    tiers = Counter(e.tier.value for e in graph.edges)
    print(f"account={graph.account} region={graph.region} @ {graph.collected_at}",
          file=sys.stderr)
    print(f"\nNodes ({len(graph.nodes)}):", file=sys.stderr)
    for t, c in ntypes.most_common():
        print(f"  {t}: {c}", file=sys.stderr)
    print(f"\nEdges ({len(graph.edges)}) by tier {dict(tiers)}:", file=sys.stderr)
    for t, c in etypes.most_common():
        print(f"  {t}: {c}", file=sys.stderr)
    print(f"\nFindings ({len(graph.findings)}):", file=sys.stderr)
    for f in graph.findings:
        print(f"  [{f.severity}] {f.rule}: {f.evidence}", file=sys.stderr)
    if graph.errors:
        print(f"\nCollection errors ({len(graph.errors)}):", file=sys.stderr)
        for e in graph.errors:
            print(f"  {e.collector} @ {e.target}: {e.error}", file=sys.stderr)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Build the AgentCore access graph (read-only).")
    ap.add_argument("--region", required=True)
    ap.add_argument("--agent", help="Restrict output to this agent runtime ARN's subgraph")
    ap.add_argument("-o", "--out", help="Write graph JSON to this file (default: stdout)")
    ap.add_argument("--no-raw", action="store_true", help="Omit raw source payloads")
    ap.add_argument("--summary", action="store_true", help="Print counts/findings to stderr only")
    ap.add_argument("--observe", action="store_true",
                    help="Overlay Tier-C observed edges from runtime traces (M5)")
    ap.add_argument("--observe-window", type=int, default=3600, metavar="SECONDS",
                    help="Observability lookback window in seconds (default: 3600)")
    ap.add_argument("--print-policy", action="store_true",
                    help="Print the least-privilege reader IAM policy this tool needs and exit")
    args = ap.parse_args(argv)

    if args.print_policy:
        print(_reader_policy_json())
        return 0

    graph = build_graph(args.region, observe=args.observe,
                        observe_window_seconds=args.observe_window)
    if args.agent:
        graph = _subgraph(graph, args.agent)

    _print_summary(graph)
    if args.summary:
        return 0

    out_json = graph.to_json(include_raw=not args.no_raw)
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(out_json)
        print(f"\nwrote {args.out}", file=sys.stderr)
    else:
        print(out_json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
