"""FastAPI backend for the AgentCore access-graph web app.

Read-only. Builds the graph once per (region) and caches it; the frontend
queries /inventory and /graph. Rebuild with ?refresh=1.

Run:
  PYTHONPATH=src uvicorn agentcore_graph.api:app --reload --port 8899
  # then open http://localhost:8899/
"""
from __future__ import annotations

import os
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .cli import READER_POLICY, _subgraph
from .model import Graph, NodeType
from .resolver import build_graph

app = FastAPI(title="AgentCore Access Graph", version="0.1.0")

_DEFAULT_REGION = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
# Tier-C observe lookback (seconds). Sessions older than this window won't be
# seen; overridable per request via ?observe_window=. Default 24h so a graph
# built hours after the last agent run still shows its sessions (the 1h CLI
# default is too short for an on-demand dashboard).
_DEFAULT_OBSERVE_WINDOW = int(os.environ.get("OBSERVE_WINDOW_SECONDS") or 86400)
# cache keyed by (region, observe, window) so each Tier-C overlay/window is a
# distinct view
_CACHE: dict[tuple[str, bool, int], Graph] = {}

_WEB_DIR = os.path.join(os.path.dirname(__file__), "web")


def _get_graph(region: str, refresh: bool = False, observe: bool = False,
               observe_window: int = _DEFAULT_OBSERVE_WINDOW) -> Graph:
    key = (region, observe, observe_window)
    if refresh or key not in _CACHE:
        _CACHE[key] = build_graph(region, observe=observe,
                                  observe_window_seconds=observe_window)
    return _CACHE[key]


@app.get("/api/inventory")
def inventory(region: str = Query(_DEFAULT_REGION), refresh: bool = False,
              observe: bool = False,
              observe_window: int = Query(_DEFAULT_OBSERVE_WINDOW)):
    g = _get_graph(region, refresh, observe, observe_window)
    agents = [
        {"id": n.id, "name": n.name, "status": n.attrs.get("status"),
         "protocol": n.attrs.get("protocol")}
        for n in g.nodes if n.type == NodeType.AGENT_RUNTIME
    ]
    agents.sort(key=lambda a: a["name"])
    return {
        "account": g.account,
        "region": g.region,
        "collectedAt": g.collected_at,
        "agents": agents,
        "counts": _counts(g),
        "findingsCount": len(g.findings),
        "errorsCount": len(g.errors),
    }


@app.get("/api/graph")
def graph(region: str = Query(_DEFAULT_REGION), agent: Optional[str] = None,
          refresh: bool = False, raw: bool = False, observe: bool = False,
          observe_window: int = Query(_DEFAULT_OBSERVE_WINDOW)):
    g = _get_graph(region, refresh, observe, observe_window)
    if agent:
        matches = [n for n in g.nodes
                   if n.type == NodeType.AGENT_RUNTIME and (n.id == agent or n.name == agent)]
        if not matches:
            raise HTTPException(404, f"agent not found: {agent}")
        g = _subgraph(g, matches[0].id)
    return JSONResponse(g.to_dict(include_raw=raw))


@app.get("/api/reader-policy")
def reader_policy():
    """The least-privilege, read-only IAM policy this tool needs (M4 export)."""
    return READER_POLICY


def _counts(g: Graph) -> dict:
    from collections import Counter
    return dict(Counter(n.type for n in g.nodes))


# ---- static frontend (mounted last so /api/* wins) ----
if os.path.isdir(_WEB_DIR):
    @app.get("/")
    def index():
        return FileResponse(os.path.join(_WEB_DIR, "index.html"))

    app.mount("/", StaticFiles(directory=_WEB_DIR), name="web")
