"""Read-only collectors — one per AgentCore concern.

Each collector adds nodes/edges to the shared Graph and records a
CollectionError (rather than raising) when a permission is missing, so a
partial-access principal still produces a partial graph.

Tiers (see docs/SPEC.md §4.1):
  A = static/authoritative   B = inferred from env vars   C = observed (M5)
"""
from __future__ import annotations

import re
from typing import Any, Optional

from botocore.exceptions import ClientError

from .aws import (Aws, gateway_id_from_url, is_arn, normalize_gateway_url,
                  paginate, parse_arn, role_name_from_arn)
from .model import Edge, EdgeType, Graph, Node, NodeType, Tier

CP = "bedrock-agentcore-control"


class BaseCollector:
    name = "base"

    def __init__(self, aws: Aws, graph: Graph):
        self.aws = aws
        self.g = graph

    def _err(self, target: str):
        return lambda code: self.g.add_error(self.name, target, code)

    def collect(self) -> None:  # pragma: no cover - overridden
        raise NotImplementedError


# --------------------------------------------------------------------------
class _TierBCollector(BaseCollector):
    """Shared Tier-B inference. Classifies a config key/value pair — whether it
    came from `environmentVariables` (RuntimeCollector) or an SSM parameter
    (SsmConfigCollector) — into the same inferred edges, so the wiring an agent
    keeps in SSM links up exactly like the wiring it keeps in env vars.

    Keys are matched against a normalized form so an env var `NEPTUNE_GATEWAY_URL`
    and an SSM parameter `/agenticidp/dev/gateway-url` both resolve to a gateway.
    """

    # config-key heuristics validated in M0 (SPEC §10a)
    _MEMORY_KEY = re.compile(r"MEMORY_ID$", re.I)
    _GATEWAY_KEY = re.compile(r"GATEWAY_URL$", re.I)
    _KB_KEY = re.compile(r"(KB_ID|KNOWLEDGE_BASE_ID)$", re.I)
    _TABLE_KEY = re.compile(r"TABLE$", re.I)
    _GUARDRAIL_KEY = re.compile(r"GUARDRAIL(_ID(ENTIFIER)?)?$", re.I)
    # value that is an SSM parameter reference we can dereference (opt-in, fail-soft)
    _SSM_REF = re.compile(r"^(?:arn:[^:]*:ssm:[^:]*:[^:]*:parameter(/.+)|ssm:(/.+)|\{\{resolve:ssm:(/[^:}]+).*\}\})$")

    @staticmethod
    def _norm_key(name: str) -> str:
        """Fold an SSM parameter name (or env key) to the canonical key the
        heuristics match: last path segment, non-alnum -> '_', uppercased.
        `/agenticidp/dev/gateway-url` -> `GATEWAY_URL`."""
        seg = name.rstrip("/").split("/")[-1]
        return re.sub(r"[^0-9A-Za-z]+", "_", seg).upper()

    def _classify(self, agent_arn: str, key: str, value: str, source: str) -> None:
        if self._GATEWAY_KEY.search(key):
            # store as pending gateway ref keyed by normalized URL; the resolver
            # links to the real gateway via aliases registered by GatewayCollector
            self.g.add_edge(Edge(agent_arn, f"gatewayurl:{normalize_gateway_url(value)}",
                                 EdgeType.USES_GATEWAY, Tier.B, source,
                                 attrs={"gatewayUrl": value, "unresolved": True}))
        elif self._MEMORY_KEY.search(key):
            self.g.add_edge(Edge(agent_arn, f"memoryid:{value}", EdgeType.USES_MEMORY,
                                 Tier.B, source,
                                 attrs={"memoryId": value, "unresolved": True}))
        elif self._KB_KEY.search(key):
            ds = self._data_source(f"kb:{value}", "bedrock-knowledge-base")
            self.g.add_edge(Edge(agent_arn, ds.id, EdgeType.READS_DATA_SOURCE, Tier.B, source))
        elif self._TABLE_KEY.search(key):
            ds = self._data_source(f"dynamodb:{value}", "dynamodb-table")
            self.g.add_edge(Edge(agent_arn, ds.id, EdgeType.READS_DATA_SOURCE, Tier.B, source))
        elif self._GUARDRAIL_KEY.search(key):
            ds = self._data_source(value if is_arn(value) else f"guardrail:{value}", "bedrock-guardrail")
            self.g.add_edge(Edge(agent_arn, ds.id, EdgeType.READS_DATA_SOURCE, Tier.B, source))
        elif is_arn(value) and ":runtime/" in value:
            # a sub-agent runtime referenced by config -> delegation edge.
            # Skip a self-reference (an agent that stores its own ARN in config).
            if value != agent_arn:
                self.g.add_edge(Edge(agent_arn, value, EdgeType.DELEGATES_TO, Tier.B, source))
        elif is_arn(value):
            self._external(value)
            self.g.add_edge(Edge(agent_arn, value, EdgeType.REACHES_RESOURCE, Tier.B, source))

    def _maybe_resolve_ssm(self, agent_arn: str, k: str, v: str) -> Optional[str]:
        """If a value is an explicit SSM parameter reference, dereference it to
        its literal value (needs ssm:GetParameter; fail-soft on denial)."""
        m = self._SSM_REF.match(v)
        if not m:
            return None
        name = next((g for g in m.groups() if g), None)
        if not name:
            return None
        try:
            resp = self.aws.ssm.get_parameter(Name=name, WithDecryption=False)
            return resp["Parameter"]["Value"]
        except Exception:  # noqa: BLE001 - missing perm / param: keep the raw ref
            self.g.add_error(self.name, f"{agent_arn}:ssm:{name}", "get_parameter failed")
            return None

    def _data_source(self, ident: str, kind: str) -> Node:
        return self.g.add_node(Node(
            id=ident if is_arn(ident) else f"datasource:{ident}",
            type=NodeType.DATA_SOURCE, name=ident.split(":")[-1],
            region=self.aws.region, account=self.aws.account,
            attrs={"kind": kind}, source_api="inferred"))

    def _external(self, arn: str) -> Node:
        p = parse_arn(arn) or {}
        return self.g.add_node(Node(
            id=arn, type=NodeType.EXTERNAL_RESOURCE,
            name=(p.get("resource_id") or arn).split("/")[-1],
            region=p.get("region") or self.aws.region, account=p.get("account"),
            attrs={"service": p.get("service")}, source_api="inferred"))


class RuntimeCollector(_TierBCollector):
    """Agent runtimes + their static edges (role, workload identity) and
    Tier-B inferred edges parsed from environmentVariables."""

    name = "RuntimeCollector"

    def collect(self) -> None:
        try:
            runtimes = paginate(self.aws.control, "list_agent_runtimes", "agentRuntimes")
        except Exception as e:  # noqa: BLE001 - top-level list failure
            self.g.add_error(self.name, "list_agent_runtimes", str(e)[:200])
            return
        for item in runtimes:
            rid = item["agentRuntimeId"]
            full = None
            try:
                full = self.aws.control.get_agent_runtime(agentRuntimeId=rid)
            except Exception:  # noqa: BLE001
                self.g.add_error(self.name, rid, "get_agent_runtime failed")
            self._add_runtime(item, full)

    def _add_runtime(self, item: dict, full: Optional[dict]) -> None:
        data = full or item
        arn = data.get("agentRuntimeArn") or item.get("agentRuntimeArn")
        node = Node(
            id=arn,
            type=NodeType.AGENT_RUNTIME,
            name=data.get("agentRuntimeName", item.get("agentRuntimeName", "")),
            region=self.aws.region,
            account=self.aws.account,
            attrs={
                "status": data.get("status"),
                "version": data.get("agentRuntimeVersion"),
                "protocol": (data.get("protocolConfiguration") or {}).get("serverProtocol"),
                "containerUri": ((data.get("agentRuntimeArtifact") or {})
                                 .get("containerConfiguration") or {}).get("containerUri"),
                "hasInboundAuth": bool(data.get("authorizerConfiguration")),
            },
            source_api=f"{CP}:GetAgentRuntime",
            raw=full,
        )
        self.g.add_node(node)

        role_arn = data.get("roleArn")
        if role_arn:
            self.g.add_edge(Edge(arn, role_arn, EdgeType.ASSUMES_ROLE, Tier.A,
                                 "GetAgentRuntime.roleArn"))
        wid = (data.get("workloadIdentityDetails") or {}).get("workloadIdentityArn")
        if wid:
            self.g.add_edge(Edge(arn, wid, EdgeType.HAS_WORKLOAD_IDENTITY, Tier.A,
                                 "GetAgentRuntime.workloadIdentityDetails"))
        # filesystem access points -> data sources
        for fs in (data.get("filesystemConfigurations") or []):
            for key, arn_key in (("s3FilesAccessPoint", "accessPointArn"),
                                 ("efsAccessPoint", "accessPointArn")):
                ap = (fs.get(key) or {}).get(arn_key)
                if ap:
                    self._data_source(ap, "filesystem")
                    self.g.add_edge(Edge(arn, ap, EdgeType.READS_DATA_SOURCE, Tier.A,
                                         f"filesystemConfigurations.{key}"))
        # Tier-B: parse env vars for gateway / memory / data-source references
        if full:
            self._infer_from_env(arn, full.get("environmentVariables") or {})

    def _infer_from_env(self, agent_arn: str, env: dict[str, str]) -> None:
        for k, v in env.items():
            if not v:
                continue
            # dereference an SSM parameter reference to its literal value first
            resolved = self._maybe_resolve_ssm(agent_arn, k, v)
            v = resolved if resolved is not None else v
            self._classify(agent_arn, k, v, f"environmentVariables.{k}")


# --------------------------------------------------------------------------
class GatewayCollector(BaseCollector):
    """Gateways, their targets (union dispatch -> tools + downstream ARNs),
    credential-provider bindings, policy-engine binding, and gateway rules."""

    name = "GatewayCollector"

    def collect(self) -> None:
        try:
            gws = paginate(self.aws.control, "list_gateways", "items")
        except Exception as e:  # noqa: BLE001
            self.g.add_error(self.name, "list_gateways", str(e)[:200])
            return
        for item in gws:
            gid = item.get("gatewayId") or item.get("gatewayIdentifier")
            full = None
            try:
                full = self.aws.control.get_gateway(gatewayIdentifier=gid)
            except Exception:  # noqa: BLE001
                self.g.add_error(self.name, gid, "get_gateway failed")
            gw_arn = self._add_gateway(gid, item, full)
            self._collect_targets(gid, gw_arn, full)

    def _add_gateway(self, gid: str, item: dict, full: Optional[dict]) -> str:
        data = full or item
        gw_arn = data.get("gatewayArn") or f"gateway:{self.aws.region}:{gid}"
        gw_url = data.get("gatewayUrl")
        self.g.add_node(Node(
            id=gw_arn, type=NodeType.GATEWAY,
            name=data.get("name", gid), region=self.aws.region, account=self.aws.account,
            attrs={
                "gatewayId": gid,
                "gatewayUrl": gw_url,
                "protocolType": data.get("protocolType"),
                "status": data.get("status"),
                "hasInboundAuth": bool(data.get("authorizerConfiguration")),
            },
            source_api=f"{CP}:GetGateway", raw=full))
        role_arn = data.get("roleArn")
        if role_arn:
            self.g.add_edge(Edge(gw_arn, role_arn, EdgeType.ASSUMES_ROLE, Tier.A,
                                 "GetGateway.roleArn"))
        pe = (data.get("policyEngineConfiguration") or {}).get("arn")
        if pe:
            self.g.add_edge(Edge(gw_arn, pe, EdgeType.BOUND_TO_POLICY_ENGINE, Tier.A,
                                 "GetGateway.policyEngineConfiguration"))
        # register alias keys so the resolver can link Tier-B agent edges even
        # when the env var and control-plane URL differ by scheme/slash/path,
        # and also by gatewayId (the first URL host label).
        for alias_key in self._gateway_alias_keys(gw_url, gid):
            self.g.add_node(Node(
                id=alias_key, type="_GatewayUrlAlias", name=gw_url or gid,
                attrs={"gatewayArn": gw_arn}, source_api="alias"))
        return gw_arn

    @staticmethod
    def _gateway_alias_keys(gw_url: Optional[str], gid: Optional[str]) -> set[str]:
        keys: set[str] = set()
        if gw_url:
            keys.add(f"gatewayurl:{normalize_gateway_url(gw_url)}")
            url_gid = gateway_id_from_url(gw_url)
            if url_gid:
                keys.add(f"gatewayurl:{url_gid}")
        if gid:
            keys.add(f"gatewayurl:{gid}")
        return keys

    def _collect_targets(self, gid: str, gw_arn: str, gw_full: Optional[dict]) -> None:
        try:
            targets = paginate(self.aws.control, "list_gateway_targets", "items",
                               gatewayIdentifier=gid)
        except Exception:  # noqa: BLE001
            self.g.add_error(self.name, f"{gid}:targets", "list_gateway_targets failed")
            return
        gw_role = (gw_full or {}).get("roleArn")
        for t in targets:
            tid = t["targetId"]
            full = None
            try:
                full = self.aws.control.get_gateway_target(gatewayIdentifier=gid, targetId=tid)
            except Exception:  # noqa: BLE001
                self.g.add_error(self.name, f"{gid}/{tid}", "get_gateway_target failed")
            self._add_target(gw_arn, gw_role, tid, t, full)

    def _add_target(self, gw_arn: str, gw_role: Optional[str], tid: str,
                    item: dict, full: Optional[dict]) -> None:
        data = full or item
        t_arn = f"{gw_arn}/target/{tid}"
        tc = data.get("targetConfiguration") or {}
        kind, detail = _target_kind(tc)
        self.g.add_node(Node(
            id=t_arn, type=NodeType.GATEWAY_TARGET,
            name=data.get("name", tid), region=self.aws.region, account=self.aws.account,
            attrs={"targetType": item.get("targetType") or kind, "kind": kind,
                   "status": data.get("status")},
            source_api=f"{CP}:GetGatewayTarget", raw=full))
        self.g.add_edge(Edge(gw_arn, t_arn, EdgeType.HAS_TARGET, Tier.A, "ListGatewayTargets"))

        # downstream resource + tools per union kind
        self._resolve_target_config(t_arn, kind, detail)

        # credential provider bindings (incl. GATEWAY_IAM_ROLE special case)
        for cpc in (data.get("credentialProviderConfigurations") or []):
            self._resolve_credential(t_arn, gw_role, cpc)

    def _resolve_target_config(self, t_arn: str, kind: str, detail: dict) -> None:
        if kind == "mcp.lambda":
            arn = detail.get("lambdaArn")
            if arn:
                self._external(arn, "lambda")
                self.g.add_edge(Edge(t_arn, arn, EdgeType.REACHES_RESOURCE, Tier.A,
                                     "targetConfiguration.mcp.lambda.lambdaArn"))
            for tool in ((detail.get("toolSchema") or {}).get("inlinePayload") or []):
                self._tool(t_arn, tool.get("name"), tool.get("description"))
        elif kind == "mcp.openApiSchema" or kind == "mcp.smithyModel":
            s3 = (detail.get("s3") or {}).get("uri")
            if s3:
                self.g.add_edge(Edge(t_arn, s3, EdgeType.READS_DATA_SOURCE, Tier.A,
                                     f"targetConfiguration.{kind}.s3"))
        elif kind == "mcp.mcpServer" or kind == "http.passthrough":
            ep = detail.get("endpoint")
            if ep:
                self._external(ep, "http-endpoint")
                self.g.add_edge(Edge(t_arn, ep, EdgeType.REACHES_RESOURCE, Tier.A,
                                     f"targetConfiguration.{kind}.endpoint"))
        elif kind == "mcp.apiGateway":
            rid = detail.get("restApiId")
            if rid:
                res = f"apigateway:{rid}:{detail.get('stage','')}"
                self._external(res, "api-gateway")
                self.g.add_edge(Edge(t_arn, res, EdgeType.REACHES_RESOURCE, Tier.A,
                                     "targetConfiguration.mcp.apiGateway"))
        elif kind == "http.agentcoreRuntime":
            arn = detail.get("arn")
            if arn:  # agent -> agent edge
                self.g.add_edge(Edge(t_arn, arn, EdgeType.DELEGATES_TO, Tier.A,
                                     "targetConfiguration.http.agentcoreRuntime.arn"))

    def _resolve_credential(self, t_arn: str, gw_role: Optional[str], cpc: dict) -> None:
        ctype = cpc.get("credentialProviderType")
        if ctype == "GATEWAY_IAM_ROLE":
            if gw_role:
                self.g.add_edge(Edge(t_arn, gw_role, EdgeType.USES_CREDENTIAL, Tier.A,
                                     "credentialProviderType=GATEWAY_IAM_ROLE"))
            return
        cp = cpc.get("credentialProvider") or {}
        for key in ("oauthCredentialProvider", "apiKeyCredentialProvider"):
            arn = (cp.get(key) or {}).get("providerArn")
            if arn:
                self.g.add_edge(Edge(t_arn, arn, EdgeType.USES_CREDENTIAL, Tier.A,
                                     f"credentialProviderConfigurations.{key}.providerArn"))

    def _tool(self, t_arn: str, name: Optional[str], desc: Optional[str]) -> None:
        if not name:
            return
        tool_id = f"{t_arn}/tool/{name}"
        self.g.add_node(Node(id=tool_id, type=NodeType.TOOL, name=name,
                             region=self.aws.region, account=self.aws.account,
                             attrs={"description": desc}, source_api="GetGatewayTarget.toolSchema"))
        self.g.add_edge(Edge(t_arn, tool_id, EdgeType.EXPOSES_TOOL, Tier.A, "toolSchema"))

    def _external(self, arn: str, service: str) -> None:
        p = parse_arn(arn) if is_arn(arn) else None
        self.g.add_node(Node(
            id=arn, type=NodeType.EXTERNAL_RESOURCE,
            name=(p or {}).get("resource_id", arn).split(":")[-1] if p else arn,
            region=(p or {}).get("region", self.aws.region), account=(p or {}).get("account"),
            attrs={"service": (p or {}).get("service", service)}, source_api="target"))


def _target_kind(tc: dict) -> tuple[str, dict]:
    """Dispatch on the targetConfiguration union key path (SPEC §3.2)."""
    for top in ("mcp", "http", "inference"):
        sub = tc.get(top)
        if isinstance(sub, dict):
            for k, v in sub.items():
                if isinstance(v, dict):
                    return f"{top}.{k}", v
    return "unknown", {}


# --------------------------------------------------------------------------
class MemoryCollector(BaseCollector):
    name = "MemoryCollector"

    def collect(self) -> None:
        try:
            mems = paginate(self.aws.control, "list_memories", "memories")
        except Exception as e:  # noqa: BLE001
            self.g.add_error(self.name, "list_memories", str(e)[:200])
            return
        for item in mems:
            mid = item.get("id") or item.get("memoryId")
            full = None
            try:
                full = self.aws.control.get_memory(memoryId=mid).get("memory")
            except Exception:  # noqa: BLE001
                self.g.add_error(self.name, mid, "get_memory failed")
            self._add_memory(mid, item, full)

    def _add_memory(self, mid: str, item: dict, full: Optional[dict]) -> None:
        data = full or item
        arn = data.get("arn") or f"memory:{self.aws.region}:{mid}"
        strategies = [{"type": s.get("type"), "namespaces": s.get("namespaces")}
                      for s in (data.get("strategies") or [])]
        self.g.add_node(Node(
            id=arn, type=NodeType.MEMORY, name=data.get("name", mid),
            region=self.aws.region, account=self.aws.account,
            attrs={"memoryId": mid, "status": data.get("status"), "strategies": strategies},
            source_api=f"{CP}:GetMemory", raw=full))
        # alias so resolver can link Tier-B agent env edges (memoryid:<id>)
        self.g.add_node(Node(id=f"memoryid:{mid}", type="_MemoryIdAlias", name=mid,
                             attrs={"memoryArn": arn}, source_api="alias"))
        role = data.get("memoryExecutionRoleArn")
        if role:
            self.g.add_edge(Edge(arn, role, EdgeType.ASSUMES_ROLE, Tier.A,
                                 "GetMemory.memoryExecutionRoleArn"))
        for res in ((data.get("streamDeliveryResources") or {}).get("resources") or []):
            ds = (res.get("kinesis") or {}).get("dataStreamArn")
            if ds:
                self.g.add_node(Node(id=ds, type=NodeType.DATA_SOURCE, name=ds.split("/")[-1],
                                     attrs={"kind": "kinesis"}, source_api="GetMemory"))
                self.g.add_edge(Edge(arn, ds, EdgeType.READS_DATA_SOURCE, Tier.A,
                                     "streamDeliveryResources.kinesis"))


# --------------------------------------------------------------------------
class IdentityCollector(BaseCollector):
    name = "IdentityCollector"

    def collect(self) -> None:
        self._simple("list_workload_identities", "get_workload_identity",
                     NodeType.WORKLOAD_IDENTITY, "workloadIdentityArn", "name",
                     id_arg="name")
        self._simple("list_oauth2_credential_providers", "get_oauth2_credential_provider",
                     NodeType.CREDENTIAL_PROVIDER, "credentialProviderArn", "name",
                     id_arg="name", extra={"vendor": "credentialProviderVendor"})
        self._simple("list_api_key_credential_providers", "get_api_key_credential_provider",
                     NodeType.CREDENTIAL_PROVIDER, "credentialProviderArn", "name",
                     id_arg="name")

    def _simple(self, list_op: str, get_op: str, node_type: str, arn_key: str,
                name_key: str, id_arg: str, extra: Optional[dict] = None) -> None:
        try:
            items = paginate(self.aws.control, list_op)
        except Exception:  # noqa: BLE001
            self.g.add_error(self.name, list_op, "list failed")
            return
        for it in items:
            arn = it.get(arn_key) or it.get("credentialProviderArn") or it.get("workloadIdentityArn")
            attrs = {"kind": node_type}
            if extra:
                attrs.update({k: it.get(v) for k, v in extra.items()})
            self.g.add_node(Node(
                id=arn or f"{node_type}:{it.get(name_key)}", type=node_type,
                name=it.get(name_key, ""), region=self.aws.region, account=self.aws.account,
                attrs=attrs, source_api=f"{CP}:{list_op}", raw=it))


# --------------------------------------------------------------------------
class PolicyEngineCollector(BaseCollector):
    name = "PolicyEngineCollector"

    def collect(self) -> None:
        try:
            engines = paginate(self.aws.control, "list_policy_engines")
        except Exception:  # noqa: BLE001
            self.g.add_error(self.name, "list_policy_engines", "list failed")
            return
        for eng in engines:
            arn = eng.get("policyEngineArn")
            eid = eng.get("policyEngineId")
            self.g.add_node(Node(id=arn or f"policyengine:{eid}", type=NodeType.POLICY_ENGINE,
                                 name=eng.get("name", eid or ""), region=self.aws.region,
                                 account=self.aws.account, attrs={"status": eng.get("status")},
                                 source_api=f"{CP}:ListPolicyEngines", raw=eng))
            # v1: list & display cedar policies (evaluate in v2)
            try:
                pols = paginate(self.aws.control, "list_policies", policyEngineId=eid)
            except Exception:  # noqa: BLE001
                self.g.add_error(self.name, f"{eid}:policies", "list_policies failed")
                continue
            for pol in pols:
                p_arn = pol.get("policyArn") or f"policy:{pol.get('policyId')}"
                self.g.add_node(Node(id=p_arn, type=NodeType.CEDAR_POLICY,
                                     name=pol.get("name", pol.get("policyId", "")),
                                     region=self.aws.region, account=self.aws.account,
                                     attrs={"enforcementMode": pol.get("enforcementMode")},
                                     source_api=f"{CP}:ListPolicies", raw=pol))
                self.g.add_edge(Edge(arn or f"policyengine:{eid}", p_arn, EdgeType.HAS_POLICY,
                                     Tier.A, "ListPolicies"))


# --------------------------------------------------------------------------
class RegistryCollector(BaseCollector):
    name = "RegistryCollector"

    def collect(self) -> None:
        try:
            regs = paginate(self.aws.control, "list_registries")
        except Exception:  # noqa: BLE001
            self.g.add_error(self.name, "list_registries", "list failed")
            return
        for reg in regs:
            arn = reg.get("registryArn")
            rid = reg.get("registryId")
            self.g.add_node(Node(id=arn or f"registry:{rid}", type=NodeType.REGISTRY,
                                 name=reg.get("name", rid or ""), region=self.aws.region,
                                 account=self.aws.account, attrs={"status": reg.get("status")},
                                 source_api=f"{CP}:ListRegistries", raw=reg))
            try:
                records = paginate(self.aws.control, "list_registry_records",
                                   registryIdentifier=rid)
            except Exception:  # noqa: BLE001
                self.g.add_error(self.name, f"{rid}:records", "list_registry_records failed")
                continue
            for rec in records:
                rec_arn = rec.get("recordArn") or f"record:{rec.get('recordId')}"
                self.g.add_node(Node(id=rec_arn, type=NodeType.REGISTRY_RECORD,
                                     name=rec.get("name", rec.get("recordId", "")),
                                     region=self.aws.region, account=self.aws.account,
                                     attrs={"descriptorType": rec.get("descriptorType")},
                                     source_api=f"{CP}:ListRegistryRecords", raw=rec))
                self.g.add_edge(Edge(arn or f"registry:{rid}", rec_arn, EdgeType.HAS_TARGET,
                                     Tier.A, "ListRegistryRecords"))


# --------------------------------------------------------------------------
class IamCollector(BaseCollector):
    """Resolve every roleArn referenced by an assumesRole edge into its
    attached+inline policies and the concrete resource ARNs they grant."""

    name = "IamCollector"

    def collect(self) -> None:
        role_arns = {e.to_id for e in self.g.edges if e.type == EdgeType.ASSUMES_ROLE}
        for role_arn in role_arns:
            name = role_name_from_arn(role_arn)
            if not name:
                continue
            self._add_role(role_arn, name)

    def _add_role(self, role_arn: str, role_name: str) -> None:
        iam = self.aws.iam
        try:
            role = iam.get_role(RoleName=role_name)["Role"]
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "ClientError")
            self.g.add_error(self.name, role_arn, f"get_role: {code}")
            if code == "NoSuchEntity":
                # referenced role was deleted — record a stub and stop
                self.g.add_node(Node(id=role_arn, type=NodeType.IAM_ROLE,
                                     name=role_name, account=self.aws.account,
                                     attrs={"missing": True}, source_api="iam:GetRole"))
                return
            role = {}
        except Exception:  # noqa: BLE001
            self.g.add_error(self.name, role_arn, "get_role failed")
            role = {}
        self.g.add_node(Node(id=role_arn, type=NodeType.IAM_ROLE, name=role_name,
                             account=self.aws.account,
                             attrs={"trustPolicy": role.get("AssumeRolePolicyDocument")},
                             source_api="iam:GetRole", raw=role or None))
        # managed policies
        try:
            for ap in paginate(iam, "list_attached_role_policies", RoleName=role_name):
                self._managed(role_arn, ap["PolicyArn"], ap.get("PolicyName"))
        except Exception:  # noqa: BLE001
            self.g.add_error(self.name, f"{role_name}:attached", "list_attached failed")
        # inline policies
        try:
            for pol_name in paginate(iam, "list_role_policies", RoleName=role_name):
                self._inline(role_arn, role_name, pol_name)
        except Exception:  # noqa: BLE001
            self.g.add_error(self.name, f"{role_name}:inline", "list_role_policies failed")

    def _managed(self, role_arn: str, pol_arn: str, pol_name: Optional[str]) -> None:
        iam = self.aws.iam
        doc = None
        try:
            ver = iam.get_policy(PolicyArn=pol_arn)["Policy"]["DefaultVersionId"]
            doc = iam.get_policy_version(PolicyArn=pol_arn, VersionId=ver)["PolicyVersion"]["Document"]
        except Exception:  # noqa: BLE001
            self.g.add_error(self.name, pol_arn, "get_policy_version failed")
        self._policy_node(role_arn, pol_arn, pol_name or pol_arn, doc, managed=True)

    def _inline(self, role_arn: str, role_name: str, pol_name: str) -> None:
        doc = None
        try:
            doc = self.aws.iam.get_role_policy(RoleName=role_name, PolicyName=pol_name)["PolicyDocument"]
        except Exception:  # noqa: BLE001
            self.g.add_error(self.name, f"{role_name}/{pol_name}", "get_role_policy failed")
        pid = f"{role_arn}/inline/{pol_name}"
        self._policy_node(role_arn, pid, pol_name, doc, managed=False)

    def _policy_node(self, role_arn: str, pol_id: str, name: str,
                     doc: Optional[dict], managed: bool) -> None:
        self.g.add_node(Node(id=pol_id, type=NodeType.IAM_POLICY, name=name,
                             account=self.aws.account,
                             attrs={"managed": managed, "document": doc},
                             source_api="iam:GetPolicyVersion" if managed else "iam:GetRolePolicy",
                             raw={"document": doc}))
        self.g.add_edge(Edge(role_arn, pol_id, EdgeType.ATTACHES_POLICY, Tier.A,
                             "ListAttachedRolePolicies" if managed else "ListRolePolicies"))
        # parse statements -> concrete resource ARNs
        for stmt in _statements(doc):
            if stmt.get("Effect") != "Allow":
                continue
            for res in _as_list(stmt.get("Resource")):
                if res == "*" or not is_arn(res):
                    continue
                p = parse_arn(res) or {}
                self.g.add_node(Node(id=res, type=NodeType.EXTERNAL_RESOURCE,
                                     name=res.split(":")[-1], region=p.get("region"),
                                     account=p.get("account"),
                                     attrs={"service": p.get("service")}, source_api="iam-policy"))
                self.g.add_edge(Edge(pol_id, res, EdgeType.GRANTS_ACCESS_TO, Tier.A,
                                     "PolicyDocument.Statement.Resource"))


# --------------------------------------------------------------------------
class SsmConfigCollector(_TierBCollector):
    """Tier-B inference from SSM Parameter Store.

    Some agents keep their wiring (gateway URL, memory id, sub-agent ARNs) in
    SSM parameters read at runtime rather than in `environmentVariables`, so the
    env-var pass leaves them isolated. The role's own IAM policy is the signal:
    it grants `ssm:GetParametersByPath`/`GetParameter` on a specific parameter
    path (e.g. `.../parameter/agenticidp/dev/*`). For each agent we scan the
    granted path prefixes read-only and classify each parameter exactly like an
    env var — so an SSM `gateway-url` links to the same gateway subgraph.

    Runs after IamCollector so the role policy documents are already in the
    graph. Fail-soft: missing `ssm:*` perms or empty paths leave Tier B as-is.
    """

    name = "SsmConfigCollector"

    def collect(self) -> None:
        # map each agent runtime -> the role it assumes
        role_of: dict[str, str] = {}
        for e in self.g.edges:
            if e.type == EdgeType.ASSUMES_ROLE and self._is_agent(e.from_id):
                role_of[e.from_id] = e.to_id
        if not role_of:
            return
        # index policy documents by the role they attach to
        docs_by_role = self._policy_docs_by_role()
        for agent_arn, role_arn in role_of.items():
            prefixes = set()
            for doc in docs_by_role.get(role_arn, []):
                prefixes |= self._ssm_prefixes(doc)
            for prefix in sorted(prefixes):
                self._scan_prefix(agent_arn, prefix)

    def _is_agent(self, node_id: str) -> bool:
        n = self.g._nodes.get(node_id)  # noqa: SLF001
        return n is not None and n.type == NodeType.AGENT_RUNTIME

    def _policy_docs_by_role(self) -> dict[str, list[dict]]:
        """role ARN -> its policy documents, joined via attachesPolicy edges."""
        policy_owner: dict[str, str] = {}
        for e in self.g.edges:
            if e.type == EdgeType.ATTACHES_POLICY:
                policy_owner[e.to_id] = e.from_id
        out: dict[str, list[dict]] = {}
        for n in self.g.nodes:
            if n.type != NodeType.IAM_POLICY:
                continue
            doc = n.attrs.get("document")
            role = policy_owner.get(n.id)
            if doc and role:
                out.setdefault(role, []).append(doc)
        return out

    def _ssm_prefixes(self, doc: dict) -> set[str]:
        """Extract SSM parameter path prefixes from a policy's ssm:Get* grants.
        `arn:aws:ssm:r:a:parameter/agenticidp/dev/*` -> `/agenticidp/dev/`."""
        prefixes: set[str] = set()
        for stmt in _statements(doc):
            if stmt.get("Effect") != "Allow":
                continue
            actions = [a.lower() for a in _as_list(stmt.get("Action"))]
            if not any(a.startswith("ssm:getparameter") for a in actions):
                continue
            for res in _as_list(stmt.get("Resource")):
                p = parse_arn(res) or {}
                if p.get("service") != "ssm":
                    continue
                # resource_id is like "parameter/agenticidp/dev/*"
                rid = p.get("resource_id") or ""
                path = rid[len("parameter"):] if rid.startswith("parameter") else rid
                path = path.rstrip("*")
                if path and path != "/":
                    prefixes.add(path if path.startswith("/") else "/" + path)
        return prefixes

    def _scan_prefix(self, agent_arn: str, prefix: str) -> None:
        # SSM paginates with PascalCase NextToken (not AgentCore's camelCase),
        # so use boto3's built-in paginator rather than the AgentCore helper.
        params: list[dict] = []
        try:
            pager = self.aws.ssm.get_paginator("get_parameters_by_path")
            for page in pager.paginate(Path=prefix, Recursive=True,
                                       WithDecryption=False):
                params.extend(page.get("Parameters", []) or [])
        except Exception as e:  # noqa: BLE001 - missing perm / bad path: fail-soft
            self.g.add_error(self.name, f"{agent_arn}:ssm:{prefix}",
                             f"get_parameters_by_path: {str(e)[:80]}")
            return
        for p in params:
            name, value = p.get("Name"), p.get("Value")
            if not name or not value:
                continue
            self._classify(agent_arn, self._norm_key(name), value, f"ssm:{name}")


# --------------------------------------------------------------------------
class ObservabilityCollector(BaseCollector):
    """Tier-C observed edges from runtime traces (SPEC §3 Observability, §5.1).

    Opt-in: only runs when build_graph(observe=True). Queries the CloudWatch
    Logs `aws/spans` group (Transaction Search) over a bounded window and turns
    each span attributed to a known agent into an observed edge:
      agent -> tool               (a tool the agent actually invoked)
      agent -> agent              (delegation)
      agent -> gateway/resource   (downstream actually reached)
    Fail-soft: missing perms / tracing-off leaves Tier C empty, never raises.
    """

    name = "ObservabilityCollector"
    SPANS_GROUP = "aws/spans"

    def __init__(self, aws: Aws, graph: Graph, window_seconds: int = 3600):
        super().__init__(aws, graph)
        self.window_seconds = window_seconds

    def collect(self) -> None:
        agents = [n for n in self.g.nodes if n.type == NodeType.AGENT_RUNTIME]
        if not agents:
            return
        try:
            rows = self._query_spans()
        except Exception as e:  # noqa: BLE001 - tracing off / no perms / group absent
            self.g.add_error(self.name, self.SPANS_GROUP, f"spans query failed: {str(e)[:120]}")
            return
        # index agents by every key a span might carry so it can be attributed:
        #   - the runtime ARN (node id, and the ARN inside cloud.resource_id)
        #   - the bare agent name
        #   - the OTel service.name, which is "<agent-name>.<endpoint>" (e.g.
        #     "semantic_layer_dev_ontology.DEFAULT")
        by_key: dict[str, str] = {}
        for a in agents:
            by_key[a.id] = a.id
            if a.name:
                by_key[a.name] = a.id
                by_key[f"{a.name}.DEFAULT"] = a.id
        for edge in spans_to_edges(rows, by_key):
            # ensure the observed-tool target exists as a node so the UI renders
            # it; the resolver later re-points it to a real Tool node by name.
            if edge.to_id.startswith("observed-tool:"):
                self.g.add_node(Node(
                    id=edge.to_id, type=NodeType.TOOL,
                    name=edge.attrs.get("observedTool", edge.to_id),
                    region=self.aws.region, account=self.aws.account,
                    attrs={"observed": True}, source_api="aws/spans"))
            elif is_arn(edge.to_id):
                # downstream resource actually reached — mark it observed
                self.g.add_node(Node(
                    id=edge.to_id, type=NodeType.EXTERNAL_RESOURCE,
                    name=edge.to_id.split(":")[-1].split("/")[-1],
                    region=self.aws.region, account=self.aws.account,
                    attrs={"observed": True}, source_api="aws/spans"))
            self.g.add_edge(edge)
            # mark both endpoints observed: source agent for the untraced finding,
            # target for the over-provisioning gap (observation lives on the node,
            # since a Tier-C edge collapses into a colliding Tier-A/B edge by key).
            src = self.g._nodes.get(edge.from_id)  # noqa: SLF001
            if src is not None:
                src.attrs["observed"] = True
            dst = self.g._nodes.get(edge.to_id)  # noqa: SLF001
            if dst is not None:
                dst.attrs["observed"] = True

    def _query_spans(self) -> list[dict]:
        import time
        # end/start are unix seconds; window defaults to the last hour
        end = int(time.time())
        start = end - self.window_seconds
        logs = self.aws.logs
        # AgentCore/OTel GenAI spans identify the emitting agent via the OTel
        # *resource* (service.name = "<agent>.DEFAULT", cloud.resource_id = the
        # runtime ARN) and carry the invoked tool in attributes.gen_ai.tool.name.
        # Dotted field names must be backtick-quoted in Logs Insights.
        q = logs.start_query(
            logGroupName=self.SPANS_GROUP,
            startTime=start, endTime=end,
            queryString=(
                "fields `resource.attributes.service.name`, "
                "`resource.attributes.cloud.resource_id`, "
                "`attributes.gen_ai.tool.name`, `attributes.session.id`, "
                "`attributes.gen_ai.operation.name`, "
                "`attributes.downstream.arn`, name "
                "| filter ispresent(`attributes.gen_ai.tool.name`) "
                "or `attributes.gen_ai.operation.name` = 'invoke_agent' "
                "or ispresent(`attributes.downstream.arn`) "
                "| limit 2000"
            ),
        )
        qid = q["queryId"]
        for _ in range(30):  # poll up to ~15s
            res = logs.get_query_results(queryId=qid)
            if res.get("status") in ("Complete", "Failed", "Cancelled", "Timeout"):
                if res.get("status") != "Complete":
                    raise RuntimeError(f"query {res.get('status')}")
                return [{c["field"]: c["value"] for c in row} for row in res.get("results", [])]
            time.sleep(0.5)
        raise RuntimeError("query timed out")


def _resolve_agent(r: dict, agent_by_key: dict[str, str]) -> Optional[str]:
    """Attribute a span row to a known agent's runtime ARN. AgentCore GenAI
    spans carry the emitting agent in the OTel resource, not span attributes:
      resource.attributes.cloud.resource_id -> the runtime ARN (plus an
        /runtime-endpoint/... suffix), matched by ARN prefix
      resource.attributes.service.name      -> "<agent-name>.<endpoint>"
    Falls back to any legacy attributes.agent.* keys if present."""
    # exact-key hits first (service.name, bare name, arn, agent.* attrs)
    for k in ("resource.attributes.service.name",
              "attributes.agent.arn", "attributes.agent.name"):
        hit = agent_by_key.get(r.get(k, ""))
        if hit:
            return hit
    # cloud.resource_id embeds the runtime ARN as a prefix of a longer value
    rid = r.get("resource.attributes.cloud.resource_id", "")
    if rid:
        for key, arn in agent_by_key.items():
            if key.startswith("arn:") and rid.startswith(key):
                return arn
    return None


def spans_to_edges(rows: list[dict], agent_by_key: dict[str, str]) -> list[Edge]:
    """Pure: turn span records into Tier-C observed edges. Attributes an edge to
    an agent via its OTel resource (service.name / cloud.resource_id); the target
    is the invoked tool / reached downstream ARN. Deduped by (agent, target)."""
    edges: list[Edge] = []
    seen: set[tuple[str, str]] = set()
    for r in rows:
        agent_arn = _resolve_agent(r, agent_by_key)
        if not agent_arn:
            continue
        tool = r.get("attributes.gen_ai.tool.name") or r.get("attributes.tool.name")
        downstream = r.get("attributes.downstream.arn")
        if tool:
            key = (agent_arn, f"observed-tool:{tool}")
            if key in seen:
                continue
            seen.add(key)
            edges.append(Edge(agent_arn, f"observed-tool:{tool}", EdgeType.EXPOSES_TOOL,
                              Tier.C, "aws/spans:attributes.gen_ai.tool.name",
                              attrs={"observedTool": tool}))
        elif downstream and is_arn(downstream):
            key = (agent_arn, downstream)
            if key in seen:
                continue
            seen.add(key)
            etype = (EdgeType.DELEGATES_TO if ":runtime/" in downstream
                     else EdgeType.REACHES_RESOURCE)
            edges.append(Edge(agent_arn, downstream, etype, Tier.C,
                              "aws/spans:attributes.downstream.arn"))
    return edges


def _statements(doc: Optional[dict]) -> list[dict]:
    if not doc:
        return []
    return _as_list(doc.get("Statement"))


def _as_list(v: Any) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


# Static (Tier A/B) collectors, run in order. IamCollector must run last: it
# consumes the assumesRole edges the others emit. ObservabilityCollector (Tier
# C) is opt-in and appended by the resolver only when observe=True.
ALL_COLLECTORS = [
    RuntimeCollector,
    GatewayCollector,
    MemoryCollector,
    IdentityCollector,
    PolicyEngineCollector,
    RegistryCollector,
    IamCollector,
    SsmConfigCollector,  # after IamCollector: needs role policy docs to find SSM paths
]
