# AgentCore Access Graph — "Single Pane of Glass"

**Status:** Draft spec (pre-implementation)
**Last updated:** 2026-07-20
**Owner:** (you)

---

## 1. Problem & Goal

For any Amazon Bedrock AgentCore agent, show its **full access chain** in one interactive view:

```
agent (runtime | registry) → tools → gateway → permissions → policies → external resources → input data sources
```

A governance "single pane of glass" that answers, for a selected agent:

- **What can it reach?** (tools, gateways, downstream ARNs, data sources)
- **What is it *allowed* to reach?** (IAM execution role scope + Cedar policy-engine rules)
- **What did it *actually* reach?** (runtime traces)
- **Where is the gap?** (allowed − observed = over-provisioning; the core security finding)

### Use cases (all four in scope)
1. **Security / access review** — least-privilege audit, flag over-broad grants.
2. **Inventory & discovery** — catalog every agent and its wiring.
3. **Runtime observability** — overlay what agents actually invoked.
4. **Compliance / governance** — per-edge evidence with provenance; drift over time.

### Non-goals (v1)
- No write/remediation actions. **Read-only.**
- No cross-account crawl in v1 (AgentCore Identity is same-account; add org-crawl later).
- Not a replacement for CloudWatch GenAI Observability dashboards — we *link out* to them.
- **No LLM anywhere.** Collectors, resolver, and the findings engine are
  deterministic Python (rule logic + graph traversal), not model calls. The tool
  makes no request to any LLM — no Anthropic/OpenAI, no Bedrock
  `invoke_model`/`converse`, no `bedrock-runtime` client. `bedrock-agentcore-control`
  is the config/governance API, not the model-invocation API. Consequences: **zero
  token cost** on any account/machine, and the only AWS calls are read-only
  `List*`/`Get*`/`Describe*` (free of request charges) plus CloudWatch Logs Insights
  **only** under the opt-in observability overlay (§10 M5).

---

## 2. Decisions (locked)

| Decision | Choice |
|---|---|
| Data source | **Live AWS APIs, read-only** (+ Observability for runtime edges) |
| Interface | **Interactive node-link graph web app** |
| Persistence | Live-fetch v1; snapshot/diff is a v2 add (see §10) |
| Scaffolding | Deferred — this spec precedes scaffolding |

---

## 3. Ground truth — verified API surface

> Verified against **botocore 1.43.50** service models `bedrock-agentcore-control` (153 ops) and `bedrock-agentcore` (65 ops) on 2026-07-20. Shapes below are confirmed present in the SDK model. Field *semantics* from AgentCore internal runbooks are marked **[runbook]** and must still be confirmed against a live account before relying on them.

Two planes:
- **`bedrock-agentcore-control`** — control plane / static config. **This is the backbone of the graph.**
- **`bedrock-agentcore`** — data plane / runtime (memory records, sessions, invoke, tokens).

IAM, Lambda, S3, API Gateway, CloudWatch/X-Ray are standard services used to resolve leaf resources and runtime edges.

### 3.1 Corrections to prior research (confirmed via SDK)

These changed the design and are called out so the build doesn't inherit the earlier assumptions:

1. **A Registry exists.** `ListRegistries`, `GetRegistry`, `ListRegistryRecords`, `GetRegistryRecord`, `SearchRegistryRecords`. Records carry `descriptors` for `mcp.server` / `mcp.tools` / `a2a.agentCard` / `agentSkills` / `custom` (inline content). The "registry" in your chain is real, not just Runtime. Records can sync `fromUrl` with their own credential providers.
2. **A Cedar Policy Engine exists.** `GetPolicyEngine`, `ListPolicies`, `GetPolicy` → `definition.cedar.statement` (Cedar policy text) + `enforcementMode`. Gateways bind to it via `GetGateway.policyEngineConfiguration.arn`. This is a **second, authoritative authorization layer** distinct from IAM — must be a first-class node.
3. **Target → credential-provider is a STATIC edge.** `GetGatewayTarget.credentialProviderConfigurations[].credentialProvider.{oauthCredentialProvider|apiKeyCredentialProvider|iamCredentialProvider}.providerArn`. Prior research said this binding was only in code — it is not; the target declares which provider ARN it uses.
4. **Runtime env vars are exposed.** `GetAgentRuntime.environmentVariables` (map). The agent→gateway / agent→memory associations that "live in code" are frequently recoverable **statically** by parsing these env vars (Tier B becomes cheaper and more reliable).

### 3.2 Node shapes (confirmed fields, abridged to the load-bearing ones)

**AgentRuntime** — `ListAgentRuntimes` → `GetAgentRuntime`
- `agentRuntimeArn`, `agentRuntimeId`, `agentRuntimeName`, `agentRuntimeVersion`, `status`
- `roleArn` → **IAM execution role (Tier A edge)**
- `workloadIdentityDetails.workloadIdentityArn` → WorkloadIdentity
- `environmentVariables{}` → **parse for gateway URL / memory id (Tier B edges)**
- `agentRuntimeArtifact.containerConfiguration.containerUri` (ECR) OR `codeConfiguration.code.s3{bucket,prefix}`
- `networkConfiguration.networkMode` (PUBLIC | VPC{subnets, securityGroups})
- `protocolConfiguration.serverProtocol` (MCP | HTTP | A2A | …)
- `authorizerConfiguration.customJWTAuthorizer{discoveryUrl, allowedClients, allowedAudience, allowedScopes}` → **inbound auth (who may invoke)**
- `filesystemConfigurations[]` → `s3FilesAccessPoint.accessPointArn` / `efsAccessPoint.accessPointArn` → **data-source edges**
- Related: `ListAgentRuntimeVersions`, `ListAgentRuntimeEndpoints` / `GetAgentRuntimeEndpoint` (endpoint → liveVersion routing)

**Gateway** — `ListGateways` → `GetGateway`
- `gatewayArn`, `gatewayId`, `gatewayUrl` (MCP endpoint), `status`, `protocolType`
- `roleArn` → **IAM gateway execution role (Tier A edge)**
- `authorizerConfiguration.customJWTAuthorizer{…}` → inbound auth
- `policyEngineConfiguration.arn` → **Cedar PolicyEngine (Tier A edge)**
- `workloadIdentityDetails.workloadIdentityArn`
- `customTransformConfiguration.lambda.arn`, `interceptorConfigurations[].interceptor.lambda.arn` → Lambda edges
- `kmsKeyArn`, `webAclArn` / `wafConfiguration`

**GatewayTarget** — `ListGatewayTargets` (`items[].targetType` present here) → `GetGatewayTarget`
- **Target type dispatch = the `targetConfiguration` union key path** (GetGatewayTarget has no top-level targetType):
  - `mcp.lambda` → `lambdaArn` + `toolSchema.inlinePayload[]{name,description,inputSchema,outputSchema}` → **one tool per schema entry**
  - `mcp.openApiSchema` → `s3{uri,bucketOwnerAccountId}` | `inlinePayload` → **one tool per operationId**
  - `mcp.smithyModel` → `s3` | `inlinePayload` → **one tool per operation** (SigV4 to AWS service)
  - `mcp.mcpServer` → `endpoint` + `mcpToolSchema` + `listingMode`
  - `mcp.apiGateway` → `restApiId` + `stage` + `apiGatewayToolConfiguration.toolOverrides[]{name,path,method}`
  - `mcp.connector` → `source.connectorId` + `configurations[]`
  - `http.agentcoreRuntime` → `arn` + `qualifier` → **agent→agent edge**
  - `http.passthrough` → `endpoint` + `protocolType`
  - `inference.connector` / `inference.provider` → model backends
- `credentialProviderConfigurations[].credentialProvider.*.providerArn` → **CredentialProvider (Tier A edge)**
- Tool naming convention: `{targetName}___{toolName}` (triple underscore) **[runbook]**

**Memory** — `ListMemories` → `GetMemory.memory`
- `arn`, `id`, `status`, `memoryExecutionRoleArn` → IAM edge
- `strategies[]{type, namespaces, namespaceTemplates}` (Semantic | UserPreference | SessionSummary | Episodic | Custom)
- `encryptionKeyArn`, `streamDeliveryResources.resources[].kinesis.dataStreamArn` → data egress edge
- `managedByResourceArn` (may link back to owning resource)
- Data plane (runtime content, optional): `ListActors`, `ListSessions`, `ListEvents`, `ListMemoryRecords`, `RetrieveMemoryRecords`

**Identity / Credential providers** — same-account, SigV4
- `ListWorkloadIdentities` / `GetWorkloadIdentity` (`workloadIdentityArn`, `allowedResourceOauth2ReturnUrls`)
- `ListOauth2CredentialProviders` / `GetOauth2CredentialProvider` (`credentialProviderArn`, vendor, `clientSecretArn.secretArn` → Secrets Manager, discovery/clientId, `onBehalfOfTokenExchangeConfig`)
- `ListApiKeyCredentialProviders` / `GetApiKeyCredentialProvider`
- `ListPaymentCredentialProviders` / `Get…`

**PolicyEngine (Cedar)** — `ListPolicyEngines`/`GetPolicyEngine`; `ListPolicies`/`GetPolicy`
- `GetPolicy.definition.cedar.statement` (Cedar text), `enforcementMode`, `policyEngineId`
- `GetPolicyEngineSummary`, `ListPolicySummaries`

**Registry** — `ListRegistries`/`GetRegistry`; `ListRegistryRecords`/`GetRegistryRecord`; `SearchRegistryRecords`
- Record `descriptors.{mcp.server, mcp.tools, a2a.agentCard, agentSkills, custom}` (inline content)
- `synchronizationConfiguration.fromUrl.credentialProviderConfigurations[]`
- `authorizerConfiguration.customJWTAuthorizer{…}`

**GatewayRule** — `ListGatewayRules`/`GetGatewayRule`
- `conditions[].matchPrincipals.anyOf[].iamPrincipal.arn` → **which principals may route** (authorization signal)
- `actions[].routeToTarget.staticRoute.targetName` / `weightedRoute` → principal→target routing

**IAM (standard)** — for any `roleArn` above
- `GetRole` (trust policy → confirm principal `bedrock-agentcore.amazonaws.com` + `aws:SourceArn` scoping)
- `ListAttachedRolePolicies` + `GetPolicy`/`GetPolicyVersion` (managed)
- `ListRolePolicies` + `GetRolePolicy` (inline)
- Parse `Statement[].{Action, Resource}` → concrete resource ARNs (Lambda, S3, DynamoDB, `secretsmanager:GetSecretValue`, `bedrock-agentcore:Get*Token`, …)

**Observability (standard)** — runtime edges
- CloudWatch Logs spans group `aws/spans` (Transaction Search); X-Ray trace segments; OTEL runtime logs `/aws/bedrock-agentcore/runtimes/{id}/otel-rt-logs`
- Metrics: `AgentCore.Runtime` (by agent ARN/endpoint), `AWS/Bedrock-AgentCore` (gateway/memory/identity)
- Also queryable via the **cw-omni-agents** MCP (`search_agent_traces`, `search_local_telemetry`) for OTEL-shaped spans.

---

## 4. Graph model

### 4.1 Edge provenance tiers (the core concept)

Every edge carries a **tier** and a **source** (which API/field produced it). The UI renders tiers distinctly so a reviewer never mistakes an inferred edge for a proven one.

| Tier | Meaning | Render | Examples |
|---|---|---|---|
| **A — Static / authoritative** | Provable from control-plane config or IAM/Cedar | solid | agent→role→policy→ARN; gateway→target→tool; target→credProvider; gateway→policyEngine |
| **B — Inferred** | Recovered from `environmentVariables` / SSM / artifact parsing | dashed | agent→gateway, agent→memory |
| **C — Observed** | Seen in runtime traces | dotted | agent→(actual tool call); agent→agent delegation; provider actually used |

**Effective access** = Tier A reachable set (targets ∩ IAM, filtered by Cedar). **Over-provisioning finding** = (A ∪ B) − C.

### 4.2 Node types

`AgentRuntime`, `AgentRuntimeEndpoint`, `Gateway`, `GatewayTarget`, `Tool`, `CredentialProvider`, `WorkloadIdentity`, `PolicyEngine`, `CedarPolicy`, `Registry`, `RegistryRecord`, `Memory`, `IamRole`, `IamPolicy`, `ExternalResource` (Lambda/S3/APIGW/DynamoDB/MCP endpoint/HTTP), `DataSource` (S3/EFS access point, Kinesis stream, Memory namespace).

### 4.3 Edge catalog

| From | To | Tier | Source field |
|---|---|---|---|
| AgentRuntime | IamRole | A | `GetAgentRuntime.roleArn` |
| AgentRuntime | WorkloadIdentity | A | `workloadIdentityDetails.workloadIdentityArn` |
| AgentRuntime | DataSource(S3/EFS) | A | `filesystemConfigurations[]` |
| AgentRuntime | Gateway | **B** | parse `environmentVariables` (gatewayUrl) |
| AgentRuntime | Memory | **B** | parse `environmentVariables` (memoryId) / SSM |
| AgentRuntime | Gateway/Tool | **C** | traces (`aws/spans`) |
| AgentRuntime | AgentRuntime | A / C | target `http.agentcoreRuntime.arn` (A) or delegation span (C) |
| Gateway | IamRole | A | `GetGateway.roleArn` |
| Gateway | PolicyEngine | A | `policyEngineConfiguration.arn` |
| Gateway | GatewayTarget | A | `ListGatewayTargets` |
| Gateway | Lambda | A | `customTransformConfiguration.lambda.arn`, `interceptorConfigurations[]` |
| GatewayTarget | Tool | A | `targetConfiguration.*` tool schemas |
| GatewayTarget | CredentialProvider | A | `credentialProviderConfigurations[].*.providerArn` |
| GatewayTarget | ExternalResource | A | `lambdaArn` / `apiGateway` / `mcpServer.endpoint` / `passthrough.endpoint` |
| GatewayRule | GatewayTarget | A | `actions[].routeToTarget.*.targetName` |
| GatewayRule | IamPrincipal | A | `conditions[].matchPrincipals…iamPrincipal.arn` |
| PolicyEngine | CedarPolicy | A | `ListPolicies` (by `policyEngineId`) |
| CredentialProvider | ExternalResource | A | discovery URL / secret ARN |
| Memory | IamRole | A | `memoryExecutionRoleArn` |
| Memory | DataSource(Kinesis) | A | `streamDeliveryResources…dataStreamArn` |
| IamRole | IamPolicy | A | `ListAttached/ListRolePolicies` |
| IamPolicy | ExternalResource | A | parsed `Statement[].Resource` |
| RegistryRecord | Tool/AgentCard | A | `descriptors.*` |

### 4.4 Identifiers
- Canonical node id = **ARN** where one exists; otherwise `{type}:{region}:{account}:{id}`.
- Resolver joins strictly by ARN. Every node stores `region`, `account`, `raw` (source payload), `collectedAt`, `sourceApi`.

---

## 5. Architecture

```
┌──────────────┐   ┌──────────────────┐   ┌────────────────┐   ┌──────────────┐
│  Collectors  │──▶│    Resolver      │──▶│  Graph store   │──▶│  Web app     │
│ (read-only)  │   │ (merge by ARN,   │   │ (in-mem / JSON │   │ (node-link,  │
│ 1 per plane  │   │  tier, findings) │   │  cache)        │   │  drill-down) │
└──────────────┘   └──────────────────┘   └────────────────┘   └──────────────┘
```

### 5.1 Collectors (independent, fail-soft)
One per concern; a denied permission drops that collector's edges with a recorded `collectionError`, never fails the whole graph.

- `RuntimeCollector` — ListAgentRuntimes → GetAgentRuntime (+ versions/endpoints), env-var parse
- `GatewayCollector` — ListGateways → GetGateway; ListGatewayTargets → GetGatewayTarget (union dispatch → tools); ListGatewayRules
- `IdentityCollector` — workload identities + OAuth2/ApiKey/Payment providers
- `PolicyCollector` — policy engines + Cedar policies
- `RegistryCollector` — registries + records
- `MemoryCollector` — memories + strategies (control plane only in v1)
- `IamCollector` — for each discovered `roleArn`: role, attached+inline policies, statement parse
- `ObservabilityCollector` — spans/traces → Tier C edges (opt-in; may be empty if tracing off)

### 5.2 Resolver
- Merge nodes by ARN; attach edges with tier + source.
- Resolve leaf ARNs from IAM statements and target configs into `ExternalResource` nodes.
- Compute **effective reachable set** and **findings** (§6).
- Emit a single typed graph document (§7).

### 5.3 Web app
- **Inventory pane**: searchable list of agents (from `ListAgentRuntimes`) + registry records.
- **Graph pane**: pick agent → expand its subgraph; tier-styled edges (solid/dashed/dotted); collapse/expand by node type.
- **Detail drawer**: click any node/edge → raw source payload + provenance (`sourceApi`, `collectedAt`) → evidence for compliance.
- **Findings pane**: ranked list (§6), each linking to the offending nodes.
- Link-outs to CloudWatch GenAI Observability for the selected agent.

---

## 6. Findings engine (security / governance)

Rule-based, each finding cites the exact node/edge + source field:

1. **Over-broad IAM** — execution-role statement with `Resource: "*"` or `Action: "service:*"` (note: Amazon's A5 CDK construct grants `bedrock-agentcore:*` on `*` — flag but rank as expected-pattern).
2. **Over-provisioning gap** — resource in Tier A/B reachable set never seen in Tier C traces (requires observability).
3. **Unauthenticated inbound** — runtime/gateway with no `customJWTAuthorizer`.
4. **Cedar vs IAM divergence** — gateway bound to a PolicyEngine whose Cedar policies are `enforcementMode` != enforce, or absent while IAM is broad.
5. **Cross-boundary data egress** — Memory `streamDeliveryResources` Kinesis ARN or S3 access point in a different account.
6. **Dangling credential** — CredentialProvider referenced by a target whose secret/discovery is unreachable, or provider with no referencing target.
7. **Untraced agent** — agent with no spans in window (observability blind spot).

Findings carry `severity`, `nodeRefs[]`, `evidence`, `tier`.

---

## 7. Graph document schema (resolver output / API contract)

```jsonc
{
  "account": "111122223333",
  "region": "us-east-1",
  "collectedAt": "2026-07-20T19:00:00Z",
  "nodes": [
    { "id": "arn:...:runtime/foo-5Jr", "type": "AgentRuntime",
      "name": "foo", "region": "...", "account": "...",
      "attrs": { "status": "READY", "protocol": "MCP", "...": "..." },
      "sourceApi": "bedrock-agentcore-control:GetAgentRuntime",
      "raw": { /* full payload */ } }
  ],
  "edges": [
    { "from": "arn:...:runtime/foo-5Jr", "to": "arn:...:role/foo-exec",
      "type": "assumesRole", "tier": "A",
      "sourceApi": "GetAgentRuntime.roleArn" }
  ],
  "findings": [
    { "id": "F-001", "rule": "over-broad-iam", "severity": "high",
      "nodeRefs": ["arn:...:policy/..."], "tier": "A",
      "evidence": "Statement[2].Resource == '*'" }
  ],
  "collectionErrors": [
    { "collector": "IamCollector", "target": "arn:...:role/x",
      "error": "AccessDenied: iam:GetRolePolicy" }
  ]
}
```

---

## 8. Required IAM permissions (read-only)

The tool's own principal needs (least-privilege, all read):
- `bedrock-agentcore:List*`, `bedrock-agentcore:Get*`, `bedrock-agentcore:Search*` (control-plane reads)
- `iam:GetRole`, `iam:ListAttachedRolePolicies`, `iam:ListRolePolicies`, `iam:GetPolicy`, `iam:GetPolicyVersion`, `iam:GetRolePolicy`
- `logs:StartQuery`/`GetQueryResults`/`FilterLogEvents`, `xray:GetTraceSummaries`/`BatchGetTraces`, `cloudwatch:GetMetricData` (observability)
- `lambda:GetFunction`/`GetPolicy`, `apigateway:GET`, `s3:GetBucketPolicy` (optional leaf enrichment)

Ship a ready-to-attach policy JSON as part of setup. **No write actions anywhere.**

---

## 9. Tech stack (proposed)

- **Backend / collectors:** Python + boto3 (service models already present @ botocore 1.43.50). Async fan-out across collectors; per-call pagination + retry/backoff. Rationale: boto3 has the AgentCore models; matches the Omni tooling context.
- **Graph model:** plain typed dicts → single JSON document (§7); optional NetworkX for reachability queries.
- **API:** FastAPI serving `GET /graph?agent=<arn>` and `GET /inventory`.
- **Frontend:** React + a graph lib (Cytoscape.js or React Flow) for node-link + tier-styled edges; detail drawer + findings pane.
- **Auth:** uses the operator's ambient AWS creds (same-account, read-only).

*(Open to swapping frontend graph lib; Cytoscape.js is the default for large graphs + styling.)*

---

## 9a. Deployment & auth models

**How identity works today.** There is no login and no account parameter — the
account graphed is *implicit*: whatever `boto3.Session()` resolves the process's
ambient AWS credentials to (`~/.aws`, `AWS_PROFILE`, env vars, or an attached
instance/task role). The API accepts only `region`. So the tool is currently
**single-tenant: it graphs the one account the running process's credentials
belong to.** The code has a clean seam for changing this — `Aws(region,
session=…)` accepts an injected boto3 session and `build_graph(region, aws=…)`
accepts an injected `Aws`, so the *credential source* is swappable without
touching collectors, resolver, or findings.

Two known gaps that gate any shared deployment:
- **No web-app authentication.** `/api/*` is open; anyone who can reach the URL
  reads whatever the deployment's role can see.
- **In-process cache** (`_CACHE` keyed by `(region, observe)`) — no per-tenant
  isolation or eviction.

| Model | Identity / auth | Accounts per instance | Build effort | Security posture | Best for |
|---|---|---|---|---|---|
| **1. Local per-user** *(today)* | Ambient `~/.aws` creds; no login | 1 (whoever you're logged in as) | none | Excellent — creds never leave the machine, nothing on a network | SAs / security engineers running audits or demos on accounts they already access |
| **2. Shared single-account deploy** | The deployment's own task/exec role (`reader-policy.json`) *is* the AWS identity; optional web-app login | 1 (the account it runs in) | small (package + role); **add app auth if not on a trusted network** | Good, but anyone who can open the URL sees the whole account's graph | A permanent internal dashboard for a fixed, small set of accounts |
| **3. Multi-account via assume-role** | App login (Cognito/OIDC/ALB) **+** per-request `sts:AssumeRole` into a customer-created read-only role | many | largest — session factory, tenant-scoped cache, real authN/Z, onboarding template | Strongest model (no stored long-lived creds, customer-revocable) but largest surface to get right | External customers, or a central platform/security team surveying many accounts |

**Recommended sequencing:** 2 → 3. Stand up a single-account internal dashboard
first (small delta over today); invest in assume-role multi-tenancy only once
there's demand. Org-wide / cross-account crawl is a v2 item (§10).

**What model 3 concretely requires** (for when it's built): a per-request
session factory that calls `sts:AssumeRole` on a customer role ARN and injects
the temporary session into `Aws(...)`; `account`/`roleArn` threaded through the
API and folded into the cache key; an authentication layer on the web app; and a
one-click CloudFormation template so a customer account can create the trusting
read-only role. The customer never hands over long-lived keys — only a role they
can revoke.

---

## 10. Milestones

- **M0 — Live probe & schema lock.** Run collectors against a real account, capture 1 real payload per node type, freeze §3 field semantics (remove **[runbook]** caveats). Confirms auth + pagination + `environmentVariables` parseability.
- **M1 — Static backbone (Tier A).** Runtime + Gateway + Target→Tool + IAM resolution + PolicyEngine + Registry + Memory → emit graph document (§7). CLI: `graph --agent <arn> -o graph.json`.
- **M2 — Inference (Tier B).** Env-var / SSM / artifact parsing → agent→gateway, agent→memory edges.
- **M3 — Web app.** Inventory + node-link graph + detail drawer + provenance.
- **M4 — Findings engine.** §6 rules + findings pane + IAM policy export.
- **M5 — Observability (Tier C).** Spans → observed edges + over-provisioning gap.
- **v2 — Snapshots & diff.** Persist graph documents; drift over time; org/multi-account crawl.

---

## 10a. M0 probe results (2026-07-20, account default, us-east-1)

Live read-only probe run; findings that **lock** prior `[runbook]` caveats:

- **Inventory found:** 5 agent runtimes, 7 gateways (6 empty, 1 with 10 targets), 1 memory, 13 workload identities. 0 policy engines / registries / oauth providers in this account (collectors must treat empty as normal, not error).
- **Tier B env-var join CONFIRMED.** Agent `environmentVariables` reliably carry the associations the control plane omits:
  - `NEPTUNE_GATEWAY_URL` → matches a real `gatewayUrl` / gatewayId (agent→gateway edge).
  - `LESSONS_MEMORY_ID` == the Memory `id` exactly (agent→memory edge).
  - Bonus data-source edges seen in env: `SEMANTIC_RAG_KB_ID` (Bedrock KB), `GUARDRAIL_IDENTIFIER` (Bedrock guardrail ARN), `METRICS_TABLE`/`ONTOLOGY_METADATA_TABLE` (DynamoDB). **Add a heuristic env parser** (keys matching `*_GATEWAY_URL`, `*_MEMORY_ID`, `*_KB_ID`, `*_TABLE`, `*ARN`, guardrail/*).
- **Union dispatch CONFIRMED.** `GetGatewayTarget.targetConfiguration.mcp.lambda.lambdaArn` + `toolSchema.inlinePayload[].name` (e.g. tool `persist_to_neptune`). `ListGatewayTargets.items[].targetType` = `"LAMBDA"` present.
- **New credentialProviderType value:** `"GATEWAY_IAM_ROLE"` — target defers to the gateway's execution role instead of a separate `providerArn`. Add to the target→credential handling (no providerArn to follow; the edge is target→gateway.roleArn).
- **Nuances for collectors:** `protocolConfiguration.serverProtocol` seen as `HTTP` (not just MCP); `gateway.protocolType` can be `None`; `policyEngineConfiguration`, `filesystemConfigurations`, `streamDeliveryResources`, `memoryExecutionRoleArn` can all be `None`. Empty gateways return 0 targets. Timestamps need `default=str` on JSON dump.
- **Pagination:** all list ops use `nextToken`; item list key varies (`agentRuntimes`, `items`, `memories`, …) — resolve by first list-typed value when key unknown.

## 11. Open questions / risks

1. **`environmentVariables` reliability (Tier B):** how consistently do agents encode gatewayUrl/memoryId there vs. SSM/baked defaults? — resolve empirically in M0.
2. **Trace coverage (Tier C):** requires per-agent tracing toggle; expect partial. Untraced agents flagged (finding #7).
3. **Cedar semantics:** we surface Cedar policy text; do we *evaluate* it (Cedar engine) in v1 or just display? — proposed: display in v1, evaluate in v2.
4. **`[runbook]` field semantics** (tool-naming `___`, env-var discovery pattern, A5 broad-scope) — confirm against live account in M0 before findings depend on them.
5. **Scale:** hundreds of agents × IAM fan-out → cache + rate-limit; graph doc per-agent to keep the web payload bounded.
6. **Registry vs Runtime overlap:** a record may describe an agent also present as a runtime — dedupe/link by name+ARN.

---

## 12. Provenance of this spec

- API operations & shapes: **verified** against botocore 1.43.50 service models (`bedrock-agentcore-control`, `bedrock-agentcore`) on the dev machine, 2026-07-20.
- Field *semantics* & internal service context: from a research pass over AgentCore internal runbooks/specs (marked **[runbook]**), **not yet** independently re-opened — to be confirmed in M0.
- Four corrections to that research (Registry exists, Policy Engine exists, static target→credProvider edge, exposed env vars) were made directly from the SDK models.
