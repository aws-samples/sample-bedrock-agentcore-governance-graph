#!/usr/bin/env python3
"""M0 live probe — read-only inventory of AgentCore resources.

Lists every AgentCore control-plane resource type in the given regions,
counts them, and captures ONE sample payload per type so we can lock the
field semantics that SPEC.md §3 currently marks [runbook].

Strictly read-only: only List*/Get* calls.
"""
import json
import sys
import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

REGIONS = ["us-east-1", "us-west-2"]

# (list_op, item_key, get_op, get_arg_from_item) — get_op optional
LIST_SPECS = [
    ("list_agent_runtimes", "agentRuntimes", "get_agent_runtime",
     lambda it: {"agentRuntimeId": it["agentRuntimeId"]}),
    ("list_gateways", "items", "get_gateway",
     lambda it: {"gatewayIdentifier": it.get("gatewayId") or it.get("gatewayIdentifier")}),
    ("list_memories", "memories", "get_memory",
     lambda it: {"memoryId": it.get("id") or it.get("memoryId")}),
    ("list_workload_identities", "workloadIdentities", None, None),
    ("list_oauth2_credential_providers", "credentialProviders", None, None),
    ("list_api_key_credential_providers", "credentialProviders", None, None),
    ("list_policy_engines", "policyEngines", None, None),
    ("list_registries", "registries", None, None),
    ("list_browsers", "browsers", None, None),
    ("list_code_interpreters", "codeInterpreters", None, None),
]


def paginate(client, op, item_key):
    """Collect all items from a list op, following nextToken."""
    items, token = [], None
    while True:
        kwargs = {"nextToken": token} if token else {}
        try:
            resp = client.__getattribute__(op)(**kwargs)
        except TypeError:
            resp = getattr(client, op)(**kwargs)
        # find the list in the response
        key = item_key if item_key in resp else next(
            (k for k, v in resp.items() if isinstance(v, list)), None)
        items.extend(resp.get(key, []) if key else [])
        token = resp.get("nextToken")
        if not token:
            break
    return items


def probe_region(region):
    out = {"region": region, "types": {}, "errors": []}
    cp = boto3.client("bedrock-agentcore-control", region_name=region)
    for list_op, item_key, get_op, get_arg in LIST_SPECS:
        if not hasattr(cp, list_op):
            out["errors"].append(f"{list_op}: not in SDK")
            continue
        try:
            items = paginate(cp, list_op, item_key)
        except (ClientError, EndpointConnectionError) as e:
            code = getattr(e, "response", {}).get("Error", {}).get("Code", type(e).__name__)
            out["errors"].append(f"{list_op}: {code}")
            continue
        entry = {"count": len(items), "sample_list_item": items[0] if items else None}
        # capture one full Get* payload
        if items and get_op and hasattr(cp, get_op):
            try:
                entry["sample_get"] = getattr(cp, get_op)(**get_arg(items[0]))
            except (ClientError, KeyError, EndpointConnectionError) as e:
                entry["get_error"] = str(e)[:200]
        out["types"][list_op] = entry
    return out


def main():
    ident = boto3.client("sts").get_caller_identity()
    result = {"account": ident["Account"], "arn": ident["Arn"], "regions": []}
    for r in REGIONS:
        print(f"probing {r} ...", file=sys.stderr)
        result["regions"].append(probe_region(r))
    # default=str handles datetimes
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
