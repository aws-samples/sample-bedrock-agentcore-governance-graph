"""Shared AWS helpers — client factory, pagination, ARN parsing.

All calls are read-only (List*/Get*). Collectors catch ClientError and
record a CollectionError rather than aborting the whole graph build.
"""
from __future__ import annotations

import re
from typing import Any, Callable, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

_CONFIG = Config(retries={"max_attempts": 5, "mode": "adaptive"})


class Aws:
    """Region-scoped boto3 client cache."""

    def __init__(self, region: str, session: Optional[boto3.Session] = None):
        self.region = region
        self._session = session or boto3.Session()
        self._clients: dict[str, Any] = {}

    def client(self, service: str) -> Any:
        if service not in self._clients:
            self._clients[service] = self._session.client(
                service, region_name=self.region, config=_CONFIG
            )
        return self._clients[service]

    @property
    def control(self):
        return self.client("bedrock-agentcore-control")

    @property
    def iam(self):
        # IAM is global; region doesn't matter but keep one client
        return self.client("iam")

    @property
    def ssm(self):
        return self.client("ssm")

    @property
    def logs(self):
        return self.client("logs")

    @property
    def xray(self):
        return self.client("xray")

    def account_id(self) -> str:
        return self._session.client("sts").get_caller_identity()["Account"]


def paginate(client: Any, op_name: str, item_key: Optional[str] = None, **kwargs) -> list[dict]:
    """Collect all items from a List* op, following nextToken.

    If item_key is not present in the response, falls back to the first
    list-valued field (list-op response keys vary across AgentCore ops).
    """
    op = getattr(client, op_name)
    items: list[dict] = []
    token: Optional[str] = None
    while True:
        call_kwargs = dict(kwargs)
        if token:
            call_kwargs["nextToken"] = token
        resp = op(**call_kwargs)
        key = item_key if (item_key and item_key in resp) else _first_list_key(resp)
        if key:
            items.extend(resp.get(key, []) or [])
        token = resp.get("nextToken")
        if not token:
            break
    return items


def _first_list_key(resp: dict) -> Optional[str]:
    for k, v in resp.items():
        if k == "ResponseMetadata":
            continue
        if isinstance(v, list):
            return k
    return None


def safe_get(fn: Callable[[], Any], on_error: Callable[[str], None]) -> Optional[Any]:
    """Run a Get* call, routing ClientError to on_error(code) and returning None."""
    try:
        return fn()
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "ClientError")
        on_error(code)
        return None


# ---- ARN parsing ----
_ARN_RE = re.compile(
    r"^arn:(?P<partition>[^:]*):(?P<service>[^:]*):(?P<region>[^:]*):"
    r"(?P<account>[^:]*):(?P<resource>.*)$"
)


def parse_arn(arn: str) -> Optional[dict[str, str]]:
    m = _ARN_RE.match(arn or "")
    if not m:
        return None
    d = m.groupdict()
    # resource may be "type/name", "type:name", or bare "name"
    res = d["resource"]
    sep = "/" if "/" in res else (":" if ":" in res else None)
    if sep:
        d["resource_type"], d["resource_id"] = res.split(sep, 1)
    else:
        d["resource_type"], d["resource_id"] = "", res
    return d


def is_arn(s: str) -> bool:
    return isinstance(s, str) and s.startswith("arn:")


def role_name_from_arn(arn: str) -> Optional[str]:
    p = parse_arn(arn)
    if p and p["service"] == "iam" and p["resource_type"] == "role":
        return p["resource_id"]
    return None


def account_of(arn: str) -> Optional[str]:
    """Return the account id embedded in an ARN, or None if absent/unparseable."""
    p = parse_arn(arn)
    acct = (p or {}).get("account")
    return acct or None


# ---- gateway URL matching (Tier-B env-var join) ----
def normalize_gateway_url(url: str) -> str:
    """Canonicalize a gateway URL for exact-match joins: lowercase host,
    drop scheme, trailing slash, and a trailing /mcp path suffix. Env vars and
    the control-plane gatewayUrl often differ only by these."""
    if not url:
        return ""
    u = url.strip().lower()
    u = re.sub(r"^https?://", "", u)
    u = u.rstrip("/")
    u = re.sub(r"/mcp$", "", u)
    return u


def gateway_id_from_url(url: str) -> Optional[str]:
    """AgentCore gateway URLs are https://<gatewayId>.gateway.bedrock-agentcore.
    <region>.amazonaws.com/... — the first host label is the gatewayId."""
    m = re.match(r"^https?://([^./]+)\.", (url or "").strip())
    return m.group(1) if m else None
