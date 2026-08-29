# Developing & Deploying

Exact setup, build, test, run, and deploy steps for the AgentCore Access Graph.
For *what* the tool does and *why*, see [`README.md`](README.md) and
[`docs/SPEC.md`](docs/SPEC.md).

## Prerequisites

- **Python 3.11+** (developed on 3.11).
- **AWS credentials** with read-only access to the target account
  (`~/.aws/credentials`, `AWS_PROFILE`, env vars, or an attached
  instance/task role). See [Required IAM](#required-iam) below.
- No Node.js / npm — the frontend is a no-build single page served by the API,
  with Cytoscape.js vendored into the repo (no CDN, no network at runtime).

## Setup

Dependencies and packaging are declared in [`pyproject.toml`](pyproject.toml).
Use a virtualenv to keep them isolated, then do an editable install.

```bash
# from the repo root
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# CLI only
pip install -e .

# CLI + web app
pip install -e '.[web]'

# CLI + web app + test tooling
pip install -e '.[web,dev]'
```

The editable install puts the package on the path (no `PYTHONPATH=src` needed)
and installs an `agentcore-graph` console command. Dependency sets:

| Extra     | Packages                | Use              |
|-----------|-------------------------|------------------|
| *(base)*  | `boto3`                 | CLI              |
| `web`     | `fastapi`, `uvicorn`    | web app          |
| `dev`     | `pytest`                | tests            |

Everything else (`argparse`, `dataclasses`, `json`, `re`, …) is in the standard
library.

## Build

There is **no compile/bundle step** — it's plain Python plus a no-build
frontend. The editable install in [Setup](#setup) is all that's needed. To build
a distributable wheel/sdist instead:

```bash
pip install build
python3 -m build          # writes dist/*.whl and dist/*.tar.gz
```

To sanity-check that the package imports cleanly:

```bash
python3 -c "import agentcore_graph.cli, agentcore_graph.api; print('ok')"
```

### Frontend assets

`src/agentcore_graph/web/` holds the entire frontend — four files, all served
verbatim by `api.py`:

| File               | Role                                               |
|--------------------|----------------------------------------------------|
| `index.html`       | the page shell                                     |
| `app.js`           | graph rendering, filters, detail panel, findings   |
| `app.css`          | Cloudscape-flavoured styling                       |
| `cytoscape.min.js` | **vendored** Cytoscape.js (~370 KB), not a CDN ref |

`cytoscape.min.js` is committed to the repo, so a clone works offline and in
locked-down networks. It must stay committed: `index.html` loads it from
`/cytoscape.min.js`, so if the file is missing the API returns 404 for it and the
graph silently never renders. `pyproject.toml`'s `package-data = ["web/*"]`
glob picks it up for wheels automatically. To refresh the version, drop a new
minified build in place — there's nothing to rebuild.

## Test

```bash
python3 -m pytest tests/ -q          # after `pip install -e '.[dev]'`
```

Or run the offline suite directly (no AWS, no pytest needed):

```bash
python3 tests/test_graph.py
```

Both run the same 18 checks against fixtures — no AWS calls, no credentials
required, so they're safe in CI.

## Run

### CLI

After `pip install -e .`, use the `agentcore-graph` console command (equivalent
to `python3 -m agentcore_graph.cli`):

```bash
# whole account/region -> stdout
agentcore-graph --region us-east-1

# ...or to a file
agentcore-graph --region us-east-1 -o graph.json

# one agent's access chain
agentcore-graph --region us-east-1 \
    --agent arn:aws:bedrock-agentcore:us-east-1:ACCT:runtime/foo-XXXX -o foo.json

# counts + findings only, no JSON payload
agentcore-graph --region us-east-1 --summary

# drop raw source payloads to shrink the document
agentcore-graph --region us-east-1 --no-raw -o graph.json

# overlay Tier-C observed edges from CloudWatch traces (opt-in)
agentcore-graph --region us-east-1 --observe -o graph.json

# ...with a wider lookback than the 1h CLI default (seconds)
agentcore-graph --region us-east-1 --observe --observe-window 86400 -o graph.json

# print the least-privilege reader IAM policy, then exit
agentcore-graph --region us-east-1 --print-policy
```

`--region` is the only required flag. The graph JSON goes to stdout (or `-o`),
while the `--summary` counts, findings, and any `collectionErrors` go to
**stderr** — so `agentcore-graph ... > graph.json` still shows you the summary on
the terminal, and `2>/dev/null` silences it.

### Web app

```bash
uvicorn agentcore_graph.api:app --port 8899
# open http://localhost:8899/
```

For live reload during frontend/API work:

```bash
uvicorn agentcore_graph.api:app --port 8899 --reload
```

Endpoints: `GET /api/inventory`, `GET /api/graph?agent=<arn>`
(add `?refresh=1` to rebuild from AWS, `?raw=true` to include source payloads),
`GET /api/reader-policy`. The API has no `--region` flag — every endpoint takes
`?region=`, defaulting to `AWS_REGION`, then `AWS_DEFAULT_REGION`, then
`us-east-1`; the header's region box sets it per request.

Tier-C observed edges: add `?observe=1` (both endpoints). On the API the lookback
window defaults to **24h** (the CLI's `--observe-window` defaults to 1h) and is
overridable per request with `?observe_window=<seconds>` or globally via the
`OBSERVE_WINDOW_SECONDS` env var — sessions older than the window won't appear
(the web UI exposes a `last 1h … 30d` picker next to the *observe* toggle, which
stays disabled until *observe* is ticked). Spans come from the CloudWatch Logs
`aws/spans` group (Transaction Search) and are attributed to an agent via their
OTel resource — `resource.attributes.service.name` (`"<agent>.<endpoint>"`) or
`resource.attributes.cloud.resource_id` (the runtime ARN), falling back to
`attributes.agent.arn` / `attributes.agent.name` — carrying the invoked tool in
`attributes.gen_ai.tool.name`.

The graph is cached per `(region, observe, observe_window)`, so toggling the
overlay or the window builds a separate snapshot rather than mutating the
existing one. `?refresh=1` forces a rebuild of the entry you're asking for.

## Required IAM

Attach [`docs/reader-policy.json`](docs/reader-policy.json) to the principal
running the tool (all read-only), or generate it live with `--print-policy`.
A missing permission degrades one collector and is recorded under
`collectionErrors` rather than failing the run.

## Deploy

The tool is **single-tenant**: no login, no account parameter — it graphs
whatever account the process's ambient AWS credentials resolve to. The web API
has **no authentication yet**, so any shared deployment must add an auth layer
(reverse proxy, SSO sidecar, etc.) in front of it first. The three deployment
models and their code seams are detailed in [`docs/SPEC.md` §9a](docs/SPEC.md).

### Setting the target account

There is **no `--account` or `--profile` flag.** The target account is whatever
your ambient AWS credentials resolve to via boto3's standard resolution chain
(`Aws.__init__` in `src/agentcore_graph/aws.py` calls `boto3.Session()` with no
args). `--region` only selects the region; the account comes from the
credentials. You steer it by controlling that credential chain:

```bash
# named profile from ~/.aws/config
AWS_PROFILE=my-target-acct agentcore-graph --region us-east-1 -o graph.json

# explicit credentials in the environment
AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=... \
    agentcore-graph --region us-east-1 -o graph.json
```

On EC2/ECS/Lambda, the attached instance/task role *is* the target account —
nothing to set. Verify which account you'll actually graph with
`aws sts get-caller-identity` (the tool reports the same via `account_id()`).

### 1. Local, per-user (default)

Run the CLI or `uvicorn` locally as shown in [Run](#run) with your own AWS
profile. Nothing else to deploy.

### 2. Shared, single-account service

Run the web app on a host/instance whose task or instance role carries the
reader policy. Bind uvicorn to loopback and front it with an authenticating
reverse proxy — **do not expose port 8899 directly.**

```bash
# on the host, behind a reverse proxy that terminates auth
uvicorn agentcore_graph.api:app --host 127.0.0.1 --port 8899
```

For a longer-lived process, run it under a supervisor (systemd, container
`CMD`, ECS task, etc.):

```bash
# example container command
uvicorn agentcore_graph.api:app --host 0.0.0.0 --port 8899 --workers 2
```

Install into the image/host with `pip install '.[web]'`, or build a wheel (see
[Build](#build)) and install that:

```bash
# quote the whole spec — an unquoted [web] is a shell glob, not an extra
pip install 'dist/agentcore_graph-0.1.0-py3-none-any.whl[web]'
```

The no-build frontend — including the vendored `cytoscape.min.js` — ships inside
the package, so no separate `src/` copy is needed. Include
`docs/reader-policy.json` if you attach IAM from the repo.

### 3. Multi-account (assume-role)

Not yet implemented as a first-class flag — you assume the role *outside* the
process and hand it credentials per run. Two copy-paste paths:

**A. Assume-role in the shell, then export the temp credentials:**

```bash
read -r AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN < <(
  aws sts assume-role \
    --role-arn arn:aws:iam::TARGET_ACCOUNT_ID:role/agentcore-graph-reader \
    --role-session-name agentcore-graph \
    --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
    --output text)
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN

agentcore-graph --region us-east-1 -o target.json
# for another account, re-run assume-role with a different --role-arn
```

**B. A profile that assumes the role, selected via `AWS_PROFILE`** — put this in
`~/.aws/config`, then just set `AWS_PROFILE`:

```ini
[profile graph-target]
role_arn       = arn:aws:iam::TARGET_ACCOUNT_ID:role/agentcore-graph-reader
source_profile = default            # a profile allowed to sts:AssumeRole
region         = us-east-1
```

```bash
AWS_PROFILE=graph-target agentcore-graph --region us-east-1 -o target.json
```

The target account's `agentcore-graph-reader` role must carry
[`docs/reader-policy.json`](docs/reader-policy.json) and trust your source
principal. To sweep several accounts, loop over role ARNs re-running path A.

**In-process seam (v2):** `Aws.__init__` already accepts a `session=` argument,
so a `--assume-role-arn` flag could build `boto3.Session(**assumed_creds)` and
pass it in — no other code changes. See [`docs/SPEC.md` §9a](docs/SPEC.md);
tracked under **v2** (org / multi-account crawl) in the README status.
