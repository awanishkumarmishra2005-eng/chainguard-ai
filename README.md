# ChainGuard AI

Flask dashboard for graph-backed security investigation using FalkorDB. The
repository contains the application currently checked out locally; it does
not contain the separate original project, a SQLite/authentication service, or
Render credentials.

## Features

- Interactive dashboard with graph-node details.
- FalkorDB-backed investigation paths for users, events, IP addresses, devices,
  and departments.
- Rule-based investigation findings with explicit fictional-data notices.
- Local Ollama explanations using `qwen2.5:1.5b` when live mode is configured.
- Read-only graph inspection by default, with explicit opt-in for graph writes.

## Requirements

- Python 3.12.10
- Docker Desktop for the local FalkorDB container
- Ollama for local model responses
- PowerShell on Windows

## What was verified

The local Docker container `chainguard-db` exposes FalkorDB on port `6379` and
the browser on port `3000`. The existing `ChainGuard` graph was queried
read-only and contained 18 `Entity` nodes and 16 relationships when this
diagnosis was performed. No graph was deleted, flushed, recreated, or migrated.

The application uses the graph only when `DEMO_MODE=false`. Demo mode returns
clearly labelled synthetic data and does not connect to FalkorDB. If
`DEMO_MODE` is absent, the application now defaults to live mode rather than
silently changing behavior because it happens to run on Render.

## Windows PowerShell: local live mode

Run these commands from this `chainguard_fixed` directory.

1. Confirm the existing container without recreating it:

   ```powershell
   docker ps -a --filter "name=chainguard-db"
   docker start chainguard-db
   ```

   If the container does not exist, stop and confirm that no existing graph
   data needs to be preserved before creating a new empty instance. Bind a new
   local-only instance to loopback rather than all host interfaces:

   ```powershell
   docker run --name chainguard-db `
     -p 127.0.0.1:6379:6379 `
     -p 127.0.0.1:3000:3000 `
     -d falkordb/falkordb:latest
   ```

   Do not run that creation command for the existing data-bearing container
   without a verified RDB backup. The current container has no persistent
   Docker volume.

2. Create and activate a project-local virtual environment:

   ```powershell
   py -3.12 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install --upgrade pip
   python -m pip install -r requirements.lock
   ```

3. Copy the safe example configuration. Do not put real credentials in Git:

   ```powershell
   Copy-Item .env.example .env
   $env:DEMO_MODE = "false"
   $env:ALLOW_GRAPH_WRITES = "false"
   $env:FALKORDB_HOST = "localhost"
   $env:FALKORDB_PORT = "6379"
   $env:FALKORDB_GRAPH_NAME = "ChainGuard"
   $env:OLLAMA_URL = "http://127.0.0.1:11434"
   $env:OLLAMA_MODEL = "qwen2.5:1.5b"
   ```

   The app does not automatically load `.env`; the PowerShell variables above
   are the deterministic setup. If you prefer a URL, use a provider URL in
   `FALKORDB_URL` and leave the host/port fallback unused. Never paste a real
   URL containing a password into chat or source control.

4. Start Ollama separately and verify the model:

   ```powershell
   ollama pull qwen2.5:1.5b
   ollama list
   Invoke-RestMethod http://127.0.0.1:11434/api/tags
   ```

5. Run the focused checks and start Flask:

   ```powershell
   python -m unittest discover -s tests -v
   python -m py_compile app.py falkor_store.py
   python app.py
   ```

6. In another PowerShell window, verify the real service:

   ```powershell
   Invoke-RestMethod http://127.0.0.1:5000/api/version
   Invoke-RestMethod http://127.0.0.1:5000/api/health
   Invoke-RestMethod http://127.0.0.1:5000/api/graph
   Invoke-RestMethod http://127.0.0.1:5000/api/investigate
   Invoke-RestMethod http://127.0.0.1:5000/api/investigate-paths
   ```

   Expected live health fields include `application: "ok"`, `graph: "ok"`,
   and `database: "connected"`. A real graph query must succeed before the
   UI is described as connected.

   Test an evidence-grounded AI explanation without writing graph data:

   ```powershell
   $body = @{ question = "Explain the investigation evidence and distinguish observed facts from possible risks." } | ConvertTo-Json
   Invoke-RestMethod `
     -Uri "http://127.0.0.1:5000/api/ai-explain" `
     -Method Post `
     -ContentType "application/json" `
     -Body $body
   ```

   With `ALLOW_GRAPH_WRITES=false`, the chatbot route remains read-only and
   reports that memory persistence is disabled. Do not call `/api/seed` against
   the existing `ChainGuard` graph unless a write is explicitly approved.

## Windows PowerShell: intentional demo mode

Demo mode is useful for a public presentation when no reachable hosted graph
exists. It is not graph persistence and it is not threat intelligence:

```powershell
$env:DEMO_MODE = "true"
python app.py
Invoke-RestMethod http://127.0.0.1:5000/api/health
```

The response reports `application: "ok"`, `graph: "demo_mode"`, and
`database: "demo_mode"`. It does not claim a live FalkorDB connection.

## Configuration reference

Preferred names are listed first. The legacy `DB_*` aliases are accepted only
when the corresponding preferred name is absent.

| Variable | Required | Meaning |
|---|---:|---|
| `DEMO_MODE` | No | `true` explicitly selects synthetic data; default is `false`. |
| `ALLOW_GRAPH_WRITES` | No | Defaults to `false`; enables `/api/seed` and agent-memory writes only in an authorized local/test environment. |
| `FALKORDB_URL` | No | Preferred `falkor://`, `falkors://`, `redis://`, or `rediss://` provider URL. |
| `FALKORDB_HOST` | No | Host fallback; default `localhost`. |
| `FALKORDB_PORT` | No | Port fallback; default `6379`. |
| `FALKORDB_GRAPH_NAME` | No | Graph name; default `ChainGuard`. |
| `FALKORDB_USERNAME` | No | Database username, if the provider requires one. |
| `FALKORDB_PASSWORD` | No | Database password, supplied only through the secret manager/environment. |
| `FALKORDB_TLS` | No | `true` enables TLS for host/port configuration. Secure URL schemes enable it automatically. |
| `FALKORDB_SSL_CERT_REQS` | No | `required` (recommended), `optional`, or `none`. |
| `FALKORDB_SSL_CA_CERTS` | No | Optional CA bundle path required by a provider. |
| `FALKORDB_CONNECT_TIMEOUT` | No | Connection timeout seconds; default `5`. |
| `FALKORDB_SOCKET_TIMEOUT` | No | Socket/query timeout seconds; default `10`. |
| `OLLAMA_URL` | No | Local model endpoint; default `http://127.0.0.1:11434`. |
| `OLLAMA_MODEL` | No | Ollama model; default `qwen2.5:1.5b`. |

The `/api/version` and `/api/health` responses expose only host/port/graph,
TLS, and whether authentication is configured. They never return a password
or the raw connection URL.

When live mode is enabled and `ALLOW_GRAPH_WRITES=false`:

- `/api/seed` returns HTTP 403 and does not write to FalkorDB.
- `/api/agent-chat` can read graph evidence and answer through Ollama, but does
  not persist the response in `InvestigationMemory`.

Set `ALLOW_GRAPH_WRITES=true` only for an authorized local or disposable test
environment. This flag is not an authentication system and must not be used as
a substitute for protecting a public deployment.

## Render architecture

Render cannot reach the developer laptop's `localhost` or the Docker container
named `chainguard-db`. Setting `DEMO_MODE=false` on Render alone therefore
cannot create connectivity. The public deployment currently responds as an
older `v5-stable` service: its public `/api/version` reports `demo_mode:false`,
while `/api/health` reports HTTP `503` and `database: "unavailable"`. This is
evidence of a deployed code/configuration mismatch, not proof that the local
FalkorDB is broken.

### Safe hosted choices

**Choice A — keep the public demo (no hosted graph required):**

1. In the Render service's Environment settings, set `DEMO_MODE` to `true`.
2. Deploy the code version that labels health as `graph: "demo_mode"`.
3. Do not set local `localhost` FalkorDB values on Render.

**Choice B — use live graph data:**

1. Provision or select one persistent, reachable FalkorDB-compatible service.
   Do not create a duplicate instance until the intended graph owner confirms
   that the existing `ChainGuard` graph is not the one to reuse.
2. Require provider authentication and TLS. Do not expose unauthenticated
   Redis/FalkorDB directly to the public internet.
3. In Render, add the provider's secret connection URL as `FALKORDB_URL`, or
   add the `FALKORDB_HOST`, `FALKORDB_PORT`, `FALKORDB_USERNAME`, and
   `FALKORDB_PASSWORD` values as protected environment variables.
4. Set `FALKORDB_GRAPH_NAME=ChainGuard` only after confirming that this is the
   intended existing graph.
5. Set `FALKORDB_TLS=true` when using host/port settings, or use a `falkors://`
   or `rediss://` URL. Keep certificate verification at `required` unless the
   provider documents a different CA setup.
6. Set `DEMO_MODE=false`, redeploy only with approval, then check `/api/health`
   and require `graph: "ok"` plus `database: "connected"`.

The local Docker endpoint is not a valid Render endpoint. Render plan support,
private networking, persistent disks, egress, and provider pricing must be
confirmed in the Render/provider dashboards; they cannot be inferred from this
repository.

## Tests

The repository has no prior test suite; the added tests use Python's standard
library and do not require a live database by default:

```powershell
python -m unittest discover -s tests -v
```

The live integration test is explicitly skipped unless enabled. It writes only
to the separate test graph name `ChainGuard_Test` by default and never touches
the existing `ChainGuard` graph:

```powershell
$env:RUN_FALKORDB_INTEGRATION = "1"
$env:FALKORDB_TEST_GRAPH = "ChainGuard_Test"
python -m unittest tests.test_falkor_store -v
Remove-Item Env:RUN_FALKORDB_INTEGRATION
Remove-Item Env:FALKORDB_TEST_GRAPH
```

Use the live test only against a disposable/test graph. Do not point it at the
production or original `ChainGuard` graph.

## Docker build/run

The included Dockerfile installs the pinned lockfile and binds Gunicorn to the
Render-provided `PORT` (or `5000` locally):

The accompanying `.dockerignore` excludes `.git`, environment files, Python
caches, RDB backups, and patch artifacts from the build context. Keep real
environment files outside Docker build contexts.

```powershell
docker build -t chainguard-ai .
docker run --rm -p 5000:5000 `
  -e DEMO_MODE=true `
  chainguard-ai
```

For live local Docker-to-Docker access, put the Flask container and FalkorDB
container on the same user-defined Docker network and use the database
container name as `FALKORDB_HOST`; do not use `localhost` from inside the Flask
container.

## Known limitations

- This checkout contains no authentication, CSRF, rate limiting, audit-log,
  Trust Layer, SQLite, `render.yaml`, or deployment-secret implementation to
  preserve. Those claims must be checked in the other project checkout before
  merging this patch there.
- No hosted FalkorDB endpoint or Render environment values were available to
  test. The public Render HTTP endpoints were tested without exposing secrets.
- The graph's relationships are the existing fictional `Entity` model. The
  application does not add real passwords, session secrets, or authentication
  credentials to the graph.
