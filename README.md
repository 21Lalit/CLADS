# CLADS

**Closed-Loop Autonomous Defense System** is a deployable research MVP for the
Detect → Analyze → Respond → Adapt cyber-defense cycle. It turns simulated
network flows into contextual risk scores, explainable multi-agent traces, and
human-governed response recommendations.

> Safety and research scope: the public build is dry-run only. It does not modify
> host firewall rules. Its deterministic scoring engine is an explainable baseline;
> it does **not** claim to be a trained GraphSAGE or PPO implementation. Those
> models remain planned empirical work from the accompanying research proposal.

## What works

- Five-stage agent trace: Detection, Graph, Decision, Response, Learning
- Persistent SQLite telemetry and aggregate metrics
- Human-approval state for high-impact actions
- Responsive dashboard and OpenAPI documentation
- One-process deployment suitable for Render's free web service
- Input validation, safe HTML rendering, health check, and API tests
- Five-view interactive research console: command center, attack laboratory,
  policy control plane, autonomous learning, and closed-loop evidence
- 30 extensible attack profiles across nine major network-threat families
- Browser-rendered risk history, entity topology, policy utility, approval queue,
  adaptation log, and per-event five-stage evidence

## Run locally

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
uvicorn app.main:app --reload
```

Open <http://localhost:8000>. API documentation is at `/docs`.

Run tests:

```powershell
pytest -q
```

## Deploy on Render

1. Push this directory to a GitHub repository.
2. In Render, choose **New → Blueprint** and select the repository.
3. Render reads `render.yaml`, builds the Docker image, and checks `/api/health`.

The free Render filesystem is ephemeral, so demo events may reset after a restart.
For durable telemetry, attach a persistent disk (paid) and set `CLADS_DB` to its
mount path, or replace SQLite with managed PostgreSQL.

## Free GitHub Pages demonstration

The primary public demo runs entirely in each visitor's browser. It uses GitHub
Pages and GitHub Actions only, sends no actual network traffic, and needs no paid
server or database. Visitors can simulate HTTPS, SSH, DNS, database, and ICMP
requests with normal, scan, brute-force, web-attack, botnet, and DDoS behavior.
The latest 50 simulated events are stored locally in the visitor's browser.

Shared demonstration intelligence is backed by a free Cloudflare Worker and D1.
Visitor IP addresses are HMAC-pseudonymized at the edge and never stored raw or
returned to clients. Approximate coordinates are rounded, and only actions
performed inside the simulation are recorded and correlated. The Worker source
and database schema are in `worker/`.

Push `main`, then set **Repository Settings → Pages → Source** to **GitHub
Actions**. The included workflow publishes the demonstration automatically.

## Architecture

```text
Network flow → Detection → Graph context → Decision → Response gate
                    ↑                              │
                    └──────── feedback/adapt ──────┘
```

The current graph score approximates relationship context using repeat-source
history and flow characteristics. A production research phase should replace the
baseline with trained CNN/Random Forest detection, GraphSAGE embeddings, and a PPO
policy, evaluated independently on CICIDS2017 and NSL-KDD without data leakage.

## API

- `GET /api/health` — service readiness
- `POST /api/simulate` — execute one closed-loop simulation
- `GET /api/events` — recent telemetry
- `GET /api/metrics` — aggregate dashboard metrics
- `POST /api/actions/{id}/approve` — approve an action in dry-run mode

## Responsible use

CLADS is defensive research software. Keep enforcement behind explicit operator
approval, validate policies in an isolated environment, and never run attack
simulations against systems you do not own or have permission to test.

## License

MIT
