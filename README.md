# CLADS

CLADS is a closed-loop autonomous cyber-defense platform that turns network
signals into contextual risk intelligence, governed response decisions, and
continuous adaptation.

## Platform capabilities

- Hybrid threat scoring across 30 attack profiles and nine threat families
- Geographic visitor-node intelligence with historical event correlation
- Graph-based entity, service, location, and behavior analysis
- Policy-constrained autonomous response selection
- Human approval workflow for high-impact actions
- Reward-driven action utility and adaptation history
- Complete Detect → Analyze → Decide → Respond → Adapt evidence trail
- Secured administration with rate limiting and expiring signed sessions
- Persistent Cloudflare D1 intelligence and a responsive GitHub Pages console

## Privacy and security

Visitor public IP addresses are returned only to the originating browser for
source-aware analysis. CLADS stores an HMAC-derived node identity instead of the
raw IP. Public intelligence exposes approximate, rounded location data and never
returns raw addresses. Shared visit and event records expire after 30 days.

Administration is verified by the Cloudflare control plane. Credentials are held
in encrypted Worker secrets, failed logins are rate-limited, and signed sessions
expire after 30 minutes. The local credential file is excluded from Git.

## Architecture

```text
GitHub Pages console
        │
        ▼
Cloudflare Worker ── identity, policy, admin authorization
        │
        ▼
Cloudflare D1 ────── visitor nodes, threat events, correlations
```

The browser analysis engine handles scoring, graph context, policy evaluation,
action selection, evidence rendering, and local learning state. The edge control
plane adds persistent cross-visitor intelligence, geographic context, and secure
administration.

## Run locally

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
uvicorn app.main:app --reload
```

Open <http://localhost:8000>. Run API tests with:

```powershell
python -m pytest -q
```

## Deployment

The customer console deploys from `main` through `.github/workflows/pages.yml`.
The intelligence control plane is in `worker/` and deploys with:

```powershell
cd worker
npm install
npx wrangler deploy
```

Both components operate within free GitHub Pages, Cloudflare Workers, and D1
allocations for normal showcase traffic.

## Responsible operation

Use CLADS only with networks and systems you own or are authorized to assess.
Keep active enforcement behind operator approval, rollback controls, and audited
policies.

## License

MIT
