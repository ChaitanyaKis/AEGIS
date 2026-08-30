# AEGIS Control Center

A read-and-drive dashboard for the AEGIS governed control plane. React 19, TypeScript,
Vite 8, Tailwind 4, React Router 6.

It is a **viewer**. It submits an incident and renders what the control plane decided. It
holds no authority of its own: there is no call in `src/api/client.ts` that approves a
plan, grants a capability, or executes anything, because the service exposes none. The
"simulated human" selector on the incident page sends one bounded boolean that the
approval engine consumes — the approval engine still decides whether approval was required
at all.

## Running it

The dashboard needs the AEGIS service. From the repository root:

```bash
python run_service.py            # listens on http://0.0.0.0:8080
```

Then, in `frontend/`:

```bash
npm install
npm run dev                      # http://localhost:5173
```

Vite proxies `/api/*` to the service, stripping the prefix, so the browser calls
`/api/health` and the service sees `/health`. The prefix exists so the SPA's own routes
(`/overview`, `/incidents`, …) stay reachable — a proxy mounted at `/` would send every
page load to Python instead of to React.

Point it somewhere else with either:

```bash
AEGIS_ORIGIN=http://127.0.0.1:9090 npm run dev   # dev proxy target
VITE_API_BASE=https://aegis-xyz.run.app npm run build   # baked into the bundle
```

`VITE_API_BASE` is what a deployed build needs, since the dev proxy does not exist in
production. The service sends no CORS headers, so a cross-origin deployment needs a
reverse proxy in front of both — or `VITE_API_BASE` pointed at a path the same origin
serves.

## Scripts

| | |
|---|---|
| `npm run dev` | Dev server with the `/api` proxy and HMR |
| `npm run build` | `tsc -b` then `vite build` into `dist/` |
| `npm run lint` | oxlint |
| `npm run preview` | Serve `dist/` — **no proxy**, so set `VITE_API_BASE` before building |

## Pages

| Route | What it shows |
|---|---|
| `/overview` | Service posture, execution mode, declared resources, operational limits, and the pipeline the control plane enforces |
| `/incidents` | Submit an incident; render the result as the chain of boundaries it passed through |
| `/governance` | Proposal authority, delegation matrix and Commander tools, projected from `/health` |
| `/fleet` | Each agent's delegation edges and proposal authority, derived from the same document |

## The enforcement chain

`src/components/GovernanceChain.tsx` is the view the rest of the dashboard exists to
support. It draws **every** stage — untrusted input, reasoning, investigation, delegation,
policy, approval, gate, execution, verification, audit — including the ones a run never
reached, dashed and dimmed.

That is deliberate. A refused approval that simply omitted an "Execution" card would look
like a shorter run; drawing it as `NOT REACHED` is the difference between showing a result
and showing an enforcement boundary. Try the same incident twice with the approval
selector on Approve and then on Refuse and compare.

Nothing in that component computes a verdict. Every colour is read off a field the control
plane already decided.

## Honest limits

- **The enterprise behind it is simulated.** Every resource, deployment, metric and
  mutation is synthetic and deterministic. The dashboard says so on every page that can
  cause one, because the service says so in its own payloads.
- **No live provider is configured by default.** Live mode needs both an operator opt-in
  and credentials; when either is missing the service answers `409` and the dashboard
  reports it as a refusal rather than quietly running deterministically.
- **The fleet page is derived, not registered.** The service exposes delegation edges and
  proposal authority, not per-agent registration documents — so owner, department, version
  and lifecycle status are not shown. That page says so rather than inventing them.
- **There is no history.** Each run is displayed and discarded; the service keeps no
  incident store to page through.
- **`react-router-dom` 6 carries two moderate advisories** (SSR hydration and open redirect
  via `<Link>`). This is a client-only SPA with hard-coded link targets and no SSR, so
  neither path is reachable here. Fixing them means a major upgrade to v7.
