# AGENTS.md

## Project layout

Two independent apps — no monorepo tooling, no shared workspace.

```
frontend/   React 18 + TypeScript + Vite 6 + Tailwind CSS v4
backend/    Python FastAPI + WebSocket + Scapy decision engine
```

Backend pipeline apps live under `backend/app/` (ingest, features, rules, ML,
decision, realtime WS). Utility scripts split into two dirs:
- `backend/scripts/` — Python tools (train_models.py, replay_pcap.py, run_sensor.py).
- `backend/app/scripts/` — shell scripts (run-sensor.sh, setup-wireguard.sh, setup-vm-lab.sh).

## Commands

All frontend commands run from `frontend/`:

```sh
cd frontend
npm run dev        # Vite dev server on :5173, proxies /api and /ws to :8000
npm run build      # tsc -b && vite build
npm run lint       # eslint . (flat config: eslint.config.mjs)
npm run test       # playwright test (Chromium only, auto-starts dev server)
npm run test:report
```

Backend (from `backend/`):

```sh
python app/main.py                       # dev server on 0.0.0.0:8000
PYTHONPATH=$PWD python -m pytest tests/ -q   # 20 unit/integration tests
```

Backend deps must be pip-installed manually — there is no `requirements.txt`
at the root `backend/`; install from a venv (fastapi, uvicorn, scapy,
pydantic, aiosqlite, pytest, pytest-asyncio, httpx).

## Key architecture facts

- Frontend pages are wired to the backend through `src/lib/api.ts` (typed
  client) + `src/store/engine.ts` (zustand `useEngine` store: `gotData` flag,
  `error` set when every poll endpoint fails, plus **real-time toasts** and
  per-source **ACTIVE/STOPPED attack tracking** fed by `/ws/alerts`) and a sync
  hook in `src/hooks/useEngineSync.tsx` (5s polling + `/ws` for metrics +
  `/ws/alerts` for bare alert broadcasts, 2s source-activity tick, reconnect,
  mounted in `AppFrame`). New detections raise a slide-in toast popup
  (click → investigation) and a separate "Attack ended" toast fires ~20s after
  a source stops sending. Alert delivery: while a flood keeps hitting the same
  (dst, proto, threat, severity) the backend **merges** into the existing
  alert and re-broadcasts a ~2s live pulse (`AlertManager._pulse`) so the UI's
  aggregation counts/timestamp keep updating; the frontend **upserts** already-
  seen alert ids instead of ignoring them. The 5s poll baselines existing
  alerts once and afterwards toasts genuinely-new ids it discovers (WS-failure
  fallback). `GET /api/v1/alerts` returns live-session alerts only (never the
  full DB history) so floods can't bias the window. Backend timestamps are naive
  UTC — `parseApiTs` in `api.ts` appends `Z` so `timeAgo`/`formatTs` show real
  ages (`4h` bug was naive timestamps parsed as local). The Overview trend keeps
  24 × 5s samples (≈2 min) so the chart never gaps like the old 5-minute window.
- Routes (6, `createBrowserRouter`): `/` Overview, `/alerts`, `/traffic`,
  `/engine`, `/about`, `/investigation/:id`. Sidebar lists these 5 pages
  (alerts item carries a live open-count badge) plus a collapse toggle.
  TopBar shows live counters (flow rate, active flows, alerts, open/critical)
  and a Refresh button. `ConnectivityBanner` in AppFrame surfaces
  `error`/no-data as an explicit amber banner (never a silent blank page).
- Shared threat/severity meta lives in `src/lib/threats.ts`
  (`SEVERITY` colors + `threatMeta` blurbs); `src/components/alerts/`
  holds `SeverityBadge`, `ThreatBadge`, `AlertRow`/`FlowPair`, `EmptyState`.
  `src/components/ui/StatCard.tsx` is the KPI card. Pages: Overview uses
  recharts (trend area + threat donut), Alerts has search + severity/threat
  selects + status tabs, Traffic renders the live flow table with TCP-flag
  and periodicity columns, Investigation fetches the alert by id and shows
  features + score_breakdown + advisory actions.
- Vite proxy: `/api` -> `http://localhost:8000` (changeOrigin), `/ws` ->
  `ws://localhost:8000` (ws: true).
- Path alias: `@/*` maps to `src/*` (tsconfig `baseUrl: "."`).
- Tailwind v4 configured via Vite plugin — no `tailwind.config.*` file.
- The legacy standalone HTML dashboard (`backend/mirror/`) was removed and
  replaced by the FastAPI pipeline under `backend/app/`; frontend is
  exclusively the React app in `frontend/`.
- Backend ingest channels all feed one pipeline: `POST /traffic/flow` + `/flows`
  (sensor/pcap replay), live Scapy capture (`ingestion/scapy*.py`), and the UDP
  flow-export listener (`ingestion/flow_export_listener.py`, port 2055) parsing
  NetFlow v5/v9, IPFIX v10, and sFlow (`ingestion/netflow.py`).
- Runtime websocket events: `/ws` emits `{type:"metrics"|"engine_state", data}`
  envelopes plus `hello`/`pong`; `/ws/alerts` broadcasts bare alert payloads
  (no envelope) identifiable by an `alert_id` key.

## Testing

- Playwright E2E — 17 tests across 5 spec files in `frontend/tests/`
  (`navigation`, `dashboard`, `alerts`, `traffic`, `investigation`).
  Specs are written against the live network-SOC UI with tolerant empty-state
  fallbacks (`.or()` matchers) so they pass with the backend either up or down.
- Chromium only, 1440x900 viewport, `trace: retain-on-failure`.
- `webServer` config auto-runs `npm run dev` before tests (backend must be
  running on :8000 for live data assertions).
- Test helper: `tests/_helpers.ts` exports `attachFullPage()` for screenshots.
- Backend tests: `backend/tests/` — 20 passing (`pytest -q`), asyncio via
  `pytest-asyncio` auto mode; `conftest.py` uses a temp SQLite DB.

## TypeScript / Linting

- `strict: true` in tsconfig, but `noUnusedLocals` and `noUnusedParameters`
  are **off** (TS build tolerates unused vars; ESLint still flags them).
- ESLint 9 flat config at `eslint.config.mjs` (typescript-eslint +
  react-hooks recommended-latest + react-refresh). `npm run lint` is clean
  (0 errors; one known warning for the hook/component export in
  `useEngineSync.tsx`).

## Style conventions

- Tailwind utility classes inline — no CSS modules, no styled-components.
- Custom CSS in `src/index.css` uses `@theme` directives and custom utility
  classes (`glass-panel`, `accent-gradient`, `live-source`, etc.).
- Components in `src/components/` (UI primitives in `ui/`, layout in
  `layout/`, alert widgets in `alerts/`, brand in `brand/`), pages in
  `src/pages/`.
- Router uses `react-router-dom` v7 `createBrowserRouter`.
- Shared threat/severity meta lives in `src/lib/threats.ts`; format helpers
  in `src/lib/api.ts` (`humanThreatType`, `formatBytes`, `formatNumber`,
  `formatTs`, `timeAgo`).

## Gotchas

- `dedup_window_sec` is 300: re-sending the same (dst, proto, threat,
  severity) within 5 min merges into the old alert (live WS pulse, no new id),
  so a fresh sim to the same victim won't emit a new alert/toast until the
  window lapses — restart the backend (or use a new scenario/target) for clean
  demos.
- No root `.gitignore` — only `frontend/.gitignore` exists (`dist/` and
  `node_modules/` are ignored).
- No CI workflows, no pre-commit hooks.
- Legacy SOC-product UI (`src/components/soc/`, `src/components/dashboard/`,
  `src/data/soc.ts`, `src/theme.ts`, old pages like Reports/Settings/AI) was
  **removed** in the frontend rewrite — do NOT re-add it as live-pages.
- UniShield AI is a **read-only analyzer**: no Block/Isolate/mitigation
  buttons in the frontend; "Recommended Actions" are advisory only.
- Backend `FlowRecord` only carries cyber fields via optional metadata
  (`dns_qname`, `tls_ja3`); the numeric ML vector is fixed at
  `FEATURE_COLUMNS` (20) — new features go through rules/evidence, not the
  vector.
- WireGuard: Laptop 1 server `/etc/wireguard/wg0.conf` (tunnel net
  `172.16.250.0/24`, server `172.16.250.1`, server pubkey
  `D2xtJpoZVuM8unhjrgFXu5NBh1eNtfpgiCvuX0CIYwo=`); Laptop 2 Windows client
  pubkey `gGC6ZZAajuFyhLrP/3VAKuFysu7C4QNcULYuGxPHwzw=` (peer `.2`, importable
  config `docs/wireguard/laptop2-windows.conf`). Endpoints `171.79.55.84:51820`
  (public, dynamic) / `10.21.21.131:51820` (LAN). After a machine reset
  regenerate with `backend/app/scripts/setup-wireguard.sh server` + a fresh
  client keypair; demo steps in `docs/Presentation-Steps.md`.