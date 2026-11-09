# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

LLM-Based Wazuh Alert Triage and Incident Analysis: an LLM-powered SOC (Security Operations Center) analyst. Wazuh security alerts are triaged in real time by a local LLM (llama3 via Ollama) and streamed to a React dashboard.

Data flow (two-phase):

```
Wazuh (or send_alerts.py simulator)
  → UDP :5140 → Backend script/SOC-py-backend.py
      → phase 1: alert broadcast to UI immediately (analysis_status: "analyzing")
      → simulated block: external src IPs at level >= 6 appended to blocked_ips.txt
      → phase 2: llama3 verdict (JSON-schema constrained) broadcast when inference completes
  → WebSocket :8765 → React dashboard (src/)
```

## Commands

Frontend (Vite + React 19 + Tailwind 3):

```bash
npm run dev        # dev server (localhost:5173)
npm run build      # production build
npm run lint       # eslint (react-hooks rules are strict: no impure calls in render)
```

Backend (Python, requires `ollama` and `websockets` packages, plus Ollama running locally):

```bash
cd "Backend script"
python3 SOC-py-backend.py                            # real-time bridge: UDP + LLM workers + WebSocket
python3 SOC-batch-analyst.py dataset/mimikatz.json   # batch mode: one-shot incident report over a dataset
python3 send_alerts.py                               # simulator: replays alerts.json over UDP
python3 send_alerts.py --file dataset/lsass.json --delay 2   # replay a labeled attack capture
```

Bridge config is via `SOC_*` env vars (see the config block at the top of SOC-py-backend.py). There are no tests.

## Architecture Notes

- **`Backend script/SOC-py-backend.py`** is the core, fully asyncio (no threads): a `DatagramProtocol` receives Wazuh JSON, `handle_alert` normalizes it into a record and broadcasts it instantly, then LLM worker task(s) consume an `asyncio.Queue` and broadcast the verdict as a follow-up message. Ollama is called with `format=ANALYSIS_SCHEMA` (JSON schema) so llama3 returns structured verdicts: `{verdict, summary, risk, false_positive_likelihood, recommended_actions, mitre_techniques}`. `resolve_model()` matches the configured model name against installed Ollama tags at startup (e.g. `llama3` → `llama3:8b-instruct-q4_K_M`).
- **WebSocket protocol** (bridge → UI): `hello` (model + thresholds), `history` (replay of recent alerts on connect, deque of 200), `alert` (phase 1), `analysis` (phase 2, matched to the alert by `id`). The `blocked` flag and `severity` string are computed server-side — the frontend never re-derives blocking, so thresholds live only in Python.
- **Blocking is simulated**: level >= `BLOCK_LEVEL` (6) appends to `blocked_ips.txt`, deduplicated per session, and never blocks the agent's own IP (self-source alerts like rootkits get `blocked: false`).
- **Frontend structure**: `src/SOCDashboard.jsx` composes `components/` (StatusBar, ConnectionPanel, ReadoutStrip, AlertRow + AnalysisPanel, SideRail). `src/hooks/useSocket.js` owns the WebSocket with auto-reconnect (exponential backoff, capped 15s, only while the user wants a connection) and a reducer that merges history/alert/analysis messages by id. `src/lib/severity.js` holds severity/verdict vocabularies as full literal Tailwind class strings (required for Tailwind's scanner).
- **Design system** (tailwind.config.js): `void/panel/raise/line` base colors, `signal` (teal) = the system acting (live, auto-block), `ai` (violet) = the LLM speaking, `sev.*` = severity data only. Fonts: Rajdhani (display), IBM Plex Sans (body), JetBrains Mono (data) — loaded in index.html, applied via Tailwind font utilities.
- **`Backend script/SOC-batch-analyst.py`** is the second analysis mode (the dataset evaluation harness): loads a whole dataset, normalizes Sysmon/Windows-audit shapes, categorizes events by kill-chain stage, and produces one grounded incident report per run (broadcast as a `batch_analysis` message, rendered by `src/components/IncidentReport.jsx`). Its distinctive techniques: telemetry-inventory grounding rules + post-hoc IOC sanitization against hallucination, and a progressive LLM JSON repair parser (also ported into the bridge as `parse_llm_json`). It binds the same WS port as the bridge — run one at a time.
- **`Backend script/business_context.txt`** describes what's normal vs hostile per host; both backends inject it into their prompts (bridge: `SOC_CONTEXT_FILE` env var). Deleting it degrades gracefully.
- **`Backend script/dataset/`**: labeled Wazuh+Sysmon captures from a Windows lab (mimikatz, lsass, ps_enco, iwr, benign, baseline_idle), OpenSearch export format (`hits.hits[]._source`) — `send_alerts.py` unwraps this shape automatically.
- **`Backend script/alerts.json`**: 20 sample Wazuh-format alerts across the severity range for demos.
