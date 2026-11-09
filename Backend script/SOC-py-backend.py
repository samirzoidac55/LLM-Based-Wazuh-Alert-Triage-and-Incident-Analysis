"""
LLM-Based Wazuh Alert Triage and Incident Analysis — Wazuh → Ollama → WebSocket bridge.

Pipeline:
  Wazuh (UDP JSON)  →  triage + simulated IP block  →  broadcast "alert" to UI
                    →  LLM analysis queue (llama3)  →  broadcast "analysis" update

The UI sees every alert the moment it arrives (analysis_status: "analyzing"),
then receives a second message when the LLM verdict is ready. New clients get
a replay of recent alerts on connect.
"""

import asyncio
import json
import logging
import os
import re
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

import ollama
import websockets

# ── Configuration (override via environment) ─────────────────
UDP_HOST      = os.getenv("SOC_UDP_HOST", "0.0.0.0")
UDP_PORT      = int(os.getenv("SOC_UDP_PORT", "5140"))     # Wazuh forwards alerts here
WS_HOST       = os.getenv("SOC_WS_HOST", "0.0.0.0")
WS_PORT       = int(os.getenv("SOC_WS_PORT", "8765"))      # React UI connects here
MODEL         = os.getenv("SOC_MODEL", "llama3")
MIN_LEVEL     = int(os.getenv("SOC_MIN_LEVEL", "1"))       # ignore alerts below this level
BLOCK_LEVEL   = int(os.getenv("SOC_BLOCK_LEVEL", "6"))     # simulate-block source IPs at/above this level
HISTORY_SIZE  = int(os.getenv("SOC_HISTORY_SIZE", "200"))  # alerts replayed to newly connected UIs
LLM_WORKERS   = int(os.getenv("SOC_LLM_WORKERS", "1"))     # concurrent Ollama requests
BLOCKED_FILE  = Path(__file__).parent / "blocked_ips.txt"  # simulated blocklist file
CONTEXT_FILE  = Path(__file__).parent / os.getenv("SOC_CONTEXT_FILE", "business_context.txt")
# ─────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("soc-bridge")

connected_clients: set = set()
history: deque = deque(maxlen=HISTORY_SIZE)   # alert records, oldest → newest
blocked_ips: set = set()                      # session blocklist (avoids duplicate writes)
analysis_queue: asyncio.Queue = asyncio.Queue()


# ── Severity helpers ──────────────────────────────────────────
def severity_of(level: int) -> str:
    if level >= 12: return "critical"
    if level >= 9:  return "high"
    if level >= 6:  return "medium"
    return "low"


SEVERITY_CONTEXT = {
    "critical": "This represents an active, severe threat requiring instant response.",
    "high":     "This indicates a serious security incident requiring prompt investigation.",
    "medium":   "This warrants attention and monitoring for escalation.",
    "low":      "This is normal activity that requires only standard monitoring.",
}


# ── Simulated IP blocker ──────────────────────────────────────
def block_ip(record: dict) -> bool:
    """Append the source IP to the simulated blocklist. Returns True if blocked."""
    ip = record["src_ip"]
    if not ip or ip == "Unknown":
        return False
    if ip == record["agent_ip"]:
        # The "source" is the monitored host itself (rootkit, ransomware, local
        # privilege escalation). Blocking our own server would be self-harm.
        log.info("   ⛔ %s is the agent's own IP — containment needed, not a block", ip)
        return False
    if ip in blocked_ips:
        log.info("   🚫 %s already on the blocklist", ip)
        return True
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(BLOCKED_FILE, "a") as f:
            f.write(f"{timestamp} | IP: {ip} | Level: {record['level']} | Reason: {record['rule_desc']}\n")
        blocked_ips.add(ip)
        log.info("   🚫 %s written to %s", ip, BLOCKED_FILE.name)
        return True
    except OSError as e:
        log.error("   ❌ Failed to write blocked IP: %s", e)
        return False


# ── Alert parsing ─────────────────────────────────────────────
def _first(*vals, default=None):
    """Return the first non-empty value."""
    for v in vals:
        if v not in (None, "", [], {}, "N/A"):
            return v
    return default


def extract_details(alert: dict) -> dict:
    """Pull the forensically interesting fields out of an alert, handling both
    plain Wazuh data and Windows audit shapes (data.win.eventdata)."""
    data = alert.get("data", {}) or {}
    win  = data.get("win", {}) if isinstance(data.get("win"), dict) else {}
    ed   = win.get("eventdata", {}) if isinstance(win.get("eventdata"), dict) else {}
    details = {
        "user":           _first(data.get("user"), data.get("dstuser"), ed.get("subjectUserName")),
        "process":        _first(data.get("process"), ed.get("newProcessName"), ed.get("image")),
        "command_line":   _first(data.get("command"), ed.get("commandLine")),
        "parent_process": _first(ed.get("parentProcessName"), ed.get("parentImage")),
        "target_file":    _first(data.get("file"), ed.get("targetFilename"), ed.get("objectName")),
        "dest_ip":        _first(data.get("dstip"), ed.get("destinationIp")),
        "dest_port":      _first(data.get("dstport"), ed.get("destinationPort")),
        "url":            data.get("url"),
    }
    return {k: v for k, v in details.items() if v}


def build_record(alert: dict) -> dict:
    """Normalize a raw Wazuh alert into the record broadcast to the UI."""
    rule  = alert.get("rule", {}) or {}
    agent = alert.get("agent", {}) or {}
    data  = alert.get("data", {}) or {}
    win   = data.get("win", {}) if isinstance(data.get("win"), dict) else {}
    ed    = win.get("eventdata", {}) if isinstance(win.get("eventdata"), dict) else {}
    mitre = rule.get("mitre", {}) if isinstance(rule.get("mitre"), dict) else {}
    level = int(rule.get("level", 0) or 0)
    return {
        "id":              uuid.uuid4().hex,
        "received_at":     datetime.now(timezone.utc).isoformat(),
        "event_time":      _first(alert.get("timestamp"), alert.get("@timestamp")),
        "rule_id":         rule.get("id"),
        "rule_desc":       rule.get("description", "Unknown Alert"),
        "groups":          rule.get("groups", []),
        "rule_mitre_ids":  mitre.get("id", []) if isinstance(mitre.get("id"), list) else [],
        "level":           level,
        "severity":        severity_of(level),
        "src_ip":          _first(data.get("srcip"), ed.get("sourceIp"), agent.get("ip"), default="Unknown"),
        "agent_name":      agent.get("name", "Unknown"),
        "agent_ip":        agent.get("ip", "Unknown"),
        "location":        alert.get("location"),
        "details":         extract_details(alert),
        "data":            data,
        "blocked":         False,
        "analysis_status": "analyzing",
        "analysis":        None,
        "model":           MODEL,
    }


# ── LLM analysis ──────────────────────────────────────────────
def resolve_model(name: str) -> str:
    """Match the configured model against what Ollama actually has installed.

    'llama3' resolves to e.g. 'llama3:8b-instruct-q4_K_M' when no ':latest'
    tag exists, so the bridge works regardless of which quantization was pulled.
    """
    try:
        listing = ollama.list()
        models = getattr(listing, "models", None) or listing.get("models", [])
        names = [getattr(m, "model", None) or m.get("model") or m.get("name") for m in models]
        names = [n for n in names if n]
    except Exception as e:
        log.warning("Could not list Ollama models (%s) — is Ollama running?", e)
        return name
    if name in names or f"{name}:latest" in names:
        return name
    prefixed = [n for n in names if n.startswith(f"{name}:")]
    if prefixed:
        log.info("Model '%s' not found; using '%s'", name, prefixed[0])
        return prefixed[0]
    log.warning("Model '%s' not installed in Ollama (available: %s)", name, ", ".join(names) or "none")
    return name



ANALYSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {
            "type": "string",
            "enum": ["escalate", "investigate", "monitor", "routine"],
        },
        "summary":                   {"type": "string"},
        "risk":                      {"type": "string"},
        "false_positive_likelihood": {"type": "string", "enum": ["low", "medium", "high"]},
        "recommended_actions":       {"type": "array", "items": {"type": "string"}},
        "mitre_techniques":          {"type": "array", "items": {"type": "string"}},
    },
    "required": [
        "verdict", "summary", "risk",
        "false_positive_likelihood", "recommended_actions", "mitre_techniques",
    ],
}


def load_business_context() -> str:
    """The business context document teaches the model what is normal vs
    hostile on the monitored hosts — the difference between an analyst who
    knows the environment and one who alerts on everything."""
    try:
        return CONTEXT_FILE.read_text().strip()
    except OSError:
        return ""


BUSINESS_CONTEXT = ""  # loaded once at startup


def build_prompt(record: dict) -> str:
    severity = record["severity"]
    block_note = (
        "The source IP has ALREADY been automatically blocked — say so; do NOT recommend blocking it."
        if record["blocked"]
        else f"No automatic block was applied (threshold is level {BLOCK_LEVEL}+, external IPs only)."
    )
    context_block = (
        f"═══ BUSINESS CONTEXT (what is normal vs hostile in this environment) ═══\n"
        f"{BUSINESS_CONTEXT}\n\n"
        if BUSINESS_CONTEXT else ""
    )
    details = record["details"] or {}
    detail_lines = "\n".join(f"- {k}: {str(v)[:220]}" for k, v in details.items())
    mitre_hint = (
        f"Wazuh rule MITRE hint: {', '.join(record['rule_mitre_ids'])}\n"
        if record["rule_mitre_ids"] else ""
    )
    return (
        "You are a tier-2 SOC analyst with 5 years of experience. "
        "Analyze this Wazuh security event with precision and professionalism. "
        "Reason only from the evidence provided.\n\n"
        f"{context_block}"
        "═══ ALERT ═══\n"
        f"Severity: level {record['level']}/15 — {severity.upper()}. {SEVERITY_CONTEXT[severity]}\n"
        f"Rule {record['rule_id']}: {record['rule_desc']}\n"
        f"Rule groups: {', '.join(record['groups']) or 'none'}\n"
        f"{mitre_hint}"
        f"Source IP: {record['src_ip']}\n"
        f"Affected system: {record['agent_name']} ({record['agent_ip']})\n"
        f"Log source: {record['location'] or 'unknown'}\n"
        + (f"Extracted evidence:\n{detail_lines}\n" if detail_lines
           else f"Event data: {json.dumps(record['data'])[:600]}\n")
        + f"Response status: {block_note}\n\n"
        "═══ RESPOND WITH JSON ═══\n"
        "- verdict: 'escalate' (critical, active compromise), 'investigate' (serious, needs an analyst), "
        "'monitor' (watch for escalation), or 'routine' (expected activity)\n"
        "- summary: 1 sentence stating exactly what occurred. Distinguish successful actions "
        "(logins, privilege escalations) from failed attempts (brute force, rejected connections).\n"
        "- risk: 1-2 sentences on risk and potential impact, matched to the severity level. "
        "Low-level alerts are NOT 'concerning' or 'suspicious'.\n"
        "- false_positive_likelihood: 'low', 'medium', or 'high'\n"
        "- recommended_actions: 1-3 short, specific, actionable steps. For routine activity a single "
        "'Continue routine monitoring' is enough. Never recommend blocking for level 1-5 alerts "
        "unless there is concrete evidence of compromise.\n"
        "- mitre_techniques: MITRE ATT&CK techniques that plausibly map to this event, as "
        "'T1110 — Brute Force' style strings. Empty array if none apply. Do not guess exotic IDs.\n\n"
        "Be direct and actionable. Avoid hedge words like 'might' or 'possibly' for high-severity alerts. "
        + ("If the business context marks this activity as normal for this host/user, say so and lower "
           "the verdict accordingly (raise false_positive_likelihood); if it marks it hostile, escalate. "
           if BUSINESS_CONTEXT else "")
        + "No meta-commentary — just the analysis."
    )


# ── LLM JSON repair (small quantized models emit imperfect JSON) ──
def _repair_unescaped_backslashes(text: str) -> str:
    r"""Double up backslashes that aren't valid JSON escapes (\Windows → \\Windows)."""
    valid_escapes = set('"\\/bfnrtu')
    out, i = [], 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text) and text[i + 1] not in valid_escapes:
            out.append("\\\\")
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _strip_trailing_comma(text: str) -> str:
    text = re.sub(r",(\s*})", r"\1", text)
    text = re.sub(r",(\s*\])", r"\1", text)
    return text


def parse_llm_json(text: str) -> dict:
    """Strict parse, then progressively repair the common failure modes,
    then fall back to extracting the outermost JSON object."""
    attempts = (
        lambda s: s,
        _strip_trailing_comma,
        _repair_unescaped_backslashes,
        lambda s: _strip_trailing_comma(_repair_unescaped_backslashes(s)),
    )
    last_err = None
    for repair in attempts:
        try:
            return json.loads(repair(text))
        except json.JSONDecodeError as e:
            last_err = e
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        try:
            return json.loads(_strip_trailing_comma(_repair_unescaped_backslashes(m.group(0))))
        except json.JSONDecodeError:
            pass
    raise last_err


def analyze(record: dict) -> dict:
    """Blocking Ollama call. Runs in a worker thread via asyncio.to_thread."""
    response = ollama.chat(
        model=MODEL,
        messages=[{"role": "user", "content": build_prompt(record)}],
        format=ANALYSIS_SCHEMA,
        options={"temperature": 0.2},
    )
    raw = response["message"]["content"]
    try:
        analysis = parse_llm_json(raw)
    except json.JSONDecodeError:
        # Unrepairable output — degrade gracefully to a plain-text summary.
        analysis = {
            "verdict": "investigate",
            "summary": raw.strip(),
            "risk": "",
            "false_positive_likelihood": "medium",
            "recommended_actions": [],
            "mitre_techniques": [],
        }
    return analysis


async def analysis_worker(worker_id: int):
    while True:
        record = await analysis_queue.get()
        started = time.monotonic()
        try:
            analysis = await asyncio.to_thread(analyze, record)
            elapsed_ms = int((time.monotonic() - started) * 1000)
            record["analysis"] = analysis
            record["analysis_status"] = "complete"
            record["analysis_ms"] = elapsed_ms
            log.info("   🧠 [%s] %s (%.1fs): %s", record["src_ip"], analysis["verdict"],
                     elapsed_ms / 1000, analysis["summary"][:80])
            await broadcast({
                "type": "analysis",
                "id": record["id"],
                "status": "complete",
                "analysis": analysis,
                "analysis_ms": elapsed_ms,
            })
        except Exception as e:
            record["analysis_status"] = "error"
            record["analysis_error"] = str(e)
            log.error("   ❌ LLM analysis failed (worker %d): %s", worker_id, e)
            await broadcast({
                "type": "analysis",
                "id": record["id"],
                "status": "error",
                "error": f"{type(e).__name__}: {e}",
            })
        finally:
            analysis_queue.task_done()


# ── WebSocket server ──────────────────────────────────────────
async def ws_handler(websocket):
    log.info("🖥️  UI connected from %s", websocket.remote_address)
    connected_clients.add(websocket)
    try:
        await websocket.send(json.dumps({
            "type": "hello",
            "model": MODEL,
            "block_level": BLOCK_LEVEL,
            "min_level": MIN_LEVEL,
        }))
        await websocket.send(json.dumps({
            "type": "history",
            "alerts": list(history),
        }))
        await websocket.wait_closed()
    finally:
        connected_clients.discard(websocket)
        log.info("🖥️  UI disconnected")


async def broadcast(payload: dict):
    if not connected_clients:
        return
    msg = json.dumps(payload)
    await asyncio.gather(
        *[c.send(msg) for c in connected_clients],
        return_exceptions=True,
    )


# ── UDP listener (native asyncio, no threads) ─────────────────
class WazuhUDPProtocol(asyncio.DatagramProtocol):
    def datagram_received(self, data, addr):
        try:
            raw = data.decode("utf-8", errors="replace")
            json_start = raw.find("{")
            if json_start == -1:
                log.warning("📨 Packet from %s has no JSON, skipping", addr)
                return
            alert = json.loads(raw[json_start:])
        except json.JSONDecodeError as e:
            log.warning("📨 JSON parse error from %s: %s", addr, e)
            return
        asyncio.get_running_loop().create_task(handle_alert(alert))

    def error_received(self, exc):
        log.error("📡 UDP error: %s", exc)


async def handle_alert(alert: dict):
    record = build_record(alert)
    log.info("📋 [%d/%s] %s | src: %s", record["level"], record["severity"],
             record["rule_desc"], record["src_ip"])

    if record["level"] < MIN_LEVEL:
        log.info("   ⏭️  Below minimum level %d, skipping", MIN_LEVEL)
        return

    if record["level"] >= BLOCK_LEVEL:
        record["blocked"] = block_ip(record)

    # Phase 1: the UI sees the alert immediately, marked "analyzing".
    history.append(record)
    await broadcast({"type": "alert", "alert": record})

    # Phase 2: queue for LLM analysis; the verdict is broadcast when ready.
    await analysis_queue.put(record)


# ── Main ──────────────────────────────────────────────────────
async def main():
    global MODEL, BUSINESS_CONTEXT
    loop = asyncio.get_running_loop()
    MODEL = resolve_model(MODEL)
    BUSINESS_CONTEXT = load_business_context()
    if BUSINESS_CONTEXT:
        log.info("📖 Business context loaded from %s (%d chars)", CONTEXT_FILE.name, len(BUSINESS_CONTEXT))
    else:
        log.info("📖 No business context file (%s) — triaging without environment knowledge", CONTEXT_FILE.name)

    transport, _ = await loop.create_datagram_endpoint(
        WazuhUDPProtocol, local_addr=(UDP_HOST, UDP_PORT)
    )
    log.info("📡 Listening for Wazuh alerts on UDP %s:%d", UDP_HOST, UDP_PORT)

    workers = [asyncio.create_task(analysis_worker(i)) for i in range(max(1, LLM_WORKERS))]
    log.info("🧠 %d LLM worker(s) ready — model: %s", len(workers), MODEL)

    try:
        async with websockets.serve(ws_handler, WS_HOST, WS_PORT):
            log.info("🌐 WebSocket server on ws://%s:%d", WS_HOST, WS_PORT)
            await asyncio.Future()  # run forever
    finally:
        transport.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("👋 Bridge stopped")
