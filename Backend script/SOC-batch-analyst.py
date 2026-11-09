"""LLM-Based Wazuh Alert Triage and Incident Analysis batch incident analysis.

Analyzes a whole dataset window in one LLM pass and broadcasts a full
incident report to the dashboard. Usage:

    python3 SOC-batch-analyst.py [dataset/mimikatz.json]
"""
import json
import asyncio
import ollama
import websockets
import re
import sys
import time
from datetime import datetime

# ══════════════════════════════════════════════
# CONFIGURATION - SIMULATION MODE
# ══════════════════════════════════════════════
WS_HOST = "0.0.0.0"
WS_PORT = 8765
MODEL = "llama3:8b-instruct-q4_K_M"
DATASET_FILE = sys.argv[1] if len(sys.argv) > 1 else "dataset/benign.json"
BLOCKED_IPS_FILE = "blocked_ips.txt"
CONTEXT_DOCUMENT = "business_context.txt"

# Global State
connected_clients = set()
processing_times = []

# ══════════════════════════════════════════════
# WEBSOCKET SERVER
# ══════════════════════════════════════════════
async def ws_handler(websocket):
    print(f"  UI connected from {websocket.remote_address}")
    connected_clients.add(websocket)
    try:
        await websocket.wait_closed()
    finally:
        connected_clients.discard(websocket)
        print("  UI disconnected")

async def broadcast(payload: dict):
    if not connected_clients:
        print("  No connected clients to broadcast to")
        return
    msg = json.dumps(payload)
    disconnected = set()
    for client in connected_clients:
        try:
            await client.send(msg)
            print(f"   Sent to {client.remote_address}")
        except websockets.exceptions.ConnectionClosed:
            disconnected.add(client)
    for client in disconnected:
        connected_clients.discard(client)

# ══════════════════════════════════════════════
# SIMULATED IP BLOCKING (File-Based)
# ══════════════════════════════════════════════
def block_ip_to_file(agent_id, src_ip):
    if not src_ip or src_ip in ("Unknown", "N/A", "", None):
        print(f"       Skipping invalid IP: {src_ip}")
        return False
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(BLOCKED_IPS_FILE, "a") as f:
            f.write(f"{timestamp} | Agent: {agent_id} | IP: {src_ip} | Status: BLOCKED\n")
        print(f"      IP {src_ip} blocked (logged to {BLOCKED_IPS_FILE})")
        return True
    except Exception as e:
        print(f"      Failed to log blocked IP {src_ip}: {e}")
        return False

# ══════════════════════════════════════════════
# ADAPTIVE FIELD EXTRACTION
# Works for both flat Sysmon-style alerts and nested Wazuh-style alerts.
# ══════════════════════════════════════════════
def _first(*vals, default="N/A"):
    """Return first non-empty value, else default."""
    for v in vals:
        if v not in (None, "", [], {}, "N/A"):
            return v
    return default

def normalize_alert(a: dict) -> dict:
    """Map an alert (any shape) into a flat, predictable dict."""
    rule = a.get("rule", {}) if isinstance(a.get("rule"), dict) else {}
    agent = a.get("agent", {}) if isinstance(a.get("agent"), dict) else {}
    data = a.get("data", {}) if isinstance(a.get("data"), dict) else {}
    mitre = rule.get("mitre", {}) if isinstance(rule.get("mitre"), dict) else {}
    # Windows audit-log shape (EID 4688 / 4663 / 4657) lives at data.win.eventdata
    win = data.get("win", {}) if isinstance(data.get("win"), dict) else {}
    ed  = win.get("eventdata", {}) if isinstance(win.get("eventdata"), dict) else {}
    sys_ = win.get("system", {}) if isinstance(win.get("system"), dict) else {}

    return {
        "timestamp": _first(a.get("timestamp"), default="N/A"),
        "severity": _first(a.get("severity"), rule.get("level"), default=0),
        "rule_desc": _first(a.get("rule_description"), rule.get("description"), default="Unknown"),
        "rule_id": _first(rule.get("id"), default="?"),
        "groups": rule.get("groups", []) if isinstance(rule.get("groups"), list) else [],
        "mitre_ids": _first(a.get("mitre_ids"), mitre.get("id"), default=[]) if isinstance(_first(a.get("mitre_ids"), mitre.get("id"), default=[]), list) else [],
        "host": _first(a.get("host"), agent.get("name"), default="Unknown"),
        "host_ip": _first(a.get("host_ip"), agent.get("ip"), default="N/A"),
        "user": _first(a.get("user"), data.get("user"), ed.get("subjectUserName"), default="N/A"),
        "process": _first(a.get("process"), ed.get("newProcessName"), ed.get("image"), default="N/A"),
        "command_line": _first(a.get("command_line"), data.get("command"), ed.get("commandLine"), default="N/A"),
        "parent_process": _first(a.get("parent_process"), ed.get("parentProcessName"), ed.get("parentImage"), default="N/A"),
        "parent_command": _first(a.get("parent_command"), ed.get("parentCommandLine"), default="N/A"),
        "target_file": _first(a.get("target_file"), ed.get("targetFilename"), ed.get("objectName"), default="N/A"),
        "src_ip": _first(a.get("src_ip"), data.get("srcip"), ed.get("sourceIp"), default="N/A"),
        "dest_ip": _first(a.get("destinationIp"), a.get("dest_ip"), ed.get("destinationIp"), default="N/A"),
        "dest_port": _first(a.get("destination_port"), a.get("dest_port"), ed.get("destinationPort"), default="N/A"),
        "sysmon_event_id": _first(a.get("sysmon_event_id"), sys_.get("eventID"), default="N/A"),
    }

def categorize(n: dict) -> str:
    """Return a high-level category for an event."""
    sid = str(n.get("sysmon_event_id", ""))
    desc = (n.get("rule_desc") or "").lower()
    cmd = (n.get("command_line") or "").lower()
    proc = (n.get("process") or "").lower()

    if any(k in cmd for k in ["lsass", "sekurlsa", "mimikatz", "procdump", "pypykatz",
                              "comsvcs.dll", "createdump", "nanodump", "xordump"]):
        return "credential_access"
    if sid == "3" or "network connection" in desc:
        return "network"
    if sid in ("11", "4663") or "file dropped" in desc or "file create" in desc:
        return "file_drop"
    if sid in ("13", "12", "4657") or "reg.exe" in proc or "registry" in desc or "hklm" in cmd or "hkcu" in cmd or "hkey_" in cmd:
        return "registry_persistence"
    if "powershell" in proc and "powershell" in (n.get("parent_process") or "").lower():
        return "script_chaining"
    if sid in ("1", "4688") or "command prompt" in desc or "process create" in desc or "a process was created" in desc:
        return "process_execution"
    if "syscheck" in n.get("groups", []) or "integrity" in desc:
        return "file_integrity"
    if "sudo" in n.get("groups", []) or "sudo" in desc:
        return "privilege_escalation"
    if "authentication" in " ".join(n.get("groups", [])) or "auth" in desc:
        return "authentication"
    return "other"

CATEGORY_LABELS = {
    "credential_access": "Credential Access",
    "network": "Network / Egress",
    "file_drop": "File Drop / Staging",
    "registry_persistence": "Registry & Persistence",
    "script_chaining": "Script Chaining (PS spawns PS)",
    "process_execution": "Process Execution",
    "file_integrity": "File Integrity",
    "privilege_escalation": "Privilege Escalation",
    "authentication": "Authentication",
    "other": "Other",
}

# ══════════════════════════════════════════════
# LLM JSON REPAIR
# Small quantized models occasionally emit invalid JSON. Common failures we handle:
#   1. Unescaped backslashes in Windows paths (\Windows -> \\Windows)
#   2. Trailing commas before } or ]
#   3. Unescaped double-quotes INSIDE string values (the model uses " for inline
#      quoting and forgets to escape it).
#   4. Preamble/postamble text around the JSON object.
# ══════════════════════════════════════════════
def _repair_unescaped_backslashes(text: str) -> str:
    r"""Double up backslashes that aren't followed by a valid JSON escape char."""
    valid_escapes = set('"\\/bfnrtu')
    out = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == '\\' and i + 1 < len(text):
            if text[i + 1] not in valid_escapes:
                out.append('\\\\')
                i += 1
                continue
        out.append(ch)
        i += 1
    return ''.join(out)

def _strip_trailing_comma(text: str) -> str:
    """Remove `,}` and `,]` patterns."""
    text = re.sub(r',(\s*})', r'\1', text)
    text = re.sub(r',(\s*\])', r'\1', text)
    return text

def _repair_unescaped_quotes_in_strings(text: str) -> str:
    """
    Fix the most common Mistral-Nemo quote bug: an unescaped `"` inside a JSON
    string value.

    Strategy: walk the text as a tiny parser. When inside a string value, an
    unescaped `"` is only legal if it is followed (modulo whitespace) by one of
    the JSON-structural characters: , } ] : (in some positions). If it is
    followed instead by a letter/space/punctuation, treat it as an in-string
    quote that should be escaped.
    """
    out = []
    in_string = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if not in_string:
            out.append(ch)
            if ch == '"':
                in_string = True
            i += 1
            continue
        # We're inside a string.
        if ch == '\\' and i + 1 < n:
            # Pass escape sequence through unchanged.
            out.append(ch)
            out.append(text[i + 1])
            i += 2
            continue
        if ch == '"':
            # Decide: is this the closing quote, or an unescaped inner quote?
            # Look ahead, skipping whitespace.
            j = i + 1
            while j < n and text[j] in ' \t\r\n':
                j += 1
            # Legal terminators after a closing string quote in JSON:
            if j >= n or text[j] in ',}]:':
                # Real closing quote.
                out.append(ch)
                in_string = False
                i += 1
                continue
            else:
                # Inner quote — escape it.
                out.append('\\"')
                i += 1
                continue
        out.append(ch)
        i += 1
    return ''.join(out)

def _parse_llm_json(text: str) -> dict:
    """
    Try strict parse, then progressively repair common Mistral-Nemo output errors.
    Raises json.JSONDecodeError if all attempts fail.
    """
    attempts = [
        ("strict", lambda s: s),
        ("strip-trailing-comma", _strip_trailing_comma),
        ("escape-backslashes", _repair_unescaped_backslashes),
        ("escape-inner-quotes", _repair_unescaped_quotes_in_strings),
        ("all-repairs",
         lambda s: _strip_trailing_comma(
             _repair_unescaped_quotes_in_strings(
                 _repair_unescaped_backslashes(s)))),
    ]
    last_err = None
    for label, repair in attempts:
        candidate = repair(text)
        try:
            return json.loads(candidate)
        except json.JSONDecodeError as e:
            last_err = e
            if label != "strict":
                print(f"     JSON repair attempt '{label}' failed at {e.pos}; trying next.")
            continue
    # Final fallback: extract the JSON object substring and try all repairs on it
    m = re.search(r'\{.*\}', text, re.DOTALL)
    if m:
        try:
            return json.loads(_strip_trailing_comma(
                _repair_unescaped_quotes_in_strings(
                    _repair_unescaped_backslashes(m.group(0)))))
        except json.JSONDecodeError:
            pass
    raise last_err

# ══════════════════════════════════════════════
# MISTRAL NEMO ANALYSIS
# ══════════════════════════════════════════════
async def analyze_alerts(alerts):
    start_time = time.time()
    batch_id = f"BATCH-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

    normalized = [normalize_alert(a) for a in alerts]
    try:
        normalized.sort(key=lambda x: x.get("timestamp") or "")
    except Exception:
        pass

    window_start = normalized[0]["timestamp"] if normalized else "Unknown"
    window_end = normalized[-1]["timestamp"] if normalized else "Unknown"

    print(f"\n🔬 ANALYZING {batch_id} ({len(alerts)} alerts)")

    try:
        with open(CONTEXT_DOCUMENT, "r") as f:
            business_context = f.read()
    except FileNotFoundError:
        business_context = "No business context file was found."

    cat_buckets = {k: [] for k in CATEGORY_LABELS}
    unique_dest_ips = set()
    unique_hosts = set()
    unique_users = set()
    unique_files = set()

    for n in normalized:
        cat_buckets[categorize(n)].append(n)
        if n["dest_ip"] != "N/A":
            unique_dest_ips.add(n["dest_ip"])
        if n["host"] != "Unknown":
            unique_hosts.add(n["host"])
        if n["user"] != "N/A":
            unique_users.add(n["user"])
        if n["target_file"] != "N/A":
            unique_files.add(n["target_file"])

    category_lines = ["EVENT CATEGORIZATION:"]
    for key, label in CATEGORY_LABELS.items():
        bucket = cat_buckets[key]
        if not bucket:
            continue
        category_lines.append(f"  {label}: {len(bucket)}")
    category_summary = "\n".join(category_lines)

    alert_details = []
    for i, n in enumerate(normalized, 1):
        # Build compact action description
        action = ""
        if n["command_line"] != "N/A":
            action = f"cmd: {n['command_line'][:220]}"
        elif n["target_file"] != "N/A":
            action = f"file_write: {n['target_file']}"
        elif n["dest_ip"] != "N/A":
            action = f"net→{n['dest_ip']}:{n['dest_port']}"

        # Process tree only when meaningful (parent != self, parent != generic powershell-spawning-itself)
        proc_chain = ""
        if n["parent_process"] != "N/A" and n["process"] != "N/A":
            parent_short = n["parent_process"].rsplit("\\", 1)[-1]
            proc_short = n["process"].rsplit("\\", 1)[-1]
            proc_chain = f" | {parent_short}→{proc_short}"
        elif n["process"] != "N/A":
            proc_short = n["process"].rsplit("\\", 1)[-1]
            proc_chain = f" | {proc_short}"

        # MITRE if available (the filter now passes mitre_ids through)
        mitre_str = ""
        mitre_ids = n.get("mitre_ids") if isinstance(n, dict) else None
        if mitre_ids:
            mitre_str = f" | MITRE: {','.join(mitre_ids)}"

        line1 = f"[{i:2}] {n['timestamp'][11:19]} sev{n['severity']:>2} | {n['rule_desc'][:80]}{mitre_str}{proc_chain}"
        if action:
            alert_details.append(f"{line1}\n     {action}")
        else:
            alert_details.append(line1)
    alert_text = "\n".join(alert_details)

    inventory_lines = [
        "TELEMETRY INVENTORY (only values listed below actually appear in the logs):",
        f"  • Hosts seen: {sorted(unique_hosts) or ['(none)']}",
        f"  • Users seen: {sorted(unique_users) or ['(none)']}",
        f"  • External destination IPs seen: {sorted(unique_dest_ips) or ['(none)']}",
        f"  • Files written (Sysmon EID 11): {len(unique_files)} unique paths",
    ]
    inventory = "\n".join(inventory_lines)

    prompt = f"""You are an experienced SOC analyst producing a structured triage report on the security telemetry below. Reason only from the evidence provided.

================================================
BUSINESS CONTEXT
================================================
{business_context}

================================================
TIME WINDOW: {window_start} → {window_end}
TOTAL EVENTS: {len(normalized)}
================================================

{inventory}

{category_summary}

================================================
DETAILED EVENT LOG (chronological, with process tree):
================================================
{alert_text}

================================================
ANALYSIS FRAMEWORK
================================================
Work through the evidence in this order before producing the JSON output:

1. FACTS. Use only values that appear in the TELEMETRY INVENTORY and the DETAILED EVENT LOG. Reconstruct the activity chronologically. Walk parent → child process chains.

2. PATTERN. Identify which kill-chain stage best describes the observed activity (Reconnaissance, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact). Consider the business context: which patterns it labels as hostile, benign, or ambiguous on this host.

3. MITRE. For each malicious behaviour you identify, map it to the most precise MITRE ATT&CK sub-technique you can justify from the log. Cite the specific event (command line, file write, or process chain) that supports each mapping. If you are not confident about the sub-technique, fall back to the parent technique rather than guessing the sub-number.

4. RESPONSE. Decide priority based on the four-tier scheme defined in the business context. Decide whether perimeter blocking is appropriate — only external IPs (not 10.x.x.x, 172.16-31.x.x, 192.168.x.x) that are clearly involved in malicious activity warrant a block, and only when confidence is at least 80 percent.

================================================
EXAMPLE OF A WELL-FORMED RESPONSE (DIFFERENT SCENARIO — do NOT copy any of these values; they are illustrative only)
================================================
The example below is from a Linux SSH brute-force scenario. Your input is from a Windows host, so the techniques, IOCs, and remediation in your output will be entirely different. The example shows only the expected structure, tone, and level of specificity.

{{
  "status": "Incident",
  "confidence": 90,
  "incident_title": "SSH brute-force followed by web shell deployment on public-facing API server.",
  "attack_summary": "An external IP (203.0.113.45) brute-forced SSH on api-prod-01 over a 12-minute window, ultimately authenticating as the 'deploy' user. The attacker then uploaded a PHP web shell to /var/www/html/uploads/ and executed reconnaissance commands before attempting privilege escalation via sudo.",
  "investigation_guide": [
    "Blast Radius: Confirm whether 'deploy' is reused on other internal hosts. Query: `grep 'Accepted password for deploy' /var/log/auth.log` across the fleet.",
    "Hunt Query: Search for additional dropped files in web roots. Query: `find /var/www -type f -newer /tmp/marker -name '*.php'`",
    "Next Steps: The attacker has interactive shell access; expect lateral movement via SSH key harvesting from /home/deploy/.ssh/."
  ],
  "mitre_techniques": [
    {{"id": "T1110.001", "name": "Brute Force: Password Guessing", "justification": "Hundreds of failed SSH authentications from a single external IP."}},
    {{"id": "T1505.003", "name": "Server Software Component: Web Shell", "justification": "PHP file written under a web-accessible directory after successful login."}}
  ],
  "affected_assets": ["api-prod-01"],
  "indicators_of_compromise": {{
    "ips": ["203.0.113.45"],
    "commands": ["whoami", "cat /etc/passwd"],
    "files": ["/var/www/html/uploads/shell.php"]
  }},
  "blocking_rationale": "203.0.113.45 is an external IP that brute-forced authentication and deployed a web shell — perimeter block is justified.",
  "remediation_playbook": [
    "Immediate Action: Disable the 'deploy' account and rotate credentials. Command: `sudo usermod -L deploy && sudo passwd -e deploy`",
    "Long-Term Fix: Enforce SSH key-only authentication and add fail2ban. Command: edit `/etc/ssh/sshd_config` to set `PasswordAuthentication no`."
  ],
  "priority": "Critical",
  "false_positive_likelihood": "Low"
}}

================================================
OUTPUT SCHEMA — respond with ONLY valid JSON matching this shape:
================================================
{{
  "status": "Incident" | "Healthy" | "Insufficient Data",
  "confidence": 0-100,
  "incident_title": "One-sentence summary of what happened.",
  "attack_summary": "For Incident: 3-5 sentences walking through entry point, progression, intent, and business impact. For Healthy: 4-5 sentences explaining what process produced the events, why the behaviour is normal on this host according to the business context, what was checked and ruled out (parent processes, command lines, persistence indicators, credential access), and why any rule-level severity is a false positive in this context. For Insufficient Data: 2-3 sentences stating what evidence is missing.",
  "investigation_guide": [
    "Blast Radius: <what to check next>. Query: <concrete SIEM, PowerShell, or shell query>",
    "Hunt Query: <what to look for>. Query: <concrete command>",
    "Next Steps: <what the attacker is likely to do next>"
    // investigation_guide MUST contain all three entries (Blast Radius, Hunt Query, Next Steps) for any Incident verdict. Do not omit any.
  ],
  "mitre_techniques": [
    {{"id": "T####.###", "name": "Technique name", "justification": "Specific event from the log that supports this mapping"}}
  ],
  "affected_assets": ["host names that appear in the TELEMETRY INVENTORY"],
  "indicators_of_compromise": {{
    "ips": ["external IPs that appear in the TELEMETRY INVENTORY"],
    "commands": ["command lines that appear in the DETAILED EVENT LOG"],
    "files": ["file paths that appear in the DETAILED EVENT LOG"]
  }},
  "blocking_rationale": "One sentence justifying the block or no-block decision.",
  "remediation_playbook": [
    "Immediate Action: <action>. Command: <exact command>",
    "Long-Term Fix: <control>. Command: <exact command>"
  ],
  "priority": "Critical" | "High" | "Medium" | "Low",
  "false_positive_likelihood": "Low" | "Medium" | "High"
}}

================================================
GROUNDING RULES (the output is rejected if these are violated)
================================================
1. Every IP in indicators_of_compromise.ips must appear verbatim in the TELEMETRY INVENTORY's "External destination IPs seen" list. If that list is empty, ips must be [].
2. Every host in affected_assets must appear in the TELEMETRY INVENTORY's "Hosts seen" list.
3. Every command in indicators_of_compromise.commands must be a substring of a cmd: line in the DETAILED EVENT LOG.
4. Every file in indicators_of_compromise.files must appear as a file_write: entry or as a path inside a command line in the log.
5. If the evidence is genuinely insufficient to reach a verdict, return status "Insufficient Data" with confidence below 50, rather than guessing.
6. For any Incident verdict, the investigation_guide array MUST contain three entries: one starting with "Blast Radius:", one with "Hunt Query:", one with "Next Steps:". Outputs missing any of these are rejected.
================================================
JSON FORMATTING RULES (the output must parse with json.loads)
================================================
6. Inside any string value, use single quotes for inline quoting. Write "executed 'net user' command", not "executed \\"net user\\" command".
7. Escape backslashes in Windows paths. Write "C:\\\\Windows\\\\System32", not "C:\\Windows\\System32".
8. No trailing commas before }} or ]].
"""

    try:
        print("   Sending to Mistral Nemo... ")
        response = await asyncio.to_thread(
            ollama.chat,
            model=MODEL,
            messages=[{'role': 'user', 'content': prompt}],
            format='json',
            options={
                "temperature": 0.1,
                "top_p": 0.1,
                "num_ctx": 8192,
            }
        )

        ai_response = response["message"]["content"].strip()
        print("   Received AI response, parsing...")

        if ai_response.startswith('```'):
            ai_response = re.sub(r'^```(?:json)?\n?', '', ai_response)
            ai_response = re.sub(r'\n?```$', '', ai_response)

        analysis = _parse_llm_json(ai_response)

        # Post-hoc IOC sanitization vs hallucination
        iocs = analysis.get("indicators_of_compromise") or {}
        if isinstance(iocs, dict):
            if "ips" in iocs and isinstance(iocs["ips"], list):
                cleaned = [ip for ip in iocs["ips"] if ip in unique_dest_ips]
                if cleaned != iocs["ips"]:
                    print(f"     Dropped hallucinated IPs: {set(iocs['ips']) - set(cleaned)}")
                iocs["ips"] = cleaned
            if isinstance(analysis.get("affected_assets"), list):
                analysis["affected_assets"] = [h for h in analysis["affected_assets"] if h in unique_hosts]
            analysis["indicators_of_compromise"] = iocs

        processing_time = time.time() - start_time
        processing_times.append(processing_time)

        print(f"   Analysis Complete: {analysis.get('status')} "
              f"(Confidence: {analysis.get('confidence', 0)}%) "
              f"in {processing_time:.2f}s")

        if (analysis.get('status') == 'Incident'
            and analysis.get('confidence', 0) >= 80
            and analysis.get('indicators_of_compromise')):
            iocs = analysis['indicators_of_compromise']
            if iocs.get('ips'):
                print(f"\n   AI RECOMMENDS BLOCKING {len(iocs['ips'])} IP(s)")
                print(f"   Rationale: {analysis.get('blocking_rationale', 'Not provided')}")
                for ip in iocs['ips']:
                    agent_id = next(
                        (a.get('agent', {}).get('id', '000')
                         for a in alerts if a.get('data', {}).get('srcip') == ip),
                        '000'
                    )
                    block_ip_to_file(agent_id, ip)

        batch_result = {
            "type": "batch_analysis",
            "batch_id": batch_id,
            "window_start": window_start,
            "window_end": window_end,
            "alert_count": len(alerts),
            "analysis": analysis,
            "raw_alerts": alerts,
            "processing_time": round(processing_time, 2),
            "timestamp": datetime.now().isoformat(),
            "event_categories": {
                # Legacy keys (kept for backward compat with any old UI bindings)
                "fim": len(cat_buckets["file_drop"]) + len(cat_buckets["file_integrity"]),
                "sudo": len(cat_buckets["privilege_escalation"]) + len(cat_buckets["registry_persistence"]),
                "commands": len(cat_buckets["process_execution"]) + len(cat_buckets["script_chaining"]) + len(cat_buckets["credential_access"]),
                "auth": len(cat_buckets["authentication"]) + len(cat_buckets["network"]),
                # Windows-native keys (preferred; the dashboard renders these when present)
                "registry":          len(cat_buckets["registry_persistence"]),
                "credential_access": len(cat_buckets["credential_access"]),
                "script_chaining":   len(cat_buckets["script_chaining"]),
                "file_drop":         len(cat_buckets["file_drop"]),
                "process_exec":      len(cat_buckets["process_execution"]),
                "network":           len(cat_buckets["network"]),
            }
        }
        return batch_result

    except json.JSONDecodeError as e:
        print(f"   JSON Parse Error: {e}")
        print(f"   Raw AI response (first 500 chars):\n{ai_response[:500]}...")
        return {
            "type": "batch_analysis",
            "batch_id": batch_id,
            "analysis": {
                "status": "Error",
                "summary": "AI response parsing failed - invalid JSON format",
                "confidence": 0,
            },
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        print(f"   Analysis Error: {e}")
        import traceback
        traceback.print_exc()
        return {
            "type": "batch_analysis",
            "batch_id": batch_id,
            "analysis": {
                "status": "Error",
                "summary": f"System error: {str(e)}",
                "confidence": 0
            },
            "timestamp": datetime.now().isoformat()
        }

# ══════════════════════════════════════════════
# DATASET LOADER & PROCESSOR
# ══════════════════════════════════════════════
async def process_dataset():
    try:
        with open(DATASET_FILE, 'r') as f:
            raw_data = json.load(f)

        if isinstance(raw_data, dict) and 'hits' in raw_data:
            alerts = [hit.get('_source', {}) for hit in raw_data.get('hits', {}).get('hits', [])]
        else:
            alerts = raw_data

        print(f"\n Loaded {len(alerts)} alerts from {DATASET_FILE}")
        if len(alerts) == 0:
            print(" Dataset is empty. Nothing to process.")
            return

        result = await analyze_alerts(alerts)
        if result:
            print(f"\n Broadcasting analysis to {len(connected_clients)} client(s)...")
            await broadcast(result)
            print(" Broadcast complete\n")

    except FileNotFoundError:
        print(f"\n ERROR: Dataset file '{DATASET_FILE}' not found!\n")
    except json.JSONDecodeError as e:
        print(f"\n ERROR: Invalid JSON in {DATASET_FILE}: {e}\n")
    except Exception as e:
        print(f"\n ERROR: Failed to process dataset: {e}\n")
        import traceback
        traceback.print_exc()

# ══════════════════════════════════════════════
# MAIN EXECUTION
# ══════════════════════════════════════════════
async def main():
    print("\n" + "="*60)
    print("  WAZUH LLM TRIAGE - SIMULATION MODE")
    print("="*60)
    print(f"AI Model: {MODEL}")
    print(f"Dataset: {DATASET_FILE}")
    print(f"Blocked IPs Log: {BLOCKED_IPS_FILE}")
    print(f"WebSocket: ws://{WS_HOST}:{WS_PORT}")
    print("="*60 + "\n")

    async with websockets.serve(ws_handler, WS_HOST, WS_PORT):
        print("WebSocket server running")
        print("Waiting for React UI to connect...\n")

        while len(connected_clients) == 0:
            await asyncio.sleep(0.5)

        print(f" UI Connected! Starting analysis in 2 seconds...\n")
        await asyncio.sleep(2)

        await process_dataset()

        print("="*60)
        print("ANALYSIS COMPLETE")
        print("="*60)

        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            print("\n Server shutting down...")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n Server stopped by user (Ctrl+C)\n")