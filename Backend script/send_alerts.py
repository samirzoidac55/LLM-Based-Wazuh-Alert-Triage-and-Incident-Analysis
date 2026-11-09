"""Replay sample Wazuh alerts to the bridge over UDP.

Examples:
    python3 send_alerts.py                     # all alerts, 3s apart
    python3 send_alerts.py --delay 1 --shuffle # faster, random order
    python3 send_alerts.py --count 5 --loop    # first 5, repeating forever
    python3 send_alerts.py --file dataset/mimikatz.json --delay 2   # replay an attack dataset
"""

import argparse
import json
import random
import socket
import time
from pathlib import Path

parser = argparse.ArgumentParser(description="Replay sample Wazuh alerts to the SOC bridge.")
parser.add_argument("--host",  default="127.0.0.1", help="bridge host (default: 127.0.0.1)")
parser.add_argument("--port",  type=int, default=5140, help="bridge UDP port (default: 5140)")
parser.add_argument("--delay", type=float, default=3.0, help="seconds between alerts (default: 3)")
parser.add_argument("--count", type=int, default=None, help="send only the first N alerts")
parser.add_argument("--shuffle", action="store_true", help="send alerts in random order")
parser.add_argument("--loop",  action="store_true", help="repeat forever (Ctrl-C to stop)")
parser.add_argument("--file",  default=str(Path(__file__).parent / "alerts.json"),
                    help="alerts file (default: alerts.json next to this script)")
args = parser.parse_args()

with open(args.file) as f:
    raw = json.load(f)

# Plain list of alerts, or an OpenSearch export ({"hits": {"hits": [{"_source": …}]}})
if isinstance(raw, dict) and "hits" in raw:
    alerts = [hit.get("_source", {}) for hit in raw.get("hits", {}).get("hits", [])]
else:
    alerts = raw

if args.shuffle:
    random.shuffle(alerts)
if args.count:
    alerts = alerts[:args.count]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

try:
    while True:
        for i, alert in enumerate(alerts):
            sock.sendto(json.dumps(alert).encode("utf-8"), (args.host, args.port))
            print(f"📤 Sent alert {i + 1}/{len(alerts)}: {alert['rule']['description']}")
            time.sleep(args.delay)
        if not args.loop:
            break
        print("🔁 Looping…")
except KeyboardInterrupt:
    print("\n👋 Stopped")
else:
    print("✅ All alerts sent!")
