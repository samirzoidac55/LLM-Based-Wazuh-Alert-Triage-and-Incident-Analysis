import { useEffect, useMemo, useState } from "react";
import { Download, Radar, Search, Trash2 } from "lucide-react";
import { useSocket } from "./hooks/useSocket";
import { severityOf } from "./lib/severity";
import StatusBar from "./components/StatusBar";
import ConnectionPanel from "./components/ConnectionPanel";
import ReadoutStrip from "./components/ReadoutStrip";
import AlertRow from "./components/AlertRow";
import IncidentReport from "./components/IncidentReport";
import SideRail from "./components/SideRail";

const DEFAULT_HOST = "localhost";
const DEFAULT_PORT = "8765"; // must match WS_PORT in the Python bridge
const FILTERS = ["all", "critical", "high", "medium", "low"];

function exportAlerts(alerts) {
  const blob = new Blob([JSON.stringify(alerts, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `soc-alerts-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

function EmptyState({ status }) {
  const message =
    status === "open"
      ? "Feed is live — waiting for alerts"
      : status === "reconnecting"
        ? "Connection lost — retrying automatically"
        : "Connect to the bridge to start triaging alerts";
  return (
    <div className="bg-panel rounded-xl border border-line p-14 text-center">
      <Radar className={`w-12 h-12 mx-auto mb-4 ${status === "open" ? "text-signal/60 animate-pulse" : "text-slate-700"}`} />
      <p className="text-slate-400">{message}</p>
      {status === "idle" && (
        <p className="font-mono text-xs text-slate-600 mt-2">
          python3 "Backend script/SOC-py-backend.py"
        </p>
      )}
    </div>
  );
}

export default function SOCDashboard() {
  const { status, alerts, reports, server, attempt, error, connect, disconnect, clearAlerts } = useSocket();
  const [host, setHost] = useState(DEFAULT_HOST);
  const [port, setPort] = useState(DEFAULT_PORT);
  const [filter, setFilter] = useState("all");
  const [query, setQuery] = useState("");
  const [expanded, setExpanded] = useState(null);

  // Single 10s tick keeps every "n min ago" label honest.
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 10_000);
    return () => clearInterval(t);
  }, []);

  const counts = useMemo(() => {
    const c = { all: alerts.length, critical: 0, high: 0, medium: 0, low: 0 };
    for (const a of alerts) c[a.severity ?? severityOf(a.level)]++;
    return c;
  }, [alerts]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return alerts.filter((a) => {
      if (filter !== "all" && (a.severity ?? severityOf(a.level)) !== filter) return false;
      if (!q) return true;
      return [a.src_ip, a.rule_desc, a.agent_name, ...(a.groups ?? [])]
        .filter(Boolean)
        .some((field) => field.toLowerCase().includes(q));
    });
  }, [alerts, filter, query]);

  return (
    <div className="min-h-screen p-4 lg:p-6">
      <div className="max-w-7xl mx-auto space-y-4">
        <StatusBar status={status} server={server} />

        <ConnectionPanel
          host={host} port={port} setHost={setHost} setPort={setPort}
          status={status} attempt={attempt} error={error}
          onConnect={() => connect(host, port)}
          onDisconnect={disconnect}
        />

        <ReadoutStrip alerts={alerts} />

        {/* Filters, search, feed actions */}
        <div className="flex flex-wrap items-center gap-2">
          {FILTERS.map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              data-active={filter === f}
              className="px-3.5 py-1.5 rounded-full border font-mono text-xs uppercase tracking-wider transition-colors
                border-line bg-panel text-slate-500 hover:text-slate-300
                data-[active=true]:border-signal/50 data-[active=true]:text-signal data-[active=true]:bg-signal/10"
            >
              {f} <span className="text-slate-600">{counts[f]}</span>
            </button>
          ))}

          <div className="relative ml-auto">
            <Search className="w-4 h-4 text-slate-600 absolute left-3 top-1/2 -translate-y-1/2" aria-hidden="true" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter by IP, rule, host…"
              spellCheck={false}
              className="bg-panel border border-line rounded-full pl-9 pr-4 py-1.5 font-mono text-xs text-white w-56 placeholder:text-slate-600"
            />
          </div>

          {alerts.length > 0 && (
            <>
              <button
                onClick={() => exportAlerts(alerts)}
                title="Export alerts as JSON"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-full border border-line bg-panel font-mono text-xs text-slate-400 hover:text-slate-200 transition-colors"
              >
                <Download className="w-3.5 h-3.5" /> Export
              </button>
              <button
                onClick={clearAlerts}
                title="Clear the feed (bridge history is kept)"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-full border border-line bg-panel font-mono text-xs text-slate-400 hover:text-sev-critical hover:border-sev-critical/40 transition-colors"
              >
                <Trash2 className="w-3.5 h-3.5" /> Clear
              </button>
            </>
          )}
        </div>

        {/* Feed + side rail */}
        <div className="flex gap-4 items-start">
          <main className="flex-1 min-w-0 space-y-2.5">
            {reports.map((report, i) => (
              <IncidentReport key={report.batch_id ?? i} report={report} defaultOpen={i === 0} />
            ))}
            {filtered.length === 0 && alerts.length === 0 && reports.length === 0 && <EmptyState status={status} />}
            {filtered.length === 0 && alerts.length > 0 && (
              <div className="bg-panel rounded-xl border border-line p-10 text-center">
                <p className="text-slate-500">No alerts match the current filter.</p>
              </div>
            )}
            {filtered.map((alert) => (
              <AlertRow
                key={alert.id}
                alert={alert}
                now={now}
                open={expanded === alert.id}
                onToggle={() => setExpanded(expanded === alert.id ? null : alert.id)}
              />
            ))}
          </main>
          <SideRail alerts={alerts} />
        </div>
      </div>
    </div>
  );
}
