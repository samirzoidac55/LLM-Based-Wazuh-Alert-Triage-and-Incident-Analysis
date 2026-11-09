import { createElement, useEffect, useMemo, useState } from "react";
import {
  ArrowDownToLine,
  ArrowUpRight,
  Bell,
  Check,
  ChevronRight,
  CircleHelp,
  FileText,
  Inbox,
  LayoutList,
  LoaderCircle,
  Network,
  Plug,
  Search,
  Settings2,
  Shield,
  SlidersHorizontal,
  X,
} from "lucide-react";
import { useSocket } from "./hooks/useSocket";
import { severityOf, timeAgo } from "./lib/severity";
import AnalysisPanel from "./components/AnalysisPanel";
import IncidentReport from "./components/IncidentReport";

const FILTERS = ["all", "critical", "high", "medium", "low"];
const STATUS = {
  open: "Connected",
  connecting: "Connecting",
  reconnecting: "Reconnecting",
  idle: "Disconnected",
};

function exportAlerts(alerts) {
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(alerts, null, 2)], { type: "application/json" }),
  );
  const link = document.createElement("a");
  link.href = url;
  link.download = "wazuh-alerts.json";
  link.click();
  URL.revokeObjectURL(url);
}

function Verdict({ alert }) {
  if (alert.analysis_status === "analyzing")
    return (
      <span className="queue-status">
        <LoaderCircle size={12} className="spin" /> In progress
      </span>
    );
  if (alert.analysis_status === "error")
    return <span className="queue-status failed">Unavailable</span>;
  return (
    <span className={`verdict verdict-${alert.analysis?.verdict ?? "pending"}`}>
      {alert.analysis?.verdict ?? "Pending"}
    </span>
  );
}

function Empty({ icon = Inbox, title, children }) {
  return (
    <div className="empty-state">
      <div className="empty-icon">
        {createElement(icon, { size: 24, strokeWidth: 1.5 })}
      </div>
      <h3>{title}</h3>
      <p>{children}</p>
    </div>
  );
}

export default function SOCDashboard() {
  const {
    status,
    alerts,
    reports,
    server,
    attempt,
    error,
    connect,
    disconnect,
    clearAlerts,
  } = useSocket();
  const [host, setHost] = useState("localhost");
  const [port, setPort] = useState("8765");
  const [view, setView] = useState("alerts");
  const [filter, setFilter] = useState("all");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(null);
  const [connectionOpen, setConnectionOpen] = useState(false);
  const [detailTab, setDetailTab] = useState("analysis");
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 10000);
    return () => clearInterval(timer);
  }, []);
  const busy = status !== "idle";
  const counts = useMemo(() => {
    const c = { all: alerts.length, critical: 0, high: 0, medium: 0, low: 0 };
    for (const a of alerts) c[a.severity ?? severityOf(a.level)]++;
    return c;
  }, [alerts]);
  const filtered = useMemo(
    () =>
      alerts.filter((a) => {
        const matches =
          filter === "all" || (a.severity ?? severityOf(a.level)) === filter;
        return (
          matches &&
          [a.rule_desc, a.src_ip, a.agent_name, ...(a.groups ?? [])]
            .join(" ")
            .toLowerCase()
            .includes(query.toLowerCase().trim())
        );
      }),
    [alerts, filter, query],
  );
  const active = filtered.find((a) => a.id === selected) ?? filtered[0];
  const completed = alerts.filter(
    (a) => a.analysis_status === "complete",
  ).length;
  const pending = alerts.filter(
    (a) => a.analysis_status === "analyzing",
  ).length;
  const sources = useMemo(() => {
    const map = new Map();
    for (const a of alerts) {
      const ip = a.src_ip || "Unknown";
      const entry = map.get(ip) ?? {
        ip,
        count: 0,
        highest: 0,
        hosts: new Set(),
      };
      entry.count++;
      entry.highest = Math.max(entry.highest, Number(a.level) || 0);
      if (a.agent_name) entry.hosts.add(a.agent_name);
      map.set(ip, entry);
    }
    return [...map.values()].sort((a, b) => b.count - a.count);
  }, [alerts]);
  const heading = {
    alerts: "Alert triage",
    reports: "Incident reports",
    sources: "Source activity",
  }[view];
  const subheading = {
    alerts: "Review incoming detections and decide what needs a closer look.",
    reports:
      "Investigate telemetry windows with context from your local model.",
    sources: "See where alerts originate and which hosts are affected.",
  }[view];

  return (
    <div className="workspace">
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      <aside className="sidebar">
        <a
          className="brand"
          href="#"
          onClick={(e) => {
            e.preventDefault();
            setView("alerts");
          }}
        >
          <span className="brand-mark">
            <Shield size={21} strokeWidth={1.7} />
          </span>
          <span>
            Wazuh triage<small>ANALYST WORKSPACE</small>
          </span>
        </a>
        <div className="workspace-label">
          <span className="workspace-avatar">L</span>
          <span>
            Local environment<small>Security operations</small>
          </span>
          <ChevronRight size={14} />
        </div>
        <div className="nav-label">WORKSPACE</div>
        <nav aria-label="Main navigation">
          {[
            {
              id: "alerts",
              label: "Alert queue",
              icon: LayoutList,
              count: alerts.length,
            },
            {
              id: "reports",
              label: "Incident reports",
              icon: FileText,
              count: reports.length,
            },
            {
              id: "sources",
              label: "Sources",
              icon: Network,
              count: sources.length,
            },
          ].map(({ id, label, icon, count }) => (
            <button
              key={id}
              aria-label={label}
              title={label}
              className={`nav-item ${view === id ? "active" : ""}`}
              aria-current={view === id ? "page" : undefined}
              onClick={() => setView(id)}
            >
              {createElement(icon, { size: 17, strokeWidth: 1.6 })}
              <span>{label}</span>
              <span className="nav-count">{count}</span>
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <button
            className="nav-item"
            onClick={() => setConnectionOpen((v) => !v)}
          >
            <Settings2 size={17} />
            Connection settings
          </button>
          <div className="local-note">
            <span className="local-lock">
              <Shield size={15} />
            </span>
            <div>
              Inference stays local<small>Powered by Ollama</small>
            </div>
          </div>
          <div className="profile">
            <span className="profile-avatar">SA</span>
            <div>
              Security analyst<small>Local session</small>
            </div>
            <span className="profile-dot" />
          </div>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div className="breadcrumb">
            <span>Workspace</span>
            <ChevronRight size={13} />
            <strong>{heading}</strong>
          </div>
          <div className="topbar-end">
            <span className="environment-tag">Local environment</span>
            <span className={`connection-state state-${status}`} role="status">
              <i />
              {STATUS[status]}
            </span>
          </div>
        </header>
        <main id="main-content" className="main-content">
          <div className="page-heading">
            <div>
              <div className="eyebrow">SECURITY OPERATIONS</div>
              <h1>{heading}</h1>
              <p>{subheading}</p>
            </div>
            <div className="heading-actions">
              <button
                className="button"
                disabled={!alerts.length}
                onClick={() => exportAlerts(alerts)}
              >
                <ArrowDownToLine size={15} />
                Export alerts
              </button>
              <button
                className="button primary"
                onClick={() => (busy ? disconnect() : connect(host, port))}
              >
                <Plug size={15} />
                {busy ? "Disconnect" : "Connect bridge"}
              </button>
            </div>
          </div>
          {connectionOpen && (
            <section
              className="connection-card"
              aria-label="Connection settings"
            >
              <div>
                <h2>Backend connection</h2>
                <p>Choose the alert bridge for this workspace.</p>
              </div>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  connect(host, port);
                }}
              >
                <label>
                  Host
                  <input
                    value={host}
                    disabled={busy}
                    required
                    onChange={(e) => setHost(e.target.value)}
                  />
                </label>
                <label>
                  Port
                  <input
                    value={port}
                    disabled={busy}
                    required
                    type="number"
                    min="1"
                    max="65535"
                    onChange={(e) => setPort(e.target.value)}
                  />
                </label>
                <button className="button primary" disabled={busy}>
                  Connect
                </button>
              </form>
              <button
                className="icon-button"
                aria-label="Close connection settings"
                onClick={() => setConnectionOpen(false)}
              >
                <X size={17} />
              </button>
            </section>
          )}
          {error && status !== "open" && (
            <div className="notice error-notice" role="alert">
              <CircleHelp size={17} />
              <span>
                {error}
                {status === "reconnecting"
                  ? ` Reconnection attempt ${attempt}.`
                  : ""}
              </span>
              <button onClick={() => setConnectionOpen(true)}>
                Connection settings
              </button>
            </div>
          )}
          <section className="metrics" aria-label="Session overview">
            {[
              {
                label: "Alerts received",
                value: alerts.length,
                note: "In this session",
                icon: Inbox,
              },
              {
                label: "High priority",
                value: counts.critical + counts.high,
                note: "Critical and high severity",
                icon: Bell,
                tone: "warm",
              },
              {
                label: "Analysis complete",
                value: completed,
                note: "Model verdicts available",
                icon: Check,
              },
              {
                label: "Awaiting analysis",
                value: pending,
                note: "In the analysis queue",
                icon: LoaderCircle,
              },
            ].map(({ label, value, note, icon, tone }) => (
              <div className="metric" key={label}>
                <div className="metric-label">
                  {label}
                  {createElement(icon, { size: 16 })}
                </div>
                <strong className={tone ?? ""}>{value.toLocaleString()}</strong>
                <small>{note}</small>
              </div>
            ))}
          </section>
          {view === "alerts" && (
            <div
              className={`investigation-layout ${active ? "has-selection" : ""}`}
            >
              <section className="queue-card">
                <div className="section-heading">
                  <div>
                    <h2>
                      Alert queue{" "}
                      <span className="count-badge">{alerts.length}</span>
                    </h2>
                    <p>Newest detections first</p>
                  </div>
                  <span className="quiet-label">
                    <span
                      className={`small-dot ${status === "open" ? "green" : ""}`}
                    />
                    {status === "open" ? "Receiving alerts" : "Bridge offline"}
                  </span>
                </div>
                <div className="queue-toolbar">
                  <div className="search-field">
                    <Search size={16} />
                    <input
                      aria-label="Search alerts"
                      value={query}
                      onChange={(e) => setQuery(e.target.value)}
                      placeholder="Search detection, host, or IP address"
                    />
                  </div>
                  <label className="severity-select">
                    <SlidersHorizontal size={14} />
                    <select
                      aria-label="Filter severity"
                      value={filter}
                      onChange={(e) => setFilter(e.target.value)}
                    >
                      {FILTERS.map((f) => (
                        <option key={f} value={f}>
                          {f === "all"
                            ? "All severities"
                            : f[0].toUpperCase() + f.slice(1)}
                        </option>
                      ))}
                    </select>
                  </label>
                </div>
                <div className="table-scroll">
                  <table className="alert-table">
                    <thead>
                      <tr>
                        <th>Severity</th>
                        <th>Detection</th>
                        <th>Analysis</th>
                        <th>Received</th>
                        <th>
                          <span className="sr-only">Details</span>
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {filtered.map((a) => (
                        <tr
                          key={a.id}
                          className={active?.id === a.id ? "selected" : ""}
                        >
                          <td>
                            <span
                              className={`severity severity-${a.severity ?? severityOf(a.level)}`}
                            >
                              <i />
                              {a.severity ?? severityOf(a.level)}
                            </span>
                          </td>
                          <td>
                            <button
                              className="detection-button"
                              aria-label={`Inspect ${a.rule_desc}`}
                              onClick={() => {
                                setSelected(a.id);
                                setDetailTab("analysis");
                              }}
                            >
                              <strong>{a.rule_desc}</strong>
                              <span>
                                {a.agent_name ?? "Unknown host"}
                                <b aria-hidden="true">&middot;</b>
                                <code>{a.src_ip}</code>
                              </span>
                            </button>
                          </td>
                          <td>
                            <Verdict alert={a} />
                          </td>
                          <td className="received-cell">
                            <time dateTime={a.received_at}>
                              {timeAgo(a.received_at, now)}
                            </time>
                          </td>
                          <td>
                            <button
                              className="icon-button"
                              aria-label={`Open details for ${a.rule_desc}`}
                              onClick={() => setSelected(a.id)}
                            >
                              <ChevronRight size={15} />
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {!filtered.length && (
                  <Empty
                    title={
                      alerts.length
                        ? "No matching alerts"
                        : "Your queue is clear"
                    }
                  >
                    {alerts.length
                      ? "Try a different search or severity filter."
                      : status === "open"
                        ? "The bridge is connected. New Wazuh detections will appear here as they arrive."
                        : "Connect your alert bridge to start reviewing Wazuh detections in this workspace."}
                  </Empty>
                )}
                <div className="table-footer">
                  <span>
                    {filtered.length} of {alerts.length} alerts
                  </span>
                  <span>Session history</span>
                  <button
                    disabled={!alerts.length && !reports.length}
                    onClick={() => {
                      clearAlerts();
                      setSelected(null);
                    }}
                  >
                    Clear local view
                  </button>
                </div>
              </section>
              <aside className="detail-column">
                {active ? (
                  <section className="detail-card">
                    <div className="detail-header">
                      <span className="eyebrow">INVESTIGATION</span>
                      <span
                        className={`severity severity-${active.severity ?? severityOf(active.level)}`}
                      >
                        {active.severity ?? severityOf(active.level)}
                      </span>
                    </div>
                    <h2>{active.rule_desc}</h2>
                    <dl className="event-facts">
                      <div>
                        <dt>Source address</dt>
                        <dd>{active.src_ip ?? "Unknown"}</dd>
                      </div>
                      <div>
                        <dt>Affected host</dt>
                        <dd>{active.agent_name ?? "Unknown"}</dd>
                      </div>
                      <div>
                        <dt>Rule level</dt>
                        <dd>{active.level} / 15</dd>
                      </div>
                      <div>
                        <dt>Response</dt>
                        <dd>
                          {active.blocked
                            ? "Simulated block recorded"
                            : "No simulated block"}
                        </dd>
                      </div>
                    </dl>
                    <div
                      className="detail-tabs"
                      role="tablist"
                      aria-label="Investigation details"
                    >
                      <button
                        role="tab"
                        id="analysis-tab"
                        aria-selected={detailTab === "analysis"}
                        aria-controls="detail-content"
                        className={detailTab === "analysis" ? "active" : ""}
                        onClick={() => setDetailTab("analysis")}
                      >
                        Analysis
                      </button>
                      <button
                        role="tab"
                        id="event-tab"
                        aria-selected={detailTab === "event"}
                        aria-controls="detail-content"
                        className={detailTab === "event" ? "active" : ""}
                        onClick={() => setDetailTab("event")}
                      >
                        Raw event
                      </button>
                    </div>
                    <div
                      id="detail-content"
                      role="tabpanel"
                      aria-labelledby={
                        detailTab === "analysis" ? "analysis-tab" : "event-tab"
                      }
                    >
                      {detailTab === "analysis" ? (
                        <AnalysisPanel alert={active} />
                      ) : (
                        <pre className="raw-event">
                          {JSON.stringify(active.data ?? active, null, 2)}
                        </pre>
                      )}
                    </div>
                  </section>
                ) : (
                  <section className="guidance-card">
                    <span className="guidance-icon">
                      <LayoutList size={20} strokeWidth={1.5} />
                    </span>
                    <h2>A little context goes a long way.</h2>
                    <p>
                      Select a detection to review the evidence, model
                      assessment, and suggested next steps.
                    </p>
                    <div className="workflow-step">
                      <span>1</span>
                      <div>
                        Review the detection
                        <small>Start with severity, source, and host.</small>
                      </div>
                    </div>
                    <div className="workflow-step">
                      <span>2</span>
                      <div>
                        Read the assessment
                        <small>
                          Use the model verdict as a starting point.
                        </small>
                      </div>
                    </div>
                    <div className="workflow-step">
                      <span>3</span>
                      <div>
                        Validate and investigate
                        <small>Check the evidence before taking action.</small>
                      </div>
                    </div>
                  </section>
                )}
                <section className="model-card">
                  <div>
                    <span
                      className={`small-dot ${status === "open" ? "green" : ""}`}
                    />
                    <h3>Local analysis</h3>
                    <ArrowUpRight size={14} />
                  </div>
                  <p>{server?.model ?? "No model connected"}</p>
                  <small>
                    Model findings require analyst review. Response blocking is
                    simulated.
                  </small>
                </section>
              </aside>
            </div>
          )}
          {view === "reports" && (
            <section className="reports-view">
              <div className="section-heading">
                <div>
                  <h2>Incident reports</h2>
                  <p>Reports received from the batch analysis backend</p>
                </div>
                <FileText size={19} />
              </div>
              {reports.length ? (
                <div className="report-list">
                  {reports.map((r, i) => (
                    <IncidentReport
                      key={r.batch_id ?? i}
                      report={r}
                      defaultOpen={i === 0}
                    />
                  ))}
                </div>
              ) : (
                <Empty icon={FileText} title="No incident reports yet">
                  Run a batch analysis and connect this workspace to receive the
                  report.
                </Empty>
              )}
            </section>
          )}
          {view === "sources" && (
            <section className="queue-card">
              <div className="section-heading">
                <div>
                  <h2>Observed sources</h2>
                  <p>Grouped from alerts received in this session</p>
                </div>
                <Network size={19} />
              </div>
              {sources.length ? (
                <div className="table-scroll">
                  <table className="alert-table">
                    <thead>
                      <tr>
                        <th>Source address</th>
                        <th>Alerts</th>
                        <th>Highest severity</th>
                        <th>Affected hosts</th>
                      </tr>
                    </thead>
                    <tbody>
                      {sources.map((s) => (
                        <tr key={s.ip}>
                          <td>
                            <code>{s.ip}</code>
                          </td>
                          <td>{s.count}</td>
                          <td>
                            <span
                              className={`severity severity-${severityOf(s.highest)}`}
                            >
                              {severityOf(s.highest)}
                            </span>
                          </td>
                          <td>{[...s.hosts].join(", ") || "Unknown"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <Empty icon={Network} title="No sources observed">
                  Source addresses and affected hosts will appear when alerts
                  arrive.
                </Empty>
              )}
            </section>
          )}
          <footer className="page-footer">
            <span>
              Wazuh + Ollama <span aria-hidden="true">&middot;</span>{" "}
              LLM-assisted alert triage
            </span>
            <span>
              <Shield size={12} />
              Local workspace
            </span>
          </footer>
        </main>
      </div>
    </div>
  );
}
