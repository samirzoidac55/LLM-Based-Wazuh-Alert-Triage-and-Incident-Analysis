import { SEVERITIES, severityOf } from "../lib/severity";

function Readout({ label, value, className = "text-white" }) {
  return (
    <div className="px-4 py-2 min-w-[5.5rem]">
      <p className="font-mono text-[10px] uppercase tracking-widest text-slate-500">{label}</p>
      <p className={`font-display text-2xl font-bold leading-tight tabular-nums ${className}`}>{value}</p>
    </div>
  );
}

/** Micro-histogram of the most recent alerts, oldest → newest, bar height = level/15. */
function Pulseline({ alerts }) {
  const recent = alerts.slice(0, 48).reverse();
  if (recent.length === 0) return null;
  return (
    <div className="hidden md:flex items-end gap-[3px] h-9 px-4 ml-auto" aria-hidden="true">
      {recent.map((a) => (
        <div
          key={a.id}
          className={`w-[4px] rounded-sm ${SEVERITIES[a.severity ?? severityOf(a.level)].seg}`}
          style={{ height: `${Math.max(12, (a.level / 15) * 100)}%`, opacity: 0.85 }}
          title={`Level ${a.level}: ${a.rule_desc}`}
        />
      ))}
    </div>
  );
}

export default function ReadoutStrip({ alerts }) {
  const bySev = { critical: 0, high: 0, medium: 0, low: 0 };
  let blocked = 0;
  let analyzedMs = [];
  for (const a of alerts) {
    bySev[a.severity ?? severityOf(a.level)]++;
    if (a.blocked) blocked++;
    if (a.analysis_status === "complete" && a.analysis_ms) analyzedMs.push(a.analysis_ms);
  }
  const avgMs = analyzedMs.length
    ? `${(analyzedMs.reduce((s, v) => s + v, 0) / analyzedMs.length / 1000).toFixed(1)}s`
    : "—";

  return (
    <section
      className="bg-panel rounded-xl border border-line flex flex-wrap items-center divide-x divide-line overflow-hidden"
      aria-label="Alert statistics"
    >
      <Readout label="Alerts" value={alerts.length} />
      <Readout label="Critical" value={bySev.critical} className={bySev.critical ? SEVERITIES.critical.text : "text-slate-600"} />
      <Readout label="High" value={bySev.high} className={bySev.high ? SEVERITIES.high.text : "text-slate-600"} />
      <Readout label="Medium" value={bySev.medium} className={bySev.medium ? SEVERITIES.medium.text : "text-slate-600"} />
      <Readout label="Low" value={bySev.low} className={bySev.low ? SEVERITIES.low.text : "text-slate-600"} />
      <Readout label="IPs blocked" value={blocked} className={blocked ? "text-signal" : "text-slate-600"} />
      <Readout label="Avg triage" value={avgMs} className="text-ai" />
      <Pulseline alerts={alerts} />
    </section>
  );
}
