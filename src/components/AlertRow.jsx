import { ArrowRight, Clock, ShieldCheck } from "lucide-react";
import { SEVERITIES, VERDICTS, severityOf, timeAgo } from "../lib/severity";
import AnalysisPanel from "./AnalysisPanel";

/** Wazuh levels run 0–15 — the meter fills bottom-up like a VU meter. */
function LevelMeter({ level, severity }) {
  const seg = SEVERITIES[severity].seg;
  return (
    <div
      className="flex flex-col-reverse gap-[2px] w-1.5 self-stretch py-0.5 shrink-0"
      role="img"
      aria-label={`Severity level ${level} of 15`}
    >
      {Array.from({ length: 15 }, (_, i) => (
        <div
          key={i}
          className={`flex-1 rounded-[1px] ${i < level ? seg : "bg-line/60"}`}
        />
      ))}
    </div>
  );
}

function StatusChip({ alert }) {
  if (alert.analysis_status === "analyzing") {
    return <span className="font-mono text-[11px] text-ai animate-pulse">analyzing…</span>;
  }
  if (alert.analysis_status === "error") {
    return <span className="font-mono text-[11px] text-sev-critical">LLM error</span>;
  }
  const verdict = VERDICTS[alert.analysis?.verdict] ?? VERDICTS.investigate;
  return (
    <span className={`font-mono text-[11px] font-bold uppercase tracking-wider ${verdict.chip}`}>
      {verdict.label}
    </span>
  );
}

export default function AlertRow({ alert, open, onToggle, now }) {
  const severity = alert.severity ?? severityOf(alert.level);
  const sev = SEVERITIES[severity];

  return (
    <article className="bg-panel rounded-xl border border-line overflow-hidden animate-alert-in hover:border-slate-600/70 transition-colors">
      <button
        className="w-full text-left px-4 py-3 flex items-stretch gap-3.5"
        onClick={onToggle}
        aria-expanded={open}
      >
        <LevelMeter level={alert.level} severity={severity} />

        <div className={`self-center w-9 shrink-0 text-center font-display text-2xl font-bold tabular-nums ${sev.text}`}>
          {alert.level}
        </div>

        <div className="flex-1 min-w-0 self-center">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1 mb-0.5">
            <span className="font-mono text-sm font-bold text-white">{alert.src_ip}</span>
            <ArrowRight className="w-3 h-3 text-slate-600" aria-hidden="true" />
            <span className="font-mono text-xs text-slate-400">{alert.agent_name ?? "unknown host"}</span>
            <span className={`px-2 py-px rounded border font-mono text-[10px] font-semibold uppercase tracking-wider ${sev.chip}`}>
              {severity}
            </span>
            {alert.blocked && (
              <span className="flex items-center gap-1 px-2 py-px rounded border border-signal/40 bg-signal/10 text-signal font-mono text-[10px] uppercase tracking-wider">
                <ShieldCheck className="w-3 h-3" /> Auto-blocked
              </span>
            )}
          </div>
          <p className="text-sm text-slate-300 truncate">{alert.rule_desc}</p>
          {alert.groups?.length > 0 && (
            <p className="font-mono text-[10px] text-slate-500 mt-1 truncate">
              {alert.groups.slice(0, 4).join(" · ")}
              {alert.location ? `  —  ${alert.location}` : ""}
            </p>
          )}
        </div>

        <div className="self-center flex flex-col items-end gap-1.5 shrink-0">
          <span className="flex items-center gap-1 font-mono text-[11px] text-slate-500 tabular-nums">
            <Clock className="w-3 h-3" />
            {timeAgo(alert.received_at, now)}
          </span>
          <StatusChip alert={alert} />
        </div>
      </button>

      {open && <AnalysisPanel alert={alert} />}
    </article>
  );
}
