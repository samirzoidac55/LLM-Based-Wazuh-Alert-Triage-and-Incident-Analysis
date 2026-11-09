import { useState } from "react";
import { ChevronDown, ChevronRight, FileWarning } from "lucide-react";

// Verdict of the batch analyst: status drives the stamp color.
const STATUS_STYLE = {
  Incident:            "border-sev-critical/60 text-sev-critical bg-sev-critical/10",
  Healthy:             "border-signal/60 text-signal bg-signal/10",
  "Insufficient Data": "border-sev-medium/60 text-sev-medium bg-sev-medium/10",
  Error:               "border-slate-500/60 text-slate-400 bg-slate-500/10",
};

const PRIORITY_STYLE = {
  Critical: "text-sev-critical",
  High:     "text-sev-high",
  Medium:   "text-sev-medium",
  Low:      "text-sev-low",
};

function Section({ label, children }) {
  return (
    <div>
      <p className="font-mono text-[10px] uppercase tracking-widest text-slate-500 mb-1.5">{label}</p>
      {children}
    </div>
  );
}

function IocGroup({ label, items }) {
  if (!items?.length) return null;
  return (
    <div className="min-w-0">
      <p className="font-mono text-[10px] uppercase tracking-widest text-slate-600 mb-1">{label}</p>
      <div className="flex flex-wrap gap-1.5">
        {items.map((item, i) => (
          <code key={i} className="font-mono text-[11px] px-2 py-0.5 rounded border border-line bg-void/60 text-slate-300 break-all">
            {item}
          </code>
        ))}
      </div>
    </div>
  );
}

/** Renders a batch_analysis report from SOC-batch-analyst.py — a whole
 *  telemetry window triaged in one LLM pass. */
export default function IncidentReport({ report, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen);
  const a = report.analysis ?? {};
  const status = a.status ?? "Error";
  const iocs = a.indicators_of_compromise ?? {};

  return (
    <article className="bg-panel rounded-xl border border-ai/30 overflow-hidden animate-alert-in">
      <button
        className="w-full text-left px-4 py-3 flex items-center gap-3"
        onClick={() => setOpen(!open)}
        aria-expanded={open}
      >
        <FileWarning className="w-4 h-4 text-ai shrink-0" />
        <span className="font-mono text-xs uppercase tracking-widest text-ai shrink-0">Incident report</span>
        <span className={`px-2 py-px rounded border font-mono text-[11px] font-bold uppercase tracking-wider shrink-0 ${STATUS_STYLE[status] ?? STATUS_STYLE.Error}`}>
          {status}
        </span>
        {typeof a.confidence === "number" && (
          <span className="font-mono text-[11px] text-slate-500 shrink-0 tabular-nums">{a.confidence}% confidence</span>
        )}
        <span className="text-sm text-slate-300 truncate hidden md:block">{a.incident_title}</span>
        <span className="ml-auto flex items-center gap-3 shrink-0">
          {report.alert_count != null && (
            <span className="font-mono text-[11px] text-slate-500 tabular-nums">{report.alert_count} events</span>
          )}
          {report.processing_time != null && (
            <span className="font-mono text-[11px] text-slate-500 tabular-nums">{report.processing_time}s</span>
          )}
          {open ? <ChevronDown className="w-4 h-4 text-slate-500" /> : <ChevronRight className="w-4 h-4 text-slate-500" />}
        </span>
      </button>

      {open && (
        <div className="border-t border-line/70 px-4 py-4 pl-5 relative space-y-4">
          <div className="absolute left-0 top-0 bottom-0 w-0.5 bg-ai/50" aria-hidden="true" />

          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[11px] text-slate-500">
            {report.batch_id && <span>{report.batch_id}</span>}
            {report.window_start && (
              <span className="tabular-nums">window {report.window_start.slice(11, 19)} → {report.window_end?.slice(11, 19)}</span>
            )}
            {a.priority && (
              <span>
                priority: <span className={`font-bold ${PRIORITY_STYLE[a.priority] ?? "text-slate-300"}`}>{a.priority}</span>
              </span>
            )}
            {a.false_positive_likelihood && <span>false-positive risk: {a.false_positive_likelihood}</span>}
          </div>

          {a.incident_title && <p className="font-display text-lg font-semibold text-white">{a.incident_title}</p>}
          {(a.attack_summary ?? a.summary) && (
            <p className="text-sm text-slate-300 leading-relaxed">{a.attack_summary ?? a.summary}</p>
          )}

          {a.investigation_guide?.length > 0 && (
            <Section label="Investigation guide">
              <ul className="space-y-1.5">
                {a.investigation_guide.map((step, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                    <ChevronRight className="w-3.5 h-3.5 mt-1 text-ai shrink-0" />
                    <span className="min-w-0 break-words">{step}</span>
                  </li>
                ))}
              </ul>
            </Section>
          )}

          {a.mitre_techniques?.length > 0 && (
            <Section label="MITRE ATT&CK">
              <ul className="space-y-1.5">
                {a.mitre_techniques.map((t, i) => (
                  <li key={i} className="text-sm">
                    <span className="font-mono text-[11px] px-2 py-0.5 rounded border border-ai/40 text-ai bg-ai/10 mr-2">
                      {t.id} — {t.name}
                    </span>
                    {t.justification && <span className="text-slate-400">{t.justification}</span>}
                  </li>
                ))}
              </ul>
            </Section>
          )}

          {(iocs.ips?.length || iocs.commands?.length || iocs.files?.length) ? (
            <Section label="Indicators of compromise">
              <div className="space-y-2">
                <IocGroup label="IPs" items={iocs.ips} />
                <IocGroup label="Commands" items={iocs.commands} />
                <IocGroup label="Files" items={iocs.files} />
              </div>
            </Section>
          ) : null}

          {a.remediation_playbook?.length > 0 && (
            <Section label="Remediation playbook">
              <ul className="space-y-1.5">
                {a.remediation_playbook.map((step, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                    <ChevronRight className="w-3.5 h-3.5 mt-1 text-signal shrink-0" />
                    <span className="min-w-0 break-words">{step}</span>
                  </li>
                ))}
              </ul>
            </Section>
          )}

          {a.blocking_rationale && (
            <Section label="Blocking decision">
              <p className="text-sm text-slate-400">{a.blocking_rationale}</p>
            </Section>
          )}

          {a.affected_assets?.length > 0 && (
            <p className="font-mono text-[11px] text-slate-500">
              affected assets: <span className="text-slate-300">{a.affected_assets.join(", ")}</span>
            </p>
          )}
        </div>
      )}
    </article>
  );
}
