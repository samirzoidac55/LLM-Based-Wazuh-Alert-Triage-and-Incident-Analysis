// Severity vocabulary shared across the dashboard.
// Wazuh rule levels run 0–15: 12+ critical, 9+ high, 6+ medium, else low.
// Class strings are full literals so Tailwind's scanner picks them up.

export const SEVERITIES = {
  critical: {
    text: "text-sev-critical",
    seg: "bg-sev-critical",
    chip: "bg-sev-critical/10 text-sev-critical border-sev-critical/40",
    tab: "data-[active=true]:border-sev-critical/60 data-[active=true]:text-sev-critical",
  },
  high: {
    text: "text-sev-high",
    seg: "bg-sev-high",
    chip: "bg-sev-high/10 text-sev-high border-sev-high/40",
    tab: "data-[active=true]:border-sev-high/60 data-[active=true]:text-sev-high",
  },
  medium: {
    text: "text-sev-medium",
    seg: "bg-sev-medium",
    chip: "bg-sev-medium/10 text-sev-medium border-sev-medium/40",
    tab: "data-[active=true]:border-sev-medium/60 data-[active=true]:text-sev-medium",
  },
  low: {
    text: "text-sev-low",
    seg: "bg-sev-low",
    chip: "bg-sev-low/10 text-sev-low border-sev-low/40",
    tab: "data-[active=true]:border-sev-low/60 data-[active=true]:text-sev-low",
  },
};

export const severityOf = (level) =>
  level >= 12 ? "critical" : level >= 9 ? "high" : level >= 6 ? "medium" : "low";

// LLM verdict vocabulary — the color says how loudly the analyst is speaking.
export const VERDICTS = {
  escalate: {
    label: "Escalate",
    stamp: "border-sev-critical/60 text-sev-critical bg-sev-critical/10",
    chip: "text-sev-critical",
  },
  investigate: {
    label: "Investigate",
    stamp: "border-sev-high/60 text-sev-high bg-sev-high/10",
    chip: "text-sev-high",
  },
  monitor: {
    label: "Monitor",
    stamp: "border-sev-medium/60 text-sev-medium bg-sev-medium/10",
    chip: "text-sev-medium",
  },
  routine: {
    label: "Routine",
    stamp: "border-slate-500/60 text-slate-400 bg-slate-500/10",
    chip: "text-slate-400",
  },
};

export function timeAgo(iso, now = Date.now()) {
  const d = Math.max(0, Math.floor((now - new Date(iso).getTime()) / 1000));
  if (d < 60) return `${d}s ago`;
  if (d < 3600) return `${Math.floor(d / 60)}m ago`;
  return `${Math.floor(d / 3600)}h ago`;
}
