import { useEffect, useState } from "react";
import { Shield } from "lucide-react";

function UTCClock() {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  return (
    <span className="hidden sm:block font-mono text-sm text-slate-500 tabular-nums">
      {now.toISOString().slice(11, 19)} <span className="text-slate-600">UTC</span>
    </span>
  );
}

const STATUS_PILL = {
  open:         { label: "Live",         cls: "border-signal/40 text-signal bg-signal/10", dot: "bg-signal animate-pulse" },
  connecting:   { label: "Connecting",   cls: "border-sev-medium/40 text-sev-medium bg-sev-medium/10", dot: "bg-sev-medium animate-pulse" },
  reconnecting: { label: "Reconnecting", cls: "border-sev-medium/40 text-sev-medium bg-sev-medium/10", dot: "bg-sev-medium animate-pulse" },
  idle:         { label: "Offline",      cls: "border-line text-slate-500 bg-panel", dot: "bg-slate-600" },
};

export default function StatusBar({ status, server }) {
  const pill = STATUS_PILL[status] ?? STATUS_PILL.idle;
  const model = server?.model ?? "llama3";
  return (
    <header className="flex items-center justify-between gap-4">
      <div className="flex items-center gap-3 min-w-0">
        <div className="p-2 rounded-lg bg-signal-dim/60 border border-signal/20 shrink-0">
          <Shield className="w-6 h-6 text-signal" />
        </div>
        <div className="min-w-0">
          <h1 className="font-display font-bold text-2xl leading-none tracking-[0.18em] text-white uppercase">
            LLM Alert Triage
          </h1>
          <p className="font-mono text-[10px] tracking-[0.25em] text-slate-500 uppercase mt-1 truncate">
            Wazuh × {model} · real-time triage
          </p>
        </div>
      </div>
      <div className="flex items-center gap-4 shrink-0">
        <UTCClock />
        <span className={`flex items-center gap-2 px-3 py-1.5 rounded-full border font-mono text-xs uppercase tracking-widest ${pill.cls}`}>
          <span className={`w-1.5 h-1.5 rounded-full ${pill.dot}`} />
          {pill.label}
        </span>
      </div>
    </header>
  );
}
