import { BrainCircuit, ChevronRight } from "lucide-react";
import { VERDICTS } from "../lib/severity";

function Skeleton() {
  return (
    <div className="space-y-2 animate-pulse" aria-hidden="true">
      <div className="h-3 rounded bg-ai-dim/60 w-3/4" />
      <div className="h-3 rounded bg-ai-dim/40 w-full" />
      <div className="h-3 rounded bg-ai-dim/40 w-2/3" />
    </div>
  );
}

function Section({ label, children }) {
  return (
    <div>
      <p className="font-mono text-[10px] uppercase tracking-widest text-slate-500 mb-1">{label}</p>
      {children}
    </div>
  );
}

export default function AnalysisPanel({ alert }) {
  const { analysis_status: status, analysis, analysis_ms, analysis_error, model, data, details } = alert;
  const verdict = analysis ? VERDICTS[analysis.verdict] ?? VERDICTS.investigate : null;
  const evidence = Object.entries(details ?? {});

  return (
    <div className="border-t border-line/70 px-4 py-4 pl-5 relative">
      <div className="absolute left-0 top-0 bottom-0 w-0.5 bg-ai/50" aria-hidden="true" />

      <div className="flex items-center gap-2 mb-3">
        <BrainCircuit className="w-4 h-4 text-ai" />
        <span className="font-mono text-xs uppercase tracking-widest text-ai">
          AI analyst · {model ?? "llama3"}
        </span>
        {status === "complete" && analysis_ms && (
          <span className="font-mono text-[10px] text-slate-500 ml-auto tabular-nums">
            triaged in {(analysis_ms / 1000).toFixed(1)}s
          </span>
        )}
      </div>

      {status === "analyzing" && (
        <div className="space-y-3">
          <Skeleton />
          <p className="font-mono text-xs text-ai/80 animate-pulse">Analyzing event…</p>
        </div>
      )}

      {status === "error" && (
        <div className="font-mono text-xs text-sev-critical bg-sev-critical/10 border border-sev-critical/30 rounded-lg px-3 py-2">
          <p>Analysis failed: {analysis_error ?? "unknown error"}</p>
          <p className="text-slate-400 mt-1">Check that Ollama is running and the model is pulled.</p>
        </div>
      )}

      {status === "complete" && analysis && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-3">
            <span className={`inline-block border-2 rounded px-3 py-1 font-mono text-sm font-bold uppercase tracking-[0.2em] ${verdict.stamp}`}>
              {verdict.label}
            </span>
            <span className="font-mono text-[11px] text-slate-500">
              false-positive risk:{" "}
              <span className={
                analysis.false_positive_likelihood === "high" ? "text-slate-300"
                : analysis.false_positive_likelihood === "medium" ? "text-sev-medium"
                : "text-sev-high"
              }>
                {analysis.false_positive_likelihood}
              </span>
            </span>
          </div>

          <p className="text-sm text-slate-200 leading-relaxed">{analysis.summary}</p>

          {analysis.risk && (
            <Section label="Risk">
              <p className="text-sm text-slate-400 leading-relaxed">{analysis.risk}</p>
            </Section>
          )}

          {analysis.recommended_actions?.length > 0 && (
            <Section label="Response">
              <ul className="space-y-1">
                {analysis.recommended_actions.map((action, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                    <ChevronRight className="w-3.5 h-3.5 mt-1 text-ai shrink-0" />
                    {action}
                  </li>
                ))}
              </ul>
            </Section>
          )}

          {analysis.mitre_techniques?.length > 0 && (
            <Section label="MITRE ATT&CK">
              <div className="flex flex-wrap gap-1.5">
                {analysis.mitre_techniques.map((t, i) => (
                  <span key={i} className="font-mono text-[11px] px-2 py-0.5 rounded border border-ai/40 text-ai bg-ai/10">
                    {t}
                  </span>
                ))}
              </div>
            </Section>
          )}
        </div>
      )}

      {evidence.length > 0 && (
        <div className="mt-4">
          <p className="font-mono text-[10px] uppercase tracking-widest text-slate-500 mb-1.5">Evidence</p>
          <dl className="space-y-1">
            {evidence.map(([key, value]) => (
              <div key={key} className="flex gap-2 items-baseline min-w-0">
                <dt className="font-mono text-[10px] text-slate-600 w-24 shrink-0">{key}</dt>
                <dd className="font-mono text-xs text-slate-300 break-all">{String(value)}</dd>
              </div>
            ))}
          </dl>
        </div>
      )}

      {data && Object.keys(data).length > 0 && (
        <details className="mt-4 group">
          <summary className="font-mono text-[10px] uppercase tracking-widest text-slate-500 cursor-pointer hover:text-slate-300 select-none">
            Raw event data
          </summary>
          <pre className="mt-2 font-mono text-xs text-slate-400 bg-void/60 border border-line rounded-lg p-3 overflow-x-auto">
            {JSON.stringify(data, null, 2)}
          </pre>
        </details>
      )}
    </div>
  );
}
