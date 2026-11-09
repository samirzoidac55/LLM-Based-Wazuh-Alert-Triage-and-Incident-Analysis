import { Clock3, CircleAlert, LoaderCircle } from "lucide-react";

export default function AnalysisPanel({ alert }) {
  const {
    analysis_status: status,
    analysis,
    analysis_ms,
    analysis_error,
    model,
    details,
  } = alert;
  return (
    <div className="analysis-content">
      <div className="analysis-byline">
        <span>Model assessment</span>
        <code>{model ?? "Local model"}</code>
      </div>
      {status === "analyzing" && (
        <div className="analysis-message">
          <LoaderCircle size={18} className="spin" />
          <div>
            <strong>Analysis in progress</strong>
            <p>
              The event is queued for local inference. Its assessment will
              appear here.
            </p>
          </div>
        </div>
      )}
      {status === "error" && (
        <div className="analysis-message analysis-error">
          <CircleAlert size={18} />
          <div>
            <strong>Assessment unavailable</strong>
            <p>
              Check that Ollama is running and the configured model has finished
              downloading.
            </p>
            <details>
              <summary>Technical details</summary>
              <code>{analysis_error ?? "Unknown analysis error"}</code>
            </details>
          </div>
        </div>
      )}
      {status === "complete" && analysis && (
        <>
          <div className="assessment-result">
            <span className={`verdict verdict-${analysis.verdict}`}>
              {analysis.verdict}
            </span>
            {analysis_ms != null && (
              <small>
                <Clock3 size={11} />
                {(analysis_ms / 1000).toFixed(1)}s
              </small>
            )}
          </div>
          <p className="analysis-summary">{analysis.summary}</p>
          {analysis.risk && (
            <section>
              <h3>Risk assessment</h3>
              <p>{analysis.risk}</p>
            </section>
          )}
          {analysis.false_positive_likelihood && (
            <div className="false-positive">
              <span>False-positive likelihood</span>
              <strong>{analysis.false_positive_likelihood}</strong>
            </div>
          )}
          {analysis.recommended_actions?.length > 0 && (
            <section>
              <h3>Recommended next steps</h3>
              <ol className="action-list">
                {analysis.recommended_actions.map((a, i) => (
                  <li key={i}>{a}</li>
                ))}
              </ol>
            </section>
          )}
          {analysis.mitre_techniques?.length > 0 && (
            <section>
              <h3>MITRE ATT&CK</h3>
              <div className="technique-list">
                {analysis.mitre_techniques.map((t, i) => (
                  <code key={i}>
                    {typeof t === "string"
                      ? t
                      : [t.id, t.name].filter(Boolean).join(" - ")}
                  </code>
                ))}
              </div>
            </section>
          )}
        </>
      )}
      {Object.keys(details ?? {}).length > 0 && (
        <section>
          <h3>Event evidence</h3>
          <dl className="evidence-list">
            {Object.entries(details).map(([k, v]) => (
              <div key={k}>
                <dt>{k}</dt>
                <dd>{typeof v === "object" ? JSON.stringify(v) : String(v)}</dd>
              </div>
            ))}
          </dl>
        </section>
      )}
      <p className="analyst-note">
        Validate model findings against the original event before taking action.
      </p>
    </div>
  );
}
