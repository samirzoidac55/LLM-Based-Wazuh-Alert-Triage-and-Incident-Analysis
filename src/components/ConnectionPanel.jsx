import { Plug, Unplug } from "lucide-react";

export default function ConnectionPanel({ host, port, setHost, setPort, status, attempt, error, onConnect, onDisconnect }) {
  const busy = status === "open" || status === "connecting" || status === "reconnecting";

  return (
    <section className="bg-panel rounded-xl border border-line p-4">
      <form
        className="flex flex-wrap items-end gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          busy ? onDisconnect() : onConnect();
        }}
      >
        <label className="block">
          <span className="block font-mono text-[10px] uppercase tracking-widest text-slate-500 mb-1.5">Bridge host</span>
          <input
            value={host}
            onChange={(e) => setHost(e.target.value)}
            disabled={busy}
            spellCheck={false}
            className="bg-raise border border-line rounded-lg px-3 py-2 font-mono text-sm text-white w-44 disabled:opacity-50"
          />
        </label>
        <label className="block">
          <span className="block font-mono text-[10px] uppercase tracking-widest text-slate-500 mb-1.5">Port</span>
          <input
            value={port}
            onChange={(e) => setPort(e.target.value)}
            disabled={busy}
            spellCheck={false}
            inputMode="numeric"
            className="bg-raise border border-line rounded-lg px-3 py-2 font-mono text-sm text-white w-24 disabled:opacity-50"
          />
        </label>
        <button
          type="submit"
          className={`flex items-center gap-2 px-5 py-2 rounded-lg text-sm font-semibold transition-colors ${
            busy
              ? "bg-raise border border-line text-slate-300 hover:border-sev-critical/50 hover:text-sev-critical"
              : "bg-signal/15 border border-signal/40 text-signal hover:bg-signal/25"
          }`}
        >
          {busy ? <Unplug className="w-4 h-4" /> : <Plug className="w-4 h-4" />}
          {busy ? "Disconnect" : "Connect"}
        </button>
        {status === "reconnecting" && (
          <span className="font-mono text-xs text-sev-medium py-2">
            Connection lost — retry #{attempt} in progress
          </span>
        )}
      </form>
      {error && status !== "open" && (
        <p className="mt-3 font-mono text-xs text-sev-critical bg-sev-critical/10 border border-sev-critical/30 rounded-lg px-3 py-2">
          {error}
        </p>
      )}
    </section>
  );
}
