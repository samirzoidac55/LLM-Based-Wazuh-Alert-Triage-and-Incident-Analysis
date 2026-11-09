import { Ban, Crosshair } from "lucide-react";
import { SEVERITIES, severityOf } from "../lib/severity";

function RailCard({ icon, title, children }) {
  return (
    <div className="bg-panel rounded-xl border border-line">
      <div className="flex items-center gap-2 px-4 py-3 border-b border-line/70">
        {icon}
        <h2 className="font-mono text-[11px] uppercase tracking-widest text-slate-400">{title}</h2>
      </div>
      <div className="p-3">{children}</div>
    </div>
  );
}

const Empty = ({ children }) => (
  <p className="font-mono text-xs text-slate-600 px-1 py-2">{children}</p>
);

export default function SideRail({ alerts }) {
  // Session blocklist: unique auto-blocked IPs, most recent first.
  const blockedSeen = new Set();
  const blockedList = [];
  for (const a of alerts) {
    if (a.blocked && !blockedSeen.has(a.src_ip)) {
      blockedSeen.add(a.src_ip);
      blockedList.push(a);
    }
  }

  // Top offending sources by alert count (external view — skip unknowns).
  const counts = new Map();
  for (const a of alerts) {
    if (!a.src_ip || a.src_ip === "Unknown") continue;
    const entry = counts.get(a.src_ip) ?? { count: 0, maxLevel: 0 };
    entry.count += 1;
    entry.maxLevel = Math.max(entry.maxLevel, a.level);
    counts.set(a.src_ip, entry);
  }
  const topSources = [...counts.entries()]
    .sort((a, b) => b[1].count - a[1].count || b[1].maxLevel - a[1].maxLevel)
    .slice(0, 6);
  const maxCount = topSources[0]?.[1].count ?? 1;

  return (
    <aside className="hidden xl:flex flex-col gap-4 w-72 shrink-0">
      <RailCard icon={<Ban className="w-3.5 h-3.5 text-signal" />} title={`Blocklist · ${blockedList.length}`}>
        {blockedList.length === 0 ? (
          <Empty>No IPs blocked this session</Empty>
        ) : (
          <ul className="space-y-1">
            {blockedList.slice(0, 10).map((a) => (
              <li key={a.src_ip} className="flex items-center justify-between px-1 py-1 rounded hover:bg-raise">
                <span className="font-mono text-xs text-slate-200">{a.src_ip}</span>
                <span className={`font-mono text-[10px] ${SEVERITIES[a.severity ?? severityOf(a.level)].text}`}>
                  L{a.level}
                </span>
              </li>
            ))}
          </ul>
        )}
      </RailCard>

      <RailCard icon={<Crosshair className="w-3.5 h-3.5 text-slate-400" />} title="Top sources">
        {topSources.length === 0 ? (
          <Empty>No traffic observed yet</Empty>
        ) : (
          <ul className="space-y-2">
            {topSources.map(([ip, { count, maxLevel }]) => {
              const sev = SEVERITIES[severityOf(maxLevel)];
              return (
                <li key={ip} className="px-1">
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-xs text-slate-300">{ip}</span>
                    <span className="font-mono text-[10px] text-slate-500 tabular-nums">×{count}</span>
                  </div>
                  <div className="h-1 rounded bg-line/60 overflow-hidden">
                    <div
                      className={`h-full rounded ${sev.seg}`}
                      style={{ width: `${(count / maxCount) * 100}%`, opacity: 0.7 }}
                    />
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </RailCard>
    </aside>
  );
}
