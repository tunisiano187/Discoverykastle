import { useEffect, useState } from "react";
import { getAgents, Agent } from "../api/agents";
import { useDashboardWS } from "../hooks/useDashboardWS";
import StatusBadge from "../components/StatusBadge";

/** A compact horizontal bar showing a percentage with a colour-coded fill. */
function MetricBar({ value }: { value: number | null }) {
  if (value === null) {
    return <span className="text-gray-600 text-xs">—</span>;
  }
  const pct = Math.min(100, Math.max(0, value));
  const colour =
    pct >= 90
      ? "bg-red-500"
      : pct >= 70
      ? "bg-yellow-500"
      : "bg-green-500";

  return (
    <div className="flex items-center gap-1.5 min-w-[80px]">
      <div className="flex-1 h-1.5 rounded-full bg-surface-3 overflow-hidden">
        <div
          className={`h-full rounded-full transition-all ${colour}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="text-[10px] text-gray-400 tabular-nums w-9 text-right">
        {pct.toFixed(0)}%
      </span>
    </div>
  );
}

export default function Agents() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const { connectedAgents } = useDashboardWS();

  useEffect(() => {
    getAgents()
      .then(setAgents)
      .catch((e: unknown) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const enriched = agents.map((a) => ({
    ...a,
    liveStatus: connectedAgents.includes(a.id) ? "online" : "offline",
  }));

  const hasMetrics = enriched.some(
    (a) => a.cpu_percent !== null || a.memory_percent !== null || a.disk_percent !== null
  );

  return (
    <div className="p-6 space-y-4">
      <h1 className="text-xl font-semibold text-white">Agents</h1>

      {loading && <p className="text-gray-500 text-sm">Loading…</p>}
      {error && <p className="text-red-400 text-sm">{error}</p>}

      {!loading && !error && (
        <div className="bg-surface-1 border border-surface-3 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-surface-3 text-xs text-gray-500">
                <th className="text-left px-4 py-3">Hostname</th>
                <th className="text-left px-4 py-3">IP Address</th>
                <th className="text-left px-4 py-3">Version</th>
                <th className="text-left px-4 py-3">Status</th>
                {hasMetrics && (
                  <>
                    <th className="text-left px-4 py-3">CPU</th>
                    <th className="text-left px-4 py-3">Memory</th>
                    <th className="text-left px-4 py-3">Disk</th>
                  </>
                )}
                <th className="text-left px-4 py-3">Last heartbeat</th>
              </tr>
            </thead>
            <tbody>
              {enriched.length === 0 ? (
                <tr>
                  <td
                    colSpan={hasMetrics ? 8 : 5}
                    className="px-4 py-6 text-center text-gray-600 text-xs"
                  >
                    No agents registered.
                  </td>
                </tr>
              ) : (
                enriched.map((a) => (
                  <tr
                    key={a.id}
                    className="border-b border-surface-2 last:border-0 hover:bg-surface-2 transition-colors"
                  >
                    <td className="px-4 py-3 font-mono text-xs text-white">
                      {a.hostname}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-gray-400">
                      {a.ip_address}
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-400">
                      {a.version ?? "—"}
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge status={a.liveStatus} />
                    </td>
                    {hasMetrics && (
                      <>
                        <td className="px-4 py-3">
                          <MetricBar value={a.cpu_percent} />
                        </td>
                        <td className="px-4 py-3">
                          <MetricBar value={a.memory_percent} />
                        </td>
                        <td className="px-4 py-3">
                          <MetricBar value={a.disk_percent} />
                        </td>
                      </>
                    )}
                    <td className="px-4 py-3 text-xs text-gray-500">
                      {a.last_heartbeat
                        ? new Date(a.last_heartbeat).toLocaleString()
                        : "—"}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
