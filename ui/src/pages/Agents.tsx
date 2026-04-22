import { useEffect, useState } from "react";
import { getAgents, Agent } from "../api/agents";
import { useDashboardWS } from "../hooks/useDashboardWS";
import StatusBadge from "../components/StatusBadge";

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
                <th className="text-left px-4 py-3">Platform</th>
                <th className="text-left px-4 py-3">Version</th>
                <th className="text-left px-4 py-3">Status</th>
                <th className="text-left px-4 py-3">Last seen</th>
              </tr>
            </thead>
            <tbody>
              {enriched.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-6 text-center text-gray-600 text-xs">
                    No agents registered.
                  </td>
                </tr>
              ) : (
                enriched.map((a) => (
                  <tr key={a.id} className="border-b border-surface-2 last:border-0 hover:bg-surface-2 transition-colors">
                    <td className="px-4 py-3 font-mono text-xs text-white">{a.hostname}</td>
                    <td className="px-4 py-3 font-mono text-xs text-gray-400">{a.ip_address}</td>
                    <td className="px-4 py-3 text-xs text-gray-400">{a.platform ?? "—"}</td>
                    <td className="px-4 py-3 text-xs text-gray-400">{a.version ?? "—"}</td>
                    <td className="px-4 py-3">
                      <StatusBadge status={a.liveStatus} />
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-500">
                      {a.last_seen ? new Date(a.last_seen).toLocaleString() : "—"}
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
