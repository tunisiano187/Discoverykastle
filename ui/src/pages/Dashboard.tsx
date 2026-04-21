import { useEffect, useState } from "react";
import { getVulnSummary, VulnSummary } from "../api/vulns";
import { getAgents, Agent } from "../api/agents";
import { useDashboardWS } from "../hooks/useDashboardWS";
import SeverityBadge from "../components/SeverityBadge";

const SEV_ORDER = ["critical", "high", "medium", "low", "none", "unknown"] as const;
const SEV_BAR_COLOR: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-blue-500",
  none: "bg-gray-600",
  unknown: "bg-gray-700",
};

function StatCard({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="bg-surface-1 border border-surface-3 rounded-xl p-4">
      <p className="text-xs text-gray-500 mb-1">{label}</p>
      <p className="text-2xl font-bold text-white">{value}</p>
    </div>
  );
}

export default function Dashboard() {
  const [summary, setSummary] = useState<VulnSummary | null>(null);
  const [agents, setAgents] = useState<Agent[]>([]);
  const { connectedAgents, events, connected } = useDashboardWS();

  useEffect(() => {
    getVulnSummary().then(setSummary).catch(console.error);
    getAgents().then(setAgents).catch(console.error);
  }, []);

  const onlineCount = connectedAgents.length;
  const totalAgents = agents.length;
  const maxSev = summary
    ? Math.max(...SEV_ORDER.map((s) => summary.by_severity[s]))
    : 0;

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-white">Dashboard</h1>
        <span className={`flex items-center gap-1.5 text-xs ${connected ? "text-green-400" : "text-gray-500"}`}>
          <span className={`h-2 w-2 rounded-full ${connected ? "bg-green-400" : "bg-gray-600"}`} />
          {connected ? "Live" : "Disconnected"}
        </span>
      </div>

      {/* KPI cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Agents online" value={`${onlineCount} / ${totalAgents}`} />
        <StatCard label="Total vulnerabilities" value={summary?.total ?? "—"} />
        <StatCard label="Unique CVEs" value={summary?.unique_cves ?? "—"} />
        <StatCard label="Affected hosts" value={summary?.affected_hosts ?? "—"} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity breakdown */}
        {summary && (
          <div className="bg-surface-1 border border-surface-3 rounded-xl p-4 space-y-3">
            <h2 className="text-sm font-semibold text-gray-300">Severity breakdown</h2>
            {SEV_ORDER.map((sev) => {
              const count = summary.by_severity[sev];
              const pct = maxSev > 0 ? (count / maxSev) * 100 : 0;
              return (
                <div key={sev} className="flex items-center gap-3">
                  <div className="w-16">
                    <SeverityBadge severity={sev} />
                  </div>
                  <div className="flex-1 bg-surface-2 rounded-full h-2 overflow-hidden">
                    <div
                      className={`h-full rounded-full ${SEV_BAR_COLOR[sev]}`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <span className="text-xs text-gray-400 w-8 text-right">{count}</span>
                </div>
              );
            })}
          </div>
        )}

        {/* Top CVEs */}
        {summary && summary.top_cves.length > 0 && (
          <div className="bg-surface-1 border border-surface-3 rounded-xl p-4 space-y-2">
            <h2 className="text-sm font-semibold text-gray-300">Top CVEs by affected hosts</h2>
            <div className="space-y-1">
              {summary.top_cves.slice(0, 8).map((c) => (
                <div key={c.cve_id} className="flex items-center justify-between text-sm py-1 border-b border-surface-2 last:border-0">
                  <span className="text-brand font-mono text-xs">{c.cve_id}</span>
                  <div className="flex items-center gap-3">
                    <SeverityBadge severity={c.severity} />
                    <span className="text-gray-400 text-xs w-16 text-right">{c.affected_hosts} hosts</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Live event feed */}
      <div className="bg-surface-1 border border-surface-3 rounded-xl p-4">
        <h2 className="text-sm font-semibold text-gray-300 mb-3">Live events</h2>
        {events.length === 0 ? (
          <p className="text-xs text-gray-600">No events yet.</p>
        ) : (
          <div className="space-y-1 max-h-48 overflow-y-auto font-mono text-xs">
            {events.map((ev, i) => (
              <div key={i} className="text-gray-400 border-b border-surface-2 py-0.5 last:border-0">
                <span className="text-gray-600 mr-2">{ev.type}</span>
                {JSON.stringify(ev, null, 0).slice(0, 120)}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
