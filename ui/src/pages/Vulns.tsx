import { useEffect, useState } from "react";
import { getVulns, getVulnSummary, VulnOut, VulnSummary } from "../api/vulns";
import SeverityBadge from "../components/SeverityBadge";

const SEVERITIES = ["", "critical", "high", "medium", "low", "none"];

export default function Vulns() {
  const [vulns, setVulns] = useState<VulnOut[]>([]);
  const [summary, setSummary] = useState<VulnSummary | null>(null);
  const [severity, setSeverity] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    getVulnSummary().then(setSummary).catch(console.error);
  }, []);

  useEffect(() => {
    setLoading(true);
    getVulns({ severity: severity || undefined, limit: 200 })
      .then(setVulns)
      .catch((e: unknown) => setError(String(e)))
      .finally(() => setLoading(false));
  }, [severity]);

  return (
    <div className="p-6 space-y-5">
      <h1 className="text-xl font-semibold text-white">Vulnerabilities</h1>

      {/* Summary cards */}
      {summary && (
        <div className="grid grid-cols-3 sm:grid-cols-6 gap-3">
          {(["critical", "high", "medium", "low", "none", "unknown"] as const).map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverity(sev === severity ? "" : sev)}
              className={`bg-surface-1 border rounded-lg p-3 text-center transition-all ${
                severity === sev ? "border-brand" : "border-surface-3 hover:border-surface-3"
              }`}
            >
              <p className="text-lg font-bold text-white">{summary.by_severity[sev]}</p>
              <SeverityBadge severity={sev} />
            </button>
          ))}
        </div>
      )}

      {/* Filter bar */}
      <div className="flex items-center gap-3 text-xs text-gray-500">
        <span>Filter:</span>
        {SEVERITIES.map((s) => (
          <button
            key={s || "all"}
            onClick={() => setSeverity(s)}
            className={`px-2 py-0.5 rounded border transition-colors ${
              severity === s
                ? "border-brand text-brand"
                : "border-surface-3 text-gray-500 hover:text-white"
            }`}
          >
            {s || "All"}
          </button>
        ))}
      </div>

      {loading && <p className="text-gray-500 text-sm">Loading…</p>}
      {error && <p className="text-red-400 text-sm">{error}</p>}

      {!loading && !error && (
        <div className="bg-surface-1 border border-surface-3 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-surface-3 text-xs text-gray-500">
                <th className="text-left px-4 py-3">CVE ID</th>
                <th className="text-left px-4 py-3">Severity</th>
                <th className="text-left px-4 py-3">CVSS</th>
                <th className="text-left px-4 py-3">Host</th>
                <th className="text-left px-4 py-3">Description</th>
                <th className="text-left px-4 py-3">First seen</th>
              </tr>
            </thead>
            <tbody>
              {vulns.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-6 text-center text-gray-600 text-xs">
                    No vulnerabilities found.
                  </td>
                </tr>
              ) : (
                vulns.map((v) => (
                  <tr key={v.id} className="border-b border-surface-2 last:border-0 hover:bg-surface-2 transition-colors">
                    <td className="px-4 py-3 font-mono text-xs text-brand whitespace-nowrap">{v.cve_id}</td>
                    <td className="px-4 py-3">
                      <SeverityBadge severity={v.severity} />
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-400">
                      {v.cvss_score != null ? v.cvss_score.toFixed(1) : "—"}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-gray-400">
                      {v.host_fqdn ?? v.host_ip_addresses[0] ?? "—"}
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-500 max-w-xs truncate">
                      {v.description ?? "—"}
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-500 whitespace-nowrap">
                      {new Date(v.first_seen).toLocaleDateString()}
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
