import { useEffect, useState } from "react";
import { getHosts, Host } from "../api/hosts";

export default function Hosts() {
  const [hosts, setHosts] = useState<Host[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");

  useEffect(() => {
    getHosts(200)
      .then(setHosts)
      .catch((e: unknown) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const filtered = hosts.filter((h) => {
    const q = search.toLowerCase();
    return (
      !q ||
      h.fqdn?.toLowerCase().includes(q) ||
      h.ip_addresses.some((ip) => ip.includes(q)) ||
      h.os?.toLowerCase().includes(q)
    );
  });

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-xl font-semibold text-white">Hosts</h1>
        <input
          type="text"
          placeholder="Search by FQDN, IP or OS…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="bg-surface-2 border border-surface-3 rounded-md px-3 py-1.5 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-brand w-64"
        />
      </div>

      {loading && <p className="text-gray-500 text-sm">Loading…</p>}
      {error && <p className="text-red-400 text-sm">{error}</p>}

      {!loading && !error && (
        <div className="bg-surface-1 border border-surface-3 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-surface-3 text-xs text-gray-500">
                <th className="text-left px-4 py-3">FQDN</th>
                <th className="text-left px-4 py-3">IP Addresses</th>
                <th className="text-left px-4 py-3">OS</th>
                <th className="text-left px-4 py-3">First seen</th>
                <th className="text-left px-4 py-3">Last seen</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-6 text-center text-gray-600 text-xs">
                    {search ? "No hosts match your search." : "No hosts discovered."}
                  </td>
                </tr>
              ) : (
                filtered.map((h) => (
                  <tr key={h.id} className="border-b border-surface-2 last:border-0 hover:bg-surface-2 transition-colors">
                    <td className="px-4 py-3 font-mono text-xs text-white">{h.fqdn ?? "—"}</td>
                    <td className="px-4 py-3 font-mono text-xs text-gray-400">
                      {h.ip_addresses.join(", ") || "—"}
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-400">
                      {h.os ? `${h.os}${h.os_version ? ` ${h.os_version}` : ""}` : "—"}
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-500">
                      {new Date(h.first_seen).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-500">
                      {new Date(h.last_seen).toLocaleDateString()}
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
