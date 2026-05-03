import { useEffect, useState } from "react";
import { apiFetch } from "../api/client";

interface Device {
  id: string;
  ip_address: string;
  hostname: string | null;
  vendor: string | null;
  model: string | null;
  firmware_version: string | null;
  device_type: string | null;
  created_at: string;
  updated_at: string;
}

export default function Devices() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");

  useEffect(() => {
    apiFetch<Device[]>("/api/v1/inventory/devices")
      .then(setDevices)
      .catch((e: unknown) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const filtered = devices.filter((d) => {
    const q = search.toLowerCase();
    return (
      !q ||
      d.ip_address.includes(q) ||
      d.hostname?.toLowerCase().includes(q) ||
      d.vendor?.toLowerCase().includes(q) ||
      d.model?.toLowerCase().includes(q)
    );
  });

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-xl font-semibold text-white">Network Devices</h1>
        <input
          type="text"
          placeholder="Search by IP, hostname, vendor…"
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
                <th className="text-left px-4 py-3">IP Address</th>
                <th className="text-left px-4 py-3">Hostname</th>
                <th className="text-left px-4 py-3">Type</th>
                <th className="text-left px-4 py-3">Vendor / Model</th>
                <th className="text-left px-4 py-3">Firmware</th>
                <th className="text-left px-4 py-3">Last updated</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-6 text-center text-gray-600 text-xs">
                    {search
                      ? "No devices match your search."
                      : "No network devices discovered yet. Deploy an agent with NETMIKO_ENABLED=true."}
                  </td>
                </tr>
              ) : (
                filtered.map((d) => (
                  <tr
                    key={d.id}
                    className="border-b border-surface-2 last:border-0 hover:bg-surface-2 transition-colors"
                  >
                    <td className="px-4 py-3 font-mono text-xs text-white">{d.ip_address}</td>
                    <td className="px-4 py-3 text-xs text-gray-300">{d.hostname ?? "—"}</td>
                    <td className="px-4 py-3 text-xs">
                      {d.device_type ? (
                        <span className="bg-surface-3 text-gray-300 px-2 py-0.5 rounded text-[10px] font-mono">
                          {d.device_type}
                        </span>
                      ) : (
                        <span className="text-gray-600">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-400">
                      {[d.vendor, d.model].filter(Boolean).join(" ") || "—"}
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-500 font-mono">
                      {d.firmware_version ?? "—"}
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-500">
                      {new Date(d.updated_at).toLocaleString()}
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
