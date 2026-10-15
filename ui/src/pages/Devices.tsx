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
  last_seen: string;
}

interface DeviceInterface {
  name: string;
  ip?: string | null;
  mac?: string | null;
  status?: string | null;
  speed?: string | null;
  mtu?: number | null;
  description?: string | null;
}

interface StructuredData {
  interfaces?: DeviceInterface[];
  vlans?: Array<{ id: number; name: string }>;
  routes?: Array<{ prefix: string; next_hop: string; protocol?: string }>;
  neighbors?: Array<{ device: string; port: string; protocol: string }>;
  snmp?: Record<string, string>;
}

interface DeviceDetail extends Device {
  config_snapshot: string | null;
  structured_data: string | null;
}

function parseStructured(raw: string | null): StructuredData | null {
  if (!raw) return null;
  try {
    return JSON.parse(raw) as StructuredData;
  } catch {
    return null;
  }
}

function DeviceTypeBadge({ type }: { type: string | null }) {
  if (!type) return <span className="text-gray-600">—</span>;
  const colours: Record<string, string> = {
    router: "bg-blue-900/40 text-blue-300 border-blue-800",
    switch: "bg-purple-900/40 text-purple-300 border-purple-800",
    firewall: "bg-red-900/40 text-red-300 border-red-800",
    ap: "bg-green-900/40 text-green-300 border-green-800",
  };
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-mono border ${colours[type] ?? "bg-surface-3 text-gray-400 border-surface-3"}`}>
      {type}
    </span>
  );
}

function InterfaceStatusDot({ status }: { status?: string | null }) {
  const up = status?.toLowerCase() === "up" || status?.toLowerCase() === "connected";
  const down = status?.toLowerCase() === "down" || status?.toLowerCase() === "disconnected";
  if (up) return <span className="inline-block w-1.5 h-1.5 rounded-full bg-green-500 mr-1.5" />;
  if (down) return <span className="inline-block w-1.5 h-1.5 rounded-full bg-red-500 mr-1.5" />;
  return <span className="inline-block w-1.5 h-1.5 rounded-full bg-gray-600 mr-1.5" />;
}

type DetailTab = "interfaces" | "routes" | "vlans" | "snmp" | "config";

function DetailPanel({
  detail,
  loading,
}: {
  detail: DeviceDetail | null;
  loading: boolean;
}) {
  const [tab, setTab] = useState<DetailTab>("interfaces");
  const structured = detail ? parseStructured(detail.structured_data) : null;

  const tabs: Array<{ key: DetailTab; label: string; count?: number }> = (
    [
      { key: "interfaces" as DetailTab, label: "Interfaces", count: structured?.interfaces?.length },
      { key: "routes" as DetailTab, label: "Routes", count: structured?.routes?.length },
      { key: "vlans" as DetailTab, label: "VLANs", count: structured?.vlans?.length },
      { key: "snmp" as DetailTab, label: "SNMP OIDs", count: structured?.snmp ? Object.keys(structured.snmp).length : undefined },
      { key: "config" as DetailTab, label: "Config", count: undefined },
    ] satisfies Array<{ key: DetailTab; label: string; count?: number }>
  ).filter((t) => {
    if (!structured && t.key !== "config") return false;
    return true;
  });

  if (loading) return <p className="text-xs text-gray-600 py-2">Loading…</p>;
  if (!detail) return null;

  return (
    <div className="space-y-2">
      <div className="flex gap-1">
        {tabs.map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`text-[11px] px-2.5 py-1 rounded transition-colors ${
              tab === t.key
                ? "bg-surface-3 text-white"
                : "text-gray-500 hover:text-gray-300 hover:bg-surface-2"
            }`}
          >
            {t.label}
            {t.count !== undefined && t.count > 0 && (
              <span className="ml-1 text-gray-600">({t.count})</span>
            )}
          </button>
        ))}
      </div>

      {tab === "interfaces" && (
        <>
          {!structured?.interfaces?.length ? (
            <p className="text-xs text-gray-600">No interface data available.</p>
          ) : (
            <table className="w-full text-xs">
              <thead>
                <tr className="text-gray-600 text-[10px] uppercase tracking-wider">
                  <th className="text-left py-1 pr-4">Name</th>
                  <th className="text-left py-1 pr-4">Status</th>
                  <th className="text-left py-1 pr-4">IP Address</th>
                  <th className="text-left py-1 pr-4">MAC</th>
                  <th className="text-left py-1 pr-4">Speed</th>
                  <th className="text-left py-1">Description</th>
                </tr>
              </thead>
              <tbody>
                {structured.interfaces.map((iface, i) => (
                  <tr key={i} className="border-t border-surface-2">
                    <td className="py-1 pr-4 font-mono text-white">{iface.name}</td>
                    <td className="py-1 pr-4">
                      <span className="flex items-center">
                        <InterfaceStatusDot status={iface.status} />
                        <span className="text-gray-400">{iface.status ?? "—"}</span>
                      </span>
                    </td>
                    <td className="py-1 pr-4 font-mono text-gray-300">{iface.ip ?? "—"}</td>
                    <td className="py-1 pr-4 font-mono text-gray-500">{iface.mac ?? "—"}</td>
                    <td className="py-1 pr-4 text-gray-400">{iface.speed ?? "—"}</td>
                    <td className="py-1 text-gray-500">{iface.description ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}

      {tab === "routes" && (
        <>
          {!structured?.routes?.length ? (
            <p className="text-xs text-gray-600">No route data available.</p>
          ) : (
            <table className="w-full text-xs">
              <thead>
                <tr className="text-gray-600 text-[10px] uppercase tracking-wider">
                  <th className="text-left py-1 pr-4">Prefix</th>
                  <th className="text-left py-1 pr-4">Next Hop</th>
                  <th className="text-left py-1">Protocol</th>
                </tr>
              </thead>
              <tbody>
                {structured.routes.map((r, i) => (
                  <tr key={i} className="border-t border-surface-2">
                    <td className="py-1 pr-4 font-mono text-white">{r.prefix}</td>
                    <td className="py-1 pr-4 font-mono text-gray-300">{r.next_hop}</td>
                    <td className="py-1 text-gray-500">{r.protocol ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}

      {tab === "vlans" && (
        <>
          {!structured?.vlans?.length ? (
            <p className="text-xs text-gray-600">No VLAN data available.</p>
          ) : (
            <table className="w-full text-xs">
              <thead>
                <tr className="text-gray-600 text-[10px] uppercase tracking-wider">
                  <th className="text-left py-1 pr-4">ID</th>
                  <th className="text-left py-1">Name</th>
                </tr>
              </thead>
              <tbody>
                {structured.vlans.map((v, i) => (
                  <tr key={i} className="border-t border-surface-2">
                    <td className="py-1 pr-4 font-mono text-white">{v.id}</td>
                    <td className="py-1 text-gray-300">{v.name}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}

      {tab === "snmp" && (
        <>
          {!structured?.snmp || Object.keys(structured.snmp).length === 0 ? (
            <p className="text-xs text-gray-600">No SNMP OID data available.</p>
          ) : (
            <table className="w-full text-xs">
              <thead>
                <tr className="text-gray-600 text-[10px] uppercase tracking-wider">
                  <th className="text-left py-1 pr-4">OID</th>
                  <th className="text-left py-1">Value</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(structured.snmp).map(([oid, val]) => (
                  <tr key={oid} className="border-t border-surface-2">
                    <td className="py-1 pr-4 font-mono text-gray-400 text-[10px]">{oid}</td>
                    <td className="py-1 text-gray-300 break-all">{val}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}

      {tab === "config" && (
        <>
          {!detail.config_snapshot ? (
            <p className="text-xs text-gray-600">No configuration snapshot available.</p>
          ) : (
            <pre className="text-[10px] font-mono text-gray-300 bg-surface-2 rounded p-3 overflow-x-auto max-h-64 whitespace-pre-wrap">
              {detail.config_snapshot}
            </pre>
          )}
        </>
      )}
    </div>
  );
}

export default function Devices() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");

  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [detailCache, setDetailCache] = useState<Record<string, DeviceDetail>>({});
  const [detailLoading, setDetailLoading] = useState(false);

  useEffect(() => {
    apiFetch<Device[]>("/api/v1/inventory/devices")
      .then(setDevices)
      .catch((e: unknown) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const toggleExpand = async (id: string) => {
    if (expandedId === id) {
      setExpandedId(null);
      return;
    }
    setExpandedId(id);
    if (detailCache[id]) return;
    setDetailLoading(true);
    try {
      const detail = await apiFetch<DeviceDetail>(`/api/v1/inventory/devices/${id}`);
      setDetailCache((prev) => ({ ...prev, [id]: detail }));
    } catch {
      // leave cache empty; panel will show empty state
    } finally {
      setDetailLoading(false);
    }
  };

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
                <th className="w-8 px-2 py-3" />
                <th className="text-left px-4 py-3">IP Address</th>
                <th className="text-left px-4 py-3">Hostname</th>
                <th className="text-left px-4 py-3">Type</th>
                <th className="text-left px-4 py-3">Vendor / Model</th>
                <th className="text-left px-4 py-3">Firmware</th>
                <th className="text-left px-4 py-3">Last seen</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-6 text-center text-gray-600 text-xs">
                    {search
                      ? "No devices match your search."
                      : "No network devices discovered yet. Deploy an agent with NETMIKO_ENABLED=true."}
                  </td>
                </tr>
              ) : (
                filtered.flatMap((d) => [
                  <tr
                    key={d.id}
                    className="border-b border-surface-2 hover:bg-surface-2 transition-colors cursor-pointer"
                    onClick={() => toggleExpand(d.id)}
                  >
                    <td className="px-2 py-3 text-center">
                      <svg
                        className={`w-3 h-3 mx-auto text-gray-500 transition-transform ${expandedId === d.id ? "rotate-90" : ""}`}
                        fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
                      >
                        <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
                      </svg>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-white">{d.ip_address}</td>
                    <td className="px-4 py-3 text-xs text-gray-300">{d.hostname ?? "—"}</td>
                    <td className="px-4 py-3 text-xs">
                      <DeviceTypeBadge type={d.device_type} />
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-400">
                      {[d.vendor, d.model].filter(Boolean).join(" ") || "—"}
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-500 font-mono">
                      {d.firmware_version ?? "—"}
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-500">
                      {new Date(d.last_seen).toLocaleString()}
                    </td>
                  </tr>,
                  expandedId === d.id && (
                    <tr key={`${d.id}-detail`} className="border-b border-surface-2 bg-surface-1">
                      <td colSpan={7} className="px-6 py-4">
                        <DetailPanel
                          detail={detailCache[d.id] ?? null}
                          loading={detailLoading && !detailCache[d.id]}
                        />
                      </td>
                    </tr>
                  ),
                ])
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
