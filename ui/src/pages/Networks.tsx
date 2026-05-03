import { useEffect, useState } from "react";
import {
  getNetworks,
  getAuthRequests,
  requestPublicScan,
  approveAuthRequest,
  denyAuthRequest,
  Network,
  AuthRequest,
} from "../api/networks";

function IpClassBadge({ cls }: { cls: string }) {
  const styles: Record<string, string> = {
    private: "bg-green-900/40 text-green-300 border-green-800",
    public: "bg-yellow-900/40 text-yellow-300 border-yellow-800",
    mixed: "bg-orange-900/40 text-orange-300 border-orange-800",
    unknown: "bg-gray-800 text-gray-400 border-gray-700",
  };
  return (
    <span
      className={`inline-block px-2 py-0.5 rounded text-[10px] font-mono border ${
        styles[cls] ?? styles.unknown
      }`}
    >
      {cls}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    pending: "bg-yellow-900/40 text-yellow-300 border-yellow-800",
    approved: "bg-green-900/40 text-green-300 border-green-800",
    denied: "bg-red-900/40 text-red-300 border-red-800",
  };
  return (
    <span
      className={`inline-block px-2 py-0.5 rounded text-[10px] font-mono border ${
        styles[status] ?? "bg-gray-800 text-gray-400 border-gray-700"
      }`}
    >
      {status}
    </span>
  );
}

export default function Networks() {
  const [networks, setNetworks] = useState<Network[]>([]);
  const [authRequests, setAuthRequests] = useState<AuthRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [tab, setTab] = useState<"networks" | "auth">("networks");
  const [actionMsg, setActionMsg] = useState("");

  const reload = () => {
    setLoading(true);
    Promise.all([getNetworks(), getAuthRequests()])
      .then(([nets, auths]) => {
        setNetworks(nets);
        setAuthRequests(auths);
      })
      .catch((e: unknown) => setError(String(e)))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    reload();
  }, []);

  const handleRequestScan = async (net: Network) => {
    try {
      await requestPublicScan(net.id);
      setActionMsg(`Scan authorization request sent for ${net.cidr}`);
      reload();
    } catch (e: unknown) {
      setActionMsg(`Error: ${String(e)}`);
    }
  };

  const handleApprove = async (id: string) => {
    try {
      await approveAuthRequest(id);
      setActionMsg("Request approved.");
      reload();
    } catch (e: unknown) {
      setActionMsg(`Error: ${String(e)}`);
    }
  };

  const handleDeny = async (id: string) => {
    try {
      await denyAuthRequest(id);
      setActionMsg("Request denied.");
      reload();
    } catch (e: unknown) {
      setActionMsg(`Error: ${String(e)}`);
    }
  };

  const pendingCount = authRequests.filter((r) => r.status === "pending").length;

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center gap-4">
        <h1 className="text-xl font-semibold text-white">Networks</h1>
        <div className="flex gap-2 ml-auto">
          <button
            onClick={() => setTab("networks")}
            className={`px-3 py-1.5 rounded-md text-sm transition-colors ${
              tab === "networks"
                ? "bg-surface-3 text-white"
                : "text-gray-400 hover:text-white hover:bg-surface-2"
            }`}
          >
            Networks
          </button>
          <button
            onClick={() => setTab("auth")}
            className={`px-3 py-1.5 rounded-md text-sm transition-colors relative ${
              tab === "auth"
                ? "bg-surface-3 text-white"
                : "text-gray-400 hover:text-white hover:bg-surface-2"
            }`}
          >
            Auth Requests
            {pendingCount > 0 && (
              <span className="absolute -top-1 -right-1 bg-yellow-500 text-black text-[9px] font-bold rounded-full w-4 h-4 flex items-center justify-center">
                {pendingCount}
              </span>
            )}
          </button>
        </div>
      </div>

      {actionMsg && (
        <p className="text-xs text-brand bg-brand/10 border border-brand/30 rounded px-3 py-2">
          {actionMsg}
        </p>
      )}

      {loading && <p className="text-gray-500 text-sm">Loading…</p>}
      {error && <p className="text-red-400 text-sm">{error}</p>}

      {!loading && !error && tab === "networks" && (
        <div className="bg-surface-1 border border-surface-3 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-surface-3 text-xs text-gray-500">
                <th className="text-left px-4 py-3">CIDR</th>
                <th className="text-left px-4 py-3">Class</th>
                <th className="text-left px-4 py-3">Domain</th>
                <th className="text-left px-4 py-3">Authorized</th>
                <th className="text-left px-4 py-3">Description</th>
                <th className="text-left px-4 py-3"></th>
              </tr>
            </thead>
            <tbody>
              {networks.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-6 text-center text-gray-600 text-xs">
                    No networks discovered yet.
                  </td>
                </tr>
              ) : (
                networks.map((net) => (
                  <tr
                    key={net.id}
                    className="border-b border-surface-2 last:border-0 hover:bg-surface-2 transition-colors"
                  >
                    <td className="px-4 py-3 font-mono text-xs text-white">{net.cidr}</td>
                    <td className="px-4 py-3">
                      <IpClassBadge cls={net.ip_class} />
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-400">
                      {net.domain_name ?? "—"}
                    </td>
                    <td className="px-4 py-3 text-xs">
                      {net.scan_authorized ? (
                        <span className="text-green-400">Yes</span>
                      ) : (
                        <span className="text-gray-600">No</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-500">
                      {net.description ?? "—"}
                    </td>
                    <td className="px-4 py-3 text-right">
                      {net.ip_class !== "private" && !net.scan_authorized && (
                        <button
                          onClick={() => handleRequestScan(net)}
                          className="text-xs px-2 py-1 rounded bg-yellow-900/40 text-yellow-300 border border-yellow-800 hover:bg-yellow-900/70 transition-colors"
                        >
                          Request scan
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {!loading && !error && tab === "auth" && (
        <div className="bg-surface-1 border border-surface-3 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-surface-3 text-xs text-gray-500">
                <th className="text-left px-4 py-3">Type</th>
                <th className="text-left px-4 py-3">Details</th>
                <th className="text-left px-4 py-3">Status</th>
                <th className="text-left px-4 py-3">Requested</th>
                <th className="text-left px-4 py-3"></th>
              </tr>
            </thead>
            <tbody>
              {authRequests.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-6 text-center text-gray-600 text-xs">
                    No authorization requests.
                  </td>
                </tr>
              ) : (
                authRequests.map((req) => (
                  <tr
                    key={req.id}
                    className="border-b border-surface-2 last:border-0 hover:bg-surface-2 transition-colors"
                  >
                    <td className="px-4 py-3 text-xs text-gray-300 font-mono">
                      {req.request_type}
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-400 font-mono max-w-xs truncate">
                      {JSON.stringify(req.details)}
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge status={req.status} />
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-500">
                      {new Date(req.requested_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-right">
                      {req.status === "pending" && (
                        <div className="flex gap-2 justify-end">
                          <button
                            onClick={() => handleApprove(req.id)}
                            className="text-xs px-2 py-1 rounded bg-green-900/40 text-green-300 border border-green-800 hover:bg-green-900/70 transition-colors"
                          >
                            Approve
                          </button>
                          <button
                            onClick={() => handleDeny(req.id)}
                            className="text-xs px-2 py-1 rounded bg-red-900/40 text-red-300 border border-red-800 hover:bg-red-900/70 transition-colors"
                          >
                            Deny
                          </button>
                        </div>
                      )}
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
