import { useEffect, useState } from "react";
import { getHosts, assignHostTeam, Host } from "../api/hosts";
import { getTeams, Team } from "../api/teams";
import { useAuth } from "../hooks/useAuth";

export default function Hosts() {
  const { role } = useAuth();
  const [hosts, setHosts] = useState<Host[]>([]);
  const [teams, setTeams] = useState<Team[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  // hostId → pending/error state for team picker
  const [assigning, setAssigning] = useState<Record<string, boolean>>({});
  const [assignError, setAssignError] = useState<Record<string, string>>({});

  useEffect(() => {
    Promise.all([getHosts(200), getTeams()])
      .then(([h, t]) => {
        setHosts(h);
        setTeams(t);
      })
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

  const teamMap = Object.fromEntries(teams.map((t) => [t.id, t.name]));
  const isAdmin = role === "admin";

  async function handleTeamChange(hostId: string, teamId: string | null) {
    setAssigning((p) => ({ ...p, [hostId]: true }));
    setAssignError((p) => ({ ...p, [hostId]: "" }));
    try {
      const updated = await assignHostTeam(hostId, teamId);
      setHosts((prev) =>
        prev.map((h) => (h.id === hostId ? { ...h, team_id: updated.team_id } : h))
      );
    } catch (e: unknown) {
      setAssignError((p) => ({ ...p, [hostId]: String(e) }));
    } finally {
      setAssigning((p) => ({ ...p, [hostId]: false }));
    }
  }

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
                <th className="text-left px-4 py-3">Team</th>
                <th className="text-left px-4 py-3">First seen</th>
                <th className="text-left px-4 py-3">Last seen</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-6 text-center text-gray-600 text-xs">
                    {search ? "No hosts match your search." : "No hosts discovered."}
                  </td>
                </tr>
              ) : (
                filtered.map((h) => (
                  <tr
                    key={h.id}
                    className="border-b border-surface-2 last:border-0 hover:bg-surface-2 transition-colors"
                  >
                    <td className="px-4 py-3 font-mono text-xs text-white">{h.fqdn ?? "—"}</td>
                    <td className="px-4 py-3 font-mono text-xs text-gray-400">
                      {h.ip_addresses.join(", ") || "—"}
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-400">
                      {h.os ? `${h.os}${h.os_version ? ` ${h.os_version}` : ""}` : "—"}
                    </td>
                    <td className="px-4 py-3 text-xs">
                      {isAdmin ? (
                        <div className="flex flex-col gap-1">
                          <select
                            value={h.team_id ?? ""}
                            disabled={assigning[h.id]}
                            onChange={(e) =>
                              handleTeamChange(h.id, e.target.value || null)
                            }
                            className="bg-surface-2 border border-surface-3 rounded px-2 py-1 text-xs text-white focus:outline-none focus:border-brand disabled:opacity-50 max-w-[160px]"
                          >
                            <option value="">— unassigned —</option>
                            {teams.map((t) => (
                              <option key={t.id} value={t.id}>
                                {t.name}
                              </option>
                            ))}
                          </select>
                          {assignError[h.id] && (
                            <span className="text-red-400 text-xs">{assignError[h.id]}</span>
                          )}
                        </div>
                      ) : (
                        <span className="text-gray-400">
                          {h.team_id ? (teamMap[h.team_id] ?? h.team_id) : "—"}
                        </span>
                      )}
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
