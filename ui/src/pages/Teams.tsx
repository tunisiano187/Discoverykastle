import { useEffect, useState } from "react";
import { useAuth } from "../hooks/useAuth";
import {
  getTeams,
  getTeam,
  createTeam,
  deleteTeam,
  addMember,
  removeMember,
  type Team,
  type TeamDetail,
} from "../api/teams";

const ROLES = ["viewer", "analyst", "operator", "admin"] as const;

function RoleBadge({ role }: { role: string }) {
  const colours: Record<string, string> = {
    admin: "bg-red-900 text-red-300",
    operator: "bg-amber-900 text-amber-300",
    analyst: "bg-blue-900 text-blue-300",
    viewer: "bg-surface-3 text-gray-400",
  };
  return (
    <span
      className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase ${
        colours[role] ?? colours.viewer
      }`}
    >
      {role}
    </span>
  );
}

export default function Teams() {
  const { role: myRole } = useAuth();
  const isAdmin = myRole === "admin";

  const [teams, setTeams] = useState<Team[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // Expanded team detail
  const [expanded, setExpanded] = useState<string | null>(null);
  const [detail, setDetail] = useState<TeamDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState("");

  // Create team modal
  const [showCreate, setShowCreate] = useState(false);
  const [createName, setCreateName] = useState("");
  const [createDesc, setCreateDesc] = useState("");
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState("");

  // Add member form
  const [addUsername, setAddUsername] = useState("");
  const [addRole, setAddRole] = useState<string>("viewer");
  const [addError, setAddError] = useState("");
  const [addBusy, setAddBusy] = useState(false);

  // Delete busy set
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [removingUser, setRemovingUser] = useState<string | null>(null);

  function loadTeams() {
    setLoading(true);
    setError("");
    getTeams()
      .then(setTeams)
      .catch((e: unknown) => setError(String(e)))
      .finally(() => setLoading(false));
  }

  useEffect(loadTeams, []);

  function toggleExpand(id: string) {
    if (expanded === id) {
      setExpanded(null);
      setDetail(null);
      setDetailError("");
      return;
    }
    setExpanded(id);
    setDetail(null);
    setDetailError("");
    setAddUsername("");
    setAddRole("viewer");
    setAddError("");
    setDetailLoading(true);
    getTeam(id)
      .then(setDetail)
      .catch((e: unknown) => setDetailError(String(e)))
      .finally(() => setDetailLoading(false));
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!createName.trim()) return;
    setCreating(true);
    setCreateError("");
    try {
      await createTeam(createName.trim(), createDesc.trim() || undefined);
      setShowCreate(false);
      setCreateName("");
      setCreateDesc("");
      loadTeams();
    } catch (e: unknown) {
      setCreateError(String(e));
    } finally {
      setCreating(false);
    }
  }

  async function handleDelete(id: string, name: string) {
    if (!confirm(`Delete team "${name}"? This cannot be undone.`)) return;
    setDeletingId(id);
    try {
      await deleteTeam(id);
      if (expanded === id) {
        setExpanded(null);
        setDetail(null);
      }
      loadTeams();
    } catch (e: unknown) {
      setError(String(e));
    } finally {
      setDeletingId(null);
    }
  }

  async function handleAddMember(e: React.FormEvent) {
    e.preventDefault();
    if (!expanded || !addUsername.trim()) return;
    setAddBusy(true);
    setAddError("");
    try {
      await addMember(expanded, addUsername.trim(), addRole);
      setAddUsername("");
      // Refresh detail
      const d = await getTeam(expanded);
      setDetail(d);
    } catch (e: unknown) {
      setAddError(String(e));
    } finally {
      setAddBusy(false);
    }
  }

  async function handleRemoveMember(username: string) {
    if (!expanded) return;
    setRemovingUser(username);
    setAddError("");
    try {
      await removeMember(expanded, username);
      const d = await getTeam(expanded);
      setDetail(d);
    } catch (e: unknown) {
      setAddError(String(e));
    } finally {
      setRemovingUser(null);
    }
  }

  return (
    <div className="p-6 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-xl font-semibold text-white">Teams</h1>
        {isAdmin && (
          <button
            onClick={() => setShowCreate(true)}
            className="bg-brand hover:bg-brand/80 text-white text-sm px-3 py-1.5 rounded-md transition-colors"
          >
            + New team
          </button>
        )}
      </div>

      {loading && <p className="text-gray-500 text-sm">Loading…</p>}
      {error && <p className="text-red-400 text-sm">{error}</p>}

      {/* Team list */}
      {!loading && (
        <div className="space-y-2">
          {teams.length === 0 && (
            <p className="text-gray-600 text-sm py-6 text-center">
              No teams yet.{" "}
              {isAdmin ? 'Click "+ New team" to create one.' : "Ask an admin to create one."}
            </p>
          )}

          {teams.map((team) => {
            const open = expanded === team.id;
            return (
              <div
                key={team.id}
                className="bg-surface-1 border border-surface-3 rounded-xl overflow-hidden"
              >
                {/* Team row */}
                <div
                  className="flex items-center justify-between px-5 py-4 cursor-pointer hover:bg-surface-2 transition-colors"
                  onClick={() => toggleExpand(team.id)}
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <span className="text-base">{open ? "▾" : "▸"}</span>
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-white truncate">{team.name}</p>
                      {team.description && (
                        <p className="text-xs text-gray-500 truncate">{team.description}</p>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-3 flex-shrink-0">
                    <span className="text-xs text-gray-600">by {team.created_by}</span>
                    {isAdmin && (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleDelete(team.id, team.name);
                        }}
                        disabled={deletingId === team.id}
                        className="text-gray-600 hover:text-red-400 transition-colors text-xs px-2 py-1 rounded"
                        title="Delete team"
                      >
                        {deletingId === team.id ? "…" : "✕"}
                      </button>
                    )}
                  </div>
                </div>

                {/* Expanded: members */}
                {open && (
                  <div className="border-t border-surface-3 px-5 py-4 space-y-4 bg-surface-0/40">
                    {detailLoading && (
                      <p className="text-gray-500 text-xs">Loading members…</p>
                    )}
                    {detailError && (
                      <p className="text-red-400 text-xs">{detailError}</p>
                    )}

                    {detail && (
                      <>
                        <div>
                          <p className="text-xs text-gray-500 uppercase tracking-wide mb-2">
                            Members ({detail.members.length})
                          </p>
                          {detail.members.length === 0 ? (
                            <p className="text-gray-600 text-xs">No members yet.</p>
                          ) : (
                            <table className="w-full text-sm">
                              <thead>
                                <tr className="text-xs text-gray-500">
                                  <th className="text-left py-1">Username</th>
                                  <th className="text-left py-1">Role</th>
                                  {isAdmin && <th className="py-1 w-10" />}
                                </tr>
                              </thead>
                              <tbody>
                                {detail.members.map((m) => (
                                  <tr
                                    key={m.username}
                                    className="border-t border-surface-2"
                                  >
                                    <td className="py-2 text-xs font-mono text-white">
                                      {m.username}
                                    </td>
                                    <td className="py-2">
                                      <RoleBadge role={m.role} />
                                    </td>
                                    {isAdmin && (
                                      <td className="py-2 text-right">
                                        <button
                                          onClick={() => handleRemoveMember(m.username)}
                                          disabled={removingUser === m.username}
                                          className="text-gray-600 hover:text-red-400 transition-colors text-xs"
                                          title="Remove member"
                                        >
                                          {removingUser === m.username ? "…" : "✕"}
                                        </button>
                                      </td>
                                    )}
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          )}
                        </div>

                        {/* Add member form (admin only) */}
                        {isAdmin && (
                          <form
                            onSubmit={handleAddMember}
                            className="flex items-center gap-2 pt-2 border-t border-surface-2"
                          >
                            <input
                              type="text"
                              placeholder="username"
                              value={addUsername}
                              onChange={(e) => setAddUsername(e.target.value)}
                              className="bg-surface-2 border border-surface-3 rounded px-3 py-1 text-xs text-white placeholder-gray-600 focus:outline-none focus:border-brand flex-1"
                            />
                            <select
                              value={addRole}
                              onChange={(e) => setAddRole(e.target.value)}
                              className="bg-surface-2 border border-surface-3 rounded px-2 py-1 text-xs text-white focus:outline-none focus:border-brand"
                            >
                              {ROLES.map((r) => (
                                <option key={r} value={r}>
                                  {r}
                                </option>
                              ))}
                            </select>
                            <button
                              type="submit"
                              disabled={addBusy || !addUsername.trim()}
                              className="bg-brand hover:bg-brand/80 disabled:opacity-40 text-white text-xs px-3 py-1 rounded transition-colors"
                            >
                              {addBusy ? "Adding…" : "Add"}
                            </button>
                          </form>
                        )}
                        {addError && (
                          <p className="text-red-400 text-xs">{addError}</p>
                        )}
                      </>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Create team modal */}
      {showCreate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="bg-surface-1 border border-surface-3 rounded-xl shadow-2xl w-full max-w-md p-6 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-base font-semibold text-white">New team</h2>
              <button
                onClick={() => {
                  setShowCreate(false);
                  setCreateName("");
                  setCreateDesc("");
                  setCreateError("");
                }}
                className="text-gray-500 hover:text-white transition-colors"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreate} className="space-y-3">
              <div>
                <label className="text-xs text-gray-500 block mb-1">Team name *</label>
                <input
                  autoFocus
                  type="text"
                  value={createName}
                  onChange={(e) => setCreateName(e.target.value)}
                  placeholder="e.g. Security, DevOps, Network"
                  className="w-full bg-surface-2 border border-surface-3 rounded px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-brand"
                />
              </div>
              <div>
                <label className="text-xs text-gray-500 block mb-1">Description (optional)</label>
                <input
                  type="text"
                  value={createDesc}
                  onChange={(e) => setCreateDesc(e.target.value)}
                  placeholder="Short description…"
                  className="w-full bg-surface-2 border border-surface-3 rounded px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-brand"
                />
              </div>

              {createError && <p className="text-red-400 text-xs">{createError}</p>}

              <div className="flex justify-end gap-2 pt-1">
                <button
                  type="button"
                  onClick={() => {
                    setShowCreate(false);
                    setCreateName("");
                    setCreateDesc("");
                    setCreateError("");
                  }}
                  className="text-gray-400 hover:text-white text-sm px-3 py-1.5 rounded transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating || !createName.trim()}
                  className="bg-brand hover:bg-brand/80 disabled:opacity-40 text-white text-sm px-4 py-1.5 rounded transition-colors"
                >
                  {creating ? "Creating…" : "Create"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
