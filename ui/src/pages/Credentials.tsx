import { useEffect, useState } from "react";
import { useAuth } from "../hooks/useAuth";
import {
  listCredentials,
  createCredential,
  deleteCredential,
  type Credential,
} from "../api/credentials";

// ---------------------------------------------------------------------------
// Credential-type definitions
// ---------------------------------------------------------------------------

type FieldDef = { key: string; label: string; type?: "text" | "password"; required?: boolean };

const CRED_TYPES: Record<string, { label: string; fields: FieldDef[] }> = {
  ssh: {
    label: "SSH",
    fields: [
      { key: "username", label: "Username", required: true },
      { key: "password", label: "Password", type: "password" },
      { key: "private_key", label: "Private key (PEM)", type: "password" },
    ],
  },
  snmp: {
    label: "SNMP",
    fields: [
      { key: "community", label: "Community string", required: true },
      { key: "version", label: "Version (v1 / v2c / v3)", required: true },
    ],
  },
  api_key: {
    label: "API key",
    fields: [
      { key: "api_key", label: "API key", type: "password", required: true },
      { key: "endpoint", label: "Endpoint URL" },
    ],
  },
  password: {
    label: "Password",
    fields: [
      { key: "username", label: "Username", required: true },
      { key: "password", label: "Password", type: "password", required: true },
    ],
  },
  custom: {
    label: "Custom (JSON)",
    fields: [],
  },
};

const CRED_TYPE_KEYS = Object.keys(CRED_TYPES) as (keyof typeof CRED_TYPES)[];

// ---------------------------------------------------------------------------
// Helper: type badge
// ---------------------------------------------------------------------------

function TypeBadge({ type }: { type: string }) {
  const colours: Record<string, string> = {
    ssh: "bg-blue-900 text-blue-300",
    snmp: "bg-purple-900 text-purple-300",
    api_key: "bg-amber-900 text-amber-300",
    password: "bg-green-900 text-green-300",
    custom: "bg-surface-3 text-gray-400",
  };
  return (
    <span
      className={`px-2 py-0.5 rounded text-[10px] font-mono ${
        colours[type] ?? colours.custom
      }`}
    >
      {CRED_TYPES[type]?.label ?? type}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Add credential modal
// ---------------------------------------------------------------------------

interface AddModalProps {
  onClose: () => void;
  onCreated: () => void;
}

function AddModal({ onClose, onCreated }: AddModalProps) {
  const [label, setLabel] = useState("");
  const [credType, setCredType] = useState<string>("ssh");
  const [deviceId, setDeviceId] = useState("");
  const [fields, setFields] = useState<Record<string, string>>({});
  const [customJson, setCustomJson] = useState("{}");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  function setField(key: string, value: string) {
    setFields((prev) => ({ ...prev, [key]: value }));
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");

    let data: Record<string, string>;
    if (credType === "custom") {
      try {
        data = JSON.parse(customJson);
        if (typeof data !== "object" || Array.isArray(data)) {
          throw new Error("Must be a JSON object");
        }
      } catch (err) {
        setError(`Invalid JSON: ${String(err)}`);
        return;
      }
    } else {
      // Filter out empty values
      data = Object.fromEntries(
        Object.entries(fields).filter(([, v]) => v.trim() !== "")
      );
    }

    setBusy(true);
    try {
      await createCredential({
        label: label.trim(),
        credential_type: credType,
        device_id: deviceId.trim() || null,
        data,
      });
      onCreated();
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  }

  const typeDef = CRED_TYPES[credType];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-surface-1 border border-surface-3 rounded-xl shadow-2xl w-full max-w-lg p-6 space-y-4 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-semibold text-white">New credential</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-white transition-colors">
            ✕
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-3">
          {/* Label */}
          <div>
            <label className="text-xs text-gray-500 block mb-1">Label *</label>
            <input
              autoFocus
              type="text"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="e.g. prod-router-ssh"
              className="w-full bg-surface-2 border border-surface-3 rounded px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-brand"
              required
            />
          </div>

          {/* Type */}
          <div>
            <label className="text-xs text-gray-500 block mb-1">Type *</label>
            <select
              value={credType}
              onChange={(e) => {
                setCredType(e.target.value);
                setFields({});
                setCustomJson("{}");
              }}
              className="w-full bg-surface-2 border border-surface-3 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-brand"
            >
              {CRED_TYPE_KEYS.map((k) => (
                <option key={k} value={k}>
                  {CRED_TYPES[k].label}
                </option>
              ))}
            </select>
          </div>

          {/* Device ID (optional) */}
          <div>
            <label className="text-xs text-gray-500 block mb-1">
              Device ID <span className="text-gray-600">(optional UUID)</span>
            </label>
            <input
              type="text"
              value={deviceId}
              onChange={(e) => setDeviceId(e.target.value)}
              placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
              className="w-full bg-surface-2 border border-surface-3 rounded px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-brand font-mono"
            />
          </div>

          {/* Type-specific fields */}
          {credType !== "custom" ? (
            typeDef.fields.map((f) => (
              <div key={f.key}>
                <label className="text-xs text-gray-500 block mb-1">
                  {f.label}
                  {f.required && <span className="text-brand ml-1">*</span>}
                </label>
                <input
                  type={f.type ?? "text"}
                  value={fields[f.key] ?? ""}
                  onChange={(e) => setField(f.key, e.target.value)}
                  className="w-full bg-surface-2 border border-surface-3 rounded px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-brand"
                  required={f.required}
                />
              </div>
            ))
          ) : (
            <div>
              <label className="text-xs text-gray-500 block mb-1">
                Data <span className="text-brand ml-1">*</span>
                <span className="text-gray-600 ml-1">(JSON object)</span>
              </label>
              <textarea
                value={customJson}
                onChange={(e) => setCustomJson(e.target.value)}
                rows={6}
                className="w-full bg-surface-2 border border-surface-3 rounded px-3 py-2 text-sm text-white font-mono placeholder-gray-600 focus:outline-none focus:border-brand resize-y"
                spellCheck={false}
              />
            </div>
          )}

          {error && <p className="text-red-400 text-xs">{error}</p>}

          <div className="flex justify-end gap-2 pt-1">
            <button
              type="button"
              onClick={onClose}
              className="text-gray-400 hover:text-white text-sm px-3 py-1.5 rounded transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={busy || !label.trim()}
              className="bg-brand hover:bg-brand/80 disabled:opacity-40 text-white text-sm px-4 py-1.5 rounded transition-colors"
            >
              {busy ? "Saving…" : "Save"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export default function Credentials() {
  const { role } = useAuth();
  const isAdmin = role === "admin";
  const canWrite = role === "admin" || role === "operator";

  const [creds, setCreds] = useState<Credential[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // Filters
  const [filterType, setFilterType] = useState("");
  const [filterLabel, setFilterLabel] = useState("");

  // Modal
  const [showAdd, setShowAdd] = useState(false);

  // Delete state
  const [deletingId, setDeletingId] = useState<string | null>(null);

  function loadCreds() {
    setLoading(true);
    setError("");
    listCredentials({
      credential_type: filterType || undefined,
      label: filterLabel || undefined,
    })
      .then(setCreds)
      .catch((e: unknown) => setError(String(e)))
      .finally(() => setLoading(false));
  }

  // Reload when filters change (debounced label)
  useEffect(() => {
    const t = setTimeout(loadCreds, filterLabel ? 300 : 0);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filterType, filterLabel]);

  async function handleDelete(id: string, label: string) {
    if (!confirm(`Delete credential "${label}"? This cannot be undone.`)) return;
    setDeletingId(id);
    try {
      await deleteCredential(id);
      setCreds((prev) => prev.filter((c) => c.id !== id));
    } catch (e: unknown) {
      setError(String(e));
    } finally {
      setDeletingId(null);
    }
  }

  return (
    <div className="p-6 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-xl font-semibold text-white">Credentials</h1>
        {canWrite && (
          <button
            onClick={() => setShowAdd(true)}
            className="bg-brand hover:bg-brand/80 text-white text-sm px-3 py-1.5 rounded-md transition-colors"
          >
            + Add credential
          </button>
        )}
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <input
          type="text"
          value={filterLabel}
          onChange={(e) => setFilterLabel(e.target.value)}
          placeholder="Search label…"
          className="bg-surface-1 border border-surface-3 rounded px-3 py-1.5 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-brand w-56"
        />
        <select
          value={filterType}
          onChange={(e) => setFilterType(e.target.value)}
          className="bg-surface-1 border border-surface-3 rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-brand"
        >
          <option value="">All types</option>
          {CRED_TYPE_KEYS.map((k) => (
            <option key={k} value={k}>
              {CRED_TYPES[k].label}
            </option>
          ))}
        </select>
        <button
          onClick={loadCreds}
          className="text-gray-500 hover:text-white text-sm transition-colors"
          title="Refresh"
        >
          ↺ Refresh
        </button>
      </div>

      {loading && <p className="text-gray-500 text-sm">Loading…</p>}
      {error && <p className="text-red-400 text-sm">{error}</p>}

      {!loading && !error && (
        <div className="bg-surface-1 border border-surface-3 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-surface-3 text-xs text-gray-500">
                <th className="text-left px-4 py-3">Label</th>
                <th className="text-left px-4 py-3">Type</th>
                <th className="text-left px-4 py-3">Device ID</th>
                <th className="text-left px-4 py-3">Created by</th>
                <th className="text-left px-4 py-3">Created at</th>
                {isAdmin && <th className="px-4 py-3 w-10" />}
              </tr>
            </thead>
            <tbody>
              {creds.length === 0 ? (
                <tr>
                  <td
                    colSpan={isAdmin ? 6 : 5}
                    className="px-4 py-8 text-center text-gray-600 text-xs"
                  >
                    {filterLabel || filterType
                      ? "No credentials match these filters."
                      : canWrite
                      ? 'No credentials yet. Click "+ Add credential" to store your first one.'
                      : "No credentials stored yet."}
                  </td>
                </tr>
              ) : (
                creds.map((c) => (
                  <tr
                    key={c.id}
                    className="border-b border-surface-2 last:border-0 hover:bg-surface-2 transition-colors"
                  >
                    <td className="px-4 py-3 font-medium text-white text-sm">
                      {c.label}
                    </td>
                    <td className="px-4 py-3">
                      <TypeBadge type={c.credential_type} />
                    </td>
                    <td className="px-4 py-3 font-mono text-[10px] text-gray-500">
                      {c.device_id
                        ? c.device_id.slice(0, 8) + "…"
                        : <span className="text-gray-700">—</span>}
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-400">{c.created_by}</td>
                    <td className="px-4 py-3 text-xs text-gray-500">
                      {new Date(c.created_at).toLocaleString()}
                    </td>
                    {isAdmin && (
                      <td className="px-4 py-3 text-right">
                        <button
                          onClick={() => handleDelete(c.id, c.label)}
                          disabled={deletingId === c.id}
                          className="text-gray-600 hover:text-red-400 transition-colors text-xs px-2 py-1 rounded"
                          title="Delete credential"
                        >
                          {deletingId === c.id ? "…" : "✕"}
                        </button>
                      </td>
                    )}
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Vault info banner */}
      <p className="text-[11px] text-gray-600 flex items-center gap-1.5">
        <span>🔒</span>
        Credentials are encrypted with AES-256-GCM. Plaintext is never stored.
      </p>

      {/* Add modal */}
      {showAdd && (
        <AddModal
          onClose={() => setShowAdd(false)}
          onCreated={() => {
            setShowAdd(false);
            loadCreds();
          }}
        />
      )}
    </div>
  );
}
