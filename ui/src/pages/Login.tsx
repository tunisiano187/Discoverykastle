import { FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../hooks/useAuth";

export default function Login() {
  const { login } = useAuth();
  const nav = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await login(username, password);
      nav("/", { replace: true });
    } catch {
      setError("Invalid username or password.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex h-screen items-center justify-center bg-surface-0">
      <div className="w-full max-w-sm space-y-6">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-brand">Discoverykastle</h1>
          <p className="mt-1 text-sm text-gray-500">Operator login</p>
        </div>

        <form onSubmit={submit} className="bg-surface-1 rounded-xl border border-surface-3 p-6 space-y-4">
          {error && (
            <p className="text-sm text-red-400 bg-red-950 border border-red-800 rounded px-3 py-2">
              {error}
            </p>
          )}
          <div>
            <label className="block text-xs text-gray-400 mb-1">Username</label>
            <input
              type="text"
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              className="w-full bg-surface-2 border border-surface-3 rounded-md px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-brand"
            />
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">Password</label>
            <input
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="w-full bg-surface-2 border border-surface-3 rounded-md px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-brand"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="w-full bg-brand text-surface-0 font-semibold text-sm py-2 rounded-md hover:opacity-90 disabled:opacity-50 transition-opacity"
          >
            {loading ? "Signing in…" : "Sign in"}
          </button>
        </form>
      </div>
    </div>
  );
}
