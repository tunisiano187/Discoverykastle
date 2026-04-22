import { createContext, useContext, useEffect, useState } from "react";
import { apiFetch, clearToken, setToken } from "../api/client";

interface AuthState {
  username: string | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
}

export const AuthContext = createContext<AuthState>({
  username: null,
  loading: true,
  login: async () => {},
  logout: () => {},
});

export function useAuth(): AuthState {
  return useContext(AuthContext);
}

export function useAuthProvider(): AuthState {
  const [username, setUsername] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!localStorage.getItem("dk_token")) {
      setLoading(false);
      return;
    }
    apiFetch<{ username: string }>("/api/v1/auth/me")
      .then((r) => setUsername(r.username))
      .catch(() => clearToken())
      .finally(() => setLoading(false));
  }, []);

  const login = async (user: string, password: string) => {
    const body = new URLSearchParams({ username: user, password });
    const res = await fetch("/api/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    if (!res.ok) throw new Error("Invalid credentials");
    const data = (await res.json()) as { access_token: string };
    setToken(data.access_token);
    setUsername(user);
  };

  const logout = () => {
    clearToken();
    setUsername(null);
  };

  return { username, loading, login, logout };
}
