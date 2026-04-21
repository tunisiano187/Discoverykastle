const BASE = "";

function token(): string | null {
  return localStorage.getItem("dk_token");
}

export function setToken(t: string): void {
  localStorage.setItem("dk_token", t);
}

export function clearToken(): void {
  localStorage.removeItem("dk_token");
}

export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const tok = token();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init?.headers as Record<string, string>),
  };
  if (tok) headers["Authorization"] = `Bearer ${tok}`;

  const res = await fetch(`${BASE}${path}`, { ...init, headers });
  if (res.status === 401) {
    clearToken();
    window.location.href = "/login";
    throw new Error("Unauthorized");
  }
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || res.statusText);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export function wsUrl(path: string): string {
  const tok = token();
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const qs = tok ? `?token=${encodeURIComponent(tok)}` : "";
  return `${proto}://${location.host}${path}${qs}`;
}
