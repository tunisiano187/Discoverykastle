import { apiFetch } from "./client";

export interface Agent {
  id: string;
  hostname: string;
  ip_address: string;
  status: "online" | "offline";
  platform: string | null;
  version: string | null;
  last_seen: string | null;
}

export const getAgents = () => apiFetch<Agent[]>("/api/v1/agents");
