import { apiFetch } from "./client";

export interface Agent {
  id: string;
  hostname: string;
  ip_address: string;
  status: "online" | "offline";
  platform: string | null;
  version: string | null;
  last_seen: string | null;
  // Resource metrics — null when the agent has not sent them yet
  cpu_percent: number | null;
  memory_percent: number | null;
  disk_percent: number | null;
  last_heartbeat: string | null;
}

export const getAgents = () => apiFetch<Agent[]>("/api/v1/agents");
