import { apiFetch } from "./client";

export interface Host {
  id: string;
  fqdn: string | null;
  ip_addresses: string[];
  os: string | null;
  os_version: string | null;
  first_seen: string;
  last_seen: string;
  team_id: string | null;
}

export const getHosts = (limit = 100, offset = 0) =>
  apiFetch<Host[]>(`/api/v1/inventory/hosts?limit=${limit}&offset=${offset}`);

export const assignHostTeam = (hostId: string, teamId: string | null) =>
  apiFetch<Host>(`/api/v1/inventory/hosts/${hostId}/team`, {
    method: "PATCH",
    body: JSON.stringify({ team_id: teamId }),
  });
