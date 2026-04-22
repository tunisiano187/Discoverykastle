import { apiFetch } from "./client";

export interface Host {
  id: string;
  fqdn: string | null;
  ip_addresses: string[];
  os: string | null;
  os_version: string | null;
  first_seen: string;
  last_seen: string;
}

export const getHosts = (limit = 100, offset = 0) =>
  apiFetch<Host[]>(`/api/v1/inventory/hosts?limit=${limit}&offset=${offset}`);
