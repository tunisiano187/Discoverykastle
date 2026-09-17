import { apiFetch } from "./client";

export interface Network {
  id: string;
  cidr: string;
  description: string | null;
  domain_name: string | null;
  scan_authorized: boolean;
  scan_depth: number;
  ip_class: "private" | "public" | "mixed" | "unknown";
  created_at: string;
}

export interface AuthRequest {
  id: string;
  agent_id: string;
  request_type: string;
  details: Record<string, unknown>;
  status: "pending" | "approved" | "denied";
  requested_at: string;
  resolved_at: string | null;
  resolved_by: string | null;
}

export interface ScanResult {
  id: string;
  network_id: string | null;
  agent_id: string;
  started_at: string;
  completed_at: string | null;
  hosts_found: string[];
  created_at: string;
}

export interface TopologyEdge {
  id: string;
  source_host_id: string;
  target_host_id: string;
  edge_type: string;
}

export const getNetworks = (authorizedOnly = false) =>
  apiFetch<Network[]>(
    `/api/v1/inventory/networks${authorizedOnly ? "?authorized=true" : ""}`
  );

export const requestPublicScan = (networkId: string) =>
  apiFetch<{ detail: string }>(
    `/api/v1/inventory/networks/${networkId}/request-public-scan`,
    { method: "POST" }
  );

export const getAuthRequests = () =>
  apiFetch<AuthRequest[]>("/api/v1/inventory/authorization-requests");

export const approveAuthRequest = (id: string) =>
  apiFetch<{ detail: string }>(
    `/api/v1/inventory/authorization-requests/${id}/approve`,
    { method: "POST" }
  );

export const denyAuthRequest = (id: string) =>
  apiFetch<{ detail: string }>(
    `/api/v1/inventory/authorization-requests/${id}/deny`,
    { method: "POST" }
  );

export const getScanResults = (networkId?: string, limit = 50) =>
  apiFetch<ScanResult[]>(
    `/api/v1/inventory/scan-results?limit=${limit}${networkId ? `&network_id=${networkId}` : ""}`
  );

export const getNetworkScanResults = (networkId: string, limit = 20) =>
  apiFetch<ScanResult[]>(
    `/api/v1/inventory/networks/${networkId}/scan-results?limit=${limit}`
  );

export const getTopologyEdges = () =>
  apiFetch<{ nodes: unknown[]; edges: TopologyEdge[] }>("/api/v1/topology").then(
    (r) => r.edges ?? []
  );
