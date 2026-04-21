import { apiFetch } from "./client";

export interface VulnOut {
  id: string;
  cve_id: string;
  severity: string;
  cvss_score: number | null;
  description: string | null;
  host_id: string;
  host_fqdn: string | null;
  host_ip_addresses: string[];
  first_seen: string;
}

export interface SeverityCount {
  critical: number;
  high: number;
  medium: number;
  low: number;
  none: number;
  unknown: number;
}

export interface TopCve {
  cve_id: string;
  affected_hosts: number;
  severity: string;
  cvss_score: number | null;
}

export interface VulnSummary {
  total: number;
  unique_cves: number;
  affected_hosts: number;
  by_severity: SeverityCount;
  top_cves: TopCve[];
}

export const getVulns = (params?: { severity?: string; limit?: number; offset?: number }) => {
  const qs = new URLSearchParams();
  if (params?.severity) qs.set("severity", params.severity);
  if (params?.limit) qs.set("limit", String(params.limit));
  if (params?.offset) qs.set("offset", String(params.offset));
  const q = qs.toString();
  return apiFetch<VulnOut[]>(`/api/v1/vulns${q ? `?${q}` : ""}`);
};

export const getVulnSummary = () => apiFetch<VulnSummary>("/api/v1/vulns/summary");
