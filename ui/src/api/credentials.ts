import { apiFetch } from "./client";

export interface Credential {
  id: string;
  label: string;
  credential_type: string;
  device_id: string | null;
  created_by: string;
  updated_by: string | null;
  created_at: string;
  updated_at: string;
}

export interface CredentialCreate {
  label: string;
  credential_type: string;
  device_id?: string | null;
  data: Record<string, string>;
}

export interface CredentialUpdate {
  label?: string;
  device_id?: string | null;
  data?: Record<string, string>;
}

export const listCredentials = (params?: {
  credential_type?: string;
  label?: string;
  skip?: number;
  limit?: number;
}) => {
  const qs = new URLSearchParams();
  if (params?.credential_type) qs.set("credential_type", params.credential_type);
  if (params?.label) qs.set("label", params.label);
  if (params?.skip != null) qs.set("skip", String(params.skip));
  if (params?.limit != null) qs.set("limit", String(params.limit));
  const q = qs.toString();
  return apiFetch<Credential[]>(`/api/v1/vault/credentials${q ? `?${q}` : ""}`);
};

export const createCredential = (body: CredentialCreate) =>
  apiFetch<Credential>("/api/v1/vault/credentials", {
    method: "POST",
    body: JSON.stringify(body),
  });

export const updateCredential = (id: string, body: CredentialUpdate) =>
  apiFetch<Credential>(`/api/v1/vault/credentials/${id}`, {
    method: "PATCH",
    body: JSON.stringify(body),
  });

export const deleteCredential = (id: string) =>
  apiFetch<void>(`/api/v1/vault/credentials/${id}`, { method: "DELETE" });
