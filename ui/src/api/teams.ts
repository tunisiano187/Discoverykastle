import { apiFetch } from "./client";

export interface Team {
  id: string;
  name: string;
  description: string | null;
  created_by: string;
}

export interface Member {
  username: string;
  role: string;
}

export interface TeamDetail extends Team {
  members: Member[];
}

export const getTeams = () => apiFetch<Team[]>("/api/v1/teams");

export const getTeam = (id: string) => apiFetch<TeamDetail>(`/api/v1/teams/${id}`);

export const createTeam = (name: string, description?: string) =>
  apiFetch<Team>("/api/v1/teams", {
    method: "POST",
    body: JSON.stringify({ name, description: description || null }),
  });

export const deleteTeam = (id: string) =>
  apiFetch<void>(`/api/v1/teams/${id}`, { method: "DELETE" });

export const addMember = (teamId: string, username: string, role: string) =>
  apiFetch<void>(`/api/v1/teams/${teamId}/members`, {
    method: "POST",
    body: JSON.stringify({ username, role }),
  });

export const removeMember = (teamId: string, username: string) =>
  apiFetch<void>(`/api/v1/teams/${teamId}/members/${username}`, {
    method: "DELETE",
  });
