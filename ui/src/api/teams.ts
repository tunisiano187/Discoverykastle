import { apiFetch } from "./client";

export interface Team {
  id: string;
  name: string;
  description: string | null;
  created_by: string;
}

export const getTeams = () => apiFetch<Team[]>("/api/v1/teams");
