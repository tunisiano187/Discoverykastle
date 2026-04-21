import { useEffect, useRef, useState } from "react";
import { wsUrl } from "../api/client";

export interface WSEvent {
  type: string;
  [key: string]: unknown;
}

export interface DashboardState {
  connectedAgents: string[];
  events: WSEvent[];
  connected: boolean;
}

export function useDashboardWS(): DashboardState {
  const [connectedAgents, setConnectedAgents] = useState<string[]>([]);
  const [events, setEvents] = useState<WSEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    const token = localStorage.getItem("dk_token");
    if (!token) return;

    let ws: WebSocket;
    let reconnectTimer: ReturnType<typeof setTimeout>;

    const connect = () => {
      ws = new WebSocket(wsUrl("/api/v1/ws/dashboard"));
      wsRef.current = ws;

      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        reconnectTimer = setTimeout(connect, 5000);
      };
      ws.onerror = () => ws.close();

      ws.onmessage = (e: MessageEvent) => {
        const msg = JSON.parse(e.data as string) as WSEvent;
        if (msg.type === "connected_agents") {
          setConnectedAgents(msg.agent_ids as string[]);
        } else if (msg.type === "agent_connected") {
          setConnectedAgents((prev) =>
            prev.includes(msg.agent_id as string) ? prev : [...prev, msg.agent_id as string],
          );
        } else if (msg.type === "agent_disconnected") {
          setConnectedAgents((prev) => prev.filter((id) => id !== (msg.agent_id as string)));
        }
        setEvents((prev) => [msg, ...prev].slice(0, 50));
      };
    };

    connect();

    return () => {
      clearTimeout(reconnectTimer);
      wsRef.current?.close();
    };
  }, []);

  return { connectedAgents, events, connected };
}
