import { useEffect, useRef, useState } from "react";
import { getTopologyEdges, TopologyEdge } from "../api/networks";
import { getHosts, Host } from "../api/hosts";

interface NodePos {
  x: number;
  y: number;
  host: Host;
}

const W = 900;
const H = 560;
const R = 22;

function positionNodes(hosts: Host[]): NodePos[] {
  if (hosts.length === 0) return [];
  const cx = W / 2;
  const cy = H / 2;
  if (hosts.length === 1) return [{ x: cx, y: cy, host: hosts[0] }];
  const radius = Math.min(cx, cy) - 60;
  return hosts.map((host, i) => {
    const angle = (2 * Math.PI * i) / hosts.length - Math.PI / 2;
    return {
      x: cx + radius * Math.cos(angle),
      y: cy + radius * Math.sin(angle),
      host,
    };
  });
}

export default function Topology() {
  const [nodes, setNodes] = useState<NodePos[]>([]);
  const [edges, setEdges] = useState<TopologyEdge[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [tooltip, setTooltip] = useState<{ x: number; y: number; host: Host } | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);

  useEffect(() => {
    Promise.all([getHosts(500), getTopologyEdges()])
      .then(([hosts, topo]) => {
        setNodes(positionNodes(hosts));
        setEdges(topo);
      })
      .catch((e: unknown) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const nodeById = new Map(nodes.map((n) => [n.host.id, n]));

  return (
    <div className="p-6 space-y-4">
      <h1 className="text-xl font-semibold text-white">Topology</h1>

      {loading && <p className="text-gray-500 text-sm">Loading…</p>}
      {error && <p className="text-red-400 text-sm">{error}</p>}

      {!loading && !error && nodes.length === 0 && (
        <p className="text-gray-600 text-sm">No hosts discovered yet.</p>
      )}

      {!loading && !error && nodes.length > 0 && (
        <div className="bg-surface-1 border border-surface-3 rounded-xl overflow-hidden">
          <svg
            ref={svgRef}
            viewBox={`0 0 ${W} ${H}`}
            className="w-full"
            style={{ maxHeight: H }}
            onMouseLeave={() => setTooltip(null)}
          >
            {/* Edges */}
            {edges.map((e) => {
              const src = nodeById.get(e.source_host_id);
              const tgt = nodeById.get(e.target_host_id);
              if (!src || !tgt) return null;
              return (
                <line
                  key={e.id}
                  x1={src.x} y1={src.y}
                  x2={tgt.x} y2={tgt.y}
                  stroke="#3f3f46"
                  strokeWidth={1.5}
                />
              );
            })}

            {/* Nodes */}
            {nodes.map(({ x, y, host }) => (
              <g
                key={host.id}
                transform={`translate(${x},${y})`}
                className="cursor-pointer"
                onMouseEnter={() => setTooltip({ x, y, host })}
              >
                <circle
                  r={R}
                  fill="#18181b"
                  stroke="#52525b"
                  strokeWidth={1.5}
                />
                <text
                  textAnchor="middle"
                  dy="0.35em"
                  fontSize={9}
                  fill="#a1a1aa"
                  className="select-none pointer-events-none"
                >
                  {(host.fqdn ?? host.ip_addresses[0] ?? "?").slice(0, 14)}
                </text>
              </g>
            ))}

            {/* Tooltip */}
            {tooltip && (() => {
              const tx = Math.min(tooltip.x + 30, W - 180);
              const ty = Math.min(tooltip.y - 10, H - 80);
              const h = tooltip.host;
              return (
                <g transform={`translate(${tx},${ty})`}>
                  <rect
                    x={0} y={0} width={200} height={70}
                    rx={6}
                    fill="#27272a"
                    stroke="#3f3f46"
                  />
                  <text x={10} y={18} fontSize={10} fill="#e4e4e7" fontWeight="bold">
                    {h.fqdn ?? h.ip_addresses[0] ?? "—"}
                  </text>
                  <text x={10} y={33} fontSize={9} fill="#71717a">
                    {h.ip_addresses.join(", ")}
                  </text>
                  <text x={10} y={47} fontSize={9} fill="#71717a">
                    {h.os ? `${h.os}${h.os_version ? ` ${h.os_version}` : ""}` : "OS unknown"}
                  </text>
                  <text x={10} y={61} fontSize={9} fill="#52525b">
                    Last seen {new Date(h.last_seen).toLocaleDateString()}
                  </text>
                </g>
              );
            })()}
          </svg>

          <div className="px-4 py-2 border-t border-surface-2 text-xs text-gray-600">
            {nodes.length} host{nodes.length !== 1 ? "s" : ""} · {edges.length} link{edges.length !== 1 ? "s" : ""}
            {edges.length === 0 && " — Topology links are discovered via ARP/LLDP/CDP data submitted by agents."}
          </div>
        </div>
      )}
    </div>
  );
}
