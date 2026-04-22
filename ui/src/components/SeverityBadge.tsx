const COLORS: Record<string, string> = {
  critical: "bg-red-900 text-red-300 border border-red-700",
  high: "bg-orange-900 text-orange-300 border border-orange-700",
  medium: "bg-yellow-900 text-yellow-300 border border-yellow-700",
  low: "bg-blue-900 text-blue-300 border border-blue-700",
  none: "bg-gray-800 text-gray-400 border border-gray-600",
  unknown: "bg-gray-800 text-gray-400 border border-gray-600",
};

export default function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${COLORS[severity] ?? COLORS["unknown"]}`}>
      {severity}
    </span>
  );
}
