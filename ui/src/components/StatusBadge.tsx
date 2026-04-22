export default function StatusBadge({ status }: { status: string }) {
  const online = status === "online";
  return (
    <span className="flex items-center gap-1.5 text-xs">
      <span
        className={`h-2 w-2 rounded-full ${online ? "bg-green-400" : "bg-gray-500"}`}
      />
      <span className={online ? "text-green-400" : "text-gray-500"}>{status}</span>
    </span>
  );
}
