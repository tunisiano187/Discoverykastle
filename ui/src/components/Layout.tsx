import { NavLink, Outlet } from "react-router-dom";
import { useAuth } from "../hooks/useAuth";

const NAV_ITEMS = [
  { to: "/", label: "Dashboard", icon: "⬡" },
  { to: "/agents", label: "Agents", icon: "⚡" },
  { to: "/hosts", label: "Hosts", icon: "🖥" },
  { to: "/networks", label: "Networks", icon: "◈" },
  { to: "/topology", label: "Topology", icon: "⟁" },
  { to: "/vulns", label: "Vulnerabilities", icon: "🛡" },
];

export default function Layout() {
  const { username, logout } = useAuth();

  return (
    <div className="flex h-screen overflow-hidden">
      {/* Sidebar */}
      <aside className="w-56 flex-shrink-0 bg-surface-1 border-r border-surface-3 flex flex-col">
        <div className="px-5 py-4 border-b border-surface-3">
          <span className="text-brand font-bold text-lg tracking-wide">Discoverykastle</span>
        </div>
        <nav className="flex-1 py-4 space-y-1 px-2">
          {NAV_ITEMS.map(({ to, label, icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/"}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
                  isActive
                    ? "bg-surface-3 text-white"
                    : "text-gray-400 hover:text-white hover:bg-surface-2"
                }`
              }
            >
              <span>{icon}</span>
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="px-4 py-3 border-t border-surface-3 text-xs text-gray-500 flex items-center justify-between">
          <span className="truncate">{username}</span>
          <button
            onClick={logout}
            className="text-gray-500 hover:text-red-400 transition-colors ml-2"
          >
            Sign out
          </button>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 overflow-y-auto bg-surface-0">
        <Outlet />
      </main>
    </div>
  );
}
