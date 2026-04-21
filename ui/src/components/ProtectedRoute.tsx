import { Navigate } from "react-router-dom";
import { useAuth } from "../hooks/useAuth";

export default function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { username, loading } = useAuth();
  if (loading) return <div className="flex h-screen items-center justify-center text-gray-500">Loading…</div>;
  if (!username) return <Navigate to="/login" replace />;
  return <>{children}</>;
}
