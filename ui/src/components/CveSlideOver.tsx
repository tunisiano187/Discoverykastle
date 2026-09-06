/**
 * CveSlideOver — slide-over panel showing all hosts affected by a given CVE.
 *
 * Usage:
 *   <CveSlideOver cveId="CVE-2024-1234" onClose={() => setSelected(null)} />
 *
 * The panel fetches GET /api/v1/vulns/{cveId} on mount and renders a host table.
 * Closes on backdrop click or Escape key.
 */
import { useEffect, useRef, useState } from "react";
import { getCveDetail, CveDetail } from "../api/vulns";
import SeverityBadge from "./SeverityBadge";

interface Props {
  cveId: string;
  onClose: () => void;
}

export default function CveSlideOver({ cveId, onClose }: Props) {
  const [detail, setDetail] = useState<CveDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const panelRef = useRef<HTMLDivElement>(null);

  // Fetch CVE detail on mount / when cveId changes
  useEffect(() => {
    setLoading(true);
    setError("");
    setDetail(null);
    getCveDetail(cveId)
      .then(setDetail)
      .catch((e: unknown) => setError(String(e)))
      .finally(() => setLoading(false));
  }, [cveId]);

  // Close on Escape key
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  // Trap focus inside the panel when it opens
  useEffect(() => {
    panelRef.current?.focus();
  }, []);

  return (
    /* Backdrop */
    <div
      className="fixed inset-0 z-50 flex justify-end"
      aria-modal="true"
      role="dialog"
      aria-label={`CVE detail: ${cveId}`}
    >
      {/* Semi-transparent overlay — click to close */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Panel */}
      <div
        ref={panelRef}
        tabIndex={-1}
        className="relative z-10 w-full max-w-2xl bg-surface-0 border-l border-surface-3 flex flex-col h-full shadow-2xl outline-none overflow-hidden"
      >
        {/* Header */}
        <div className="flex items-start justify-between gap-4 px-6 py-5 border-b border-surface-3 shrink-0">
          <div className="space-y-1 min-w-0">
            <div className="flex items-center gap-3 flex-wrap">
              <span className="font-mono text-lg font-bold text-brand">{cveId}</span>
              {detail && <SeverityBadge severity={detail.severity} />}
              {detail?.cvss_score != null && (
                <span className="text-xs text-gray-400 font-semibold">
                  CVSS {detail.cvss_score.toFixed(1)}
                </span>
              )}
            </div>
            {detail && (
              <p className="text-xs text-gray-500">
                {detail.affected_host_count} affected host{detail.affected_host_count !== 1 ? "s" : ""}
              </p>
            )}
          </div>
          <button
            onClick={onClose}
            className="shrink-0 text-gray-500 hover:text-white transition-colors p-1 rounded"
            aria-label="Close panel"
          >
            <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-5">
          {loading && (
            <p className="text-sm text-gray-500">Loading…</p>
          )}
          {error && (
            <p className="text-sm text-red-400">{error}</p>
          )}

          {detail && (
            <>
              {/* Description */}
              {detail.description && (
                <section>
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-500 mb-1">
                    Description
                  </h3>
                  <p className="text-sm text-gray-300 leading-relaxed">{detail.description}</p>
                </section>
              )}

              {/* Remediation */}
              {detail.remediation && (
                <section>
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-500 mb-1">
                    Remediation
                  </h3>
                  <p className="text-sm text-gray-300 leading-relaxed">{detail.remediation}</p>
                </section>
              )}

              {/* Affected hosts table */}
              <section>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-500 mb-2">
                  Affected hosts ({detail.affected_host_count})
                </h3>
                <div className="rounded-xl border border-surface-3 overflow-hidden">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-surface-3 text-gray-500">
                        <th className="text-left px-4 py-2">Host</th>
                        <th className="text-left px-4 py-2">IP addresses</th>
                        <th className="text-left px-4 py-2">Package</th>
                        <th className="text-left px-4 py-2 whitespace-nowrap">First seen</th>
                      </tr>
                    </thead>
                    <tbody>
                      {detail.affected_hosts.length === 0 ? (
                        <tr>
                          <td colSpan={4} className="px-4 py-4 text-center text-gray-600">
                            No hosts found.
                          </td>
                        </tr>
                      ) : (
                        detail.affected_hosts.map((h) => (
                          <tr
                            key={h.host_id}
                            className="border-b border-surface-2 last:border-0 hover:bg-surface-2 transition-colors"
                          >
                            <td className="px-4 py-2.5 font-mono text-gray-300 whitespace-nowrap">
                              {h.fqdn ?? h.host_id.slice(0, 8)}
                            </td>
                            <td className="px-4 py-2.5 font-mono text-gray-500">
                              {h.ip_addresses.length > 0
                                ? h.ip_addresses.join(", ")
                                : "—"}
                            </td>
                            <td className="px-4 py-2.5 font-mono text-gray-500">
                              {h.package_id ? h.package_id.slice(0, 8) : "—"}
                            </td>
                            <td className="px-4 py-2.5 text-gray-500 whitespace-nowrap">
                              {new Date(h.first_seen).toLocaleDateString()}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </section>

              {/* External link */}
              <div className="pt-2">
                <a
                  href={`https://nvd.nist.gov/vuln/detail/${cveId}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 text-xs text-brand hover:underline"
                >
                  View on NVD
                  <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 6H5.25A2.25 2.25 0 003 8.25v10.5A2.25 2.25 0 005.25 21h10.5A2.25 2.25 0 0018 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25" />
                  </svg>
                </a>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
