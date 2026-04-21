"""
Vulnerability read API — /api/v1/vulns

GET /api/v1/vulns             — list CVE findings (filterable)
GET /api/v1/vulns/summary     — severity distribution + top CVEs
GET /api/v1/vulns/{cve_id}    — all hosts affected by a specific CVE

All endpoints require operator JWT.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import desc, distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.models.host import Host
from server.models.vulnerability import Vulnerability
from server.services.auth import require_operator

router = APIRouter(prefix="/api/v1/vulns", tags=["vulnerabilities"])

# Canonical severity order (most to least severe)
SEVERITY_ORDER = ["critical", "high", "medium", "low", "none", "unknown"]


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class VulnOut(BaseModel):
    id: str
    cve_id: str
    severity: str
    cvss_score: float | None
    description: str | None
    remediation: str | None
    host_id: str
    host_fqdn: str | None
    host_ip_addresses: list[str]
    package_id: str | None
    first_seen: datetime


class AffectedHost(BaseModel):
    host_id: str
    fqdn: str | None
    ip_addresses: list[str]
    package_id: str | None
    first_seen: datetime


class CveDetail(BaseModel):
    cve_id: str
    severity: str
    cvss_score: float | None
    description: str | None
    remediation: str | None
    affected_host_count: int
    affected_hosts: list[AffectedHost]


class SeverityCount(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    none: int = 0
    unknown: int = 0


class TopCve(BaseModel):
    cve_id: str
    affected_hosts: int
    severity: str
    cvss_score: float | None


class VulnSummary(BaseModel):
    total: int
    unique_cves: int
    affected_hosts: int
    by_severity: SeverityCount
    top_cves: list[TopCve]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _vuln_out(v: Vulnerability, host: Host) -> VulnOut:
    return VulnOut(
        id=str(v.id),
        cve_id=v.cve_id,
        severity=v.severity,
        cvss_score=v.cvss_score,
        description=v.description,
        remediation=v.remediation,
        host_id=str(v.host_id),
        host_fqdn=host.fqdn if host else None,
        host_ip_addresses=host.ip_addresses if host else [],
        package_id=str(v.package_id) if v.package_id else None,
        first_seen=v.first_seen,
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("", response_model=list[VulnOut])
async def list_vulns(
    operator: Annotated[str, Depends(require_operator)],
    severity: str | None = Query(default=None, description="Filter by severity level"),
    host_id: uuid.UUID | None = Query(default=None, description="Filter by host UUID"),
    cve_id: str | None = Query(default=None, description="Filter by CVE ID (exact match)"),
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> list[VulnOut]:
    """
    List CVE findings across all hosts (operator JWT required).

    Query params:
    - ``severity``: one of ``critical``, ``high``, ``medium``, ``low``, ``none``
    - ``host_id``: restrict to a single host
    - ``cve_id``: exact CVE ID match (e.g. ``CVE-2024-1234``)
    - ``limit`` / ``offset``: pagination (default 100, max 500)

    Results are ordered by CVSS score descending (nulls last), then severity.
    """
    q = (
        select(Vulnerability, Host)
        .join(Host, Vulnerability.host_id == Host.id)
        .order_by(desc(Vulnerability.cvss_score), Vulnerability.severity)
        .limit(limit)
        .offset(offset)
    )
    if severity:
        q = q.where(Vulnerability.severity == severity.lower())
    if host_id:
        q = q.where(Vulnerability.host_id == host_id)
    if cve_id:
        q = q.where(Vulnerability.cve_id == cve_id.upper())

    rows = await db.execute(q)
    return [_vuln_out(v, h) for v, h in rows]


@router.get("/summary", response_model=VulnSummary)
async def vuln_summary(
    operator: Annotated[str, Depends(require_operator)],
    top_n: int = Query(default=10, le=50, description="Number of top CVEs to return"),
    db: AsyncSession = Depends(get_db),
) -> VulnSummary:
    """
    Severity distribution and top CVEs by affected host count (operator JWT required).

    Returns:
    - ``total``: total number of vulnerability records
    - ``unique_cves``: distinct CVE IDs observed
    - ``affected_hosts``: distinct hosts with at least one CVE
    - ``by_severity``: count per severity level
    - ``top_cves``: top N CVEs ranked by affected host count
    """
    # --- Aggregate counts ---
    totals_row = await db.execute(
        select(
            func.count(Vulnerability.id).label("total"),
            func.count(distinct(Vulnerability.cve_id)).label("unique_cves"),
            func.count(distinct(Vulnerability.host_id)).label("affected_hosts"),
        )
    )
    totals = totals_row.one()

    # --- Per-severity counts ---
    sev_rows = await db.execute(
        select(Vulnerability.severity, func.count(Vulnerability.id).label("cnt"))
        .group_by(Vulnerability.severity)
    )
    by_sev: dict[str, int] = {row.severity: row.cnt for row in sev_rows}
    severity_counts = SeverityCount(
        critical=by_sev.get("critical", 0),
        high=by_sev.get("high", 0),
        medium=by_sev.get("medium", 0),
        low=by_sev.get("low", 0),
        none=by_sev.get("none", 0),
        unknown=sum(v for k, v in by_sev.items() if k not in SEVERITY_ORDER),
    )

    # --- Top CVEs by distinct affected host count ---
    top_rows = await db.execute(
        select(
            Vulnerability.cve_id,
            func.count(distinct(Vulnerability.host_id)).label("affected_hosts"),
            # Pick the most severe severity reported for this CVE
            func.max(Vulnerability.severity).label("severity"),
            func.max(Vulnerability.cvss_score).label("cvss_score"),
        )
        .group_by(Vulnerability.cve_id)
        .order_by(desc(func.count(distinct(Vulnerability.host_id))))
        .limit(top_n)
    )
    top_cves = [
        TopCve(
            cve_id=row.cve_id,
            affected_hosts=row.affected_hosts,
            severity=row.severity,
            cvss_score=row.cvss_score,
        )
        for row in top_rows
    ]

    return VulnSummary(
        total=totals.total,
        unique_cves=totals.unique_cves,
        affected_hosts=totals.affected_hosts,
        by_severity=severity_counts,
        top_cves=top_cves,
    )


@router.get("/{cve_id}", response_model=CveDetail)
async def get_cve(
    cve_id: str,
    operator: Annotated[str, Depends(require_operator)],
    db: AsyncSession = Depends(get_db),
) -> CveDetail:
    """
    Return all hosts affected by a specific CVE (operator JWT required).

    The ``cve_id`` path parameter is case-insensitive (normalised to upper-case).
    Returns 404 if no records exist for this CVE.
    """
    cve_upper = cve_id.upper()

    rows = await db.execute(
        select(Vulnerability, Host)
        .join(Host, Vulnerability.host_id == Host.id)
        .where(Vulnerability.cve_id == cve_upper)
        .order_by(desc(Vulnerability.cvss_score))
    )
    results = list(rows)

    if not results:
        raise HTTPException(status_code=404, detail=f"CVE {cve_upper} not found")

    # Use metadata from the first (highest-score) record
    first_vuln: Vulnerability = results[0][0]

    affected_hosts = [
        AffectedHost(
            host_id=str(v.host_id),
            fqdn=h.fqdn,
            ip_addresses=h.ip_addresses or [],
            package_id=str(v.package_id) if v.package_id else None,
            first_seen=v.first_seen,
        )
        for v, h in results
    ]

    return CveDetail(
        cve_id=cve_upper,
        severity=first_vuln.severity,
        cvss_score=first_vuln.cvss_score,
        description=first_vuln.description,
        remediation=first_vuln.remediation,
        affected_host_count=len(affected_hosts),
        affected_hosts=affected_hosts,
    )
