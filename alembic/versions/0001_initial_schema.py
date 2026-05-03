"""Initial schema — all tables

Revision ID: 0001
Revises:
Create Date: 2026-01-01 00:00:00.000000

Creates the full initial schema from scratch.  When upgrading an existing
installation that used create_all() (pre-Alembic), run:

    alembic stamp 0001

to tell Alembic that the current DB is already at this revision, then apply
future migrations normally with `alembic upgrade head`.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ------------------------------------------------------------------
    # agents
    # ------------------------------------------------------------------
    op.create_table(
        "agents",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("certificate_fingerprint", sa.String(128), nullable=False, unique=True),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("ip_address", sa.String(50), nullable=True),
        sa.Column("version", sa.String(50), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="offline"),
        sa.Column("authorized_cidrs", postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("last_heartbeat", sa.DateTime, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )

    # ------------------------------------------------------------------
    # audit_log
    # ------------------------------------------------------------------
    op.create_table(
        "audit_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agents.id"), nullable=True),
        sa.Column("user_id", sa.String(100), nullable=True),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("target", sa.String(255), nullable=True),
        sa.Column("params", postgresql.JSON, nullable=False, server_default="{}"),
        sa.Column("result", sa.String(20), nullable=True),
        sa.Column("timestamp", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )

    # ------------------------------------------------------------------
    # authorization_requests
    # ------------------------------------------------------------------
    op.create_table(
        "authorization_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agents.id"), nullable=False),
        sa.Column("request_type", sa.String(50), nullable=False),
        sa.Column("details", postgresql.JSON, nullable=False, server_default="{}"),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("requested_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("resolved_at", sa.DateTime, nullable=True),
        sa.Column("resolved_by", sa.String(100), nullable=True),
        sa.Column("expires_at", sa.DateTime, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )

    # ------------------------------------------------------------------
    # hosts
    # ------------------------------------------------------------------
    op.create_table(
        "hosts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("fqdn", sa.String(255), nullable=True),
        sa.Column("ip_addresses", postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("os", sa.String(255), nullable=True),
        sa.Column("os_version", sa.String(255), nullable=True),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agents.id"), nullable=True),
        sa.Column("first_seen", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )

    # ------------------------------------------------------------------
    # services
    # ------------------------------------------------------------------
    op.create_table(
        "services",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("host_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("hosts.id"), nullable=False),
        sa.Column("port", sa.Integer, nullable=False),
        sa.Column("protocol", sa.String(10), nullable=False, server_default="tcp"),
        sa.Column("service_name", sa.String(100), nullable=True),
        sa.Column("version", sa.String(255), nullable=True),
        sa.Column("banner", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_unique_constraint("uq_services_host_port_proto", "services", ["host_id", "port", "protocol"])

    # ------------------------------------------------------------------
    # packages
    # ------------------------------------------------------------------
    op.create_table(
        "packages",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("host_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("hosts.id"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("version", sa.String(100), nullable=True),
        sa.Column("package_manager", sa.String(50), nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )

    # ------------------------------------------------------------------
    # vulnerabilities
    # ------------------------------------------------------------------
    op.create_table(
        "vulnerabilities",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("host_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("hosts.id"), nullable=False),
        sa.Column("package_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("packages.id"), nullable=True),
        sa.Column("cve_id", sa.String(30), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("cvss_score", sa.Float, nullable=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("remediation", sa.Text, nullable=True),
        sa.Column("first_seen", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )

    # ------------------------------------------------------------------
    # networks
    # ------------------------------------------------------------------
    op.create_table(
        "networks",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("cidr", sa.String(50), nullable=False, unique=True),
        sa.Column("description", sa.String(255), nullable=True),
        sa.Column("domain_name", sa.String(255), nullable=True),
        sa.Column("discovered_via_host_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("hosts.id"), nullable=True),
        sa.Column("scan_authorized", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("scan_depth", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )

    # ------------------------------------------------------------------
    # network_interfaces
    # ------------------------------------------------------------------
    op.create_table(
        "network_interfaces",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("host_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("hosts.id"), nullable=False),
        sa.Column("network_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("networks.id"), nullable=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("ip_address", sa.String(50), nullable=True),
        sa.Column("netmask", sa.String(50), nullable=True),
        sa.Column("mac_address", sa.String(20), nullable=True),
        sa.Column("interface_type", sa.String(50), nullable=True),
        sa.Column("is_up", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )

    # ------------------------------------------------------------------
    # topology_edges
    # ------------------------------------------------------------------
    op.create_table(
        "topology_edges",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("source_host_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("hosts.id"), nullable=False),
        sa.Column("target_host_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("hosts.id"), nullable=False),
        sa.Column("edge_type", sa.String(50), nullable=False),
        sa.Column("interface_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("network_interfaces.id"), nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )

    # ------------------------------------------------------------------
    # scan_results
    # ------------------------------------------------------------------
    op.create_table(
        "scan_results",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("network_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("networks.id"), nullable=True),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agents.id"), nullable=False),
        sa.Column("started_at", sa.DateTime, nullable=False),
        sa.Column("completed_at", sa.DateTime, nullable=True),
        sa.Column("hosts_found", postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("raw_output", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )

    # ------------------------------------------------------------------
    # network_devices
    # ------------------------------------------------------------------
    op.create_table(
        "network_devices",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("ip_address", sa.String(50), nullable=False, unique=True),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("vendor", sa.String(100), nullable=True),
        sa.Column("model", sa.String(100), nullable=True),
        sa.Column("firmware_version", sa.String(100), nullable=True),
        sa.Column("device_type", sa.String(50), nullable=True),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agents.id"), nullable=True),
        sa.Column("raw_config", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )

    # ------------------------------------------------------------------
    # alerts
    # ------------------------------------------------------------------
    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("host_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("hosts.id"), nullable=True),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agents.id"), nullable=True),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("alert_type", sa.String(50), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("message", sa.Text, nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="open"),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )

    # ------------------------------------------------------------------
    # agent_tasks
    # ------------------------------------------------------------------
    op.create_table(
        "agent_tasks",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agents.id"), nullable=False),
        sa.Column("task_type", sa.String(50), nullable=False),
        sa.Column("params", postgresql.JSON, nullable=False, server_default="{}"),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("result", postgresql.JSON, nullable=True),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("retry_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("max_retries", sa.Integer, nullable=False, server_default="3"),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime, nullable=True),
        sa.Column("completed_at", sa.DateTime, nullable=True),
        sa.Column("timeout_at", sa.DateTime, nullable=True),
    )


def downgrade() -> None:
    op.drop_table("agent_tasks")
    op.drop_table("alerts")
    op.drop_table("network_devices")
    op.drop_table("scan_results")
    op.drop_table("topology_edges")
    op.drop_table("network_interfaces")
    op.drop_table("networks")
    op.drop_table("vulnerabilities")
    op.drop_table("packages")
    op.drop_constraint("uq_services_host_port_proto", "services", type_="unique")
    op.drop_table("services")
    op.drop_table("hosts")
    op.drop_table("authorization_requests")
    op.drop_table("audit_log")
    op.drop_table("agents")
