"""
Tests for /api/v1/inventory — Networks, AuthorizationRequests.

Uses mocked DB sessions; no PostgreSQL required.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from server.api.inventory import router, NetworkOut
from server.models.network import Network
from server.models.agent import AuthorizationRequest, Agent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


def _make_network(
    cidr: str = "192.168.1.0/24",
    scan_authorized: bool = False,
    domain_name: str | None = None,
) -> Network:
    net = Network(
        id=uuid.uuid4(),
        cidr=cidr,
        description=None,
        domain_name=domain_name,
        scan_authorized=scan_authorized,
        scan_depth=0,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    return net


def _make_auth_request(
    status: str = "pending",
    request_type: str = "public_scan",
    network_cidr: str = "8.8.8.0/24",
) -> AuthorizationRequest:
    return AuthorizationRequest(
        id=uuid.uuid4(),
        agent_id=uuid.uuid4(),
        request_type=request_type,
        details={"cidr": network_cidr},
        status=status,
        requested_at=datetime.utcnow(),
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )


# ---------------------------------------------------------------------------
# NetworkOut schema
# ---------------------------------------------------------------------------

class TestNetworkOutSchema:
    """ip_class is derived from CIDR, not stored in DB."""

    def test_private_cidr_class(self) -> None:
        net = _make_network(cidr="192.168.0.0/24")
        out = NetworkOut(
            id=net.id,
            cidr=net.cidr,
            description=net.description,
            domain_name=net.domain_name,
            scan_authorized=net.scan_authorized,
            scan_depth=net.scan_depth,
            ip_class="private",
            created_at=net.created_at,
        )
        assert out.ip_class == "private"

    def test_public_cidr_class(self) -> None:
        from server.services.ip_utils import classify_cidr
        out = NetworkOut(
            id=uuid.uuid4(),
            cidr="8.8.8.0/24",
            description=None,
            domain_name=None,
            scan_authorized=False,
            scan_depth=0,
            ip_class=classify_cidr("8.8.8.0/24"),
            created_at=datetime.utcnow(),
        )
        assert out.ip_class == "public"

    def test_domain_name_optional(self) -> None:
        out = NetworkOut(
            id=uuid.uuid4(),
            cidr="10.0.0.0/8",
            description=None,
            domain_name=None,
            scan_authorized=False,
            scan_depth=0,
            ip_class="private",
            created_at=datetime.utcnow(),
        )
        assert out.domain_name is None


# ---------------------------------------------------------------------------
# GET /api/v1/inventory/networks
# ---------------------------------------------------------------------------

class TestListNetworks:
    def _make_client_with_networks(self, networks: list[Network]) -> TestClient:
        app = _make_app()

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = networks

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_result)

        async def override_get_db():
            yield mock_db

        from server.database import get_db
        app.dependency_overrides[get_db] = override_get_db

        from unittest.mock import patch
        with patch("server.api.inventory.get_current_user", return_value="admin"):
            return TestClient(app)

    def test_returns_list(self) -> None:
        nets = [_make_network("192.168.1.0/24"), _make_network("10.0.0.0/8")]
        app = _make_app()
        mock_result = MagicMock()
        mock_result.scalars.return_value = nets  # list() works directly on a list

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_result)

        async def override_get_db():
            yield mock_db

        from server.database import get_db
        app.dependency_overrides[get_db] = override_get_db

        client = TestClient(app)
        resp = client.get("/api/v1/inventory/networks")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2

    def test_ip_class_in_response(self) -> None:
        nets = [_make_network("192.168.1.0/24")]
        app = _make_app()
        mock_result = MagicMock()
        mock_result.scalars.return_value = nets
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_result)

        async def override_get_db():
            yield mock_db

        from server.database import get_db
        app.dependency_overrides[get_db] = override_get_db

        client = TestClient(app)
        resp = client.get("/api/v1/inventory/networks")
        assert resp.status_code == 200
        net_data = resp.json()[0]
        assert net_data["ip_class"] == "private"
        assert net_data["cidr"] == "192.168.1.0/24"


# ---------------------------------------------------------------------------
# AuthorizationRequest — status transitions
# ---------------------------------------------------------------------------

class TestAuthRequestStatusTransitions:
    """Verify the status field values are well-formed."""

    def test_pending_status(self) -> None:
        req = _make_auth_request(status="pending")
        assert req.status == "pending"

    def test_approved_status(self) -> None:
        req = _make_auth_request(status="approved")
        assert req.status == "approved"

    def test_denied_status(self) -> None:
        req = _make_auth_request(status="denied")
        assert req.status == "denied"

    def test_details_contain_cidr(self) -> None:
        req = _make_auth_request(network_cidr="203.0.114.0/24")
        assert req.details.get("cidr") == "203.0.114.0/24"


# ---------------------------------------------------------------------------
# classify_cidr integration in ip_class field
# ---------------------------------------------------------------------------

class TestIpClassDerivation:
    """End-to-end: cidr string → ip_class in API response."""

    @pytest.mark.parametrize("cidr,expected_class", [
        ("10.0.0.0/8", "private"),
        ("172.16.0.0/12", "private"),
        ("192.168.0.0/16", "private"),
        ("127.0.0.0/8", "private"),
        ("8.8.8.0/24", "public"),
        ("1.1.1.0/24", "public"),
    ])
    def test_cidr_to_ip_class(self, cidr: str, expected_class: str) -> None:
        from server.services.ip_utils import classify_cidr
        assert classify_cidr(cidr) == expected_class
