"""Tests for the API client module."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import httpx

from isilon_mcp.api_client import IsilonAPIClient
from isilon_mcp.exceptions import (
    AuthenticationError,
    ConnectionError as IsilonConnectionError,
    APIResponseError,
    RateLimitError,
)


class TestIsilonAPIClient:
    """Tests for IsilonAPIClient class."""

    def test_init(self):
        """Test client initialization."""
        client = IsilonAPIClient(
            host="test-cluster.example.com",
            username="test_user",
            password="test_password",
        )
        assert client.host == "test-cluster.example.com"
        assert client.client is None

    def test_base_url_https(self):
        """Test base URL with HTTPS."""
        client = IsilonAPIClient(
            host="test-cluster.example.com",
            username="test_user",
            password="test_password",
            port=8080,
            use_https=True,
        )
        assert client.base_url == "https://test-cluster.example.com:8080"

    def test_base_url_http(self):
        """Test base URL with HTTP."""
        client = IsilonAPIClient(
            host="test-cluster.example.com",
            username="test_user",
            password="test_password",
            port=8080,
            use_https=False,
        )
        assert client.base_url == "http://test-cluster.example.com:8080"

    def test_custom_port(self):
        """Test custom port."""
        client = IsilonAPIClient(
            host="test-cluster.example.com",
            username="test_user",
            password="test_password",
            port=443,
        )
        assert "443" in client.base_url

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test async context manager creates and closes client properly."""
        client = IsilonAPIClient(
            host="test-cluster.example.com",
            username="test_user",
            password="test_password",
        )

        # Client is lazily initialized, so it should be None initially
        assert client.client is None

        # When using as context manager, it returns self
        async with client as ctx:
            assert ctx is client

    @pytest.mark.asyncio
    async def test_execute_operation_get(self, mock_httpx_client):
        """Test executing a GET operation."""
        client = IsilonAPIClient(
            host="test-cluster.example.com",
            username="test_user",
            password="test_password",
        )
        client.client = mock_httpx_client

        result = await client.execute_operation(
            path="/platform/18/cluster/config",
            method="GET",
            params={"limit": 10},
        )

        mock_httpx_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_operation_post(self, mock_httpx_client, mock_httpx_response):
        """Test executing a POST operation."""
        mock_httpx_response.status_code = 201
        mock_httpx_client.post.return_value = mock_httpx_response

        client = IsilonAPIClient(
            host="test-cluster.example.com",
            username="test_user",
            password="test_password",
        )
        client.client = mock_httpx_client

        result = await client.execute_operation(
            path="/platform/18/protocols/smb/shares",
            method="POST",
            body={"name": "test_share", "path": "/ifs/data"},
        )

        mock_httpx_client.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_operation_delete(self, mock_httpx_client, mock_httpx_response):
        """Test executing a DELETE operation."""
        mock_httpx_response.status_code = 204
        mock_httpx_response.json.return_value = None
        mock_httpx_client.delete.return_value = mock_httpx_response

        client = IsilonAPIClient(
            host="test-cluster.example.com",
            username="test_user",
            password="test_password",
        )
        client.client = mock_httpx_client

        result = await client.execute_operation(
            path="/platform/18/snapshot/snapshots/123",
            method="DELETE",
        )

        mock_httpx_client.delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_authentication_error(self, mock_httpx_client, mock_httpx_response):
        """Test handling authentication error."""
        mock_httpx_response.status_code = 401
        mock_httpx_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "401 Unauthorized",
            request=MagicMock(),
            response=mock_httpx_response,
        )
        mock_httpx_client.get.return_value = mock_httpx_response

        client = IsilonAPIClient(
            host="test-cluster.example.com",
            username="test_user",
            password="wrong_password",
        )
        client.client = mock_httpx_client

        with pytest.raises(AuthenticationError):
            await client.execute_operation(
                path="/platform/18/cluster/config",
                method="GET",
            )

    @pytest.mark.asyncio
    async def test_rate_limit_error(self, mock_httpx_client, mock_httpx_response):
        """Test handling rate limit error."""
        mock_httpx_response.status_code = 429
        mock_httpx_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "429 Too Many Requests",
            request=MagicMock(),
            response=mock_httpx_response,
        )
        mock_httpx_client.get.return_value = mock_httpx_response

        client = IsilonAPIClient(
            host="test-cluster.example.com",
            username="test_user",
            password="test_password",
            max_retries=0,  # Disable retries for test
        )
        client.client = mock_httpx_client

        with pytest.raises(RateLimitError):
            await client.execute_operation(
                path="/platform/18/cluster/config",
                method="GET",
            )

    @pytest.mark.asyncio
    async def test_connection_error(self, mock_httpx_client):
        """Test handling connection error."""
        mock_httpx_client.get.side_effect = httpx.ConnectError("Connection failed")

        client = IsilonAPIClient(
            host="unreachable-host.example.com",
            username="test_user",
            password="test_password",
            max_retries=0,  # Disable retries for test
        )
        client.client = mock_httpx_client

        with pytest.raises(IsilonConnectionError):
            await client.execute_operation(
                path="/platform/18/cluster/config",
                method="GET",
            )
