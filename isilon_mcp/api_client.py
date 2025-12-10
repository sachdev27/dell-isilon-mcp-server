"""Isilon/PowerScale API client with Basic Authentication.

This module provides an async HTTP client for the PowerScale REST API
using HTTP Basic Authentication on every request.

Example:
    >>> async with IsilonAPIClient(
    ...     host="powerscale.example.com",
    ...     username="admin",
    ...     password="password123",
    ... ) as client:
    ...     config = await client.execute_operation("/platform/1/cluster/config", "GET")
    ...     print(f"Cluster name: {config['name']}")

Note:
    PowerScale API uses HTTP Basic Authentication which must be passed
    with every request.

    PowerScale API URL structure:
    - Platform API: /platform/{version}/{category}/{resource}
    - Namespace API: /namespace/{path}

    Examples:
      - /platform/1/cluster/config
      - /platform/1/protocols/smb/shares
      - /namespace/ifs/data/files
"""

from __future__ import annotations

import asyncio
import base64
from typing import Any
from urllib.parse import urljoin

import httpx

from .exceptions import (
    APIResponseError,
    AuthenticationError,
    AuthorizationError,
    ConnectionError,
    RateLimitError,
    ResourceNotFoundError,
)
from .logging_config import LoggerAdapter, get_logger

logger = get_logger(__name__)


class IsilonAPIClient:
    """PowerScale API client using HTTP Basic Authentication.

    This client creates HTTP connections using Basic Authentication.
    Credentials must be provided for every request.

    The PowerScale REST API uses two main URL structures:
    - Platform API: /platform/{version}/{category}/{resource}
    - Namespace API: /namespace/{path}

    Attributes:
        host: PowerScale host address.
        base_url: Full base URL for API requests.

    Example:
        >>> client = IsilonAPIClient(
        ...     host="powerscale.example.com",
        ...     username="admin",
        ...     password="password123",
        ... )
        >>> try:
        ...     result = await client.execute_operation("/platform/1/cluster/config", "GET")
        ...     print(result)
        ... finally:
        ...     await client.close()
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 8080,
        use_https: bool = True,
        tls_verify: bool = False,
        timeout: int = 30,
        max_retries: int = 3,
    ) -> None:
        """Initialize PowerScale API client.

        Args:
            host: PowerScale host (e.g., "powerscale.example.com").
            username: PowerScale username.
            password: PowerScale password.
            port: PowerScale API port (default: 8080).
            use_https: Use HTTPS instead of HTTP (default: True).
            tls_verify: Whether to verify TLS certificates.
            timeout: Request timeout in seconds.
            max_retries: Maximum number of retry attempts for transient errors.

        Raises:
            ValueError: If host, username, or password is empty.
        """
        if not host:
            raise ValueError("host is required")
        if not username:
            raise ValueError("username is required")
        if not password:
            raise ValueError("password is required")

        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.use_https = use_https
        self.tls_verify = tls_verify
        self.timeout = timeout
        self.max_retries = max_retries

        # Build base URL
        protocol = "https" if use_https else "http"
        self.base_url = f"{protocol}://{host}:{port}"

        # Create Basic Auth header
        credentials = f"{username}:{password}"
        encoded = base64.b64encode(credentials.encode()).decode()
        self._auth_header = f"Basic {encoded}"

        # Create logger adapter with host context
        self._logger = LoggerAdapter(logger, {"host": host})

        # HTTP client (created lazily)
        self.client: httpx.AsyncClient | None = None

    async def _ensure_client(self) -> httpx.AsyncClient:
        """Ensure HTTP client is initialized.

        Returns:
            The initialized HTTP client.
        """
        if self.client is None:
            self.client = httpx.AsyncClient(
                verify=self.tls_verify,
                timeout=self.timeout,
                follow_redirects=True,
                headers={
                    "Authorization": self._auth_header,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
            )
        return self.client

    async def execute_operation(
        self,
        path: str,
        method: str = "GET",
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[dict[str, Any]]:
        """Execute an API operation with Basic Auth.

        This method handles retries for transient errors and provides
        detailed logging for debugging.

        Args:
            path: API endpoint path (e.g., "/platform/1/cluster/config").
            method: HTTP method (GET, POST, PUT, DELETE, PATCH).
            params: Query parameters.
            body: Request body for POST/PUT/PATCH requests.

        Returns:
            Parsed JSON response (dict or list).

        Raises:
            AuthenticationError: If credentials are invalid.
            AuthorizationError: If permissions are insufficient.
            ConnectionError: If connection fails.
            APIResponseError: If API returns an error.
            RateLimitError: If rate limit is exceeded.
            ResourceNotFoundError: If resource is not found.
        """
        client = await self._ensure_client()
        url = urljoin(self.base_url, path)

        self._logger.debug(
            f"Executing {method} {path}",
            extra={"params": params, "has_body": body is not None},
        )

        last_error: Exception | None = None

        for attempt in range(self.max_retries + 1):
            try:
                response = await self._make_request(client, method, url, params, body)
                return self._parse_response(response, path)

            except (httpx.TimeoutException, httpx.ConnectError) as e:
                last_error = e
                if attempt < self.max_retries:
                    wait_time = (2**attempt) * 0.5  # Exponential backoff
                    self._logger.warning(
                        f"Request failed, retrying in {wait_time}s (attempt {attempt + 1}/{self.max_retries})",
                        extra={"error": str(e)},
                    )
                    await asyncio.sleep(wait_time)
                else:
                    raise ConnectionError(self.host, e) from e

            except AuthenticationError:
                # Don't retry auth errors
                raise

            except RateLimitError as e:
                # Handle rate limiting with retry-after
                if e.retry_after and attempt < self.max_retries:
                    self._logger.warning(
                        f"Rate limited, waiting {e.retry_after}s",
                    )
                    await asyncio.sleep(e.retry_after)
                else:
                    raise

        # Should not reach here, but just in case
        raise ConnectionError(self.host, last_error)

    async def _make_request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        params: dict[str, Any] | None,
        body: dict[str, Any] | None,
    ) -> httpx.Response:
        """Make the actual HTTP request.

        Args:
            client: HTTP client.
            method: HTTP method.
            url: Full URL.
            params: Query parameters.
            body: Request body.

        Returns:
            HTTP response.
        """
        method = method.upper()

        if method == "GET":
            response = await client.get(url, params=params)
        elif method == "POST":
            response = await client.post(url, params=params, json=body)
        elif method == "PUT":
            response = await client.put(url, params=params, json=body)
        elif method == "DELETE":
            response = await client.delete(url, params=params)
        elif method == "PATCH":
            response = await client.patch(url, params=params, json=body)
        elif method == "HEAD":
            response = await client.head(url, params=params)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

        return response

    def _parse_response(
        self, response: httpx.Response, path: str = ""
    ) -> dict[str, Any] | list[dict[str, Any]]:
        """Parse and validate API response.

        Args:
            response: HTTP response object.
            path: Original request path for error context.

        Returns:
            Parsed JSON data.

        Raises:
            AuthenticationError: If authentication failed (401).
            AuthorizationError: If authorization failed (403).
            ResourceNotFoundError: If resource not found (404).
            RateLimitError: If rate limit exceeded (429).
            APIResponseError: For other API errors.
        """
        # Handle authentication errors
        if response.status_code == 401:
            raise AuthenticationError(
                "Authentication failed - check your username and password",
                status_code=401,
            )

        # Handle authorization errors
        if response.status_code == 403:
            raise AuthorizationError(
                "Access denied - insufficient permissions for this operation",
                status_code=403,
            )

        # Handle not found
        if response.status_code == 404:
            raise ResourceNotFoundError(path)

        # Handle rate limiting
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitError(retry_after=int(retry_after) if retry_after else None)

        # Handle other errors
        if response.status_code >= 400:
            try:
                error_body = response.json()
                # PowerScale error format
                errors = error_body.get("errors", [])
                if errors:
                    error_message = errors[0].get("message", str(error_body))
                else:
                    error_message = (
                        error_body.get("message")
                        or str(error_body)
                    )
            except Exception:
                error_message = response.text or f"HTTP {response.status_code}"

            raise APIResponseError(
                message=error_message,
                status_code=response.status_code,
                response_body=response.text,
            )

        # Parse successful response
        try:
            # Handle 204 No Content
            if response.status_code == 204:
                return {"status": "success", "message": "Operation completed"}

            data = response.json()
            self._logger.debug(
                "Request successful",
                extra={"status_code": response.status_code},
            )
            return data
        except Exception as e:
            # If response is not JSON, return as text
            self._logger.warning(
                f"Response is not JSON: {e}",
                extra={"content_type": response.headers.get("content-type")},
            )
            return {"raw_response": response.text}

    async def close(self) -> None:
        """Close the HTTP client and release resources."""
        if self.client:
            await self.client.aclose()
            self.client = None
            self._logger.debug("HTTP client closed")

    async def __aenter__(self) -> "IsilonAPIClient":
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.close()


async def test_connection(
    host: str,
    username: str,
    password: str,
    port: int = 8080,
    use_https: bool = True,
    tls_verify: bool = False,
) -> dict[str, Any]:
    """Test connection to PowerScale cluster.

    Args:
        host: PowerScale host.
        username: Username.
        password: Password.
        port: PowerScale API port.
        use_https: Use HTTPS.
        tls_verify: Verify TLS certificates.

    Returns:
        Connection test result.

    Example:
        >>> result = await test_connection("powerscale.example.com", "admin", "password")
        >>> print(result["success"])
    """
    async with IsilonAPIClient(
        host=host,
        username=username,
        password=password,
        port=port,
        use_https=use_https,
        tls_verify=tls_verify,
        timeout=10,
        max_retries=1,
    ) as client:
        try:
            # Try to get cluster config as a connection test
            result = await client.execute_operation(
                "/platform/1/cluster/config",
                "GET",
            )
            cluster_name = result.get("name", "Unknown")
            return {
                "success": True,
                "message": f"Connected to cluster: {cluster_name}",
                "host": host,
                "cluster_name": cluster_name,
            }
        except AuthenticationError:
            return {
                "success": False,
                "message": "Authentication failed - check username/password",
                "host": host,
            }
        except ConnectionError as e:
            return {
                "success": False,
                "message": f"Connection failed: {e}",
                "host": host,
            }
        except Exception as e:
            return {
                "success": False,
                "message": f"Unexpected error: {e}",
                "host": host,
            }
