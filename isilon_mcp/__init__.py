"""Dell PowerScale (Isilon) MCP Server - Basic auth with per-request host support.

This package provides a Model Context Protocol (MCP) server for Dell PowerScale
(formerly Isilon) OneFS storage systems. It automatically generates tools
from OpenAPI specifications and supports both stdio and HTTP/SSE transports.

Features:
    - Automatic tool generation from OpenAPI specs
    - Basic auth with per-request host support
    - Multi-host support for managing multiple PowerScale clusters
    - Read-only GET operations for safe diagnostics (configurable)
    - SSE transport for n8n and web clients
    - stdio transport for Claude Desktop

Example:
    Using as a CLI tool (stdio transport)::

        $ python -m isilon_mcp

    Using as HTTP server (SSE transport)::

        $ uvicorn isilon_mcp.http_server:app --host 0.0.0.0 --port 3000

    Using as a library::

        from isilon_mcp.config import load_config
        from isilon_mcp.server import IsilonMCPServer

        config = load_config()
        server = IsilonMCPServer(config)
        await server.initialize()

Attributes:
    __version__: Package version following semantic versioning.
    __author__: Package author/maintainer.
"""

__version__ = "1.0.0"
__author__ = "sachdev27"

# Import public API
from .api_client import IsilonAPIClient
from .config import load_config
from .server import IsilonMCPServer

__all__ = [
    "__version__",
    "__author__",
    "IsilonMCPServer",
    "IsilonAPIClient",
    "load_config",
]
