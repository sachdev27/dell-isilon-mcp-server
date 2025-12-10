"""HTTP/SSE server for Isilon MCP Server.

This module provides an HTTP server with SSE (Server-Sent Events) support
for web clients and n8n integration.

This implementation uses pure ASGI instead of Starlette Routes to properly
handle MCP's SSE transport which manages responses directly via ASGI.

Example:
    Running with uvicorn::

        $ uvicorn isilon_mcp.http_server:app --host 0.0.0.0 --port 3000
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

from mcp.server import NotificationOptions
from mcp.server.models import InitializationOptions
from mcp.server.sse import SseServerTransport

from .config import load_config
from .logging_config import get_logger, setup_logging
from .server import IsilonMCPServer

logger = get_logger(__name__)

# Type aliases for ASGI
Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]


class CORSMiddleware:
    """Simple CORS middleware for ASGI applications."""

    def __init__(self, app: Callable) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Handle CORS preflight
        if scope["method"] == "OPTIONS":
            await self._send_cors_preflight(send)
            return

        # Wrap send to add CORS headers
        async def send_with_cors(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend(
                    [
                        (b"access-control-allow-origin", b"*"),
                        (b"access-control-allow-methods", b"GET, POST, OPTIONS"),
                        (b"access-control-allow-headers", b"*"),
                        (b"access-control-expose-headers", b"*"),
                    ]
                )
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_cors)

    async def _send_cors_preflight(self, send: Send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 204,
                "headers": [
                    (b"access-control-allow-origin", b"*"),
                    (b"access-control-allow-methods", b"GET, POST, OPTIONS"),
                    (b"access-control-allow-headers", b"*"),
                    (b"access-control-max-age", b"86400"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": b""})


class MCPHttpServer:
    """Pure ASGI HTTP server for MCP with SSE support.

    This uses pure ASGI instead of Starlette Routes because MCP's
    SseServerTransport manages responses directly via ASGI, which is
    incompatible with Starlette's Route abstraction that requires
    returning Response objects.
    """

    VERSION = "1.0.0"

    def __init__(self) -> None:
        self.mcp_server: IsilonMCPServer | None = None
        self.sse_transport: SseServerTransport | None = None
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize the MCP server."""
        if self._initialized:
            return

        config = load_config()
        setup_logging(
            log_level=config.server.log_level,
            json_format=config.server.log_json,
            log_file=config.server.log_file,
        )

        logger.info("Initializing Isilon MCP HTTP Server")

        self.mcp_server = IsilonMCPServer(config)
        await self.mcp_server.initialize()

        # Create SSE transport - the path must match the messages endpoint
        self.sse_transport = SseServerTransport("/messages")

        self._initialized = True
        logger.info(
            "Server initialized", extra={"tool_count": len(self.mcp_server.tools)}
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """ASGI application entry point."""
        if scope["type"] == "lifespan":
            await self._handle_lifespan(scope, receive, send)
            return

        if scope["type"] != "http":
            return

        # Lazy initialization
        if not self._initialized:
            await self.initialize()

        path = scope["path"]
        method = scope["method"]

        # Route requests
        if path == "/health" and method == "GET":
            await self._handle_health(scope, receive, send)
        elif path == "/tools" and method == "GET":
            await self._handle_tools(scope, receive, send)
        elif path == "/sse" and method == "GET":
            await self._handle_sse(scope, receive, send)
        elif path == "/messages" and method == "POST":
            await self._handle_messages(scope, receive, send)
        elif path == "/call" and method == "POST":
            await self._handle_call(scope, receive, send)
        else:
            await self._send_json(send, {"error": "Not found"}, status=404)

    async def _handle_lifespan(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        """Handle ASGI lifespan events."""
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                try:
                    await self.initialize()
                    await send({"type": "lifespan.startup.complete"})
                except Exception as e:
                    logger.error(f"Startup failed: {e}")
                    await send({"type": "lifespan.startup.failed", "message": str(e)})
            elif message["type"] == "lifespan.shutdown":
                logger.info("Shutting down Isilon MCP HTTP Server")
                await send({"type": "lifespan.shutdown.complete"})
                return

    async def _handle_health(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Health check endpoint."""
        try:
            await self._send_json(
                send,
                {
                    "status": "healthy",
                    "server": "isilon-mcp-server",
                    "version": self.VERSION,
                    "initialized": self._initialized,
                    "tool_count": len(self.mcp_server.tools) if self.mcp_server else 0,
                },
            )
        except Exception as e:
            await self._send_json(
                send, {"status": "unhealthy", "error": str(e)}, status=503
            )

    async def _handle_tools(self, scope: Scope, receive: Receive, send: Send) -> None:
        """List available tools."""
        try:
            tools = [
                {
                    "name": tool["name"],
                    "description": (
                        tool["description"][:200] + "..."
                        if len(tool["description"]) > 200
                        else tool["description"]
                    ),
                    "inputSchema": tool["inputSchema"],
                }
                for tool in (self.mcp_server.tools if self.mcp_server else [])
            ]
            await self._send_json(send, {"tools": tools, "count": len(tools)})
        except Exception as e:
            await self._send_json(send, {"error": str(e)}, status=500)

    async def _handle_sse(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Handle SSE connection for MCP transport."""
        if not self.sse_transport or not self.mcp_server:
            await self._send_json(send, {"error": "Server not initialized"}, status=503)
            return

        try:
            # Let MCP's SSE transport handle the connection
            async with self.sse_transport.connect_sse(scope, receive, send) as streams:
                await self.mcp_server.server.run(
                    streams[0],
                    streams[1],
                    InitializationOptions(
                        server_name="isilon-mcp-server",
                        server_version=self.VERSION,
                        capabilities=self.mcp_server.server.get_capabilities(
                            NotificationOptions(),
                            {},
                        ),
                    ),
                )
        except Exception as e:
            logger.error(f"SSE error: {e}")

    async def _handle_messages(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        """Handle MCP messages endpoint."""
        if not self.sse_transport:
            await self._send_json(send, {"error": "Server not initialized"}, status=503)
            return

        try:
            await self.sse_transport.handle_post_message(scope, receive, send)
        except Exception as e:
            logger.error(f"Messages error: {e}")
            await self._send_json(send, {"error": str(e)}, status=500)

    async def _handle_call(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Direct tool call endpoint (bypasses SSE)."""
        if not self.mcp_server:
            await self._send_json(send, {"error": "Server not initialized"}, status=503)
            return

        try:
            # Read request body
            body = b""
            while True:
                message = await receive()
                body += message.get("body", b"")
                if not message.get("more_body", False):
                    break

            data = json.loads(body.decode())
            tool_name = data.get("tool")
            arguments = data.get("arguments", {})

            if not tool_name:
                await self._send_json(
                    send, {"error": "Missing 'tool' parameter"}, status=400
                )
                return

            # Execute tool
            result = await self.mcp_server._execute_tool(tool_name, arguments)

            # Format response
            response = {
                "success": not result.isError,
                "content": [
                    {"type": c.type, "text": c.text}
                    for c in result.content
                    if hasattr(c, "text")
                ],
            }

            await self._send_json(send, response)

        except json.JSONDecodeError:
            await self._send_json(send, {"error": "Invalid JSON"}, status=400)
        except Exception as e:
            logger.error(f"Call error: {e}")
            await self._send_json(send, {"error": str(e)}, status=500)

    async def _send_json(
        self, send: Send, data: dict[str, Any], status: int = 200
    ) -> None:
        """Send JSON response."""
        body = json.dumps(data).encode()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


# Create ASGI app with CORS middleware
_server = MCPHttpServer()
app = CORSMiddleware(_server)
