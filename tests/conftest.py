"""Pytest configuration and fixtures for Isilon MCP Server tests."""

import json
import os
from pathlib import Path
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock

import pytest

from isilon_mcp.config import IsilonConfig, ServerConfig


@pytest.fixture
def sample_isilon_config() -> IsilonConfig:
    """Create a sample Isilon configuration for testing."""
    return IsilonConfig(
        host="test-cluster.example.com",
        username="test_user",
        password="test_password",
        port=8080,
        use_https=True,
        tls_verify=False,
    )


@pytest.fixture
def sample_server_config() -> ServerConfig:
    """Create a sample server configuration for testing."""
    return ServerConfig(
        log_level="DEBUG",
        log_json=False,
    )


@pytest.fixture
def minimal_openapi_spec() -> Dict[str, Any]:
    """Create a minimal OpenAPI spec for testing."""
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "Test PowerScale API",
            "version": "9.7.0",
        },
        "servers": [
            {"url": "https://test-cluster:8080"}
        ],
        "paths": {
            "/platform/18/cluster/config": {
                "get": {
                    "operationId": "getClusterConfig",
                    "summary": "Get cluster configuration",
                    "description": "Retrieve the cluster configuration settings",
                    "tags": ["cluster"],
                    "responses": {
                        "200": {
                            "description": "Successful response",
                        }
                    }
                }
            },
            "/platform/18/protocols/smb/shares": {
                "get": {
                    "operationId": "listSmbShares",
                    "summary": "List SMB shares",
                    "description": "List all SMB shares on the cluster",
                    "tags": ["protocols"],
                    "parameters": [
                        {
                            "name": "limit",
                            "in": "query",
                            "description": "Maximum number of items to return",
                            "required": False,
                            "schema": {"type": "integer"},
                        },
                        {
                            "name": "resume",
                            "in": "query",
                            "description": "Resume token for pagination",
                            "required": False,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Successful response",
                        }
                    }
                },
                "post": {
                    "operationId": "createSmbShare",
                    "summary": "Create SMB share",
                    "description": "Create a new SMB share",
                    "tags": ["protocols"],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["name", "path"],
                                    "properties": {
                                        "name": {
                                            "type": "string",
                                            "description": "Share name"
                                        },
                                        "path": {
                                            "type": "string",
                                            "description": "Share path"
                                        },
                                        "description": {
                                            "type": "string",
                                            "description": "Share description"
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "description": "Share created",
                        }
                    }
                }
            },
            "/platform/18/snapshot/snapshots/{snapshot_id}": {
                "get": {
                    "operationId": "getSnapshot",
                    "summary": "Get snapshot",
                    "description": "Get details of a specific snapshot",
                    "tags": ["snapshot"],
                    "parameters": [
                        {
                            "name": "snapshot_id",
                            "in": "path",
                            "description": "Snapshot ID",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Successful response",
                        }
                    }
                },
                "delete": {
                    "operationId": "deleteSnapshot",
                    "summary": "Delete snapshot",
                    "description": "Delete a specific snapshot",
                    "tags": ["snapshot"],
                    "parameters": [
                        {
                            "name": "snapshot_id",
                            "in": "path",
                            "description": "Snapshot ID",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {
                        "204": {
                            "description": "Snapshot deleted",
                        }
                    }
                }
            }
        }
    }


@pytest.fixture
def openapi_spec_file(tmp_path: Path, minimal_openapi_spec: Dict[str, Any]) -> Path:
    """Create a temporary OpenAPI spec file."""
    spec_file = tmp_path / "test_openapi.json"
    with open(spec_file, "w") as f:
        json.dump(minimal_openapi_spec, f)
    return spec_file


@pytest.fixture
def mock_httpx_response():
    """Create a mock httpx response."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"status": "ok", "data": {}}
    mock_response.raise_for_status = MagicMock()
    mock_response.text = '{"status": "ok"}'
    return mock_response


@pytest.fixture
def mock_httpx_client(mock_httpx_response):
    """Create a mock httpx async client."""
    mock_client = AsyncMock()
    mock_client.request.return_value = mock_httpx_response
    mock_client.get.return_value = mock_httpx_response
    mock_client.post.return_value = mock_httpx_response
    mock_client.put.return_value = mock_httpx_response
    mock_client.delete.return_value = mock_httpx_response
    mock_client.aclose = AsyncMock()
    return mock_client


@pytest.fixture
def env_with_credentials(monkeypatch):
    """Set environment variables with test credentials."""
    monkeypatch.setenv("ISILON_HOST", "test-cluster.example.com")
    monkeypatch.setenv("ISILON_USERNAME", "test_user")
    monkeypatch.setenv("ISILON_PASSWORD", "test_password")
    monkeypatch.setenv("ISILON_PORT", "8080")
    monkeypatch.setenv("ISILON_TLS_VERIFY", "false")


@pytest.fixture
def env_without_credentials(monkeypatch):
    """Clear environment variables for credential-free testing."""
    for var in ["ISILON_HOST", "ISILON_USERNAME", "ISILON_PASSWORD",
                "ISILON_PORT", "ISILON_TLS_VERIFY"]:
        monkeypatch.delenv(var, raising=False)
