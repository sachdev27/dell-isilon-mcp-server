"""Tests for the tool generator module."""

import json
import pytest
from pathlib import Path
from typing import Dict, Any

from isilon_mcp.tool_generator import ToolGenerator, load_openapi_spec
from isilon_mcp.exceptions import OpenAPILoadError


class TestToolGenerator:
    """Tests for ToolGenerator class."""

    def test_init_with_spec(self, minimal_openapi_spec: Dict[str, Any]):
        """Test initializing ToolGenerator with an OpenAPI spec."""
        generator = ToolGenerator(minimal_openapi_spec)
        assert generator.spec == minimal_openapi_spec

    def test_generate_tools_default_get_only(self, minimal_openapi_spec: Dict[str, Any]):
        """Test generating tools from OpenAPI spec (default GET only)."""
        generator = ToolGenerator(minimal_openapi_spec)
        tools = generator.generate_tools()

        # Should only have GET tools by default
        assert len(tools) == 3  # getClusterConfig, listSmbShares, getSnapshot
        tool_names = [t["name"] for t in tools]
        assert "getClusterConfig" in tool_names
        assert "listSmbShares" in tool_names
        assert "getSnapshot" in tool_names
        # POST and DELETE should not be included by default
        assert "createSmbShare" not in tool_names
        assert "deleteSnapshot" not in tool_names

    def test_generate_tools_all_methods(self, minimal_openapi_spec: Dict[str, Any]):
        """Test generating tools for all HTTP methods."""
        generator = ToolGenerator(
            minimal_openapi_spec,
            allowed_methods=["GET", "POST", "DELETE"]
        )
        tools = generator.generate_tools()

        # Should have all 5 tools
        assert len(tools) == 5
        tool_names = [t["name"] for t in tools]
        assert "getClusterConfig" in tool_names
        assert "listSmbShares" in tool_names
        assert "createSmbShare" in tool_names
        assert "getSnapshot" in tool_names
        assert "deleteSnapshot" in tool_names

    def test_tool_has_required_keys(self, minimal_openapi_spec: Dict[str, Any]):
        """Test that generated tools have all required keys."""
        generator = ToolGenerator(minimal_openapi_spec)
        tools = generator.generate_tools()

        for tool in tools:
            assert "name" in tool
            assert "description" in tool
            assert "inputSchema" in tool
            assert "_path" in tool
            assert "_method" in tool

    def test_tool_input_schema_has_credentials(self, minimal_openapi_spec: Dict[str, Any]):
        """Test that tool input schema includes credential parameters."""
        generator = ToolGenerator(minimal_openapi_spec)
        tools = generator.generate_tools()

        for tool in tools:
            schema = tool["inputSchema"]
            assert "properties" in schema
            props = schema["properties"]
            # All tools should require credentials
            assert "host" in props
            assert "username" in props
            assert "password" in props

    def test_tool_with_path_parameters(self, minimal_openapi_spec: Dict[str, Any]):
        """Test tool generation for endpoints with path parameters."""
        generator = ToolGenerator(minimal_openapi_spec)
        tools = generator.generate_tools()

        # Find the getSnapshot tool
        snapshot_tool = next(t for t in tools if t["name"] == "getSnapshot")

        # Should have snapshot_id in the schema
        schema = snapshot_tool["inputSchema"]
        assert "snapshot_id" in schema["properties"]

    def test_tool_with_query_parameters(self, minimal_openapi_spec: Dict[str, Any]):
        """Test tool generation for endpoints with query parameters."""
        generator = ToolGenerator(minimal_openapi_spec)
        tools = generator.generate_tools()

        # Find the listSmbShares tool
        smb_tool = next(t for t in tools if t["name"] == "listSmbShares")

        # Should have limit and resume in the schema
        schema = smb_tool["inputSchema"]
        assert "limit" in schema["properties"]
        assert "resume" in schema["properties"]

    def test_tool_method_stored(self, minimal_openapi_spec: Dict[str, Any]):
        """Test that HTTP method is stored in the tool."""
        generator = ToolGenerator(
            minimal_openapi_spec,
            allowed_methods=["GET", "POST", "DELETE"]
        )
        tools = generator.generate_tools()

        method_map = {t["name"]: t["_method"] for t in tools}

        assert method_map["getClusterConfig"] == "get"
        assert method_map["listSmbShares"] == "get"
        assert method_map["createSmbShare"] == "post"
        assert method_map["getSnapshot"] == "get"
        assert method_map["deleteSnapshot"] == "delete"

    def test_tool_path_stored(self, minimal_openapi_spec: Dict[str, Any]):
        """Test that API path is stored in the tool."""
        generator = ToolGenerator(minimal_openapi_spec)
        tools = generator.generate_tools()

        path_map = {t["name"]: t["_path"] for t in tools}

        assert path_map["getClusterConfig"] == "/platform/18/cluster/config"
        assert path_map["listSmbShares"] == "/platform/18/protocols/smb/shares"
        assert path_map["getSnapshot"] == "/platform/18/snapshot/snapshots/{snapshot_id}"

    def test_empty_spec(self):
        """Test handling empty OpenAPI spec."""
        empty_spec = {
            "openapi": "3.0.3",
            "info": {"title": "Empty", "version": "1.0.0"},
            "paths": {}
        }
        generator = ToolGenerator(empty_spec)
        tools = generator.generate_tools()

        assert len(tools) == 0


class TestLoadOpenAPISpec:
    """Tests for load_openapi_spec function."""

    def test_load_json_spec(self, openapi_spec_file: Path):
        """Test loading a JSON OpenAPI spec."""
        spec = load_openapi_spec(str(openapi_spec_file))

        assert spec["openapi"] == "3.0.3"
        assert spec["info"]["title"] == "Test PowerScale API"
        assert "/platform/18/cluster/config" in spec["paths"]

    def test_load_nonexistent_file(self):
        """Test loading a non-existent file raises error."""
        with pytest.raises(OpenAPILoadError):
            load_openapi_spec("/nonexistent/path/openapi.json")

    def test_load_yaml_spec(self, tmp_path: Path, minimal_openapi_spec: Dict[str, Any]):
        """Test loading a YAML OpenAPI spec."""
        import yaml

        spec_file = tmp_path / "test_openapi.yaml"
        with open(spec_file, "w") as f:
            yaml.dump(minimal_openapi_spec, f)

        spec = load_openapi_spec(str(spec_file))

        assert spec["openapi"] == "3.0.3"
        assert spec["info"]["title"] == "Test PowerScale API"
