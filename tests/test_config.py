"""Tests for the configuration module."""

import os
import pytest
from pydantic import ValidationError

from isilon_mcp.config import IsilonConfig, ServerConfig, load_config


class TestIsilonConfig:
    """Tests for IsilonConfig model."""

    def test_valid_config(self, sample_isilon_config):
        """Test creating a valid configuration."""
        assert sample_isilon_config.host == "test-cluster.example.com"
        assert sample_isilon_config.username == "test_user"
        assert sample_isilon_config.password == "test_password"
        assert sample_isilon_config.port == 8080
        assert sample_isilon_config.use_https is True
        assert sample_isilon_config.tls_verify is False

    def test_default_port(self):
        """Test default port value."""
        config = IsilonConfig(
            host="test-cluster",
            username="user",
            password="pass",
        )
        assert config.port == 8080

    def test_custom_port(self):
        """Test custom port value."""
        config = IsilonConfig(
            host="test-cluster",
            username="user",
            password="pass",
            port=443,
        )
        assert config.port == 443

    def test_default_use_https(self):
        """Test default use_https value."""
        config = IsilonConfig(
            host="test-cluster",
            username="user",
            password="pass",
        )
        assert config.use_https is True

    def test_http_mode(self):
        """Test HTTP mode (use_https=False)."""
        config = IsilonConfig(
            host="test-cluster",
            username="user",
            password="pass",
            use_https=False,
        )
        assert config.use_https is False

    def test_tls_verify_default(self):
        """Test default tls_verify value."""
        config = IsilonConfig(
            host="test-cluster",
            username="user",
            password="pass",
        )
        # Default is False for PowerScale (often uses self-signed certs)
        assert config.tls_verify is False


class TestServerConfig:
    """Tests for ServerConfig model."""

    def test_default_values(self):
        """Test default values for server configuration."""
        config = ServerConfig()
        assert config.port == 3000
        assert config.log_level == "INFO"
        assert config.log_json is False

    def test_custom_log_level(self):
        """Test custom log level."""
        config = ServerConfig(log_level="DEBUG")
        assert config.log_level == "DEBUG"

    def test_custom_port(self):
        """Test custom port."""
        config = ServerConfig(port=8000)
        assert config.port == 8000

    def test_log_json_enabled(self):
        """Test enabling JSON logging."""
        config = ServerConfig(log_json=True)
        assert config.log_json is True


class TestLoadConfig:
    """Tests for load_config function."""

    def test_load_config_from_env(self, env_with_credentials):
        """Test loading configuration from environment variables."""
        config = load_config()
        assert config.isilon.host == "test-cluster.example.com"
        assert config.isilon.username == "test_user"
        assert config.isilon.password == "test_password"

    def test_load_config_without_credentials(self, env_without_credentials):
        """Test loading configuration without credentials returns config with empty values."""
        config = load_config()
        # Should not raise, but credentials should be empty/default
        assert config.isilon is not None

    def test_load_config_partial_credentials(self, monkeypatch):
        """Test loading configuration with partial credentials."""
        monkeypatch.setenv("ISILON_HOST", "partial-host")
        monkeypatch.delenv("ISILON_USERNAME", raising=False)
        monkeypatch.delenv("ISILON_PASSWORD", raising=False)

        config = load_config()
        assert config.isilon.host == "partial-host"
        # Username and password should be None or default
        assert config.isilon is not None
